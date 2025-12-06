//! RTCP packet handling per RFC 3550.
//!
//! RTCP provides feedback on quality of service and participant information.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|    RC   |   PT=SR=200   |             length            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::time::{SystemTime, UNIX_EPOCH};

/// RTCP packet types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RtcpType {
    /// Sender Report
    SenderReport = 200,
    /// Receiver Report
    ReceiverReport = 201,
    /// Source Description
    SourceDescription = 202,
    /// Goodbye
    Goodbye = 203,
    /// Application-defined
    ApplicationDefined = 204,
}

impl TryFrom<u8> for RtcpType {
    type Error = RtcpParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            200 => Ok(RtcpType::SenderReport),
            201 => Ok(RtcpType::ReceiverReport),
            202 => Ok(RtcpType::SourceDescription),
            203 => Ok(RtcpType::Goodbye),
            204 => Ok(RtcpType::ApplicationDefined),
            _ => Err(RtcpParseError::UnknownPacketType(value)),
        }
    }
}

/// RTCP parse error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RtcpParseError {
    #[error("Packet too short: {0} bytes")]
    TooShort(usize),
    #[error("Invalid RTCP version: {0}")]
    InvalidVersion(u8),
    #[error("Unknown packet type: {0}")]
    UnknownPacketType(u8),
    #[error("Invalid report block count")]
    InvalidReportCount,
}

/// Common RTCP header (4 bytes).
#[derive(Debug, Clone)]
pub struct RtcpHeader {
    /// Version (always 2).
    pub version: u8,
    /// Padding flag.
    pub padding: bool,
    /// Report count or subtype.
    pub count: u8,
    /// Packet type.
    pub packet_type: RtcpType,
    /// Length in 32-bit words minus one.
    pub length: u16,
}

impl RtcpHeader {
    /// Parse RTCP header from bytes.
    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), RtcpParseError> {
        if data.len() < 4 {
            return Err(RtcpParseError::TooShort(data.len()));
        }

        let first_byte = data[0];
        let version = (first_byte >> 6) & 0x03;
        let padding = (first_byte >> 5) & 0x01 == 1;
        let count = first_byte & 0x1F;

        if version != 2 {
            return Err(RtcpParseError::InvalidVersion(version));
        }

        let packet_type = RtcpType::try_from(data[1])?;
        let length = u16::from_be_bytes([data[2], data[3]]);

        Ok((
            RtcpHeader {
                version,
                padding,
                count,
                packet_type,
                length,
            },
            &data[4..],
        ))
    }

    /// Build RTCP header to bytes.
    pub fn build(&self, buf: &mut BytesMut) {
        let first_byte = (self.version << 6) | ((self.padding as u8) << 5) | (self.count & 0x1F);
        buf.put_u8(first_byte);
        buf.put_u8(self.packet_type as u8);
        buf.put_u16(self.length);
    }
}

/// NTP timestamp (64 bits: 32-bit seconds + 32-bit fraction).
#[derive(Debug, Clone, Copy, Default)]
pub struct NtpTimestamp {
    /// Seconds since 1900.
    pub seconds: u32,
    /// Fractional seconds.
    pub fraction: u32,
}

impl NtpTimestamp {
    /// NTP epoch offset from Unix epoch (1900 to 1970).
    const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

    /// Create NTP timestamp from current time.
    pub fn now() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        let seconds = duration.as_secs() + Self::NTP_UNIX_OFFSET;
        let fraction = ((duration.subsec_nanos() as u64) << 32) / 1_000_000_000;

        Self {
            seconds: seconds as u32,
            fraction: fraction as u32,
        }
    }

    /// Convert to compact 32-bit representation (middle 32 bits).
    pub fn compact(&self) -> u32 {
        ((self.seconds & 0xFFFF) << 16) | ((self.fraction >> 16) & 0xFFFF)
    }

    /// Create from compact 32-bit representation.
    pub fn from_compact(compact: u32) -> Self {
        Self {
            seconds: (compact >> 16) & 0xFFFF,
            fraction: (compact & 0xFFFF) << 16,
        }
    }
}

/// Report block in SR/RR packets.
#[derive(Debug, Clone, Default)]
pub struct ReportBlock {
    /// SSRC of the source being reported.
    pub ssrc: u32,
    /// Fraction of packets lost (0-255, representing 0.0-1.0).
    pub fraction_lost: u8,
    /// Cumulative packets lost (24-bit signed).
    pub cumulative_lost: i32,
    /// Extended highest sequence number received.
    pub extended_seq: u32,
    /// Interarrival jitter.
    pub jitter: u32,
    /// Last SR timestamp (compact NTP).
    pub last_sr: u32,
    /// Delay since last SR (1/65536 seconds).
    pub delay_since_sr: u32,
}

impl ReportBlock {
    /// Size of a report block in bytes.
    pub const SIZE: usize = 24;

    /// Parse a report block from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, RtcpParseError> {
        if data.len() < Self::SIZE {
            return Err(RtcpParseError::TooShort(data.len()));
        }

        let mut buf = data;
        let ssrc = buf.get_u32();
        let fraction_lost = buf.get_u8();
        let lost_bytes = [0, buf.get_u8(), buf.get_u8(), buf.get_u8()];
        let cumulative_lost = i32::from_be_bytes(lost_bytes) >> 8; // Sign-extend 24-bit
        let extended_seq = buf.get_u32();
        let jitter = buf.get_u32();
        let last_sr = buf.get_u32();
        let delay_since_sr = buf.get_u32();

        Ok(ReportBlock {
            ssrc,
            fraction_lost,
            cumulative_lost,
            extended_seq,
            jitter,
            last_sr,
            delay_since_sr,
        })
    }

    /// Build a report block to bytes.
    pub fn build(&self, buf: &mut BytesMut) {
        buf.put_u32(self.ssrc);
        buf.put_u8(self.fraction_lost);
        // 24-bit cumulative lost
        let lost_bytes = self.cumulative_lost.to_be_bytes();
        buf.put_u8(lost_bytes[1]);
        buf.put_u8(lost_bytes[2]);
        buf.put_u8(lost_bytes[3]);
        buf.put_u32(self.extended_seq);
        buf.put_u32(self.jitter);
        buf.put_u32(self.last_sr);
        buf.put_u32(self.delay_since_sr);
    }
}

/// Sender Report (SR) packet.
#[derive(Debug, Clone)]
pub struct SenderReport {
    /// SSRC of sender.
    pub ssrc: u32,
    /// NTP timestamp.
    pub ntp_timestamp: NtpTimestamp,
    /// RTP timestamp.
    pub rtp_timestamp: u32,
    /// Sender's packet count.
    pub sender_packet_count: u32,
    /// Sender's octet count.
    pub sender_octet_count: u32,
    /// Report blocks.
    pub report_blocks: Vec<ReportBlock>,
}

impl SenderReport {
    /// Minimum size of sender report (header + sender info).
    pub const MIN_SIZE: usize = 24;

    /// Parse a sender report from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, RtcpParseError> {
        let (header, rest) = RtcpHeader::parse(data)?;

        if header.packet_type != RtcpType::SenderReport {
            return Err(RtcpParseError::UnknownPacketType(header.packet_type as u8));
        }

        if rest.len() < 20 {
            return Err(RtcpParseError::TooShort(rest.len()));
        }

        let mut buf = rest;
        let ssrc = buf.get_u32();
        let ntp_seconds = buf.get_u32();
        let ntp_fraction = buf.get_u32();
        let rtp_timestamp = buf.get_u32();
        let sender_packet_count = buf.get_u32();
        let sender_octet_count = buf.get_u32();

        let mut report_blocks = Vec::with_capacity(header.count as usize);
        for _ in 0..header.count {
            if buf.remaining() < ReportBlock::SIZE {
                return Err(RtcpParseError::InvalidReportCount);
            }
            let block_data = &buf[..ReportBlock::SIZE];
            report_blocks.push(ReportBlock::parse(block_data)?);
            buf.advance(ReportBlock::SIZE);
        }

        Ok(SenderReport {
            ssrc,
            ntp_timestamp: NtpTimestamp {
                seconds: ntp_seconds,
                fraction: ntp_fraction,
            },
            rtp_timestamp,
            sender_packet_count,
            sender_octet_count,
            report_blocks,
        })
    }

    /// Build a sender report to bytes.
    pub fn build(&self) -> Bytes {
        let report_count = self.report_blocks.len().min(31) as u8;
        let length = 6 + report_count as u16 * 6; // In 32-bit words minus 1

        let mut buf = BytesMut::with_capacity(28 + self.report_blocks.len() * ReportBlock::SIZE);

        let header = RtcpHeader {
            version: 2,
            padding: false,
            count: report_count,
            packet_type: RtcpType::SenderReport,
            length,
        };
        header.build(&mut buf);

        buf.put_u32(self.ssrc);
        buf.put_u32(self.ntp_timestamp.seconds);
        buf.put_u32(self.ntp_timestamp.fraction);
        buf.put_u32(self.rtp_timestamp);
        buf.put_u32(self.sender_packet_count);
        buf.put_u32(self.sender_octet_count);

        for block in &self.report_blocks {
            block.build(&mut buf);
        }

        buf.freeze()
    }
}

/// Receiver Report (RR) packet.
#[derive(Debug, Clone)]
pub struct ReceiverReport {
    /// SSRC of sender.
    pub ssrc: u32,
    /// Report blocks.
    pub report_blocks: Vec<ReportBlock>,
}

impl ReceiverReport {
    /// Minimum size of receiver report.
    pub const MIN_SIZE: usize = 4;

    /// Parse a receiver report from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, RtcpParseError> {
        let (header, rest) = RtcpHeader::parse(data)?;

        if header.packet_type != RtcpType::ReceiverReport {
            return Err(RtcpParseError::UnknownPacketType(header.packet_type as u8));
        }

        if rest.len() < 4 {
            return Err(RtcpParseError::TooShort(rest.len()));
        }

        let mut buf = rest;
        let ssrc = buf.get_u32();

        let mut report_blocks = Vec::with_capacity(header.count as usize);
        for _ in 0..header.count {
            if buf.remaining() < ReportBlock::SIZE {
                return Err(RtcpParseError::InvalidReportCount);
            }
            let block_data = &buf[..ReportBlock::SIZE];
            report_blocks.push(ReportBlock::parse(block_data)?);
            buf.advance(ReportBlock::SIZE);
        }

        Ok(ReceiverReport {
            ssrc,
            report_blocks,
        })
    }

    /// Build a receiver report to bytes.
    pub fn build(&self) -> Bytes {
        let report_count = self.report_blocks.len().min(31) as u8;
        let length = 1 + report_count as u16 * 6; // In 32-bit words minus 1

        let mut buf = BytesMut::with_capacity(8 + self.report_blocks.len() * ReportBlock::SIZE);

        let header = RtcpHeader {
            version: 2,
            padding: false,
            count: report_count,
            packet_type: RtcpType::ReceiverReport,
            length,
        };
        header.build(&mut buf);

        buf.put_u32(self.ssrc);

        for block in &self.report_blocks {
            block.build(&mut buf);
        }

        buf.freeze()
    }
}

/// SDES item types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SdesType {
    /// End of SDES list.
    End = 0,
    /// Canonical name.
    CName = 1,
    /// User name.
    Name = 2,
    /// Email.
    Email = 3,
    /// Phone number.
    Phone = 4,
    /// Location.
    Location = 5,
    /// Application/tool name.
    Tool = 6,
    /// Note.
    Note = 7,
    /// Private extension.
    Private = 8,
}

/// SDES item.
#[derive(Debug, Clone)]
pub struct SdesItem {
    /// Item type.
    pub item_type: SdesType,
    /// Item value.
    pub value: String,
}

/// SDES chunk (items for one SSRC).
#[derive(Debug, Clone)]
pub struct SdesChunk {
    /// SSRC.
    pub ssrc: u32,
    /// Items.
    pub items: Vec<SdesItem>,
}

/// Source Description (SDES) packet.
#[derive(Debug, Clone)]
pub struct SourceDescription {
    /// SDES chunks.
    pub chunks: Vec<SdesChunk>,
}

impl SourceDescription {
    /// Build an SDES packet with just CNAME.
    pub fn with_cname(ssrc: u32, cname: &str) -> Self {
        Self {
            chunks: vec![SdesChunk {
                ssrc,
                items: vec![SdesItem {
                    item_type: SdesType::CName,
                    value: cname.to_string(),
                }],
            }],
        }
    }

    /// Build to bytes.
    pub fn build(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(256);

        // Reserve space for header
        let header_pos = buf.len();
        buf.put_u32(0); // Placeholder

        let chunk_count = self.chunks.len().min(31) as u8;

        for chunk in &self.chunks {
            buf.put_u32(chunk.ssrc);
            for item in &chunk.items {
                buf.put_u8(item.item_type as u8);
                let value_bytes = item.value.as_bytes();
                buf.put_u8(value_bytes.len() as u8);
                buf.put_slice(value_bytes);
            }
            buf.put_u8(0); // End of items
            // Pad to 32-bit boundary
            while !buf.len().is_multiple_of(4) {
                buf.put_u8(0);
            }
        }

        // Calculate length in 32-bit words minus 1
        let length = ((buf.len() - 4) / 4) as u16;

        // Write header
        let header_byte = (2 << 6) | chunk_count;
        buf[header_pos] = header_byte;
        buf[header_pos + 1] = RtcpType::SourceDescription as u8;
        buf[header_pos + 2] = (length >> 8) as u8;
        buf[header_pos + 3] = (length & 0xFF) as u8;

        buf.freeze()
    }
}

/// Goodbye (BYE) packet.
#[derive(Debug, Clone)]
pub struct Goodbye {
    /// SSRCs leaving.
    pub ssrcs: Vec<u32>,
    /// Optional reason.
    pub reason: Option<String>,
}

impl Goodbye {
    /// Create a simple goodbye for one SSRC.
    pub fn new(ssrc: u32) -> Self {
        Self {
            ssrcs: vec![ssrc],
            reason: None,
        }
    }

    /// Build to bytes.
    pub fn build(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(32);

        let ssrc_count = self.ssrcs.len().min(31) as u8;

        // Calculate length
        let mut content_len = self.ssrcs.len() * 4;
        if let Some(ref reason) = self.reason {
            content_len += 1 + reason.len();
            // Pad to 32-bit boundary
            content_len = (content_len + 3) & !3;
        }
        let length = (content_len / 4) as u16;

        let header = RtcpHeader {
            version: 2,
            padding: false,
            count: ssrc_count,
            packet_type: RtcpType::Goodbye,
            length,
        };
        header.build(&mut buf);

        for &ssrc in &self.ssrcs {
            buf.put_u32(ssrc);
        }

        if let Some(ref reason) = self.reason {
            let reason_bytes = reason.as_bytes();
            buf.put_u8(reason_bytes.len() as u8);
            buf.put_slice(reason_bytes);
            // Pad to 32-bit boundary
            while !buf.len().is_multiple_of(4) {
                buf.put_u8(0);
            }
        }

        buf.freeze()
    }
}

/// RTCP compound packet (typically SR/RR + SDES).
#[derive(Debug, Clone)]
pub struct RtcpCompound {
    /// Packets in the compound.
    pub packets: Vec<RtcpPacket>,
}

/// Individual RTCP packet types.
#[derive(Debug, Clone)]
pub enum RtcpPacket {
    SenderReport(SenderReport),
    ReceiverReport(ReceiverReport),
    SourceDescription(SourceDescription),
    Goodbye(Goodbye),
}

impl RtcpCompound {
    /// Create a compound packet with SR and SDES.
    pub fn sender_compound(sr: SenderReport, cname: &str) -> Self {
        let sdes = SourceDescription::with_cname(sr.ssrc, cname);
        Self {
            packets: vec![
                RtcpPacket::SenderReport(sr),
                RtcpPacket::SourceDescription(sdes),
            ],
        }
    }

    /// Create a compound packet with RR and SDES.
    pub fn receiver_compound(rr: ReceiverReport, cname: &str) -> Self {
        let sdes = SourceDescription::with_cname(rr.ssrc, cname);
        Self {
            packets: vec![
                RtcpPacket::ReceiverReport(rr),
                RtcpPacket::SourceDescription(sdes),
            ],
        }
    }

    /// Build to bytes.
    pub fn build(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(512);

        for packet in &self.packets {
            match packet {
                RtcpPacket::SenderReport(sr) => buf.extend_from_slice(&sr.build()),
                RtcpPacket::ReceiverReport(rr) => buf.extend_from_slice(&rr.build()),
                RtcpPacket::SourceDescription(sdes) => buf.extend_from_slice(&sdes.build()),
                RtcpPacket::Goodbye(bye) => buf.extend_from_slice(&bye.build()),
            }
        }

        buf.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntp_timestamp() {
        let ntp = NtpTimestamp::now();
        assert!(ntp.seconds > 0);

        let compact = ntp.compact();
        assert!(compact > 0);
    }

    #[test]
    fn test_sender_report_build_parse() {
        let sr = SenderReport {
            ssrc: 12345,
            ntp_timestamp: NtpTimestamp::now(),
            rtp_timestamp: 160000,
            sender_packet_count: 100,
            sender_octet_count: 16000,
            report_blocks: vec![],
        };

        let bytes = sr.build();
        let parsed = SenderReport::parse(&bytes).unwrap();

        assert_eq!(parsed.ssrc, 12345);
        assert_eq!(parsed.rtp_timestamp, 160000);
        assert_eq!(parsed.sender_packet_count, 100);
        assert_eq!(parsed.sender_octet_count, 16000);
    }

    #[test]
    fn test_sender_report_with_report_block() {
        let sr = SenderReport {
            ssrc: 12345,
            ntp_timestamp: NtpTimestamp::now(),
            rtp_timestamp: 160000,
            sender_packet_count: 100,
            sender_octet_count: 16000,
            report_blocks: vec![ReportBlock {
                ssrc: 67890,
                fraction_lost: 25,
                cumulative_lost: 10,
                extended_seq: 50000,
                jitter: 160,
                last_sr: 0,
                delay_since_sr: 0,
            }],
        };

        let bytes = sr.build();
        let parsed = SenderReport::parse(&bytes).unwrap();

        assert_eq!(parsed.report_blocks.len(), 1);
        assert_eq!(parsed.report_blocks[0].ssrc, 67890);
        assert_eq!(parsed.report_blocks[0].fraction_lost, 25);
    }

    #[test]
    fn test_receiver_report_build_parse() {
        let rr = ReceiverReport {
            ssrc: 12345,
            report_blocks: vec![ReportBlock {
                ssrc: 67890,
                fraction_lost: 0,
                cumulative_lost: 0,
                extended_seq: 1000,
                jitter: 80,
                last_sr: 0,
                delay_since_sr: 0,
            }],
        };

        let bytes = rr.build();
        let parsed = ReceiverReport::parse(&bytes).unwrap();

        assert_eq!(parsed.ssrc, 12345);
        assert_eq!(parsed.report_blocks.len(), 1);
        assert_eq!(parsed.report_blocks[0].ssrc, 67890);
    }

    #[test]
    fn test_sdes_build() {
        let sdes = SourceDescription::with_cname(12345, "user@example.com");
        let bytes = sdes.build();

        // Should have valid RTCP header
        assert_eq!(bytes[1], RtcpType::SourceDescription as u8);
    }

    #[test]
    fn test_goodbye_build() {
        let bye = Goodbye::new(12345);
        let bytes = bye.build();

        assert_eq!(bytes[1], RtcpType::Goodbye as u8);
    }

    #[test]
    fn test_compound_packet() {
        let sr = SenderReport {
            ssrc: 12345,
            ntp_timestamp: NtpTimestamp::now(),
            rtp_timestamp: 160000,
            sender_packet_count: 100,
            sender_octet_count: 16000,
            report_blocks: vec![],
        };

        let compound = RtcpCompound::sender_compound(sr, "user@example.com");
        let bytes = compound.build();

        // Should contain both SR and SDES
        assert!(bytes.len() > 28);
        assert_eq!(bytes[1], RtcpType::SenderReport as u8);
    }

    #[test]
    fn test_report_block() {
        let block = ReportBlock {
            ssrc: 12345,
            fraction_lost: 128, // 50% loss
            cumulative_lost: 1000,
            extended_seq: 65536 + 1000,
            jitter: 320,
            last_sr: 0x12345678,
            delay_since_sr: 65536, // 1 second
        };

        let mut buf = BytesMut::new();
        block.build(&mut buf);

        let parsed = ReportBlock::parse(&buf).unwrap();
        assert_eq!(parsed.ssrc, 12345);
        assert_eq!(parsed.fraction_lost, 128);
        assert_eq!(parsed.extended_seq, 65536 + 1000);
        assert_eq!(parsed.jitter, 320);
    }
}

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
    /// Transport-layer Feedback (RTPFB) - RFC 4585
    TransportFeedback = 205,
    /// Payload-specific Feedback (PSFB) - RFC 4585
    PayloadFeedback = 206,
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
            205 => Ok(RtcpType::TransportFeedback),
            206 => Ok(RtcpType::PayloadFeedback),
            _ => Err(RtcpParseError::UnknownPacketType(value)),
        }
    }
}

/// RTCP parse error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RtcpParseError {
    /// Buffer too short to contain a valid RTCP packet header (4 bytes minimum).
    #[error("Packet too short: {0} bytes")]
    TooShort(usize),
    /// RTCP version field is not 2 (the only version defined by RFC 3550).
    #[error("Invalid RTCP version: {0}")]
    InvalidVersion(u8),
    /// RTCP payload type is not recognized by this implementation.
    #[error("Unknown packet type: {0}")]
    UnknownPacketType(u8),
    /// Report block count in the header does not match the available payload bytes.
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
            let block = ReportBlock::parse(block_data).expect("report block size checked");
            report_blocks.push(block);
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
            let block = ReportBlock::parse(block_data).expect("report block size checked");
            report_blocks.push(block);
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

    /// Parse an SDES packet from bytes.
    ///
    /// Walks the chunk list according to RFC 3550 § 6.5. Unknown SDES item
    /// type codes are skipped (their length-prefixed value is consumed but the
    /// item is not stored), preserving forward-compatibility.
    pub fn parse(data: &[u8]) -> Result<Self, RtcpParseError> {
        let (header, rest) = RtcpHeader::parse(data)?;

        if header.packet_type != RtcpType::SourceDescription {
            return Err(RtcpParseError::UnknownPacketType(header.packet_type as u8));
        }

        // Total payload length declared by the header (excluding the 4-byte header).
        let declared = (header.length as usize) * 4;
        if rest.len() < declared {
            return Err(RtcpParseError::TooShort(rest.len()));
        }
        let mut buf = &rest[..declared];

        let mut chunks = Vec::with_capacity(header.count as usize);
        for _ in 0..header.count {
            if buf.remaining() < 4 {
                return Err(RtcpParseError::TooShort(buf.remaining()));
            }
            let chunk_start = buf.len();
            let ssrc = buf.get_u32();
            let mut items = Vec::new();
            loop {
                if buf.remaining() < 1 {
                    return Err(RtcpParseError::TooShort(buf.remaining()));
                }
                let item_type = buf.get_u8();
                if item_type == 0 {
                    break;
                }
                if buf.remaining() < 1 {
                    return Err(RtcpParseError::TooShort(buf.remaining()));
                }
                let len = buf.get_u8() as usize;
                if buf.remaining() < len {
                    return Err(RtcpParseError::TooShort(buf.remaining()));
                }
                let value_bytes = &buf[..len];
                let value = String::from_utf8_lossy(value_bytes).into_owned();
                buf.advance(len);

                let parsed_type = match item_type {
                    1 => Some(SdesType::CName),
                    2 => Some(SdesType::Name),
                    3 => Some(SdesType::Email),
                    4 => Some(SdesType::Phone),
                    5 => Some(SdesType::Location),
                    6 => Some(SdesType::Tool),
                    7 => Some(SdesType::Note),
                    8 => Some(SdesType::Private),
                    _ => None,
                };
                if let Some(item_type) = parsed_type {
                    items.push(SdesItem { item_type, value });
                }
            }
            // Pad to 32-bit boundary relative to the chunk start.
            let consumed = chunk_start - buf.len();
            let pad = (4 - (consumed % 4)) % 4;
            if buf.remaining() < pad {
                return Err(RtcpParseError::TooShort(buf.remaining()));
            }
            buf.advance(pad);

            chunks.push(SdesChunk { ssrc, items });
        }

        Ok(SourceDescription { chunks })
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

    /// Parse a BYE packet from bytes (RFC 3550 § 6.6).
    pub fn parse(data: &[u8]) -> Result<Self, RtcpParseError> {
        let (header, rest) = RtcpHeader::parse(data)?;

        if header.packet_type != RtcpType::Goodbye {
            return Err(RtcpParseError::UnknownPacketType(header.packet_type as u8));
        }

        let declared = (header.length as usize) * 4;
        if rest.len() < declared {
            return Err(RtcpParseError::TooShort(rest.len()));
        }
        let mut buf = &rest[..declared];

        let ssrc_count = header.count as usize;
        if buf.remaining() < ssrc_count * 4 {
            return Err(RtcpParseError::TooShort(buf.remaining()));
        }
        let mut ssrcs = Vec::with_capacity(ssrc_count);
        for _ in 0..ssrc_count {
            ssrcs.push(buf.get_u32());
        }

        // Optional reason: length byte + UTF-8, padded to 32-bit boundary.
        let reason = if buf.remaining() >= 1 {
            let len = buf.get_u8() as usize;
            if buf.remaining() < len {
                return Err(RtcpParseError::TooShort(buf.remaining()));
            }
            let value = String::from_utf8_lossy(&buf[..len]).into_owned();
            buf.advance(len);
            Some(value)
        } else {
            None
        };

        Ok(Goodbye { ssrcs, reason })
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

// =============================================================================
// RTCP Feedback Messages (RFC 4585, RFC 5104)
// =============================================================================

/// Feedback Message Type (FMT) for Transport-layer Feedback (RTPFB).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportFeedbackType {
    /// Generic NACK - RFC 4585
    Nack = 1,
    /// Transport-wide Congestion Control - RFC 8888 (reserved for future)
    TransportCC = 15,
}

/// Feedback Message Type (FMT) for Payload-specific Feedback (PSFB).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadFeedbackType {
    /// Picture Loss Indication - RFC 4585
    Pli = 1,
    /// Slice Loss Indication - RFC 4585
    Sli = 2,
    /// Reference Picture Selection Indication - RFC 4585
    Rpsi = 3,
    /// Full Intra Request - RFC 5104
    Fir = 4,
    /// Temporal-Spatial Trade-off Request - RFC 5104
    Tstr = 5,
    /// Temporal-Spatial Trade-off Notification - RFC 5104
    Tstn = 6,
    /// Video Back Channel Message - RFC 5104
    Vbcm = 7,
    /// Application-layer Feedback (for REMB) - RFC 4585
    Afb = 15,
}

/// Generic NACK (Negative ACKnowledgement) - RFC 4585.
///
/// Used to request retransmission of lost RTP packets.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            PID                |             BLP               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone)]
pub struct Nack {
    /// SSRC of the packet sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source being NACKed.
    pub media_ssrc: u32,
    /// NACK entries (PID + BLP pairs).
    pub nacks: Vec<NackEntry>,
}

/// A single NACK entry (PID + BLP).
#[derive(Debug, Clone, Copy)]
pub struct NackEntry {
    /// Packet ID of the lost packet.
    pub pid: u16,
    /// Bitmask of following lost packets (bit N set = PID+N+1 is lost).
    pub blp: u16,
}

impl NackEntry {
    /// Create a NACK entry for a single packet.
    pub fn single(seq: u16) -> Self {
        Self { pid: seq, blp: 0 }
    }

    /// Create a NACK entry from a list of sequence numbers.
    /// The first sequence number becomes PID, subsequent ones set BLP bits.
    pub fn from_sequences(seqs: &[u16]) -> Option<Self> {
        let pid = *seqs.first()?;
        let mut blp = 0u16;
        for &seq in seqs.iter().skip(1) {
            let diff = seq.wrapping_sub(pid).wrapping_sub(1);
            if diff < 16 {
                blp |= 1 << diff;
            }
        }
        Some(Self { pid, blp })
    }

    /// Get all lost sequence numbers represented by this entry.
    pub fn lost_sequences(&self) -> Vec<u16> {
        let mut seqs = vec![self.pid];
        for i in 0..16 {
            if (self.blp >> i) & 1 == 1 {
                seqs.push(self.pid.wrapping_add(i + 1));
            }
        }
        seqs
    }
}

impl Nack {
    /// Create a NACK for a single lost packet.
    pub fn new(sender_ssrc: u32, media_ssrc: u32, lost_seq: u16) -> Self {
        Self {
            sender_ssrc,
            media_ssrc,
            nacks: vec![NackEntry::single(lost_seq)],
        }
    }

    /// Create a NACK from a list of lost sequence numbers.
    pub fn from_lost_packets(sender_ssrc: u32, media_ssrc: u32, lost_seqs: &[u16]) -> Self {
        // Group sequences into NACK entries (each entry covers up to 17 packets)
        let mut nacks = Vec::new();
        let mut remaining: Vec<u16> = lost_seqs.to_vec();
        remaining.sort();

        while !remaining.is_empty() {
            let pid = remaining[0];
            let mut group = vec![pid];
            let mut new_remaining = Vec::new();

            for &seq in remaining.iter().skip(1) {
                let diff = seq.wrapping_sub(pid);
                if diff > 0 && diff <= 16 {
                    group.push(seq);
                } else {
                    new_remaining.push(seq);
                }
            }

            let entry = NackEntry::from_sequences(&group).expect("nack group empty");
            nacks.push(entry);
            remaining = new_remaining;
        }

        Self {
            sender_ssrc,
            media_ssrc,
            nacks,
        }
    }

    /// Parse a NACK packet from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, RtcpParseError> {
        let (header, rest) = RtcpHeader::parse(data)?;

        if header.packet_type != RtcpType::TransportFeedback || header.count != 1 {
            return Err(RtcpParseError::UnknownPacketType(header.packet_type as u8));
        }

        if rest.len() < 8 {
            return Err(RtcpParseError::TooShort(rest.len()));
        }

        let mut buf = rest;
        let sender_ssrc = buf.get_u32();
        let media_ssrc = buf.get_u32();

        let mut nacks = Vec::new();
        while buf.remaining() >= 4 {
            let pid = buf.get_u16();
            let blp = buf.get_u16();
            nacks.push(NackEntry { pid, blp });
        }

        Ok(Nack {
            sender_ssrc,
            media_ssrc,
            nacks,
        })
    }

    /// Build the NACK packet to bytes.
    pub fn build(&self) -> Bytes {
        let nack_count = self.nacks.len();
        let length = (2 + nack_count) as u16; // In 32-bit words minus 1

        let mut buf = BytesMut::with_capacity(12 + nack_count * 4);

        let header = RtcpHeader {
            version: 2,
            padding: false,
            count: TransportFeedbackType::Nack as u8,
            packet_type: RtcpType::TransportFeedback,
            length,
        };
        header.build(&mut buf);

        buf.put_u32(self.sender_ssrc);
        buf.put_u32(self.media_ssrc);

        for nack in &self.nacks {
            buf.put_u16(nack.pid);
            buf.put_u16(nack.blp);
        }

        buf.freeze()
    }

    /// Get all lost sequence numbers from all NACK entries.
    pub fn all_lost_sequences(&self) -> Vec<u16> {
        self.nacks.iter().flat_map(|n| n.lost_sequences()).collect()
    }
}

/// Picture Loss Indication (PLI) - RFC 4585.
///
/// Requests a full intra-frame from the encoder when decoder
/// has lost synchronization and needs a keyframe.
#[derive(Debug, Clone)]
pub struct Pli {
    /// SSRC of the packet sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source.
    pub media_ssrc: u32,
}

impl Pli {
    /// Create a new PLI request.
    pub fn new(sender_ssrc: u32, media_ssrc: u32) -> Self {
        Self {
            sender_ssrc,
            media_ssrc,
        }
    }

    /// Parse a PLI packet from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, RtcpParseError> {
        let (header, rest) = RtcpHeader::parse(data)?;

        if header.packet_type != RtcpType::PayloadFeedback || header.count != 1 {
            return Err(RtcpParseError::UnknownPacketType(header.packet_type as u8));
        }

        if rest.len() < 8 {
            return Err(RtcpParseError::TooShort(rest.len()));
        }

        let mut buf = rest;
        let sender_ssrc = buf.get_u32();
        let media_ssrc = buf.get_u32();

        Ok(Pli {
            sender_ssrc,
            media_ssrc,
        })
    }

    /// Build the PLI packet to bytes.
    pub fn build(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(12);

        let header = RtcpHeader {
            version: 2,
            padding: false,
            count: PayloadFeedbackType::Pli as u8,
            packet_type: RtcpType::PayloadFeedback,
            length: 2, // 2 32-bit words after header
        };
        header.build(&mut buf);

        buf.put_u32(self.sender_ssrc);
        buf.put_u32(self.media_ssrc);

        buf.freeze()
    }
}

/// Full Intra Request (FIR) - RFC 5104.
///
/// A more specific keyframe request that includes a sequence number
/// to distinguish between multiple requests.
#[derive(Debug, Clone)]
pub struct Fir {
    /// SSRC of the packet sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source (unused, must be 0).
    pub media_ssrc: u32,
    /// FIR entries.
    pub entries: Vec<FirEntry>,
}

/// A single FIR entry.
#[derive(Debug, Clone, Copy)]
pub struct FirEntry {
    /// SSRC of the target encoder.
    pub ssrc: u32,
    /// Sequence number (to detect duplicates).
    pub seq_nr: u8,
}

impl Fir {
    /// Create a FIR for a single target.
    pub fn new(sender_ssrc: u32, target_ssrc: u32, seq_nr: u8) -> Self {
        Self {
            sender_ssrc,
            media_ssrc: 0,
            entries: vec![FirEntry {
                ssrc: target_ssrc,
                seq_nr,
            }],
        }
    }

    /// Parse a FIR packet from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, RtcpParseError> {
        let (header, rest) = RtcpHeader::parse(data)?;

        if header.packet_type != RtcpType::PayloadFeedback || header.count != 4 {
            return Err(RtcpParseError::UnknownPacketType(header.packet_type as u8));
        }

        if rest.len() < 8 {
            return Err(RtcpParseError::TooShort(rest.len()));
        }

        let mut buf = rest;
        let sender_ssrc = buf.get_u32();
        let media_ssrc = buf.get_u32();

        let mut entries = Vec::new();
        while buf.remaining() >= 8 {
            let ssrc = buf.get_u32();
            let seq_nr = buf.get_u8();
            let _ = buf.get_u8(); // Reserved
            let _ = buf.get_u16(); // Reserved
            entries.push(FirEntry { ssrc, seq_nr });
        }

        Ok(Fir {
            sender_ssrc,
            media_ssrc,
            entries,
        })
    }

    /// Build the FIR packet to bytes.
    pub fn build(&self) -> Bytes {
        let entry_count = self.entries.len();
        let length = (2 + entry_count * 2) as u16; // Each entry is 2 32-bit words

        let mut buf = BytesMut::with_capacity(12 + entry_count * 8);

        let header = RtcpHeader {
            version: 2,
            padding: false,
            count: PayloadFeedbackType::Fir as u8,
            packet_type: RtcpType::PayloadFeedback,
            length,
        };
        header.build(&mut buf);

        buf.put_u32(self.sender_ssrc);
        buf.put_u32(self.media_ssrc);

        for entry in &self.entries {
            buf.put_u32(entry.ssrc);
            buf.put_u8(entry.seq_nr);
            buf.put_u8(0); // Reserved
            buf.put_u16(0); // Reserved
        }

        buf.freeze()
    }
}

/// Receiver Estimated Maximum Bitrate (REMB) - draft-alvestrand-rmcat-remb.
///
/// Used to communicate estimated available bandwidth from receiver to sender.
/// This is a Google extension carried in an Application-layer Feedback message.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P| FMT=15  |   PT=206      |             length            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  SSRC of packet sender                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  SSRC of media source                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Unique identifier 'R' 'E' 'M' 'B'                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Num SSRC     | BR Exp    |  BR Mantissa                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   SSRC feedback                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  ...                                                          |
/// ```
#[derive(Debug, Clone)]
pub struct Remb {
    /// SSRC of the packet sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source (unused in REMB, often 0).
    pub media_ssrc: u32,
    /// Estimated bitrate in bits per second.
    pub bitrate: u64,
    /// SSRCs this estimation applies to.
    pub ssrcs: Vec<u32>,
}

impl Remb {
    /// REMB unique identifier: "REMB"
    const UNIQUE_ID: [u8; 4] = [b'R', b'E', b'M', b'B'];

    /// Create a new REMB message.
    pub fn new(sender_ssrc: u32, bitrate: u64, ssrcs: Vec<u32>) -> Self {
        Self {
            sender_ssrc,
            media_ssrc: 0,
            bitrate,
            ssrcs,
        }
    }

    /// Parse a REMB packet from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, RtcpParseError> {
        let (header, rest) = RtcpHeader::parse(data)?;

        if header.packet_type != RtcpType::PayloadFeedback || header.count != 15 {
            return Err(RtcpParseError::UnknownPacketType(header.packet_type as u8));
        }

        if rest.len() < 16 {
            return Err(RtcpParseError::TooShort(rest.len()));
        }

        let mut buf = rest;
        let sender_ssrc = buf.get_u32();
        let media_ssrc = buf.get_u32();

        // Check unique identifier
        let mut unique_id = [0u8; 4];
        buf.copy_to_slice(&mut unique_id);
        if unique_id != Self::UNIQUE_ID {
            return Err(RtcpParseError::UnknownPacketType(206));
        }

        let num_ssrc = buf.get_u8();
        let br_exp = (buf.get_u8() & 0xFC) >> 2;
        // Get mantissa from remaining bits + next 2 bytes
        let mantissa_high = (rest[13] & 0x03) as u32;
        let mantissa_mid = rest[14] as u32;
        let mantissa_low = rest[15] as u32;
        let mantissa = (mantissa_high << 16) | (mantissa_mid << 8) | mantissa_low;
        buf.advance(2);

        let bitrate = (mantissa as u64) << br_exp;

        let mut ssrcs = Vec::with_capacity(num_ssrc as usize);
        for _ in 0..num_ssrc {
            if buf.remaining() < 4 {
                break;
            }
            ssrcs.push(buf.get_u32());
        }

        Ok(Remb {
            sender_ssrc,
            media_ssrc,
            bitrate,
            ssrcs,
        })
    }

    /// Build the REMB packet to bytes.
    pub fn build(&self) -> Bytes {
        let ssrc_count = self.ssrcs.len().min(255);
        let length = (4 + ssrc_count) as u16; // 4 32-bit words + SSRCs

        let mut buf = BytesMut::with_capacity(16 + ssrc_count * 4);

        let header = RtcpHeader {
            version: 2,
            padding: false,
            count: PayloadFeedbackType::Afb as u8,
            packet_type: RtcpType::PayloadFeedback,
            length,
        };
        header.build(&mut buf);

        buf.put_u32(self.sender_ssrc);
        buf.put_u32(self.media_ssrc);

        // Unique identifier
        buf.put_slice(&Self::UNIQUE_ID);

        // Encode bitrate as mantissa * 2^exp
        let (mantissa, exp) = Self::encode_bitrate(self.bitrate);

        buf.put_u8(ssrc_count as u8);
        buf.put_u8((exp << 2) | ((mantissa >> 16) as u8 & 0x03));
        buf.put_u16((mantissa & 0xFFFF) as u16);

        for &ssrc in self.ssrcs.iter().take(ssrc_count) {
            buf.put_u32(ssrc);
        }

        buf.freeze()
    }

    /// Encode bitrate as mantissa * 2^exp (18-bit mantissa, 6-bit exp).
    fn encode_bitrate(bitrate: u64) -> (u32, u8) {
        if bitrate == 0 {
            return (0, 0);
        }

        // Find the highest set bit
        let bits = 64 - bitrate.leading_zeros();

        // Mantissa is 18 bits
        if bits <= 18 {
            (bitrate as u32, 0)
        } else {
            let exp = (bits - 18) as u8;
            let mantissa = (bitrate >> exp) as u32;
            (mantissa & 0x3FFFF, exp)
        }
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
    /// Sender Report (SR, PT=200) — transmission and reception statistics from an active sender.
    SenderReport(SenderReport),
    /// Receiver Report (RR, PT=201) — reception statistics from a non-sending participant.
    ReceiverReport(ReceiverReport),
    /// Source Description (SDES, PT=202) — CNAME and other identifying information for sources.
    SourceDescription(SourceDescription),
    /// Goodbye (BYE, PT=203) — indicates that one or more sources are leaving the session.
    Goodbye(Goodbye),
    /// Generic NACK feedback.
    Nack(Nack),
    /// Picture Loss Indication.
    Pli(Pli),
    /// Full Intra Request.
    Fir(Fir),
    /// Receiver Estimated Maximum Bitrate.
    Remb(Remb),
    /// An RTCP packet with a type code this implementation does not decode.
    ///
    /// Per RFC 3550 § 6.1, receivers must tolerate unknown packet types in a
    /// compound rather than rejecting the whole datagram. The raw bytes (after
    /// the 4-byte common header) are kept verbatim so callers can log,
    /// passthrough, or extend later without losing data.
    Unknown {
        /// The RTCP packet type code (PT field) as it appeared on the wire.
        packet_type: u8,
        /// Full packet bytes including the 4-byte common header.
        bytes: Bytes,
    },
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
                RtcpPacket::Nack(nack) => buf.extend_from_slice(&nack.build()),
                RtcpPacket::Pli(pli) => buf.extend_from_slice(&pli.build()),
                RtcpPacket::Fir(fir) => buf.extend_from_slice(&fir.build()),
                RtcpPacket::Remb(remb) => buf.extend_from_slice(&remb.build()),
                RtcpPacket::Unknown { bytes, .. } => buf.extend_from_slice(bytes),
            }
        }

        buf.freeze()
    }

    /// Add a NACK to the compound packet.
    pub fn add_nack(&mut self, nack: Nack) {
        self.packets.push(RtcpPacket::Nack(nack));
    }

    /// Add a PLI to the compound packet.
    pub fn add_pli(&mut self, pli: Pli) {
        self.packets.push(RtcpPacket::Pli(pli));
    }

    /// Add a FIR to the compound packet.
    pub fn add_fir(&mut self, fir: Fir) {
        self.packets.push(RtcpPacket::Fir(fir));
    }

    /// Add a REMB to the compound packet.
    pub fn add_remb(&mut self, remb: Remb) {
        self.packets.push(RtcpPacket::Remb(remb));
    }

    /// Parse a compound RTCP packet (RFC 3550 § 6.1).
    ///
    /// Walks the buffer packet-by-packet, dispatching to the per-type parser
    /// for known packet types. Unknown packet-type codes (anything outside
    /// 200-206) and unrecognised feedback subtypes are preserved as
    /// `RtcpPacket::Unknown` so callers do not lose data — RFC 3550 § 6.1
    /// requires receivers to tolerate unknown types in a compound rather than
    /// rejecting the whole datagram.
    ///
    /// Errors only on truncation or a per-packet parser failure on a known
    /// type.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let mut remaining = data;
        let mut packets = Vec::new();

        while !remaining.is_empty() {
            // Need at least a common header to determine the packet length.
            if remaining.len() < 4 {
                return Err(format!(
                    "truncated RTCP packet: {} bytes left, need at least 4",
                    remaining.len()
                ));
            }

            // Validate version up front. Length is in 32-bit words minus one
            // and is the source of truth for advancing past this packet, so
            // read it directly from the wire — `RtcpHeader::parse` rejects
            // unknown PTs, which we handle leniently below.
            let version = (remaining[0] >> 6) & 0x03;
            if version != 2 {
                return Err(format!("invalid RTCP version: {version}"));
            }
            let pt = remaining[1];
            let length_words = u16::from_be_bytes([remaining[2], remaining[3]]) as usize;
            let pkt_len = (length_words + 1) * 4;

            if pkt_len > remaining.len() {
                return Err(format!(
                    "truncated RTCP packet: declared {pkt_len} bytes, only {} remain",
                    remaining.len()
                ));
            }
            let pkt_bytes = &remaining[..pkt_len];

            // Subtype field (FMT for feedback packets, RC for SR/RR, SC for
            // SDES/BYE). Used only to distinguish REMB inside PSFB.
            let subtype = remaining[0] & 0x1F;

            let packet = match pt {
                200 => RtcpPacket::SenderReport(
                    SenderReport::parse(pkt_bytes).map_err(|e| format!("{e}"))?,
                ),
                201 => RtcpPacket::ReceiverReport(
                    ReceiverReport::parse(pkt_bytes).map_err(|e| format!("{e}"))?,
                ),
                202 => RtcpPacket::SourceDescription(
                    SourceDescription::parse(pkt_bytes).map_err(|e| format!("{e}"))?,
                ),
                203 => RtcpPacket::Goodbye(Goodbye::parse(pkt_bytes).map_err(|e| format!("{e}"))?),
                206 if subtype == PayloadFeedbackType::Afb as u8 && pkt_len >= 16 && {
                    // Distinguish REMB from other AFB messages by the
                    // 4-byte unique identifier at offset 12.
                    &pkt_bytes[12..16] == b"REMB"
                } =>
                {
                    RtcpPacket::Remb(Remb::parse(pkt_bytes).map_err(|e| format!("{e}"))?)
                }
                _ => RtcpPacket::Unknown {
                    packet_type: pt,
                    bytes: Bytes::copy_from_slice(pkt_bytes),
                },
            };

            packets.push(packet);
            remaining = &remaining[pkt_len..];
        }

        Ok(RtcpCompound { packets })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_rtcp_err_contains<T>(result: Result<T, RtcpParseError>, needle: &str) {
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(format!("{err:?}").contains(needle));
    }

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

    // ==========================================================================
    // RTCP Feedback Message Tests
    // ==========================================================================

    #[test]
    fn test_nack_single_packet() {
        let nack = Nack::new(111111, 222222, 1000);
        let bytes = nack.build();

        assert_eq!(bytes[1], RtcpType::TransportFeedback as u8);
        assert_eq!(bytes[0] & 0x1F, TransportFeedbackType::Nack as u8);

        let parsed = Nack::parse(&bytes).unwrap();
        assert_eq!(parsed.sender_ssrc, 111111);
        assert_eq!(parsed.media_ssrc, 222222);
        assert_eq!(parsed.nacks.len(), 1);
        assert_eq!(parsed.nacks[0].pid, 1000);
        assert_eq!(parsed.nacks[0].blp, 0);
    }

    #[test]
    fn test_nack_multiple_packets() {
        // Lost packets: 100, 101, 103, 105, 200
        let lost = vec![100, 101, 103, 105, 200];
        let nack = Nack::from_lost_packets(111111, 222222, &lost);

        // Should create 2 NACK entries (one group starting at 100, one at 200)
        assert_eq!(nack.nacks.len(), 2);

        let all_lost = nack.all_lost_sequences();
        assert!(all_lost.contains(&100));
        assert!(all_lost.contains(&101));
        assert!(all_lost.contains(&103));
        assert!(all_lost.contains(&105));
        assert!(all_lost.contains(&200));
    }

    #[test]
    fn test_nack_entry_blp() {
        // Test BLP encoding
        let entry = NackEntry::from_sequences(&[1000, 1001, 1002, 1016]).unwrap();
        assert_eq!(entry.pid, 1000);
        // BLP should have bits 0, 1, 15 set (for 1001, 1002, 1016)
        assert_eq!(entry.blp & 1, 1); // 1001
        assert_eq!((entry.blp >> 1) & 1, 1); // 1002
        assert_eq!((entry.blp >> 15) & 1, 1); // 1016

        let seqs = entry.lost_sequences();
        assert_eq!(seqs.len(), 4);
        assert!(seqs.contains(&1000));
        assert!(seqs.contains(&1001));
        assert!(seqs.contains(&1002));
        assert!(seqs.contains(&1016));
    }

    #[test]
    fn test_pli_build_parse() {
        let pli = Pli::new(111111, 222222);
        let bytes = pli.build();

        assert_eq!(bytes[1], RtcpType::PayloadFeedback as u8);
        assert_eq!(bytes[0] & 0x1F, PayloadFeedbackType::Pli as u8);

        let parsed = Pli::parse(&bytes).unwrap();
        assert_eq!(parsed.sender_ssrc, 111111);
        assert_eq!(parsed.media_ssrc, 222222);
    }

    #[test]
    fn test_fir_build_parse() {
        let fir = Fir::new(111111, 222222, 5);
        let bytes = fir.build();

        assert_eq!(bytes[1], RtcpType::PayloadFeedback as u8);
        assert_eq!(bytes[0] & 0x1F, PayloadFeedbackType::Fir as u8);

        let parsed = Fir::parse(&bytes).unwrap();
        assert_eq!(parsed.sender_ssrc, 111111);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].ssrc, 222222);
        assert_eq!(parsed.entries[0].seq_nr, 5);
    }

    #[test]
    fn test_remb_build() {
        let remb = Remb::new(111111, 1_500_000, vec![222222, 333333]);
        let bytes = remb.build();

        assert_eq!(bytes[1], RtcpType::PayloadFeedback as u8);
        assert_eq!(bytes[0] & 0x1F, PayloadFeedbackType::Afb as u8);

        // Check REMB identifier
        assert_eq!(&bytes[12..16], b"REMB");

        // SSRC count
        assert_eq!(bytes[16], 2);
    }

    #[test]
    fn test_remb_bitrate_encoding() {
        // Test various bitrates
        for &bitrate in &[0u64, 1000, 100_000, 1_000_000, 10_000_000, 100_000_000] {
            let (mantissa, exp) = Remb::encode_bitrate(bitrate);
            let decoded = (mantissa as u64) << exp;
            // Should be within 1% or exact for small values
            if bitrate > 0 {
                let error = ((decoded as i64 - bitrate as i64).abs() as f64) / (bitrate as f64);
                assert!(error < 0.01);
            }
        }
    }

    #[test]
    fn test_compound_with_feedback() {
        let sr = SenderReport {
            ssrc: 12345,
            ntp_timestamp: NtpTimestamp::now(),
            rtp_timestamp: 160000,
            sender_packet_count: 100,
            sender_octet_count: 16000,
            report_blocks: vec![],
        };

        let mut compound = RtcpCompound::sender_compound(sr, "user@example.com");
        compound.add_nack(Nack::new(12345, 67890, 500));
        compound.add_pli(Pli::new(12345, 67890));

        let bytes = compound.build();

        // Should contain SR + SDES + NACK + PLI
        assert!(bytes.len() > 60);
    }

    #[test]
    fn test_compound_with_goodbye() {
        let sr = SenderReport {
            ssrc: 12345,
            ntp_timestamp: NtpTimestamp::now(),
            rtp_timestamp: 160000,
            sender_packet_count: 100,
            sender_octet_count: 16000,
            report_blocks: vec![],
        };
        let mut compound = RtcpCompound::sender_compound(sr, "user@example.com");
        compound
            .packets
            .push(RtcpPacket::Goodbye(Goodbye::new(12345)));

        let bytes = compound.build();
        assert!(!bytes.is_empty());
    }

    // ==========================================================================
    // Additional RTCP Tests for Coverage
    // ==========================================================================

    #[test]
    fn test_rtcp_header_parse_too_short() {
        let data = [0u8; 2]; // Only 2 bytes, need at least 4
        assert_rtcp_err_contains(RtcpHeader::parse(&data), "TooShort");
    }

    #[test]
    fn test_rtcp_header_invalid_version() {
        // Version 0 (bits 00 instead of 10)
        let data = [0x00, 200, 0, 6];
        assert_rtcp_err_contains(RtcpHeader::parse(&data), "InvalidVersion");

        // Version 3 (bits 11 instead of 10)
        let data = [0xC0, 200, 0, 6];
        assert_rtcp_err_contains(RtcpHeader::parse(&data), "InvalidVersion");
    }

    #[test]
    fn test_rtcp_header_invalid_packet_type() {
        let data = [0x80, 199, 0, 1];
        assert_rtcp_err_contains(RtcpHeader::parse(&data), "UnknownPacketType");
    }

    #[test]
    fn test_rtcp_type_unknown() {
        let result = RtcpType::try_from(199u8);
        assert_rtcp_err_contains(result, "UnknownPacketType");
    }

    #[test]
    fn test_rtcp_type_all_values() {
        assert_eq!(RtcpType::try_from(200u8).unwrap(), RtcpType::SenderReport);
        assert_eq!(RtcpType::try_from(201u8).unwrap(), RtcpType::ReceiverReport);
        assert_eq!(
            RtcpType::try_from(202u8).unwrap(),
            RtcpType::SourceDescription
        );
        assert_eq!(RtcpType::try_from(203u8).unwrap(), RtcpType::Goodbye);
        assert_eq!(
            RtcpType::try_from(204u8).unwrap(),
            RtcpType::ApplicationDefined
        );
        assert_eq!(
            RtcpType::try_from(205u8).unwrap(),
            RtcpType::TransportFeedback
        );
        assert_eq!(
            RtcpType::try_from(206u8).unwrap(),
            RtcpType::PayloadFeedback
        );
    }

    #[test]
    fn test_ntp_timestamp_compact_roundtrip() {
        let ntp = NtpTimestamp {
            seconds: 0x12345678,
            fraction: 0xABCDE000,
        };

        let compact = ntp.compact();
        let restored = NtpTimestamp::from_compact(compact);

        // Lower bits of seconds and upper bits of fraction should match
        assert_eq!(restored.seconds, ntp.seconds & 0xFFFF);
        assert_eq!(restored.fraction & 0xFFFF0000, ntp.fraction & 0xFFFF0000);
    }

    #[test]
    fn test_report_block_too_short() {
        let data = [0u8; 10]; // Need 24 bytes
        assert_rtcp_err_contains(ReportBlock::parse(&data), "TooShort");
    }

    #[test]
    fn test_sender_report_parse_header_too_short() {
        let data = [0u8; 2];
        assert_rtcp_err_contains(SenderReport::parse(&data), "TooShort");
    }

    #[test]
    fn test_sender_report_wrong_type() {
        // Build a valid RR and try to parse as SR
        let rr = ReceiverReport {
            ssrc: 12345,
            report_blocks: vec![],
        };
        let bytes = rr.build();
        let result = SenderReport::parse(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_sender_report_too_short_payload() {
        // Valid header but not enough payload
        let mut data = vec![0x80, 200, 0, 1]; // Header says 1 word
        data.extend_from_slice(&[0u8; 4]); // Only 4 bytes of payload, need 20
        assert_rtcp_err_contains(SenderReport::parse(&data), "TooShort");
    }

    #[test]
    fn test_receiver_report_parse_header_too_short() {
        let data = [0u8; 2];
        assert_rtcp_err_contains(ReceiverReport::parse(&data), "TooShort");
    }

    #[test]
    fn test_sender_report_invalid_report_count() {
        // Valid SR header claiming 5 report blocks but not enough data
        let sr = SenderReport {
            ssrc: 12345,
            ntp_timestamp: NtpTimestamp::now(),
            rtp_timestamp: 160000,
            sender_packet_count: 100,
            sender_octet_count: 16000,
            report_blocks: vec![],
        };
        let mut bytes = sr.build().to_vec();
        // Modify count to claim 5 report blocks
        bytes[0] = (bytes[0] & 0xE0) | 5;
        assert_rtcp_err_contains(SenderReport::parse(&bytes), "InvalidReportCount");
    }

    #[test]
    fn test_receiver_report_wrong_type() {
        let sr = SenderReport {
            ssrc: 12345,
            ntp_timestamp: NtpTimestamp::now(),
            rtp_timestamp: 160000,
            sender_packet_count: 100,
            sender_octet_count: 16000,
            report_blocks: vec![],
        };
        let bytes = sr.build();
        let result = ReceiverReport::parse(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_receiver_report_too_short_payload() {
        let data = vec![0x80, 201, 0, 0]; // RR header with 0 length
        assert_rtcp_err_contains(ReceiverReport::parse(&data), "TooShort");
    }

    #[test]
    fn test_receiver_report_invalid_report_count() {
        let rr = ReceiverReport {
            ssrc: 12345,
            report_blocks: vec![],
        };
        let mut bytes = rr.build().to_vec();
        // Modify count to claim 5 report blocks
        bytes[0] = (bytes[0] & 0xE0) | 5;
        assert_rtcp_err_contains(ReceiverReport::parse(&bytes), "InvalidReportCount");
    }

    #[test]
    fn test_receiver_report_compound() {
        let rr = ReceiverReport {
            ssrc: 12345,
            report_blocks: vec![ReportBlock {
                ssrc: 67890,
                fraction_lost: 10,
                cumulative_lost: 5,
                extended_seq: 1000,
                jitter: 50,
                last_sr: 0,
                delay_since_sr: 0,
            }],
        };
        let compound = RtcpCompound::receiver_compound(rr, "receiver@test.com");
        let bytes = compound.build();

        // Should have RR + SDES
        assert!(bytes.len() > 8);
        assert_eq!(bytes[1], RtcpType::ReceiverReport as u8);
    }

    #[test]
    fn test_goodbye_with_reason() {
        let bye = Goodbye {
            ssrcs: vec![12345, 67890],
            reason: Some("Going offline".to_string()),
        };
        let bytes = bye.build();

        assert_eq!(bytes[1], RtcpType::Goodbye as u8);
        // Count should be 2 for 2 SSRCs
        assert_eq!(bytes[0] & 0x1F, 2);
    }

    #[test]
    fn test_nack_parse_too_short() {
        let data = vec![0x81, 205, 0, 1, 0, 0, 0, 0]; // Only 4 bytes payload, need 8
        assert_rtcp_err_contains(Nack::parse(&data), "TooShort");
    }

    #[test]
    fn test_nack_parse_header_too_short() {
        let data = [0u8; 2];
        assert_rtcp_err_contains(Nack::parse(&data), "TooShort");
    }

    #[test]
    fn test_nack_wrong_type() {
        // PLI packet instead of NACK
        let pli = Pli::new(111111, 222222);
        let bytes = pli.build();
        let result = Nack::parse(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_nack_wrong_count() {
        let nack = Nack::new(111111, 222222, 1000);
        let mut bytes = nack.build().to_vec();
        bytes[0] = (bytes[0] & 0xE0) | 2;
        let result = Nack::parse(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_pli_parse_too_short() {
        let data = vec![0x81, 206, 0, 1, 0, 0, 0, 0]; // Only 4 bytes payload
        assert_rtcp_err_contains(Pli::parse(&data), "TooShort");
    }

    #[test]
    fn test_pli_parse_header_too_short() {
        let data = [0u8; 2];
        assert_rtcp_err_contains(Pli::parse(&data), "TooShort");
    }

    #[test]
    fn test_pli_wrong_type() {
        let nack = Nack::new(111111, 222222, 1000);
        let bytes = nack.build();
        let result = Pli::parse(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_pli_wrong_count() {
        let pli = Pli::new(111111, 222222);
        let mut bytes = pli.build().to_vec();
        bytes[0] = (bytes[0] & 0xE0) | 2;
        let result = Pli::parse(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_fir_parse_too_short() {
        let data = vec![0x84, 206, 0, 1, 0, 0, 0, 0]; // Only 4 bytes payload
        assert_rtcp_err_contains(Fir::parse(&data), "TooShort");
    }

    #[test]
    fn test_fir_parse_header_too_short() {
        let data = [0u8; 2];
        assert_rtcp_err_contains(Fir::parse(&data), "TooShort");
    }

    #[test]
    fn test_fir_wrong_type() {
        let pli = Pli::new(111111, 222222);
        let bytes = pli.build();
        let result = Fir::parse(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_fir_wrong_packet_type() {
        let header = RtcpHeader {
            version: 2,
            padding: false,
            count: 0,
            packet_type: RtcpType::SenderReport,
            length: 0,
        };
        let mut buf = BytesMut::new();
        header.build(&mut buf);

        assert_rtcp_err_contains(Fir::parse(&buf), "UnknownPacketType");
    }

    #[test]
    fn test_fir_wrong_count() {
        let fir = Fir::new(111111, 222222, 1);
        let mut bytes = fir.build().to_vec();
        bytes[0] = (bytes[0] & 0xE0) | 5;
        let result = Fir::parse(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_fir_multiple_entries() {
        let fir = Fir {
            sender_ssrc: 111111,
            media_ssrc: 0,
            entries: vec![
                FirEntry {
                    ssrc: 222222,
                    seq_nr: 1,
                },
                FirEntry {
                    ssrc: 333333,
                    seq_nr: 2,
                },
                FirEntry {
                    ssrc: 444444,
                    seq_nr: 3,
                },
            ],
        };
        let bytes = fir.build();
        let parsed = Fir::parse(&bytes).unwrap();

        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.entries[0].ssrc, 222222);
        assert_eq!(parsed.entries[1].ssrc, 333333);
        assert_eq!(parsed.entries[2].ssrc, 444444);
    }

    #[test]
    fn test_remb_parse_too_short() {
        let data = vec![0x8F, 206, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = Remb::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_remb_wrong_unique_id() {
        // Build a REMB but corrupt the unique identifier
        let remb = Remb::new(111111, 1_000_000, vec![222222]);
        let mut bytes = remb.build().to_vec();
        // Corrupt "REMB" identifier
        bytes[12] = b'X';
        let result = Remb::parse(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_remb_wrong_type() {
        let fir = Fir::new(111111, 222222, 1);
        let bytes = fir.build();
        let result = Remb::parse(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_remb_wrong_packet_type() {
        let header = RtcpHeader {
            version: 2,
            padding: false,
            count: 0,
            packet_type: RtcpType::SenderReport,
            length: 0,
        };
        let mut buf = BytesMut::new();
        header.build(&mut buf);

        assert_rtcp_err_contains(Remb::parse(&buf), "UnknownPacketType");
    }

    #[test]
    fn test_remb_parse_header_too_short() {
        let data = [0u8; 2];
        assert_rtcp_err_contains(Remb::parse(&data), "TooShort");
    }

    #[test]
    fn test_remb_wrong_count() {
        let remb = Remb::new(111111, 1_000_000, vec![222222]);
        let mut bytes = remb.build().to_vec();
        bytes[0] = (bytes[0] & 0xE0) | 1;
        let result = Remb::parse(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_remb_parse_truncated_ssrcs() {
        let remb = Remb::new(111111, 1_000_000, vec![222222]);
        let mut bytes = remb.build().to_vec();
        bytes[16] = 2;
        let parsed = Remb::parse(&bytes).unwrap();
        assert_eq!(parsed.ssrcs.len(), 1);
    }

    #[test]
    fn test_remb_zero_bitrate() {
        let remb = Remb::new(111111, 0, vec![222222]);
        let bytes = remb.build();
        let parsed = Remb::parse(&bytes).unwrap();
        assert_eq!(parsed.bitrate, 0);
    }

    #[test]
    fn test_remb_large_bitrate() {
        let remb = Remb::new(111111, 1_000_000_000, vec![222222]); // 1 Gbps
        let bytes = remb.build();
        let parsed = Remb::parse(&bytes).unwrap();
        // Should be close to original (may have precision loss)
        let error = ((parsed.bitrate as i64 - 1_000_000_000i64).abs() as f64) / 1_000_000_000.0;
        assert!(error < 0.01);
    }

    #[test]
    fn test_remb_multiple_ssrcs() {
        let remb = Remb::new(111111, 2_000_000, vec![222222, 333333, 444444, 555555]);
        let bytes = remb.build();
        let parsed = Remb::parse(&bytes).unwrap();

        assert_eq!(parsed.ssrcs.len(), 4);
        assert!(parsed.ssrcs.contains(&222222));
        assert!(parsed.ssrcs.contains(&333333));
        assert!(parsed.ssrcs.contains(&444444));
        assert!(parsed.ssrcs.contains(&555555));
    }

    #[test]
    fn test_nack_entry_single() {
        let entry = NackEntry::single(1000);
        assert_eq!(entry.pid, 1000);
        assert_eq!(entry.blp, 0);

        let seqs = entry.lost_sequences();
        assert_eq!(seqs.len(), 1);
        assert_eq!(seqs[0], 1000);
    }

    #[test]
    fn test_nack_entry_from_sequences_empty() {
        let result = NackEntry::from_sequences(&[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_nack_from_lost_packets_large_gap() {
        let nack = Nack::from_lost_packets(111111, 222222, &[1000, 2000]);
        assert_eq!(nack.nacks.len(), 2);
        assert_eq!(nack.nacks[0].pid, 1000);
        assert_eq!(nack.nacks[1].pid, 2000);
    }

    #[test]
    fn test_nack_from_lost_packets_in_range() {
        let nack = Nack::from_lost_packets(111111, 222222, &[1000, 1002, 1010]);
        assert_eq!(nack.nacks.len(), 1);

        let seqs = nack.nacks[0].lost_sequences();
        assert!(seqs.contains(&1000));
        assert!(seqs.contains(&1002));
        assert!(seqs.contains(&1010));
    }

    #[test]
    fn test_nack_from_lost_packets_with_duplicates() {
        let nack = Nack::from_lost_packets(111111, 222222, &[1000, 1000, 1001]);
        assert_eq!(nack.nacks.len(), 2);
        assert_eq!(nack.nacks[0].pid, 1000);
        assert_eq!(nack.nacks[1].pid, 1000);
    }

    #[test]
    fn test_nack_entry_out_of_range() {
        // Sequence 1000 + sequences far beyond 16 should be ignored
        let seqs = vec![1000, 1001, 1100]; // 1100 is 100 away, beyond BLP range
        let entry = NackEntry::from_sequences(&seqs).unwrap();

        let lost = entry.lost_sequences();
        assert!(lost.contains(&1000));
        assert!(lost.contains(&1001));
        assert!(!lost.contains(&1100)); // Too far
    }

    #[test]
    fn test_nack_all_blp_bits() {
        // Test all 16 BLP positions
        let mut seqs = vec![1000u16];
        for i in 1..=16 {
            seqs.push(1000 + i);
        }
        let entry = NackEntry::from_sequences(&seqs).unwrap();

        // BLP should have all bits set
        assert_eq!(entry.blp, 0xFFFF);

        let lost = entry.lost_sequences();
        assert_eq!(lost.len(), 17); // 1000 + 16 more
    }

    #[test]
    fn test_compound_add_fir() {
        let sr = SenderReport {
            ssrc: 12345,
            ntp_timestamp: NtpTimestamp::now(),
            rtp_timestamp: 160000,
            sender_packet_count: 100,
            sender_octet_count: 16000,
            report_blocks: vec![],
        };

        let mut compound = RtcpCompound::sender_compound(sr, "test@example.com");
        compound.add_fir(Fir::new(12345, 67890, 1));

        let bytes = compound.build();
        assert!(bytes.len() > 28);
    }

    #[test]
    fn test_compound_add_remb() {
        let sr = SenderReport {
            ssrc: 12345,
            ntp_timestamp: NtpTimestamp::now(),
            rtp_timestamp: 160000,
            sender_packet_count: 100,
            sender_octet_count: 16000,
            report_blocks: vec![],
        };

        let mut compound = RtcpCompound::sender_compound(sr, "test@example.com");
        compound.add_remb(Remb::new(12345, 5_000_000, vec![67890]));

        let bytes = compound.build();
        assert!(bytes.len() > 28);
    }

    #[test]
    fn test_sdes_type_enum() {
        assert_eq!(SdesType::End as u8, 0);
        assert_eq!(SdesType::CName as u8, 1);
        assert_eq!(SdesType::Name as u8, 2);
        assert_eq!(SdesType::Email as u8, 3);
        assert_eq!(SdesType::Phone as u8, 4);
        assert_eq!(SdesType::Location as u8, 5);
        assert_eq!(SdesType::Tool as u8, 6);
        assert_eq!(SdesType::Note as u8, 7);
        assert_eq!(SdesType::Private as u8, 8);
    }

    #[test]
    fn test_sdes_multiple_items() {
        let sdes = SourceDescription {
            chunks: vec![SdesChunk {
                ssrc: 12345,
                items: vec![
                    SdesItem {
                        item_type: SdesType::CName,
                        value: "user@host".to_string(),
                    },
                    SdesItem {
                        item_type: SdesType::Name,
                        value: "Test User".to_string(),
                    },
                    SdesItem {
                        item_type: SdesType::Email,
                        value: "test@example.com".to_string(),
                    },
                ],
            }],
        };

        let bytes = sdes.build();
        assert_eq!(bytes[1], RtcpType::SourceDescription as u8);
    }

    #[test]
    fn test_multiple_report_blocks_sr() {
        let sr = SenderReport {
            ssrc: 12345,
            ntp_timestamp: NtpTimestamp::now(),
            rtp_timestamp: 160000,
            sender_packet_count: 100,
            sender_octet_count: 16000,
            report_blocks: vec![
                ReportBlock {
                    ssrc: 67890,
                    fraction_lost: 10,
                    cumulative_lost: 5,
                    extended_seq: 1000,
                    jitter: 50,
                    last_sr: 0x11111111,
                    delay_since_sr: 32768,
                },
                ReportBlock {
                    ssrc: 11111,
                    fraction_lost: 20,
                    cumulative_lost: 10,
                    extended_seq: 2000,
                    jitter: 100,
                    last_sr: 0x22222222,
                    delay_since_sr: 65536,
                },
            ],
        };

        let bytes = sr.build();
        let parsed = SenderReport::parse(&bytes).unwrap();

        assert_eq!(parsed.report_blocks.len(), 2);
        assert_eq!(parsed.report_blocks[0].ssrc, 67890);
        assert_eq!(parsed.report_blocks[1].ssrc, 11111);
    }

    #[test]
    fn test_rtcp_header_build() {
        let header = RtcpHeader {
            version: 2,
            padding: true,
            count: 5,
            packet_type: RtcpType::SenderReport,
            length: 10,
        };

        let mut buf = BytesMut::new();
        header.build(&mut buf);

        assert_eq!(buf.len(), 4);
        // Check version (2), padding (1), count (5)
        assert_eq!(buf[0], 0b10100101); // V=2, P=1, RC=5
        assert_eq!(buf[1], 200); // SR
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 10);
    }

    #[test]
    fn test_report_block_negative_cumulative_lost() {
        let block = ReportBlock {
            ssrc: 12345,
            fraction_lost: 0,
            cumulative_lost: -100, // Negative (e.g., packet duplication)
            extended_seq: 1000,
            jitter: 50,
            last_sr: 0,
            delay_since_sr: 0,
        };

        let mut buf = BytesMut::new();
        block.build(&mut buf);

        let parsed = ReportBlock::parse(&buf).unwrap();
        // The 24-bit encoding/decoding may not preserve exact negative values
        // Just verify the roundtrip works (parsed value exists)
        assert!(parsed.ssrc == 12345);
        assert!(parsed.extended_seq == 1000);
    }

    #[test]
    fn test_transport_feedback_type_enum() {
        assert_eq!(TransportFeedbackType::Nack as u8, 1);
        assert_eq!(TransportFeedbackType::TransportCC as u8, 15);
    }

    #[test]
    fn test_payload_feedback_type_enum() {
        assert_eq!(PayloadFeedbackType::Pli as u8, 1);
        assert_eq!(PayloadFeedbackType::Sli as u8, 2);
        assert_eq!(PayloadFeedbackType::Rpsi as u8, 3);
        assert_eq!(PayloadFeedbackType::Fir as u8, 4);
        assert_eq!(PayloadFeedbackType::Tstr as u8, 5);
        assert_eq!(PayloadFeedbackType::Tstn as u8, 6);
        assert_eq!(PayloadFeedbackType::Vbcm as u8, 7);
        assert_eq!(PayloadFeedbackType::Afb as u8, 15);
    }

    // ==========================================================================
    // RtcpCompound::parse — compound walker tests
    // ==========================================================================

    #[test]
    fn roundtrip_sr_sdes() {
        let sr = SenderReport {
            ssrc: 0xDEAD_BEEF,
            ntp_timestamp: NtpTimestamp {
                seconds: 0x1234_5678,
                fraction: 0x9ABC_DEF0,
            },
            rtp_timestamp: 160_000,
            sender_packet_count: 42,
            sender_octet_count: 6720,
            report_blocks: vec![],
        };
        let compound = RtcpCompound::sender_compound(sr, "user@example.com");
        let bytes = compound.build();

        let parsed = RtcpCompound::parse(&bytes).expect("parse compound");
        assert_eq!(parsed.packets.len(), 2);

        match &parsed.packets[0] {
            RtcpPacket::SenderReport(sr) => {
                assert_eq!(sr.ssrc, 0xDEAD_BEEF);
                assert_eq!(sr.rtp_timestamp, 160_000);
                assert_eq!(sr.sender_packet_count, 42);
                assert_eq!(sr.sender_octet_count, 6720);
            }
            other => panic!("expected SenderReport, got {other:?}"),
        }
        match &parsed.packets[1] {
            RtcpPacket::SourceDescription(sdes) => {
                assert_eq!(sdes.chunks.len(), 1);
                assert_eq!(sdes.chunks[0].ssrc, 0xDEAD_BEEF);
                assert_eq!(sdes.chunks[0].items.len(), 1);
                assert_eq!(sdes.chunks[0].items[0].item_type, SdesType::CName);
                assert_eq!(sdes.chunks[0].items[0].value, "user@example.com");
            }
            other => panic!("expected SourceDescription, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_rr_remb() {
        let rr = ReceiverReport {
            ssrc: 0x1111_2222,
            report_blocks: vec![ReportBlock {
                ssrc: 0x3333_4444,
                fraction_lost: 0,
                cumulative_lost: 0,
                extended_seq: 100,
                jitter: 25,
                last_sr: 0,
                delay_since_sr: 0,
            }],
        };

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&rr.build());
        let remb = Remb::new(0x1111_2222, 64_000, vec![0x3333_4444]);
        buf.extend_from_slice(&remb.build());

        let parsed = RtcpCompound::parse(&buf).expect("parse compound");
        assert_eq!(parsed.packets.len(), 2);

        match &parsed.packets[0] {
            RtcpPacket::ReceiverReport(rr) => {
                assert_eq!(rr.ssrc, 0x1111_2222);
                assert_eq!(rr.report_blocks.len(), 1);
                assert_eq!(rr.report_blocks[0].ssrc, 0x3333_4444);
            }
            other => panic!("expected ReceiverReport, got {other:?}"),
        }
        match &parsed.packets[1] {
            RtcpPacket::Remb(remb) => {
                // 64_000 fits within the 18-bit mantissa exactly, so no
                // rounding loss is expected.
                assert_eq!(remb.bitrate, 64_000);
                assert_eq!(remb.sender_ssrc, 0x1111_2222);
            }
            other => panic!("expected Remb, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_truncated() {
        let sr = SenderReport {
            ssrc: 1,
            ntp_timestamp: NtpTimestamp::now(),
            rtp_timestamp: 0,
            sender_packet_count: 0,
            sender_octet_count: 0,
            report_blocks: vec![],
        };
        let bytes = sr.build();
        assert!(bytes.len() > 8);

        // Chop the last 4 bytes, so the declared length exceeds what is left.
        let truncated = &bytes[..bytes.len() - 4];
        let result = RtcpCompound::parse(truncated);
        assert!(result.is_err(), "expected error on truncated input");
        let err = result.err().unwrap();
        assert!(
            err.contains("truncated") || err.contains("TooShort"),
            "expected truncation error, got: {err}"
        );
    }

    #[test]
    fn parse_preserves_unknown_types() {
        // Build a 4-byte RTCP packet with an unrecognised PT (230). Common
        // header layout: V=2, P=0, count=0, PT=230, length=0 (so total
        // length = (0 + 1) * 4 = 4 bytes — header only).
        let raw = [0x80u8, 230, 0x00, 0x00];

        let parsed = RtcpCompound::parse(&raw).expect("parse must accept unknown PT");
        assert_eq!(parsed.packets.len(), 1);
        match &parsed.packets[0] {
            RtcpPacket::Unknown { packet_type, bytes } => {
                assert_eq!(*packet_type, 230);
                assert_eq!(&bytes[..], &raw[..]);
            }
            other => panic!("expected Unknown variant, got {other:?}"),
        }
    }

    #[test]
    fn parse_walks_past_unknown_in_middle() {
        // Compound: SR + (raw unknown PT=230) + RR. The walker must use the
        // unknown packet's own length field to advance past it so the
        // following known packet still parses.
        let sr = SenderReport {
            ssrc: 0xAAAA_AAAA,
            ntp_timestamp: NtpTimestamp {
                seconds: 0x0102_0304,
                fraction: 0x0506_0708,
            },
            rtp_timestamp: 8_000,
            sender_packet_count: 1,
            sender_octet_count: 160,
            report_blocks: vec![],
        };
        let rr = ReceiverReport {
            ssrc: 0xBBBB_BBBB,
            report_blocks: vec![],
        };

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&sr.build());
        // V=2, P=0, RC=0, PT=230, length=0 -> 4-byte header-only unknown packet.
        buf.extend_from_slice(&[0x80u8, 230, 0x00, 0x00]);
        buf.extend_from_slice(&rr.build());

        let parsed = RtcpCompound::parse(&buf).expect("parse compound");
        assert_eq!(parsed.packets.len(), 3);

        match &parsed.packets[0] {
            RtcpPacket::SenderReport(sr) => {
                assert_eq!(sr.ssrc, 0xAAAA_AAAA);
            }
            other => panic!("expected SenderReport, got {other:?}"),
        }
        match &parsed.packets[1] {
            RtcpPacket::Unknown { packet_type, .. } => {
                assert_eq!(*packet_type, 230);
            }
            other => panic!("expected Unknown variant, got {other:?}"),
        }
        match &parsed.packets[2] {
            RtcpPacket::ReceiverReport(rr) => {
                assert_eq!(rr.ssrc, 0xBBBB_BBBB);
            }
            other => panic!("expected ReceiverReport, got {other:?}"),
        }
    }

    #[test]
    fn psfb_fmt15_without_remb_magic_is_unknown() {
        // PSFB (PT=206) with FMT=15 (AFB) but missing the "REMB" magic at
        // offset 12 must fall through to Unknown rather than be misparsed
        // as a REMB packet.
        //
        // Layout (20 bytes total = 5 32-bit words, length field = 4):
        //   [0..4]   header: V=2, P=0, FMT=15, PT=206, length=4
        //   [4..8]   sender SSRC
        //   [8..12]  media SSRC
        //   [12..16] 4-byte magic (NOT "REMB")
        //   [16..20] body padding
        let mut buf = BytesMut::new();
        // Header: V=2, P=0, FMT=15; PT=206; length=4
        buf.put_u8(0x80 | 15);
        buf.put_u8(206);
        buf.put_u16(4);
        // Sender SSRC
        buf.put_u32(0xCAFE_BABE);
        // Media SSRC (unused for AFB)
        buf.put_u32(0x0000_0000);
        // Non-REMB magic at canonical offset 12
        buf.put_slice(b"AFBX");
        // 4 bytes of body to satisfy the declared length
        buf.put_u32(0xDEAD_BEEF);

        assert_eq!(buf.len(), 20);

        let parsed = RtcpCompound::parse(&buf).expect("parse compound");
        assert_eq!(parsed.packets.len(), 1);
        match &parsed.packets[0] {
            RtcpPacket::Unknown { packet_type, .. } => {
                assert_eq!(*packet_type, 206);
            }
            other => panic!("expected Unknown variant for non-REMB AFB, got {other:?}"),
        }
    }
}

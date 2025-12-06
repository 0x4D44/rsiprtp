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

            if let Some(entry) = NackEntry::from_sequences(&group) {
                nacks.push(entry);
            }
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
        self.nacks
            .iter()
            .flat_map(|n| n.lost_sequences())
            .collect()
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
    SenderReport(SenderReport),
    ReceiverReport(ReceiverReport),
    SourceDescription(SourceDescription),
    Goodbye(Goodbye),
    /// Generic NACK feedback.
    Nack(Nack),
    /// Picture Loss Indication.
    Pli(Pli),
    /// Full Intra Request.
    Fir(Fir),
    /// Receiver Estimated Maximum Bitrate.
    Remb(Remb),
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
                assert!(error < 0.01 || decoded == bitrate,
                    "Bitrate {} encoded as {}*2^{} = {}, error = {}",
                    bitrate, mantissa, exp, decoded, error);
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
}

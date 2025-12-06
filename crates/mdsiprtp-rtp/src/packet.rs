//! RTP packet parsing and building per RFC 3550.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|X|  CC   |M|     PT      |       sequence number         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           timestamp                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           synchronization source (SSRC) identifier            |
//! +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//! |            contributing source (CSRC) identifiers             |
//! |                             ....                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// RTP header minimum size (12 bytes).
pub const RTP_HEADER_SIZE: usize = 12;

/// Maximum number of CSRC identifiers.
pub const MAX_CSRC: usize = 15;

/// RTP packet.
#[derive(Debug, Clone)]
pub struct RtpPacket {
    /// RTP version (always 2).
    pub version: u8,
    /// Padding flag.
    pub padding: bool,
    /// Extension header present.
    pub extension: bool,
    /// Marker bit.
    pub marker: bool,
    /// Payload type.
    pub payload_type: u8,
    /// Sequence number.
    pub sequence_number: u16,
    /// Timestamp.
    pub timestamp: u32,
    /// Synchronization source identifier.
    pub ssrc: u32,
    /// Contributing source identifiers.
    pub csrc: Vec<u32>,
    /// Extension header (if present).
    pub extension_header: Option<ExtensionHeader>,
    /// Payload data.
    pub payload: Bytes,
}

/// RTP extension header.
#[derive(Debug, Clone)]
pub struct ExtensionHeader {
    /// Profile-specific identifier.
    pub profile: u16,
    /// Extension data.
    pub data: Bytes,
}

/// RTP parse error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RtpParseError {
    #[error("Packet too short: {0} bytes")]
    TooShort(usize),
    #[error("Invalid RTP version: {0}")]
    InvalidVersion(u8),
    #[error("Extension header truncated")]
    ExtensionTruncated,
    #[error("Payload truncated")]
    PayloadTruncated,
}

impl RtpPacket {
    /// Parse an RTP packet from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, RtpParseError> {
        if data.len() < RTP_HEADER_SIZE {
            return Err(RtpParseError::TooShort(data.len()));
        }

        let mut buf = data;

        // First byte: V(2), P(1), X(1), CC(4)
        let first_byte = buf.get_u8();
        let version = (first_byte >> 6) & 0x03;
        let padding = (first_byte >> 5) & 0x01 == 1;
        let extension = (first_byte >> 4) & 0x01 == 1;
        let csrc_count = (first_byte & 0x0F) as usize;

        if version != 2 {
            return Err(RtpParseError::InvalidVersion(version));
        }

        // Second byte: M(1), PT(7)
        let second_byte = buf.get_u8();
        let marker = (second_byte >> 7) & 0x01 == 1;
        let payload_type = second_byte & 0x7F;

        // Sequence number
        let sequence_number = buf.get_u16();

        // Timestamp
        let timestamp = buf.get_u32();

        // SSRC
        let ssrc = buf.get_u32();

        // Check remaining length for CSRC
        let required_len = csrc_count * 4;
        if buf.remaining() < required_len {
            return Err(RtpParseError::TooShort(data.len()));
        }

        // CSRC list
        let mut csrc = Vec::with_capacity(csrc_count);
        for _ in 0..csrc_count {
            csrc.push(buf.get_u32());
        }

        // Extension header
        let extension_header = if extension {
            if buf.remaining() < 4 {
                return Err(RtpParseError::ExtensionTruncated);
            }
            let profile = buf.get_u16();
            let length = buf.get_u16() as usize * 4; // Length is in 32-bit words

            if buf.remaining() < length {
                return Err(RtpParseError::ExtensionTruncated);
            }

            let ext_data = Bytes::copy_from_slice(&buf[..length]);
            buf.advance(length);

            Some(ExtensionHeader {
                profile,
                data: ext_data,
            })
        } else {
            None
        };

        // Handle padding
        let payload_len = if padding && !buf.is_empty() {
            // Last byte contains padding count
            let padding_count = data[data.len() - 1] as usize;
            if buf.remaining() < padding_count {
                return Err(RtpParseError::PayloadTruncated);
            }
            buf.remaining() - padding_count
        } else {
            buf.remaining()
        };

        let payload = Bytes::copy_from_slice(&buf[..payload_len]);

        Ok(RtpPacket {
            version,
            padding,
            extension,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrc,
            extension_header,
            payload,
        })
    }

    /// Build an RTP packet to bytes.
    pub fn build(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(
            RTP_HEADER_SIZE
                + self.csrc.len() * 4
                + self.extension_header.as_ref().map_or(0, |e| 4 + e.data.len())
                + self.payload.len(),
        );

        // First byte: V(2), P(1), X(1), CC(4)
        let first_byte = (self.version << 6)
            | ((self.padding as u8) << 5)
            | ((self.extension_header.is_some() as u8) << 4)
            | (self.csrc.len() as u8 & 0x0F);
        buf.put_u8(first_byte);

        // Second byte: M(1), PT(7)
        let second_byte = ((self.marker as u8) << 7) | (self.payload_type & 0x7F);
        buf.put_u8(second_byte);

        // Sequence number
        buf.put_u16(self.sequence_number);

        // Timestamp
        buf.put_u32(self.timestamp);

        // SSRC
        buf.put_u32(self.ssrc);

        // CSRC list
        for &csrc in &self.csrc {
            buf.put_u32(csrc);
        }

        // Extension header
        if let Some(ref ext) = self.extension_header {
            buf.put_u16(ext.profile);
            let word_len = ext.data.len().div_ceil(4); // Round up to 32-bit words
            buf.put_u16(word_len as u16);
            buf.put_slice(&ext.data);
            // Padding to word boundary
            let padding = word_len * 4 - ext.data.len();
            for _ in 0..padding {
                buf.put_u8(0);
            }
        }

        // Payload
        buf.put_slice(&self.payload);

        buf.freeze()
    }

    /// Create a new RTP packet.
    pub fn new(payload_type: u8, sequence_number: u16, timestamp: u32, ssrc: u32) -> Self {
        Self {
            version: 2,
            padding: false,
            extension: false,
            marker: false,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrc: Vec::new(),
            extension_header: None,
            payload: Bytes::new(),
        }
    }

    /// Set the marker bit.
    pub fn with_marker(mut self, marker: bool) -> Self {
        self.marker = marker;
        self
    }

    /// Set the payload.
    pub fn with_payload(mut self, payload: impl Into<Bytes>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Add a CSRC.
    pub fn with_csrc(mut self, csrc: u32) -> Self {
        if self.csrc.len() < MAX_CSRC {
            self.csrc.push(csrc);
        }
        self
    }

    /// Get header size in bytes.
    pub fn header_size(&self) -> usize {
        RTP_HEADER_SIZE
            + self.csrc.len() * 4
            + self.extension_header.as_ref().map_or(0, |e| 4 + e.data.len().div_ceil(4) * 4)
    }
}

/// Calculate the sequence number difference handling wraparound.
pub fn sequence_diff(a: u16, b: u16) -> i32 {
    let diff = a.wrapping_sub(b) as i16;
    diff as i32
}

/// Check if sequence number a is newer than b.
pub fn sequence_newer(a: u16, b: u16) -> bool {
    sequence_diff(a, b) > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_packet() {
        // Minimal RTP packet: V=2, P=0, X=0, CC=0, M=0, PT=0, seq=1, ts=160, ssrc=12345
        let data = [
            0x80, 0x00, // V=2, P=0, X=0, CC=0, M=0, PT=0
            0x00, 0x01, // seq=1
            0x00, 0x00, 0x00, 0xA0, // timestamp=160
            0x00, 0x00, 0x30, 0x39, // ssrc=12345
            0xAA, 0xBB, 0xCC, 0xDD, // payload
        ];

        let pkt = RtpPacket::parse(&data).unwrap();
        assert_eq!(pkt.version, 2);
        assert!(!pkt.padding);
        assert!(!pkt.extension);
        assert!(!pkt.marker);
        assert_eq!(pkt.payload_type, 0);
        assert_eq!(pkt.sequence_number, 1);
        assert_eq!(pkt.timestamp, 160);
        assert_eq!(pkt.ssrc, 12345);
        assert!(pkt.csrc.is_empty());
        assert_eq!(&pkt.payload[..], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_parse_with_marker() {
        let data = [
            0x80, 0x80, // V=2, M=1, PT=0
            0x00, 0x01,
            0x00, 0x00, 0x00, 0xA0,
            0x00, 0x00, 0x30, 0x39,
        ];

        let pkt = RtpPacket::parse(&data).unwrap();
        assert!(pkt.marker);
        assert_eq!(pkt.payload_type, 0);
    }

    #[test]
    fn test_parse_with_payload_type() {
        let data = [
            0x80, 0x08, // V=2, PT=8 (PCMA)
            0x00, 0x01,
            0x00, 0x00, 0x00, 0xA0,
            0x00, 0x00, 0x30, 0x39,
        ];

        let pkt = RtpPacket::parse(&data).unwrap();
        assert_eq!(pkt.payload_type, 8);
    }

    #[test]
    fn test_build_and_parse() {
        let original = RtpPacket::new(0, 100, 1600, 0xDEADBEEF)
            .with_marker(true)
            .with_payload(vec![0x01, 0x02, 0x03, 0x04]);

        let bytes = original.build();
        let parsed = RtpPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.version, 2);
        assert!(parsed.marker);
        assert_eq!(parsed.payload_type, 0);
        assert_eq!(parsed.sequence_number, 100);
        assert_eq!(parsed.timestamp, 1600);
        assert_eq!(parsed.ssrc, 0xDEADBEEF);
        assert_eq!(&parsed.payload[..], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_with_csrc() {
        let pkt = RtpPacket::new(0, 1, 160, 12345)
            .with_csrc(11111)
            .with_csrc(22222);

        let bytes = pkt.build();
        let parsed = RtpPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.csrc.len(), 2);
        assert_eq!(parsed.csrc[0], 11111);
        assert_eq!(parsed.csrc[1], 22222);
    }

    #[test]
    fn test_sequence_diff() {
        assert_eq!(sequence_diff(10, 5), 5);
        assert_eq!(sequence_diff(5, 10), -5);
        // Wraparound
        assert_eq!(sequence_diff(0, 65535), 1);
        assert_eq!(sequence_diff(65535, 0), -1);
    }

    #[test]
    fn test_sequence_newer() {
        assert!(sequence_newer(10, 5));
        assert!(!sequence_newer(5, 10));
        assert!(sequence_newer(0, 65535)); // 0 is newer than 65535 (wrapped)
    }

    #[test]
    fn test_too_short() {
        let data = [0x80, 0x00, 0x00, 0x01];
        let result = RtpPacket::parse(&data);
        assert!(matches!(result, Err(RtpParseError::TooShort(_))));
    }

    #[test]
    fn test_invalid_version() {
        let data = [
            0x40, 0x00, // V=1 (invalid)
            0x00, 0x01,
            0x00, 0x00, 0x00, 0xA0,
            0x00, 0x00, 0x30, 0x39,
        ];
        let result = RtpPacket::parse(&data);
        assert!(matches!(result, Err(RtpParseError::InvalidVersion(1))));
    }
}

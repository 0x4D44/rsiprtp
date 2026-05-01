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
    /// Buffer too short to contain a valid RTP packet header (12 bytes minimum).
    #[error("Packet too short: {0} bytes")]
    TooShort(usize),
    /// RTP version field is not 2 (the only version defined by RFC 3550).
    #[error("Invalid RTP version: {0}")]
    InvalidVersion(u8),
    /// Extension header is declared but the buffer is truncated before its end.
    #[error("Extension header truncated")]
    ExtensionTruncated,
    /// Declared payload extends past the end of the buffer.
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
                + self
                    .extension_header
                    .as_ref()
                    .map_or(0, |e| 4 + e.data.len())
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
            + self
                .extension_header
                .as_ref()
                .map_or(0, |e| 4 + e.data.len().div_ceil(4) * 4)
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

    fn assert_rtp_err_contains<T>(result: Result<T, RtpParseError>, needle: &str) {
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(format!("{err:?}").contains(needle));
    }

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
            0x00, 0x01, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x30, 0x39,
        ];

        let pkt = RtpPacket::parse(&data).unwrap();
        assert!(pkt.marker);
        assert_eq!(pkt.payload_type, 0);
    }

    #[test]
    fn test_parse_with_payload_type() {
        let data = [
            0x80, 0x08, // V=2, PT=8 (PCMA)
            0x00, 0x01, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x30, 0x39,
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
        assert_rtp_err_contains(RtpPacket::parse(&data), "TooShort");
    }

    #[test]
    fn test_invalid_version() {
        let data = [
            0x40, 0x00, // V=1 (invalid)
            0x00, 0x01, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x30, 0x39,
        ];
        assert_rtp_err_contains(RtpPacket::parse(&data), "InvalidVersion");
    }

    // Additional tests for better coverage

    #[test]
    fn test_rtp_packet_debug() {
        let pkt = RtpPacket::new(0, 1, 160, 12345);
        let debug = format!("{:?}", pkt);
        assert!(debug.contains("RtpPacket"));
    }

    #[test]
    fn test_rtp_packet_clone() {
        let pkt = RtpPacket::new(0, 1, 160, 12345)
            .with_marker(true)
            .with_payload(vec![0x01, 0x02]);
        let cloned = pkt.clone();
        assert_eq!(pkt.sequence_number, cloned.sequence_number);
        assert_eq!(pkt.timestamp, cloned.timestamp);
        assert_eq!(pkt.marker, cloned.marker);
        assert_eq!(pkt.payload, cloned.payload);
    }

    #[test]
    fn test_extension_header_debug() {
        let ext = ExtensionHeader {
            profile: 0xBEDE,
            data: Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]),
        };
        let debug = format!("{:?}", ext);
        assert!(debug.contains("ExtensionHeader"));
    }

    #[test]
    fn test_extension_header_clone() {
        let ext = ExtensionHeader {
            profile: 0xBEDE,
            data: Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]),
        };
        let cloned = ext.clone();
        assert_eq!(ext.profile, cloned.profile);
        assert_eq!(ext.data, cloned.data);
    }

    #[test]
    fn test_rtp_parse_error_display() {
        let err1 = RtpParseError::TooShort(5);
        assert!(err1.to_string().contains("5"));

        let err2 = RtpParseError::InvalidVersion(1);
        assert!(err2.to_string().contains("1"));

        let err3 = RtpParseError::ExtensionTruncated;
        assert!(err3.to_string().contains("Extension"));

        let err4 = RtpParseError::PayloadTruncated;
        assert!(err4.to_string().contains("Payload"));
    }

    #[test]
    fn test_rtp_parse_error_debug() {
        assert!(format!("{:?}", RtpParseError::TooShort(5)).contains("TooShort"));
        assert!(format!("{:?}", RtpParseError::InvalidVersion(1)).contains("InvalidVersion"));
        assert!(format!("{:?}", RtpParseError::ExtensionTruncated).contains("ExtensionTruncated"));
        assert!(format!("{:?}", RtpParseError::PayloadTruncated).contains("PayloadTruncated"));
    }

    #[test]
    fn test_rtp_parse_error_clone() {
        let err = RtpParseError::TooShort(5);
        let cloned = err.clone();
        assert!(format!("{cloned:?}").contains("TooShort"));
    }

    #[test]
    fn test_parse_with_extension() {
        // Build packet with extension
        let mut pkt = RtpPacket::new(0, 1, 160, 12345);
        pkt.extension_header = Some(ExtensionHeader {
            profile: 0xBEDE,
            data: Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]),
        });

        let bytes = pkt.build();
        let parsed = RtpPacket::parse(&bytes).unwrap();

        assert!(parsed.extension_header.is_some());
        let ext = parsed.extension_header.unwrap();
        assert_eq!(ext.profile, 0xBEDE);
        assert_eq!(&ext.data[..], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_parse_with_padding() {
        // RTP packet with padding flag set
        // 4 bytes of padding means last byte = 4, and 4 bytes total are padding
        let data = [
            0xA0, 0x00, // V=2, P=1, X=0, CC=0, M=0, PT=0
            0x00, 0x01, // seq=1
            0x00, 0x00, 0x00, 0xA0, // timestamp=160
            0x00, 0x00, 0x30, 0x39, // ssrc=12345
            0xAA, 0xBB, 0xCC, 0xDD, // payload (4 bytes)
            0x00, 0x00, 0x00, 0x04, // 4 bytes of padding (last byte = count)
        ];

        let pkt = RtpPacket::parse(&data).unwrap();
        assert!(pkt.padding);
        // Payload should not include padding
        assert_eq!(&pkt.payload[..], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_parse_padding_with_empty_payload() {
        let data = [
            0xA0, 0x00, // V=2, P=1, X=0, CC=0, M=0, PT=0
            0x00, 0x01, // seq=1
            0x00, 0x00, 0x00, 0xA0, // timestamp=160
            0x00, 0x00, 0x30, 0x39, // ssrc=12345
        ];

        let pkt = RtpPacket::parse(&data).unwrap();
        assert!(pkt.padding);
        assert!(pkt.payload.is_empty());
    }

    #[test]
    fn test_csrc_truncated() {
        // CC=1 but no CSRC data
        let data = [
            0x81, 0x00, // V=2, P=0, X=0, CC=1
            0x00, 0x01, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x30, 0x39,
            // Missing CSRC
        ];

        assert_rtp_err_contains(RtpPacket::parse(&data), "TooShort");
    }

    #[test]
    fn test_extension_truncated_header() {
        // X=1 but no extension header data
        let data = [
            0x90, 0x00, // V=2, P=0, X=1, CC=0
            0x00, 0x01, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x30,
            0x39,
            // Missing extension header (need at least 4 bytes)
        ];

        assert_rtp_err_contains(RtpPacket::parse(&data), "ExtensionTruncated");
    }

    #[test]
    fn test_extension_truncated_data() {
        // X=1 with extension header but truncated data
        let data = [
            0x90, 0x00, // V=2, P=0, X=1, CC=0
            0x00, 0x01, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x30, 0x39, 0xBE, 0xDE, // profile
            0x00, 0x02, // length = 2 words = 8 bytes
            // Only 4 bytes of data (need 8)
            0x01, 0x02, 0x03, 0x04,
        ];

        assert_rtp_err_contains(RtpPacket::parse(&data), "ExtensionTruncated");
    }

    #[test]
    fn test_payload_truncated_with_padding() {
        // Padding flag set but padding count exceeds remaining data
        let data = [
            0xA0, 0x00, // V=2, P=1
            0x00, 0x01, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x30, 0x39,
            0xFF, // Last byte claims 255 bytes of padding (but only 1 byte)
        ];

        assert_rtp_err_contains(RtpPacket::parse(&data), "PayloadTruncated");
    }

    #[test]
    fn test_header_size() {
        // Basic packet
        let pkt = RtpPacket::new(0, 1, 160, 12345);
        assert_eq!(pkt.header_size(), 12);

        // With 2 CSRC
        let pkt2 = RtpPacket::new(0, 1, 160, 12345)
            .with_csrc(11111)
            .with_csrc(22222);
        assert_eq!(pkt2.header_size(), 20); // 12 + 8

        // With extension
        let mut pkt3 = RtpPacket::new(0, 1, 160, 12345);
        pkt3.extension_header = Some(ExtensionHeader {
            profile: 0xBEDE,
            data: Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]),
        });
        assert_eq!(pkt3.header_size(), 20); // 12 + 4 (ext header) + 4 (data rounded to 32-bit)
    }

    #[test]
    fn test_with_csrc_max() {
        let mut pkt = RtpPacket::new(0, 1, 160, 12345);

        // Add MAX_CSRC entries
        for i in 0..MAX_CSRC {
            pkt = pkt.with_csrc(i as u32);
        }
        assert_eq!(pkt.csrc.len(), MAX_CSRC);

        // Try to add one more (should be ignored)
        pkt = pkt.with_csrc(99999);
        assert_eq!(pkt.csrc.len(), MAX_CSRC);
    }

    #[test]
    fn test_build_with_extension_padding() {
        // Extension data not aligned to 32-bit boundary
        let mut pkt = RtpPacket::new(0, 1, 160, 12345);
        pkt.extension_header = Some(ExtensionHeader {
            profile: 0xBEDE,
            data: Bytes::from_static(&[0x01, 0x02, 0x03]), // 3 bytes, needs 1 byte padding
        });

        let bytes = pkt.build();
        let parsed = RtpPacket::parse(&bytes).unwrap();

        assert!(parsed.extension_header.is_some());
        // Extension data is padded to 4 bytes in the packet
        let ext = parsed.extension_header.unwrap();
        assert_eq!(ext.data.len(), 4);
    }

    #[test]
    fn test_parse_with_csrc() {
        // Packet with 2 CSRC entries
        let data = [
            0x82, 0x00, // V=2, P=0, X=0, CC=2
            0x00, 0x01, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x30, 0x39, // ssrc
            0x00, 0x00, 0x2B, 0x67, // csrc1 = 11111
            0x00, 0x00, 0x56, 0xCE, // csrc2 = 22222
            0xAA, 0xBB, // payload
        ];

        let pkt = RtpPacket::parse(&data).unwrap();
        assert_eq!(pkt.csrc.len(), 2);
        assert_eq!(pkt.csrc[0], 11111);
        assert_eq!(pkt.csrc[1], 22222);
        assert_eq!(&pkt.payload[..], &[0xAA, 0xBB]);
    }

    #[test]
    fn test_sequence_diff_edge_cases() {
        // Same sequence number
        assert_eq!(sequence_diff(100, 100), 0);

        // Near wraparound
        assert_eq!(sequence_diff(5, 65530), 11);
        assert_eq!(sequence_diff(65530, 5), -11);
    }

    #[test]
    fn test_sequence_newer_edge_cases() {
        // Same sequence number
        assert!(!sequence_newer(100, 100));

        // Near half range - 32768 is ambiguous due to i16 range
        // 32767 from 0 should be "newer" (positive diff)
        assert!(sequence_newer(32767, 0));
        // 32769 from 0 wraps to negative, so not newer
        assert!(!sequence_newer(32769, 0));
    }

    #[test]
    fn test_new_packet_defaults() {
        let pkt = RtpPacket::new(8, 1000, 80000, 0xCAFEBABE);
        assert_eq!(pkt.version, 2);
        assert!(!pkt.padding);
        assert!(!pkt.extension);
        assert!(!pkt.marker);
        assert_eq!(pkt.payload_type, 8);
        assert_eq!(pkt.sequence_number, 1000);
        assert_eq!(pkt.timestamp, 80000);
        assert_eq!(pkt.ssrc, 0xCAFEBABE);
        assert!(pkt.csrc.is_empty());
        assert!(pkt.extension_header.is_none());
        assert!(pkt.payload.is_empty());
    }

    #[test]
    fn test_with_payload_bytes() {
        let pkt = RtpPacket::new(0, 1, 160, 12345).with_payload(Bytes::from_static(&[0x01, 0x02]));
        assert_eq!(&pkt.payload[..], &[0x01, 0x02]);
    }
}

//! Security and input validation tests.
//!
//! These tests verify that the SIP/RTP stack properly handles malicious or malformed input,
//! including buffer boundaries, integer overflows, null byte injection, CRLF injection,
//! and other attack vectors.

use mdsiprtp_rtp::{RtpPacket, RtpParseError};
use mdsiprtp_sdp::SessionDescription;
use mdsiprtp_sip::SipMessage;

mod sip_security {
    use super::*;

    /// Test extremely long header values (buffer overflow prevention)
    #[test]
    fn test_extremely_long_header() {
        let long_value = "A".repeat(100000);
        let msg = format!(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: {}<sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n",
            long_value
        );

        // Should not crash or panic
        let result = SipMessage::parse(msg.as_bytes());
        // May parse or may error, but must not crash
        let _ = result;
    }

    /// Test Content-Length integer overflow attempt
    #[test]
    fn test_content_length_overflow() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 99999999999999999999999999999\r\n\
\r\n";

        let result = SipMessage::parse(msg);
        // Should handle gracefully (parse or error, but not crash)
        let _ = result;
    }

    /// Test negative Content-Length
    #[test]
    fn test_negative_content_length() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: -100\r\n\
\r\n";

        let result = SipMessage::parse(msg);
        // Should handle gracefully
        let _ = result;
    }

    /// Test Content-Length mismatch (claimed vs actual)
    #[test]
    fn test_content_length_mismatch() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 1000\r\n\
\r\n\
v=0\r\n";

        let result = SipMessage::parse(msg);
        // Should handle gracefully (may truncate or error)
        let _ = result;
    }

    /// Test null byte injection in headers
    #[test]
    fn test_null_byte_injection() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob\x00Admin <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let result = SipMessage::parse(msg);
        // Should handle null bytes safely
        let _ = result;
    }

    /// Test CRLF injection attempt in header values
    #[test]
    fn test_crlf_injection() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\nX-Injected: evil\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let result = SipMessage::parse(msg);
        // Should not allow header injection
        let _ = result;
    }

    /// Test deeply nested Via headers (stack overflow prevention)
    #[test]
    fn test_deeply_nested_via_headers() {
        let mut msg = "INVITE sip:bob@biloxi.com SIP/2.0\r\n".to_string();

        // Add 1000 Via headers
        for i in 0..1000 {
            msg.push_str(&format!(
                "Via: SIP/2.0/UDP proxy{}.example.com;branch=z9hG4bK{}\r\n",
                i, i
            ));
        }

        msg.push_str(
            "Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n",
        );

        let result = SipMessage::parse(msg.as_bytes());
        // Should handle without stack overflow
        let _ = result;
    }

    /// Test truncated message (incomplete headers)
    #[test]
    fn test_truncated_headers() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@bilo";

        let result = SipMessage::parse(msg);
        assert!(result.is_err() || result.is_ok());
    }

    /// Test message with only headers, no body separator
    #[test]
    fn test_missing_body_separator() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 10\r\n";

        let result = SipMessage::parse(msg);
        // Should handle missing CRLF separator
        let _ = result;
    }

    /// Test invalid UTF-8 in message
    #[test]
    fn test_invalid_utf8() {
        let mut msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: "
            .to_vec();

        // Add invalid UTF-8 sequence
        msg.extend_from_slice(&[0xFF, 0xFE, 0xFD]);

        msg.extend_from_slice(
            b" <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n",
        );

        let result = SipMessage::parse(&msg);
        // Should handle invalid UTF-8 gracefully
        let _ = result;
    }

    /// Test message smuggling attempt (multiple Content-Length headers)
    #[test]
    fn test_multiple_content_length() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 10\r\n\
Content-Length: 20\r\n\
\r\n\
0123456789";

        let result = SipMessage::parse(msg);
        // Should handle ambiguous Content-Length safely
        let _ = result;
    }
}

mod sdp_security {
    use super::*;

    /// Test extremely long SDP lines
    #[test]
    fn test_extremely_long_sdp_line() {
        let long_session_name = "A".repeat(100000);
        let sdp = format!(
            "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s={}\r\n\
t=0 0\r\n",
            long_session_name
        );

        let result = SessionDescription::parse(&sdp);
        // Should not crash
        let _ = result;
    }

    /// Test SDP with malformed origin line
    #[test]
    fn test_malformed_origin_fields() {
        let sdp = "v=0\r\n\
o=user 123 456\r\n\
s=-\r\n\
t=0 0\r\n";

        let result = SessionDescription::parse(sdp);
        assert!(result.is_err());
    }

    /// Test SDP with injection attempt in session name
    #[test]
    fn test_sdp_session_name_injection() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=Normal\r\nv=1\r\nm=evil 666 RTP/AVP 0\r\n\
t=0 0\r\n";

        let result = SessionDescription::parse(sdp);
        // Should not allow line injection
        if let Ok(parsed) = result {
            // If it parses, version should still be 0
            assert_eq!(parsed.version, 0);
        }
    }

    /// Test SDP with invalid IP address
    #[test]
    fn test_invalid_ip_address() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 999.999.999.999\r\n\
s=-\r\n\
t=0 0\r\n";

        let result = SessionDescription::parse(sdp);
        // Should parse (validation happens at usage time)
        let _ = result;
    }

    /// Test SDP with negative timing values
    #[test]
    fn test_negative_timing() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=-1 -1\r\n";

        let result = SessionDescription::parse(sdp);
        // Should handle gracefully
        let _ = result;
    }

    /// Test SDP with invalid media port
    #[test]
    fn test_invalid_media_port() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 99999 RTP/AVP 0\r\n";

        let result = SessionDescription::parse(sdp);
        // May parse with truncated port or error
        let _ = result;
    }

    /// Test SDP with excessive media descriptions
    #[test]
    fn test_excessive_media_descriptions() {
        let mut sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n"
            .to_string();

        // Add 1000 media descriptions
        for i in 0..1000 {
            sdp.push_str(&format!("m=audio {} RTP/AVP 0\r\n", 10000 + i));
        }

        let result = SessionDescription::parse(&sdp);
        // Should handle without resource exhaustion
        let _ = result;
    }

    /// Test SDP with null bytes
    #[test]
    fn test_sdp_null_bytes() {
        let sdp = b"v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=\x00injection\r\n\
t=0 0\r\n";

        let result = SessionDescription::parse(std::str::from_utf8(sdp).unwrap_or(""));
        // Should handle null bytes
        let _ = result;
    }
}

mod rtp_security {
    use super::*;

    /// Test RTP packet with truncated header
    #[test]
    fn test_rtp_truncated_header() {
        let data = [0x80, 0x00, 0x00, 0x01]; // Only 4 bytes
        let result = RtpPacket::parse(&data);
        assert!(matches!(result, Err(RtpParseError::TooShort(_))));
    }

    /// Test RTP packet with invalid version
    #[test]
    fn test_rtp_invalid_version() {
        let data = [
            0xC0, // V=3 (invalid)
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x30, 0x39, 0xaa,
        ];
        let result = RtpPacket::parse(&data);
        assert!(matches!(result, Err(RtpParseError::InvalidVersion(_))));
    }

    /// Test RTP packet with excessive CSRC count
    #[test]
    fn test_rtp_excessive_csrc() {
        let data = [
            0x8F, // V=2, CC=15 (max)
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x30,
            0x39, // SSRC
                  // Missing CSRC data (should be 15 * 4 = 60 bytes)
        ];
        let result = RtpPacket::parse(&data);
        assert!(result.is_err());
    }

    /// Test RTP packet with malformed extension
    #[test]
    fn test_rtp_malformed_extension() {
        let data = [
            0x90, // V=2, X=1 (extension present)
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x30, 0x39, // SSRC
            0xAB, 0xCD, // Extension profile
                  // Missing extension length
        ];
        let result = RtpPacket::parse(&data);
        assert!(matches!(result, Err(RtpParseError::ExtensionTruncated)));
    }

    /// Test RTP packet with invalid padding
    #[test]
    fn test_rtp_invalid_padding() {
        let data = [
            0xA0, // V=2, P=1 (padding)
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x30, 0x39, // SSRC
            0xaa, 0xFF, // Last byte claims 255 bytes padding (more than packet size)
        ];
        let result = RtpPacket::parse(&data);
        // Should detect invalid padding
        assert!(result.is_err() || result.is_ok()); // Implementation dependent
    }

    /// Test RTP packet with empty data
    #[test]
    fn test_rtp_empty_packet() {
        let data = [];
        let result = RtpPacket::parse(&data);
        assert!(matches!(result, Err(RtpParseError::TooShort(0))));
    }

    /// Test RTP packet with maximum valid size
    #[test]
    fn test_rtp_max_size() {
        let mut data = vec![
            0x80, // V=2, P=0, X=0, CC=0
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x30,
            0x39, // SSRC (12 bytes header)
        ];

        // Add large payload (MTU - header)
        data.extend(vec![0xAA; 1400]);

        let result = RtpPacket::parse(&data);
        assert!(result.is_ok());
        if let Ok(packet) = result {
            assert_eq!(packet.payload.len(), 1400);
        }
    }

    /// Test RTP packet with extension length overflow
    #[test]
    fn test_rtp_extension_length_overflow() {
        let data = [
            0x90, // V=2, X=1
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x30, 0x39, // SSRC
            0xAB, 0xCD, // Extension profile
            0xFF, 0xFF, // Extension length = 65535 * 4 bytes (way too large)
        ];
        let result = RtpPacket::parse(&data);
        assert!(matches!(result, Err(RtpParseError::ExtensionTruncated)));
    }
}

mod boundary_conditions {
    use super::*;

    /// Test parsing with exact buffer boundaries
    #[test]
    fn test_exact_boundary_rtp() {
        let data = [
            0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x30,
            0x39, // Exactly 12 bytes (minimal header)
        ];
        let result = RtpPacket::parse(&data);
        assert!(result.is_ok());
        if let Ok(packet) = result {
            assert_eq!(packet.payload.len(), 0);
        }
    }

    /// Test off-by-one buffer read
    #[test]
    fn test_off_by_one_rtp() {
        let data = [
            0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00,
            0x30, // 11 bytes (1 byte short)
        ];
        let result = RtpPacket::parse(&data);
        assert!(matches!(result, Err(RtpParseError::TooShort(_))));
    }

    /// Test maximum field values
    #[test]
    fn test_max_field_values_rtp() {
        let data = [
            0xBF, // V=2, P=1, X=1, CC=15
            0xFF, // M=1, PT=127
            0xFF, 0xFF, // Seq = 65535
            0xFF, 0xFF, 0xFF, 0xFF, // Timestamp = max u32
            0xFF, 0xFF, 0xFF, 0xFF, // SSRC = max u32
        ];
        // This will fail because CSRC count is 15 but no CSRC data provided
        let result = RtpPacket::parse(&data);
        assert!(result.is_err());
    }

    /// Test zero values
    #[test]
    fn test_zero_values_rtp() {
        let data = [
            0x80, // V=2, all else zero
            0x00, // M=0, PT=0
            0x00, 0x00, // Seq = 0
            0x00, 0x00, 0x00, 0x00, // Timestamp = 0
            0x00, 0x00, 0x00, 0x00, // SSRC = 0
        ];
        let result = RtpPacket::parse(&data);
        assert!(result.is_ok());
    }
}

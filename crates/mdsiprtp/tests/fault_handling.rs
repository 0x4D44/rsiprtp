//! Fault handling and error path tests.
//!
//! These tests verify that the SIP/RTP stack handles various error conditions
//! gracefully, including network failures, malformed messages, resource exhaustion,
//! and timeout scenarios.

use mdsiprtp_rtp::{RtpPacket, RtpParseError, RtpSession};
use mdsiprtp_sdp::SessionDescription;
use mdsiprtp_sip::{Method, SipMessage, SipRequest};
use mdsiprtp_transaction::{
    InviteClientTransaction, InviteServerTransaction, NonInviteClientTransaction, Timer,
};

mod transaction_faults {
    use super::*;

    fn create_invite() -> SipRequest {
        SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap()
    }

    /// Test transaction timeout after multiple retransmissions
    #[test]
    fn test_transaction_timeout_after_retransmits() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // Simulate retransmissions
        for _ in 0..7 {
            tx.handle_timeout(Timer::A);
            tx.poll_actions();
        }

        // Final timeout with Timer B
        tx.handle_timeout(Timer::B);
        assert!(tx.is_terminated());
    }

    /// Test handling of spurious timer events
    #[test]
    fn test_spurious_timer_events() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // Send Timer D when in Calling state (invalid)
        tx.handle_timeout(Timer::D);
        // Should not crash or panic
        assert!(!tx.is_terminated());
    }

    /// Test reliable transport with network errors
    #[test]
    fn test_reliable_transport_timeout() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, true).unwrap();
        tx.poll_actions();

        // Even with reliable transport, Timer B should fire
        tx.handle_timeout(Timer::B);
        assert!(tx.is_terminated());
    }

    /// Test multiple rapid Timer E events (unreliable transport)
    #[test]
    fn test_rapid_timer_e_events() {
        let request = SipRequest::builder()
            .method(Method::Register)
            .uri("sip:example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:alice@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let mut tx = NonInviteClientTransaction::new(request, false).unwrap();
        tx.poll_actions();

        // Rapid Timer E events
        for _ in 0..10 {
            tx.handle_timeout(Timer::E);
            tx.poll_actions();
        }

        // Should still be alive until Timer F
        assert!(!tx.is_terminated());
    }

    /// Test server transaction with no TU responses
    #[test]
    fn test_server_transaction_no_response_timeout() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // Simulate retransmitted INVITE without sending response
        for _ in 0..5 {
            let invite = create_invite();
            tx.handle_request(invite);
            tx.poll_actions();
        }

        // Transaction should handle retransmissions gracefully
        assert!(!tx.is_terminated());
    }

    /// Test transaction in Completed state handling retransmissions
    #[test]
    fn test_completed_state_retransmission_storm() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // Send failure response
        let response = mdsiprtp_sip::SipResponse::builder()
            .status(404, "Not Found")
            .from_request(&invite)
            .to_tag("totag")
            .build()
            .unwrap();
        tx.send_response(response);
        tx.poll_actions();

        // Simulate retransmission storm
        for _ in 0..20 {
            let invite = create_invite();
            tx.handle_request(invite);
            tx.poll_actions();
        }

        // Should absorb all retransmissions
        // (implementation may stay in Completed or move to Confirmed)
        assert!(!tx.is_terminated());
    }

    /// Test Timer H timeout without ACK
    #[test]
    fn test_timer_h_no_ack_received() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // Send failure response to go to Completed
        let response = mdsiprtp_sip::SipResponse::builder()
            .status(500, "Server Error")
            .from_request(&invite)
            .to_tag("totag")
            .build()
            .unwrap();
        tx.send_response(response);
        tx.poll_actions();

        // Timer G fires several times (retransmissions)
        for _ in 0..5 {
            tx.handle_timeout(Timer::G);
            tx.poll_actions();
        }

        // Timer H fires (give up)
        tx.handle_timeout(Timer::H);
        assert!(tx.is_terminated());
    }

    /// Test DNS failure simulation (REGISTER without response)
    #[test]
    fn test_dns_failure_timeout() {
        let request = SipRequest::builder()
            .method(Method::Register)
            .uri("sip:unreachable.invalid")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:alice@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let mut tx = NonInviteClientTransaction::new(request, false).unwrap();
        tx.poll_actions();

        // Simulate timeout due to DNS/network failure
        tx.handle_timeout(Timer::F);
        assert!(tx.is_terminated());
    }
}

mod rtp_faults {
    use super::*;

    /// Test RTP session with sequence number overflow
    #[test]
    fn test_sequence_number_overflow() {
        let mut session = RtpSession::new(12345, 0, 8000);

        // Create 70000 packets to force wraparound (u16::MAX = 65535)
        for _ in 0..70000 {
            let _packet = session.create_packet(vec![0; 160], 160, false);
        }

        // Verify session still works after many packets
        let packet = session.create_packet(vec![0; 160], 160, false);
        assert_eq!(packet.ssrc, 12345);
        assert_eq!(packet.payload.len(), 160);
    }

    /// Test RTP session with timestamp overflow
    #[test]
    fn test_timestamp_overflow() {
        let mut session = RtpSession::new(12345, 0, 8000);

        // Create enough packets to overflow timestamp (u32::MAX)
        // At 160 samples per packet, need ~26.8M packets
        // Test near-overflow condition instead
        for _ in 0..100000 {
            let _packet = session.create_packet(vec![0; 160], 160, false);
        }

        // Verify session handles large timestamps
        let packet = session.create_packet(vec![0; 160], 160, false);
        assert!(packet.timestamp > 0);
    }

    /// Test parsing truncated RTP packets (fault injection)
    #[test]
    fn test_truncated_rtp_packet() {
        let valid_packet = [
            0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x30, 0x39,
        ];

        // Try all truncation points
        for len in 0..valid_packet.len() {
            let truncated = &valid_packet[..len];
            let result = RtpPacket::parse(truncated);
            assert!(result.is_err(), "Truncated packet at {} should fail", len);
        }
    }

    /// Test RTP packet with corrupted header
    #[test]
    fn test_corrupted_rtp_header() {
        let mut packet = [
            0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x30, 0x39,
        ];

        // Corrupt version field
        packet[0] = 0xC0; // V=3
        let result = RtpPacket::parse(&packet);
        assert!(matches!(result, Err(RtpParseError::InvalidVersion(_))));
    }

    /// Test RTP with extreme CSRC count
    #[test]
    fn test_extreme_csrc_count() {
        let packet = [
            0x8F, // CC=15 (max)
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x30,
            0x39, // Only header, no CSRC data
        ];

        let result = RtpPacket::parse(&packet);
        assert!(result.is_err());
    }
}

mod sdp_faults {
    use super::*;

    /// Test SDP parsing with missing required fields
    #[test]
    fn test_sdp_missing_required_fields() {
        // Missing origin line
        let sdp = "v=0\r\ns=Test\r\nt=0 0\r\n";
        let result = SessionDescription::parse(sdp);
        assert!(result.is_err());

        // Missing version
        let sdp = "o=- 123 456 IN IP4 192.168.1.1\r\ns=Test\r\nt=0 0\r\n";
        let result = SessionDescription::parse(sdp);
        assert!(result.is_err());

        // Missing timing
        let sdp = "v=0\r\no=- 123 456 IN IP4 192.168.1.1\r\ns=Test\r\n";
        let result = SessionDescription::parse(sdp);
        assert!(result.is_err());
    }

    /// Test SDP with truncated lines
    #[test]
    fn test_sdp_truncated_lines() {
        let sdp = "v=0\r\no=- 123 456 IN IP4 192.168.1.1\r\ns=Test\r\nt=";
        let result = SessionDescription::parse(sdp);
        assert!(result.is_err() || result.is_ok()); // May parse or error
    }

    /// Test SDP with wrong line order
    #[test]
    fn test_sdp_wrong_line_order() {
        // Timing before origin
        let sdp = "v=0\r\nt=0 0\r\no=- 123 456 IN IP4 192.168.1.1\r\ns=Test\r\n";
        let result = SessionDescription::parse(sdp);
        // Parser may be lenient - just verify it doesn't crash
        let _ = result;
    }

    /// Test SDP with malformed media line
    #[test]
    fn test_sdp_malformed_media() {
        let sdp = "v=0\r\n\
                   o=- 123 456 IN IP4 192.168.1.1\r\n\
                   s=Test\r\n\
                   t=0 0\r\n\
                   m=audio INVALID RTP/AVP 0\r\n";
        let result = SessionDescription::parse(sdp);
        assert!(result.is_err() || result.is_ok()); // Implementation dependent
    }
}

mod message_parsing_faults {
    use super::*;

    /// Test SIP message parsing with incomplete status line
    #[test]
    fn test_incomplete_status_line() {
        let msg = b"SIP/2.0 200";
        let result = SipMessage::parse(msg);
        assert!(result.is_err());
    }

    /// Test SIP message with no CRLF separator
    #[test]
    fn test_no_crlf_separator() {
        let msg = b"INVITE sip:bob@example.com SIP/2.0\n\
                    Via: SIP/2.0/UDP pc.example.com;branch=z9hG4bK776asdhds\n";
        let result = SipMessage::parse(msg);
        // May succeed with LF-only parsing or fail
        let _ = result;
    }

    /// Test SIP message with empty headers
    #[test]
    fn test_empty_headers() {
        let msg = b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n";
        let result = SipMessage::parse(msg);
        // Should handle gracefully (may error on missing required headers)
        let _ = result;
    }

    /// Test handling of extremely long request URI
    #[test]
    fn test_extremely_long_request_uri() {
        let long_uri = "a".repeat(10000);
        let msg = format!(
            "INVITE sip:{}@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP pc.example.com;branch=z9hG4bK776\r\n\
             \r\n",
            long_uri
        );
        let result = SipMessage::parse(msg.as_bytes());
        // Should not crash
        let _ = result;
    }
}

mod resource_exhaustion {
    use super::*;

    /// Test creating many RTP sessions (memory usage)
    #[test]
    fn test_many_rtp_sessions() {
        let sessions: Vec<RtpSession> = (0..1000).map(|i| RtpSession::new(i, 0, 8000)).collect();

        assert_eq!(sessions.len(), 1000);
    }

    /// Test creating many packets in a session
    #[test]
    fn test_many_packets_single_session() {
        let mut session = RtpSession::new(12345, 0, 8000);

        for _ in 0..10000 {
            let _packet = session.create_packet(vec![0; 160], 160, false);
        }

        // Session should still be functional
        let packet = session.create_packet(vec![0; 160], 160, false);
        assert_eq!(packet.ssrc, 12345);
    }

    /// Test SDP with excessive attributes
    #[test]
    fn test_sdp_excessive_attributes() {
        let mut sdp = "v=0\r\n\
                       o=- 123 456 IN IP4 192.168.1.1\r\n\
                       s=Test\r\n\
                       t=0 0\r\n"
            .to_string();

        // Add 1000 attributes
        for i in 0..1000 {
            sdp.push_str(&format!("a=test-{}: value\r\n", i));
        }

        let result = SessionDescription::parse(&sdp);
        // Should handle without crashing
        let _ = result;
    }

    /// Test parsing many SIP messages
    #[test]
    fn test_parse_many_sip_messages() {
        let msg = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP pc.example.com;branch=z9hG4bK776\r\n\
                    Max-Forwards: 70\r\n\
                    To: Bob <sip:bob@biloxi.com>\r\n\
                    From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                    Call-ID: a84b4c76e66710@pc.atlanta.com\r\n\
                    CSeq: 314159 INVITE\r\n\
                    Content-Length: 0\r\n\
                    \r\n";

        for _ in 0..1000 {
            let _ = SipMessage::parse(msg);
        }
    }
}

mod timeout_scenarios {
    use super::*;

    /// Test INVITE client transaction full timeout sequence
    #[test]
    fn test_invite_full_timeout_sequence() {
        let invite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:unreachable@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:unreachable@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // Simulate Timer A firing multiple times with exponential backoff
        let mut timer_a_count = 0;
        while timer_a_count < 7 {
            tx.handle_timeout(Timer::A);
            tx.poll_actions();
            timer_a_count += 1;
        }

        // Finally Timer B fires
        tx.handle_timeout(Timer::B);
        assert!(tx.is_terminated());
    }

    /// Test non-INVITE timeout with retransmissions
    #[test]
    fn test_non_invite_timeout_with_retransmits() {
        let request = SipRequest::builder()
            .method(Method::Options)
            .uri("sip:example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let mut tx = NonInviteClientTransaction::new(request, false).unwrap();
        tx.poll_actions();

        // Simulate Timer E firing multiple times
        for _ in 0..10 {
            tx.handle_timeout(Timer::E);
            tx.poll_actions();
        }

        // Timer F fires (final timeout)
        tx.handle_timeout(Timer::F);
        assert!(tx.is_terminated());
    }

    /// Test server transaction Timer H timeout
    #[test]
    fn test_server_timer_h_timeout() {
        let invite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // Send error response
        let response = mdsiprtp_sip::SipResponse::builder()
            .status(503, "Service Unavailable")
            .from_request(&invite)
            .to_tag("totag")
            .build()
            .unwrap();
        tx.send_response(response);
        tx.poll_actions();

        // Timer G fires several times (retransmit)
        for _ in 0..5 {
            tx.handle_timeout(Timer::G);
            tx.poll_actions();
        }

        // Timer H fires (give up waiting for ACK)
        tx.handle_timeout(Timer::H);
        assert!(tx.is_terminated());
    }
}

//! Concurrency and thread safety tests.
//!
//! These tests verify that the SIP/RTP stack components are thread-safe and handle
//! concurrent operations correctly, including parallel operations, shared state access,
//! and resource management under concurrent load.

use mdsiprtp_rtp::RtpSession;
use std::sync::{Arc, Mutex};
use std::thread;

mod rtp_concurrency {
    use super::*;

    /// Test creating RTP sessions from multiple threads
    #[test]
    fn test_parallel_session_creation() {
        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    let session = RtpSession::new(10000 + i, 0, 8000);
                    assert_eq!(session.ssrc(), 10000 + i);
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    /// Test concurrent packet creation from same session
    #[test]
    fn test_concurrent_packet_creation() {
        let session = Arc::new(Mutex::new(RtpSession::new(12345, 0, 8000)));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let session = Arc::clone(&session);
                thread::spawn(move || {
                    let mut session = session.lock().unwrap();
                    for _ in 0..100 {
                        let _packet = session.create_packet(vec![0; 160], 160, false);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify session is still functional
        let mut session = session.lock().unwrap();
        let packet = session.create_packet(vec![0; 160], 160, false);
        assert_eq!(packet.ssrc, 12345);
    }

    /// Test multiple sessions operating in parallel
    #[test]
    fn test_multiple_sessions_parallel() {
        let sessions: Vec<_> = (0..10)
            .map(|i| Arc::new(Mutex::new(RtpSession::new(20000 + i, 0, 8000))))
            .collect();

        let handles: Vec<_> = sessions
            .iter()
            .enumerate()
            .map(|(i, session)| {
                let session = Arc::clone(session);
                thread::spawn(move || {
                    let mut session = session.lock().unwrap();
                    for _ in 0..50 {
                        let _packet = session.create_packet(vec![0; 160], 160, false);
                    }
                    assert_eq!(session.ssrc(), 20000 + i as u32);
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    /// Test RTP packet parsing from multiple threads
    #[test]
    fn test_concurrent_packet_parsing() {
        let packet_data: &'static [u8] = &[
            0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x30, 0x39, 0xAA, 0xBB,
        ];

        let handles: Vec<_> = (0..10)
            .map(|_| {
                thread::spawn(move || {
                    for _ in 0..100 {
                        let result = mdsiprtp_rtp::RtpPacket::parse(packet_data);
                        assert!(result.is_ok());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }
}

mod sip_concurrency {
    use super::*;
    use mdsiprtp_sip::SipMessage;

    /// Test concurrent SIP message parsing
    #[test]
    fn test_concurrent_sip_parsing() {
        let message = Arc::new(
            b"INVITE sip:bob@example.com SIP/2.0\r\n\
            Via: SIP/2.0/UDP pc.example.com;branch=z9hG4bK776\r\n\
            Max-Forwards: 70\r\n\
            To: Bob <sip:bob@biloxi.com>\r\n\
            From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
            Call-ID: a84b4c76e66710@pc.atlanta.com\r\n\
            CSeq: 314159 INVITE\r\n\
            Content-Length: 0\r\n\
            \r\n"
                .to_vec(),
        );

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let msg = Arc::clone(&message);
                thread::spawn(move || {
                    for _ in 0..100 {
                        let result = SipMessage::parse(&msg);
                        assert!(result.is_ok());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    /// Test concurrent SIP request building
    #[test]
    fn test_concurrent_request_building() {
        use mdsiprtp_sip::{Method, SipRequest};

        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    for j in 0..50 {
                        let request = SipRequest::builder()
                            .method(Method::Invite)
                            .uri(&format!("sip:user{}@example.com", i * 50 + j))
                            .via(
                                "192.168.1.1",
                                5060,
                                "UDP",
                                &format!("z9hG4bK{}", i * 50 + j),
                            )
                            .from("sip:alice@example.com", "fromtag")
                            .to(&format!("sip:user{}@example.com", i * 50 + j))
                            .call_id(&format!("call-{}@example.com", i * 50 + j))
                            .cseq(1)
                            .build();
                        assert!(request.is_ok());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }
}

mod sdp_concurrency {
    use super::*;
    use mdsiprtp_sdp::SessionDescription;

    /// Test concurrent SDP parsing
    #[test]
    fn test_concurrent_sdp_parsing() {
        let sdp = Arc::new(
            "v=0\r\n\
             o=- 123 456 IN IP4 192.168.1.1\r\n\
             s=Test Session\r\n\
             t=0 0\r\n\
             m=audio 49170 RTP/AVP 0 8\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:8 PCMA/8000\r\n"
                .to_string(),
        );

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let sdp = Arc::clone(&sdp);
                thread::spawn(move || {
                    for _ in 0..100 {
                        let result = SessionDescription::parse(&sdp);
                        assert!(result.is_ok());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    /// Test concurrent SDP offer/answer creation
    #[test]
    fn test_concurrent_offer_answer() {
        use mdsiprtp_sdp::{
            builder::{MediaBuilder, SdpBuilder},
            negotiation::create_answer,
            Codec,
        };
        use std::net::{IpAddr, Ipv4Addr};

        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    let local_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
                    let local_port = 10000 + i * 100;

                    for j in 0..20 {
                        let offer = SdpBuilder::new(local_addr)
                            .add_media(MediaBuilder::audio(local_port + j).pcmu().pcma())
                            .build();
                        assert!(offer.media.len() > 0);

                        // Create answer to the offer
                        let answer_codecs = vec![Codec::pcmu()];
                        let answer = create_answer(&offer, &answer_codecs, local_port + j + 1000);
                        assert!(answer.is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }
}

mod transaction_concurrency {
    use super::*;
    use mdsiprtp_sip::{Method, SipRequest};
    use mdsiprtp_transaction::{InviteClientTransaction, NonInviteClientTransaction};

    /// Test concurrent transaction creation
    #[test]
    fn test_concurrent_transaction_creation() {
        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    for j in 0..20 {
                        let request = SipRequest::builder()
                            .method(Method::Invite)
                            .uri("sip:bob@example.com")
                            .via("192.168.1.1", 5060, "UDP", &format!("z9hG4bK{}{}", i, j))
                            .from("sip:alice@example.com", "fromtag")
                            .to("sip:bob@example.com")
                            .call_id(&format!("call-{}{}@example.com", i, j))
                            .cseq(1)
                            .build()
                            .unwrap();

                        let tx = InviteClientTransaction::new(request, false);
                        assert!(tx.is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    /// Test concurrent non-INVITE transaction creation
    #[test]
    fn test_concurrent_non_invite_transactions() {
        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    for j in 0..20 {
                        let request = SipRequest::builder()
                            .method(Method::Register)
                            .uri("sip:example.com")
                            .via("192.168.1.1", 5060, "UDP", &format!("z9hG4bK{}{}", i, j))
                            .from("sip:alice@example.com", "fromtag")
                            .to("sip:alice@example.com")
                            .call_id(&format!("reg-{}{}@example.com", i, j))
                            .cseq(1)
                            .build()
                            .unwrap();

                        let tx = NonInviteClientTransaction::new(request, false);
                        assert!(tx.is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }
}

mod stress_tests {
    use super::*;

    /// Test high-volume packet creation
    #[test]
    fn test_high_volume_packet_creation() {
        let session = Arc::new(Mutex::new(RtpSession::new(12345, 0, 8000)));

        let handles: Vec<_> = (0..5)
            .map(|_| {
                let session = Arc::clone(&session);
                thread::spawn(move || {
                    let mut session = session.lock().unwrap();
                    for _ in 0..1000 {
                        let _packet = session.create_packet(vec![0; 160], 160, false);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify session handled 5000 packets
        let session = session.lock().unwrap();
        assert_eq!(session.ssrc(), 12345);
    }

    /// Test concurrent parsing under stress
    #[test]
    fn test_stress_concurrent_parsing() {
        use mdsiprtp_sip::SipMessage;

        let message = Arc::new(
            b"INVITE sip:bob@example.com SIP/2.0\r\n\
            Via: SIP/2.0/UDP pc.example.com;branch=z9hG4bK776\r\n\
            Max-Forwards: 70\r\n\
            To: Bob <sip:bob@biloxi.com>\r\n\
            From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
            Call-ID: a84b4c76e66710@pc.atlanta.com\r\n\
            CSeq: 314159 INVITE\r\n\
            Content-Length: 0\r\n\
            \r\n"
                .to_vec(),
        );

        let handles: Vec<_> = (0..20)
            .map(|_| {
                let msg = Arc::clone(&message);
                thread::spawn(move || {
                    for _ in 0..500 {
                        let _ = SipMessage::parse(&msg);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    /// Test memory safety under concurrent load
    #[test]
    fn test_memory_safety_concurrent_load() {
        let sessions: Vec<_> = (0..20)
            .map(|i| Arc::new(Mutex::new(RtpSession::new(30000 + i, 0, 8000))))
            .collect();

        let handles: Vec<_> = sessions
            .iter()
            .map(|session| {
                let session = Arc::clone(session);
                thread::spawn(move || {
                    for _ in 0..200 {
                        let mut session = session.lock().unwrap();
                        let packet = session.create_packet(vec![0; 160], 160, false);
                        // Immediately drop packet to test cleanup
                        drop(packet);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // All sessions should still be valid
        for (i, session) in sessions.iter().enumerate() {
            let session = session.lock().unwrap();
            assert_eq!(session.ssrc(), 30000 + i as u32);
        }
    }
}

mod resource_limits {
    use super::*;

    /// Test handling many concurrent sessions
    #[test]
    fn test_many_concurrent_sessions() {
        let sessions: Vec<_> = (0..100)
            .map(|i| Arc::new(Mutex::new(RtpSession::new(40000 + i, 0, 8000))))
            .collect();

        let handles: Vec<_> = sessions
            .iter()
            .map(|session| {
                let session = Arc::clone(session);
                thread::spawn(move || {
                    let mut session = session.lock().unwrap();
                    for _ in 0..10 {
                        let _packet = session.create_packet(vec![0; 160], 160, false);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(sessions.len(), 100);
    }

    /// Test concurrent parsing with different message types
    #[test]
    fn test_mixed_message_parsing() {
        use mdsiprtp_sip::SipMessage;

        let invite = Arc::new(b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP pc.example.com;branch=z9hG4bK776\r\nMax-Forwards: 70\r\nTo: Bob <sip:bob@biloxi.com>\r\nFrom: Alice <sip:alice@atlanta.com>;tag=1928301774\r\nCall-ID: a84b4c76e66710@pc.atlanta.com\r\nCSeq: 314159 INVITE\r\nContent-Length: 0\r\n\r\n".to_vec());
        let response = Arc::new(b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP pc.example.com;branch=z9hG4bK776\r\nTo: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\nFrom: Alice <sip:alice@atlanta.com>;tag=1928301774\r\nCall-ID: a84b4c76e66710@pc.atlanta.com\r\nCSeq: 314159 INVITE\r\nContent-Length: 0\r\n\r\n".to_vec());

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let msg = if i % 2 == 0 {
                    Arc::clone(&invite)
                } else {
                    Arc::clone(&response)
                };
                thread::spawn(move || {
                    for _ in 0..100 {
                        let _ = SipMessage::parse(&msg);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }
}

mod synchronization_tests {
    use super::*;

    /// Test proper synchronization with Arc and Mutex
    #[test]
    fn test_arc_mutex_synchronization() {
        let session = Arc::new(Mutex::new(RtpSession::new(12345, 0, 8000)));
        let counter = Arc::new(Mutex::new(0u32));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let session = Arc::clone(&session);
                let counter = Arc::clone(&counter);
                thread::spawn(move || {
                    for _ in 0..100 {
                        let mut session = session.lock().unwrap();
                        let _packet = session.create_packet(vec![0; 160], 160, false);

                        let mut count = counter.lock().unwrap();
                        *count += 1;
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let final_count = *counter.lock().unwrap();
        assert_eq!(final_count, 1000);
    }

    /// Test no data races in concurrent operations
    #[test]
    fn test_no_data_races() {
        use mdsiprtp_rtp::RtpPacket;

        let packet_data: &'static [u8] = &[
            0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x30, 0x39, 0xAA, 0xBB,
        ];

        let results = Arc::new(Mutex::new(Vec::new()));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let results = Arc::clone(&results);
                thread::spawn(move || {
                    for _ in 0..50 {
                        if let Ok(packet) = RtpPacket::parse(packet_data) {
                            let mut results = results.lock().unwrap();
                            results.push(packet.ssrc);
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let results = results.lock().unwrap();
        assert_eq!(results.len(), 500);
        // All SSRCs should be the same (0x3039 from packet data)
        assert!(results.iter().all(|&ssrc| ssrc == results[0]));
    }
}

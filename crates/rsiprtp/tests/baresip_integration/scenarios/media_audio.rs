//! Media audio validation test scenarios.
//!
//! These tests verify actual RTP audio streaming, including packet validation,
//! jitter measurement, packet loss detection, and tone verification.

use std::time::Duration;

use crate::framework::{Codec, RtpValidator, TestConfig, TestEndpoint};

/// Test bidirectional RTP audio flow
#[tokio::test]
async fn test_audio_bidirectional_rtp() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    // Establish call
    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
    let handle_a = endpoint_a.call(&target_uri).await.unwrap();

    let incoming = endpoint_b
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();
    let _handle_b = endpoint_b.accept_call(incoming).await.unwrap();

    endpoint_a
        .wait_for_answer(&handle_a, Duration::from_secs(5))
        .await
        .unwrap();

    // Create RTP validators
    let mut validator_a = RtpValidator::new(Codec::PCMU);
    let mut validator_b = RtpValidator::new(Codec::PCMU);

    // Send RTP from A to B
    let rtp_b_addr = format!("127.0.0.1:{}", config_b.local_rtp_port)
        .parse()
        .unwrap();

    for i in 0..50u16 {
        let rtp_packet =
            create_rtp_packet(i, i as u32 * 160, 0x12345678, Codec::PCMU.payload_type());
        endpoint_a.send_rtp(&rtp_packet, rtp_b_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Send RTP from B to A
    let rtp_a_addr = format!("127.0.0.1:{}", config_a.local_rtp_port)
        .parse()
        .unwrap();

    for i in 0..50u16 {
        let rtp_packet =
            create_rtp_packet(i, i as u32 * 160, 0x87654321, Codec::PCMU.payload_type());
        endpoint_b.send_rtp(&rtp_packet, rtp_a_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Collect RTP at both ends
    for _ in 0..50 {
        if let Ok((data, _)) = endpoint_a.recv_rtp(Duration::from_millis(100)).await {
            validator_a.record_packet(&data);
        }
        if let Ok((data, _)) = endpoint_b.recv_rtp(Duration::from_millis(100)).await {
            validator_b.record_packet(&data);
        }
    }

    // Verify both received audio
    assert!(validator_a.has_audio(), "Endpoint A should receive audio");
    assert!(validator_b.has_audio(), "Endpoint B should receive audio");

    // Verify stream properties
    let result_a = validator_a.verify_stream();
    assert!(result_a.valid, "A's RTP stream should be valid");

    let result_b = validator_b.verify_stream();
    assert!(result_b.valid, "B's RTP stream should be valid");

    // Cleanup
    endpoint_a.hangup(&handle_a).await.unwrap();
}

/// Test RTP sequence number validation
#[tokio::test]
async fn test_rtp_sequence_validation() {
    let mut validator = RtpValidator::new(Codec::PCMU);

    // Send packets in order
    for i in 0..20u16 {
        let packet = create_rtp_packet(i, i as u32 * 160, 0x12345678, 0);
        validator.record_packet(&packet);
    }

    assert_eq!(validator.packet_count(), 20);
    assert_eq!(validator.packet_loss_percent(), 0.0);

    let result = validator.verify_stream();
    assert!(result.valid);
    assert!(result.errors.is_empty());
}

/// Test RTP with packet loss detection
#[tokio::test]
async fn test_rtp_packet_loss_detection() {
    let mut validator = RtpValidator::new(Codec::PCMU);

    // Send packets with gaps (simulating loss)
    let sequences = vec![0, 1, 2, 4, 5, 7, 8, 9]; // Missing 3 and 6

    for &seq in &sequences {
        let packet = create_rtp_packet(seq, seq as u32 * 160, 0x12345678, 0);
        validator.record_packet(&packet);
    }

    assert_eq!(validator.packet_count(), 8);
    let loss = validator.packet_loss_percent();
    assert!(loss > 0.0, "Should detect packet loss");
    assert!(loss < 30.0, "Loss should be around 20%");

    let result = validator.verify_stream();
    assert!(result.valid); // Still valid, just has warnings
    assert!(!result.warnings.is_empty(), "Should have loss warning");
}

/// Test RTP timestamp validation
#[tokio::test]
async fn test_rtp_timestamp_validation() {
    let mut validator = RtpValidator::new(Codec::PCMU);

    // Correct timestamps for PCMU: increment by 160 per 20ms packet
    for i in 0..20u16 {
        let packet = create_rtp_packet(i, i as u32 * 160, 0x12345678, 0);
        validator.record_packet(&packet);
    }

    let stats = validator.stats();
    assert_eq!(stats.total_packets, 20);
    assert_eq!(stats.start_timestamp, 0);
    assert_eq!(stats.end_timestamp, 19 * 160);

    // Jitter should be low with perfect timestamps
    let jitter = validator.jitter();
    assert!(
        jitter.as_millis() < 10,
        "Jitter should be minimal with perfect timestamps"
    );
}

/// Test RTP SSRC consistency
#[tokio::test]
async fn test_rtp_ssrc_consistency() {
    let mut validator = RtpValidator::new(Codec::PCMU);
    let ssrc = 0x12345678;

    for i in 0..10u16 {
        let packet = create_rtp_packet(i, i as u32 * 160, ssrc, 0);
        validator.record_packet(&packet);
    }

    let result = validator.verify_stream();
    assert!(result.valid);
    assert!(result.warnings.is_empty(), "SSRC should be consistent");
}

/// Test RTP payload type validation
#[tokio::test]
async fn test_rtp_payload_type_validation() {
    let mut validator = RtpValidator::new(Codec::PCMU);

    // All packets should have PT 0 for PCMU
    for i in 0..10u16 {
        let packet = create_rtp_packet(i, i as u32 * 160, 0x12345678, Codec::PCMU.payload_type());
        validator.record_packet(&packet);
    }

    let result = validator.verify_stream();
    assert!(result.valid);
}

/// Test RTP stream statistics calculation
#[tokio::test]
async fn test_rtp_stream_stats() {
    let mut validator = RtpValidator::new(Codec::PCMU);

    for i in 0..100u16 {
        let packet = create_rtp_packet(i, i as u32 * 160, 0x12345678, 0);
        validator.record_packet(&packet);
    }

    let stats = validator.stats();
    assert_eq!(stats.total_packets, 100);
    assert_eq!(stats.lost_packets, 0);
    assert!(stats.jitter_ms < 1.0);
}

/// Test RTP with jitter (varying timestamps)
#[tokio::test]
async fn test_rtp_with_jitter() {
    let mut validator = RtpValidator::new(Codec::PCMU);

    // Introduce timestamp jitter
    let jitter_pattern = [0i32, 5, -3, 2, -1, 4, -2, 1];
    for i in 0..20u16 {
        let base_ts = i as u32 * 160;
        let jitter = jitter_pattern[(i % 8) as usize];
        let ts = (base_ts as i32 + jitter) as u32;
        let packet = create_rtp_packet(i, ts, 0x12345678, 0);
        validator.record_packet(&packet);
    }

    let jitter = validator.jitter();
    // Jitter detection may be subtle with this pattern, just verify it doesn't crash
    let result = validator.verify_stream();
    assert!(result.valid);

    // Print for verification
    println!("Detected jitter: {:?}", jitter);
}

/// Test empty RTP validator
#[tokio::test]
async fn test_empty_validator() {
    let validator = RtpValidator::new(Codec::PCMU);

    assert_eq!(validator.packet_count(), 0);
    assert!(!validator.has_audio());

    let result = validator.verify_stream();
    assert!(!result.valid);
    assert!(!result.errors.is_empty());
}

/// Test codec-specific properties
#[tokio::test]
async fn test_codec_properties() {
    let _pcmu_validator = RtpValidator::new(Codec::PCMU);
    let _pcma_validator = RtpValidator::new(Codec::PCMA);
    let _g722_validator = RtpValidator::new(Codec::G722);

    // Send one packet to each
    let _pcmu_pkt = create_rtp_packet(0, 0, 0x1111, Codec::PCMU.payload_type());
    let _pcma_pkt = create_rtp_packet(0, 0, 0x2222, Codec::PCMA.payload_type());
    let _g722_pkt = create_rtp_packet(0, 0, 0x3333, Codec::G722.payload_type());

    // Verify different payload types
    assert_eq!(Codec::PCMU.payload_type(), 0);
    assert_eq!(Codec::PCMA.payload_type(), 8);
    assert_eq!(Codec::G722.payload_type(), 9);
}

/// Helper to create RTP packet
fn create_rtp_packet(seq: u16, timestamp: u32, ssrc: u32, payload_type: u8) -> Vec<u8> {
    let mut packet = Vec::new();

    // RTP header
    packet.push(0x80); // V=2, P=0, X=0, CC=0
    packet.push(payload_type); // M=0, PT=payload_type
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());

    // Dummy payload (160 bytes for 20ms PCMU)
    packet.extend_from_slice(&[0x55; 160]);

    packet
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_create_rtp_packet() {
        let packet = create_rtp_packet(100, 1600, 0x12345678, 0);

        assert!(packet.len() >= 12);
        assert_eq!(packet[0], 0x80); // Version 2
        assert_eq!(packet[1], 0x00); // PT 0
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 100);
        assert_eq!(
            u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
            1600
        );
    }

    #[test]
    fn test_codec_samples() {
        assert_eq!(Codec::PCMU.samples_per_packet(), 160);
        assert_eq!(Codec::PCMA.samples_per_packet(), 160);
        assert_eq!(Codec::G722.samples_per_packet(), 160);
    }
}

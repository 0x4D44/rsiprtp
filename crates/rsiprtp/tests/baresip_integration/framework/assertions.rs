//! Test assertions for SIP/RTP integration tests.

use super::sip_endpoint::{CallHandle, RtpStats, TestCallState, TestEndpoint};

/// Assert that RTP media is flowing (packets being received).
pub fn assert_rtp_flowing(stats: &RtpStats) {
    assert!(
        stats.packets_received > 0,
        "Expected RTP packets, got {}",
        stats.packets_received
    );
}

/// Assert that a minimum number of RTP packets have been received.
pub fn assert_rtp_packets_received(stats: &RtpStats, min_packets: u64) {
    assert!(
        stats.packets_received >= min_packets,
        "Expected at least {} RTP packets, got {}",
        min_packets,
        stats.packets_received
    );
}

/// Assert that packet loss is below a threshold.
pub fn assert_packet_loss_below(stats: &RtpStats, max_loss_percent: f64) {
    assert!(
        stats.packet_loss_percent < max_loss_percent,
        "Packet loss too high: {}% (max {}%)",
        stats.packet_loss_percent,
        max_loss_percent
    );
}

/// Assert that a call is in the established state.
pub fn assert_call_established(endpoint: &TestEndpoint, handle: &CallHandle) {
    let state = endpoint.call_state(handle);
    assert_eq!(
        state,
        Some(TestCallState::Established),
        "Expected call to be Established, got {:?}",
        state
    );
}

/// Assert that a call is terminated.
pub fn assert_call_terminated(endpoint: &TestEndpoint, handle: &CallHandle) {
    let state = endpoint.call_state(handle);
    assert_eq!(
        state,
        Some(TestCallState::Terminated),
        "Expected call to be Terminated, got {:?}",
        state
    );
}

/// Assert that DTMF digits were received.
pub fn assert_dtmf_received(endpoint: &TestEndpoint, handle: &CallHandle, expected: &[char]) {
    let received = endpoint.received_dtmf(handle);
    assert_eq!(
        received, expected,
        "DTMF mismatch: expected {:?}, got {:?}",
        expected, received
    );
}

/// Assert that at least the expected DTMF digits were received (order matters).
pub fn assert_dtmf_contains(endpoint: &TestEndpoint, handle: &CallHandle, expected: &[char]) {
    let received = endpoint.received_dtmf(handle);
    for (i, digit) in expected.iter().enumerate() {
        assert!(
            received.get(i) == Some(digit),
            "DTMF digit {} mismatch: expected '{}', got {:?}",
            i,
            digit,
            received.get(i)
        );
    }
}

/// Helper macro for skipping tests if baresip is not available.
#[macro_export]
macro_rules! require_baresip {
    () => {
        if !$crate::framework::config::is_baresip_available() {
            eprintln!("Test skipped: baresip not installed");
            return;
        }
    };
}

/// Helper to check if an SDP contains a specific codec.
pub fn sdp_has_codec(sdp: &str, codec_name: &str) -> bool {
    sdp.to_lowercase()
        .contains(&"a=rtpmap:".to_string().to_lowercase())
        && sdp.to_lowercase().contains(&codec_name.to_lowercase())
}

/// Extract media port from SDP.
pub fn extract_sdp_media_port(sdp: &str) -> Option<u16> {
    for line in sdp.lines() {
        if line.starts_with("m=audio ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse().ok();
            }
        }
    }
    None
}

/// Extract connection address from SDP.
pub fn extract_sdp_connection_address(sdp: &str) -> Option<String> {
    for line in sdp.lines() {
        if let Some(addr) = line.strip_prefix("c=IN IP4 ") {
            return Some(addr.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdp_has_codec() {
        let sdp = "v=0\r\nm=audio 5000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        assert!(sdp_has_codec(sdp, "PCMU"));
        assert!(!sdp_has_codec(sdp, "OPUS"));
    }

    #[test]
    fn test_extract_sdp_media_port() {
        let sdp = "v=0\r\nm=audio 5000 RTP/AVP 0\r\n";
        assert_eq!(extract_sdp_media_port(sdp), Some(5000));
    }

    #[test]
    fn test_extract_sdp_connection_address() {
        let sdp = "v=0\r\nc=IN IP4 192.168.1.1\r\nm=audio 5000 RTP/AVP 0\r\n";
        assert_eq!(
            extract_sdp_connection_address(sdp),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_rtp_stats_assertions() {
        let good_stats = RtpStats {
            packets_received: 100,
            packets_sent: 100,
            bytes_received: 16000,
            bytes_sent: 16000,
            packet_loss_percent: 1.0,
        };

        assert_rtp_flowing(&good_stats);
        assert_rtp_packets_received(&good_stats, 50);
        assert_packet_loss_below(&good_stats, 5.0);
    }

    #[test]
    #[should_panic(expected = "Expected RTP packets")]
    fn test_rtp_flowing_fails_on_zero() {
        let bad_stats = RtpStats::default();
        assert_rtp_flowing(&bad_stats);
    }
}

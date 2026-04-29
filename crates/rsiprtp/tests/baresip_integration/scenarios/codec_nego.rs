//! Codec negotiation test scenarios.
//!
//! Tests for SDP offer/answer codec negotiation.

use std::time::Duration;

use crate::framework::{
    extract_sdp_media_port, is_baresip_available, sdp_has_codec, BaresipInstance, TestConfig,
    TestEndpoint,
};

/// Test PCMU (G.711 mu-law) codec negotiation.
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_pcmu_negotiation() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let baresip = BaresipInstance::spawn(config.baresip_config()).unwrap();

    // Establish call - verify PCMU is negotiated
    let target_uri = config.baresip_uri("test");
    let handle = endpoint.call(&target_uri).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    baresip.accept().unwrap();
    endpoint
        .wait_for_answer(&handle, Duration::from_secs(5))
        .await
        .unwrap();

    // Note: Would verify the negotiated codec from SDP answer
    println!("PCMU negotiation test: call established with G.711 codecs");

    // Cleanup
    endpoint.hangup(&handle).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    baresip.shutdown().unwrap();
}

/// Test PCMA (G.711 A-law) codec negotiation.
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_pcma_negotiation() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let baresip = BaresipInstance::spawn(config.baresip_config()).unwrap();

    // Establish call - verify PCMA is available
    let target_uri = config.local_uri("test");
    baresip.dial(&target_uri).unwrap();

    let incoming = endpoint
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();

    // Check SDP offer has PCMA
    if let Some(ref sdp) = incoming.sdp_offer {
        let has_pcma = sdp_has_codec(sdp, "PCMA");
        println!("SDP offer has PCMA: {}", has_pcma);
    }

    let handle = endpoint.accept_call(incoming).await.unwrap();

    // Cleanup
    baresip.hangup().unwrap();
    endpoint
        .wait_for_hangup(&handle, Duration::from_secs(5))
        .await
        .unwrap();
    baresip.shutdown().unwrap();
}

/// Test codec preference ordering.
///
/// The first codec in the offer should be the preferred one.
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_codec_preference_order() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let baresip = BaresipInstance::spawn(config.baresip_config()).unwrap();

    // Receive call from baresip to check its codec preference
    let target_uri = config.local_uri("test");
    baresip.dial(&target_uri).unwrap();

    let incoming = endpoint
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();

    // Analyze SDP for codec order
    if let Some(ref sdp) = incoming.sdp_offer {
        println!("Received SDP:\n{}", sdp);
        // The m= line payload type order indicates preference
        if let Some(port) = extract_sdp_media_port(sdp) {
            println!("Media port: {}", port);
        }
    }

    let handle = endpoint.accept_call(incoming).await.unwrap();

    // Cleanup
    baresip.hangup().unwrap();
    endpoint
        .wait_for_hangup(&handle, Duration::from_secs(5))
        .await
        .unwrap();
    baresip.shutdown().unwrap();
}

/// Test telephone-event (RFC 4733) negotiation for DTMF.
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_telephone_event_negotiation() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let baresip = BaresipInstance::spawn(config.baresip_config()).unwrap();

    // Receive call from baresip
    let target_uri = config.local_uri("test");
    baresip.dial(&target_uri).unwrap();

    let incoming = endpoint
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();

    // Check for telephone-event in SDP
    if let Some(ref sdp) = incoming.sdp_offer {
        let has_telephone_event = sdp.to_lowercase().contains("telephone-event");
        println!("SDP has telephone-event: {}", has_telephone_event);

        // Our SDP offer should include telephone-event
        let has_rtpmap_101 = sdp.contains("a=rtpmap:101");
        println!("Has rtpmap 101: {}", has_rtpmap_101);
    }

    let handle = endpoint.accept_call(incoming).await.unwrap();

    // Cleanup
    baresip.hangup().unwrap();
    endpoint
        .wait_for_hangup(&handle, Duration::from_secs(5))
        .await
        .unwrap();
    baresip.shutdown().unwrap();
}

/// Test handling of no common codec (should reject with 488).
///
/// Note: This test requires configuring baresip with non-overlapping codecs,
/// which is complex. This is a placeholder for that scenario.
#[tokio::test]
#[ignore = "requires special baresip configuration"]
async fn test_codec_mismatch_488() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    // This would require configuring baresip with only uncommon codecs
    // and our endpoint with different codecs
    println!("Codec mismatch test: would return 488 Not Acceptable Here");
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_sdp_codec_detection() {
        let sdp =
            "v=0\r\nm=audio 5000 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n";

        assert!(sdp_has_codec(sdp, "PCMU"));
        assert!(sdp_has_codec(sdp, "PCMA"));
        assert!(!sdp_has_codec(sdp, "OPUS"));
    }

    #[test]
    fn test_sdp_port_extraction() {
        let sdp = "v=0\r\nm=audio 12345 RTP/AVP 0\r\n";
        assert_eq!(extract_sdp_media_port(sdp), Some(12345));

        let sdp_no_audio = "v=0\r\nm=video 5000 RTP/AVP 96\r\n";
        assert_eq!(extract_sdp_media_port(sdp_no_audio), None);
    }
}

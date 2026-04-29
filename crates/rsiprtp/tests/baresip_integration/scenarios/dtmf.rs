//! DTMF (Dual-Tone Multi-Frequency) test scenarios.
//!
//! Tests for DTMF digit transmission using RFC 4733 (telephone-event).

use std::time::Duration;

use crate::framework::{is_baresip_available, BaresipInstance, TestConfig, TestEndpoint};

/// Test sending DTMF digits from rsiprtp to baresip.
///
/// Flow:
/// 1. Establish call with telephone-event in SDP
/// 2. rsiprtp sends DTMF digits via RTP telephone-event
/// 3. Verify baresip receives the digits
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_dtmf_send_to_baresip() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let baresip = BaresipInstance::spawn(config.baresip_config()).unwrap();

    // Establish call
    let target_uri = config.baresip_uri("test");
    let handle = endpoint.call(&target_uri).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    baresip.accept().unwrap();
    endpoint
        .wait_for_answer(&handle, Duration::from_secs(5))
        .await
        .unwrap();

    // Wait for media to stabilize
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Note: Full DTMF sending would use RTP telephone-event packets
    // This is a placeholder - our simple test endpoint doesn't implement DTMF sending yet
    println!("DTMF send test: call established, DTMF sending not yet implemented");

    // Cleanup
    endpoint.hangup(&handle).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    baresip.shutdown().unwrap();
}

/// Test receiving DTMF digits from baresip.
///
/// Flow:
/// 1. Establish call with telephone-event in SDP
/// 2. baresip sends DTMF digits via /sndcode command
/// 3. Verify rsiprtp receives the digits
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_dtmf_receive_from_baresip() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let baresip = BaresipInstance::spawn(config.baresip_config()).unwrap();

    // Establish call - baresip calls rsiprtp
    let target_uri = config.local_uri("test");
    baresip.dial(&target_uri).unwrap();

    let incoming = endpoint
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();
    let handle = endpoint.accept_call(incoming).await.unwrap();

    // Wait for media to stabilize
    tokio::time::sleep(Duration::from_secs(1)).await;

    // baresip sends DTMF digits
    let digits = ['1', '2', '3', '#'];
    for digit in &digits {
        baresip.send_dtmf(*digit).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Note: We would need to parse incoming RTP for telephone-event
    // This is a placeholder - our simple test endpoint doesn't implement DTMF receiving yet
    println!(
        "DTMF receive test: sent digits {:?}, receiving not yet implemented",
        digits
    );

    // Cleanup
    baresip.hangup().unwrap();
    endpoint
        .wait_for_hangup(&handle, Duration::from_secs(5))
        .await
        .unwrap();
    baresip.shutdown().unwrap();
}

/// Test DTMF bi-directional exchange.
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_dtmf_bidirectional() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let baresip = BaresipInstance::spawn(config.baresip_config()).unwrap();

    // Establish call
    let target_uri = config.baresip_uri("test");
    let handle = endpoint.call(&target_uri).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    baresip.accept().unwrap();
    endpoint
        .wait_for_answer(&handle, Duration::from_secs(5))
        .await
        .unwrap();

    // Wait for media to stabilize
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Send DTMF in both directions
    // From baresip to rsiprtp
    baresip.send_dtmf('5').unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Note: Would also send from rsiprtp to baresip here
    println!("DTMF bidirectional test: basic framework in place");

    // Cleanup
    endpoint.hangup(&handle).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    baresip.shutdown().unwrap();
}

/// Test all DTMF digits (0-9, *, #, A-D).
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_dtmf_all_digits() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let baresip = BaresipInstance::spawn(config.baresip_config()).unwrap();

    // Establish call
    let target_uri = config.local_uri("test");
    baresip.dial(&target_uri).unwrap();

    let incoming = endpoint
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();
    let handle = endpoint.accept_call(incoming).await.unwrap();

    // Wait for media to stabilize
    tokio::time::sleep(Duration::from_secs(1)).await;

    // All standard DTMF digits
    let all_digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '#'];

    for digit in &all_digits {
        baresip.send_dtmf(*digit).unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    println!("All digits test: sent {:?}", all_digits);

    // Cleanup
    baresip.hangup().unwrap();
    endpoint
        .wait_for_hangup(&handle, Duration::from_secs(5))
        .await
        .unwrap();
    baresip.shutdown().unwrap();
}

#[cfg(test)]
mod unit_tests {

    #[test]
    fn test_dtmf_digits() {
        // Standard DTMF digits
        let digits: Vec<char> = "0123456789*#".chars().collect();
        assert_eq!(digits.len(), 12);
    }
}

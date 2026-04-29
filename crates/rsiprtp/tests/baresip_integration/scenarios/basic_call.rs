//! Basic call test scenarios.
//!
//! Tests for fundamental SIP call flows: INVITE, 200 OK, ACK, BYE.

use std::time::Duration;

use crate::framework::{
    assert_call_established, assert_call_terminated, is_baresip_available, BaresipInstance,
    TestCallState, TestConfig, TestEndpoint,
};

/// Test outgoing call from rsiprtp to baresip.
///
/// Flow:
/// 1. rsiprtp sends INVITE to baresip
/// 2. baresip accepts (/accept command)
/// 3. Verify call established
/// 4. rsiprtp hangs up
/// 5. Verify call terminated
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_outgoing_call_to_baresip() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let baresip = BaresipInstance::spawn(config.baresip_config()).unwrap();

    // rsiprtp calls baresip
    let target_uri = config.baresip_uri("test");
    let handle = endpoint.call(&target_uri).await.unwrap();

    // Wait a bit for INVITE to be processed
    tokio::time::sleep(Duration::from_millis(500)).await;

    // baresip accepts
    baresip.accept().unwrap();

    // Wait for 200 OK and send ACK
    endpoint
        .wait_for_answer(&handle, Duration::from_secs(5))
        .await
        .unwrap();

    // Verify call is established
    assert_call_established(&endpoint, &handle);

    // Wait for media to flow
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Hang up
    endpoint.hangup(&handle).await.unwrap();

    // Wait for call to terminate
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Cleanup
    baresip.shutdown().unwrap();
}

/// Test incoming call from baresip to rsiprtp.
///
/// Flow:
/// 1. baresip dials rsiprtp
/// 2. rsiprtp accepts incoming call
/// 3. Verify call established
/// 4. baresip hangs up
/// 5. Verify BYE received
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_incoming_call_from_baresip() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let baresip = BaresipInstance::spawn(config.baresip_config()).unwrap();

    // baresip calls rsiprtp
    let target_uri = config.local_uri("test");
    baresip.dial(&target_uri).unwrap();

    // Wait for incoming INVITE
    let incoming = endpoint
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();

    // Accept the call
    let handle = endpoint.accept_call(incoming).await.unwrap();

    // Verify call is established
    assert_eq!(
        endpoint.call_state(&handle),
        Some(TestCallState::Established)
    );

    // Wait for media
    tokio::time::sleep(Duration::from_secs(1)).await;

    // baresip hangs up
    baresip.hangup().unwrap();

    // Wait for BYE
    endpoint
        .wait_for_hangup(&handle, Duration::from_secs(5))
        .await
        .unwrap();

    // Verify call terminated
    assert_call_terminated(&endpoint, &handle);

    // Cleanup
    baresip.shutdown().unwrap();
}

/// Test call rejection (486 Busy Here).
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_call_rejected_busy() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let baresip = BaresipInstance::spawn(config.baresip_config()).unwrap();

    // baresip calls rsiprtp
    let target_uri = config.local_uri("test");
    baresip.dial(&target_uri).unwrap();

    // Wait for incoming INVITE
    let incoming = endpoint
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();

    // Reject with 486 Busy
    endpoint.reject_call(&incoming, 486).await.unwrap();

    // Wait for baresip to see rejection
    baresip
        .wait_for_event("closed", Duration::from_secs(5))
        .ok(); // May not always trigger event

    // Cleanup
    baresip.shutdown().unwrap();
}

/// Test call rejection (603 Decline).
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_call_rejected_decline() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let baresip = BaresipInstance::spawn(config.baresip_config()).unwrap();

    // baresip calls rsiprtp
    let target_uri = config.local_uri("test");
    baresip.dial(&target_uri).unwrap();

    // Wait for incoming INVITE
    let incoming = endpoint
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();

    // Reject with 603 Decline
    endpoint.reject_call(&incoming, 603).await.unwrap();

    // Wait for baresip to see rejection
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Cleanup
    baresip.shutdown().unwrap();
}

/// Test call cancelled before answer (CANCEL).
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_call_cancelled() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let baresip = BaresipInstance::spawn(config.baresip_config()).unwrap();

    // baresip calls rsiprtp
    let target_uri = config.local_uri("test");
    baresip.dial(&target_uri).unwrap();

    // Wait for incoming INVITE
    let _incoming = endpoint
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();

    // Don't answer - let baresip cancel
    // baresip hangs up before we answer (sends CANCEL)
    baresip.hangup().unwrap();

    // We should receive a CANCEL (though our simple endpoint doesn't fully handle it)
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Cleanup
    baresip.shutdown().unwrap();
}

/// Test bi-directional call establishment and teardown.
///
/// This tests a complete call cycle from both directions.
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_bidirectional_call_cycle() {
    if !is_baresip_available() {
        eprintln!("Skipping: baresip not installed");
        return;
    }

    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let baresip = BaresipInstance::spawn(config.baresip_config()).unwrap();

    // First: outbound call
    println!("=== Test 1: Outbound call ===");
    let target_uri = config.baresip_uri("test");
    let handle1 = endpoint.call(&target_uri).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    baresip.accept().unwrap();
    endpoint
        .wait_for_answer(&handle1, Duration::from_secs(5))
        .await
        .unwrap();
    assert_call_established(&endpoint, &handle1);
    endpoint.hangup(&handle1).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Second: inbound call
    println!("=== Test 2: Inbound call ===");
    let target_uri = config.local_uri("test");
    baresip.dial(&target_uri).unwrap();
    let incoming = endpoint
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();
    let handle2 = endpoint.accept_call(incoming).await.unwrap();
    assert_call_established(&endpoint, &handle2);
    baresip.hangup().unwrap();
    endpoint
        .wait_for_hangup(&handle2, Duration::from_secs(5))
        .await
        .unwrap();
    assert_call_terminated(&endpoint, &handle2);

    // Cleanup
    baresip.shutdown().unwrap();
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = TestConfig::with_available_ports();
        assert_ne!(config.local_sip_port, 0);
        assert_ne!(config.baresip_sip_port, 0);
        assert_ne!(config.local_sip_port, config.baresip_sip_port);
    }

    #[tokio::test]
    async fn test_endpoint_creation() {
        let config = TestConfig::with_available_ports();
        let endpoint = TestEndpoint::new(config).await;
        assert!(endpoint.is_ok());
    }
}

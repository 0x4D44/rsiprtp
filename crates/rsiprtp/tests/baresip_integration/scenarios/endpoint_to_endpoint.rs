//! Endpoint-to-endpoint test scenarios.
//!
//! These tests verify SIP signaling between two TestEndpoint instances,
//! providing integration testing without requiring external dependencies.

use std::time::Duration;

use crate::framework::{TestCallState, TestConfig, TestEndpoint};

/// Test basic call flow between two endpoints.
///
/// Flow:
/// 1. Endpoint A sends INVITE to Endpoint B
/// 2. Endpoint B accepts
/// 3. Verify both endpoints see call as established
/// 4. Endpoint A hangs up
/// 5. Verify call terminated
#[tokio::test]
async fn test_endpoint_to_endpoint_basic_call() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    // A calls B
    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
    let handle_a = endpoint_a.call(&target_uri).await.unwrap();

    // B waits for and accepts the call
    let incoming = endpoint_b
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();
    let handle_b = endpoint_b.accept_call(incoming).await.unwrap();

    // A waits for answer
    endpoint_a
        .wait_for_answer(&handle_a, Duration::from_secs(5))
        .await
        .unwrap();

    // Verify both sides are established
    assert_eq!(
        endpoint_a.call_state(&handle_a),
        Some(TestCallState::Established)
    );
    assert_eq!(
        endpoint_b.call_state(&handle_b),
        Some(TestCallState::Established)
    );

    // A hangs up
    endpoint_a.hangup(&handle_a).await.unwrap();

    // B should receive BYE
    endpoint_b
        .wait_for_hangup(&handle_b, Duration::from_secs(5))
        .await
        .unwrap();

    // Verify B's call is terminated
    assert_eq!(
        endpoint_b.call_state(&handle_b),
        Some(TestCallState::Terminated)
    );
}

/// Test call rejection with 486 Busy.
#[tokio::test]
async fn test_endpoint_to_endpoint_call_rejected() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    // A calls B
    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
    let handle_a = endpoint_a.call(&target_uri).await.unwrap();

    // B waits for call and rejects it
    let incoming = endpoint_b
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();
    endpoint_b.reject_call(&incoming, 486).await.unwrap();

    // A should receive rejection
    let result = endpoint_a
        .wait_for_answer(&handle_a, Duration::from_secs(5))
        .await;

    // Should fail with rejection
    assert!(result.is_err());
}

/// Test call with BYE from callee.
#[tokio::test]
async fn test_endpoint_to_endpoint_callee_hangup() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    // A calls B
    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
    let handle_a = endpoint_a.call(&target_uri).await.unwrap();

    // B accepts
    let incoming = endpoint_b
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();
    let handle_b = endpoint_b.accept_call(incoming).await.unwrap();

    // A waits for answer
    endpoint_a
        .wait_for_answer(&handle_a, Duration::from_secs(5))
        .await
        .unwrap();

    // B hangs up
    endpoint_b.hangup(&handle_b).await.unwrap();

    // A should receive BYE
    endpoint_a
        .wait_for_hangup(&handle_a, Duration::from_secs(5))
        .await
        .unwrap();

    // Verify A's call is terminated
    assert_eq!(
        endpoint_a.call_state(&handle_a),
        Some(TestCallState::Terminated)
    );
}

/// Test multiple concurrent calls.
#[tokio::test]
async fn test_endpoint_to_endpoint_multiple_calls() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();
    let config_c = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();
    let mut endpoint_c = TestEndpoint::new(config_c.clone()).await.unwrap();

    // A calls B
    let target_b = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
    let handle_ab = endpoint_a.call(&target_b).await.unwrap();

    // B accepts A's call
    let incoming_b = endpoint_b
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();
    let handle_ba = endpoint_b.accept_call(incoming_b).await.unwrap();

    // A waits for B's answer
    endpoint_a
        .wait_for_answer(&handle_ab, Duration::from_secs(5))
        .await
        .unwrap();

    // Now C calls A (while A-B call is active)
    let target_a = format!("sip:test@127.0.0.1:{}", config_a.local_sip_port);
    let handle_ca = endpoint_c.call(&target_a).await.unwrap();

    // A receives C's call
    let incoming_a = endpoint_a
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();
    let handle_ac = endpoint_a.accept_call(incoming_a).await.unwrap();

    // C waits for A's answer
    endpoint_c
        .wait_for_answer(&handle_ca, Duration::from_secs(5))
        .await
        .unwrap();

    // Verify all calls established
    assert_eq!(
        endpoint_a.call_state(&handle_ab),
        Some(TestCallState::Established)
    );
    assert_eq!(
        endpoint_a.call_state(&handle_ac),
        Some(TestCallState::Established)
    );
    assert_eq!(
        endpoint_b.call_state(&handle_ba),
        Some(TestCallState::Established)
    );
    assert_eq!(
        endpoint_c.call_state(&handle_ca),
        Some(TestCallState::Established)
    );

    // Cleanup - hang up all calls
    endpoint_a.hangup(&handle_ab).await.unwrap();
    endpoint_c.hangup(&handle_ca).await.unwrap();
}

/// Test rapid call setup/teardown cycle.
#[tokio::test]
async fn test_endpoint_to_endpoint_rapid_cycle() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);

    // Perform 3 rapid call cycles
    for i in 0..3 {
        println!("Call cycle {}", i + 1);

        // A calls B
        let handle_a = endpoint_a.call(&target_uri).await.unwrap();

        // B accepts
        let incoming = endpoint_b
            .wait_for_incoming(Duration::from_secs(5))
            .await
            .unwrap();
        let handle_b = endpoint_b.accept_call(incoming).await.unwrap();

        // A waits for answer
        endpoint_a
            .wait_for_answer(&handle_a, Duration::from_secs(5))
            .await
            .unwrap();

        // Brief call duration
        tokio::time::sleep(Duration::from_millis(100)).await;

        // A hangs up
        endpoint_a.hangup(&handle_a).await.unwrap();

        // B receives BYE
        endpoint_b
            .wait_for_hangup(&handle_b, Duration::from_secs(5))
            .await
            .unwrap();

        // Small delay between cycles
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Test SDP exchange verification.
#[tokio::test]
async fn test_endpoint_to_endpoint_sdp_exchange() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    // A calls B
    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
    let _handle_a = endpoint_a.call(&target_uri).await.unwrap();

    // B receives INVITE with SDP
    let incoming = endpoint_b
        .wait_for_incoming(Duration::from_secs(5))
        .await
        .unwrap();

    // Verify SDP is present in offer
    assert!(
        incoming.sdp_offer.is_some(),
        "INVITE should contain SDP offer"
    );

    let sdp = incoming.sdp_offer.as_ref().unwrap();

    // Verify SDP contains required fields
    assert!(sdp.contains("v=0"), "SDP should have version line");
    assert!(sdp.contains("m=audio"), "SDP should have audio media line");
    assert!(
        sdp.contains("PCMU") || sdp.contains("PCMA"),
        "SDP should have G.711 codec"
    );

    // B accepts
    let _handle_b = endpoint_b.accept_call(incoming).await.unwrap();
}

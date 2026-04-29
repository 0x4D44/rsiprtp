//! Call transfer and conference test scenarios.
//!
//! These tests verify SIP call transfer functionality including blind transfer,
//! attended transfer, and conference bridge scenarios.

use std::time::Duration;

use crate::framework::{TestCallState, TestConfig, TestEndpoint};

/// Test blind transfer simulation between three endpoints
///
/// Flow:
/// 1. A calls B
/// 2. B accepts
/// 3. B initiates transfer to C (simulated via new call)
/// 4. C accepts
/// 5. Verify A-C are now connected (simulated)
#[tokio::test]
async fn test_blind_transfer_simulation() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();
    let config_c = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();
    let mut endpoint_c = TestEndpoint::new(config_c.clone()).await.unwrap();

    // Step 1: A calls B
    let target_b = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
    let handle_ab = endpoint_a.call(&target_b).await.unwrap();

    let incoming_b = endpoint_b
        .wait_for_incoming(Duration::from_secs(2))
        .await
        .unwrap();
    let handle_ba = endpoint_b.accept_call(incoming_b).await.unwrap();

    endpoint_a
        .wait_for_answer(&handle_ab, Duration::from_secs(2))
        .await
        .unwrap();

    // Verify A-B established
    assert_eq!(
        endpoint_a.call_state(&handle_ab),
        Some(TestCallState::Established)
    );

    // Step 2: Simulate transfer - B hangs up with A and C calls A
    endpoint_b.hangup(&handle_ba).await.unwrap();
    endpoint_a
        .wait_for_hangup(&handle_ab, Duration::from_secs(2))
        .await
        .unwrap();

    // Step 3: C calls A (simulating transfer result)
    let target_a = format!("sip:test@127.0.0.1:{}", config_a.local_sip_port);
    let handle_ca = endpoint_c.call(&target_a).await.unwrap();

    let incoming_a = endpoint_a
        .wait_for_incoming(Duration::from_secs(2))
        .await
        .unwrap();
    let handle_ac = endpoint_a.accept_call(incoming_a).await.unwrap();

    endpoint_c
        .wait_for_answer(&handle_ca, Duration::from_secs(2))
        .await
        .unwrap();

    // Verify A-C established (transfer completed)
    assert_eq!(
        endpoint_a.call_state(&handle_ac),
        Some(TestCallState::Established)
    );
    assert_eq!(
        endpoint_c.call_state(&handle_ca),
        Some(TestCallState::Established)
    );

    // Cleanup
    endpoint_c.hangup(&handle_ca).await.unwrap();

    println!("Blind transfer simulation completed");
}

/// Test attended transfer simulation
///
/// Flow:
/// 1. A calls B
/// 2. B puts A on hold (simulated)
/// 3. B calls C
/// 4. B transfers A to C (simulated by B hanging up)
/// 5. A and C are connected
#[tokio::test]
async fn test_attended_transfer_simulation() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();
    let config_c = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();
    let mut endpoint_c = TestEndpoint::new(config_c.clone()).await.unwrap();

    // A calls B
    let target_b = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
    let handle_ab = endpoint_a.call(&target_b).await.unwrap();

    let incoming_b = endpoint_b
        .wait_for_incoming(Duration::from_secs(2))
        .await
        .unwrap();
    let handle_ba = endpoint_b.accept_call(incoming_b).await.unwrap();

    endpoint_a
        .wait_for_answer(&handle_ab, Duration::from_secs(2))
        .await
        .unwrap();

    // B calls C (consultation call)
    let target_c = format!("sip:test@127.0.0.1:{}", config_c.local_sip_port);
    let handle_bc = endpoint_b.call(&target_c).await.unwrap();

    let incoming_c = endpoint_c
        .wait_for_incoming(Duration::from_secs(2))
        .await
        .unwrap();
    let _handle_cb = endpoint_c.accept_call(incoming_c).await.unwrap();

    endpoint_b
        .wait_for_answer(&handle_bc, Duration::from_secs(2))
        .await
        .unwrap();

    // Verify B has two active calls
    assert_eq!(
        endpoint_b.call_state(&handle_ba),
        Some(TestCallState::Established)
    );
    assert_eq!(
        endpoint_b.call_state(&handle_bc),
        Some(TestCallState::Established)
    );

    // Transfer: B hangs up both calls (in real REFER scenario, they'd be connected)
    endpoint_b.hangup(&handle_ba).await.unwrap();
    endpoint_b.hangup(&handle_bc).await.unwrap();

    println!("Attended transfer simulation completed");
}

/// Test conference bridge simulation (3-way call)
///
/// Flow:
/// 1. Create three endpoints
/// 2. Each connects to the others
/// 3. Simulate 3-way conference by having A connected to both B and C
#[tokio::test]
async fn test_conference_bridge_simulation() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();
    let config_c = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();
    let mut endpoint_c = TestEndpoint::new(config_c.clone()).await.unwrap();

    // A calls B
    let target_b = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
    let handle_ab = endpoint_a.call(&target_b).await.unwrap();

    let incoming_b = endpoint_b
        .wait_for_incoming(Duration::from_secs(2))
        .await
        .unwrap();
    let _handle_ba = endpoint_b.accept_call(incoming_b).await.unwrap();

    endpoint_a
        .wait_for_answer(&handle_ab, Duration::from_secs(2))
        .await
        .unwrap();

    // A calls C (adding to conference)
    let target_c = format!("sip:test@127.0.0.1:{}", config_c.local_sip_port);
    let handle_ac = endpoint_a.call(&target_c).await.unwrap();

    let incoming_c = endpoint_c
        .wait_for_incoming(Duration::from_secs(2))
        .await
        .unwrap();
    let _handle_ca = endpoint_c.accept_call(incoming_c).await.unwrap();

    endpoint_a
        .wait_for_answer(&handle_ac, Duration::from_secs(2))
        .await
        .unwrap();

    // Verify all calls established (simulating 3-way conference)
    assert_eq!(
        endpoint_a.call_state(&handle_ab),
        Some(TestCallState::Established)
    );
    assert_eq!(
        endpoint_a.call_state(&handle_ac),
        Some(TestCallState::Established)
    );

    // In real conference, A would mix audio from B and C
    println!("Conference with A as mixer: A-B and A-C both active");

    // Cleanup
    endpoint_a.hangup(&handle_ab).await.unwrap();
    endpoint_a.hangup(&handle_ac).await.unwrap();
}

/// Test transfer rejection scenario
#[tokio::test]
async fn test_transfer_rejection_simulation() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();
    let config_c = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();
    let mut endpoint_c = TestEndpoint::new(config_c.clone()).await.unwrap();

    // A calls B
    let target_b = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
    let handle_ab = endpoint_a.call(&target_b).await.unwrap();

    let incoming_b = endpoint_b
        .wait_for_incoming(Duration::from_secs(2))
        .await
        .unwrap();
    let _handle_ba = endpoint_b.accept_call(incoming_b).await.unwrap();

    endpoint_a
        .wait_for_answer(&handle_ab, Duration::from_secs(2))
        .await
        .unwrap();

    // B tries to transfer to C, but C is busy
    let target_c = format!("sip:test@127.0.0.1:{}", config_c.local_sip_port);
    let handle_bc = endpoint_b.call(&target_c).await.unwrap();

    let incoming_c = endpoint_c
        .wait_for_incoming(Duration::from_secs(2))
        .await
        .unwrap();

    // C rejects the call
    endpoint_c.reject_call(&incoming_c, 486).await.unwrap();

    // B should receive rejection
    let result = endpoint_b
        .wait_for_answer(&handle_bc, Duration::from_secs(2))
        .await;

    assert!(result.is_err(), "Transfer target should be busy");

    // Original A-B call should still be active
    assert_eq!(
        endpoint_a.call_state(&handle_ab),
        Some(TestCallState::Established)
    );

    // Cleanup
    endpoint_a.hangup(&handle_ab).await.unwrap();

    println!("Transfer rejection test completed");
}

/// Test multi-party conference join/leave
#[tokio::test]
async fn test_conference_dynamic_participants() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();
    let config_c = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();
    let mut endpoint_c = TestEndpoint::new(config_c.clone()).await.unwrap();

    // Start with A-B call
    let target_b = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
    let handle_ab = endpoint_a.call(&target_b).await.unwrap();

    let incoming_b = endpoint_b
        .wait_for_incoming(Duration::from_secs(2))
        .await
        .unwrap();
    let handle_ba = endpoint_b.accept_call(incoming_b).await.unwrap();

    endpoint_a
        .wait_for_answer(&handle_ab, Duration::from_secs(2))
        .await
        .unwrap();

    // C joins the conference
    let target_c = format!("sip:test@127.0.0.1:{}", config_c.local_sip_port);
    let handle_ac = endpoint_a.call(&target_c).await.unwrap();

    let incoming_c = endpoint_c
        .wait_for_incoming(Duration::from_secs(2))
        .await
        .unwrap();
    let _handle_ca = endpoint_c.accept_call(incoming_c).await.unwrap();

    endpoint_a
        .wait_for_answer(&handle_ac, Duration::from_secs(2))
        .await
        .unwrap();

    // All three participants active
    assert_eq!(
        endpoint_a.call_state(&handle_ab),
        Some(TestCallState::Established)
    );
    assert_eq!(
        endpoint_a.call_state(&handle_ac),
        Some(TestCallState::Established)
    );

    // B leaves the conference
    endpoint_b.hangup(&handle_ba).await.unwrap();
    endpoint_a
        .wait_for_hangup(&handle_ab, Duration::from_secs(2))
        .await
        .unwrap();

    // A-C should still be active
    assert_eq!(
        endpoint_a.call_state(&handle_ac),
        Some(TestCallState::Established)
    );

    // Cleanup
    endpoint_a.hangup(&handle_ac).await.unwrap();

    println!("Dynamic conference test completed");
}

/// Test rapid transfer scenarios
#[tokio::test]
async fn test_rapid_transfer_cycles() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();
    let config_c = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();
    let mut endpoint_c = TestEndpoint::new(config_c.clone()).await.unwrap();

    // Perform 5 transfer cycles
    for i in 0..5 {
        // A calls B
        let target_b = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
        let handle_ab = endpoint_a.call(&target_b).await.unwrap();

        let incoming_b = endpoint_b
            .wait_for_incoming(Duration::from_secs(2))
            .await
            .unwrap();
        let handle_ba = endpoint_b.accept_call(incoming_b).await.unwrap();

        endpoint_a
            .wait_for_answer(&handle_ab, Duration::from_secs(2))
            .await
            .unwrap();

        // Quick transfer simulation - B disconnects
        endpoint_b.hangup(&handle_ba).await.unwrap();
        endpoint_a
            .wait_for_hangup(&handle_ab, Duration::from_secs(2))
            .await
            .unwrap();

        // C picks up (transfer target)
        let target_c = format!("sip:test@127.0.0.1:{}", config_c.local_sip_port);
        let handle_ac = endpoint_a.call(&target_c).await.unwrap();

        let incoming_c = endpoint_c
            .wait_for_incoming(Duration::from_secs(2))
            .await
            .unwrap();
        let handle_ca = endpoint_c.accept_call(incoming_c).await.unwrap();

        endpoint_a
            .wait_for_answer(&handle_ac, Duration::from_secs(2))
            .await
            .unwrap();

        // Disconnect
        endpoint_a.hangup(&handle_ac).await.unwrap();
        endpoint_c
            .wait_for_hangup(&handle_ca, Duration::from_secs(2))
            .await
            .unwrap();

        println!("Transfer cycle {} completed", i + 1);
    }

    println!("Rapid transfer cycles test completed");
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = TestConfig::with_available_ports();
        assert!(config.local_sip_port > 0);
        assert!(config.local_rtp_port > 0);
    }

    #[test]
    fn test_transfer_scenario_setup() {
        // Verify we can create three test configs
        let config_a = TestConfig::with_available_ports();
        let config_b = TestConfig::with_available_ports();
        let config_c = TestConfig::with_available_ports();

        // Ports should be different
        assert_ne!(config_a.local_sip_port, config_b.local_sip_port);
        assert_ne!(config_b.local_sip_port, config_c.local_sip_port);
    }
}

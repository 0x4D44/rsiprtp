//! Call hold/resume test scenarios.
//!
//! Tests for SIP call hold using re-INVITE with a=sendonly/recvonly.

use std::time::Duration;

use crate::framework::{is_baresip_available, BaresipInstance, TestConfig, TestEndpoint};

/// Test call hold initiated by rsiprtp.
///
/// Flow:
/// 1. Establish call
/// 2. rsiprtp puts call on hold (re-INVITE with a=sendonly)
/// 3. Verify baresip sees hold
/// 4. rsiprtp resumes call
/// 5. Verify media flows again
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_hold_by_rsiprtp() {
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

    // Note: Full hold implementation would send re-INVITE with a=sendonly
    // This is a placeholder - our simple test endpoint doesn't fully implement hold
    println!("Hold test: call established, hold re-INVITE not yet implemented");

    // Cleanup
    endpoint.hangup(&handle).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    baresip.shutdown().unwrap();
}

/// Test call hold initiated by baresip.
///
/// Flow:
/// 1. Establish call
/// 2. baresip puts call on hold (/hold command)
/// 3. Verify rsiprtp receives re-INVITE with hold SDP
/// 4. baresip resumes (/resume command)
/// 5. Verify media flows again
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_hold_by_baresip() {
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

    // baresip puts call on hold
    baresip.hold().unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Note: We should receive a re-INVITE here
    // Our simple endpoint doesn't fully process re-INVITEs yet
    println!("Hold by baresip: sent /hold command");

    // baresip resumes
    baresip.resume().unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("Resume by baresip: sent /resume command");

    // Cleanup
    baresip.hangup().unwrap();
    endpoint
        .wait_for_hangup(&handle, Duration::from_secs(5))
        .await
        .unwrap();
    baresip.shutdown().unwrap();
}

/// Test multiple hold/resume cycles.
#[tokio::test]
#[ignore = "requires baresip to be installed"]
async fn test_multiple_hold_resume_cycles() {
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

    // Multiple hold/resume cycles
    for i in 1..=3 {
        println!("Hold/resume cycle {}", i);

        baresip.hold().unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        baresip.resume().unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

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
    use super::*;

    #[test]
    fn test_hold_config() {
        let config = TestConfig::with_available_ports();
        assert!(config.local_sip_port > 0);
    }
}

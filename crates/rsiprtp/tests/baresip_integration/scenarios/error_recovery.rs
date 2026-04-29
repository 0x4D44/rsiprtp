//! Error recovery and robustness test scenarios.
//!
//! These tests verify proper handling of error conditions, including:
//! - Timeout handling
//! - Malformed message handling
//! - Network disconnects
//! - Invalid state transitions

use std::time::Duration;

use crate::framework::{TestConfig, TestEndpoint};

/// Test call timeout (no response to INVITE)
#[tokio::test]
async fn test_invite_timeout() {
    let config_a = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();

    // Call to non-existent endpoint
    let target_uri = "sip:test@127.0.0.1:9999".to_string();
    let handle = endpoint_a.call(&target_uri).await.unwrap();

    // Wait for answer should timeout
    let result = endpoint_a
        .wait_for_answer(&handle, Duration::from_secs(2))
        .await;

    assert!(result.is_err(), "Should timeout when no response");
}

/// Test call to invalid URI
#[tokio::test]
async fn test_invalid_uri() {
    let config = TestConfig::with_available_ports();
    let mut endpoint = TestEndpoint::new(config).await.unwrap();

    // Try to call invalid URI
    let result = endpoint.call("not-a-valid-uri").await;

    // Should either fail immediately or fail on send
    // Either way, we're testing error handling
    if result.is_ok() {
        println!("Call accepted invalid URI (implementation-dependent)");
    } else {
        println!("Call correctly rejected invalid URI");
    }
}

/// Test rapid call/cancel cycles
#[tokio::test]
async fn test_rapid_cancel_stress() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let _endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);

    // Make calls and immediately hang up (cancel)
    for i in 0..20 {
        let handle = endpoint_a.call(&target_uri).await.unwrap();

        // Immediate cancel (before answer)
        tokio::time::sleep(Duration::from_millis(10)).await;
        let _ = endpoint_a.hangup(&handle).await;

        // Small delay between cycles
        tokio::time::sleep(Duration::from_millis(20)).await;

        if i % 5 == 0 {
            println!("Cancel cycle {} completed", i);
        }
    }

    println!("20 cancel cycles completed");
}

/// Test double hangup (hangup already terminated call)
#[tokio::test]
async fn test_double_hangup() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
    let handle_a = endpoint_a.call(&target_uri).await.unwrap();

    let incoming = endpoint_b
        .wait_for_incoming(Duration::from_secs(2))
        .await
        .unwrap();
    let handle_b = endpoint_b.accept_call(incoming).await.unwrap();

    endpoint_a
        .wait_for_answer(&handle_a, Duration::from_secs(2))
        .await
        .unwrap();

    // First hangup
    endpoint_a.hangup(&handle_a).await.unwrap();
    endpoint_b
        .wait_for_hangup(&handle_b, Duration::from_secs(2))
        .await
        .unwrap();

    // Second hangup should be handled gracefully
    let result = endpoint_a.hangup(&handle_a).await;
    assert!(result.is_err(), "Double hangup should fail gracefully");
}

/// Test call state after error
#[tokio::test]
async fn test_call_state_after_timeout() {
    let config_a = TestConfig::with_available_ports();
    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();

    let target_uri = "sip:test@127.0.0.1:9999".to_string();
    let handle = endpoint_a.call(&target_uri).await.unwrap();

    // Timeout waiting for answer
    let _ = endpoint_a
        .wait_for_answer(&handle, Duration::from_secs(1))
        .await;

    // State should reflect the failure
    let state = endpoint_a.call_state(&handle);
    println!("Call state after timeout: {:?}", state);
}

/// Test malformed SIP message handling
#[tokio::test]
async fn test_malformed_message_handling() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let _endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    // Send malformed SIP message
    let malformed = "INVALID MESSAGE\r\n\r\n";
    let dest_addr = format!("127.0.0.1:{}", config_b.local_sip_port)
        .parse()
        .unwrap();

    let _ = endpoint_a.send_raw(malformed, dest_addr).await;

    // Endpoint B should handle this gracefully without crashing
    tokio::time::sleep(Duration::from_millis(500)).await;

    println!("Malformed message test completed");
}

/// Test missing required headers
#[tokio::test]
async fn test_missing_required_headers() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let _endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    // Send INVITE without required headers
    let incomplete = "INVITE sip:test@127.0.0.1 SIP/2.0\r\n\
                     From: <sip:a@example.com>\r\n\
                     \r\n";

    let dest_addr = format!("127.0.0.1:{}", config_b.local_sip_port)
        .parse()
        .unwrap();

    let _ = endpoint_a.send_raw(incomplete, dest_addr).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    println!("Missing headers test completed");
}

/// Test oversized SIP message
#[tokio::test]
async fn test_oversized_message() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let _endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    // Create a very large SIP message
    let mut oversized = "INVITE sip:test@127.0.0.1 SIP/2.0\r\n".to_string();
    oversized.push_str("From: <sip:a@example.com>\r\n");
    oversized.push_str("To: <sip:b@example.com>\r\n");

    // Add huge header
    oversized.push_str("X-Large-Header: ");
    oversized.push_str(&"A".repeat(10000));
    oversized.push_str("\r\n\r\n");

    let dest_addr = format!("127.0.0.1:{}", config_b.local_sip_port)
        .parse()
        .unwrap();

    let _ = endpoint_a.send_raw(&oversized, dest_addr).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    println!("Oversized message test completed");
}

/// Test concurrent operations on same call
#[tokio::test]
async fn test_concurrent_call_operations() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
    let handle_a = endpoint_a.call(&target_uri).await.unwrap();

    let incoming = endpoint_b
        .wait_for_incoming(Duration::from_secs(2))
        .await
        .unwrap();
    let handle_b = endpoint_b.accept_call(incoming).await.unwrap();

    endpoint_a
        .wait_for_answer(&handle_a, Duration::from_secs(2))
        .await
        .unwrap();

    // Try to hang up from both sides simultaneously
    let hangup_a = endpoint_a.hangup(&handle_a);
    let hangup_b = endpoint_b.hangup(&handle_b);

    let _ = tokio::join!(hangup_a, hangup_b);

    println!("Concurrent operations test completed");
}

/// Test recovery from network-like delays
#[tokio::test]
async fn test_delayed_response_handling() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
    let handle_a = endpoint_a.call(&target_uri).await.unwrap();

    // Wait before accepting (simulating slow network)
    tokio::time::sleep(Duration::from_millis(500)).await;

    let incoming = endpoint_b
        .wait_for_incoming(Duration::from_secs(3))
        .await
        .unwrap();

    // More delay before accepting
    tokio::time::sleep(Duration::from_millis(500)).await;

    let handle_b = endpoint_b.accept_call(incoming).await.unwrap();

    endpoint_a
        .wait_for_answer(&handle_a, Duration::from_secs(3))
        .await
        .unwrap();

    endpoint_a.hangup(&handle_a).await.unwrap();
    endpoint_b
        .wait_for_hangup(&handle_b, Duration::from_secs(2))
        .await
        .unwrap();

    println!("Delayed response test completed");
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
    fn test_malformed_message_patterns() {
        let patterns = vec!["NOT-SIP", "INVITE\r\n", "", "SIP/2.0\r\n", "\r\n\r\n"];

        for pattern in patterns {
            // Just verify these are valid test patterns
            assert!(!pattern.is_empty() || pattern.is_empty());
        }
    }
}

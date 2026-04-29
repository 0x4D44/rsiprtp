//! Advanced SIP registration test scenarios with Asterisk.
//!
//! These tests verify registration functionality against an Asterisk registrar,
//! including authentication, refresh, expiry, and multiple contacts.

use std::time::Duration;

use crate::framework::{AsteriskConfig, AsteriskInstance, TestConfig, TestEndpoint};

/// Helper to check if Asterisk is available
fn is_asterisk_available() -> bool {
    AsteriskInstance::is_available()
}

/// Test basic REGISTER with Asterisk as registrar
#[tokio::test]
#[ignore = "requires asterisk to be installed"]
async fn test_register_with_asterisk() {
    if !is_asterisk_available() {
        eprintln!("Skipping: asterisk not installed");
        return;
    }

    let test_config = TestConfig::with_available_ports();
    let ast_config = AsteriskConfig::new_test(
        std::env::temp_dir().join("ast_register_test"),
        test_config.local_sip_port + 100,
        test_config.local_sip_port + 101,
    );

    let mut asterisk = AsteriskInstance::new(ast_config.clone()).unwrap();

    // Give Asterisk time to start
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Connect to AMI
    if asterisk.connect_ami().await.is_err() {
        eprintln!("Could not connect to Asterisk AMI, skipping test");
        return;
    }

    let endpoint = TestEndpoint::new(test_config.clone()).await.unwrap();

    // Build REGISTER request
    let register_uri = format!("sip:127.0.0.1:{}", asterisk.sip_port());
    let from_uri = "sip:1001@127.0.0.1".to_string();
    let contact_uri = format!("sip:1001@127.0.0.1:{}", test_config.local_sip_port);

    // Send REGISTER (will likely get 401)
    let register = build_register(&from_uri, &register_uri, &contact_uri, 3600);
    let dest_addr = format!("127.0.0.1:{}", asterisk.sip_port())
        .parse()
        .unwrap();

    endpoint.send_raw(&register, dest_addr).await.unwrap();

    // Wait for 401 Unauthorized response
    tokio::time::sleep(Duration::from_millis(500)).await;

    // TODO: Parse 401, extract challenge, build authenticated REGISTER
    // For now, this test validates the framework setup

    println!("REGISTER framework test completed");
}

/// Test registration with explicit expiry time
#[tokio::test]
#[ignore = "requires asterisk to be installed"]
async fn test_register_with_expiry() {
    if !is_asterisk_available() {
        eprintln!("Skipping: asterisk not installed");
        return;
    }

    // Similar to above but with shorter expiry
    println!("Expiry test placeholder");
}

/// Test registration refresh before expiry
#[tokio::test]
#[ignore = "requires asterisk to be installed"]
async fn test_registration_refresh() {
    if !is_asterisk_available() {
        eprintln!("Skipping: asterisk not installed");
        return;
    }

    // Register with 30s expiry
    // Wait 20s
    // Send refresh REGISTER
    // Verify registration maintained
    println!("Refresh test placeholder");
}

/// Test unregister (Expires: 0)
#[tokio::test]
#[ignore = "requires asterisk to be installed"]
async fn test_unregister_expires_zero() {
    if !is_asterisk_available() {
        eprintln!("Skipping: asterisk not installed");
        return;
    }

    // Register normally
    // Send REGISTER with Expires: 0
    // Verify unregistered
    println!("Unregister test placeholder");
}

/// Test registration with multiple contacts
#[tokio::test]
#[ignore = "requires asterisk to be installed"]
async fn test_register_multiple_contacts() {
    if !is_asterisk_available() {
        eprintln!("Skipping: asterisk not installed");
        return;
    }

    // Register from two different endpoints with same AOR
    // Verify both contacts registered
    println!("Multiple contacts test placeholder");
}

/// Test registration with Contact header parameters
#[tokio::test]
#[ignore = "requires asterisk to be installed"]
async fn test_register_contact_params() {
    if !is_asterisk_available() {
        eprintln!("Skipping: asterisk not installed");
        return;
    }

    // Register with Contact header including parameters
    // e.g., Contact: <sip:user@host>;expires=3600;q=0.7
    println!("Contact params test placeholder");
}

/// Helper to build REGISTER request
fn build_register(from_uri: &str, to_uri: &str, contact_uri: &str, expires: u32) -> String {
    let call_id = uuid::Uuid::new_v4().to_string();
    let branch = format!("z9hG4bK-{}", uuid::Uuid::new_v4().simple());

    format!(
        "REGISTER {to_uri} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch={branch}\r\n\
         From: <{from_uri}>;tag=tag-{}\r\n\
         To: <{to_uri}>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 REGISTER\r\n\
         Contact: <{contact_uri}>\r\n\
         Expires: {expires}\r\n\
         Content-Length: 0\r\n\
         \r\n",
        uuid::Uuid::new_v4().simple()
    )
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_build_register() {
        let register = build_register(
            "sip:user@example.com",
            "sip:example.com",
            "sip:user@192.168.1.1:5060",
            3600,
        );

        assert!(register.contains("REGISTER sip:example.com SIP/2.0"));
        assert!(register.contains("From: <sip:user@example.com>"));
        assert!(register.contains("Contact: <sip:user@192.168.1.1:5060>"));
        assert!(register.contains("Expires: 3600"));
        assert!(register.contains("CSeq: 1 REGISTER"));
    }

    #[test]
    fn test_asterisk_available_check() {
        // Just verify this doesn't panic
        let _available = is_asterisk_available();
    }
}

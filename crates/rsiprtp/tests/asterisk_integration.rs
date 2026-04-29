//! Integration tests against Asterisk PBX.
//!
//! These tests require a running Asterisk instance.
//! Run with: docker compose -f docker/docker-compose.yml up -d
//!
//! Test against: localhost:5060 with users 1001/test1001, 1002/test1002, etc.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;

use rsiprtp_session::{RegistrationConfig, RegistrationManager, RegistrationState};
use rsiprtp_sip::{
    generate_branch, generate_call_id, generate_tag, Method, SipMessage, SipRequest,
};
use rsiprtp_transport::UdpTransport;

/// Asterisk address (from docker compose)
const ASTERISK_ADDR: &str = "127.0.0.1:5060";

/// Test user credentials (from pjsip.conf)
const TEST_USER: &str = "1001";
const TEST_PASSWORD: &str = "test1001";
const TEST_DOMAIN: &str = "127.0.0.1";

/// Check if Asterisk is reachable
async fn check_asterisk_available() -> bool {
    let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let transport = match UdpTransport::bind(addr).await {
        Ok(t) => t,
        Err(_) => return false,
    };

    let dest: SocketAddr = ASTERISK_ADDR.parse().unwrap();
    let local = transport.local_addr();

    // Send an OPTIONS request to check if Asterisk is alive
    let branch = generate_branch();
    let call_id = generate_call_id(&local.ip().to_string());
    let tag = generate_tag();

    let request = SipRequest::builder()
        .method(Method::Options)
        .uri(&format!("sip:{}", TEST_DOMAIN))
        .via(&local.ip().to_string(), local.port(), "UDP", &branch)
        .from(&format!("sip:probe@{}", local.ip()), &tag)
        .to(&format!("sip:{}@{}", TEST_USER, TEST_DOMAIN))
        .call_id(&call_id)
        .cseq(1)
        .build();

    let request = match request {
        Ok(r) => r,
        Err(_) => return false,
    };

    if transport.send_to(&request.to_bytes(), dest).await.is_err() {
        return false;
    }

    // Wait for response
    match timeout(Duration::from_secs(2), transport.recv()).await {
        Ok(Ok(msg)) => {
            // Check if we got a SIP response
            SipMessage::parse(&msg.data).is_ok()
        }
        _ => false,
    }
}

/// Test SIP registration with Asterisk
#[tokio::test]
async fn test_register_with_asterisk() {
    // Skip if Asterisk is not available
    if !check_asterisk_available().await {
        eprintln!("Skipping test: Asterisk not available at {}", ASTERISK_ADDR);
        return;
    }

    // Bind UDP transport
    let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let transport = UdpTransport::bind(addr).await.expect("Failed to bind UDP");
    let local = transport.local_addr();

    // Create registration config
    // For PJSIP, the Request-URI must include the username for AOR lookup
    let config = RegistrationConfig {
        registrar: format!("sip:{}@{}", TEST_USER, TEST_DOMAIN),
        aor: format!("sip:{}@{}", TEST_USER, TEST_DOMAIN),
        contact: format!("sip:{}@{}:{}", TEST_USER, local.ip(), local.port()),
        username: TEST_USER.to_string(),
        password: TEST_PASSWORD.to_string(),
        expires: 60,
        local_addr: local.ip().to_string(),
        local_port: local.port(),
        transport: "UDP".to_string(),
    };

    let mut reg = RegistrationManager::new(config);

    // Create initial REGISTER
    let request = reg.create_register().expect("Failed to create REGISTER");
    assert_eq!(reg.state(), RegistrationState::Registering);

    // Send to Asterisk
    let dest: SocketAddr = ASTERISK_ADDR.parse().unwrap();
    transport
        .send_to(&request.to_bytes(), dest)
        .await
        .expect("Failed to send");

    // Wait for response (should be 401 Unauthorized)
    let response_msg = timeout(Duration::from_secs(5), transport.recv())
        .await
        .expect("Timeout waiting for response")
        .expect("Failed to receive");

    let msg = SipMessage::parse(&response_msg.data).expect("Failed to parse response");
    let response = msg.as_response().expect("Expected response");

    println!(
        "Got response: {} {}",
        response.status_code(),
        response.reason()
    );

    // Handle the response (likely 401, needs auth)
    let result = reg.handle_response(response);

    match result {
        Ok(Some(auth_request)) => {
            // Got 401, retry with authentication
            println!("Retrying with authentication...");
            transport
                .send_to(&auth_request.to_bytes(), dest)
                .await
                .expect("Failed to send auth");

            // Wait for final response
            let final_msg = timeout(Duration::from_secs(5), transport.recv())
                .await
                .expect("Timeout waiting for auth response")
                .expect("Failed to receive auth response");

            let final_parsed =
                SipMessage::parse(&final_msg.data).expect("Failed to parse auth response");
            let final_response = final_parsed.as_response().expect("Expected response");

            println!(
                "Auth response: {} {}",
                final_response.status_code(),
                final_response.reason()
            );

            let final_result = reg.handle_response(final_response);
            assert!(
                final_result.is_ok(),
                "Auth handling failed: {:?}",
                final_result.err()
            );

            // Should be registered now
            assert_eq!(
                reg.state(),
                RegistrationState::Registered,
                "Expected Registered state, got {:?}",
                reg.state()
            );
            assert!(reg.is_registered());
        }
        Ok(None) => {
            // Direct 200 OK (unlikely without auth)
            assert_eq!(reg.state(), RegistrationState::Registered);
            assert!(reg.is_registered());
        }
        Err(e) => {
            panic!("Registration failed: {:?}", e);
        }
    }

    println!("Registration successful!");

    // Now unregister
    let unreg_request = reg
        .create_unregister()
        .expect("Failed to create unregister");
    transport
        .send_to(&unreg_request.to_bytes(), dest)
        .await
        .expect("Failed to send unregister");

    // Wait for unregister response
    let unreg_msg = timeout(Duration::from_secs(5), transport.recv())
        .await
        .expect("Timeout waiting for unregister response")
        .expect("Failed to receive unregister response");

    let unreg_parsed =
        SipMessage::parse(&unreg_msg.data).expect("Failed to parse unregister response");
    let unreg_response = unreg_parsed.as_response().expect("Expected response");

    println!(
        "Unregister response: {} {}",
        unreg_response.status_code(),
        unreg_response.reason()
    );

    // Handle unregister response
    let _ = reg.handle_response(unreg_response);

    // Should be unregistered
    assert_eq!(reg.state(), RegistrationState::Unregistered);

    println!("Unregistration successful!");
}

/// Test making an outbound INVITE call to Asterisk echo service
#[tokio::test]
async fn test_outbound_call_to_echo() {
    use rsiprtp_sip::DigestChallenge;

    // Skip if Asterisk is not available
    if !check_asterisk_available().await {
        eprintln!("Skipping test: Asterisk not available at {}", ASTERISK_ADDR);
        return;
    }

    let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let transport = UdpTransport::bind(addr).await.expect("Failed to bind UDP");
    let local = transport.local_addr();
    let dest: SocketAddr = ASTERISK_ADDR.parse().unwrap();

    // Build INVITE request to echo test (*43)
    let branch = generate_branch();
    let call_id = generate_call_id(&local.ip().to_string());
    let from_tag = generate_tag();

    // Create a simple SDP offer
    let sdp = format!(
        "v=0\r\n\
         o=- {} 1 IN IP4 {}\r\n\
         s=-\r\n\
         c=IN IP4 {}\r\n\
         t=0 0\r\n\
         m=audio {} RTP/AVP 0 8\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=sendrecv\r\n",
        call_id,
        local.ip(),
        local.ip(),
        20000
    );

    let request = SipRequest::builder()
        .method(Method::Invite)
        .uri(&format!("sip:*43@{}", TEST_DOMAIN)) // Echo test extension
        .via(&local.ip().to_string(), local.port(), "UDP", &branch)
        .from(&format!("sip:{}@{}", TEST_USER, TEST_DOMAIN), &from_tag)
        .to(&format!("sip:*43@{}", TEST_DOMAIN))
        .call_id(&call_id)
        .cseq(1)
        .contact(&format!(
            "sip:{}@{}:{}",
            TEST_USER,
            local.ip(),
            local.port()
        ))
        .body(sdp.into_bytes(), "application/sdp")
        .build()
        .expect("Failed to build INVITE");

    transport
        .send_to(&request.to_bytes(), dest)
        .await
        .expect("Failed to send INVITE");

    // Wait for response (could be 100, 180, 401, 200, etc.)
    let mut cseq = 1;
    let mut authenticated = false;

    loop {
        let response_msg = timeout(Duration::from_secs(10), transport.recv())
            .await
            .expect("Timeout waiting for INVITE response")
            .expect("Failed to receive");

        let msg = SipMessage::parse(&response_msg.data).expect("Failed to parse response");
        let response = msg.as_response().expect("Expected response");

        println!(
            "INVITE response: {} {}",
            response.status_code(),
            response.reason()
        );

        match response.status_code() {
            100 => {
                continue; // Wait for next response
            }
            180 | 183 => {
                continue; // Wait for final response
            }
            200 => {
                println!("Call established!");

                // Send ACK
                let ack_branch = generate_branch();
                let to_tag = response.to_tag().unwrap_or_default();

                let ack = SipRequest::builder()
                    .method(Method::Ack)
                    .uri(&format!("sip:*43@{}", TEST_DOMAIN))
                    .via(&local.ip().to_string(), local.port(), "UDP", &ack_branch)
                    .from(&format!("sip:{}@{}", TEST_USER, TEST_DOMAIN), &from_tag)
                    .to(&format!("sip:*43@{}", TEST_DOMAIN))
                    .to_tag(&to_tag)
                    .call_id(&call_id)
                    .cseq(cseq)
                    .build()
                    .expect("Failed to build ACK");

                transport
                    .send_to(&ack.to_bytes(), dest)
                    .await
                    .expect("Failed to send ACK");
                println!("Sent ACK");

                // Wait a moment, then send BYE
                tokio::time::sleep(Duration::from_millis(500)).await;

                cseq += 1;
                let bye_branch = generate_branch();
                let bye = SipRequest::builder()
                    .method(Method::Bye)
                    .uri(&format!("sip:*43@{}", TEST_DOMAIN))
                    .via(&local.ip().to_string(), local.port(), "UDP", &bye_branch)
                    .from(&format!("sip:{}@{}", TEST_USER, TEST_DOMAIN), &from_tag)
                    .to(&format!("sip:*43@{}", TEST_DOMAIN))
                    .to_tag(&to_tag)
                    .call_id(&call_id)
                    .cseq(cseq)
                    .build()
                    .expect("Failed to build BYE");

                transport
                    .send_to(&bye.to_bytes(), dest)
                    .await
                    .expect("Failed to send BYE");
                println!("Sent BYE");

                // Wait for 200 OK to BYE
                let bye_response = timeout(Duration::from_secs(5), transport.recv())
                    .await
                    .expect("Timeout waiting for BYE response")
                    .expect("Failed to receive BYE response");

                let bye_msg =
                    SipMessage::parse(&bye_response.data).expect("Failed to parse BYE response");
                let bye_resp = bye_msg.as_response().expect("Expected response");
                println!(
                    "BYE response: {} {}",
                    bye_resp.status_code(),
                    bye_resp.reason()
                );

                assert!(bye_resp.status_code() == 200, "Expected 200 OK to BYE");
                println!("Call ended successfully!");
                break;
            }
            401 | 407 => {
                if authenticated {
                    panic!("Authentication failed even after retry");
                }

                // Need to authenticate
                let www_auth = if response.status_code() == 401 {
                    response.www_authenticate()
                } else {
                    response.proxy_authenticate()
                };

                let challenge = DigestChallenge::parse(&www_auth.expect("No auth header"))
                    .expect("Failed to parse challenge");

                // Send ACK for the 401
                let ack_branch = generate_branch();
                let ack = SipRequest::builder()
                    .method(Method::Ack)
                    .uri(&format!("sip:*43@{}", TEST_DOMAIN))
                    .via(&local.ip().to_string(), local.port(), "UDP", &ack_branch)
                    .from(&format!("sip:{}@{}", TEST_USER, TEST_DOMAIN), &from_tag)
                    .to(&format!("sip:*43@{}", TEST_DOMAIN))
                    .call_id(&call_id)
                    .cseq(cseq)
                    .build()
                    .expect("Failed to build ACK");

                transport
                    .send_to(&ack.to_bytes(), dest)
                    .await
                    .expect("Failed to send ACK");

                // Retry with authentication
                cseq += 1;
                let new_branch = generate_branch();
                let credentials = rsiprtp_sip::DigestCredentials::new(TEST_USER, TEST_PASSWORD);
                let digest_response = rsiprtp_sip::DigestResponse::from_challenge(
                    &challenge,
                    &credentials,
                    "INVITE",
                    &format!("sip:*43@{}", TEST_DOMAIN),
                    None,
                )
                .expect("Failed to create digest response");

                let auth_header = if response.status_code() == 401 {
                    ("Authorization", digest_response.to_header_value())
                } else {
                    ("Proxy-Authorization", digest_response.to_header_value())
                };

                // Recreate sdp for auth request
                let sdp_auth = format!(
                    "v=0\r\n\
                     o=- {} 1 IN IP4 {}\r\n\
                     s=-\r\n\
                     c=IN IP4 {}\r\n\
                     t=0 0\r\n\
                     m=audio {} RTP/AVP 0 8\r\n\
                     a=rtpmap:0 PCMU/8000\r\n\
                     a=rtpmap:8 PCMA/8000\r\n\
                     a=sendrecv\r\n",
                    call_id,
                    local.ip(),
                    local.ip(),
                    20000
                );

                let mut builder = SipRequest::builder()
                    .method(Method::Invite)
                    .uri(&format!("sip:*43@{}", TEST_DOMAIN))
                    .via(&local.ip().to_string(), local.port(), "UDP", &new_branch)
                    .from(&format!("sip:{}@{}", TEST_USER, TEST_DOMAIN), &from_tag)
                    .to(&format!("sip:*43@{}", TEST_DOMAIN))
                    .call_id(&call_id)
                    .cseq(cseq)
                    .contact(&format!(
                        "sip:{}@{}:{}",
                        TEST_USER,
                        local.ip(),
                        local.port()
                    ))
                    .body(sdp_auth.into_bytes(), "application/sdp");

                // Add auth header
                if auth_header.0 == "Authorization" {
                    builder = builder.authorization(&auth_header.1);
                } else {
                    builder = builder.proxy_authorization(&auth_header.1);
                }

                let auth_request = builder.build().expect("Failed to build auth INVITE");

                transport
                    .send_to(&auth_request.to_bytes(), dest)
                    .await
                    .expect("Failed to send auth INVITE");
                authenticated = true;
                continue;
            }
            code if code >= 400 => {
                panic!("Call failed: {} {}", code, response.reason());
            }
            _ => {
                continue; // Ignore other provisional responses
            }
        }
    }

    // Loop only exits on the 200-OK / ACK / BYE / 200-OK-to-BYE happy path,
    // so reaching here means the call cycle completed successfully.
}

/// Test making an OPTIONS request to Asterisk
#[tokio::test]
async fn test_options_request() {
    // Skip if Asterisk is not available
    if !check_asterisk_available().await {
        eprintln!("Skipping test: Asterisk not available at {}", ASTERISK_ADDR);
        return;
    }

    let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let transport = UdpTransport::bind(addr).await.expect("Failed to bind UDP");
    let local = transport.local_addr();

    let branch = generate_branch();
    let call_id = generate_call_id(&local.ip().to_string());
    let tag = generate_tag();

    let request = SipRequest::builder()
        .method(Method::Options)
        .uri(&format!("sip:{}", TEST_DOMAIN))
        .via(&local.ip().to_string(), local.port(), "UDP", &branch)
        .from(&format!("sip:test@{}", local.ip()), &tag)
        .to(&format!("sip:{}@{}", TEST_USER, TEST_DOMAIN))
        .call_id(&call_id)
        .cseq(1)
        .build()
        .expect("Failed to build OPTIONS");

    let dest: SocketAddr = ASTERISK_ADDR.parse().unwrap();
    transport
        .send_to(&request.to_bytes(), dest)
        .await
        .expect("Failed to send");

    let response_msg = timeout(Duration::from_secs(5), transport.recv())
        .await
        .expect("Timeout waiting for OPTIONS response")
        .expect("Failed to receive");

    let msg = SipMessage::parse(&response_msg.data).expect("Failed to parse");
    let response = msg.as_response().expect("Expected response");

    println!(
        "OPTIONS response: {} {}",
        response.status_code(),
        response.reason()
    );

    // Should get 200 OK or 401 Unauthorized
    assert!(
        response.status_code() == 200 || response.status_code() == 401,
        "Unexpected response: {} {}",
        response.status_code(),
        response.reason()
    );
}

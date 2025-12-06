//! Basic call example demonstrating SIP registration and call flow.
//!
//! This example shows how to:
//! 1. Register with a SIP server (e.g., Asterisk)
//! 2. Make an outbound call
//! 3. Handle RTP media
//! 4. Terminate the call
//!
//! # Running
//!
//! ```bash
//! # Set environment variables for your SIP server
//! export SIP_SERVER="192.168.1.1"
//! export SIP_USER="1001"
//! export SIP_PASS="secret"
//! export SIP_DEST="*43"  # Asterisk echo test
//!
//! cargo run --example basic_call
//! ```
//!
//! # Asterisk Configuration (pjsip.conf)
//!
//! ```ini
//! [transport-udp]
//! type=transport
//! protocol=udp
//! bind=0.0.0.0:5060
//!
//! [1001]
//! type=endpoint
//! context=default
//! disallow=all
//! allow=ulaw,alaw
//! auth=auth1001
//! aors=aor1001
//!
//! [auth1001]
//! type=auth
//! auth_type=userpass
//! username=1001
//! password=secret
//!
//! [aor1001]
//! type=aor
//! max_contacts=1
//! ```

use mdsiprtp::prelude::*;
use mdsiprtp::sdp::builder::MediaBuilder;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{timeout, sleep};

/// Configuration from environment
struct Config {
    server: String,
    port: u16,
    username: String,
    password: String,
    destination: String,
    local_ip: String,
    local_port: u16,
}

impl Config {
    fn from_env() -> std::result::Result<Self, String> {
        Ok(Self {
            server: env::var("SIP_SERVER").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("SIP_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5060),
            username: env::var("SIP_USER").unwrap_or_else(|_| "1001".to_string()),
            password: env::var("SIP_PASS").unwrap_or_else(|_| "secret".to_string()),
            destination: env::var("SIP_DEST").unwrap_or_else(|_| "*43".to_string()),
            local_ip: env::var("LOCAL_IP").unwrap_or_else(|_| "127.0.0.1".to_string()),
            local_port: env::var("LOCAL_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5061),
        })
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt().init();

    let config = Config::from_env()?;

    println!("=== mdsiprtp Basic Call Example ===");
    println!("Server: {}:{}", config.server, config.port);
    println!("User: {}", config.username);
    println!("Destination: {}", config.destination);
    println!();

    // Create UDP socket for SIP signaling
    let local_addr: SocketAddr = format!("{}:{}", config.local_ip, config.local_port).parse()?;
    let socket = UdpSocket::bind(local_addr).await?;
    println!("Bound to {}", socket.local_addr()?);

    let server_addr: SocketAddr = format!("{}:{}", config.server, config.port).parse()?;
    socket.connect(&server_addr).await?;

    // Create registration manager
    let reg_config = RegistrationConfig {
        registrar: format!("sip:{}", config.server),
        aor: format!("sip:{}@{}", config.username, config.server),
        contact: format!("sip:{}@{}:{}", config.username, config.local_ip, config.local_port),
        username: config.username.clone(),
        password: config.password.clone(),
        expires: 3600,
        local_addr: config.local_ip.clone(),
        local_port: config.local_port,
        transport: "UDP".to_string(),
    };

    let mut registration = RegistrationManager::new(reg_config);

    // Step 1: Register with the SIP server
    println!("\n--- Step 1: Registering with SIP server ---");

    let register_req = registration.create_register()?;
    let req_bytes = register_req.to_bytes();

    println!("Sending REGISTER...");
    socket.send(&req_bytes).await?;

    // Wait for response
    let mut buf = vec![0u8; 4096];
    let response = match timeout(Duration::from_secs(5), socket.recv(&mut buf)).await {
        Ok(Ok(n)) => {
            let msg = SipMessage::parse(&buf[..n])?;
            msg.as_response()
                .cloned()
                .ok_or("Expected response, got request")?
        }
        Ok(Err(e)) => return Err(format!("Receive error: {}", e).into()),
        Err(_) => return Err("Timeout waiting for response".into()),
    };

    println!("Received {} {}", response.status_code(), response.reason());

    // Handle authentication challenge if needed
    if let Some(retry_req) = registration.handle_response(&response)? {
        println!("Server requires authentication, retrying...");

        let req_bytes = retry_req.to_bytes();
        socket.send(&req_bytes).await?;

        let n = timeout(Duration::from_secs(5), socket.recv(&mut buf)).await??;
        let msg = SipMessage::parse(&buf[..n])?;
        let response = msg
            .as_response()
            .ok_or("Expected response, got request")?;

        println!("Received {} {}", response.status_code(), response.reason());

        registration.handle_response(response)?;
    }

    if registration.is_registered() {
        println!("Registration successful!");
    } else {
        return Err("Registration failed".into());
    }

    // Step 2: Create call manager and make a call
    println!("\n--- Step 2: Making outbound call ---");

    let call_config = CallConfig::default();
    let manager_config = ManagerConfig {
        local_sip_addr: config.local_ip.clone(),
        local_rtp_addr: config.local_ip.clone(),
        rtp_port_range: (10000, 20000),
        call_config,
    };

    let mut call_manager = CallManager::new(manager_config);

    let dest_uri = format!("sip:{}@{}", config.destination, config.server);
    let call_id = call_manager.create_call(dest_uri.clone());
    println!("Created call {} to {}", &call_id.0, dest_uri);

    // Build INVITE with SDP offer
    let from_uri = format!("sip:{}@{}", config.username, config.server);
    let from_tag = generate_tag();
    let sip_call_id = generate_call_id(&config.server);
    let branch = generate_branch();

    // Create SDP offer
    let local_rtp_port = 10000u16;
    let local_addr: IpAddr = config.local_ip.parse()?;

    let sdp = SdpBuilder::new(local_addr)
        .session_name("mdsiprtp call")
        .add_media(MediaBuilder::audio(local_rtp_port).pcmu().pcma())
        .build();

    let invite = SipRequest::builder()
        .method(Method::Invite)
        .uri(&dest_uri)
        .via(&config.local_ip, config.local_port, "UDP", &branch)
        .from(&from_uri, &from_tag)
        .to(&dest_uri)
        .call_id(&sip_call_id)
        .cseq(1)
        .contact(&format!(
            "sip:{}@{}:{}",
            config.username, config.local_ip, config.local_port
        ))
        .body(sdp.to_string().into_bytes(), "application/sdp")
        .build()?;

    println!("Sending INVITE...");
    socket.send(&invite.to_bytes()).await?;

    // Wait for responses
    loop {
        let n = match timeout(Duration::from_secs(30), socket.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(format!("Receive error: {}", e).into()),
            Err(_) => {
                println!("Call timeout");
                break;
            }
        };

        let msg = SipMessage::parse(&buf[..n])?;
        if let Some(response) = msg.as_response() {
            let status = response.status_code();
            println!("Received {} {}", status, response.reason());

            match status {
                100 => {
                    // Trying - continue waiting
                }
                180 | 183 => {
                    // Ringing or Session Progress
                    println!("Remote party is ringing...");
                }
                200 => {
                    // OK - call connected
                    println!("Call connected!");

                    // Send ACK
                    let ack = SipRequest::builder()
                        .method(Method::Ack)
                        .uri(&dest_uri)
                        .via(&config.local_ip, config.local_port, "UDP", &branch)
                        .from(&from_uri, &from_tag)
                        .to(&dest_uri)
                        .to_tag(response.to_tag().as_deref().unwrap_or(""))
                        .call_id(&sip_call_id)
                        .cseq(1)
                        .build()?;

                    socket.send(&ack.to_bytes()).await?;
                    println!("Sent ACK");

                    // Step 3: Media session (simplified)
                    println!("\n--- Step 3: Media session ---");
                    println!("Call established. Press Ctrl+C to end or waiting 10 seconds...");

                    // In a real implementation, we would:
                    // 1. Parse the SDP answer from the 200 OK
                    // 2. Start RTP/RTCP sockets
                    // 3. Begin audio encoding/decoding
                    // 4. Send RTCP reports

                    // Simulate call duration
                    sleep(Duration::from_secs(10)).await;

                    // Step 4: End the call
                    println!("\n--- Step 4: Ending call ---");

                    let bye = SipRequest::builder()
                        .method(Method::Bye)
                        .uri(&dest_uri)
                        .via(&config.local_ip, config.local_port, "UDP", &generate_branch())
                        .from(&from_uri, &from_tag)
                        .to(&dest_uri)
                        .to_tag(response.to_tag().as_deref().unwrap_or(""))
                        .call_id(&sip_call_id)
                        .cseq(2)
                        .build()?;

                    socket.send(&bye.to_bytes()).await?;
                    println!("Sent BYE");

                    // Wait for 200 OK to BYE
                    if let Ok(Ok(n)) = timeout(Duration::from_secs(5), socket.recv(&mut buf)).await
                    {
                        if let Ok(msg) = SipMessage::parse(&buf[..n]) {
                            if let Some(resp) = msg.as_response() {
                                println!("Received {} {} for BYE", resp.status_code(), resp.reason());
                            }
                        }
                    }

                    break;
                }
                401 | 407 => {
                    println!("Authentication required for call (not implemented in example)");
                    break;
                }
                _ if status >= 400 => {
                    println!("Call failed: {} {}", status, response.reason());
                    break;
                }
                _ => {
                    // Other provisional responses
                }
            }
        }
    }

    // Unregister
    println!("\n--- Step 5: Unregistering ---");

    let unreg = registration.create_unregister()?;
    socket.send(&unreg.to_bytes()).await?;

    if let Ok(Ok(n)) = timeout(Duration::from_secs(5), socket.recv(&mut buf)).await {
        if let Ok(msg) = SipMessage::parse(&buf[..n]) {
            if let Some(response) = msg.as_response() {
                println!("Unregister response: {} {}", response.status_code(), response.reason());
            }
        }
    }

    println!("\n=== Example complete ===");
    Ok(())
}

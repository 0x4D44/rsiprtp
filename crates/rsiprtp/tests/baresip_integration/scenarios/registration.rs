//! SIP registration scenarios run against a minimal in-test registrar.
//!
//! These tests do not require Asterisk or baresip — they use a small UDP
//! socket-based registrar inside the test harness so they run in any
//! environment. The goal is to exercise the REGISTER path end-to-end
//! (message format, digest authentication, refresh, unregister) and
//! verify the behaviour we'd expect of any real registrar.
//!
//! For tests that exercise interop quirks against a real registrar, see
//! `registration_advanced.rs`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rsiprtp::sip::{DigestChallenge, DigestCredentials, DigestResponse};
use tokio::net::UdpSocket;

use crate::framework::{TestConfig, TestEndpoint};

/// Allocate a free local UDP port for the registrar to bind on.
async fn bind_registrar() -> (Arc<UdpSocket>, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    (Arc::new(socket), addr)
}

/// Find a header value (case-insensitive) in a SIP message.
fn find_header(msg: &str, name: &str) -> Option<String> {
    let needle = format!("{}:", name.to_lowercase());
    for line in msg.lines() {
        if line.to_lowercase().starts_with(&needle) {
            return Some(line[needle.len()..].trim().to_string());
        }
    }
    None
}

/// Extract the CSeq number from a CSeq header value (e.g. "3 REGISTER" -> 3).
fn parse_cseq_num(header: &str) -> Option<u32> {
    header.split_whitespace().next()?.parse().ok()
}

/// Build a 200 OK response to a REGISTER request, echoing the contact and
/// expires the request asked for.
fn build_200_ok(register_msg: &str) -> String {
    let via = find_header(register_msg, "Via").unwrap_or_default();
    let from = find_header(register_msg, "From").unwrap_or_default();
    let to = find_header(register_msg, "To").unwrap_or_default();
    let call_id = find_header(register_msg, "Call-ID").unwrap_or_default();
    let cseq = find_header(register_msg, "CSeq").unwrap_or_default();
    let contact = find_header(register_msg, "Contact").unwrap_or_default();
    let expires = find_header(register_msg, "Expires").unwrap_or_else(|| "3600".to_string());

    // Real registrars add a tag to the To header in the response if the
    // request didn't supply one.
    let to_with_tag = if to.contains("tag=") {
        to
    } else {
        format!("{};tag=registrar-{}", to, uuid::Uuid::new_v4().simple())
    };

    format!(
        "SIP/2.0 200 OK\r\n\
         Via: {via}\r\n\
         From: {from}\r\n\
         To: {to_with_tag}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq}\r\n\
         Contact: {contact};expires={expires}\r\n\
         Expires: {expires}\r\n\
         Content-Length: 0\r\n\
         \r\n",
    )
}

/// Build a 401 Unauthorized response with a digest challenge.
fn build_401(register_msg: &str, realm: &str, nonce: &str) -> String {
    let via = find_header(register_msg, "Via").unwrap_or_default();
    let from = find_header(register_msg, "From").unwrap_or_default();
    let to = find_header(register_msg, "To").unwrap_or_default();
    let call_id = find_header(register_msg, "Call-ID").unwrap_or_default();
    let cseq = find_header(register_msg, "CSeq").unwrap_or_default();

    let to_with_tag = if to.contains("tag=") {
        to
    } else {
        format!("{};tag=registrar-{}", to, uuid::Uuid::new_v4().simple())
    };

    format!(
        "SIP/2.0 401 Unauthorized\r\n\
         Via: {via}\r\n\
         From: {from}\r\n\
         To: {to_with_tag}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq}\r\n\
         WWW-Authenticate: Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=MD5, qop=\"auth\"\r\n\
         Content-Length: 0\r\n\
         \r\n",
    )
}

/// Build a REGISTER request from a TestEndpoint.
#[allow(clippy::too_many_arguments)]
fn build_register(
    from_uri: &str,
    to_uri: &str,
    contact_uri: &str,
    call_id: &str,
    cseq: u32,
    expires: u32,
    via_port: u16,
    branch: &str,
    from_tag: &str,
    authorization: Option<&str>,
) -> String {
    let auth_line = match authorization {
        Some(a) => format!("Authorization: {a}\r\n"),
        None => String::new(),
    };

    format!(
        "REGISTER {to_uri} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:{via_port};branch={branch};rport\r\n\
         Max-Forwards: 70\r\n\
         From: <{from_uri}>;tag={from_tag}\r\n\
         To: <{to_uri}>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} REGISTER\r\n\
         Contact: <{contact_uri}>\r\n\
         Expires: {expires}\r\n\
         {auth_line}\
         Content-Length: 0\r\n\
         \r\n",
    )
}

/// Test that a basic REGISTER carries the headers a registrar expects, and
/// that we correctly handle a 200 OK response.
#[tokio::test]
async fn test_register_message_format() {
    let config = TestConfig::with_available_ports();
    let endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let (registrar_socket, registrar_addr) = bind_registrar().await;

    let to_uri = format!("sip:{}", registrar_addr);
    let from_uri = format!("sip:alice@127.0.0.1:{}", config.local_sip_port);
    let contact_uri = format!("sip:alice@127.0.0.1:{}", config.local_sip_port);
    let call_id = uuid::Uuid::new_v4().to_string();
    let branch = format!("z9hG4bK-{}", uuid::Uuid::new_v4().simple());

    let register = build_register(
        &from_uri,
        &to_uri,
        &contact_uri,
        &call_id,
        1,
        3600,
        config.local_sip_port,
        &branch,
        "alice-tag",
        None,
    );

    // Registrar receives REGISTER, validates required headers, replies 200 OK.
    let registrar = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let (len, src) = registrar_socket.recv_from(&mut buf).await.unwrap();
        let msg = String::from_utf8(buf[..len].to_vec()).unwrap();

        // Required REGISTER headers per RFC 3261 §10
        assert!(msg.starts_with("REGISTER "), "first line must be REGISTER");
        assert!(find_header(&msg, "Via").is_some(), "Via header required");
        assert!(find_header(&msg, "From").is_some(), "From header required");
        assert!(find_header(&msg, "To").is_some(), "To header required");
        assert!(
            find_header(&msg, "Call-ID").is_some(),
            "Call-ID header required"
        );
        assert!(
            find_header(&msg, "CSeq").is_some_and(|s| s.contains("REGISTER")),
            "CSeq must reference REGISTER"
        );
        assert!(
            find_header(&msg, "Contact").is_some(),
            "Contact header required for binding"
        );
        let expires = find_header(&msg, "Expires");
        assert_eq!(expires.as_deref(), Some("3600"));

        let resp = build_200_ok(&msg);
        registrar_socket.send_to(resp.as_bytes(), src).await.unwrap();
    });

    endpoint.send_raw(&register, registrar_addr).await.unwrap();
    let (resp, _) = endpoint.recv_raw(Duration::from_secs(2)).await.unwrap();
    let resp_str = String::from_utf8(resp).unwrap();

    assert!(
        resp_str.starts_with("SIP/2.0 200"),
        "expected 200 OK, got: {}",
        resp_str.lines().next().unwrap_or("")
    );
    assert_eq!(
        find_header(&resp_str, "Call-ID").as_deref(),
        Some(call_id.as_str()),
        "response Call-ID must match request"
    );
    assert!(
        find_header(&resp_str, "Contact")
            .is_some_and(|c| c.contains("expires=")),
        "registrar must echo expires in Contact"
    );

    registrar.await.unwrap();
}

/// Full REGISTER + 401 challenge + authenticated REGISTER + 200 OK round trip.
#[tokio::test]
async fn test_register_with_authentication() {
    let config = TestConfig::with_available_ports();
    let endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let (registrar_socket, registrar_addr) = bind_registrar().await;

    let to_uri = format!("sip:{}", registrar_addr);
    let from_uri = format!("sip:bob@127.0.0.1:{}", config.local_sip_port);
    let contact_uri = format!("sip:bob@127.0.0.1:{}", config.local_sip_port);
    let call_id = uuid::Uuid::new_v4().to_string();
    let realm = "example.com";
    let nonce = "abc123nonce";
    let username = "bob";
    let password = "s3cret";

    let registrar = tokio::spawn({
        let to_uri = to_uri.clone();
        async move {
            // Round 1: receive unauth REGISTER, respond with 401
            let mut buf = vec![0u8; 65535];
            let (len, src) = registrar_socket.recv_from(&mut buf).await.unwrap();
            let msg1 = String::from_utf8(buf[..len].to_vec()).unwrap();
            assert!(msg1.starts_with("REGISTER "));
            assert!(
                find_header(&msg1, "Authorization").is_none(),
                "first REGISTER must be unauthenticated"
            );
            registrar_socket
                .send_to(build_401(&msg1, realm, nonce).as_bytes(), src)
                .await
                .unwrap();

            // Round 2: receive authenticated REGISTER, verify digest, respond 200
            let (len2, src2) = registrar_socket.recv_from(&mut buf).await.unwrap();
            let msg2 = String::from_utf8(buf[..len2].to_vec()).unwrap();
            let auth = find_header(&msg2, "Authorization")
                .expect("second REGISTER must carry Authorization");

            // Verify structural fields are present.
            assert!(
                auth.contains(&format!("username=\"{username}\"")),
                "auth missing username: {auth}"
            );
            assert!(
                auth.contains(&format!("realm=\"{realm}\"")),
                "auth missing realm"
            );
            assert!(
                auth.contains(&format!("nonce=\"{nonce}\"")),
                "auth missing nonce"
            );

            // Pull the client's cnonce / nc / response and recompute. If the
            // client used rsiprtp's auth helper correctly, the recomputed
            // response must match byte-for-byte.
            let client_cnonce = extract_quoted(&auth, "cnonce").unwrap();
            let client_nc = extract_unquoted(&auth, "nc").unwrap();
            let client_response = extract_quoted(&auth, "response").unwrap();
            let recomputed = recompute_digest(
                username,
                password,
                realm,
                "REGISTER",
                &to_uri,
                nonce,
                &client_cnonce,
                u32::from_str_radix(&client_nc, 16).unwrap(),
            );
            assert_eq!(
                client_response, recomputed,
                "digest response mismatch: expected {recomputed} got {client_response}"
            );

            registrar_socket
                .send_to(build_200_ok(&msg2).as_bytes(), src2)
                .await
                .unwrap();
        }
    });

    // Round 1: send unauth REGISTER
    let branch1 = format!("z9hG4bK-{}", uuid::Uuid::new_v4().simple());
    let req1 = build_register(
        &from_uri,
        &to_uri,
        &contact_uri,
        &call_id,
        1,
        3600,
        config.local_sip_port,
        &branch1,
        "bob-tag",
        None,
    );
    endpoint.send_raw(&req1, registrar_addr).await.unwrap();

    let (resp1, _) = endpoint.recv_raw(Duration::from_secs(2)).await.unwrap();
    let resp1_str = String::from_utf8(resp1).unwrap();
    assert!(
        resp1_str.starts_with("SIP/2.0 401"),
        "expected 401 challenge, got: {}",
        resp1_str.lines().next().unwrap_or("")
    );

    // Parse challenge, build authenticated REGISTER
    let challenge_value = find_header(&resp1_str, "WWW-Authenticate")
        .expect("401 must carry WWW-Authenticate");
    let challenge = DigestChallenge::parse(&challenge_value).unwrap();
    let creds = DigestCredentials::new(username, password);
    let response = DigestResponse::from_challenge(
        &challenge,
        &creds,
        "REGISTER",
        &to_uri,
        None,
    )
    .unwrap();

    // Round 2: send authenticated REGISTER (CSeq must increment)
    let branch2 = format!("z9hG4bK-{}", uuid::Uuid::new_v4().simple());
    let req2 = build_register(
        &from_uri,
        &to_uri,
        &contact_uri,
        &call_id,
        2,
        3600,
        config.local_sip_port,
        &branch2,
        "bob-tag",
        Some(&response.to_header_value()),
    );
    endpoint.send_raw(&req2, registrar_addr).await.unwrap();

    let (resp2, _) = endpoint.recv_raw(Duration::from_secs(2)).await.unwrap();
    let resp2_str = String::from_utf8(resp2).unwrap();
    assert!(
        resp2_str.starts_with("SIP/2.0 200"),
        "expected 200 OK after auth, got: {}",
        resp2_str.lines().next().unwrap_or("")
    );

    registrar.await.unwrap();
}

/// Test refreshing an existing registration with the same Call-ID and an
/// incremented CSeq.
#[tokio::test]
async fn test_register_refresh() {
    let config = TestConfig::with_available_ports();
    let endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let (registrar_socket, registrar_addr) = bind_registrar().await;

    let to_uri = format!("sip:{}", registrar_addr);
    let from_uri = format!("sip:carol@127.0.0.1:{}", config.local_sip_port);
    let contact_uri = format!("sip:carol@127.0.0.1:{}", config.local_sip_port);
    let call_id = uuid::Uuid::new_v4().to_string();

    let registrar = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];

        // Initial REGISTER
        let (len1, src1) = registrar_socket.recv_from(&mut buf).await.unwrap();
        let msg1 = String::from_utf8(buf[..len1].to_vec()).unwrap();
        let cseq1 = parse_cseq_num(&find_header(&msg1, "CSeq").unwrap()).unwrap();
        assert_eq!(cseq1, 1, "initial REGISTER CSeq must be 1");
        registrar_socket
            .send_to(build_200_ok(&msg1).as_bytes(), src1)
            .await
            .unwrap();

        // Refresh REGISTER — same Call-ID, incremented CSeq
        let (len2, src2) = registrar_socket.recv_from(&mut buf).await.unwrap();
        let msg2 = String::from_utf8(buf[..len2].to_vec()).unwrap();
        assert_eq!(
            find_header(&msg2, "Call-ID").as_deref(),
            find_header(&msg1, "Call-ID").as_deref(),
            "refresh must reuse Call-ID"
        );
        let cseq2 = parse_cseq_num(&find_header(&msg2, "CSeq").unwrap()).unwrap();
        assert!(
            cseq2 > cseq1,
            "refresh CSeq {cseq2} must be > initial {cseq1}"
        );
        registrar_socket
            .send_to(build_200_ok(&msg2).as_bytes(), src2)
            .await
            .unwrap();
    });

    // Initial REGISTER
    let req1 = build_register(
        &from_uri,
        &to_uri,
        &contact_uri,
        &call_id,
        1,
        3600,
        config.local_sip_port,
        &format!("z9hG4bK-{}", uuid::Uuid::new_v4().simple()),
        "carol-tag",
        None,
    );
    endpoint.send_raw(&req1, registrar_addr).await.unwrap();
    let (resp1, _) = endpoint.recv_raw(Duration::from_secs(2)).await.unwrap();
    assert!(String::from_utf8_lossy(&resp1).starts_with("SIP/2.0 200"));

    // Refresh
    let req2 = build_register(
        &from_uri,
        &to_uri,
        &contact_uri,
        &call_id,
        2,
        3600,
        config.local_sip_port,
        &format!("z9hG4bK-{}", uuid::Uuid::new_v4().simple()),
        "carol-tag",
        None,
    );
    endpoint.send_raw(&req2, registrar_addr).await.unwrap();
    let (resp2, _) = endpoint.recv_raw(Duration::from_secs(2)).await.unwrap();
    assert!(String::from_utf8_lossy(&resp2).starts_with("SIP/2.0 200"));

    registrar.await.unwrap();
}

/// Test unregister — REGISTER with `Expires: 0`.
#[tokio::test]
async fn test_unregister() {
    let config = TestConfig::with_available_ports();
    let endpoint = TestEndpoint::new(config.clone()).await.unwrap();
    let (registrar_socket, registrar_addr) = bind_registrar().await;

    let to_uri = format!("sip:{}", registrar_addr);
    let from_uri = format!("sip:dave@127.0.0.1:{}", config.local_sip_port);
    let contact_uri = format!("sip:dave@127.0.0.1:{}", config.local_sip_port);
    let call_id = uuid::Uuid::new_v4().to_string();

    let registrar = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];

        // Initial register
        let (len1, src1) = registrar_socket.recv_from(&mut buf).await.unwrap();
        let msg1 = String::from_utf8(buf[..len1].to_vec()).unwrap();
        registrar_socket
            .send_to(build_200_ok(&msg1).as_bytes(), src1)
            .await
            .unwrap();

        // Unregister — Expires: 0
        let (len2, src2) = registrar_socket.recv_from(&mut buf).await.unwrap();
        let msg2 = String::from_utf8(buf[..len2].to_vec()).unwrap();
        let expires = find_header(&msg2, "Expires");
        assert_eq!(
            expires.as_deref(),
            Some("0"),
            "unregister must carry Expires: 0"
        );
        // Build a 200 OK that echoes Expires: 0 so the client knows
        // deregistration succeeded.
        registrar_socket
            .send_to(build_200_ok(&msg2).as_bytes(), src2)
            .await
            .unwrap();
    });

    // Register
    let req1 = build_register(
        &from_uri,
        &to_uri,
        &contact_uri,
        &call_id,
        1,
        3600,
        config.local_sip_port,
        &format!("z9hG4bK-{}", uuid::Uuid::new_v4().simple()),
        "dave-tag",
        None,
    );
    endpoint.send_raw(&req1, registrar_addr).await.unwrap();
    let _ = endpoint.recv_raw(Duration::from_secs(2)).await.unwrap();

    // Unregister
    let req2 = build_register(
        &from_uri,
        &to_uri,
        &contact_uri,
        &call_id,
        2,
        0,
        config.local_sip_port,
        &format!("z9hG4bK-{}", uuid::Uuid::new_v4().simple()),
        "dave-tag",
        None,
    );
    endpoint.send_raw(&req2, registrar_addr).await.unwrap();
    let (resp2, _) = endpoint.recv_raw(Duration::from_secs(2)).await.unwrap();
    let resp2_str = String::from_utf8(resp2).unwrap();
    assert!(resp2_str.starts_with("SIP/2.0 200"));
    assert_eq!(
        find_header(&resp2_str, "Expires").as_deref(),
        Some("0"),
        "200 OK to unregister must echo Expires: 0"
    );

    registrar.await.unwrap();
}

// --- helpers used by the auth round-trip test ---

fn extract_quoted(header: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = header.find(&needle)? + needle.len();
    let end = header[start..].find('"')?;
    Some(header[start..start + end].to_string())
}

fn extract_unquoted(header: &str, key: &str) -> Option<String> {
    // Match `key=value` where value runs to end-of-string or next comma.
    let needle = format!("{key}=");
    let start = header.find(&needle)? + needle.len();
    let rest = &header[start..];
    let end = rest.find(|c: char| c == ',' || c.is_whitespace()).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Recompute the digest response hash exactly as the auth helper would, so
/// the test registrar can verify the client's response without holding the
/// client's randomly generated cnonce.
#[allow(clippy::too_many_arguments)]
fn recompute_digest(
    username: &str,
    password: &str,
    realm: &str,
    method: &str,
    uri: &str,
    nonce: &str,
    cnonce: &str,
    nc: u32,
) -> String {
    fn md5(data: &str) -> String {
        hex::encode(md5::compute(data).0)
    }
    let ha1 = md5(&format!("{username}:{realm}:{password}"));
    let ha2 = md5(&format!("{method}:{uri}"));
    md5(&format!(
        "{ha1}:{nonce}:{nc:08x}:{cnonce}:auth:{ha2}",
    ))
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_find_header_case_insensitive() {
        let msg = "REGISTER sip:foo SIP/2.0\r\nCall-ID: abc\r\n\r\n";
        assert_eq!(find_header(msg, "Call-ID").as_deref(), Some("abc"));
        assert_eq!(find_header(msg, "call-id").as_deref(), Some("abc"));
    }

    #[test]
    fn test_parse_cseq_num() {
        assert_eq!(parse_cseq_num("5 REGISTER"), Some(5));
        assert_eq!(parse_cseq_num("garbage"), None);
    }

    #[test]
    fn test_extract_quoted_and_unquoted() {
        let h = "Digest username=\"bob\", nc=00000001, response=\"abcd\"";
        assert_eq!(extract_quoted(h, "username").as_deref(), Some("bob"));
        assert_eq!(extract_quoted(h, "response").as_deref(), Some("abcd"));
        assert_eq!(extract_unquoted(h, "nc").as_deref(), Some("00000001"));
    }

    #[test]
    fn test_recompute_digest_produces_md5_hex() {
        let digest = recompute_digest(
            "bob",
            "s3cret",
            "example.com",
            "REGISTER",
            "sip:example.com",
            "abc123",
            "deadbeef",
            1,
        );
        assert_eq!(digest.len(), 32);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

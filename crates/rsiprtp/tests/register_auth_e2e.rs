//! End-to-end test of REGISTER + digest auth against a mock registrar.
//!
//! Spins up an in-process UDP "registrar" that emulates Asterisk's
//! 401-Unauthorized → Authorization → 200-OK flow. The mock recomputes
//! the expected MD5 digest server-side per RFC 2617 and rejects the
//! retry with 403 if the client's response hash doesn't match — so a
//! green test proves the wire bytes are byte-exact, not just well-formed.
//!
//! This is what we'd otherwise validate against a live Asterisk in
//! `asterisk_integration.rs`; running here means CI doesn't depend on
//! Docker being up. The asterisk_integration test still exercises the
//! same `RegistrationManager::register` driver against real Asterisk
//! when reachable.

use std::net::SocketAddr;
use std::time::Duration;

use rsiprtp::session::{
    RegistrationConfig, RegistrationError, RegistrationManager, RegistrationState,
};
use rsiprtp::sip::SipMessage;
use rsiprtp::transport::UdpTransport;

const RECV_TIMEOUT: Duration = Duration::from_secs(2);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Recompute the expected digest response (MD5, no qop) per RFC 2617 §3.2.2.1.
fn expected_response_md5(
    username: &str,
    password: &str,
    realm: &str,
    nonce: &str,
    method: &str,
    uri: &str,
) -> String {
    let ha1 = hex::encode(md5::compute(format!("{username}:{realm}:{password}")).0);
    let ha2 = hex::encode(md5::compute(format!("{method}:{uri}")).0);
    hex::encode(md5::compute(format!("{ha1}:{nonce}:{ha2}")).0)
}

/// Recompute MD5 digest with qop=auth: H(HA1:nonce:nc:cnonce:qop:HA2).
#[allow(clippy::too_many_arguments)]
fn expected_response_md5_qop_auth(
    username: &str,
    password: &str,
    realm: &str,
    nonce: &str,
    nc: &str,
    cnonce: &str,
    method: &str,
    uri: &str,
) -> String {
    let ha1 = hex::encode(md5::compute(format!("{username}:{realm}:{password}")).0);
    let ha2 = hex::encode(md5::compute(format!("{method}:{uri}")).0);
    hex::encode(md5::compute(format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")).0)
}

/// Parse an `Authorization: Digest ...` header value into a (key → value) map.
/// Strips surrounding quotes from quoted values. Tolerates Asterisk-style
/// formatting (commas, spaces).
fn parse_digest_params(header: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let s = header.trim();
    let s = s
        .strip_prefix("Digest ")
        .or_else(|| s.strip_prefix("digest "))
        .unwrap_or(s);

    let mut rest = s;
    while !rest.is_empty() {
        rest = rest.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
        if rest.is_empty() {
            break;
        }
        let Some(eq) = rest.find('=') else { break };
        let key = rest[..eq].trim().to_lowercase();
        rest = rest[eq + 1..].trim_start();

        let value = if let Some(stripped) = rest.strip_prefix('"') {
            let Some(end) = stripped.find('"') else { break };
            let v = stripped[..end].to_string();
            rest = &stripped[end + 1..];
            v
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            let v = rest[..end].trim().to_string();
            rest = &rest[end..];
            v
        };
        out.insert(key, value);
    }
    out
}

/// Find the `Authorization:` header value in raw SIP wire bytes. Case-
/// insensitive on the header name. Returns the value with surrounding
/// whitespace trimmed.
fn extract_auth_header(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    for line in text.split("\r\n") {
        if let Some(rest) = line
            .strip_prefix("Authorization:")
            .or_else(|| line.strip_prefix("authorization:"))
        {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Find the request URI (first line after METHOD) in raw SIP bytes.
fn extract_request_uri(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    let first = text.split("\r\n").next()?;
    let parts: Vec<&str> = first.split_whitespace().collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Build a `SIP/2.0 401 Unauthorized` response by echoing the request's
/// Via / From / To / Call-ID / CSeq lines and adding `WWW-Authenticate`.
/// `to_tag` lets the test fix the To-tag so the response is deterministic.
fn build_401(request: &[u8], realm: &str, nonce: &str, qop: Option<&str>, to_tag: &str) -> Vec<u8> {
    build_response(request, 401, "Unauthorized", to_tag, &{
        let mut extras = vec![format!(
            "WWW-Authenticate: Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=MD5{}",
            qop.map(|q| format!(", qop=\"{q}\"")).unwrap_or_default()
        )];
        extras.push("Content-Length: 0".to_string());
        extras
    })
}

fn build_200_ok(request: &[u8], to_tag: &str, expires: u32) -> Vec<u8> {
    build_response(
        request,
        200,
        "OK",
        to_tag,
        &[
            format!("Expires: {expires}"),
            "Content-Length: 0".to_string(),
        ],
    )
}

fn build_403(request: &[u8], to_tag: &str) -> Vec<u8> {
    build_response(
        request,
        403,
        "Forbidden",
        to_tag,
        &["Content-Length: 0".to_string()],
    )
}

fn build_response(
    request: &[u8],
    status: u16,
    reason: &str,
    to_tag: &str,
    extra_headers: &[String],
) -> Vec<u8> {
    let text = std::str::from_utf8(request).expect("UTF-8 SIP");
    let mut via = String::new();
    let mut from = String::new();
    let mut to = String::new();
    let mut call_id = String::new();
    let mut cseq = String::new();

    for line in text.split("\r\n") {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("via:") && via.is_empty() {
            via = line.to_string();
        } else if lower.starts_with("from:") && from.is_empty() {
            from = line.to_string();
        } else if lower.starts_with("to:") && to.is_empty() {
            // Add tag if missing
            if line.contains(";tag=") {
                to = line.to_string();
            } else {
                to = format!("{line};tag={to_tag}");
            }
        } else if lower.starts_with("call-id:") && call_id.is_empty() {
            call_id = line.to_string();
        } else if lower.starts_with("cseq:") && cseq.is_empty() {
            cseq = line.to_string();
        }
    }

    let mut response = format!("SIP/2.0 {status} {reason}\r\n");
    for header in [&via, &from, &to, &call_id, &cseq] {
        response.push_str(header);
        response.push_str("\r\n");
    }
    for extra in extra_headers {
        response.push_str(extra);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    response.into_bytes()
}

/// Verifier that recomputes the expected digest response and asserts the
/// client's `response=` field matches. Returns the verdict.
enum Verdict {
    Ok,
    Reject(String),
}

fn verify_digest(
    auth: &str,
    expected_username: &str,
    expected_realm: &str,
    expected_nonce: &str,
    password: &str,
    method: &str,
) -> Verdict {
    let params = parse_digest_params(auth);

    let username = params.get("username").cloned().unwrap_or_default();
    let realm = params.get("realm").cloned().unwrap_or_default();
    let nonce = params.get("nonce").cloned().unwrap_or_default();
    let uri = params.get("uri").cloned().unwrap_or_default();
    let response = params.get("response").cloned().unwrap_or_default();
    let qop = params.get("qop").cloned();
    let nc = params.get("nc").cloned();
    let cnonce = params.get("cnonce").cloned();

    if username != expected_username {
        return Verdict::Reject(format!("username mismatch: got {username}"));
    }
    if realm != expected_realm {
        return Verdict::Reject(format!("realm mismatch: got {realm}"));
    }
    if nonce != expected_nonce {
        return Verdict::Reject(format!("nonce mismatch: got {nonce}"));
    }

    let expected = match (qop.as_deref(), nc.as_deref(), cnonce.as_deref()) {
        (Some("auth"), Some(nc), Some(cnonce)) => expected_response_md5_qop_auth(
            &username, password, &realm, &nonce, nc, cnonce, method, &uri,
        ),
        (None, _, _) | (Some(""), _, _) => {
            expected_response_md5(&username, password, &realm, &nonce, method, &uri)
        }
        (Some(other), _, _) => return Verdict::Reject(format!("unexpected qop: {other}")),
    };

    if response.eq_ignore_ascii_case(&expected) {
        Verdict::Ok
    } else {
        Verdict::Reject(format!(
            "digest mismatch: got {response}, expected {expected}"
        ))
    }
}

/// Run a single REGISTER round trip on the mock registrar.
///
/// Steps:
/// 1. Recv first REGISTER, send 401 with WWW-Authenticate.
/// 2. Recv second REGISTER, verify Authorization, send 200 OK or 403.
async fn run_mock_registrar(
    transport: &UdpTransport,
    realm: &str,
    nonce: &str,
    qop: Option<&str>,
    expected_user: &str,
    password: &str,
) {
    // First REGISTER — must NOT carry Authorization.
    let first = transport.recv().await.expect("recv 1");
    let auth = extract_auth_header(&first.data);
    assert!(
        auth.is_none(),
        "first REGISTER should not include Authorization, got {:?}",
        auth
    );
    let first_text = std::str::from_utf8(&first.data).unwrap();
    assert!(
        first_text.starts_with("REGISTER "),
        "expected REGISTER, got: {}",
        first_text.lines().next().unwrap_or("")
    );

    let response = build_401(&first.data, realm, nonce, qop, "mockregistrar");
    transport
        .send_to(&response, first.source)
        .await
        .expect("send 401");

    // Second REGISTER — must carry valid Authorization.
    let second = transport.recv().await.expect("recv 2");
    let auth = extract_auth_header(&second.data).expect("retry has Authorization");
    let request_uri = extract_request_uri(&second.data).expect("Request-URI");

    // Re-extract the URI from the auth header itself: it must match what
    // the client wrote. Per RFC 3261 §22.4 we don't strictly require URI
    // equality with the Request-URI, but we want to verify the client put
    // *something* sensible there (not blank).
    let params = parse_digest_params(&auth);
    let header_uri = params.get("uri").cloned().unwrap_or_default();
    assert!(
        !header_uri.is_empty(),
        "Authorization uri= must be non-empty"
    );

    let final_response =
        match verify_digest(&auth, expected_user, realm, nonce, password, "REGISTER") {
            Verdict::Ok => build_200_ok(&second.data, "mockregistrar", 60),
            Verdict::Reject(reason) => {
                eprintln!(
                "mock: rejecting (Request-URI={request_uri}, header_uri={header_uri}): {reason}"
            );
                build_403(&second.data, "mockregistrar")
            }
        };
    transport
        .send_to(&final_response, second.source)
        .await
        .expect("send final");
}

async fn bind_loopback() -> UdpTransport {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    UdpTransport::bind(addr).await.expect("bind UDP")
}

fn config_for(server: SocketAddr, local: SocketAddr, user: &str, pass: &str) -> RegistrationConfig {
    RegistrationConfig {
        registrar: format!("sip:{}@{}:{}", user, server.ip(), server.port()),
        aor: format!("sip:{}@{}:{}", user, server.ip(), server.port()),
        contact: format!("sip:{}@{}:{}", user, local.ip(), local.port()),
        username: user.to_string(),
        password: pass.to_string(),
        expires: 60,
        local_addr: local.ip().to_string(),
        local_port: local.port(),
        transport: "UDP".to_string(),
    }
}

/// Plain MD5 digest, no qop — the most basic flow.
#[tokio::test]
async fn register_with_digest_md5_no_qop() {
    let server = bind_loopback().await;
    let server_addr = server.local_addr();

    let mock = tokio::spawn(async move {
        run_mock_registrar(
            &server,
            "rsiprtp-mock",
            "nonce-no-qop-001",
            None,
            "alice",
            "s3cret",
        )
        .await
    });

    let client = bind_loopback().await;
    let mut reg = RegistrationManager::new(config_for(
        server_addr,
        client.local_addr(),
        "alice",
        "s3cret",
    ));

    reg.register(&client, server_addr, RECV_TIMEOUT, TOTAL_TIMEOUT)
        .await
        .expect("register succeeds");

    assert_eq!(reg.state(), RegistrationState::Registered);
    assert!(reg.is_registered());

    mock.await.unwrap();
}

/// MD5 with qop=auth — exercises the cnonce / nc path (RFC 2617 §3.2.2.1).
#[tokio::test]
async fn register_with_digest_md5_qop_auth() {
    let server = bind_loopback().await;
    let server_addr = server.local_addr();

    let mock = tokio::spawn(async move {
        run_mock_registrar(
            &server,
            "rsiprtp-mock",
            "nonce-qop-auth-002",
            Some("auth"),
            "bob",
            "passw0rd",
        )
        .await
    });

    let client = bind_loopback().await;
    let mut reg = RegistrationManager::new(config_for(
        server_addr,
        client.local_addr(),
        "bob",
        "passw0rd",
    ));

    reg.register(&client, server_addr, RECV_TIMEOUT, TOTAL_TIMEOUT)
        .await
        .expect("register succeeds with qop=auth");

    assert_eq!(reg.state(), RegistrationState::Registered);
    mock.await.unwrap();
}

/// Wrong password → mock returns 403 → driver surfaces `Failed(403, ...)`.
#[tokio::test]
async fn register_wrong_password_is_rejected() {
    let server = bind_loopback().await;
    let server_addr = server.local_addr();

    let mock = tokio::spawn(async move {
        run_mock_registrar(
            &server,
            "rsiprtp-mock",
            "nonce-bad-pw-003",
            None,
            "carol",
            "correct-password",
        )
        .await
    });

    let client = bind_loopback().await;
    let mut reg = RegistrationManager::new(config_for(
        server_addr,
        client.local_addr(),
        "carol",
        "WRONG",
    ));

    let err = reg
        .register(&client, server_addr, RECV_TIMEOUT, TOTAL_TIMEOUT)
        .await
        .expect_err("registration must fail");
    match err {
        RegistrationError::Failed(403, _) => {}
        other => panic!("expected Failed(403), got {other:?}"),
    }
    assert_eq!(reg.state(), RegistrationState::Failed);
    mock.await.unwrap();
}

/// No registrar listening → driver times out cleanly without blocking forever.
#[tokio::test]
async fn register_times_out_when_registrar_silent() {
    // Bind a server socket but never read from it: the registrar task
    // never reads from the socket and never sends a response, so the
    // client's recv hits its timeout. With `recv_timeout = 200ms` and
    // `total_timeout = 400ms` the driver must surface `Timeout`, not hang.
    let _server = bind_loopback().await;
    let server_addr = _server.local_addr();

    let client = bind_loopback().await;
    let mut reg =
        RegistrationManager::new(config_for(server_addr, client.local_addr(), "dave", "x"));

    let err = reg
        .register(
            &client,
            server_addr,
            Duration::from_millis(200),
            Duration::from_millis(400),
        )
        .await
        .expect_err("must time out");
    assert!(matches!(err, RegistrationError::Timeout), "got {err:?}");
}

/// Register, then unregister using the same driver. Verifies `unregister`
/// works post-success and that the unREGISTER carries the previously-stashed
/// digest (no second 401 round-trip needed). Uses `qop=auth` so the wire
/// carries an `nc` value — we assert the unREGISTER bumps it to
/// `00000002` (RFC 2617 §3.2.2 requires `nc` to be monotonically
/// increasing per nonce; reusing `00000001` is a replay-detection bug).
#[tokio::test]
async fn register_then_unregister() {
    let server = bind_loopback().await;
    let server_addr = server.local_addr();
    let realm = "rsiprtp-mock";
    let nonce = "nonce-cycle-004";
    let user = "erin";
    let password = "hunter2";

    // The mock handles BOTH the REGISTER round-trip and a subsequent
    // unREGISTER (which arrives pre-authenticated thanks to the stashed
    // challenge).
    let mock = tokio::spawn(async move {
        // First: REGISTER → 401 → 200 with qop=auth.
        run_mock_registrar(&server, realm, nonce, Some("auth"), user, password).await;

        // Second: unREGISTER arrives already with Authorization (from the
        // stashed challenge). The mock just sees a request with auth and
        // responds 200 OK without a fresh challenge.
        let req = server.recv().await.expect("recv unREGISTER");
        let auth = extract_auth_header(&req.data).expect("unREGISTER carries auth");
        let parsed = SipMessage::parse(&req.data).expect("parse unREGISTER");
        let _request = parsed.as_request().expect("expected request");
        // Sanity: it's REGISTER with Expires: 0.
        let text = std::str::from_utf8(&req.data).unwrap();
        assert!(text.starts_with("REGISTER "), "expected REGISTER");
        assert!(
            text.contains("Expires: 0"),
            "unREGISTER must have Expires: 0"
        );
        assert!(auth.contains("Digest"));

        // Crypto: recompute the expected digest from the same realm and
        // nonce that issued the challenge. The unREGISTER reuses the
        // stashed challenge, so realm/nonce are unchanged from the
        // initial REGISTER.
        match verify_digest(&auth, user, realm, nonce, password, "REGISTER") {
            Verdict::Ok => {}
            Verdict::Reject(reason) => panic!("unREGISTER digest invalid: {reason}"),
        }

        // RFC 2617 §3.2.2: nc MUST be monotonically increasing per
        // nonce. The initial authenticated REGISTER sent nc=00000001;
        // the unREGISTER reuses the same nonce, so it must send
        // nc=00000002.
        let params = parse_digest_params(&auth);
        let wire_nc = params
            .get("nc")
            .cloned()
            .expect("unREGISTER must include nc with qop=auth");
        assert_eq!(
            wire_nc, "00000002",
            "unREGISTER reusing the cached nonce must bump nc; \
             RFC 2617 forbids reusing the same (nonce, nc) pair"
        );

        let response = build_200_ok(&req.data, "mockregistrar", 0);
        server
            .send_to(&response, req.source)
            .await
            .expect("send 200 to unREGISTER");
    });

    let client = bind_loopback().await;
    let mut reg =
        RegistrationManager::new(config_for(server_addr, client.local_addr(), user, password));

    reg.register(&client, server_addr, RECV_TIMEOUT, TOTAL_TIMEOUT)
        .await
        .expect("register");
    assert!(reg.is_registered());

    reg.unregister(&client, server_addr, RECV_TIMEOUT, TOTAL_TIMEOUT)
        .await
        .expect("unregister");
    assert_eq!(reg.state(), RegistrationState::Unregistered);

    mock.await.unwrap();
}

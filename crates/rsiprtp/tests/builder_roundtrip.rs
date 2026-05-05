//! Builder typed round-trip oracle.
//!
//! Build typed -> serialize -> parse -> read typed -> assert agreement.
//!
//! Closes two gaps left by the M11 bytes-in oracle:
//!   1. Builder formatting choices for typed fields.
//!   2. Tier-2 typed-accessor reads that round-trip the wire value back
//!      through `parser::typed::{From,Via,CSeq,...}::parse`.
//!
//! See `wrk_docs/2026.05.05 - HLD - Builder typed round-trip oracle.md`.

use rsiprtp::sip::{
    Method, MinSe, RAck, Refresher, Require, SessionExpires, SipMessage, SipRequest, SipResponse,
    Supported,
};

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

fn roundtrip_request(req: SipRequest) -> SipRequest {
    let bytes = req.to_bytes();
    match SipMessage::parse(&bytes).unwrap_or_else(|e| {
        panic!(
            "builder emitted bytes the parser rejects: {e:?}\nbytes:\n{}",
            String::from_utf8_lossy(&bytes),
        )
    }) {
        SipMessage::Request(r) => r,
        SipMessage::Response(_) => panic!("expected Request, got Response"),
    }
}

fn roundtrip_response(resp: SipResponse) -> SipResponse {
    let bytes = resp.to_bytes();
    match SipMessage::parse(&bytes).unwrap_or_else(|e| {
        panic!(
            "builder emitted bytes the parser rejects: {e:?}\nbytes:\n{}",
            String::from_utf8_lossy(&bytes),
        )
    }) {
        SipMessage::Response(r) => r,
        SipMessage::Request(_) => panic!("expected Response, got Request"),
    }
}

// -----------------------------------------------------------------
// Request fixtures
// -----------------------------------------------------------------

#[test]
fn request_invite_minimal() {
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("alice.example.com", 5060, "UDP", "z9hG4bKnashds7")
        .from("sip:alice@example.com", "1928301774")
        .to("sip:bob@example.com")
        .call_id("a84b4c76e66710@pc33.example.com")
        .cseq(314159)
        .build()
        .unwrap();
    let r = roundtrip_request(req);
    assert_eq!(r.method(), Method::Invite);
    assert_eq!(r.uri().to_string(), "sip:bob@example.com");
    assert_eq!(r.via_branch().unwrap(), "z9hG4bKnashds7");
    assert_eq!(r.from_tag().unwrap(), "1928301774");
    assert_eq!(r.from_uri().unwrap().to_string(), "sip:alice@example.com");
    assert_eq!(r.to_uri().unwrap().to_string(), "sip:bob@example.com");
    assert_eq!(r.to_tag(), None);
    assert_eq!(r.call_id().unwrap(), "a84b4c76e66710@pc33.example.com");
    assert_eq!(r.cseq().unwrap(), 314159);
    assert_eq!(r.cseq_method().unwrap(), Method::Invite);
}

#[test]
fn request_invite_with_display_name() {
    // No typed accessor for display name; assertion is byte-level on the
    // wire form. See HLD "What the oracle will not catch".
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("alice.example.com", 5060, "UDP", "z9hG4bKdisplay")
        .from("sip:alice@example.com", "tag-display")
        .from_display("Alice")
        .to("sip:bob@example.com")
        .call_id("display@example.com")
        .cseq(1)
        .build()
        .unwrap();
    let r = roundtrip_request(req);
    let bytes = r.to_bytes();
    assert!(
        String::from_utf8_lossy(&bytes).contains("\"Alice\""),
        "expected quoted display name in wire form, got:\n{}",
        String::from_utf8_lossy(&bytes),
    );
    // Also verify the typed accessors that *do* exist still agree.
    assert_eq!(r.from_uri().unwrap().to_string(), "sip:alice@example.com");
    assert_eq!(r.from_tag().unwrap(), "tag-display");
}

#[test]
fn request_ack_with_to_tag() {
    let req = SipRequest::builder()
        .method(Method::Ack)
        .uri("sip:bob@example.com")
        .via("alice.example.com", 5060, "UDP", "z9hG4bKack")
        .from("sip:alice@example.com", "from-tag-ack")
        .to("sip:bob@example.com")
        .to_tag("to-tag-ack")
        .call_id("ack@example.com")
        .cseq(2)
        .build()
        .unwrap();
    let r = roundtrip_request(req);
    assert_eq!(r.method(), Method::Ack);
    assert_eq!(r.from_tag().unwrap(), "from-tag-ack");
    assert_eq!(r.to_tag(), Some("to-tag-ack".to_string()));
    assert_eq!(r.cseq().unwrap(), 2);
    assert_eq!(r.cseq_method().unwrap(), Method::Ack);
}

#[test]
fn request_invite_with_body_and_contact() {
    let body = b"v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n".to_vec();
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("alice.example.com", 5060, "UDP", "z9hG4bKbody")
        .from("sip:alice@example.com", "from-body")
        .to("sip:bob@example.com")
        .call_id("body@example.com")
        .cseq(3)
        .contact("sip:alice@alice.example.com")
        .body(body.clone(), "application/sdp")
        .build()
        .unwrap();
    let r = roundtrip_request(req);
    assert_eq!(r.body(), body.as_slice());
    assert_eq!(r.content_type().as_deref(), Some("application/sdp"));
    assert_eq!(
        r.contact_uri().map(|u| u.to_string()),
        Some("sip:alice@alice.example.com".to_string()),
    );
}

#[test]
fn request_register_with_authorization_and_expires() {
    let auth = "Digest username=\"alice\", realm=\"example.com\", \
                nonce=\"abc\", uri=\"sip:example.com\", response=\"deadbeef\"";
    let req = SipRequest::builder()
        .method(Method::Register)
        .uri("sip:example.com")
        .via("alice.example.com", 5060, "UDP", "z9hG4bKreg")
        .from("sip:alice@example.com", "reg-tag")
        .to("sip:alice@example.com")
        .call_id("reg@example.com")
        .cseq(4)
        .max_forwards(70)
        .authorization(auth)
        .expires(3600)
        .build()
        .unwrap();
    let r = roundtrip_request(req);
    assert_eq!(r.method(), Method::Register);
    // Authorization survives as a raw header; check via raw bytes that the
    // builder emitted the header (no typed accessor on the request side).
    let wire = String::from_utf8_lossy(&r.to_bytes()).to_string();
    assert!(
        wire.contains("Authorization: Digest username=\"alice\""),
        "missing Authorization in wire form:\n{wire}",
    );
    assert!(
        wire.contains("Expires: 3600"),
        "missing Expires header in wire form:\n{wire}",
    );
    assert!(
        wire.contains("Max-Forwards: 70"),
        "missing Max-Forwards in wire form:\n{wire}",
    );
}

#[test]
fn request_invite_with_proxy_authorization() {
    let auth = "Digest username=\"alice\", realm=\"proxy.example.com\", \
                nonce=\"xyz\", uri=\"sip:bob@example.com\", response=\"cafef00d\"";
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("alice.example.com", 5060, "UDP", "z9hG4bKproxy")
        .from("sip:alice@example.com", "proxy-tag")
        .to("sip:bob@example.com")
        .call_id("proxy@example.com")
        .cseq(5)
        .proxy_authorization(auth)
        .build()
        .unwrap();
    let r = roundtrip_request(req);
    let wire = String::from_utf8_lossy(&r.to_bytes()).to_string();
    assert!(
        wire.contains("Proxy-Authorization: Digest username=\"alice\""),
        "missing Proxy-Authorization in wire form:\n{wire}",
    );
}

#[test]
fn request_invite_with_session_expires_and_min_se() {
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("alice.example.com", 5060, "UDP", "z9hG4bKse")
        .from("sip:alice@example.com", "se-tag")
        .to("sip:bob@example.com")
        .call_id("se@example.com")
        .cseq(6)
        .session_expires(1800, Some(Refresher::Uac))
        .min_se(90)
        .build()
        .unwrap();
    let r = roundtrip_request(req);
    let se = r.session_expires().expect("Session-Expires present");
    assert_eq!(
        se,
        SessionExpires {
            delta_seconds: 1800,
            refresher: Some(Refresher::Uac),
        },
    );
    assert_eq!(r.min_se().unwrap(), MinSe(90));
}

#[test]
fn request_prack_with_rack() {
    let req = SipRequest::builder()
        .method(Method::Prack)
        .uri("sip:bob@example.com")
        .via("alice.example.com", 5060, "UDP", "z9hG4bKprack")
        .from("sip:alice@example.com", "prack-tag")
        .to("sip:bob@example.com")
        .to_tag("prack-to-tag")
        .call_id("prack@example.com")
        .cseq(7)
        .rack(101, 6, Method::Invite)
        .build()
        .unwrap();
    let r = roundtrip_request(req);
    assert_eq!(r.method(), Method::Prack);
    assert_eq!(
        r.rack().unwrap(),
        RAck {
            rseq: 101,
            cseq: 6,
            method: Method::Invite,
        },
    );
}

#[test]
fn request_invite_with_require_supported_allow() {
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("alice.example.com", 5060, "UDP", "z9hG4bKlists")
        .from("sip:alice@example.com", "lists-tag")
        .to("sip:bob@example.com")
        .call_id("lists@example.com")
        .cseq(8)
        .require(&["100rel"])
        .supported(&["timer", "replaces"])
        .allow(&[Method::Invite, Method::Ack, Method::Bye, Method::Cancel])
        .build()
        .unwrap();
    let r = roundtrip_request(req);
    assert_eq!(r.require().unwrap(), Require(vec!["100rel".to_string()]),);
    assert_eq!(
        r.supported().unwrap(),
        Supported(vec!["timer".to_string(), "replaces".to_string()]),
    );
    assert_eq!(
        r.allow().unwrap(),
        vec![Method::Invite, Method::Ack, Method::Bye, Method::Cancel],
    );
}

#[test]
fn request_invite_with_routes() {
    let routes = vec![
        "<sip:proxy1.example.com;lr>".to_string(),
        "<sip:proxy2.example.com;lr>".to_string(),
        "<sip:proxy3.example.com;lr>".to_string(),
    ];
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("alice.example.com", 5060, "UDP", "z9hG4bKroutes")
        .from("sip:alice@example.com", "routes-tag")
        .to("sip:bob@example.com")
        .call_id("routes@example.com")
        .cseq(9)
        .route(&routes)
        .build()
        .unwrap();
    let r = roundtrip_request(req);
    assert_eq!(r.route_headers(), routes);
}

#[test]
fn request_invite_with_ipv6_via_host() {
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        // IPv6 hosts must be pre-bracketed by the caller per HLD.
        .via("[2001:db8::1]", 5060, "UDP", "z9hG4bKv6")
        .from("sip:alice@example.com", "v6-tag")
        .to("sip:bob@example.com")
        .call_id("v6@example.com")
        .cseq(10)
        .build()
        .unwrap();
    let r = roundtrip_request(req);
    assert_eq!(r.via_branch().unwrap(), "z9hG4bKv6");
    let vias = r.via_headers_raw();
    assert_eq!(vias.len(), 1, "expected exactly one Via header");
    assert!(
        vias[0].contains("[2001:db8::1]"),
        "expected bracketed IPv6 host in Via, got: {}",
        vias[0],
    );
    assert!(
        vias[0].contains(":5060"),
        "expected port 5060 in Via, got: {}",
        vias[0],
    );
    assert!(
        vias[0].contains("SIP/2.0/UDP"),
        "expected UDP transport in Via, got: {}",
        vias[0],
    );
}

#[test]
fn request_invite_with_explicit_max_forwards_and_tcp_via() {
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("alice.example.com", 5061, "TCP", "z9hG4bKtcp")
        .from("sip:alice@example.com", "tcp-tag")
        .to("sip:bob@example.com")
        .call_id("tcp@example.com")
        .cseq(11)
        .max_forwards(15)
        .build()
        .unwrap();
    let r = roundtrip_request(req);
    assert_eq!(r.via_branch().unwrap(), "z9hG4bKtcp");
    let vias = r.via_headers_raw();
    assert_eq!(vias.len(), 1);
    assert!(
        vias[0].contains("SIP/2.0/TCP"),
        "expected TCP transport in Via, got: {}",
        vias[0],
    );
    assert!(
        vias[0].contains(":5061"),
        "expected port 5061 in Via, got: {}",
        vias[0],
    );
    let wire = String::from_utf8_lossy(&r.to_bytes()).to_string();
    assert!(
        wire.contains("Max-Forwards: 15"),
        "expected Max-Forwards: 15 in wire form:\n{wire}",
    );
}

// -----------------------------------------------------------------
// Response fixtures
// -----------------------------------------------------------------

#[test]
fn response_200_ok_minimal() {
    // Isolates the response build path (no `from_request`, no copy path).
    let resp = SipResponse::builder().status(200, "OK").build().unwrap();
    let r = roundtrip_response(resp);
    assert_eq!(r.status_code(), 200);
    assert_eq!(r.reason(), "OK");
}

#[test]
fn response_200_ok_from_invite() {
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("alice.example.com", 5060, "UDP", "z9hG4bKresp200")
        .from("sip:alice@example.com", "from-resp200")
        .to("sip:bob@example.com")
        .call_id("resp200@example.com")
        .cseq(12)
        .build()
        .unwrap();
    let resp = SipResponse::builder()
        .status(200, "OK")
        .from_request(&req)
        .to_tag("to-tag-resp200")
        .build()
        .unwrap();
    let r = roundtrip_response(resp);
    assert_eq!(r.status_code(), 200);
    assert_eq!(r.reason(), "OK");
    assert_eq!(r.via_branch().unwrap(), "z9hG4bKresp200");
    assert_eq!(r.from_tag().unwrap(), "from-resp200");
    assert_eq!(r.to_tag(), Some("to-tag-resp200".to_string()));
    assert_eq!(r.call_id().unwrap(), "resp200@example.com");
    assert_eq!(r.cseq().unwrap(), 12);
    assert_eq!(r.cseq_method().unwrap(), Method::Invite);
}

#[test]
fn response_200_with_body() {
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("alice.example.com", 5060, "UDP", "z9hG4bKrespbody")
        .from("sip:alice@example.com", "from-respbody")
        .to("sip:bob@example.com")
        .call_id("respbody@example.com")
        .cseq(13)
        .build()
        .unwrap();
    let body = b"v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n".to_vec();
    let resp = SipResponse::builder()
        .status(200, "OK")
        .from_request(&req)
        .to_tag("to-tag-respbody")
        .body(body.clone(), "application/sdp")
        .build()
        .unwrap();
    let r = roundtrip_response(resp);
    assert_eq!(r.status_code(), 200);
    assert_eq!(r.body(), body.as_slice());
    assert_eq!(r.content_type().as_deref(), Some("application/sdp"));
}

#[test]
fn response_200_with_session_expires_and_allow() {
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("alice.example.com", 5060, "UDP", "z9hG4bKrespse")
        .from("sip:alice@example.com", "from-respse")
        .to("sip:bob@example.com")
        .call_id("respse@example.com")
        .cseq(14)
        .build()
        .unwrap();
    let resp = SipResponse::builder()
        .status(200, "OK")
        .from_request(&req)
        .to_tag("to-tag-respse")
        .session_expires(1800, Some(Refresher::Uas))
        .allow(&[Method::Invite, Method::Ack, Method::Bye])
        .build()
        .unwrap();
    let r = roundtrip_response(resp);
    assert_eq!(
        r.session_expires().unwrap(),
        SessionExpires {
            delta_seconds: 1800,
            refresher: Some(Refresher::Uas),
        },
    );
    assert_eq!(
        r.allow().unwrap(),
        vec![Method::Invite, Method::Ack, Method::Bye],
    );
}

#[test]
fn response_183_with_rseq() {
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("alice.example.com", 5060, "UDP", "z9hG4bKresp183")
        .from("sip:alice@example.com", "from-resp183")
        .to("sip:bob@example.com")
        .call_id("resp183@example.com")
        .cseq(15)
        .build()
        .unwrap();
    let resp = SipResponse::builder()
        .status(183, "Session Progress")
        .from_request(&req)
        .to_tag("to-tag-resp183")
        .rseq(42)
        .require(&["100rel"])
        .build()
        .unwrap();
    let r = roundtrip_response(resp);
    assert_eq!(r.status_code(), 183);
    assert_eq!(r.reason(), "Session Progress");
    assert!(r.is_provisional());
    assert_eq!(r.rseq().unwrap(), rsiprtp::sip::RSeq(42),);
    assert_eq!(r.require().unwrap(), Require(vec!["100rel".to_string()]),);
}

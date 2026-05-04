use rsiprtp::sdp::parser::{Direction, SdpParseError, SessionDescription};
use rsiprtp::sip::{Method, SipMessage, SipRequest, SipResponse};
use rsiprtp::transaction::{ManagerAction, Timer, TransactionManager};

fn build_request(method: Method) -> SipRequest {
    SipRequest::builder()
        .method(method)
        .uri("sip:bob@example.com")
        .via("example.com", 5060, "UDP", "z9hG4bKtest")
        .from("sip:alice@example.com", "fromtag")
        .to("sip:bob@example.com")
        .call_id("call-id")
        .cseq(1)
        .build()
        .expect("request build")
}

fn build_response(req: &SipRequest, status: u16, reason: &str) -> SipResponse {
    SipResponse::builder()
        .status(status, reason)
        .from_request(req)
        .build()
        .expect("response build")
}

fn extract_handle(actions: &[ManagerAction]) -> rsiprtp::transaction::TransactionHandle {
    actions
        .iter()
        .find_map(|action| {
            if let ManagerAction::Event(handle, _) = action {
                Some(*handle)
            } else {
                None
            }
        })
        .expect("expected transaction event")
}

#[test]
fn test_sdp_parse_skips_empty_and_short_lines() {
    let sdp = "v=0\n\
\n\
a\n\
ab\n\
o=- 0 0 IN IP4 0.0.0.0\n\
s=-\n\
i=Session Info\n\
t=0 0\n\
z=ignored\n\
m=audio 5000 RTP/AVP 0\n\
c=IN IP4 203.0.113.1\n\
b=AS:64\n\
b=AS64\n\
a=rtpmap:0 PCMU/8000\n\
a=fmtp:0 foo=bar\n\
x=ignored\n";
    let parsed = SessionDescription::parse(sdp).expect("parse sdp");
    let audio = parsed.audio_media().expect("audio media");
    assert_eq!(parsed.session_info, Some("Session Info".to_string()));
    assert_eq!(audio.direction(), Direction::SendRecv);
    assert_eq!(audio.bandwidth.get("AS"), Some(&64));
    assert_eq!(audio.fmtps().len(), 1);
}

#[test]
fn test_sdp_parse_invalid_connection() {
    let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nc=IN IP4\nt=0 0\n";
    let err = SessionDescription::parse(sdp).unwrap_err();
    assert!(matches!(err, SdpParseError::InvalidConnection));
}

#[test]
fn test_sdp_parse_invalid_media_line() {
    let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 5000\n";
    let err = SessionDescription::parse(sdp).unwrap_err();
    assert!(matches!(err, SdpParseError::InvalidMedia));
}

#[test]
fn test_sdp_parse_invalid_media_port() {
    let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio abc/2 RTP/AVP 0\n";
    let err = SessionDescription::parse(sdp).unwrap_err();
    assert!(matches!(err, SdpParseError::InvalidMedia));
}

#[test]
fn test_sdp_parse_invalid_media_num_ports() {
    let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 5000/abc RTP/AVP 0\n";
    let err = SessionDescription::parse(sdp).unwrap_err();
    assert!(matches!(err, SdpParseError::InvalidMedia));
}

#[test]
fn test_sip_request_helpers_cover_headers() {
    let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP example.com;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: call-id\r\n\
CSeq: 1 INVITE\r\n\
Record-Route: <sip:proxy.example.com>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 0\r\n\r\n";
    let msg = SipMessage::parse(raw).expect("parse invite");
    let req = msg.as_request().expect("request").clone();
    assert!(req.content_type().is_some());
    assert_eq!(req.record_routes().len(), 1);
    assert!(!req.via_headers_raw().is_empty());
}

#[test]
fn test_sip_response_helpers_cover_headers() {
    let raw = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP example.com;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>;tag=totag\r\n\
Call-ID: call-id\r\n\
CSeq: 1 INVITE\r\n\
Record-Route: <sip:proxy.example.com>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 0\r\n\r\n";
    let msg = SipMessage::parse(raw).expect("parse response");
    let resp = msg.as_response().expect("response");
    assert!(resp.content_type().is_some());
    assert_eq!(resp.record_routes().len(), 1);
    assert!(!resp.via_headers_raw().is_empty());
}

#[test]
fn test_sip_message_as_request_none_for_response() {
    let raw = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP example.com;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>;tag=totag\r\n\
Call-ID: call-id\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";
    let msg = SipMessage::parse(raw).expect("parse response");
    assert!(msg.as_request().is_none());
}

#[test]
fn test_sip_message_as_response_none_for_request() {
    let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP example.com;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: call-id\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";
    let msg = SipMessage::parse(raw).expect("parse request");
    assert!(msg.as_response().is_none());
}

#[test]
fn test_sip_request_from_tag_and_uri_success() {
    let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP example.com;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: call-id\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";
    let msg = SipMessage::parse(raw).expect("parse request");
    let req = msg.as_request().expect("request");
    let (tag, uri) = req.from_tag_and_uri().expect("from tag and uri");
    assert_eq!(tag, "fromtag");
    assert_eq!(uri.to_string(), "sip:alice@example.com");
}

#[test]
fn test_sip_request_from_tag_and_uri_missing_header() {
    let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP example.com;branch=z9hG4bKtest\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: call-id\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";
    let msg = SipMessage::parse(raw).expect("parse request");
    let req = msg.as_request().expect("request");
    let err = req.from_tag_and_uri().unwrap_err();
    assert!(err.to_string().contains("Missing required header"));
}

#[test]
fn test_sip_request_content_type_none() {
    let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP example.com;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: call-id\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";
    let msg = SipMessage::parse(raw).expect("parse request");
    let req = msg.as_request().expect("request");
    assert!(req.content_type().is_none());
}

#[test]
fn test_sip_response_content_type_none() {
    let raw = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP example.com;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>;tag=totag\r\n\
Call-ID: call-id\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";
    let msg = SipMessage::parse(raw).expect("parse response");
    let resp = msg.as_response().expect("response");
    assert!(resp.content_type().is_none());
}

#[test]
fn test_method_conversions_for_coverage() {
    use std::str::FromStr;

    // M7 removed `Method::to_rsip()` and `From<&rsip::Method> for Method`
    // from the public surface — they were the rsip-bridge escape hatches.
    // The replacement is the canonical method-name round-trip via
    // `Display` + `FromStr`, which is lossless for all 14 variants.
    for m in [
        Method::Prack,
        Method::Subscribe,
        Method::Notify,
        Method::Publish,
        Method::Refer,
        Method::Message,
        Method::Update,
    ] {
        let s = m.to_string();
        assert_eq!(Method::from_str(&s).unwrap(), m);
    }

    assert_eq!(format!("{}", Method::Ack), "ACK");
    assert_eq!(format!("{}", Method::Prack), "PRACK");
    assert_eq!(format!("{}", Method::Subscribe), "SUBSCRIBE");
    assert_eq!(format!("{}", Method::Notify), "NOTIFY");
    assert_eq!(format!("{}", Method::Publish), "PUBLISH");
    assert_eq!(format!("{}", Method::Info), "INFO");
    assert_eq!(format!("{}", Method::Refer), "REFER");
    assert_eq!(format!("{}", Method::Message), "MESSAGE");
    assert_eq!(format!("{}", Method::Update), "UPDATE");
}

#[test]
fn test_sip_request_builder_contact_invalid_uri() {
    let req = SipRequest::builder()
        .method(Method::Options)
        .uri("sip:bob@example.com")
        .via("example.com", 5060, "UDP", "z9hG4bKtest")
        .from("sip:alice@example.com", "fromtag")
        .to("sip:bob@example.com")
        .call_id("call-id")
        .cseq(1)
        .contact("sip:alice@[::1")
        .build()
        .expect("build request");
    assert!(req.contact_uri().is_none());
}

#[test]
fn test_sip_request_builder_invalid_from_uri_error() {
    let err = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("example.com", 5060, "UDP", "z9hG4bKtest")
        .from("sip:alice@[::1", "fromtag")
        .to("sip:bob@example.com")
        .call_id("call-id")
        .cseq(1)
        .build()
        .unwrap_err()
        .to_string();
    assert!(err.contains("Invalid From URI"));
}

#[test]
fn test_sip_request_builder_invalid_to_uri_error() {
    let err = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("example.com", 5060, "UDP", "z9hG4bKtest")
        .from("sip:alice@example.com", "fromtag")
        .to("sip:alice@[::1")
        .call_id("call-id")
        .cseq(1)
        .build()
        .unwrap_err()
        .to_string();
    assert!(err.contains("Invalid To URI"));
}

#[test]
fn test_sip_request_builder_from_display() {
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("example.com", 5060, "UDP", "z9hG4bKtest")
        .from("sip:alice@example.com", "fromtag")
        .from_display("Alice")
        .to("sip:bob@example.com")
        .call_id("call-id")
        .cseq(1)
        .build()
        .expect("build request");
    let bytes = req.to_bytes();
    assert!(String::from_utf8_lossy(&bytes).contains("\"Alice\""));
}

#[test]
fn test_sip_request_builder_sets_content_type_for_body() {
    let req = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("example.com", 5060, "UDP", "z9hG4bKtest")
        .from("sip:alice@example.com", "fromtag")
        .to("sip:bob@example.com")
        .call_id("call-id")
        .cseq(1)
        .body(b"v=0\r\n".to_vec(), "application/sdp")
        .build()
        .expect("build request");
    assert!(req.content_type().is_some());
}

#[test]
fn test_sip_response_builder_contact_invalid_uri_and_to_tag() {
    let req = build_request(Method::Invite);
    let resp = SipResponse::builder()
        .status(200, "OK")
        .from_request(&req)
        .contact("sip:alice@[::1")
        .to_tag("newtag")
        .build()
        .expect("build response");
    assert!(resp.contact_uri().is_none());
    assert_eq!(resp.to_tag(), Some("newtag".to_string()));
}

#[test]
fn test_sip_response_builder_to_tag_noop_when_existing() {
    let req = build_request(Method::Invite);
    let resp = SipResponse::builder()
        .status(200, "OK")
        .from_request(&req)
        .to_tag("firsttag")
        .to_tag("secondtag")
        .build()
        .expect("build response");
    assert_eq!(resp.to_tag(), Some("firsttag".to_string()));
}

#[test]
fn test_sip_response_builder_sets_content_type_for_body() {
    let req = build_request(Method::Invite);
    let resp = SipResponse::builder()
        .status(200, "OK")
        .from_request(&req)
        .body(b"v=0\r\n".to_vec(), "application/sdp")
        .build()
        .expect("build response");
    assert!(resp.content_type().is_some());
}

#[test]
fn test_sip_response_builder_from_request_invalid_via() {
    let raw = b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
Via: invalid-via\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: call-id\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";
    let msg = SipMessage::parse(raw).expect("parse request");
    let req = msg.as_request().expect("request").clone();
    let resp = SipResponse::builder()
        .status(200, "OK")
        .from_request(&req)
        .build()
        .expect("build response");
    let vias = resp.via_headers_raw();
    assert!(vias.iter().any(|via| via.contains("invalid-via")));
}

#[test]
fn test_transaction_manager_create_client_transaction_missing_via_branch_invite() {
    let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP example.com\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: call-id\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";
    let msg = SipMessage::parse(raw).expect("parse request");
    let req = msg.as_request().expect("request").clone();
    let mut mgr = TransactionManager::new(false);
    assert!(mgr.create_client_transaction(req).is_none());
}

#[test]
fn test_transaction_manager_create_client_transaction_missing_via_branch_non_invite() {
    let raw = b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP example.com\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: call-id\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";
    let msg = SipMessage::parse(raw).expect("parse request");
    let req = msg.as_request().expect("request").clone();
    let mut mgr = TransactionManager::new(false);
    assert!(mgr.create_client_transaction(req).is_none());
}

#[test]
fn test_transaction_manager_handle_request_for_client_transaction_noop() {
    let mut mgr = TransactionManager::new(false);
    let req = build_request(Method::Invite);
    let _handle = mgr
        .create_client_transaction(req.clone())
        .expect("invite client transaction");
    mgr.poll_actions();
    mgr.handle_message(SipMessage::Request(req));
    assert!(mgr.poll_actions().is_empty());
}

#[test]
fn test_transaction_manager_handle_response_missing_via_branch() {
    let raw = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP example.com\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>;tag=totag\r\n\
Call-ID: call-id\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";
    let msg = SipMessage::parse(raw).expect("parse response");
    let resp = msg.as_response().expect("response").clone();
    let mut mgr = TransactionManager::new(false);
    mgr.handle_message(SipMessage::Response(resp));
    assert!(mgr.poll_actions().is_empty());
}

#[test]
fn test_transaction_manager_handle_response_no_matching_handle() {
    let req = build_request(Method::Invite);
    let resp = build_response(&req, 200, "OK");
    let mut mgr = TransactionManager::new(false);
    mgr.handle_message(SipMessage::Response(resp));
    assert!(mgr.poll_actions().is_empty());
}

#[test]
fn test_transaction_manager_handle_response_for_server_handle_noop() {
    let mut mgr = TransactionManager::new(false);
    let req = build_request(Method::Invite);
    mgr.handle_message(SipMessage::Request(req.clone()));
    let actions = mgr.poll_actions();
    let _handle = extract_handle(&actions);

    let resp = build_response(&req, 200, "OK");
    mgr.handle_message(SipMessage::Response(resp));
    assert!(mgr.poll_actions().is_empty());
}

#[test]
fn test_transaction_manager_send_response_ignores_client_handle() {
    let mut mgr = TransactionManager::new(false);
    let req = build_request(Method::Invite);
    let handle = mgr
        .create_client_transaction(req.clone())
        .expect("invite client transaction");
    mgr.poll_actions();
    let resp = build_response(&req, 200, "OK");
    mgr.send_response(handle, resp);
    assert!(mgr.poll_actions().is_empty());
}

#[test]
fn test_transaction_manager_ignores_request_without_via_branch() {
    let raw = b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP example.com\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: call-id\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";
    let msg = SipMessage::parse(raw).expect("parse request");
    let req = msg.as_request().expect("request").clone();
    let mut mgr = TransactionManager::new(false);
    mgr.handle_message(SipMessage::Request(req));
    assert!(mgr.poll_actions().is_empty());
}

#[test]
fn test_transaction_manager_routes_existing_non_invite_request() {
    let mut mgr = TransactionManager::new(false);
    let req = build_request(Method::Options);
    mgr.handle_message(SipMessage::Request(req.clone()));
    let handle = extract_handle(&mgr.poll_actions());
    let resp = build_response(&req, 200, "OK");
    mgr.send_response(handle, resp);
    mgr.poll_actions();
    mgr.handle_message(SipMessage::Request(req));
    let actions = mgr.poll_actions();
    assert!(actions
        .iter()
        .any(|action| matches!(action, ManagerAction::Send(_))));
}

#[test]
fn test_transaction_manager_server_dispatch_paths() {
    let mut mgr = TransactionManager::new(false);

    let invite_req = build_request(Method::Invite);
    mgr.handle_message(SipMessage::Request(invite_req.clone()));
    let invite_handle = extract_handle(&mgr.poll_actions());
    mgr.handle_message(SipMessage::Request(invite_req.clone()));
    mgr.poll_actions();

    let invite_resp = build_response(&invite_req, 180, "Ringing");
    mgr.send_response(invite_handle, invite_resp);
    mgr.poll_actions();
    mgr.handle_timeout(invite_handle, Timer::H);
    mgr.handle_transport_error(invite_handle);
    mgr.poll_actions();

    let options_req = build_request(Method::Options);
    mgr.handle_message(SipMessage::Request(options_req.clone()));
    let options_handle = extract_handle(&mgr.poll_actions());
    mgr.handle_message(SipMessage::Request(options_req.clone()));
    mgr.poll_actions();

    let options_resp = build_response(&options_req, 200, "OK");
    mgr.send_response(options_handle, options_resp);
    mgr.poll_actions();
    mgr.handle_timeout(options_handle, Timer::J);
    mgr.handle_transport_error(options_handle);
    mgr.poll_actions();
}

#[test]
fn test_transaction_manager_client_dispatch_paths() {
    let mut mgr = TransactionManager::new(false);

    let invite_req = build_request(Method::Invite);
    let invite_handle = mgr
        .create_client_transaction(invite_req.clone())
        .expect("invite client transaction");
    mgr.poll_actions();
    let invite_resp = build_response(&invite_req, 180, "Ringing");
    mgr.handle_message(SipMessage::Response(invite_resp));
    mgr.poll_actions();
    mgr.handle_timeout(invite_handle, Timer::A);
    mgr.handle_transport_error(invite_handle);
    mgr.poll_actions();

    let options_req = build_request(Method::Options);
    let options_handle = mgr
        .create_client_transaction(options_req.clone())
        .expect("non-invite client transaction");
    mgr.poll_actions();
    let options_resp = build_response(&options_req, 200, "OK");
    mgr.handle_message(SipMessage::Response(options_resp));
    mgr.poll_actions();
    mgr.handle_timeout(options_handle, Timer::E);
    mgr.handle_transport_error(options_handle);
    mgr.poll_actions();
}

#[test]
fn test_transaction_manager_cleanup_terminated_non_invite_client() {
    let mut mgr = TransactionManager::new(false);
    let req = build_request(Method::Options);
    let handle = mgr
        .create_client_transaction(req.clone())
        .expect("create client transaction");
    mgr.poll_actions();
    let resp = build_response(&req, 200, "OK");
    mgr.handle_message(SipMessage::Response(resp));
    mgr.poll_actions();
    mgr.handle_timeout(handle, Timer::K);
    mgr.poll_actions();
    mgr.cleanup_terminated();
    mgr.handle_timeout(handle, Timer::E);
    assert!(mgr.poll_actions().is_empty());
}

#[test]
fn test_transaction_manager_cleanup_terminated_non_invite_server() {
    let mut mgr = TransactionManager::new(false);
    let req = build_request(Method::Options);
    mgr.handle_message(SipMessage::Request(req.clone()));
    let handle = extract_handle(&mgr.poll_actions());
    let resp = build_response(&req, 200, "OK");
    mgr.send_response(handle, resp);
    mgr.poll_actions();
    mgr.handle_timeout(handle, Timer::J);
    mgr.poll_actions();
    mgr.cleanup_terminated();
    mgr.handle_transport_error(handle);
    assert!(mgr.poll_actions().is_empty());
}

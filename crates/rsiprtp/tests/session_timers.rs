//! Session-timer (RFC 4028) integration tests.
//!
//! Six transport-less scenarios drive `CallManager` with constructed
//! responses / requests and assert the manager's outbound queue,
//! deadlines, and call state. Phase 4's `drain_outbound_requests` plus
//! `tick(now)` make this clean: no real time advancement is required —
//! we feed `now + delta` directly.
//!
//! 1. Refresher path: 200 OK with `refresher=uac` schedules
//!    `refresh_at = now + se/2`; tick at the deadline emits an UPDATE.
//!    A 200 OK to UPDATE (signalled via `mark_in_dialog_2xx`) slides
//!    the deadline forward by another se/2.
//! 2. Non-refresher BYE path (load-bearing): 200 OK with `refresher=uas`
//!    sets `expiry_at`; if the peer goes silent past that deadline
//!    `tick` emits a BYE with `Reason: ... Session timer expired` and
//!    transitions the call to `Terminating`.
//! 3. UPDATE-not-supported fallback: when `note_update_unsupported`
//!    flips the flag, `tick` emits a re-INVITE refresh carrying SDP
//!    rebuilt from the negotiated `MediaSession` — same codec, same
//!    port (HLD snag 3).
//! 4. Outbound 422: a 422 response to the INVITE ends the call with
//!    `CallEndReason::Error`; the manager does NOT auto-retry with
//!    the larger `Min-SE` (HLD §3, scope decision).
//! 5. Inbound 422: an inbound INVITE with `Session-Expires: 30` against
//!    a manager configured with `min_se = 90` returns
//!    `InboundSessionTimer::Reject422 { min_se: 90 }`.
//! 6. Inbound refresh slides expiry: a peer-as-refresher call accepts
//!    an inbound UPDATE and slides `expiry_at` forward, so the next
//!    tick past the *original* expiry does NOT fire a BYE.

use std::time::{Duration, Instant};

use rsiprtp::sdp::negotiation::{Codec, NegotiatedMedia};
use rsiprtp::sdp::parser::Direction;
use rsiprtp::sdp::parser::SessionDescription;
use rsiprtp::session::{
    CallEndReason, CallEvent, CallId, CallManager, CallState, Dialog, InboundSessionTimer,
    ManagerConfig, ManagerEvent, OutboundRequestKind,
};
use rsiprtp::sip::{Method, Refresher, SipMessage, SipRequest, SipResponse};

// ---------------------------------------------------------------------
// Common fixtures
// ---------------------------------------------------------------------

/// Build a minimal answer SDP — peer-shaped, PCMU at port 6000.
fn answer_sdp() -> SessionDescription {
    SessionDescription::parse(
        "v=0\r\no=- 1 1 IN IP4 10.0.0.2\r\ns=-\r\nc=IN IP4 10.0.0.2\r\nt=0 0\r\n\
         m=audio 6000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n",
    )
    .expect("answer sdp")
}

/// Build a UAC dialog matching the canonical call-id used in helpers.
fn make_dialog() -> Dialog {
    Dialog::new_uac(
        "st-call-1@example.com".to_string(),
        "alice-tag".to_string(),
        "bob-tag".to_string(),
        "sip:alice@example.com".to_string(),
        "sip:bob@carrier.example.com".to_string(),
        1,
    )
}

/// Build a manager with `session_expires = secs` and default `min_se = 90s`.
fn manager_with_session_expires(secs: u64) -> CallManager {
    let mut cfg = ManagerConfig::default();
    cfg.call_config.session_expires = Duration::from_secs(secs);
    CallManager::new(cfg)
}

/// Build a 200 OK response in wire form so we can freely inject the
/// Session-Expires, Allow, and Contact headers. Raw wire control is
/// the most transparent option for these integration scenarios.
fn build_200_ok(
    invite_cseq: u32,
    session_expires_secs: Option<u32>,
    refresher: Option<Refresher>,
    allow_includes_update: bool,
) -> SipResponse {
    let allow_line = if allow_includes_update {
        "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, PRACK, UPDATE\r\n"
    } else {
        "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS\r\n"
    };
    let se_line = match (session_expires_secs, refresher) {
        (Some(s), Some(Refresher::Uac)) => format!("Session-Expires: {};refresher=uac\r\n", s),
        (Some(s), Some(Refresher::Uas)) => format!("Session-Expires: {};refresher=uas\r\n", s),
        (Some(s), None) => format!("Session-Expires: {}\r\n", s),
        (None, _) => String::new(),
    };
    let raw = format!(
        "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKabc\r\n\
From: <sip:alice@example.com>;tag=alice-tag\r\n\
To: <sip:bob@carrier.example.com>;tag=bob-tag\r\n\
Contact: <sip:bob@10.0.0.2:5060>\r\n\
Call-ID: st-call-1@example.com\r\n\
CSeq: {} INVITE\r\n\
{}{}\
Content-Length: 0\r\n\
\r\n",
        invite_cseq, se_line, allow_line
    );
    SipMessage::parse(raw.as_bytes())
        .expect("200 OK parses")
        .as_response()
        .expect("response")
        .clone()
}

/// Establish an outbound call by feeding a synthetic 200 OK through
/// `handle_invite_success`. Returns the call_id and the moment the
/// 200 OK was applied (`now0`).
fn establish_with_2xx(
    manager: &mut CallManager,
    session_expires_secs: Option<u32>,
    refresher: Option<Refresher>,
    allow_includes_update: bool,
    now: Instant,
) -> CallId {
    let call_id = manager.create_call("sip:bob@carrier.example.com".to_string());
    let dialog = make_dialog();
    let response = build_200_ok(1, session_expires_secs, refresher, allow_includes_update);
    assert!(
        manager.handle_invite_success(&call_id, dialog, &answer_sdp(), Some(&response), now,),
        "handle_invite_success accepts the 200 OK"
    );
    let _ = manager.drain_events();
    call_id
}

// ---------------------------------------------------------------------
// 1. Refresher path
// ---------------------------------------------------------------------

#[test]
fn test_session_timers_refresher_sends_update() {
    let mut manager = manager_with_session_expires(60);

    // The manager exposes the headers the app should attach to the
    // outbound INVITE via invite_offer_headers(); this is the part
    // the test owns end-to-end (the app builds the actual SipRequest).
    let offer_headers = manager.invite_offer_headers();
    assert!(
        offer_headers.supported_tags.iter().any(|t| t == "timer"),
        "Supported must include `timer`"
    );
    assert!(
        offer_headers.supported_tags.iter().any(|t| t == "100rel"),
        "Supported must include `100rel`"
    );
    let offer_se = offer_headers
        .session_expires
        .expect("Session-Expires must be present in offer headers");
    assert_eq!(
        offer_se.0, 60,
        "Session-Expires must echo CallConfig.session_expires"
    );
    // The offer's refresher tag is load-bearing — ignoring it lets a
    // regression that emits the wrong refresher (or drops the tag
    // entirely on a default-behaviour change) sneak through. The
    // manager unconditionally emits `refresher=uac` on outbound INVITE
    // offers (manager.rs::invite_offer_headers); assert that exactly.
    assert_eq!(
        offer_se.1,
        Refresher::Uac,
        "outbound INVITE offer must advertise refresher=uac \
         (manager.rs::invite_offer_headers)"
    );
    assert_eq!(
        offer_headers.min_se.expect("Min-SE"),
        90,
        "Min-SE must echo CallConfig.min_se default (90)"
    );
    assert!(offer_headers.allow_methods.contains(&Method::Prack));
    assert!(offer_headers.allow_methods.contains(&Method::Update));

    // Now feed the 200 OK with refresher=uac so we are the refresher.
    let now0 = Instant::now();
    let call_id = establish_with_2xx(&mut manager, Some(60), Some(Refresher::Uac), true, now0);

    // refresh_at should be ~ now0 + 30s.
    {
        let call = manager.get_call(&call_id).expect("call exists");
        let refresh_at = call.refresh_at.expect("refresh_at populated");
        let expected = now0 + Duration::from_secs(30);
        // Allow 1s slop in case any internal arithmetic rounds.
        let delta = if refresh_at > expected {
            refresh_at - expected
        } else {
            expected - refresh_at
        };
        assert!(
            delta < Duration::from_millis(50),
            "refresh_at must be ~now0 + 30s, got {:?} vs expected {:?}",
            refresh_at,
            expected
        );
        assert!(
            call.expiry_at.is_none(),
            "expiry_at must be None when we refresh"
        );
    }

    // Tick past the deadline.
    manager.tick(now0 + Duration::from_secs(31));
    let outbound = manager.drain_outbound_requests();
    assert_eq!(outbound.len(), 1, "exactly one outbound UPDATE");
    assert_eq!(outbound[0].kind, OutboundRequestKind::SessionTimerUpdate);
    let update_req = &outbound[0].request;
    assert_eq!(update_req.method(), Method::Update);
    let se = update_req
        .session_expires()
        .expect("UPDATE carries Session-Expires");
    assert_eq!(
        se.delta_seconds, 60,
        "UPDATE Session-Expires echoes negotiated 60"
    );
    assert_eq!(
        se.refresher,
        Some(Refresher::Uac),
        "UPDATE refresher=uac (we keep our role across refresh)"
    );

    // After tick, the manager tentatively slid `refresh_at` by se/2
    // from now0 + 31s, so it now sits at ~now0 + 61s. Capture it before
    // we drive the 2xx.
    let pre_slide_refresh_at = manager
        .get_call(&call_id)
        .expect("call")
        .refresh_at
        .expect("refresh_at after tick");

    // App receives 200 OK to UPDATE at a *distinct* time. We use
    // now0 + 45s so mark_in_dialog_2xx must materially move the
    // deadline relative to the post-tick value (now0 + 61s vs now0 +
    // 75s). If `mark_in_dialog_2xx` were a no-op for UPDATE, the
    // assertion below would fail.
    let now1 = now0 + Duration::from_secs(45);
    manager.mark_in_dialog_2xx(&call_id, Method::Update, now1);

    let call = manager.get_call(&call_id).expect("call");
    let refresh_at = call.refresh_at.expect("refresh_at still set");
    // After the 2xx, refresh_at should be ~ now1 + 30s = now0 + 75s,
    // which is materially different from the post-tick value (~now0 +
    // 61s).
    let expected = now1 + Duration::from_secs(30);
    let delta = if refresh_at > expected {
        refresh_at - expected
    } else {
        expected - refresh_at
    };
    assert!(
        delta < Duration::from_millis(50),
        "refresh_at should slide to ~now1 + 30s ({:?}), got {:?}",
        expected,
        refresh_at
    );
    assert_ne!(
        refresh_at, pre_slide_refresh_at,
        "mark_in_dialog_2xx must MOVE refresh_at, not leave it equal to the post-tick value"
    );

    // Method-discriminating filter: `mark_in_dialog_2xx` slides
    // deadlines only for UPDATE / INVITE (manager.rs ~939). A 2xx to
    // BYE arriving on this dialog must NOT slide the refresh deadline.
    // Without this guard, a regression that drops the method check
    // would silently slide on every in-dialog 2xx, including the
    // very BYE that's tearing the call down.
    let pre_bye_refresh_at = manager
        .get_call(&call_id)
        .expect("call")
        .refresh_at
        .expect("refresh_at still set before BYE 2xx");
    let bye_2xx_time = now1 + Duration::from_secs(15);
    manager.mark_in_dialog_2xx(&call_id, Method::Bye, bye_2xx_time);
    let post_bye_refresh_at = manager
        .get_call(&call_id)
        .expect("call")
        .refresh_at
        .expect("refresh_at still set after BYE 2xx");
    assert_eq!(
        post_bye_refresh_at, pre_bye_refresh_at,
        "BYE 2xx must NOT slide refresh_at — only UPDATE/INVITE 2xx slide \
         deadlines (manager.rs method-discriminating filter)"
    );
    assert_eq!(
        manager.next_deadline(),
        Some(post_bye_refresh_at),
        "next_deadline should still report the un-slid refresh_at"
    );
}

// ---------------------------------------------------------------------
// 2. Non-refresher BYE path (load-bearing)
// ---------------------------------------------------------------------

#[test]
fn test_session_timers_peer_silent_triggers_bye() {
    let mut manager = manager_with_session_expires(60);
    let now0 = Instant::now();

    // Peer chose itself as refresher — we expect them to refresh.
    let call_id = establish_with_2xx(&mut manager, Some(60), Some(Refresher::Uas), true, now0);

    // expiry_at is set, refresh_at is None.
    {
        let call = manager.get_call(&call_id).expect("call");
        let expiry_at = call.expiry_at.expect("expiry_at populated");
        assert!(
            call.refresh_at.is_none(),
            "refresh_at must be None when peer refreshes"
        );
        let expected = now0 + Duration::from_secs(60);
        let delta = if expiry_at > expected {
            expiry_at - expected
        } else {
            expected - expiry_at
        };
        assert!(
            delta < Duration::from_millis(50),
            "expiry_at must be ~now0 + 60s, got {:?}",
            expiry_at
        );
    }

    // Tick past the deadline — peer never refreshed.
    manager.tick(now0 + Duration::from_secs(61));
    let outbound = manager.drain_outbound_requests();
    assert_eq!(outbound.len(), 1, "exactly one outbound BYE");
    assert_eq!(outbound[0].kind, OutboundRequestKind::SessionTimerExpiryBye);
    let bye = &outbound[0].request;
    assert_eq!(bye.method(), Method::Bye);

    // BYE carries the RFC 3326 Reason header. We check on the wire
    // form because the SipRequest accessor for Reason isn't typed.
    let bye_wire = String::from_utf8(bye.to_bytes().to_vec()).unwrap();
    assert!(
        bye_wire.contains("Session timer expired"),
        "BYE must carry Reason: ... Session timer expired, got:\n{}",
        bye_wire
    );
    assert!(
        bye_wire.contains("Reason:") && bye_wire.contains("cause=200"),
        "BYE Reason header must include cause=200, got:\n{}",
        bye_wire
    );

    // Call moved to Terminating.
    let call = manager.get_call(&call_id).expect("call");
    assert_eq!(call.state(), CallState::Terminating);
}

// ---------------------------------------------------------------------
// 3. UPDATE-not-supported fallback
// ---------------------------------------------------------------------

/// Once `note_update_unsupported` has flipped the per-call flag, a
/// refresh-due `tick` MUST emit a re-INVITE refresh (carrying SDP
/// rebuilt from the negotiated MediaSession), not an UPDATE. The
/// manager does NOT auto-detect the flag from the 200 OK's Allow
/// header today; this test calls `note_update_unsupported` manually
/// to exercise the re-INVITE branch.
#[test]
fn test_session_timers_reinvite_refresh_when_update_unsupported() {
    let mut manager = manager_with_session_expires(60);
    let now0 = Instant::now();

    // 200 OK whose Allow does NOT include UPDATE. The manager does
    // not auto-flip update_unsupported on Allow today (it tracks the
    // flag from explicit 405/501 responses to UPDATE — see
    // note_update_unsupported). Call note_update_unsupported from the
    // test to get the same behaviour.
    let call_id = establish_with_2xx(&mut manager, Some(60), Some(Refresher::Uac), false, now0);
    manager.note_update_unsupported(&call_id);

    // Wire up media so the re-INVITE refresh can rebuild SDP from
    // the negotiated `MediaSession`. handle_invite_success only sets
    // up media if the SDP answer carries it; our build_200_ok has no
    // body, so we manually attach negotiated media here.
    let media = NegotiatedMedia {
        codec: Codec::pcmu(),
        remote_port: 6000,
        remote_addr: Some("10.0.0.2".to_string()),
        direction: Direction::SendRecv,
    };
    manager
        .get_call_mut(&call_id)
        .expect("call")
        .set_negotiated_media(media, 5000)
        .expect("media attaches");

    // Tick past the refresh deadline.
    manager.tick(now0 + Duration::from_secs(31));
    let outbound = manager.drain_outbound_requests();
    assert_eq!(outbound.len(), 1, "exactly one outbound re-INVITE");
    assert_eq!(outbound[0].kind, OutboundRequestKind::SessionTimerReInvite);
    let reinvite = &outbound[0].request;
    assert_eq!(reinvite.method(), Method::Invite);

    // Re-INVITE refresh MUST carry SDP (HLD snag 3 — re-INVITE without
    // offer is malformed).
    let body = reinvite.body();
    assert!(!body.is_empty(), "re-INVITE refresh must carry SDP body");

    let body_str = std::str::from_utf8(body).expect("SDP utf-8");
    let sdp = SessionDescription::parse(body_str).expect("SDP parses");

    // Same codec (PCMU) and same port (5000) as the negotiated session.
    let audio = sdp.audio_media().expect("audio media in refresh SDP");
    assert_eq!(
        audio.port, 5000,
        "refresh SDP must carry the negotiated port"
    );
    assert!(
        audio.formats.contains(&"0".to_string()),
        "refresh SDP must offer PCMU (payload 0), got formats={:?}",
        audio.formats
    );
}

// ---------------------------------------------------------------------
// 4. Outbound 422 — guard against an accidental auto-retry loop
// ---------------------------------------------------------------------

/// The HLD declines to implement an auto-retry on 422 Session Interval
/// Too Small (§3, scope decision). This test guards against accidentally
/// adding one. The manager has no 422-specific path today; the assertion
/// below exercises the generic INVITE failure switch and confirms (a)
/// the call ends with `CallEndReason::Error` and (b) the manager queues
/// no follow-up request. If a future refactor adds a 422-specific retry
/// branch, this test must be updated to reflect that decision
/// explicitly.
#[test]
fn test_session_timers_no_outbound_422_retry_loop() {
    let mut manager = manager_with_session_expires(30);

    // Outbound INVITE offered Session-Expires: 30. Peer rejects with
    // 422 carrying its Min-SE: 1800. Per HLD scope, no retry — the
    // call ends with CallEndReason::Error.
    let call_id = manager.create_call("sip:bob@carrier.example.com".to_string());

    // Drive the failure path through handle_invite_failure(422).
    // The manager translates non-specific failures (anything not 486 /
    // 480 / 408 / 603) to CallEndReason::Error. There is no
    // 422-specific path today; this test would behave identically for
    // any non-special status code, which is exactly the contract it is
    // guarding.
    manager.handle_invite_failure(&call_id, 422);

    let call = manager.get_call(&call_id).expect("call still tracked");
    // The call ends — CallEvent::Ended(Error) is emitted; the call
    // state becomes Terminated (handle_ended).
    assert_eq!(call.state(), CallState::Terminated);

    let events = manager.drain_events();
    let saw_error = events.iter().any(|e| {
        matches!(
            e,
            ManagerEvent::CallEvent(id, CallEvent::Ended(CallEndReason::Error)) if id == &call_id
        )
    });
    assert!(
        saw_error,
        "422 must surface as CallEnded(Error), got events: {:?}",
        events
    );

    // No auto-retry: the manager has no outbound request queued.
    let outbound = manager.drain_outbound_requests();
    assert!(
        outbound.is_empty(),
        "manager must NOT auto-retry on 422 (HLD scope decision), got {:?}",
        outbound.iter().map(|r| r.kind).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------
// 5. Inbound 422 on low Session-Expires
// ---------------------------------------------------------------------

#[test]
fn test_session_timers_inbound_422_on_low_se() {
    // Manager configured with min_se = 90s.
    let manager = CallManager::new(ManagerConfig::default());

    // Inbound INVITE with Session-Expires: 30 (below our min_se).
    let invite = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("10.0.0.99", 5060, "UDP", "z9hG4bKpeerin")
        .from("sip:alice@example.com", "ftag")
        .to("sip:bob@example.com")
        .call_id("st-call-low-se@example.com")
        .cseq(1)
        .session_expires(30, None)
        .min_se(30)
        .supported(&["timer"])
        .build()
        .expect("inbound INVITE builds");

    match manager.evaluate_inbound_invite_session_timer(&invite) {
        InboundSessionTimer::Reject422 { min_se } => {
            assert_eq!(min_se, 90, "422's Min-SE must echo our config (90s)");
        }
        other => panic!(
            "expected Reject422 for Session-Expires < min_se, got {:?}",
            other
        ),
    }
}

// ---------------------------------------------------------------------
// 6. Inbound refresh slides expiry_at
// ---------------------------------------------------------------------

#[test]
fn test_session_timers_inbound_update_slides_expiry() {
    let mut manager = manager_with_session_expires(120);
    let now0 = Instant::now();

    // Set up: peer-as-refresher call with Session-Expires=120s, so
    // expiry_at = now0 + 120s and refresh_at is None. (We use 120s
    // because the inbound UPDATE handler rejects below-min_se values
    // — default min_se is 90s, and the UPDATE will carry the
    // negotiated Session-Expires for arithmetic.)
    let call_id = establish_with_2xx(&mut manager, Some(120), Some(Refresher::Uas), true, now0);

    let dialog_id = manager
        .get_call(&call_id)
        .expect("call")
        .dialog_id()
        .expect("dialog id")
        .clone();

    // At now0 + 60s, peer sends an inbound UPDATE refreshing the
    // session. We feed it through handle_inbound_update.
    let now_refresh = now0 + Duration::from_secs(60);
    let update = SipRequest::builder()
        .method(Method::Update)
        .uri("sip:alice@example.com")
        .via("10.0.0.2", 5060, "UDP", "z9hG4bKpeerupd")
        .from("sip:bob@carrier.example.com", "bob-tag")
        .to("sip:alice@example.com")
        .to_tag("alice-tag")
        .call_id("st-call-1@example.com")
        .cseq(2)
        .session_expires(120, Some(Refresher::Uas))
        .build()
        .expect("inbound UPDATE builds");

    let resp = manager
        .handle_inbound_update(&dialog_id, &update, now_refresh)
        .expect("200 OK to UPDATE built");
    assert_eq!(resp.status_code(), 200);
    assert!(
        resp.session_expires().is_some(),
        "200 OK to UPDATE must echo Session-Expires"
    );

    // expiry_at should be slid forward to now_refresh + 120s, NOT the
    // original now0 + 120s.
    let call = manager.get_call(&call_id).expect("call");
    let expiry_at = call.expiry_at.expect("expiry_at still set");
    let expected = now_refresh + Duration::from_secs(120);
    let delta = if expiry_at > expected {
        expiry_at - expected
    } else {
        expected - expiry_at
    };
    assert!(
        delta < Duration::from_millis(50),
        "expiry_at must slide to ~now_refresh + 120s, got {:?}",
        expiry_at
    );

    // Tick past the *original* expiry (now0 + 120s + 5s) — must NOT
    // fire a BYE because the refresh moved expiry_at.
    manager.tick(now0 + Duration::from_secs(125));
    let outbound = manager.drain_outbound_requests();
    assert!(
        outbound.is_empty(),
        "no BYE after a successful peer refresh, got {:?}",
        outbound.iter().map(|r| r.kind).collect::<Vec<_>>()
    );

    // Slide-cleared regression guard: empty outbound is a necessary
    // but not sufficient signal — `maybe_fire_expiry_bye` also early-
    // returns on `expiry_at = None`, so a bug that *cleared* (rather
    // than slid) the deadline would also produce no BYE. Re-assert
    // expiry_at is still populated post-tick and still sits at the
    // slid value, so a clear-instead-of-slide regression fails loud.
    let call = manager.get_call(&call_id).expect("call");
    let expiry_at_after_tick = call
        .expiry_at
        .expect("expiry_at must remain Some after the post-original-expiry tick");
    let expected_after_tick = now_refresh + Duration::from_secs(120);
    let delta_after_tick = if expiry_at_after_tick > expected_after_tick {
        expiry_at_after_tick - expected_after_tick
    } else {
        expected_after_tick - expiry_at_after_tick
    };
    assert!(
        delta_after_tick < Duration::from_millis(50),
        "expiry_at after post-original-expiry tick must remain at \
         ~now_refresh + 120s (the slid value), got {:?}",
        expiry_at_after_tick
    );

    // Call still Established.
    assert_eq!(call.state(), CallState::Established);
}

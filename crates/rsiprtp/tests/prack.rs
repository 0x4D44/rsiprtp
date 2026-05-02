//! PRACK (RFC 3262) integration tests.
//!
//! Three transport-less scenarios drive the manager / transaction with
//! constructed SIP messages and assert outbound queue contents (PRACK
//! requests, retransmits) directly. The Sans-IO design from Phase 2
//! plus the manager's `drain_outbound_requests` from Phase 4 make this
//! clean.
//!
//! 1. UAC: an inbound 18x with `Require: 100rel` triggers a PRACK whose
//!    `RAck` echoes the right RSeq + INVITE CSeq, with `Route` from the
//!    response's `Record-Route` and a Contact header.
//! 2. UAS: a reliable 180 retransmits on Timer N until a matching PRACK
//!    arrives, then stops; the transaction emits a 200 OK to the PRACK
//!    isn't part of the transaction layer (PRACK gets its own
//!    `NonInviteServerTransaction`); the test confirms the INVITE
//!    transaction stops retransmits and the buffer is drained.
//! 3. UAS: when no PRACK arrives within 64*T1, Timer N abandons and the
//!    transaction emits `Event::PrackTimeout` so the TU can send the
//!    appropriate response (504 if no final yet).

use std::time::Duration;

use rsiprtp::session::{CallManager, Dialog, ManagerConfig, OutboundRequestKind};
use rsiprtp::sip::{Method, SipMessage, SipRequest, SipResponse};
use rsiprtp::transaction::server::invite::{
    Action as InviteServerAction, Event as InviteServerEvent, FinalSent, InviteServerTransaction,
    State as InviteServerState,
};
use rsiprtp::transaction::Timer;

/// Build a minimal answer SDP — a peer 200 OK shape that the manager
/// can negotiate against the offer codec list (PCMU).
fn answer_sdp() -> rsiprtp::sdp::parser::SessionDescription {
    rsiprtp::sdp::parser::SessionDescription::parse(
        "v=0\r\no=- 1 1 IN IP4 10.0.0.2\r\ns=-\r\nc=IN IP4 10.0.0.2\r\nt=0 0\r\n\
         m=audio 6000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n",
    )
    .expect("answer sdp")
}

/// Establish an outbound UAC call via a no-response handle_invite_success
/// so the call has an attached dialog the manager can mutate. Mirrors
/// the `established_outbound_call` helper in `manager.rs`'s unit tests.
///
/// `local_cseq` controls the dialog's seed CSeq. The PRACK test
/// chooses a value distinct from the 180's `CSeq:` header so that the
/// RAck assertion can distinguish "took from response's CSeq"
/// (correct, RFC 3262 §7.2) from "took from dialog's local CSeq"
/// (incorrect).
fn established_outbound_call_with_cseq(
    manager: &mut CallManager,
    local_cseq: u32,
) -> rsiprtp::session::CallId {
    let call_id = manager.create_call("sip:bob@carrier.example.com".to_string());
    let dialog = Dialog::new_uac(
        "prack-call-1@example.com".to_string(),
        "alice-tag".to_string(),
        "bob-tag".to_string(),
        "sip:alice@example.com".to_string(),
        "sip:bob@carrier.example.com".to_string(),
        local_cseq,
    );
    manager.handle_invite_success(
        &call_id,
        dialog,
        &answer_sdp(),
        None,
        std::time::Instant::now(),
    );
    let _ = manager.drain_events();
    call_id
}

/// Test 1: UAC — inbound 18x with Require: 100rel triggers a PRACK.
///
/// Asserts:
/// - exactly one outbound request is queued, kind = Prack
/// - the PRACK's RAck echoes the *response's* CSeq (per RFC 3262 §7.2),
///   distinguished from the dialog's local CSeq by seeding them apart
/// - the PRACK's own CSeq is the dialog's next local CSeq
/// - the PRACK carries the proxy from Record-Route as its Route header
/// - the PRACK carries a Contact header
#[test]
fn test_prack_sent_on_reliable_provisional() {
    // Disambiguate "RAck cseq == response's CSeq" (correct) from
    // "RAck cseq == dialog's local CSeq" (incorrect): seed the dialog
    // at N1=5 and craft the 180 with `CSeq: 7 INVITE` (N2=7).
    const DIALOG_LOCAL_CSEQ: u32 = 5;
    const RESPONSE_CSEQ: u32 = 7;
    assert_ne!(
        DIALOG_LOCAL_CSEQ, RESPONSE_CSEQ,
        "test fixture must use distinct values to disambiguate RAck source"
    );

    let mut manager = CallManager::new(ManagerConfig::default());
    let call_id = established_outbound_call_with_cseq(&mut manager, DIALOG_LOCAL_CSEQ);

    // Build a 180 carrying Record-Route + Contact + Require: 100rel +
    // RSeq, by raw text — the SipResponseBuilder doesn't have a
    // generic header setter for Record-Route. The 180 is what a proxy
    // would stamp onto our INVITE on the way back. Note the CSeq
    // header value (RESPONSE_CSEQ) is deliberately different from the
    // dialog's local seed.
    let raw_180 = format!(
        "SIP/2.0 180 Ringing\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKabc\r\n\
Record-Route: <sip:proxy.example.com;lr>\r\n\
From: <sip:alice@example.com>;tag=alice-tag\r\n\
To: <sip:bob@carrier.example.com>;tag=bob-tag\r\n\
Contact: <sip:bob@10.0.0.2:5060>\r\n\
Call-ID: prack-call-1@example.com\r\n\
CSeq: {} INVITE\r\n\
Require: 100rel\r\n\
RSeq: 1\r\n\
Content-Length: 0\r\n\
\r\n",
        RESPONSE_CSEQ
    );
    let one_eighty = SipMessage::parse(raw_180.as_bytes())
        .expect("parse 180")
        .as_response()
        .expect("response")
        .clone();

    // Drive the response through the manager's provisional handler so
    // the dialog routing fields populate (route_set, remote_target,
    // local_contact). PRACK built afterward then inherits them.
    manager.handle_provisional_response(&call_id, &one_eighty, None, "sip:alice@10.0.0.1:5060");

    // Build the PRACK via the manager's PRACK entry point.
    let prack = manager
        .handle_provisional_reliable(&call_id, &one_eighty)
        .expect("PRACK built");

    assert_eq!(prack.method(), Method::Prack);

    // RAck: 1 (RSeq) <response-cseq> INVITE. The cseq must echo the
    // 180's CSeq (RFC 3262 §7.2), not the dialog's local seed.
    let rack = prack.rack().expect("RAck on PRACK");
    assert_eq!(rack.rseq, 1, "RAck rseq should match 180's RSeq");
    assert_eq!(
        rack.cseq, RESPONSE_CSEQ,
        "RAck cseq must echo the response's CSeq (RFC 3262 §7.2), not the dialog's local CSeq"
    );
    assert_ne!(
        rack.cseq, DIALOG_LOCAL_CSEQ,
        "RAck cseq MUST NOT equal the dialog's local CSeq — that would mean we sourced \
         it from the wrong place; the test seed disambiguates the two on purpose"
    );
    assert_eq!(rack.method, Method::Invite, "RAck method is INVITE");

    // PRACK is its own transaction inside the dialog and gets the
    // *next* local CSeq (DIALOG_LOCAL_CSEQ + 1), not the response's
    // CSeq, not the original seed.
    assert_eq!(
        prack.cseq().expect("PRACK has CSeq"),
        DIALOG_LOCAL_CSEQ + 1,
        "PRACK's own CSeq must be dialog.local_cseq + 1 (RFC 3262 §7.2 — \
         PRACK is a new transaction)"
    );

    // Route header carries the proxy URI from Record-Route. After UAC
    // reversal a single-proxy chain stays single-proxy.
    let bytes = prack.to_bytes();
    let prack_parsed = SipMessage::parse(&bytes)
        .expect("parse PRACK")
        .as_request()
        .expect("request")
        .clone();
    let routes = prack_parsed.route_headers();
    assert_eq!(routes.len(), 1, "PRACK must carry exactly one Route header");
    assert!(
        routes[0].contains("proxy.example.com"),
        "Route must carry the proxy: {:?}",
        routes[0]
    );

    // Contact present (from the populated dialog's local_contact).
    assert!(
        prack_parsed.contact_uri().is_some(),
        "PRACK must carry a Contact header"
    );

    // Manager queued the same request for the app to dispatch.
    let outbound = manager.drain_outbound_requests();
    assert_eq!(outbound.len(), 1, "exactly one outbound request");
    assert_eq!(outbound[0].kind, OutboundRequestKind::Prack);
}

// ---------------------------------------------------------------------
// UAS-side reliable provisional tests
// ---------------------------------------------------------------------

fn create_uas_invite() -> SipRequest {
    // Inbound INVITE — peer (UAC) has 100rel in Require.
    SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("10.0.0.99", 5060, "UDP", "z9hG4bKpeer")
        .from("sip:alice@example.com", "fromtag")
        .to("sip:bob@example.com")
        .call_id("prack-uas-1@example.com")
        .cseq(1)
        .require(&["100rel"])
        .supported(&["timer", "100rel"])
        .build()
        .expect("inbound INVITE")
}

fn build_180_for(invite: &SipRequest) -> SipResponse {
    SipResponse::builder()
        .status(180, "Ringing")
        .from_request(invite)
        .to_tag("uastag")
        .build()
        .expect("180 builds")
}

/// Test 2: UAS sends reliable 180 and stops retransmitting on matching PRACK.
///
/// Asserts:
/// - The 180 emitted to the wire carries `Require: 100rel` and `RSeq: 1`.
/// - Timer N is scheduled.
/// - Driving Timer N causes a retransmit (Action::Send) and reschedules.
/// - On `Event::PrackReceived(1)`, Timer N is cancelled (CancelTimer
///   action emitted) and no further sends occur on subsequent Timer N
///   firings.
#[test]
fn test_uas_reliable_provisional_stops_on_prack() {
    let invite = create_uas_invite();
    let mut tx = InviteServerTransaction::new(invite.clone(), false /* unreliable */).unwrap();
    // Drain the initial Request event.
    tx.poll_actions();

    let one_eighty = build_180_for(&invite);
    tx.send_provisional_reliable(one_eighty);

    let actions = tx.poll_actions();

    // Find the Send action and assert its bytes carry Require: 100rel
    // and RSeq: 1.
    let send_bytes = actions
        .iter()
        .find_map(|a| {
            if let InviteServerAction::Send(b) = a {
                Some(b.clone())
            } else {
                None
            }
        })
        .expect("Send action with 180 bytes");
    let wire = String::from_utf8(send_bytes.to_vec()).unwrap();
    assert!(
        wire.contains("Require: 100rel") || wire.contains("Require:100rel"),
        "180 must carry Require: 100rel, got:\n{}",
        wire
    );
    assert!(
        wire.contains("RSeq: 1") || wire.contains("RSeq:1"),
        "180 must carry RSeq: 1, got:\n{}",
        wire
    );

    // Timer N must be scheduled.
    let timer_n_set = actions
        .iter()
        .any(|a| matches!(a, InviteServerAction::SetTimer(Timer::N, _)));
    assert!(
        timer_n_set,
        "Timer N must be set after reliable provisional"
    );

    // Drive Timer N: expect a retransmit (Send) and a reschedule
    // (SetTimer(N, ...)).
    tx.handle_timeout(Timer::N);
    let after_n = tx.poll_actions();
    let resent = after_n
        .iter()
        .any(|a| matches!(a, InviteServerAction::Send(_)));
    let rescheduled = after_n
        .iter()
        .any(|a| matches!(a, InviteServerAction::SetTimer(Timer::N, _)));
    assert!(resent, "180 must retransmit on Timer N");
    assert!(rescheduled, "Timer N must reschedule itself");

    // PRACK arrives with matching RSeq.
    tx.handle_event(InviteServerEvent::PrackReceived(1));
    let after_prack = tx.poll_actions();
    let cancelled = after_prack
        .iter()
        .any(|a| matches!(a, InviteServerAction::CancelTimer(Timer::N)));
    assert!(
        cancelled,
        "Timer N must be cancelled when matching PRACK arrives"
    );

    // Subsequent Timer N firings should be a no-op (buffer empty).
    tx.handle_timeout(Timer::N);
    let after_2 = tx.poll_actions();
    let any_send = after_2
        .iter()
        .any(|a| matches!(a, InviteServerAction::Send(_)));
    assert!(
        !any_send,
        "no further retransmits after PRACK drains the buffer, got {:?}",
        after_2
    );

    // Transaction is still in Proceeding (no final yet).
    assert_eq!(tx.state(), InviteServerState::Proceeding);
}

/// Test 3: UAS — Timer N abandons after 64*T1 with no PRACK and no
/// final, emitting `Event::PrackTimeout { final_sent: None }`.
///
/// The TU is expected to convert this into a 504 response. We don't
/// drive a 504 here; we assert the event payload and document the
/// follow-up in the test name. The transaction layer doesn't build
/// the 504 itself (the TU does), so this is the right boundary.
#[test]
fn test_prack_timeout_emits_504() {
    let invite = create_uas_invite();
    let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
    tx.poll_actions();

    let one_eighty = build_180_for(&invite);
    tx.send_provisional_reliable(one_eighty);
    tx.poll_actions();

    // Drive Timer N enough times for the entry's elapsed time to reach
    // 64*T1. Each fire advances `elapsed` by `next_fire_after`. With
    // T1 = 500ms and exponential doubling capped at T2, ~7 fires
    // takes us past 64*T1 (32s). Keep driving until we see PrackTimeout
    // emitted, summing scheduled-timer durations along the way to
    // verify the abandonment matches RFC 3262's 64*T1 budget rather
    // than firing on the very first tick (regression guard).
    let mut saw_timeout = false;
    let mut final_sent_observed: Option<FinalSent> = None;
    let mut scheduled_total = Duration::ZERO;
    let mut retransmit_count: usize = 0;
    let mut iterations: usize = 0;
    for _ in 0..32 {
        iterations += 1;
        tx.handle_timeout(Timer::N);
        let actions = tx.poll_actions();
        for a in actions {
            match a {
                InviteServerAction::Send(_) => {
                    retransmit_count += 1;
                }
                InviteServerAction::SetTimer(Timer::N, d) => {
                    scheduled_total += d;
                }
                InviteServerAction::Event(InviteServerEvent::PrackTimeout {
                    rseq,
                    final_sent,
                }) => {
                    assert_eq!(rseq, 1, "PrackTimeout rseq must be 1");
                    final_sent_observed = Some(final_sent);
                    saw_timeout = true;
                }
                _ => {}
            }
        }
        if saw_timeout {
            break;
        }
    }

    assert!(
        saw_timeout,
        "PrackTimeout must fire when no PRACK arrives within 64*T1"
    );

    // Regression guard: the timer must NOT fire PrackTimeout on the
    // first tick. RFC 3262 §3 says the UAS abandons the reliable
    // provisional after 64*T1 (≈32s with T1 = 500ms). We assert two
    // honest oracles for that schedule:
    //   (a) the cumulative scheduled-timer duration is at least 32s,
    //   (b) more than one retransmit was emitted along the way.
    // Either check alone catches the trivial regression where Timer N
    // emits PrackTimeout on the first fire.
    assert!(
        scheduled_total >= Duration::from_secs(32),
        "Timer N must accumulate ≥ 64*T1 (32s) of scheduled fires \
         before abandoning; got {:?} across {} iterations",
        scheduled_total,
        iterations
    );
    assert!(
        retransmit_count >= 2,
        "expected multiple retransmits before PrackTimeout; got {} \
         (regression: timer fired PrackTimeout on the first tick?)",
        retransmit_count
    );
    assert_eq!(
        final_sent_observed,
        Some(FinalSent::None),
        "final_sent should be None — TU's signal to send 504 Server Time-out"
    );

    // The TU's job is to send a 504 in response. Emulate that here so
    // the test documents the full RFC 3262 §3 reaction.
    let resp_504 = SipResponse::builder()
        .status(504, "Server Time-out")
        .from_request(&invite)
        .to_tag("uastag")
        .build()
        .expect("504 builds");
    tx.send_response(resp_504);
    let actions = tx.poll_actions();
    let sent = actions
        .iter()
        .any(|a| matches!(a, InviteServerAction::Send(_)));
    assert!(sent, "TU's 504 must be queued for the wire");
    // Transaction transitioned to Completed (3xx-6xx final).
    assert_eq!(tx.state(), InviteServerState::Completed);
}

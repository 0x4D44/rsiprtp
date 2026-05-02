//! End-to-end ICE wiring oracle.
//!
//! Two `CallManager` instances on `127.0.0.1` exchange offer/answer
//! through ICE-attributed SDP, run real STUN connectivity checks on
//! loopback via `IceSession`, and then prove the resulting socket pair
//! actually carries traffic. There is no real SIP signalling — SDP is
//! handed between managers in-process — but every other step is the
//! production code path described in the HLD's "Caller flow" section.
//!
//! This test is the load-bearing oracle for the ICE wiring HLD: if it
//! passes, the public surface (`IceSession`, `CallManager::accept_inbound_invite`,
//! `CallManager::build_answer_for`, `IceAnswerInputs`,
//! `sdp::ice_attrs::*`) wires up end to end. Keep it fast and
//! deterministic — no `tokio::time::sleep` calls.

use std::time::Duration;

use rsiprtp::ice::{Candidate, IceRole};
use rsiprtp::sdp::builder::{MediaBuilder, SdpBuilder};
use rsiprtp::sdp::ice_attrs;
use rsiprtp::sdp::parser::SessionDescription;
use rsiprtp::session::{
    CallEndReason, CallEvent, CallManager, CallState, Dialog, IceAnswerInputs, IceRemoteParams,
    IceSession, ManagerConfig, ManagerEvent,
};

/// Tight timeouts so a wedged check fails fast rather than dragging the
/// whole test suite. Loopback STUN exchanges complete in well under a
/// millisecond in practice.
const SHORT: Duration = Duration::from_millis(500);

/// Hard upper bound on the whole `run_checks` join — if both sides
/// haven't reported within this, something is genuinely wrong.
const RUN_CHECKS_BUDGET: Duration = Duration::from_secs(2);

/// Hard upper bound on a probe `recv_from`. Loopback round-trips are
/// sub-millisecond in practice; the headroom here is purely so a
/// genuinely-broken socket fails fast on slow CI rather than wedging.
const PROBE_BUDGET: Duration = Duration::from_secs(2);

/// Pull the peer's ICE credentials and candidate list out of an SDP.
fn extract_ice_params(sdp: &SessionDescription) -> IceRemoteParams {
    let audio = sdp.audio_media().expect("audio media");
    let (ufrag, pwd) =
        ice_attrs::read_ice_credentials(audio).expect("offer/answer carries ICE credentials");
    let candidates = ice_attrs::read_candidates(audio);
    assert!(
        !candidates.is_empty(),
        "peer SDP must carry at least one a=candidate line"
    );
    IceRemoteParams {
        ufrag,
        pwd,
        candidates,
    }
}

/// Build an offer SDP for the caller side: PCMU codec + ICE attributes
/// + rtcp-mux + `c=`/`m=` patched to the default candidate.
fn build_offer(
    default: &Candidate,
    local: &rsiprtp::session::IceLocalParams,
) -> SessionDescription {
    let local_ip = default.address.ip();
    let mut sdp = SdpBuilder::new(local_ip)
        .session_name("rsiprtp ICE test")
        .add_media(MediaBuilder::audio(default.address.port()).pcmu())
        .build();

    ice_attrs::apply_default_candidate(&mut sdp, 0, default);
    let audio = sdp
        .media
        .get_mut(0)
        .expect("audio media just inserted by builder");
    ice_attrs::write_ice_credentials(audio, &local.ufrag, &local.pwd);
    ice_attrs::write_candidates(audio, &local.candidates);
    ice_attrs::write_rtcp_mux(audio);

    sdp
}

/// Build a UAC/UAS dialog pair sharing one SIP call-id and tag set.
fn dialog_pair() -> (Dialog, Dialog) {
    let call_id = "ice-basic-call".to_string();
    let from_tag = "alice-tag".to_string();
    let to_tag = "bob-tag".to_string();
    let alice_uri = "sip:alice@127.0.0.1".to_string();
    let bob_uri = "sip:bob@127.0.0.1".to_string();

    let uac = Dialog::new_uac(
        call_id.clone(),
        from_tag.clone(),
        to_tag.clone(),
        alice_uri.clone(),
        bob_uri.clone(),
        1,
    );
    let uas = Dialog::new_uas(call_id, from_tag, to_tag, bob_uri, alice_uri, 1);
    (uac, uas)
}

#[tokio::test(flavor = "multi_thread")]
async fn ice_basic_two_managers_loopback_handshake() {
    // ---- Side A (caller) ----
    let mut a_manager = CallManager::new(ManagerConfig::default());
    let mut a_ice = IceSession::gather(IceRole::Controlling, vec![], SHORT, SHORT)
        .await
        .expect("A: gather host candidates");

    let a_call_id = a_manager.create_call("sip:bob@127.0.0.1".to_string());
    let a_default = a_ice
        .default_candidate()
        .expect("A: at least one host candidate")
        .clone();
    let offer = build_offer(&a_default, a_ice.local());

    // SDP must round-trip through the wire format (the way it would in a
    // real INVITE) before the callee parses it.
    let offer_wire = offer.to_string();
    let offer_parsed = SessionDescription::parse(&offer_wire).expect("offer SDP parses");

    // ---- Side B (callee) ----
    let mut b_manager = CallManager::new(ManagerConfig::default());
    let (uac_dialog, uas_dialog) = dialog_pair();

    let b_call_id = b_manager
        .accept_inbound_invite(uas_dialog, &offer_parsed)
        .expect("B: accept_inbound_invite");

    // R4: `accept_inbound_invite` is the deferred-answer entry point;
    // it owes us an `IncomingCall` event for the application to react
    // to. Assert before draining.
    let b_events = b_manager.drain_events();
    assert!(
        b_events
            .iter()
            .any(|e| matches!(e, ManagerEvent::IncomingCall(id) if id == &b_call_id)),
        "B: accept_inbound_invite must emit IncomingCall, got {:?}",
        b_events
    );

    let mut b_ice = IceSession::gather(IceRole::Controlled, vec![], SHORT, SHORT)
        .await
        .expect("B: gather host candidates");
    let b_default = b_ice
        .default_candidate()
        .expect("B: at least one host candidate")
        .clone();

    let answer = {
        let inputs = IceAnswerInputs::new(&b_default, b_ice.local());
        b_manager
            .build_answer_for(&b_call_id, &inputs)
            .expect("B: build_answer_for")
    };
    let answer_wire = answer.to_string();
    let answer_parsed = SessionDescription::parse(&answer_wire).expect("answer SDP parses");

    // R5: the offer carries `a=rtcp-mux`; a regression in
    // `build_answer_for` could silently drop it, leaving us with an
    // unmuxed RTCP port that nobody binds. Assert it survives.
    let answer_audio = answer_parsed
        .audio_media()
        .expect("answer carries audio media");
    assert!(
        ice_attrs::read_rtcp_mux(answer_audio),
        "answer must propagate a=rtcp-mux from the offer"
    );

    // ---- Wire the answer back into A's CallManager ----
    let a_answer_dialog = uac_dialog.clone();
    assert!(
        a_manager.handle_invite_success(&a_call_id, a_answer_dialog, &answer_parsed),
        "A: handle_invite_success accepts the answer"
    );

    // R4: the 200 OK answer drives A from `Calling` to `Established`.
    let a_events = a_manager.drain_events();
    assert!(
        a_events.iter().any(|e| matches!(
            e,
            ManagerEvent::CallStateChanged(id, CallState::Established) if id == &a_call_id
        )),
        "A: handle_invite_success must emit CallStateChanged(_, Established), got {:?}",
        a_events
    );

    // ---- Run checks concurrently ----
    let a_remote = extract_ice_params(&answer_parsed);
    let b_remote = extract_ice_params(&offer_parsed);

    let join = tokio::time::timeout(RUN_CHECKS_BUDGET, async move {
        let (a_res, b_res) = tokio::join!(a_ice.run_checks(a_remote), b_ice.run_checks(b_remote));
        (a_ice, b_ice, a_res, b_res)
    })
    .await
    .expect("ICE checks complete within budget");

    let (a_ice, b_ice, a_res, b_res) = join;
    a_res.expect("A: run_checks ok");
    b_res.expect("B: run_checks ok");

    // ---- Manager-side assertions: media is wired on both sides ----
    assert!(
        a_manager
            .get_call(&a_call_id)
            .expect("A: call exists")
            .media()
            .is_some(),
        "A: call has a media session after handle_invite_success"
    );
    // B's call is still Ringing — `build_answer_for` wires media on B
    // already, but the call goes to Established only via answer_call.
    assert!(b_manager.answer_call(&b_call_id), "B: answer_call");
    assert!(
        b_manager
            .get_call(&b_call_id)
            .expect("B: call exists")
            .media()
            .is_some(),
        "B: call has a media session after build_answer_for + answer_call"
    );

    // ---- Probe traffic A -> B ----
    let socket_a = a_ice.rtp_socket().expect("A: rtp socket");
    let socket_b = b_ice.rtp_socket().expect("B: rtp socket");
    let peer_a = a_ice.peer_addr().expect("A: peer addr");
    let peer_b = b_ice.peer_addr().expect("B: peer addr");

    // The peer addresses must be each other's bound socket.
    assert_eq!(
        peer_a,
        socket_b.local_addr().expect("B socket local addr"),
        "A's peer must be B's bound socket"
    );
    assert_eq!(
        peer_b,
        socket_a.local_addr().expect("A socket local addr"),
        "B's peer must be A's bound socket"
    );

    let probe_a_to_b = b"hello-from-a";
    socket_a
        .send_to(probe_a_to_b, peer_a)
        .await
        .expect("A: send to B");

    let mut buf = [0u8; 64];
    let (n, _from) = tokio::time::timeout(PROBE_BUDGET, socket_b.recv_from(&mut buf))
        .await
        .expect("B: probe arrives within budget")
        .expect("B: recv_from ok");
    assert_eq!(&buf[..n], probe_a_to_b, "A->B probe bytes match");

    // ---- Probe traffic B -> A ----
    let probe_b_to_a = b"hello-from-b";
    socket_b
        .send_to(probe_b_to_a, peer_b)
        .await
        .expect("B: send to A");

    let (n, _from) = tokio::time::timeout(PROBE_BUDGET, socket_a.recv_from(&mut buf))
        .await
        .expect("A: probe arrives within budget")
        .expect("A: recv_from ok");
    assert_eq!(&buf[..n], probe_b_to_a, "B->A probe bytes match");
}

/// R1 + R2: cross-component MI-validation oracle.
///
/// The happy-path test above passes even if MESSAGE-INTEGRITY validation
/// were stubbed out, because both sides have correct credentials. Real
/// MI coverage at the integration level needs a *failure* path: hand
/// one side the wrong remote password and confirm the connectivity
/// check rejects it.
///
/// What this test exercises end to end:
/// - B is given the wrong remote password. Its outbound STUN binding
///   requests therefore carry MI signed with the wrong key.
/// - A's STUN responder validates MI against A's *local* password
///   (which is what B's `remote_pwd` is supposed to be) and drops B's
///   bad-MI requests on the floor — no response is returned.
/// - B's connectivity check times out, all pairs go `Failed`, and
///   `IceSession::run_checks` rejects the agent's host-host fallback
///   as not-validated. So `b_ice.run_checks(...)` must return `Err`.
/// - The application reacts by terminating B's pre-answer call via
///   `reject_inbound_invite` (Phase 3 entry point). The call must end
///   up in `Terminated` and the dialog id must come back so a 5xx can
///   be sent upstream.
///
/// If anyone disables MI validation in `build_binding_response` (or
/// equivalent), B's bad requests would now be answered, B's check
/// would succeed, and `b_ice.run_checks(...)` would return `Ok` —
/// flipping the assertion.
#[tokio::test(flavor = "multi_thread")]
async fn ice_run_checks_rejects_bad_message_integrity_and_call_cleans_up() {
    // ---- Side A (caller, correct creds) ----
    let mut a_ice = IceSession::gather(IceRole::Controlling, vec![], SHORT, SHORT)
        .await
        .expect("A: gather");
    let a_default = a_ice
        .default_candidate()
        .expect("A: at least one host candidate")
        .clone();

    // ---- Side B (callee, will be given a wrong remote pwd) ----
    let mut b_manager = CallManager::new(ManagerConfig::default());
    let mut b_ice = IceSession::gather(IceRole::Controlled, vec![], SHORT, SHORT)
        .await
        .expect("B: gather");

    // Fake an inbound INVITE on B. We need an SDP carrying A's ICE
    // attributes so `accept_inbound_invite` can cache the answer.
    let offer = build_offer(&a_default, a_ice.local());
    let offer_wire = offer.to_string();
    let offer_parsed = SessionDescription::parse(&offer_wire).expect("offer parses");

    let (_uac_dialog, uas_dialog) = dialog_pair();
    let b_call_id = b_manager
        .accept_inbound_invite(uas_dialog, &offer_parsed)
        .expect("B: accept_inbound_invite");
    let _ = b_manager.drain_events();

    // ---- Run checks: A correct, B with wrong remote pwd ----
    // A gets the real B password; B gets a 24-byte garbage password
    // (long enough to pass the credential length checks but wrong).
    let a_remote = IceRemoteParams {
        ufrag: b_ice.local().ufrag.clone(),
        pwd: b_ice.local().pwd.clone(),
        candidates: b_ice.local().candidates.clone(),
    };
    let b_remote = IceRemoteParams {
        ufrag: a_ice.local().ufrag.clone(),
        pwd: "this-is-not-the-real-pwd".to_string(),
        candidates: a_ice.local().candidates.clone(),
    };
    // Sanity: candidate lists are non-empty (otherwise the test is
    // a no-op and the failure assertion would mean nothing).
    assert!(!a_remote.candidates.is_empty());
    assert!(!b_remote.candidates.is_empty());

    let join = tokio::time::timeout(RUN_CHECKS_BUDGET, async move {
        let (a_res, b_res) = tokio::join!(a_ice.run_checks(a_remote), b_ice.run_checks(b_remote));
        (a_res, b_res)
    })
    .await
    .expect("checks complete within budget");

    let (_a_res, b_res) = join;
    // A's outbound check is signed with the real password; B's
    // responder accepts it and replies, so A's check itself can
    // succeed. The load-bearing assertion is on B.
    let b_err = b_res.expect_err("B: run_checks must fail when its remote pwd is wrong");
    let b_msg = format!("{}", b_err);
    assert!(
        b_msg.contains("validated") || b_msg.contains("checks failed"),
        "B: error must mention validation failure, got {:?}",
        b_msg
    );

    // ---- Application cleanup via Phase 3 reject_inbound_invite ----
    let dialog_id = b_manager
        .reject_inbound_invite(&b_call_id)
        .expect("B: reject_inbound_invite returns dialog id");

    let call = b_manager
        .get_call(&b_call_id)
        .expect("B: call still present");
    assert_eq!(call.state(), CallState::Terminated, "B: call terminated");
    assert_eq!(call.dialog_id(), Some(&dialog_id));

    let events = b_manager.drain_events();
    assert!(
        events.iter().any(|e| matches!(
            e,
            ManagerEvent::CallEvent(id, CallEvent::Ended(CallEndReason::Error)) if id == &b_call_id
        )),
        "B: rejection must emit Ended(Error), got {:?}",
        events
    );

    // Second rejection is a no-op — the call is already Terminated.
    assert!(b_manager.reject_inbound_invite(&b_call_id).is_none());
}

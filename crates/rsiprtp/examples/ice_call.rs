//! End-to-end ICE wiring demonstration.
//!
//! This example demonstrates the ICE wiring API by running both sides
//! in-process — there is no real SIP transport here. A production
//! application would receive INVITE / 200 OK / ACK over
//! `transport::udp` (see `examples/basic_call.rs` for the SIP
//! signalling shape) and combine that with the ICE flow shown here:
//! gather candidates, build an offer carrying ICE attributes, hand it
//! to the callee, build an answer once the callee has gathered, run
//! connectivity checks concurrently, and finally use the validated
//! socket pair for RTP.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p rsiprtp --example ice_call
//! ```
//!
//! The example exercises the public surface (`IceSession`,
//! `CallManager::accept_inbound_invite`, `CallManager::build_answer_for`,
//! `IceAnswerInputs`, `sdp::ice_attrs::*`) end to end on loopback.

use std::time::Duration;

use rsiprtp::ice::{Candidate, IceRole};
use rsiprtp::prelude::*;
use rsiprtp::sdp::builder::MediaBuilder;
use rsiprtp::sdp::ice_attrs;
use rsiprtp::session::{IceAnswerInputs, IceLocalParams, IceRemoteParams, IceSession};

const GATHER_TIMEOUT: Duration = Duration::from_millis(500);
const CHECK_TIMEOUT: Duration = Duration::from_millis(500);
/// Hard upper bound on the whole `run_checks` join. If the example
/// wedges for any reason, `cargo run` should fail fast rather than
/// hang the developer's terminal.
const RUN_CHECKS_BUDGET: Duration = Duration::from_secs(2);

fn build_offer(default: &Candidate, local: &IceLocalParams) -> SessionDescription {
    let local_ip = default.address.ip();
    let mut sdp = SdpBuilder::new(local_ip)
        .session_name("rsiprtp ICE example")
        .add_media(MediaBuilder::audio(default.address.port()).pcmu())
        .build();

    ice_attrs::apply_default_candidate(&mut sdp, 0, default);
    let audio = sdp.media.get_mut(0).expect("audio media");
    ice_attrs::write_ice_credentials(audio, &local.ufrag, &local.pwd);
    ice_attrs::write_candidates(audio, &local.candidates);
    ice_attrs::write_rtcp_mux(audio);
    sdp
}

fn extract_remote(sdp: &SessionDescription) -> IceRemoteParams {
    let audio = sdp.audio_media().expect("audio media");
    let (ufrag, pwd) = ice_attrs::read_ice_credentials(audio).expect("ICE credentials in SDP");
    let candidates = ice_attrs::read_candidates(audio);
    IceRemoteParams {
        ufrag,
        pwd,
        candidates,
    }
}

fn dialog_pair() -> (Dialog, Dialog) {
    let call_id = "ice-example-call".to_string();
    let from_tag = "alice-tag".to_string();
    let to_tag = "bob-tag".to_string();
    let alice_uri = "sip:alice@127.0.0.1".to_string();
    let bob_uri = "sip:bob@127.0.0.1".to_string();

    (
        Dialog::new_uac(
            call_id.clone(),
            from_tag.clone(),
            to_tag.clone(),
            alice_uri.clone(),
            bob_uri.clone(),
            1,
        ),
        Dialog::new_uas(call_id, from_tag, to_tag, bob_uri, alice_uri, 1),
    )
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // `try_init` so the example doesn't panic if a global subscriber
    // already exists (e.g. the example is run from a harness that set
    // one up). Logging is best-effort here.
    let _ = tracing_subscriber::fmt().try_init();

    println!("=== rsiprtp ICE example ===");

    // ---- Side A: caller (controlling) ----
    println!("\n[A] gathering host candidates...");
    let mut a_manager = CallManager::new(ManagerConfig::default());
    let mut a_ice =
        IceSession::gather(IceRole::Controlling, vec![], GATHER_TIMEOUT, CHECK_TIMEOUT).await?;
    let a_default = a_ice
        .default_candidate()
        .ok_or("A: no host candidate gathered")?
        .clone();
    println!(
        "[A] gathered {} candidate(s); default = {}",
        a_ice.local().candidates.len(),
        a_default.address
    );

    let a_call_id = a_manager.create_call("sip:bob@127.0.0.1".to_string());
    println!("[A] created outbound call {}", a_call_id);

    let offer = build_offer(&a_default, a_ice.local());
    let offer_wire = offer.to_string();
    println!("[A] built SDP offer with ICE attributes (rtcp-mux, host candidate)");

    // ---- Side B: callee (controlled) ----
    println!("\n[B] receives the offer (in-process; no SIP wire here)");
    let offer_parsed = SessionDescription::parse(&offer_wire)?;

    let mut b_manager = CallManager::new(ManagerConfig::default());
    let (uac_dialog, uas_dialog) = dialog_pair();
    let b_call_id = b_manager
        .accept_inbound_invite(uas_dialog, &offer_parsed)
        .ok_or("B: accept_inbound_invite returned None (codec mismatch?)")?;
    println!("[B] accept_inbound_invite -> {}", b_call_id);

    println!("[B] gathering host candidates...");
    let mut b_ice =
        IceSession::gather(IceRole::Controlled, vec![], GATHER_TIMEOUT, CHECK_TIMEOUT).await?;
    let b_default = b_ice
        .default_candidate()
        .ok_or("B: no host candidate gathered")?
        .clone();
    println!(
        "[B] gathered {} candidate(s); default = {}",
        b_ice.local().candidates.len(),
        b_default.address
    );

    let answer = {
        let inputs = IceAnswerInputs::new(&b_default, b_ice.local());
        b_manager
            .build_answer_for(&b_call_id, &inputs)
            .ok_or("B: build_answer_for returned None")?
    };
    let answer_wire = answer.to_string();
    println!("[B] built SDP answer with ICE attributes");

    // ---- Side A: ingest the 200 OK answer ----
    println!("\n[A] ingesting 200 OK answer");
    let answer_parsed = SessionDescription::parse(&answer_wire)?;
    if !a_manager.handle_invite_success(
        &a_call_id,
        uac_dialog,
        &answer_parsed,
        None,
        std::time::Instant::now(),
    ) {
        return Err("A: handle_invite_success rejected the answer".into());
    }

    // ---- Run connectivity checks concurrently ----
    let a_remote = extract_remote(&answer_parsed);
    let b_remote = extract_remote(&offer_parsed);

    println!("\n[A+B] running ICE connectivity checks (concurrently)...");
    let (a_res, b_res) = tokio::time::timeout(RUN_CHECKS_BUDGET, async {
        tokio::join!(a_ice.run_checks(a_remote), b_ice.run_checks(b_remote))
    })
    .await
    .map_err(|_| "ICE connectivity checks timed out")?;
    let peer_a = a_res?;
    let peer_b = b_res?;
    println!("[A] check succeeded; peer = {}", peer_a);
    println!("[B] check succeeded; peer = {}", peer_b);

    // ---- Wire the call established on B ----
    if !b_manager.answer_call(&b_call_id) {
        return Err("B: answer_call failed".into());
    }
    println!("[B] call answered (Established)");

    // ---- Send a probe through the validated socket pair ----
    let socket_a = a_ice.rtp_socket().ok_or("A: no rtp socket")?;
    let socket_b = b_ice.rtp_socket().ok_or("B: no rtp socket")?;

    println!("\n[A] sending probe -> {}", peer_a);
    socket_a.send_to(b"hello-from-a", peer_a).await?;
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_millis(500), socket_b.recv_from(&mut buf))
        .await
        .map_err(|_| "B: probe recv timed out")??;
    println!(
        "[B] received {} byte(s): {:?}",
        n,
        std::str::from_utf8(&buf[..n]).unwrap_or("<non-utf8>")
    );

    println!("\n[B] sending probe -> {}", peer_b);
    socket_b.send_to(b"hello-from-b", peer_b).await?;
    let (n, _) = tokio::time::timeout(Duration::from_millis(500), socket_a.recv_from(&mut buf))
        .await
        .map_err(|_| "A: probe recv timed out")??;
    println!(
        "[A] received {} byte(s): {:?}",
        n,
        std::str::from_utf8(&buf[..n]).unwrap_or("<non-utf8>")
    );

    println!("\n=== Example complete ===");
    Ok(())
}

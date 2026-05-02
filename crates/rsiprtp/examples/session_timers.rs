//! Session timers / PRACK / UPDATE choreography (RFC 4028 / 3262 / 3311).
//!
//! Phase 4 added six new app-side hooks on `CallManager` for a complete
//! session-timer + PRACK + UPDATE flow:
//!
//! - `invite_offer_headers()` — what to attach to the outbound INVITE
//!   (`Supported: timer, 100rel`, `Session-Expires`, `Min-SE`,
//!   `Allow: ..., PRACK, UPDATE`).
//! - `handle_provisional_response(call_id, response, sdp, local_contact)` —
//!   populates the early-dialog routing fields (Record-Route reversal,
//!   remote target, local Contact). Required so PRACK / outbound UPDATE
//!   built before the 200 OK arrive at proxies with the right Route
//!   headers.
//! - `handle_provisional_reliable(call_id, response)` — emits a PRACK
//!   for a reliable 1xx (RFC 3262), queued via `drain_outbound_requests`.
//! - `handle_invite_success(call_id, dialog, sdp, response, now)` —
//!   establishes the call, populates the UAC dialog from the 200 OK
//!   (Record-Route + Contact), and applies session-timer state from the
//!   response's `Session-Expires` so `refresh_at` / `expiry_at` are
//!   set up for `tick`.
//! - `tick(now)` — fires UPDATE refreshes (or re-INVITE when the peer
//!   doesn't support UPDATE) when `refresh_at <= now`, and BYEs the
//!   call when `expiry_at <= now` and the peer is the refresher. Pump
//!   from the app event loop on every wake.
//! - `next_deadline()` — soonest `refresh_at` / `expiry_at` across all
//!   `Established` calls. Pass to `tokio::time::sleep_until` to avoid
//!   spinning on `tick`.
//! - `mark_in_dialog_2xx(call_id, method, now)` — call after a 2xx
//!   response to an UPDATE / re-INVITE to slide both deadlines.
//! - `note_update_unsupported(call_id)` — call on 405 / 501 to UPDATE
//!   so subsequent refreshes use re-INVITE.
//! - `drain_outbound_requests()` — pull queued PRACK / UPDATE / BYE the
//!   manager built; the app dispatches each via the appropriate
//!   transaction (NonInvite for PRACK / UPDATE / BYE, InviteClient for
//!   the re-INVITE refresh).
//!
//! This example is a documented sketch — running it end-to-end would
//! need a real SIP peer. The `tokio::select!` loop near
//! `outbound_call_choreography` shows the canonical pump shape.
//!
//! Run with:
//!
//! ```bash
//! cargo build -p rsiprtp --example session_timers
//! ```

use std::time::{Duration, Instant};

use rsiprtp::dialog::DialogId;
use rsiprtp::sdp::parser::SessionDescription;
use rsiprtp::session::{
    CallId, CallManager, Dialog, ManagerConfig, OutboundRequest, OutboundRequestKind,
};
use rsiprtp::sip::{Method, SipMessage, SipRequest, SipResponse};

/// Construct a `CallManager` configured for a 1800-second session
/// expiry with the default 90-second `Min-SE`. The Phase 4 surface is
/// always-on once `session_expires > 0`.
fn build_manager() -> CallManager {
    let mut config = ManagerConfig::default();
    config.call_config.session_expires = Duration::from_secs(1800);
    config.call_config.min_se = Duration::from_secs(90);
    CallManager::new(config)
}

/// Outbound-call choreography sketch. Not runnable end-to-end — the
/// transport, transaction-manager, and dialog construction are stubs
/// here so the example focuses on the manager's session-timer hooks.
///
/// In a real app:
/// - `transport.recv()` is the SIP socket's `recv_from`.
/// - `tx_mgr` is your `TransactionManager`; you create a client INVITE
///   transaction with the bytes from `build_outbound_invite`.
/// - `dispatch_outbound_request` opens the matching transaction
///   (NonInvite for PRACK / UPDATE / BYE; InviteClient for the
///   re-INVITE refresh) and threads the eventual 2xx back via
///   `mark_in_dialog_2xx` (or `note_update_unsupported` on 405 / 501).
#[allow(dead_code)]
async fn outbound_call_choreography(
    manager: &mut CallManager,
    call_id: &CallId,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Outbound INVITE: pull the headers the manager wants attached.
    let offer_headers = manager.invite_offer_headers();
    println!(
        "[A] outbound INVITE attaches Supported: {:?}, Allow: {:?}",
        offer_headers.supported_tags,
        offer_headers
            .allow_methods
            .iter()
            .map(|m| m.to_string())
            .collect::<Vec<_>>()
    );
    if let Some((secs, refresher)) = offer_headers.session_expires {
        println!(
            "[A] Session-Expires: {};refresher={:?}, Min-SE: {}",
            secs,
            refresher,
            offer_headers.min_se.unwrap()
        );
    }

    // 2-3. The app event loop. The block below is the canonical pump.
    // It is gated by `if false` so it never executes (no transport,
    // tx-manager, or dialog wired up here) but `rustc` still type-checks
    // it — the reader can copy-paste the body knowing the API surface
    // is real. See `examples/ice_call.rs` and `examples/basic_call.rs`
    // for fully-wired loops.
    if false {
        // Stand-in helpers so the loop type-checks without actually
        // hooking up a transport or transaction manager.
        async fn recv_msg() -> Result<SipMessage, Box<dyn std::error::Error>> {
            unreachable!("documentation-only stub")
        }
        async fn send_to_peer(
            _bytes: bytes::Bytes,
        ) -> Result<(), Box<dyn std::error::Error>> {
            unreachable!("documentation-only stub")
        }
        async fn dispatch_outbound(
            _outbound: OutboundRequest,
        ) -> Result<(), Box<dyn std::error::Error>> {
            unreachable!("documentation-only stub")
        }
        let dialog: Dialog = build_dialog_for_doc();
        let dialog_id: DialogId = DialogId::new(
            "doc-call".to_string(),
            "alice-tag".to_string(),
            "bob-tag".to_string(),
        );
        let answer_sdp: SessionDescription = SessionDescription::parse(
            "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n\
             m=audio 0 RTP/AVP 0\r\n",
        )?;
        let local_contact = "sip:me@host:port";

        let far_future = Instant::now() + Duration::from_secs(86_400);
        loop {
            let next = manager.next_deadline().unwrap_or(far_future);
            tokio::select! {
                msg = recv_msg() => {
                    match msg? {
                        SipMessage::Response(resp) if resp.is_provisional() => {
                            // 18x with Require: 100rel + RSeq -> PRACK.
                            if resp
                                .require()
                                .map(|r| r.0.iter().any(|t| t == "100rel"))
                                .unwrap_or(false)
                            {
                                manager.handle_provisional_response(
                                    call_id, &resp, None, local_contact,
                                );
                                let _ = manager.handle_provisional_reliable(call_id, &resp);
                            }
                        }
                        SipMessage::Response(resp) if resp.status_code() == 200 => {
                            // 200 OK to INVITE establishes the call and
                            // applies session-timer state.
                            manager.handle_invite_success(
                                call_id,
                                dialog.clone(),
                                &answer_sdp,
                                Some(&resp),
                                Instant::now(),
                            );
                        }
                        SipMessage::Response(resp) if resp.status_code() == 422 => {
                            // Outbound 422 — fail the call. No retry loop
                            // (HLD scope decision).
                            manager.handle_invite_failure(call_id, 422);
                        }
                        SipMessage::Request(req) if req.method() == Method::Update => {
                            // Inbound peer refresh.
                            if let Some(resp) = manager.handle_inbound_update(
                                &dialog_id, &req, Instant::now(),
                            ) {
                                send_to_peer(resp.to_bytes()).await?;
                            }
                        }
                        _ => { /* ... regular handling ... */ }
                    }
                }
                _ = tokio::time::sleep_until(next.into()) => {}
            }

            // Pump the manager every wake.
            manager.tick(Instant::now());
            for outbound in manager.drain_outbound_requests() {
                dispatch_outbound(outbound).await?;
            }
        }
    }

    Ok(())
}

/// Dispatch an outbound request the manager built. Skeleton: in a real
/// app each branch opens the right transaction kind on your
/// `TransactionManager`. The 2xx that comes back is then threaded into
/// the manager via `mark_in_dialog_2xx` (UPDATE / re-INVITE) — or
/// `note_update_unsupported` on 405 / 501 to UPDATE so subsequent
/// refreshes use re-INVITE.
#[allow(dead_code)]
fn dispatch_outbound_request(_outbound: OutboundRequest) {
    // Match on `kind` to pick the transaction type:
    // - Prack -> NonInviteClientTransaction(prack_request)
    // - SessionTimerUpdate -> NonInviteClientTransaction(update_request)
    //   * On 405/501 final response: manager.note_update_unsupported(call_id)
    //   * On 200 OK: manager.mark_in_dialog_2xx(call_id, Method::Update, now)
    // - SessionTimerReInvite -> InviteClientTransaction(reinvite_request)
    //   * On 200 OK: manager.mark_in_dialog_2xx(call_id, Method::Invite, now)
    // - SessionTimerExpiryBye -> NonInviteClientTransaction(bye_request)
    //   * On 200 OK: call is already Terminating; remove it.
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== rsiprtp session-timers / PRACK / UPDATE choreography ===");

    let mut manager = build_manager();
    println!("manager configured: session_expires=1800s, min_se=90s");

    // Outbound INVITE: pull the offer headers the manager wants.
    let _offer_headers = manager.invite_offer_headers();

    // For the example we create an outbound call and walk through the
    // hooks without driving them via a real SIP transport — each call
    // demonstrates the API shape so a reader can see what to wire up.
    let call_id = manager.create_call("sip:bob@carrier.example.com".to_string());
    println!("[A] created outbound call {}", call_id);

    // After the application sends INVITE and a 18x with Require: 100rel
    // arrives, it would call:
    //
    //     manager.handle_provisional_response(&call_id, &resp_180, None,
    //         "sip:alice@10.0.0.1:5060");
    //     let prack = manager.handle_provisional_reliable(&call_id, &resp_180)
    //         .expect("PRACK built");
    //     // dispatch `prack` via NonInviteClientTransaction
    //
    // Then on the 200 OK to INVITE:
    //
    //     manager.handle_invite_success(&call_id, dialog, &answer_sdp,
    //         Some(&resp_200), Instant::now());
    //     // session-timer deadlines are now set on the call
    //
    // The app's event loop pumps `tick` and `drain_outbound_requests`
    // on every wake (see `outbound_call_choreography` for the shape):
    //
    //     manager.tick(Instant::now());
    //     for outbound in manager.drain_outbound_requests() {
    //         dispatch_outbound_request(outbound);
    //     }
    //
    // On UPDATE 200 OK arriving back: `mark_in_dialog_2xx`. On 405 /
    // 501 to UPDATE: `note_update_unsupported`. On 422 to INVITE:
    // `handle_invite_failure(call_id, 422)`.

    println!(
        "[A] next_deadline (no Established calls yet) = {:?}",
        manager.next_deadline()
    );

    // Demonstrate the choreography wrapper compiles-clean.
    let _ = outbound_call_choreography(&mut manager, &call_id).await;

    // Demonstrate dispatch shape with a fabricated outbound request
    // for documentation purposes.
    let example_request: SipRequest = SipRequest::builder()
        .method(Method::Update)
        .uri("sip:bob@carrier.example.com")
        .via("10.0.0.1", 5060, "UDP", "z9hG4bKexample")
        .from("sip:alice@example.com", "alice-tag")
        .to("sip:bob@carrier.example.com")
        .to_tag("bob-tag")
        .call_id("st-example@example.com")
        .cseq(2)
        .build()?;
    let example = OutboundRequest {
        call_id: call_id.clone(),
        request: example_request,
        kind: OutboundRequestKind::SessionTimerUpdate,
    };
    println!(
        "[A] example outbound request: kind={:?}, method={}",
        example.kind,
        example.request.method()
    );
    dispatch_outbound_request(example);

    // Inbound INVITE side: evaluate session-timer headers before
    // accepting. If `Session-Expires` is below `Min-SE`, return 422.
    println!(
        "\n[B] inbound side: evaluate_inbound_invite_session_timer + accept_session_timer + populate_uas_dialog_routing"
    );
    println!("    handle_inbound_update returns the 200 OK to send for peer-driven refresh");

    // The doc-only helpers `build_dialog_for_doc` and
    // `build_response_for_doc` are intentionally not invoked here; they
    // anchor shapes a reader might copy. They carry `#[allow(dead_code)]`
    // to suppress unused-warning noise.

    Ok(())
}

// Documentation-only helpers (kept to anchor the dialog / response
// shapes a reader might copy). Not invoked at runtime.

#[allow(dead_code)]
fn build_dialog_for_doc() -> Dialog {
    Dialog::new_uac(
        "doc-call".to_string(),
        "alice-tag".to_string(),
        "bob-tag".to_string(),
        "sip:alice@example.com".to_string(),
        "sip:bob@example.com".to_string(),
        1,
    )
}

#[allow(dead_code)]
fn build_response_for_doc() -> Option<SipResponse> {
    let req: SipRequest = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("10.0.0.1", 5060, "UDP", "z9hG4bKdoc")
        .from("sip:alice@example.com", "alice-tag")
        .to("sip:bob@example.com")
        .call_id("doc")
        .cseq(1)
        .build()
        .ok()?;
    SipResponse::builder()
        .status(200, "OK")
        .from_request(&req)
        .to_tag("bob-tag")
        .session_expires(1800, Some(rsiprtp::sip::Refresher::Uac))
        .build()
        .ok()
}

// Suppress unused-import warnings for headers used only in doc comments.
#[allow(dead_code)]
fn _doc_anchors(sdp: &SessionDescription) -> usize {
    sdp.media.len()
}

//! Advanced SIP Protocol Integration Tests
//!
//! Tests advanced SIP features including CANCEL, re-INVITE, UPDATE,
//! authentication, and complex call scenarios.

use rsiprtp::sip::{Method, SipRequest, SipResponse};
use rsiprtp::transaction::client::invite::{
    Action as InviteClientAction, State as InviteClientState,
};
use rsiprtp::transaction::client::non_invite::State as NonInviteClientState;
use rsiprtp::transaction::server::invite::State as InviteServerState;
use rsiprtp::transaction::{
    InviteClientTransaction, InviteServerTransaction, NonInviteClientTransaction,
    NonInviteServerTransaction,
};

// Helper functions
fn create_invite() -> SipRequest {
    SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest123")
        .from("sip:alice@example.com", "fromtag123")
        .to("sip:bob@example.com")
        .call_id("call123@example.com")
        .cseq(1)
        .build()
        .unwrap()
}

fn create_cancel(_invite: &SipRequest) -> SipRequest {
    SipRequest::builder()
        .method(Method::Cancel)
        .uri("sip:bob@example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest123") // Same branch as INVITE
        .from("sip:alice@example.com", "fromtag123")
        .to("sip:bob@example.com")
        .call_id("call123@example.com")
        .cseq(1) // Same CSeq as INVITE
        .build()
        .unwrap()
}

fn create_ack(_invite: &SipRequest, _response: &SipResponse) -> SipRequest {
    SipRequest::builder()
        .method(Method::Ack)
        .uri("sip:bob@example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest123")
        .from("sip:alice@example.com", "fromtag123")
        .to("sip:bob@example.com")
        .to_tag("totag123")
        .call_id("call123@example.com")
        .cseq(1)
        .build()
        .unwrap()
}

fn create_bye() -> SipRequest {
    SipRequest::builder()
        .method(Method::Bye)
        .uri("sip:bob@example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKbye123")
        .from("sip:alice@example.com", "fromtag123")
        .to("sip:bob@example.com")
        .to_tag("totag123")
        .call_id("call123@example.com")
        .cseq(2) // Incremented CSeq
        .build()
        .unwrap()
}

fn create_register() -> SipRequest {
    SipRequest::builder()
        .method(Method::Register)
        .uri("sip:registrar.example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKreg123")
        .from("sip:alice@example.com", "fromtag789")
        .to("sip:alice@example.com")
        .call_id("register@example.com")
        .cseq(1)
        .build()
        .unwrap()
}

fn create_response(request: &SipRequest, code: u16, reason: &str) -> SipResponse {
    SipResponse::builder()
        .status(code, reason)
        .from_request(request)
        .to_tag("totag123")
        .build()
        .unwrap()
}

//
// Call Cancellation Tests
//

/// Test: CANCEL before any provisional response
#[test]
fn test_cancel_before_provisional() {
    let invite = create_invite();
    let mut invite_tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
    invite_tx.poll_actions(); // Clear initial actions

    // Client sends CANCEL before receiving any response
    let cancel = create_cancel(&invite);
    let mut cancel_tx = NonInviteClientTransaction::new(cancel.clone(), false).unwrap();

    // CANCEL transaction should complete normally
    let cancel_ok = create_response(&cancel, 200, "OK");
    cancel_tx.handle_response(cancel_ok);
    assert!(matches!(cancel_tx.state(), NonInviteClientState::Completed));

    // INVITE transaction should eventually receive 487 Request Terminated
    let terminated = create_response(&invite, 487, "Request Terminated");
    invite_tx.handle_response(terminated);
    assert!(matches!(invite_tx.state(), InviteClientState::Completed));
}

/// Test: CANCEL after 180 Ringing
#[test]
fn test_cancel_after_ringing() {
    let invite = create_invite();
    let mut invite_tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
    invite_tx.poll_actions(); // Clear initial actions

    // Receive 180 Ringing
    let ringing = create_response(&invite, 180, "Ringing");
    invite_tx.handle_response(ringing);
    assert!(matches!(invite_tx.state(), InviteClientState::Proceeding));

    // Send CANCEL
    let cancel = create_cancel(&invite);
    let mut cancel_tx = NonInviteClientTransaction::new(cancel.clone(), false).unwrap();

    // CANCEL gets 200 OK
    let cancel_ok = create_response(&cancel, 200, "OK");
    cancel_tx.handle_response(cancel_ok);
    assert!(matches!(cancel_tx.state(), NonInviteClientState::Completed));

    // INVITE gets 487 Request Terminated
    let terminated = create_response(&invite, 487, "Request Terminated");
    invite_tx.handle_response(terminated);
    assert!(matches!(invite_tx.state(), InviteClientState::Completed));

    // ACK the error response
    let actions = invite_tx.poll_actions();
    assert!(actions
        .iter()
        .any(|a| matches!(a, InviteClientAction::Send(_))));
}

/// Test: CANCEL race - 200 OK arrives before CANCEL
#[test]
fn test_cancel_race_with_200ok() {
    let invite = create_invite();
    let mut invite_tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
    invite_tx.poll_actions(); // Clear initial actions

    // Receive 180 Ringing
    let ringing = create_response(&invite, 180, "Ringing");
    invite_tx.handle_response(ringing);
    assert!(matches!(invite_tx.state(), InviteClientState::Proceeding));

    // 200 OK arrives before CANCEL is processed
    let ok = create_response(&invite, 200, "OK");
    invite_tx.handle_response(ok);
    assert!(invite_tx.is_terminated());

    // CANCEL arrives at server after 200 OK was sent
    // CANCEL transaction gets 481 Call/Transaction Does Not Exist
    let cancel = create_cancel(&invite);
    let mut cancel_tx = NonInviteClientTransaction::new(cancel.clone(), false).unwrap();
    let cancel_error = create_response(&cancel, 481, "Call/Transaction Does Not Exist");
    cancel_tx.handle_response(cancel_error);
    assert!(matches!(cancel_tx.state(), NonInviteClientState::Completed));
}

/// Test: Server receives CANCEL
#[test]
fn test_server_receives_cancel() {
    let invite = create_invite();
    let mut invite_tx = InviteServerTransaction::new(invite.clone(), false).unwrap();

    // Send provisional response
    let trying = create_response(&invite, 100, "Trying");
    invite_tx.send_response(trying);
    assert!(matches!(invite_tx.state(), InviteServerState::Proceeding));

    // Receive CANCEL
    let cancel = create_cancel(&invite);
    let mut cancel_tx = NonInviteServerTransaction::new(cancel.clone(), false).unwrap();

    // CANCEL should get 200 OK immediately
    let cancel_ok = create_response(&cancel, 200, "OK");
    cancel_tx.send_response(cancel_ok);
    assert!(matches!(
        cancel_tx.state(),
        rsiprtp::transaction::server::non_invite::State::Completed
    ));

    // INVITE should get 487 Request Terminated
    let terminated = create_response(&invite, 487, "Request Terminated");
    invite_tx.send_response(terminated);
    assert!(matches!(invite_tx.state(), InviteServerState::Completed));
}

//
// Re-INVITE Tests (Session Modification)
//

/// Test: Re-INVITE within established dialog
#[test]
fn test_reinvite_session_modification() {
    // Initial INVITE
    let invite = create_invite();
    let mut tx1 = InviteClientTransaction::new(invite.clone(), false).unwrap();
    tx1.poll_actions();

    let ok = create_response(&invite, 200, "OK");
    tx1.handle_response(ok);
    assert!(tx1.is_terminated());

    // Re-INVITE with incremented CSeq
    let reinvite = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKreinv")
        .from("sip:alice@example.com", "fromtag123")
        .to("sip:bob@example.com")
        .to_tag("totag123")
        .call_id("call123@example.com")
        .cseq(2) // Incremented
        .build()
        .unwrap();

    let mut tx2 = InviteClientTransaction::new(reinvite.clone(), false).unwrap();
    tx2.poll_actions();

    // Re-INVITE gets 200 OK
    let reinv_ok = create_response(&reinvite, 200, "OK");
    tx2.handle_response(reinv_ok);
    assert!(tx2.is_terminated());
}

/// Test: Re-INVITE rejected with 491 Request Pending
#[test]
fn test_reinvite_rejected_491() {
    let reinvite = SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKreinv")
        .from("sip:alice@example.com", "fromtag123")
        .to("sip:bob@example.com")
        .to_tag("totag123")
        .call_id("call123@example.com")
        .cseq(2)
        .build()
        .unwrap();

    let mut tx = InviteClientTransaction::new(reinvite.clone(), false).unwrap();
    tx.poll_actions();

    // Collision: server is also sending re-INVITE
    let pending = create_response(&reinvite, 491, "Request Pending");
    tx.handle_response(pending);
    assert!(matches!(tx.state(), InviteClientState::Completed));

    // ACK the error
    let actions = tx.poll_actions();
    assert!(actions
        .iter()
        .any(|a| matches!(a, InviteClientAction::Send(_))));
}

//
// BYE Tests (Call Termination)
//

/// Test: Normal BYE flow
#[test]
fn test_bye_normal_flow() {
    let bye = create_bye();
    let mut tx = NonInviteClientTransaction::new(bye.clone(), false).unwrap();
    tx.poll_actions();

    // BYE gets 200 OK
    let ok = create_response(&bye, 200, "OK");
    tx.handle_response(ok);
    assert!(matches!(tx.state(), NonInviteClientState::Completed));
}

/// Test: BYE with 481 Call/Transaction Does Not Exist
#[test]
fn test_bye_481_not_exists() {
    let bye = create_bye();
    let mut tx = NonInviteClientTransaction::new(bye.clone(), false).unwrap();
    tx.poll_actions();

    // BYE gets 481 (dialog doesn't exist on server)
    let not_exist = create_response(&bye, 481, "Call/Transaction Does Not Exist");
    tx.handle_response(not_exist);
    assert!(matches!(tx.state(), NonInviteClientState::Completed));
}

/// Test: Server receives BYE
#[test]
fn test_server_receives_bye() {
    let bye = create_bye();
    let mut tx = NonInviteServerTransaction::new(bye.clone(), false).unwrap();

    // Send 200 OK
    let ok = create_response(&bye, 200, "OK");
    tx.send_response(ok);
    assert!(matches!(
        tx.state(),
        rsiprtp::transaction::server::non_invite::State::Completed
    ));
}

//
// REGISTER Tests
//

/// Test: Successful REGISTER
#[test]
fn test_register_success() {
    let register = create_register();
    let mut tx = NonInviteClientTransaction::new(register.clone(), false).unwrap();
    tx.poll_actions();

    // REGISTER gets 200 OK
    let ok = create_response(&register, 200, "OK");
    tx.handle_response(ok);
    assert!(matches!(tx.state(), NonInviteClientState::Completed));
}

/// Test: REGISTER with 401 Unauthorized (authentication required)
#[test]
fn test_register_401_auth_required() {
    let register = create_register();
    let mut tx = NonInviteClientTransaction::new(register.clone(), false).unwrap();
    tx.poll_actions();

    // REGISTER gets 401 Unauthorized
    let unauth = create_response(&register, 401, "Unauthorized");
    tx.handle_response(unauth);
    assert!(matches!(tx.state(), NonInviteClientState::Completed));

    // Client should retry with credentials (new transaction)
    let register2 = SipRequest::builder()
        .method(Method::Register)
        .uri("sip:registrar.example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKreg456")
        .from("sip:alice@example.com", "fromtag789")
        .to("sip:alice@example.com")
        .call_id("register@example.com")
        .cseq(2) // Incremented CSeq
        // Would add Authorization header here
        .build()
        .unwrap();

    let mut tx2 = NonInviteClientTransaction::new(register2.clone(), false).unwrap();
    tx2.poll_actions();

    // Second attempt succeeds
    let ok = create_response(&register2, 200, "OK");
    tx2.handle_response(ok);
    assert!(matches!(tx2.state(), NonInviteClientState::Completed));
}

/// Test: REGISTER with 423 Interval Too Brief
#[test]
fn test_register_423_interval_too_brief() {
    let register = create_register();
    let mut tx = NonInviteClientTransaction::new(register.clone(), false).unwrap();
    tx.poll_actions();

    // REGISTER gets 423 Interval Too Brief
    let too_brief = create_response(&register, 423, "Interval Too Brief");
    tx.handle_response(too_brief);
    assert!(matches!(tx.state(), NonInviteClientState::Completed));
}

/// Test: Un-REGISTER (Expires: 0)
#[test]
fn test_unregister() {
    let unregister = SipRequest::builder()
        .method(Method::Register)
        .uri("sip:registrar.example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKunreg")
        .from("sip:alice@example.com", "fromtag789")
        .to("sip:alice@example.com")
        .call_id("register@example.com")
        .cseq(10)
        // Would add Contact: * and Expires: 0 here
        .build()
        .unwrap();

    let mut tx = NonInviteClientTransaction::new(unregister.clone(), false).unwrap();
    tx.poll_actions();

    // Un-REGISTER succeeds
    let ok = create_response(&unregister, 200, "OK");
    tx.handle_response(ok);
    assert!(matches!(tx.state(), NonInviteClientState::Completed));
}

//
// OPTIONS Tests
//

/// Test: OPTIONS keep-alive ping
#[test]
fn test_options_keepalive() {
    let options = SipRequest::builder()
        .method(Method::Options)
        .uri("sip:server.example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKopt")
        .from("sip:alice@example.com", "fromtagopt")
        .to("sip:server.example.com")
        .call_id("options@example.com")
        .cseq(1)
        .build()
        .unwrap();

    let mut tx = NonInviteClientTransaction::new(options.clone(), false).unwrap();
    tx.poll_actions();

    // OPTIONS gets 200 OK
    let ok = create_response(&options, 200, "OK");
    tx.handle_response(ok);
    assert!(matches!(tx.state(), NonInviteClientState::Completed));
}

/// Test: OPTIONS for capability discovery
#[test]
fn test_options_capabilities() {
    let options = SipRequest::builder()
        .method(Method::Options)
        .uri("sip:bob@example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKcap")
        .from("sip:alice@example.com", "fromtagcap")
        .to("sip:bob@example.com")
        .call_id("capabilities@example.com")
        .cseq(1)
        .build()
        .unwrap();

    let mut tx = NonInviteClientTransaction::new(options.clone(), false).unwrap();
    tx.poll_actions();

    // OPTIONS gets 200 OK with Allow, Accept, Supported headers
    let ok = create_response(&options, 200, "OK");
    tx.handle_response(ok);
    assert!(matches!(tx.state(), NonInviteClientState::Completed));
}

//
// ACK Tests
//

/// Test: ACK for 2xx response (separate transaction)
#[test]
fn test_ack_for_2xx() {
    let invite = create_invite();
    let ok = create_response(&invite, 200, "OK");
    let ack = create_ack(&invite, &ok);

    // ACK for 2xx is not part of INVITE transaction
    // It's sent directly to transport layer
    // This test just validates ACK construction
    assert_eq!(ack.method(), Method::Ack);
    assert_eq!(ack.cseq_method().unwrap(), Method::Ack);
}

/// Test: ACK for error response (part of INVITE transaction)
#[test]
fn test_ack_for_error() {
    let invite = create_invite();
    let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
    tx.poll_actions();

    // Receive error response
    let busy = create_response(&invite, 486, "Busy Here");
    tx.handle_response(busy);
    assert!(matches!(tx.state(), InviteClientState::Completed));

    // Transaction should automatically generate ACK
    let actions = tx.poll_actions();
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::Send(_))),
        "Should automatically send ACK for error response"
    );
}

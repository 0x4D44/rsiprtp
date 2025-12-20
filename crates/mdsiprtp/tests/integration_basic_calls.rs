//! Basic SIP Call Flow Integration Tests
//!
//! Tests complete SIP dialog flows and integration between transaction, dialog,
//! and transport layers using the transaction state machines.

use mdsiprtp::sip::{Method, SipRequest, SipResponse};
use mdsiprtp::transaction::client::invite::{
    Action as InviteClientAction, State as InviteClientState,
};
use mdsiprtp::transaction::client::non_invite::State as NonInviteClientState;
use mdsiprtp::transaction::server::invite::State as InviteServerState;
use mdsiprtp::transaction::server::non_invite::State as NonInviteServerState;
use mdsiprtp::transaction::{
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

fn create_options() -> SipRequest {
    SipRequest::builder()
        .method(Method::Options)
        .uri("sip:bob@example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKoptions")
        .from("sip:alice@example.com", "fromtag456")
        .to("sip:bob@example.com")
        .call_id("options@example.com")
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

/// Test: Complete INVITE transaction flow (Calling → Proceeding → Terminated)
#[test]
fn test_invite_client_transaction_complete_flow() {
    let invite = create_invite();
    let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();

    // Initial state should be Calling
    assert!(matches!(tx.state(), InviteClientState::Calling));
    tx.poll_actions();

    // Simulate receiving 180 Ringing
    let ringing = create_response(&invite, 180, "Ringing");
    tx.handle_response(ringing);

    // Should now be in Proceeding state
    assert!(matches!(tx.state(), InviteClientState::Proceeding));

    // Simulate receiving 200 OK
    let ok = create_response(&invite, 200, "OK");
    tx.handle_response(ok);

    // Should be terminated (200 OK terminates INVITE client transaction)
    assert!(tx.is_terminated());
}

/// Test: Call rejection with 486 Busy Here
#[test]
fn test_invite_rejection_486_busy() {
    let invite = create_invite();
    let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
    tx.poll_actions();

    // Receive 486 Busy Here
    let busy = create_response(&invite, 486, "Busy Here");
    tx.handle_response(busy);

    // Should transition to Completed
    assert!(matches!(tx.state(), InviteClientState::Completed));

    // Poll for ACK generation
    let actions = tx.poll_actions();
    let has_send_ack = actions
        .iter()
        .any(|a| matches!(a, InviteClientAction::Send(_)));
    assert!(
        has_send_ack,
        "Transaction should generate ACK for error response"
    );
}

/// Test: Call rejection with 404 Not Found
#[test]
fn test_invite_rejection_404_not_found() {
    let invite = create_invite();
    let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
    tx.poll_actions();

    let not_found = create_response(&invite, 404, "Not Found");
    tx.handle_response(not_found);
    assert!(matches!(tx.state(), InviteClientState::Completed));
}

/// Test: Call rejection with 503 Service Unavailable
#[test]
fn test_invite_rejection_503_service_unavailable() {
    let invite = create_invite();
    let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
    tx.poll_actions();

    let unavailable = create_response(&invite, 503, "Service Unavailable");
    tx.handle_response(unavailable);
    assert!(matches!(tx.state(), InviteClientState::Completed));
}

/// Test: INVITE server transaction receiving request
#[test]
fn test_invite_server_transaction_receives_invite() {
    let invite = create_invite();
    let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();

    // Initial state should be Proceeding
    assert!(matches!(tx.state(), InviteServerState::Proceeding));

    // Send 180 Ringing
    let ringing = create_response(&invite, 180, "Ringing");
    tx.send_response(ringing);

    // Still in Proceeding after provisional response
    assert!(matches!(tx.state(), InviteServerState::Proceeding));

    // Send 200 OK
    let ok = create_response(&invite, 200, "OK");
    tx.send_response(ok);

    // Should be terminated (200 OK terminates server transaction)
    assert!(tx.is_terminated());
}

/// Test: INVITE server transaction sends error response
#[test]
fn test_invite_server_sends_error_response() {
    let invite = create_invite();
    let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();

    // Send 486 Busy Here
    let busy = create_response(&invite, 486, "Busy Here");
    tx.send_response(busy);

    // Should transition to Completed
    assert!(matches!(tx.state(), InviteServerState::Completed));

    // Simulate receiving ACK
    let ack = SipRequest::builder()
        .method(Method::Ack)
        .uri("sip:bob@example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest123")
        .from("sip:alice@example.com", "fromtag123")
        .to("sip:bob@example.com")
        .to_tag("totag123")
        .call_id("call123@example.com")
        .cseq(1)
        .build()
        .unwrap();

    tx.handle_request(ack);

    // Should transition to Confirmed
    assert!(matches!(tx.state(), InviteServerState::Confirmed));
}

/// Test: Non-INVITE client transaction (OPTIONS request)
#[test]
fn test_non_invite_options_request() {
    let options = create_options();
    let mut tx = NonInviteClientTransaction::new(options.clone(), false).unwrap();

    // Initial state should be Trying
    assert!(matches!(tx.state(), NonInviteClientState::Trying));
    tx.poll_actions();

    // Simulate receiving 200 OK
    let ok = create_response(&options, 200, "OK");
    tx.handle_response(ok);

    // Should be in Completed state
    assert!(matches!(tx.state(), NonInviteClientState::Completed));
}

/// Test: Non-INVITE server transaction (OPTIONS)
#[test]
fn test_non_invite_server_options() {
    let options = create_options();
    let mut tx = NonInviteServerTransaction::new(options.clone(), false).unwrap();

    // Initial state should be Trying
    assert!(matches!(tx.state(), NonInviteServerState::Trying));

    // Send 200 OK
    let ok = create_response(&options, 200, "OK");
    tx.send_response(ok);

    // Should be in Completed state
    assert!(matches!(tx.state(), NonInviteServerState::Completed));
}

/// Test: Multiple provisional responses (100, 180, 183)
#[test]
fn test_multiple_provisional_responses() {
    let invite = create_invite();
    let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
    tx.poll_actions();

    // First provisional response: 100 Trying
    let trying = create_response(&invite, 100, "Trying");
    tx.handle_response(trying);
    assert!(matches!(tx.state(), InviteClientState::Proceeding));

    // Second provisional response: 180 Ringing
    let ringing = create_response(&invite, 180, "Ringing");
    tx.handle_response(ringing);
    assert!(matches!(tx.state(), InviteClientState::Proceeding));

    // Third provisional response: 183 Session Progress
    let progress = create_response(&invite, 183, "Session Progress");
    tx.handle_response(progress);
    // Still in Proceeding
    assert!(matches!(tx.state(), InviteClientState::Proceeding));

    // Final response
    let ok = create_response(&invite, 200, "OK");
    tx.handle_response(ok);
    assert!(tx.is_terminated());
}

/// Test: Transaction layer handles retransmitted responses
#[test]
fn test_retransmitted_response_handling() {
    let invite = create_invite();
    let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
    tx.poll_actions();

    let ringing = create_response(&invite, 180, "Ringing");

    // Receive 180 Ringing once
    tx.handle_response(ringing.clone());
    assert!(matches!(tx.state(), InviteClientState::Proceeding));

    // Receive same 180 Ringing again (retransmission)
    tx.handle_response(ringing);

    // Should still be in Proceeding (retransmission absorbed)
    assert!(matches!(tx.state(), InviteClientState::Proceeding));
}

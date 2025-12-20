//! Network Failure and Transaction Recovery Integration Tests
//!
//! Tests transaction resilience under various failure scenarios including
//! network packet loss, retransmissions, timeouts, and recovery.

use mdsiprtp::sip::{Method, SipRequest, SipResponse};
use mdsiprtp::transaction::client::invite::{
    Action as InviteClientAction, State as InviteClientState,
};
use mdsiprtp::transaction::client::non_invite::State as NonInviteClientState;
use mdsiprtp::transaction::server::invite::State as InviteServerState;
use mdsiprtp::transaction::server::non_invite::State as NonInviteServerState;
use mdsiprtp::transaction::timer::Timer;
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

//
// Network Failure Tests
//

/// Test: INVITE client transaction handles lost initial INVITE (Timer A retransmission)
#[test]
fn test_network_failure_lost_invite() {
    let invite = create_invite();
    let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();

    // Initial state: Calling
    assert!(matches!(tx.state(), InviteClientState::Calling));

    // Initial transmission
    let actions = tx.poll_actions();
    assert!(actions
        .iter()
        .any(|a| matches!(a, InviteClientAction::Send(_))));
    assert!(actions
        .iter()
        .any(|a| matches!(a, InviteClientAction::SetTimer(Timer::A, _))));

    // Simulate Timer A firing (lost packet, need retransmission)
    tx.handle_timeout(Timer::A);
    let actions = tx.poll_actions();

    // Should retransmit and reset Timer A
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::Send(_))),
        "Should retransmit INVITE on Timer A"
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::SetTimer(Timer::A, _))),
        "Should reset Timer A"
    );

    // Still in Calling state
    assert!(matches!(tx.state(), InviteClientState::Calling));
}

/// Test: INVITE client transaction handles lost provisional response
#[test]
fn test_network_failure_lost_provisional() {
    let invite = create_invite();
    let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
    tx.poll_actions(); // Clear initial actions

    // Receive 100 Trying (should transition to Proceeding)
    let trying = create_response(&invite, 100, "Trying");
    tx.handle_response(trying);
    assert!(matches!(tx.state(), InviteClientState::Proceeding));

    // In Proceeding state, no retransmissions occur
    // This tests that provisional responses are properly absorbed
    tx.handle_timeout(Timer::A); // Timer A shouldn't fire in Proceeding, but test resilience

    // Should still be in Proceeding
    assert!(matches!(tx.state(), InviteClientState::Proceeding));
}

/// Test: INVITE client transaction handles timeout (Timer B expiry)
#[test]
fn test_network_failure_invite_timeout() {
    let invite = create_invite();
    let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
    tx.poll_actions(); // Clear initial actions

    // Simulate Timer B timeout (no response received)
    tx.handle_timeout(Timer::B);

    // Should transition to Terminated
    assert!(
        tx.is_terminated(),
        "Transaction should terminate on Timer B"
    );

    // Should emit timeout event
    let actions = tx.poll_actions();
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::Event(_))),
        "Should emit timeout event"
    );
}

/// Test: INVITE server handles retransmitted INVITE (simulating packet loss)
#[test]
fn test_network_failure_retransmitted_invite() {
    let invite = create_invite();
    let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();

    // Send provisional response
    let trying = create_response(&invite, 100, "Trying");
    tx.send_response(trying.clone());

    // Receive retransmitted INVITE (client didn't receive our response)
    tx.handle_request(invite.clone());

    // Should retransmit the last response
    let actions = tx.poll_actions();
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, mdsiprtp::transaction::server::invite::Action::Send(_))),
        "Should retransmit response for retransmitted INVITE"
    );

    // Should still be in Proceeding state
    assert!(matches!(tx.state(), InviteServerState::Proceeding));
}

/// Test: INVITE server handles retransmitted INVITE after error response
#[test]
fn test_network_failure_retransmitted_invite_after_error() {
    let invite = create_invite();
    let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();

    // Send error response
    let busy = create_response(&invite, 486, "Busy Here");
    tx.send_response(busy.clone());

    // Should be in Completed state
    assert!(matches!(tx.state(), InviteServerState::Completed));

    // Receive retransmitted INVITE
    tx.handle_request(invite.clone());

    // Should retransmit error response
    let actions = tx.poll_actions();
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, mdsiprtp::transaction::server::invite::Action::Send(_))),
        "Should retransmit error response"
    );
}

/// Test: Non-INVITE client handles lost request (Timer E retransmission)
#[test]
fn test_network_failure_non_invite_lost_request() {
    let options = create_options();
    let mut tx = NonInviteClientTransaction::new(options.clone(), false).unwrap();

    // Initial state: Trying
    assert!(matches!(tx.state(), NonInviteClientState::Trying));

    // Initial transmission
    let actions = tx.poll_actions();
    assert!(actions.iter().any(|a| matches!(
        a,
        mdsiprtp::transaction::client::non_invite::Action::Send(_)
    )));

    // Simulate Timer E firing (lost packet)
    tx.handle_timeout(Timer::E);
    let actions = tx.poll_actions();

    // Should retransmit
    assert!(
        actions.iter().any(|a| matches!(
            a,
            mdsiprtp::transaction::client::non_invite::Action::Send(_)
        )),
        "Should retransmit on Timer E"
    );
}

/// Test: Non-INVITE client handles timeout (Timer F expiry)
#[test]
fn test_network_failure_non_invite_timeout() {
    let options = create_options();
    let mut tx = NonInviteClientTransaction::new(options.clone(), false).unwrap();
    tx.poll_actions(); // Clear initial actions

    // Simulate Timer F timeout
    tx.handle_timeout(Timer::F);

    // Should transition to Terminated
    assert!(
        tx.is_terminated(),
        "Transaction should terminate on Timer F"
    );
}

/// Test: Non-INVITE server handles retransmitted request
#[test]
fn test_network_failure_non_invite_retransmitted_request() {
    let options = create_options();
    let mut tx = NonInviteServerTransaction::new(options.clone(), false).unwrap();

    // Send response
    let ok = create_response(&options, 200, "OK");
    tx.send_response(ok.clone());

    // Should be in Completed state
    assert!(matches!(tx.state(), NonInviteServerState::Completed));

    // Receive retransmitted request
    tx.handle_request(options.clone());

    // Should retransmit response
    let actions = tx.poll_actions();
    assert!(
        actions.iter().any(|a| matches!(
            a,
            mdsiprtp::transaction::server::non_invite::Action::Send(_)
        )),
        "Should retransmit response for retransmitted request"
    );
}

//
// Transaction Recovery Tests
//

/// Test: Recovery from spurious timeout
#[test]
fn test_recovery_spurious_timeout() {
    let invite = create_invite();
    let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
    tx.poll_actions(); // Clear initial actions

    // Receive provisional response
    let trying = create_response(&invite, 100, "Trying");
    tx.handle_response(trying);
    assert!(matches!(tx.state(), InviteClientState::Proceeding));

    // Spurious Timer A timeout (shouldn't happen in Proceeding, but test resilience)
    tx.handle_timeout(Timer::A);

    // Should stay in Proceeding and not break
    assert!(matches!(tx.state(), InviteClientState::Proceeding));

    // Should still be able to receive final response
    let ok = create_response(&invite, 200, "OK");
    tx.handle_response(ok);
    assert!(tx.is_terminated());
}

/// Test: Recovery from out-of-order responses
#[test]
fn test_recovery_out_of_order_responses() {
    let invite = create_invite();
    let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
    tx.poll_actions(); // Clear initial actions

    // Receive 180 Ringing
    let ringing = create_response(&invite, 180, "Ringing");
    tx.handle_response(ringing.clone());
    assert!(matches!(tx.state(), InviteClientState::Proceeding));

    // Receive 100 Trying after 180 (out of order)
    let trying = create_response(&invite, 100, "Trying");
    tx.handle_response(trying);

    // Should stay in Proceeding (ignore earlier provisional)
    assert!(matches!(tx.state(), InviteClientState::Proceeding));

    // Should still be able to complete normally
    let ok = create_response(&invite, 200, "OK");
    tx.handle_response(ok);
    assert!(tx.is_terminated());
}

/// Test: Recovery from duplicate final response
#[test]
fn test_recovery_duplicate_final_response() {
    let options = create_options();
    let mut tx = NonInviteClientTransaction::new(options.clone(), false).unwrap();
    tx.poll_actions(); // Clear initial actions

    // Receive first 200 OK
    let ok = create_response(&options, 200, "OK");
    tx.handle_response(ok.clone());
    assert!(matches!(tx.state(), NonInviteClientState::Completed));

    // Receive duplicate 200 OK (retransmission from server)
    tx.handle_response(ok);

    // Should stay in Completed and absorb duplicate
    assert!(matches!(tx.state(), NonInviteClientState::Completed));
}

/// Test: INVITE server recovers from missing ACK (Timer H timeout)
#[test]
fn test_recovery_missing_ack() {
    let invite = create_invite();
    let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();

    // Send error response
    let busy = create_response(&invite, 486, "Busy Here");
    tx.send_response(busy);
    assert!(matches!(tx.state(), InviteServerState::Completed));

    // Simulate Timer H timeout (ACK never received)
    tx.handle_timeout(Timer::H);

    // Should transition to Terminated
    assert!(
        tx.is_terminated(),
        "Should terminate on Timer H (missing ACK)"
    );
}

/// Test: Transaction layer handles rapid state transitions
#[test]
fn test_recovery_rapid_state_transitions() {
    let invite = create_invite();
    let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
    tx.poll_actions(); // Clear initial actions

    // Rapid sequence of provisional responses
    for code in [100, 180, 181, 182, 183] {
        let response = create_response(&invite, code, "Progress");
        tx.handle_response(response);
        assert!(matches!(tx.state(), InviteClientState::Proceeding));
    }

    // Final response should still work
    let ok = create_response(&invite, 200, "OK");
    tx.handle_response(ok);
    assert!(tx.is_terminated());
}

/// Test: Non-INVITE transaction handles response after retransmission
#[test]
fn test_recovery_response_after_retransmit() {
    let options = create_options();
    let mut tx = NonInviteClientTransaction::new(options.clone(), false).unwrap();
    tx.poll_actions(); // Clear initial actions

    // First Timer E expiry -> retransmit
    tx.handle_timeout(Timer::E);
    let actions = tx.poll_actions();
    assert!(actions.iter().any(|a| matches!(
        a,
        mdsiprtp::transaction::client::non_invite::Action::Send(_)
    )));

    // Second Timer E expiry -> retransmit again
    tx.handle_timeout(Timer::E);
    let actions = tx.poll_actions();
    assert!(actions.iter().any(|a| matches!(
        a,
        mdsiprtp::transaction::client::non_invite::Action::Send(_)
    )));

    // Finally receive response
    let ok = create_response(&options, 200, "OK");
    tx.handle_response(ok);

    // Should complete successfully
    assert!(matches!(tx.state(), NonInviteClientState::Completed));
}

/// Test: Server transaction handles multiple retransmitted requests
#[test]
fn test_recovery_multiple_retransmits() {
    let options = create_options();
    let mut tx = NonInviteServerTransaction::new(options.clone(), false).unwrap();

    // Send response
    let ok = create_response(&options, 200, "OK");
    tx.send_response(ok);
    assert!(matches!(tx.state(), NonInviteServerState::Completed));

    // Receive 5 retransmitted requests (simulating bad network)
    for _ in 0..5 {
        tx.handle_request(options.clone());
        let actions = tx.poll_actions();
        // Each should cause response retransmission
        assert!(actions.iter().any(|a| matches!(
            a,
            mdsiprtp::transaction::server::non_invite::Action::Send(_)
        )));
    }

    // Should still be in Completed state
    assert!(matches!(tx.state(), NonInviteServerState::Completed));
}

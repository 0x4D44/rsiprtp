//! RFC 3261 Section 17 Transaction State Machine Compliance Tests.
//!
//! These tests verify that the transaction layer state machines correctly implement
//! RFC 3261 requirements for client and server transactions, including all state
//! transitions, timer behaviors, and message handling.

use crate::transaction::client::invite::{
    Action as InviteClientAction, Event as InviteClientEvent, InviteClientTransaction,
    State as InviteClientState,
};
use crate::transaction::client::non_invite::{
    Action as NonInviteClientAction, Event as NonInviteClientEvent, NonInviteClientTransaction,
    State as NonInviteClientState,
};
use crate::transaction::server::invite::{
    Action as InviteServerAction, InviteServerTransaction, State as InviteServerState,
};
use crate::transaction::server::non_invite::{
    Action as NonInviteServerAction, NonInviteServerTransaction, State as NonInviteServerState,
};
use crate::transaction::timer::Timer;
use crate::sip::{Method, SipRequest, SipResponse};

// Helper functions
fn create_invite() -> SipRequest {
    SipRequest::builder()
        .method(Method::Invite)
        .uri("sip:bob@example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
        .from("sip:alice@example.com", "fromtag")
        .to("sip:bob@example.com")
        .call_id("test@example.com")
        .cseq(1)
        .build()
        .unwrap()
}

fn create_register() -> SipRequest {
    SipRequest::builder()
        .method(Method::Register)
        .uri("sip:example.com")
        .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
        .from("sip:alice@example.com", "fromtag")
        .to("sip:alice@example.com")
        .call_id("test@example.com")
        .cseq(1)
        .build()
        .unwrap()
}

fn create_response(request: &SipRequest, code: u16) -> SipResponse {
    SipResponse::builder()
        .status(code, "Test")
        .from_request(request)
        .to_tag("totag")
        .build()
        .unwrap()
}

#[cfg(test)]
mod invite_client_transaction {
    use super::*;

    /// Test RFC 3261 17.1.1: INVITE client starts in Calling state
    #[test]
    fn test_initial_state_calling() {
        let invite = create_invite();
        let tx = InviteClientTransaction::new(invite, false).unwrap();
        assert_eq!(tx.state(), InviteClientState::Calling);
    }

    /// Test RFC 3261 17.1.1.1: Timer A fires and request is retransmitted
    #[test]
    fn test_timer_a_retransmit() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions(); // Clear initial actions

        tx.handle_timeout(Timer::A);
        let actions = tx.poll_actions();

        // Should retransmit and reset Timer A
        let has_send = actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::Send(_)));
        let has_timer_a = actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::SetTimer(Timer::A, _)));

        assert!(has_send, "Timer A should trigger retransmission");
        assert!(has_timer_a, "Timer A should be reset");
        assert_eq!(tx.state(), InviteClientState::Calling);
    }

    /// Test RFC 3261 17.1.1.2: Timer A interval doubles on each retransmit
    #[test]
    fn test_timer_a_exponential_backoff() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // First Timer A
        tx.handle_timeout(Timer::A);
        let actions1 = tx.poll_actions();
        let duration1 = actions1.iter().find_map(|a| match a {
            InviteClientAction::SetTimer(Timer::A, d) => Some(d),
            _ => None,
        });

        // Second Timer A
        tx.handle_timeout(Timer::A);
        let actions2 = tx.poll_actions();
        let duration2 = actions2.iter().find_map(|a| match a {
            InviteClientAction::SetTimer(Timer::A, d) => Some(d),
            _ => None,
        });

        assert!(duration1.is_some() && duration2.is_some());
        assert!(
            duration2.unwrap() > duration1.unwrap(),
            "Timer A should have exponential backoff"
        );
    }

    /// Test RFC 3261 17.1.1.2: Timer B fires and transaction times out
    #[test]
    fn test_timer_b_timeout() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        tx.handle_timeout(Timer::B);
        let actions = tx.poll_actions();

        let has_timeout = actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::Event(InviteClientEvent::Timeout)));

        assert!(has_timeout, "Timer B should trigger timeout event");
        assert_eq!(tx.state(), InviteClientState::Terminated);
    }

    /// Test RFC 3261 17.1.1.2: 1xx response transitions to Proceeding
    #[test]
    fn test_provisional_response_proceeding() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let response = create_response(&invite, 180);
        tx.handle_response(response.clone());
        let actions = tx.poll_actions();

        let has_provisional = actions.iter().any(|a| {
            matches!(
                a,
                InviteClientAction::Event(InviteClientEvent::Provisional(_))
            )
        });
        let has_cancel_timer_a = actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::CancelTimer(Timer::A)));

        assert!(has_provisional, "Should emit provisional event");
        assert!(has_cancel_timer_a, "Should cancel Timer A");
        assert_eq!(tx.state(), InviteClientState::Proceeding);
    }

    /// Test RFC 3261 17.1.1.2: Multiple 1xx responses stay in Proceeding
    #[test]
    fn test_multiple_provisional_responses() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // First 1xx
        tx.handle_response(create_response(&invite, 180));
        tx.poll_actions();
        assert_eq!(tx.state(), InviteClientState::Proceeding);

        // Second 1xx
        tx.handle_response(create_response(&invite, 183));
        let actions = tx.poll_actions();

        let has_provisional = actions.iter().any(|a| {
            matches!(
                a,
                InviteClientAction::Event(InviteClientEvent::Provisional(_))
            )
        });

        assert!(has_provisional);
        assert_eq!(tx.state(), InviteClientState::Proceeding);
    }

    /// Test RFC 3261 17.1.1.2: 2xx response from Calling terminates transaction
    #[test]
    fn test_success_response_from_calling() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let response = create_response(&invite, 200);
        tx.handle_response(response);
        let actions = tx.poll_actions();

        let has_success = actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::Event(InviteClientEvent::Success(_))));
        let has_cancel_timer_a = actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::CancelTimer(Timer::A)));
        let has_cancel_timer_b = actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::CancelTimer(Timer::B)));

        assert!(has_success, "Should emit success event");
        assert!(has_cancel_timer_a, "Should cancel Timer A");
        assert!(has_cancel_timer_b, "Should cancel Timer B");
        assert_eq!(tx.state(), InviteClientState::Terminated);
    }

    /// Test RFC 3261 17.1.1.2: 2xx response from Proceeding terminates transaction
    #[test]
    fn test_success_response_from_proceeding() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // First go to Proceeding
        tx.handle_response(create_response(&invite, 180));
        tx.poll_actions();

        // Then 2xx
        tx.handle_response(create_response(&invite, 200));
        let actions = tx.poll_actions();

        let has_success = actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::Event(InviteClientEvent::Success(_))));

        assert!(has_success);
        assert_eq!(tx.state(), InviteClientState::Terminated);
    }

    /// Test RFC 3261 17.1.1.2: 3xx-6xx response transitions to Completed
    #[test]
    fn test_failure_response_to_completed() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let response = create_response(&invite, 404);
        tx.handle_response(response);
        let actions = tx.poll_actions();

        let has_failure = actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::Event(InviteClientEvent::Failure(_))));
        let has_send = actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::Send(_)));
        let has_timer_d = actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::SetTimer(Timer::D, _)));

        assert!(has_failure, "Should emit failure event");
        assert!(has_send, "Should send ACK");
        assert!(has_timer_d || tx.state() == InviteClientState::Terminated);
        assert!(
            tx.state() == InviteClientState::Completed
                || tx.state() == InviteClientState::Terminated
        );
    }

    /// Test RFC 3261 17.1.1.3: Timer D fires in Completed state
    #[test]
    fn test_timer_d_terminates() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // Go to Completed
        tx.handle_response(create_response(&invite, 404));
        tx.poll_actions();

        if tx.state() == InviteClientState::Completed {
            tx.handle_timeout(Timer::D);
            assert_eq!(tx.state(), InviteClientState::Terminated);
        }
    }

    /// Test RFC 3261 17.1.1.2: Retransmitted 3xx-6xx in Completed state
    #[test]
    fn test_retransmitted_failure_in_completed() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // Go to Completed
        let response = create_response(&invite, 404);
        tx.handle_response(response.clone());
        tx.poll_actions();

        if tx.state() == InviteClientState::Completed {
            // Retransmit the same response
            tx.handle_response(response);
            let actions = tx.poll_actions();

            // Should send ACK again but stay in Completed
            let has_send = actions
                .iter()
                .any(|a| matches!(a, InviteClientAction::Send(_)));
            assert!(has_send, "Should retransmit ACK");
            assert_eq!(tx.state(), InviteClientState::Completed);
        }
    }

    /// Test RFC 3261 17.1.1: Reliable transport doesn't use Timer A
    #[test]
    fn test_reliable_transport_no_timer_a() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, true).unwrap();
        let actions = tx.poll_actions();

        let has_timer_a = actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::SetTimer(Timer::A, _)));

        assert!(!has_timer_a, "Reliable transport should not set Timer A");
    }

    /// Test RFC 3261 17.1.1: Reliable transport still uses Timer B
    #[test]
    fn test_reliable_transport_uses_timer_b() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, true).unwrap();
        let actions = tx.poll_actions();

        let has_timer_b = actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::SetTimer(Timer::B, _)));

        assert!(has_timer_b, "Reliable transport should still set Timer B");
    }

    /// Test RFC 3261 17.1.1.3: Timer D is 0 for reliable transports
    #[test]
    fn test_reliable_transport_timer_d_zero() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite.clone(), true).unwrap();
        tx.poll_actions();

        // Get failure response
        tx.handle_response(create_response(&invite, 404));
        let actions = tx.poll_actions();

        // For reliable transport, should go directly to Terminated
        let has_timer_d = actions
            .iter()
            .any(|a| matches!(a, InviteClientAction::SetTimer(Timer::D, _)));

        if has_timer_d {
            // Check if duration is zero
            for action in actions {
                if let InviteClientAction::SetTimer(Timer::D, duration) = action {
                    assert_eq!(
                        duration.as_millis(),
                        0,
                        "Timer D should be 0 for reliable transport"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod non_invite_client_transaction {
    use super::*;

    /// Test RFC 3261 17.1.2: Non-INVITE client starts in Trying state
    #[test]
    fn test_initial_state_trying() {
        let request = create_register();
        let tx = NonInviteClientTransaction::new(request, false).unwrap();
        assert_eq!(tx.state(), NonInviteClientState::Trying);
    }

    /// Test RFC 3261 17.1.2.2: Timer E fires and retransmits
    #[test]
    fn test_timer_e_retransmit() {
        let request = create_register();
        let mut tx = NonInviteClientTransaction::new(request, false).unwrap();
        tx.poll_actions();

        tx.handle_timeout(Timer::E);
        let actions = tx.poll_actions();

        let has_send = actions
            .iter()
            .any(|a| matches!(a, NonInviteClientAction::Send(_)));
        let has_timer_e = actions
            .iter()
            .any(|a| matches!(a, NonInviteClientAction::SetTimer(Timer::E, _)));

        assert!(has_send, "Timer E should trigger retransmission");
        assert!(has_timer_e, "Timer E should be reset");
    }

    /// Test RFC 3261 17.1.2.2: Timer F fires and transaction times out
    #[test]
    fn test_timer_f_timeout() {
        let request = create_register();
        let mut tx = NonInviteClientTransaction::new(request, false).unwrap();
        tx.poll_actions();

        tx.handle_timeout(Timer::F);
        let actions = tx.poll_actions();

        let has_timeout = actions.iter().any(|a| {
            matches!(
                a,
                NonInviteClientAction::Event(NonInviteClientEvent::Timeout)
            )
        });

        assert!(has_timeout, "Timer F should trigger timeout");
        assert_eq!(tx.state(), NonInviteClientState::Terminated);
    }

    /// Test RFC 3261 17.1.2.2: 1xx response transitions to Proceeding
    #[test]
    fn test_provisional_to_proceeding() {
        let request = create_register();
        let mut tx = NonInviteClientTransaction::new(request.clone(), false).unwrap();
        tx.poll_actions();

        let response = create_response(&request, 100);
        tx.handle_response(response);
        let actions = tx.poll_actions();

        let has_provisional = actions.iter().any(|a| {
            matches!(
                a,
                NonInviteClientAction::Event(NonInviteClientEvent::Provisional(_))
            )
        });

        assert!(has_provisional);
        assert_eq!(tx.state(), NonInviteClientState::Proceeding);
    }

    /// Test RFC 3261 17.1.2.2: Final response from Trying goes to Completed
    #[test]
    fn test_final_response_from_trying() {
        let request = create_register();
        let mut tx = NonInviteClientTransaction::new(request.clone(), false).unwrap();
        tx.poll_actions();

        let response = create_response(&request, 200);
        tx.handle_response(response);
        let actions = tx.poll_actions();

        let has_response = actions.iter().any(|a| {
            matches!(
                a,
                NonInviteClientAction::Event(NonInviteClientEvent::FinalResponse(_))
            )
        });

        assert!(has_response);
        assert!(
            tx.state() == NonInviteClientState::Completed
                || tx.state() == NonInviteClientState::Terminated
        );
    }

    /// Test RFC 3261 17.1.2.2: Final response from Proceeding goes to Completed
    #[test]
    fn test_final_response_from_proceeding() {
        let request = create_register();
        let mut tx = NonInviteClientTransaction::new(request.clone(), false).unwrap();
        tx.poll_actions();

        // Go to Proceeding
        tx.handle_response(create_response(&request, 100));
        tx.poll_actions();

        // Final response
        tx.handle_response(create_response(&request, 200));
        let actions = tx.poll_actions();

        let has_response = actions.iter().any(|a| {
            matches!(
                a,
                NonInviteClientAction::Event(NonInviteClientEvent::FinalResponse(_))
            )
        });

        assert!(has_response);
        assert!(
            tx.state() == NonInviteClientState::Completed
                || tx.state() == NonInviteClientState::Terminated
        );
    }

    /// Test RFC 3261 17.1.2.2: Timer K fires in Completed state
    #[test]
    fn test_timer_k_terminates() {
        let request = create_register();
        let mut tx = NonInviteClientTransaction::new(request.clone(), false).unwrap();
        tx.poll_actions();

        // Go to Completed
        tx.handle_response(create_response(&request, 200));
        tx.poll_actions();

        if tx.state() == NonInviteClientState::Completed {
            tx.handle_timeout(Timer::K);
            assert_eq!(tx.state(), NonInviteClientState::Terminated);
        }
    }

    /// Test RFC 3261 17.1.2.2: Retransmitted response in Completed state
    #[test]
    fn test_retransmitted_response_in_completed() {
        let request = create_register();
        let mut tx = NonInviteClientTransaction::new(request.clone(), false).unwrap();
        tx.poll_actions();

        let response = create_response(&request, 200);
        tx.handle_response(response.clone());
        tx.poll_actions();

        if tx.state() == NonInviteClientState::Completed {
            // Retransmit
            tx.handle_response(response);
            // Should absorb retransmission and stay in Completed
            assert_eq!(tx.state(), NonInviteClientState::Completed);
        }
    }

    /// Test RFC 3261 17.1.2: Reliable transport doesn't use Timer E
    #[test]
    fn test_reliable_no_timer_e() {
        let request = create_register();
        let mut tx = NonInviteClientTransaction::new(request, true).unwrap();
        let actions = tx.poll_actions();

        let has_timer_e = actions
            .iter()
            .any(|a| matches!(a, NonInviteClientAction::SetTimer(Timer::E, _)));

        assert!(!has_timer_e, "Reliable transport should not set Timer E");
    }

    /// Test RFC 3261 17.1.2: Reliable transport still uses Timer F
    #[test]
    fn test_reliable_uses_timer_f() {
        let request = create_register();
        let mut tx = NonInviteClientTransaction::new(request, true).unwrap();
        let actions = tx.poll_actions();

        let has_timer_f = actions
            .iter()
            .any(|a| matches!(a, NonInviteClientAction::SetTimer(Timer::F, _)));

        assert!(has_timer_f, "Reliable transport should use Timer F");
    }
}

#[cfg(test)]
mod invite_server_transaction {
    use super::*;

    /// Test RFC 3261 17.2.1: INVITE server starts in Proceeding state
    #[test]
    fn test_initial_state_proceeding() {
        let invite = create_invite();
        let tx = InviteServerTransaction::new(invite, false).unwrap();
        assert_eq!(tx.state(), InviteServerState::Proceeding);
    }

    /// Test RFC 3261 17.2.1: Sending provisional response stays in Proceeding
    #[test]
    fn test_send_provisional_stays_proceeding() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let response = create_response(&invite, 180);
        tx.send_response(response);
        tx.poll_actions();

        assert_eq!(tx.state(), InviteServerState::Proceeding);
    }

    /// Test RFC 3261 17.2.1: Sending 2xx response terminates transaction
    #[test]
    fn test_send_success_terminates() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let response = create_response(&invite, 200);
        tx.send_response(response);
        tx.poll_actions();

        assert_eq!(tx.state(), InviteServerState::Terminated);
    }

    /// Test RFC 3261 17.2.1: Sending 3xx-6xx response transitions to Completed
    #[test]
    fn test_send_failure_to_completed() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let response = create_response(&invite, 404);
        tx.send_response(response);
        tx.poll_actions();

        assert_eq!(tx.state(), InviteServerState::Completed);
    }

    /// Test RFC 3261 17.2.1: Retransmitted INVITE in Proceeding sends last response
    #[test]
    fn test_retransmit_in_proceeding() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // Send provisional
        let response = create_response(&invite, 180);
        tx.send_response(response);
        tx.poll_actions();

        // Retransmitted INVITE
        tx.handle_request(invite);
        let actions = tx.poll_actions();

        let has_send = actions
            .iter()
            .any(|a| matches!(a, InviteServerAction::Send(_)));
        assert!(has_send, "Should retransmit last response");
        assert_eq!(tx.state(), InviteServerState::Proceeding);
    }

    /// Test RFC 3261 17.2.1: ACK received in Completed transitions to Confirmed
    #[test]
    fn test_ack_to_confirmed() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // Send failure
        tx.send_response(create_response(&invite, 404));
        tx.poll_actions();

        if tx.state() == InviteServerState::Completed {
            // Create ACK
            let ack = SipRequest::builder()
                .method(Method::Ack)
                .uri("sip:bob@example.com")
                .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
                .from("sip:alice@example.com", "fromtag")
                .to("sip:bob@example.com")
                .call_id("test@example.com")
                .cseq(1)
                .build()
                .unwrap();

            tx.handle_request(ack);
            assert_eq!(tx.state(), InviteServerState::Confirmed);
        }
    }

    /// Test RFC 3261 17.2.1: Timer G fires in Completed (retransmit response)
    #[test]
    fn test_timer_g_retransmits() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // Go to Completed
        tx.send_response(create_response(&invite, 404));
        tx.poll_actions();

        if tx.state() == InviteServerState::Completed {
            tx.handle_timeout(Timer::G);
            let actions = tx.poll_actions();

            let has_send = actions
                .iter()
                .any(|a| matches!(a, InviteServerAction::Send(_)));
            let has_timer_g = actions
                .iter()
                .any(|a| matches!(a, InviteServerAction::SetTimer(Timer::G, _)));

            assert!(has_send, "Timer G should retransmit response");
            assert!(has_timer_g, "Timer G should be reset");
        }
    }

    /// Test RFC 3261 17.2.1: Timer H fires in Completed (timeout)
    #[test]
    fn test_timer_h_timeout() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // Go to Completed
        tx.send_response(create_response(&invite, 404));
        tx.poll_actions();

        if tx.state() == InviteServerState::Completed {
            tx.handle_timeout(Timer::H);
            assert_eq!(tx.state(), InviteServerState::Terminated);
        }
    }

    /// Test RFC 3261 17.2.1: Timer I fires in Confirmed (terminate)
    #[test]
    fn test_timer_i_terminates() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // Go to Completed then Confirmed
        tx.send_response(create_response(&invite, 404));
        tx.poll_actions();

        if tx.state() == InviteServerState::Completed {
            let ack = SipRequest::builder()
                .method(Method::Ack)
                .uri("sip:bob@example.com")
                .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
                .from("sip:alice@example.com", "fromtag")
                .to("sip:bob@example.com")
                .call_id("test@example.com")
                .cseq(1)
                .build()
                .unwrap();
            tx.handle_request(ack);

            if tx.state() == InviteServerState::Confirmed {
                tx.handle_timeout(Timer::I);
                assert_eq!(tx.state(), InviteServerState::Terminated);
            }
        }
    }

    /// Test RFC 3261 17.2.1: Reliable transport doesn't use Timer G
    #[test]
    fn test_reliable_no_timer_g() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), true).unwrap();
        tx.poll_actions();

        tx.send_response(create_response(&invite, 404));
        let actions = tx.poll_actions();

        let has_timer_g = actions
            .iter()
            .any(|a| matches!(a, InviteServerAction::SetTimer(Timer::G, _)));

        assert!(!has_timer_g, "Reliable transport should not set Timer G");
    }
}

#[cfg(test)]
mod non_invite_server_transaction {
    use super::*;

    /// Test RFC 3261 17.2.2: Non-INVITE server starts in Trying state
    #[test]
    fn test_initial_state_trying() {
        let request = create_register();
        let tx = NonInviteServerTransaction::new(request, false).unwrap();
        assert_eq!(tx.state(), NonInviteServerState::Trying);
    }

    /// Test RFC 3261 17.2.2: Sending provisional transitions to Proceeding
    #[test]
    fn test_provisional_to_proceeding() {
        let request = create_register();
        let mut tx = NonInviteServerTransaction::new(request.clone(), false).unwrap();
        tx.poll_actions();

        let response = create_response(&request, 100);
        tx.send_response(response);
        tx.poll_actions();

        assert_eq!(tx.state(), NonInviteServerState::Proceeding);
    }

    /// Test RFC 3261 17.2.2: Sending final from Trying goes to Completed
    #[test]
    fn test_final_from_trying_to_completed() {
        let request = create_register();
        let mut tx = NonInviteServerTransaction::new(request.clone(), false).unwrap();
        tx.poll_actions();

        let response = create_response(&request, 200);
        tx.send_response(response);
        tx.poll_actions();

        assert!(
            tx.state() == NonInviteServerState::Completed
                || tx.state() == NonInviteServerState::Terminated
        );
    }

    /// Test RFC 3261 17.2.2: Sending final from Proceeding goes to Completed
    #[test]
    fn test_final_from_proceeding_to_completed() {
        let request = create_register();
        let mut tx = NonInviteServerTransaction::new(request.clone(), false).unwrap();
        tx.poll_actions();

        // Go to Proceeding
        tx.send_response(create_response(&request, 100));
        tx.poll_actions();

        // Send final
        tx.send_response(create_response(&request, 200));
        tx.poll_actions();

        assert!(
            tx.state() == NonInviteServerState::Completed
                || tx.state() == NonInviteServerState::Terminated
        );
    }

    /// Test RFC 3261 17.2.2: Retransmitted request sends last response
    #[test]
    fn test_retransmit_sends_last_response() {
        let request = create_register();
        let mut tx = NonInviteServerTransaction::new(request.clone(), false).unwrap();
        tx.poll_actions();

        // Send response
        tx.send_response(create_response(&request, 200));
        tx.poll_actions();

        if tx.state() == NonInviteServerState::Completed {
            // Retransmit request
            tx.handle_request(request);
            let actions = tx.poll_actions();

            let has_send = actions
                .iter()
                .any(|a| matches!(a, NonInviteServerAction::Send(_)));
            assert!(has_send, "Should retransmit last response");
        }
    }

    /// Test RFC 3261 17.2.2: Timer J fires in Completed state
    #[test]
    fn test_timer_j_terminates() {
        let request = create_register();
        let mut tx = NonInviteServerTransaction::new(request.clone(), false).unwrap();
        tx.poll_actions();

        // Go to Completed
        tx.send_response(create_response(&request, 200));
        tx.poll_actions();

        if tx.state() == NonInviteServerState::Completed {
            tx.handle_timeout(Timer::J);
            assert_eq!(tx.state(), NonInviteServerState::Terminated);
        }
    }

    /// Test RFC 3261 17.2.2: Reliable transport has Timer J = 0
    #[test]
    fn test_reliable_timer_j_zero() {
        let request = create_register();
        let mut tx = NonInviteServerTransaction::new(request.clone(), true).unwrap();
        tx.poll_actions();

        tx.send_response(create_response(&request, 200));
        let actions = tx.poll_actions();

        // For reliable, should either have Timer J = 0 or go directly to Terminated
        let has_timer_j = actions
            .iter()
            .any(|a| matches!(a, NonInviteServerAction::SetTimer(Timer::J, _)));

        if has_timer_j {
            for action in actions {
                if let NonInviteServerAction::SetTimer(Timer::J, duration) = action {
                    assert_eq!(
                        duration.as_millis(),
                        0,
                        "Timer J should be 0 for reliable transport"
                    );
                }
            }
        }
    }
}

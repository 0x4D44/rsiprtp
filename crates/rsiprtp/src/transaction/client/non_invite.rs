//! Non-INVITE client transaction state machine per RFC 3261 Section 17.1.2.
//!
//! This handles REGISTER, BYE, CANCEL, OPTIONS, etc.
//!
//! State diagram:
//! ```text
//!                    |Request from TU
//!                    |send request
//!              Timer E fires     V
//!                +-----+  +------+----+
//!                |     |  |           |
//!                V     +->| Trying    |
//!                +------+ +-----+-----+
//!                              |
//!                              |1xx
//!                Timer E fires |
//!                +-----+  +----V----+
//!                |     |  |         |
//!                V     +->|Proceeding|
//!                +------+ +----+----+
//!                              |
//!                        2xx-6xx|
//!                              V
//!                    +---------+---------+
//!                    |                   |
//!                    |    Completed      |
//!                    |                   |
//!                    +---------+---------+
//!                              |
//!                        Timer K|
//!                              V
//!                    +---------+---------+
//!                    |                   |
//!                    |   Terminated      |
//!                    |                   |
//!                    +-------------------+
//! ```

use super::invite::TransactionId;
use crate::transaction::timer::{Timer, TimerValues};
use crate::sip::{Method, SipRequest, SipResponse};
use std::time::Duration;

/// State of the non-INVITE client transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Initial state - request has been sent.
    Trying,
    /// 1xx received - waiting for final response.
    Proceeding,
    /// Final response received - waiting for Timer K.
    Completed,
    /// Transaction is finished.
    Terminated,
}

/// Output action from the transaction.
#[derive(Debug, Clone)]
pub enum Action {
    /// Transmit a message to the network.
    Send(bytes::Bytes),
    /// Emit an event to the Transaction User (TU).
    Event(Event),
    /// Set a timer.
    SetTimer(Timer, Duration),
    /// Cancel a timer.
    CancelTimer(Timer),
}

/// Event emitted to the Transaction User.
#[derive(Debug, Clone)]
pub enum Event {
    /// Provisional response received.
    Provisional(SipResponse),
    /// Final response received (2xx-6xx).
    FinalResponse(SipResponse),
    /// Transaction timed out (Timer F fired).
    Timeout,
    /// Transport error.
    TransportError,
}

/// Non-INVITE client transaction (Sans-IO).
#[derive(Debug)]
pub struct NonInviteClientTransaction {
    /// Transaction ID.
    id: TransactionId,
    /// Current state.
    state: State,
    /// Original request.
    request: SipRequest,
    /// Timer values.
    timers: TimerValues,
    /// Whether transport is reliable (TCP/TLS).
    reliable: bool,
    /// Current retransmit interval for Timer E.
    retransmit_interval: Duration,
    /// Pending actions.
    actions: Vec<Action>,
}

impl NonInviteClientTransaction {
    /// Create a new non-INVITE client transaction.
    ///
    /// Returns None if the request is an INVITE.
    pub fn new(request: SipRequest, reliable: bool) -> Option<Self> {
        if request.method() == Method::Invite {
            return None;
        }
        let id = TransactionId::from_request(&request)?;
        let timers = TimerValues::default();
        let retransmit_interval = timers.timer_e();

        let mut tx = Self {
            id,
            state: State::Trying,
            request,
            timers,
            reliable,
            retransmit_interval,
            actions: Vec::new(),
        };

        // Send the request
        tx.actions.push(Action::Send(tx.request.to_bytes()));

        // For unreliable transport, start Timer E
        if !reliable {
            tx.actions
                .push(Action::SetTimer(Timer::E, tx.retransmit_interval));
        }

        // Start Timer F
        tx.actions
            .push(Action::SetTimer(Timer::F, tx.timers.timer_f()));

        Some(tx)
    }

    /// Get the transaction ID.
    pub fn id(&self) -> &TransactionId {
        &self.id
    }

    /// Get the current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Check if the transaction is terminated.
    pub fn is_terminated(&self) -> bool {
        self.state == State::Terminated
    }

    /// Handle a timer firing.
    pub fn handle_timeout(&mut self, timer: Timer) {
        match (self.state, timer) {
            (State::Trying, Timer::E) | (State::Proceeding, Timer::E) => {
                // Retransmit and restart Timer E
                self.actions.push(Action::Send(self.request.to_bytes()));
                self.retransmit_interval = self.timers.next_retransmit(self.retransmit_interval);
                self.actions
                    .push(Action::SetTimer(Timer::E, self.retransmit_interval));
            }
            (State::Trying, Timer::F) | (State::Proceeding, Timer::F) => {
                // Transaction timeout
                self.state = State::Terminated;
                self.actions.push(Action::Event(Event::Timeout));
            }
            (State::Completed, Timer::K) => {
                // Timer K fired - terminate
                self.state = State::Terminated;
            }
            _ => {
                // Ignore unexpected timers
            }
        }
    }

    /// Handle a response from the network.
    pub fn handle_response(&mut self, response: SipResponse) {
        let code = response.status_code();

        match self.state {
            State::Trying => {
                if (100..200).contains(&code) {
                    // Provisional response - transition to Proceeding
                    self.state = State::Proceeding;
                    self.actions
                        .push(Action::Event(Event::Provisional(response)));
                } else if code >= 200 {
                    // Final response - transition to Completed
                    self.state = State::Completed;
                    if !self.reliable {
                        self.actions.push(Action::CancelTimer(Timer::E));
                    }
                    self.actions.push(Action::CancelTimer(Timer::F));
                    self.actions
                        .push(Action::Event(Event::FinalResponse(response)));
                    // Start Timer K
                    let timer_k = self.timers.timer_k(self.reliable);
                    if timer_k.is_zero() {
                        self.state = State::Terminated;
                    } else {
                        self.actions.push(Action::SetTimer(Timer::K, timer_k));
                    }
                }
            }
            State::Proceeding => {
                if (100..200).contains(&code) {
                    // Another provisional response
                    self.actions
                        .push(Action::Event(Event::Provisional(response)));
                } else if code >= 200 {
                    // Final response - transition to Completed
                    self.state = State::Completed;
                    if !self.reliable {
                        self.actions.push(Action::CancelTimer(Timer::E));
                    }
                    self.actions.push(Action::CancelTimer(Timer::F));
                    self.actions
                        .push(Action::Event(Event::FinalResponse(response)));
                    // Start Timer K
                    let timer_k = self.timers.timer_k(self.reliable);
                    if timer_k.is_zero() {
                        self.state = State::Terminated;
                    } else {
                        self.actions.push(Action::SetTimer(Timer::K, timer_k));
                    }
                }
            }
            State::Completed | State::Terminated => {
                // Ignore responses in Completed/Terminated state
            }
        }
    }

    /// Drain pending actions.
    pub fn poll_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.actions)
    }

    /// Handle a transport error.
    pub fn handle_transport_error(&mut self) {
        match self.state {
            State::Trying | State::Proceeding => {
                self.state = State::Terminated;
                self.actions.push(Action::Event(Event::TransportError));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_register() -> SipRequest {
        SipRequest::builder()
            .method(Method::Register)
            .uri("sip:example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:alice@example.com")
            .call_id("register@example.com")
            .cseq(1)
            .build()
            .unwrap()
    }

    fn parse_request(raw: &[u8]) -> SipRequest {
        let msg = crate::sip::SipMessage::parse(raw).unwrap();
        msg.as_request().unwrap().clone()
    }

    fn create_response(code: u16) -> SipResponse {
        let req = create_register();
        SipResponse::builder()
            .status(code, "Test")
            .from_request(&req)
            .to_tag("totag")
            .build()
            .unwrap()
    }

    #[test]
    fn test_new_transaction() {
        let req = create_register();
        let tx = NonInviteClientTransaction::new(req, false).unwrap();
        assert_eq!(tx.state(), State::Trying);
        assert!(!tx.is_terminated());
    }

    #[test]
    fn test_new_transaction_missing_branch() {
        let raw = b"REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: register@example.com\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n";
        let req = parse_request(raw);
        let tx = NonInviteClientTransaction::new(req, false);
        assert!(tx.is_none());
    }

    #[test]
    fn test_reject_invite() {
        let invite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();
        let tx = NonInviteClientTransaction::new(invite, false);
        assert!(tx.is_none());
    }

    #[test]
    fn test_provisional_response() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        let resp = create_response(100);
        tx.handle_response(resp);

        assert_eq!(tx.state(), State::Proceeding);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Provisional(_)))));
    }

    #[test]
    fn test_success_response() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        let resp = create_response(200);
        tx.handle_response(resp);

        assert_eq!(tx.state(), State::Completed);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::FinalResponse(_)))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::K, _))));
    }

    #[test]
    fn test_trying_response_below_100_ignored() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        let resp = create_response(99);
        tx.handle_response(resp);

        assert_eq!(tx.state(), State::Trying);
        assert!(tx.poll_actions().is_empty());
    }

    #[test]
    fn test_failure_response() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        let resp = create_response(401);
        tx.handle_response(resp);

        assert_eq!(tx.state(), State::Completed);
    }

    #[test]
    fn test_timer_f_timeout() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, true).unwrap();
        tx.poll_actions();

        tx.handle_timeout(Timer::F);

        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Timeout))));
    }

    #[test]
    fn test_timer_e_retransmit() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        tx.handle_timeout(Timer::E);

        assert_eq!(tx.state(), State::Trying);
        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
    }

    #[test]
    fn test_timer_k_terminates() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        let resp = create_response(200);
        tx.handle_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Completed);

        tx.handle_timeout(Timer::K);
        assert_eq!(tx.state(), State::Terminated);
    }

    #[test]
    fn test_reliable_transport_immediate_terminate() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, true).unwrap();
        tx.poll_actions();

        let resp = create_response(200);
        tx.handle_response(resp);

        // For reliable transport, goes directly to Terminated (Timer K = 0)
        assert_eq!(tx.state(), State::Terminated);
    }

    // Additional tests for uncovered code paths

    #[test]
    fn test_transaction_id() {
        let req = create_register();
        let tx = NonInviteClientTransaction::new(req, false).unwrap();
        let id = tx.id();
        // Verify ID exists and is consistent
        assert!(!id.branch.is_empty());
    }

    #[test]
    fn test_transport_error_in_trying() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        tx.handle_transport_error();

        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::TransportError))));
    }

    #[test]
    fn test_transport_error_in_proceeding() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        // First get to Proceeding state
        let resp = create_response(100);
        tx.handle_response(resp);
        tx.poll_actions();
        assert_eq!(tx.state(), State::Proceeding);

        tx.handle_transport_error();

        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::TransportError))));
    }

    #[test]
    fn test_transport_error_in_completed_ignored() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        let resp = create_response(200);
        tx.handle_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Completed);

        tx.handle_transport_error();
        // Should stay in Completed, error is ignored
        assert_eq!(tx.state(), State::Completed);
    }

    #[test]
    fn test_timer_e_in_proceeding() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        // Get to Proceeding state
        let resp = create_response(100);
        tx.handle_response(resp);
        tx.poll_actions();
        assert_eq!(tx.state(), State::Proceeding);

        // Timer E should cause retransmit
        tx.handle_timeout(Timer::E);

        assert_eq!(tx.state(), State::Proceeding);
        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::E, _))));
    }

    #[test]
    fn test_timer_f_in_proceeding() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        // Get to Proceeding state
        let resp = create_response(100);
        tx.handle_response(resp);
        tx.poll_actions();
        assert_eq!(tx.state(), State::Proceeding);

        // Timer F should cause timeout
        tx.handle_timeout(Timer::F);

        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Timeout))));
    }

    #[test]
    fn test_response_in_completed_ignored() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        let resp = create_response(200);
        tx.handle_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Completed);

        // Additional response should be ignored
        let resp2 = create_response(200);
        tx.handle_response(resp2);

        assert_eq!(tx.state(), State::Completed);
        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_response_in_terminated_ignored() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, true).unwrap();
        tx.poll_actions();

        let resp = create_response(200);
        tx.handle_response(resp);
        // Reliable transport goes directly to Terminated
        assert_eq!(tx.state(), State::Terminated);
        tx.poll_actions();

        // Additional response should be ignored
        let resp2 = create_response(200);
        tx.handle_response(resp2);

        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_unexpected_timer_in_completed() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        let resp = create_response(200);
        tx.handle_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Completed);

        // Timer E/F in Completed should be ignored
        tx.handle_timeout(Timer::E);
        assert_eq!(tx.state(), State::Completed);

        tx.handle_timeout(Timer::F);
        assert_eq!(tx.state(), State::Completed);
    }

    #[test]
    fn test_multiple_provisional_responses() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        // First provisional
        let resp = create_response(100);
        tx.handle_response(resp);
        assert_eq!(tx.state(), State::Proceeding);
        tx.poll_actions();

        // Second provisional
        let resp2 = create_response(180);
        tx.handle_response(resp2);
        assert_eq!(tx.state(), State::Proceeding);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Provisional(_)))));
    }

    #[test]
    fn test_final_response_from_proceeding() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        // Get to Proceeding
        let resp = create_response(100);
        tx.handle_response(resp);
        tx.poll_actions();
        assert_eq!(tx.state(), State::Proceeding);

        // Final response
        let resp2 = create_response(200);
        tx.handle_response(resp2);

        assert_eq!(tx.state(), State::Completed);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::FinalResponse(_)))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::CancelTimer(Timer::E))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::CancelTimer(Timer::F))));
    }

    #[test]
    fn test_proceeding_response_below_100_ignored() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        let provisional = create_response(100);
        tx.handle_response(provisional);
        tx.poll_actions();
        assert_eq!(tx.state(), State::Proceeding);

        let resp = create_response(99);
        tx.handle_response(resp);

        assert_eq!(tx.state(), State::Proceeding);
        assert!(tx.poll_actions().is_empty());
    }

    #[test]
    fn test_reliable_transport_no_timer_e() {
        let req = create_register();
        let tx = NonInviteClientTransaction::new(req, true).unwrap();
        let actions = tx.actions.clone();

        // Reliable transport should not have Timer E
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::E, _))));
        // Should have Timer F
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::F, _))));
    }

    #[test]
    fn test_unreliable_transport_has_timer_e() {
        let req = create_register();
        let tx = NonInviteClientTransaction::new(req, false).unwrap();
        let actions = tx.actions.clone();

        // Unreliable transport should have Timer E
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::E, _))));
    }

    #[test]
    fn test_final_response_from_trying_unreliable() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        let resp = create_response(200);
        tx.handle_response(resp);

        assert_eq!(tx.state(), State::Completed);
    }

    #[test]
    fn test_final_response_from_proceeding_unreliable() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        let resp = create_response(180);
        tx.handle_response(resp);
        assert_eq!(tx.state(), State::Proceeding);
        tx.poll_actions();

        let resp2 = create_response(200);
        tx.handle_response(resp2);
        assert_eq!(tx.state(), State::Completed);
    }

    #[test]
    fn test_final_response_reliable_from_proceeding() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, true).unwrap();
        tx.poll_actions();

        // Get to Proceeding
        let resp = create_response(100);
        tx.handle_response(resp);
        tx.poll_actions();

        // Final response with reliable transport
        let resp2 = create_response(200);
        tx.handle_response(resp2);

        // Reliable goes directly to Terminated
        assert_eq!(tx.state(), State::Terminated);
    }

    #[test]
    fn test_state_debug() {
        assert_eq!(format!("{:?}", State::Trying), "Trying");
        assert_eq!(format!("{:?}", State::Proceeding), "Proceeding");
        assert_eq!(format!("{:?}", State::Completed), "Completed");
        assert_eq!(format!("{:?}", State::Terminated), "Terminated");
    }

    #[test]
    fn test_event_debug() {
        let resp = create_response(200);
        let ev1 = Event::Provisional(resp.clone());
        let ev2 = Event::FinalResponse(resp);
        let ev3 = Event::Timeout;
        let ev4 = Event::TransportError;

        assert!(format!("{:?}", ev1).contains("Provisional"));
        assert!(format!("{:?}", ev2).contains("FinalResponse"));
        assert!(format!("{:?}", ev3).contains("Timeout"));
        assert!(format!("{:?}", ev4).contains("TransportError"));
    }

    #[test]
    fn test_action_debug() {
        let action1 = Action::Send(bytes::Bytes::from_static(b"test"));
        let action2 = Action::SetTimer(Timer::E, Duration::from_secs(1));
        let action3 = Action::CancelTimer(Timer::F);

        assert!(format!("{:?}", action1).contains("Send"));
        assert!(format!("{:?}", action2).contains("SetTimer"));
        assert!(format!("{:?}", action3).contains("CancelTimer"));
    }

    #[test]
    fn test_5xx_response() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        let resp = create_response(503);
        tx.handle_response(resp);

        assert_eq!(tx.state(), State::Completed);
    }

    #[test]
    fn test_6xx_response() {
        let req = create_register();
        let mut tx = NonInviteClientTransaction::new(req, false).unwrap();
        tx.poll_actions();

        let resp = create_response(603);
        tx.handle_response(resp);

        assert_eq!(tx.state(), State::Completed);
    }

    #[test]
    fn test_options_transaction() {
        let req = SipRequest::builder()
            .method(Method::Options)
            .uri("sip:example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKopts")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:alice@example.com")
            .call_id("options@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let tx = NonInviteClientTransaction::new(req, false);
        assert!(tx.is_some());
    }

    #[test]
    fn test_bye_transaction() {
        let req = SipRequest::builder()
            .method(Method::Bye)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKbye")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("bye@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let tx = NonInviteClientTransaction::new(req, false);
        assert!(tx.is_some());
    }
}

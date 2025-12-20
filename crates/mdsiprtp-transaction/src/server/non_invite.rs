//! Non-INVITE server transaction state machine per RFC 3261 Section 17.2.2.
//!
//! This handles REGISTER, BYE, CANCEL, OPTIONS, etc.
//!
//! State diagram:
//! ```text
//!                               |Request from network
//!                               V
//!                    +---------+---------+
//!                    |                   |
//!                    |      Trying       |
//!                    |                   |
//!                    +---------+---------+
//!                               |
//!                         1xx  |  2xx-6xx
//!                   +----------+----------+
//!                   |                     |
//!                   V                     V
//!         +---------+---------+ +---------+---------+
//!         |                   | |                   |
//!         |    Proceeding     | |    Completed      |
//!         |                   | |                   |
//!         +---------+---------+ +---------+---------+
//!                   |                     |
//!             2xx-6xx|               Timer J|
//!                   |                     |
//!                   V                     V
//!         +---------+---------+ +---------+---------+
//!         |                   | |                   |
//!         |    Completed      | |   Terminated      |
//!         |                   | |                   |
//!         +---------+---------+ +-------------------+
//!                   |
//!             Timer J|
//!                   V
//!         +---------+---------+
//!         |                   |
//!         |   Terminated      |
//!         |                   |
//!         +-------------------+
//! ```

use crate::client::invite::TransactionId;
use crate::timer::{Timer, TimerValues};
use mdsiprtp_sip::{Method, SipRequest, SipResponse};
use std::time::Duration;

/// State of the non-INVITE server transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Initial state - request received, waiting for TU response.
    Trying,
    /// 1xx sent - waiting for final response.
    Proceeding,
    /// Final response sent - waiting for Timer J.
    Completed,
    /// Transaction is finished.
    Terminated,
}

/// Output action from the transaction.
#[derive(Debug, Clone)]
pub enum Action {
    /// Transmit a response to the network.
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
    /// Request received.
    Request(Box<SipRequest>),
    /// Transport error.
    TransportError,
}

/// Non-INVITE server transaction (Sans-IO).
#[derive(Debug)]
pub struct NonInviteServerTransaction {
    /// Transaction ID.
    id: TransactionId,
    /// Current state.
    state: State,
    /// Original request.
    request: SipRequest,
    /// Last response sent.
    last_response: Option<bytes::Bytes>,
    /// Timer values.
    timers: TimerValues,
    /// Whether transport is reliable (TCP/TLS).
    reliable: bool,
    /// Pending actions.
    actions: Vec<Action>,
}

impl NonInviteServerTransaction {
    /// Create a new non-INVITE server transaction from an incoming request.
    ///
    /// Returns None if the request is an INVITE.
    pub fn new(request: SipRequest, reliable: bool) -> Option<Self> {
        if request.method() == Method::Invite {
            return None;
        }
        let id = TransactionId::from_request(&request)?;

        let mut tx = Self {
            id,
            state: State::Trying,
            request: request.clone(),
            last_response: None,
            timers: TimerValues::default(),
            reliable,
            actions: Vec::new(),
        };

        // Notify TU of the request
        tx.actions
            .push(Action::Event(Event::Request(Box::new(request))));

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

    /// Get a reference to the original request.
    pub fn request(&self) -> &SipRequest {
        &self.request
    }

    /// Handle a timer firing.
    pub fn handle_timeout(&mut self, timer: Timer) {
        match (self.state, timer) {
            (State::Completed, Timer::J) => {
                // Timer J fired - terminate
                self.state = State::Terminated;
            }
            _ => {
                // Ignore unexpected timers
            }
        }
    }

    /// Handle an incoming request (retransmit).
    pub fn handle_request(&mut self, _request: SipRequest) {
        match self.state {
            State::Trying => {
                // No response sent yet - nothing to retransmit
            }
            State::Proceeding | State::Completed => {
                // Retransmitted request - resend last response
                if let Some(ref resp) = self.last_response {
                    self.actions.push(Action::Send(resp.clone()));
                }
            }
            State::Terminated => {
                // Ignore
            }
        }
    }

    /// Send a response from the TU.
    pub fn send_response(&mut self, response: SipResponse) {
        let code = response.status_code();
        let resp_bytes = response.to_bytes();

        match self.state {
            State::Trying => {
                if (100..200).contains(&code) {
                    // Provisional response - transition to Proceeding
                    self.state = State::Proceeding;
                    self.last_response = Some(resp_bytes.clone());
                    self.actions.push(Action::Send(resp_bytes));
                } else if code >= 200 {
                    // Final response - transition to Completed
                    self.state = State::Completed;
                    self.last_response = Some(resp_bytes.clone());
                    self.actions.push(Action::Send(resp_bytes));
                    // Start Timer J
                    let timer_j = self.timers.timer_j(self.reliable);
                    if timer_j.is_zero() {
                        self.state = State::Terminated;
                    } else {
                        self.actions.push(Action::SetTimer(Timer::J, timer_j));
                    }
                }
            }
            State::Proceeding => {
                if (100..200).contains(&code) {
                    // Another provisional response
                    self.last_response = Some(resp_bytes.clone());
                    self.actions.push(Action::Send(resp_bytes));
                } else if code >= 200 {
                    // Final response - transition to Completed
                    self.state = State::Completed;
                    self.last_response = Some(resp_bytes.clone());
                    self.actions.push(Action::Send(resp_bytes));
                    // Start Timer J
                    let timer_j = self.timers.timer_j(self.reliable);
                    if timer_j.is_zero() {
                        self.state = State::Terminated;
                    } else {
                        self.actions.push(Action::SetTimer(Timer::J, timer_j));
                    }
                }
            }
            _ => {
                // Ignore responses in other states
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
            State::Trying | State::Proceeding | State::Completed => {
                self.state = State::Terminated;
                self.actions.push(Action::Event(Event::TransportError));
            }
            State::Terminated => {}
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

    fn create_response(code: u16, req: &SipRequest) -> SipResponse {
        SipResponse::builder()
            .status(code, "Test")
            .from_request(req)
            .to_tag("totag")
            .build()
            .unwrap()
    }

    #[test]
    fn test_new_transaction() {
        let req = create_register();
        let tx = NonInviteServerTransaction::new(req, false).unwrap();
        assert_eq!(tx.state(), State::Trying);
        assert!(!tx.is_terminated());
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
        let tx = NonInviteServerTransaction::new(invite, false);
        assert!(tx.is_none());
    }

    #[test]
    fn test_provisional_response() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(100, &req);
        tx.send_response(resp);

        assert_eq!(tx.state(), State::Proceeding);
        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
    }

    #[test]
    fn test_final_response_from_trying() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(200, &req);
        tx.send_response(resp);

        assert_eq!(tx.state(), State::Completed);
        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::J, _))));
    }

    #[test]
    fn test_final_response_from_proceeding() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), false).unwrap();
        tx.poll_actions();

        let resp1 = create_response(100, &req);
        tx.send_response(resp1);
        tx.poll_actions();

        let resp2 = create_response(200, &req);
        tx.send_response(resp2);

        assert_eq!(tx.state(), State::Completed);
    }

    #[test]
    fn test_retransmit_response() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(200, &req);
        tx.send_response(resp);
        tx.poll_actions();

        // Retransmitted request
        tx.handle_request(req);

        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
    }

    #[test]
    fn test_timer_j_terminates() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(200, &req);
        tx.send_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Completed);

        tx.handle_timeout(Timer::J);
        assert_eq!(tx.state(), State::Terminated);
    }

    #[test]
    fn test_reliable_transport_immediate_terminate() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), true).unwrap();
        tx.poll_actions();

        let resp = create_response(200, &req);
        tx.send_response(resp);

        // For reliable transport, goes directly to Terminated (Timer J = 0)
        assert_eq!(tx.state(), State::Terminated);
    }

    #[test]
    fn test_handle_transport_error_in_trying() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req, false).unwrap();
        tx.poll_actions();

        tx.handle_transport_error();

        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::TransportError))));
    }

    #[test]
    fn test_handle_transport_error_in_proceeding() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(100, &req);
        tx.send_response(resp);
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
    fn test_handle_transport_error_in_completed() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(200, &req);
        tx.send_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Completed);

        tx.handle_transport_error();

        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::TransportError))));
    }

    #[test]
    fn test_handle_transport_error_in_terminated_noop() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), true).unwrap();
        tx.poll_actions();

        let resp = create_response(200, &req);
        tx.send_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Terminated);

        // Transport error in Terminated should be no-op
        tx.handle_transport_error();
        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_handle_request_in_trying_no_retransmit() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), false).unwrap();
        tx.poll_actions();

        // Retransmit in Trying should not send anything (no response yet)
        tx.handle_request(req);

        let actions = tx.poll_actions();
        assert!(actions.iter().all(|a| !matches!(a, Action::Send(_))));
    }

    #[test]
    fn test_handle_request_in_proceeding_retransmits() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(100, &req);
        tx.send_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Proceeding);

        // Retransmit in Proceeding should resend last response
        tx.handle_request(req);

        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
    }

    #[test]
    fn test_handle_request_in_terminated_ignored() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), true).unwrap();
        tx.poll_actions();

        let resp = create_response(200, &req);
        tx.send_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Terminated);

        // Retransmit in Terminated should be ignored
        tx.handle_request(req);

        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_multiple_provisional_in_proceeding() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), false).unwrap();
        tx.poll_actions();

        let resp1 = create_response(100, &req);
        tx.send_response(resp1);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Proceeding);

        // Another provisional in Proceeding
        let resp2 = create_response(183, &req);
        tx.send_response(resp2);

        assert_eq!(tx.state(), State::Proceeding);
        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
    }

    #[test]
    fn test_send_response_in_completed_ignored() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(200, &req);
        tx.send_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Completed);

        // Response in Completed should be ignored
        let resp2 = create_response(404, &req);
        tx.send_response(resp2);

        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_send_response_in_terminated_ignored() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), true).unwrap();
        tx.poll_actions();

        let resp = create_response(200, &req);
        tx.send_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Terminated);

        // Response in Terminated should be ignored
        let resp2 = create_response(404, &req);
        tx.send_response(resp2);

        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_unexpected_timer_ignored() {
        let req = create_register();
        let mut tx = NonInviteServerTransaction::new(req.clone(), false).unwrap();
        tx.poll_actions();

        // Timer in Trying should be ignored
        tx.handle_timeout(Timer::J);
        assert_eq!(tx.state(), State::Trying);

        // Send response to move to Proceeding
        let resp = create_response(100, &req);
        tx.send_response(resp);
        tx.poll_actions();

        // Timer J in Proceeding should be ignored
        tx.handle_timeout(Timer::J);
        assert_eq!(tx.state(), State::Proceeding);

        // Timer A in Proceeding should be ignored
        tx.handle_timeout(Timer::A);
        assert_eq!(tx.state(), State::Proceeding);
    }

    #[test]
    fn test_state_debug() {
        let state = State::Trying;
        let debug_str = format!("{:?}", state);
        assert!(debug_str.contains("Trying"));
    }

    #[test]
    fn test_action_debug() {
        let action = Action::CancelTimer(Timer::J);
        let debug_str = format!("{:?}", action);
        assert!(debug_str.contains("CancelTimer"));
    }

    #[test]
    fn test_event_debug() {
        let event = Event::TransportError;
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("TransportError"));
    }

    #[test]
    fn test_request_accessor() {
        let req = create_register();
        let tx = NonInviteServerTransaction::new(req.clone(), false).unwrap();
        assert_eq!(tx.request().method(), Method::Register);
    }

    #[test]
    fn test_id_accessor() {
        let req = create_register();
        let tx = NonInviteServerTransaction::new(req, false).unwrap();
        let id = tx.id();
        assert!(id.branch.contains("z9hG4bK"));
    }

    #[test]
    fn test_action_event_clone() {
        let action = Action::Event(Event::TransportError);
        let cloned = action.clone();
        assert!(matches!(cloned, Action::Event(Event::TransportError)));
    }

    #[test]
    fn test_action_send_clone() {
        let action = Action::Send(bytes::Bytes::from("test"));
        let cloned = action.clone();
        assert!(matches!(cloned, Action::Send(_)));
    }
}

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

use std::time::Duration;
use mdsiprtp_sip::{SipRequest, SipResponse, Method};
use crate::timer::{Timer, TimerValues};
use super::invite::TransactionId;

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
            tx.actions.push(Action::SetTimer(Timer::E, tx.retransmit_interval));
        }

        // Start Timer F
        tx.actions.push(Action::SetTimer(Timer::F, tx.timers.timer_f()));

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
                self.actions.push(Action::SetTimer(Timer::E, self.retransmit_interval));
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
                    self.actions.push(Action::Event(Event::Provisional(response)));
                } else if code >= 200 {
                    // Final response - transition to Completed
                    self.state = State::Completed;
                    if !self.reliable {
                        self.actions.push(Action::CancelTimer(Timer::E));
                    }
                    self.actions.push(Action::CancelTimer(Timer::F));
                    self.actions.push(Action::Event(Event::FinalResponse(response)));
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
                    self.actions.push(Action::Event(Event::Provisional(response)));
                } else if code >= 200 {
                    // Final response - transition to Completed
                    self.state = State::Completed;
                    if !self.reliable {
                        self.actions.push(Action::CancelTimer(Timer::E));
                    }
                    self.actions.push(Action::CancelTimer(Timer::F));
                    self.actions.push(Action::Event(Event::FinalResponse(response)));
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
        assert!(actions.iter().any(|a| matches!(a, Action::Event(Event::Provisional(_)))));
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
        assert!(actions.iter().any(|a| matches!(a, Action::Event(Event::FinalResponse(_)))));
        assert!(actions.iter().any(|a| matches!(a, Action::SetTimer(Timer::K, _))));
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
        assert!(actions.iter().any(|a| matches!(a, Action::Event(Event::Timeout))));
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
}

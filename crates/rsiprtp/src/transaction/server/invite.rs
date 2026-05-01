//! INVITE server transaction state machine per RFC 3261 Section 17.2.1.
//!
//! State diagram:
//! ```text
//!                               |INVITE from network
//!                               |100 sent
//!                               V
//!                    +---------+---------+
//!                    |                   |
//!                    |   Proceeding      |
//!                    |                   |
//!                    +---------+---------+
//!                               |
//!          1xx from TU         |
//!              +---------------+---------------+
//!              |                               |
//!              V                               V
//!    (stay in Proceeding)           2xx/3xx-6xx from TU
//!                                              |
//!                               +--------------+----------+
//!                               |                         |
//!                         2xx from TU              3xx-6xx from TU
//!                               |                         |
//!                               V                         V
//!                    +---------+---------+     +---------+---------+
//!                    |                   |     |                   |
//!                    |   Terminated      |     |    Completed      |
//!                    |                   |     |                   |
//!                    +-------------------+     +---------+---------+
//!                                                        |
//!                                                  ACK   |Timer G
//!                                                  +-----+-----+
//!                                                  |           |
//!                                                  V           V
//!                                        +------+-----+   (retransmit)
//!                                        |            |
//!                                        | Confirmed  |
//!                                        |            |
//!                                        +------+-----+
//!                                               |
//!                                         Timer I|
//!                                               V
//!                                        +------+-----+
//!                                        |            |
//!                                        | Terminated |
//!                                        |            |
//!                                        +------------+
//! ```

use crate::transaction::client::invite::TransactionId;
use crate::transaction::timer::{Timer, TimerValues};
use crate::sip::{Method, SipRequest, SipResponse};
use std::time::Duration;

/// State of the INVITE server transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Initial state - processing INVITE.
    Proceeding,
    /// 3xx-6xx sent - waiting for ACK.
    Completed,
    /// ACK received after 3xx-6xx.
    Confirmed,
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
    /// INVITE request received.
    Request(Box<SipRequest>),
    /// ACK received (for non-2xx responses).
    AckReceived,
    /// Transaction timed out (Timer H fired).
    Timeout,
    /// Transport error.
    TransportError,
}

/// INVITE server transaction (Sans-IO).
#[derive(Debug)]
pub struct InviteServerTransaction {
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
    /// Current retransmit interval for Timer G.
    retransmit_interval: Duration,
    /// Pending actions.
    actions: Vec<Action>,
}

impl InviteServerTransaction {
    /// Create a new INVITE server transaction from an incoming INVITE.
    ///
    /// Returns None if the request is not an INVITE.
    pub fn new(request: SipRequest, reliable: bool) -> Option<Self> {
        if request.method() != Method::Invite {
            return None;
        }
        let id = TransactionId::from_request(&request)?;
        let timers = TimerValues::default();

        let mut tx = Self {
            id,
            state: State::Proceeding,
            request: request.clone(),
            last_response: None,
            timers,
            reliable,
            retransmit_interval: timers.timer_g(),
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
            (State::Completed, Timer::G) => {
                // Retransmit last response
                if let Some(ref resp) = self.last_response {
                    self.actions.push(Action::Send(resp.clone()));
                }
                self.retransmit_interval = self.timers.next_retransmit(self.retransmit_interval);
                self.actions
                    .push(Action::SetTimer(Timer::G, self.retransmit_interval));
            }
            (State::Completed, Timer::H) => {
                // Timeout waiting for ACK
                self.state = State::Terminated;
                self.actions.push(Action::Event(Event::Timeout));
            }
            (State::Confirmed, Timer::I) => {
                // Time to terminate
                self.state = State::Terminated;
            }
            _ => {
                // Ignore unexpected timers
            }
        }
    }

    /// Handle an incoming request (retransmit or ACK).
    pub fn handle_request(&mut self, request: SipRequest) {
        match self.state {
            State::Proceeding => {
                if request.method() == Method::Invite {
                    // Retransmitted INVITE - resend last response if any
                    if let Some(ref resp) = self.last_response {
                        self.actions.push(Action::Send(resp.clone()));
                    }
                }
            }
            State::Completed => {
                if request.method() == Method::Invite {
                    // Retransmitted INVITE - resend last response
                    if let Some(ref resp) = self.last_response {
                        self.actions.push(Action::Send(resp.clone()));
                    }
                } else if request.method() == Method::Ack {
                    // ACK received - transition to Confirmed
                    self.state = State::Confirmed;
                    if !self.reliable {
                        self.actions.push(Action::CancelTimer(Timer::G));
                    }
                    self.actions.push(Action::CancelTimer(Timer::H));
                    self.actions.push(Action::Event(Event::AckReceived));
                    // Start Timer I
                    let timer_i = if self.reliable {
                        Duration::ZERO
                    } else {
                        self.timers.timer_i()
                    };
                    if timer_i.is_zero() {
                        self.state = State::Terminated;
                    } else {
                        self.actions.push(Action::SetTimer(Timer::I, timer_i));
                    }
                }
            }
            State::Confirmed => {
                // Absorb any additional ACKs
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
            State::Proceeding => {
                if (100..200).contains(&code) {
                    // Provisional response
                    self.last_response = Some(resp_bytes.clone());
                    self.actions.push(Action::Send(resp_bytes));
                } else if (200..300).contains(&code) {
                    // 2xx response - terminate (TU handles ACK)
                    self.state = State::Terminated;
                    self.actions.push(Action::Send(resp_bytes));
                } else if code >= 300 {
                    // 3xx-6xx response - transition to Completed
                    self.state = State::Completed;
                    self.last_response = Some(resp_bytes.clone());
                    self.actions.push(Action::Send(resp_bytes));
                    // Start Timer G (for unreliable) and Timer H
                    if !self.reliable {
                        self.actions
                            .push(Action::SetTimer(Timer::G, self.retransmit_interval));
                    }
                    self.actions
                        .push(Action::SetTimer(Timer::H, self.timers.timer_h()));
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
            State::Proceeding | State::Completed => {
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

    fn create_response(code: u16, req: &SipRequest) -> SipResponse {
        SipResponse::builder()
            .status(code, "Test")
            .from_request(req)
            .to_tag("totag")
            .build()
            .unwrap()
    }

    fn create_ack() -> SipRequest {
        SipRequest::builder()
            .method(Method::Ack)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap()
    }

    #[test]
    fn test_new_transaction() {
        let invite = create_invite();
        let tx = InviteServerTransaction::new(invite, false).unwrap();
        assert_eq!(tx.state(), State::Proceeding);
        assert!(!tx.is_terminated());
    }

    #[test]
    fn test_provisional_response() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(180, &invite);
        tx.send_response(resp);

        assert_eq!(tx.state(), State::Proceeding);
        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
    }

    #[test]
    fn test_success_response_terminates() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(200, &invite);
        tx.send_response(resp);

        assert_eq!(tx.state(), State::Terminated);
    }

    #[test]
    fn test_failure_response() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);

        assert_eq!(tx.state(), State::Completed);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::G, _))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::H, _))));
    }

    #[test]
    fn test_ack_received() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        let ack = create_ack();
        tx.handle_request(ack);

        assert_eq!(tx.state(), State::Confirmed);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::AckReceived))));
    }

    #[test]
    fn test_timer_h_timeout() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        tx.handle_timeout(Timer::H);

        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Timeout))));
    }

    #[test]
    fn test_timer_i_terminates() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        let ack = create_ack();
        tx.handle_request(ack);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Confirmed);

        tx.handle_timeout(Timer::I);
        assert_eq!(tx.state(), State::Terminated);
    }

    #[test]
    fn test_reliable_transport() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), true).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);

        let actions = tx.poll_actions();
        // Should NOT have Timer G for reliable transport
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::G, _))));
        // Should have Timer H
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::H, _))));
    }

    // Additional tests for uncovered code paths

    #[test]
    fn test_reject_non_invite() {
        let register = SipRequest::builder()
            .method(Method::Register)
            .uri("sip:example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:alice@example.com")
            .call_id("register@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let tx = InviteServerTransaction::new(register, false);
        assert!(tx.is_none());
    }

    #[test]
    fn test_transaction_id() {
        let invite = create_invite();
        let tx = InviteServerTransaction::new(invite, false).unwrap();
        let id = tx.id();
        assert!(!id.branch.is_empty());
    }

    #[test]
    fn test_request_accessor() {
        let invite = create_invite();
        let tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        assert_eq!(tx.request().method(), Method::Invite);
    }

    #[test]
    fn test_timer_g_retransmit() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Completed);

        // Timer G should retransmit last response
        tx.handle_timeout(Timer::G);

        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::G, _))));
    }

    #[test]
    fn test_timer_g_without_last_response() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        tx.last_response = None;
        tx.handle_timeout(Timer::G);

        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::G, _))));
        assert!(actions.iter().all(|a| !matches!(a, Action::Send(_))));
    }

    #[test]
    fn test_invite_retransmit_in_proceeding() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // Send provisional response
        let resp = create_response(100, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Proceeding);

        // Retransmitted INVITE should trigger response retransmit
        tx.handle_request(invite);

        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
    }

    #[test]
    fn test_non_invite_request_in_proceeding_ignored() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        let ack = create_ack();
        tx.handle_request(ack);

        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_invite_retransmit_in_proceeding_no_response() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // No provisional sent yet
        assert_eq!(tx.state(), State::Proceeding);

        // Retransmitted INVITE - no response to send
        tx.handle_request(invite);

        let actions = tx.poll_actions();
        // No actions since no response stored yet
        assert!(actions.is_empty());
    }

    #[test]
    fn test_invite_retransmit_in_completed() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Completed);

        // Retransmitted INVITE should trigger response retransmit
        tx.handle_request(invite);

        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
    }

    #[test]
    fn test_invite_retransmit_in_completed_without_response() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        tx.last_response = None;
        tx.handle_request(invite);

        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_non_invite_request_in_completed_ignored() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        let bye = SipRequest::builder()
            .method(Method::Bye)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("test@example.com")
            .cseq(2)
            .build()
            .unwrap();

        tx.handle_request(bye);

        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_ack_absorbed_in_confirmed() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        let ack = create_ack();
        tx.handle_request(ack.clone());
        tx.poll_actions();

        assert_eq!(tx.state(), State::Confirmed);

        // Additional ACK should be absorbed silently
        tx.handle_request(ack);

        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_request_in_terminated_ignored() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), true).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        let ack = create_ack();
        tx.handle_request(ack);
        // Reliable transport goes directly to Terminated
        assert_eq!(tx.state(), State::Terminated);
        tx.poll_actions();

        // Request in Terminated should be ignored
        tx.handle_request(invite);
        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_reliable_transport_ack_terminates() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), true).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        let ack = create_ack();
        tx.handle_request(ack);

        // Reliable transport should go directly to Terminated (Timer I = 0)
        assert_eq!(tx.state(), State::Terminated);
    }

    #[test]
    fn test_response_in_completed_ignored() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Completed);

        // Additional response should be ignored
        let resp2 = create_response(500, &invite);
        tx.send_response(resp2);

        assert_eq!(tx.state(), State::Completed);
        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_transport_error_in_proceeding() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        tx.handle_transport_error();

        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::TransportError))));
    }

    #[test]
    fn test_transport_error_in_completed() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        tx.handle_transport_error();

        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::TransportError))));
    }

    #[test]
    fn test_transport_error_in_confirmed_ignored() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        let ack = create_ack();
        tx.handle_request(ack);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Confirmed);

        tx.handle_transport_error();
        // Should stay in Confirmed
        assert_eq!(tx.state(), State::Confirmed);
    }

    #[test]
    fn test_unexpected_timer_ignored() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // Timer G in Proceeding should be ignored
        tx.handle_timeout(Timer::G);
        assert_eq!(tx.state(), State::Proceeding);

        // Timer H in Proceeding should be ignored
        tx.handle_timeout(Timer::H);
        assert_eq!(tx.state(), State::Proceeding);

        // Timer I in Proceeding should be ignored
        tx.handle_timeout(Timer::I);
        assert_eq!(tx.state(), State::Proceeding);
    }

    #[test]
    fn test_3xx_response() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(302, &invite);
        tx.send_response(resp);

        assert_eq!(tx.state(), State::Completed);
    }

    #[test]
    fn test_response_below_100_ignored() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(99, &invite);
        tx.send_response(resp);

        assert_eq!(tx.state(), State::Proceeding);
        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_5xx_response() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(503, &invite);
        tx.send_response(resp);

        assert_eq!(tx.state(), State::Completed);
    }

    #[test]
    fn test_6xx_response() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(603, &invite);
        tx.send_response(resp);

        assert_eq!(tx.state(), State::Completed);
    }

    #[test]
    fn test_state_debug() {
        assert_eq!(format!("{:?}", State::Proceeding), "Proceeding");
        assert_eq!(format!("{:?}", State::Completed), "Completed");
        assert_eq!(format!("{:?}", State::Confirmed), "Confirmed");
        assert_eq!(format!("{:?}", State::Terminated), "Terminated");
    }

    #[test]
    fn test_event_debug() {
        let invite = create_invite();
        let ev1 = Event::Request(Box::new(invite));
        let ev2 = Event::AckReceived;
        let ev3 = Event::Timeout;
        let ev4 = Event::TransportError;

        assert!(format!("{:?}", ev1).contains("Request"));
        assert!(format!("{:?}", ev2).contains("AckReceived"));
        assert!(format!("{:?}", ev3).contains("Timeout"));
        assert!(format!("{:?}", ev4).contains("TransportError"));
    }

    #[test]
    fn test_action_debug() {
        let action1 = Action::Send(bytes::Bytes::from_static(b"test"));
        let action2 = Action::SetTimer(Timer::G, Duration::from_secs(1));
        let action3 = Action::CancelTimer(Timer::H);

        assert!(format!("{:?}", action1).contains("Send"));
        assert!(format!("{:?}", action2).contains("SetTimer"));
        assert!(format!("{:?}", action3).contains("CancelTimer"));
    }

    #[test]
    fn test_multiple_100_responses() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // First 100
        let resp1 = create_response(100, &invite);
        tx.send_response(resp1);
        assert_eq!(tx.state(), State::Proceeding);
        tx.poll_actions();

        // Second provisional (180)
        let resp2 = create_response(180, &invite);
        tx.send_response(resp2);
        assert_eq!(tx.state(), State::Proceeding);
        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
    }

    #[test]
    fn test_ack_cancels_timers() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(404, &invite);
        tx.send_response(resp);
        tx.poll_actions();

        let ack = create_ack();
        tx.handle_request(ack);

        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::CancelTimer(Timer::G))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::CancelTimer(Timer::H))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::I, _))));
    }

    #[test]
    fn test_initial_request_event() {
        let invite = create_invite();
        let tx = InviteServerTransaction::new(invite, false).unwrap();

        let actions = tx.actions.clone();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Request(_)))));
    }
}

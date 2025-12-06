//! INVITE client transaction state machine per RFC 3261 Section 17.1.1.
//!
//! State diagram:
//! ```text
//!                    |INVITE from TU
//!                    |INVITE sent
//!                Timer A fires     V
//!                  +------+  +--+---+
//!                  |      |  |      |
//!                  V      +->|Calling|
//!                  +-------+ +--+---+
//!                               |
//!                               |1xx from network
//!                               |
//!                  +------------V-----------+
//!                  |                        |
//!                  |      Proceeding        |
//!                  |                        |
//!                  +------------+-----------+
//!                               |
//!                 300-699       |   2xx
//!                 +-------------+----------+
//!                 |                        |
//!                 V                        V
//!       +---------+---------+    +---------+---------+
//!       |                   |    |                   |
//!       |    Completed      |    |   Terminated      |
//!       |                   |    |                   |
//!       +---------+---------+    +-------------------+
//!                 |
//!                 |Timer D fires
//!                 V
//!       +---------+---------+
//!       |                   |
//!       |   Terminated      |
//!       |                   |
//!       +-------------------+
//! ```

use std::time::Duration;
use mdsiprtp_sip::{SipRequest, SipResponse, Method};
use crate::timer::{Timer, TimerValues};

/// Transaction ID for matching responses to requests.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionId {
    /// Via branch parameter.
    pub branch: String,
    /// CSeq method.
    pub method: Method,
}

impl TransactionId {
    /// Create a transaction ID from a request.
    pub fn from_request(req: &SipRequest) -> Option<Self> {
        let branch = req.via_branch().ok()?;
        Some(Self {
            branch,
            method: req.method(),
        })
    }

    /// Create a transaction ID from a response.
    pub fn from_response(resp: &SipResponse) -> Option<Self> {
        let branch = resp.via_branch().ok()?;
        let method = resp.cseq_method().ok()?;
        Some(Self { branch, method })
    }
}

/// State of the INVITE client transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Initial state - INVITE has been sent.
    Calling,
    /// 1xx received - waiting for final response.
    Proceeding,
    /// 3xx-6xx received - waiting for Timer D.
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
    /// Success response received (2xx) - transaction terminates.
    Success(SipResponse),
    /// Failure response received (3xx-6xx).
    Failure(SipResponse),
    /// Transaction timed out (Timer B fired).
    Timeout,
    /// Transport error.
    TransportError,
}

/// INVITE client transaction (Sans-IO).
#[derive(Debug)]
pub struct InviteClientTransaction {
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
    /// Current retransmit interval for Timer A.
    retransmit_interval: Duration,
    /// Pending actions.
    actions: Vec<Action>,
}

impl InviteClientTransaction {
    /// Create a new INVITE client transaction.
    ///
    /// # Panics
    /// Panics if the request is not an INVITE.
    pub fn new(request: SipRequest, reliable: bool) -> Option<Self> {
        if request.method() != Method::Invite {
            return None;
        }
        let id = TransactionId::from_request(&request)?;
        let timers = TimerValues::default();
        let retransmit_interval = timers.timer_a();

        let mut tx = Self {
            id,
            state: State::Calling,
            request,
            timers,
            reliable,
            retransmit_interval,
            actions: Vec::new(),
        };

        // Send the request
        tx.actions.push(Action::Send(tx.request.to_bytes()));

        // For unreliable transport, start Timer A
        if !reliable {
            tx.actions.push(Action::SetTimer(Timer::A, tx.retransmit_interval));
        }

        // Start Timer B
        tx.actions.push(Action::SetTimer(Timer::B, tx.timers.timer_b()));

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
            (State::Calling, Timer::A) => {
                // Retransmit and restart Timer A with doubled interval
                self.actions.push(Action::Send(self.request.to_bytes()));
                self.retransmit_interval = self.timers.next_retransmit(self.retransmit_interval);
                self.actions.push(Action::SetTimer(Timer::A, self.retransmit_interval));
            }
            (State::Calling, Timer::B) => {
                // Transaction timeout
                self.state = State::Terminated;
                self.actions.push(Action::Event(Event::Timeout));
            }
            (State::Proceeding, Timer::B) => {
                // Transaction timeout (Timer B still running in Proceeding)
                self.state = State::Terminated;
                self.actions.push(Action::Event(Event::Timeout));
            }
            (State::Completed, Timer::D) => {
                // Timer D fired - terminate
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
            State::Calling => {
                if (100..200).contains(&code) {
                    // Provisional response - transition to Proceeding
                    self.state = State::Proceeding;
                    // Cancel Timer A
                    if !self.reliable {
                        self.actions.push(Action::CancelTimer(Timer::A));
                    }
                    self.actions.push(Action::Event(Event::Provisional(response)));
                } else if (200..300).contains(&code) {
                    // 2xx response - terminate (ACK is sent by TU)
                    self.state = State::Terminated;
                    self.actions.push(Action::CancelTimer(Timer::A));
                    self.actions.push(Action::CancelTimer(Timer::B));
                    self.actions.push(Action::Event(Event::Success(response)));
                } else if code >= 300 {
                    // 3xx-6xx response - send ACK and transition to Completed
                    self.state = State::Completed;
                    self.actions.push(Action::CancelTimer(Timer::A));
                    self.actions.push(Action::CancelTimer(Timer::B));
                    self.send_ack(&response);
                    self.actions.push(Action::Event(Event::Failure(response)));
                    // Start Timer D
                    let timer_d = if self.reliable {
                        Duration::ZERO
                    } else {
                        self.timers.timer_d()
                    };
                    if timer_d.is_zero() {
                        self.state = State::Terminated;
                    } else {
                        self.actions.push(Action::SetTimer(Timer::D, timer_d));
                    }
                }
            }
            State::Proceeding => {
                if (100..200).contains(&code) {
                    // Another provisional response
                    self.actions.push(Action::Event(Event::Provisional(response)));
                } else if (200..300).contains(&code) {
                    // 2xx response - terminate (ACK is sent by TU)
                    self.state = State::Terminated;
                    self.actions.push(Action::CancelTimer(Timer::B));
                    self.actions.push(Action::Event(Event::Success(response)));
                } else if code >= 300 {
                    // 3xx-6xx response - send ACK and transition to Completed
                    self.state = State::Completed;
                    self.actions.push(Action::CancelTimer(Timer::B));
                    self.send_ack(&response);
                    self.actions.push(Action::Event(Event::Failure(response)));
                    // Start Timer D
                    let timer_d = if self.reliable {
                        Duration::ZERO
                    } else {
                        self.timers.timer_d()
                    };
                    if timer_d.is_zero() {
                        self.state = State::Terminated;
                    } else {
                        self.actions.push(Action::SetTimer(Timer::D, timer_d));
                    }
                }
            }
            State::Completed => {
                if code >= 300 {
                    // Retransmitted response - resend ACK
                    self.send_ack(&response);
                }
            }
            State::Terminated => {
                // Ignore responses in Terminated state
            }
        }
    }

    /// Generate and queue an ACK for a non-2xx response.
    fn send_ack(&mut self, _response: &SipResponse) {
        // Build ACK request with same branch as INVITE
        // Per RFC 3261 17.1.1.3, ACK for non-2xx uses same branch
        let ack = build_ack_for_non_2xx(&self.request);
        if let Some(ack) = ack {
            self.actions.push(Action::Send(ack.to_bytes()));
        }
    }

    /// Drain pending actions.
    pub fn poll_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.actions)
    }

    /// Handle a transport error.
    pub fn handle_transport_error(&mut self) {
        match self.state {
            State::Calling | State::Proceeding => {
                self.state = State::Terminated;
                self.actions.push(Action::Event(Event::TransportError));
            }
            _ => {}
        }
    }
}

/// Build an ACK for a non-2xx final response.
fn build_ack_for_non_2xx(invite: &SipRequest) -> Option<SipRequest> {
    // Per RFC 3261 17.1.1.3:
    // - Request-URI: same as INVITE
    // - Call-ID, From, CSeq (with ACK method): same as INVITE
    // - Via: same top Via as INVITE (same branch)
    // - To: same as INVITE but add tag from response (handled separately)
    let branch = invite.via_branch().ok()?;
    let from_tag = invite.from_tag().ok()?;
    let call_id = invite.call_id().ok()?;

    let ack = SipRequest::builder()
        .method(Method::Ack)
        .uri(&invite.uri().to_string())
        .via("placeholder", 5060, "UDP", &branch) // Will need proper via
        .from(&invite.from_uri().ok()?.to_string(), &from_tag)
        .to(&invite.to_uri().ok()?.to_string())
        .call_id(&call_id)
        .cseq(invite.cseq().ok()?)
        .build()
        .ok()?;

    Some(ack)
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

    fn create_response(code: u16) -> SipResponse {
        let invite = create_invite();
        SipResponse::builder()
            .status(code, "Test")
            .from_request(&invite)
            .to_tag("totag")
            .build()
            .unwrap()
    }

    #[test]
    fn test_new_transaction() {
        let invite = create_invite();
        let tx = InviteClientTransaction::new(invite, false).unwrap();
        assert_eq!(tx.state(), State::Calling);
        assert!(!tx.is_terminated());
    }

    #[test]
    fn test_provisional_response() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions(); // Clear initial actions

        let resp = create_response(180);
        tx.handle_response(resp);

        assert_eq!(tx.state(), State::Proceeding);
        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Event(Event::Provisional(_)))));
    }

    #[test]
    fn test_success_response() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        let resp = create_response(200);
        tx.handle_response(resp);

        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Event(Event::Success(_)))));
    }

    #[test]
    fn test_failure_response_unreliable() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        let resp = create_response(404);
        tx.handle_response(resp);

        assert_eq!(tx.state(), State::Completed);
        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Event(Event::Failure(_)))));
        assert!(actions.iter().any(|a| matches!(a, Action::SetTimer(Timer::D, _))));
    }

    #[test]
    fn test_failure_response_reliable() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, true).unwrap();
        tx.poll_actions();

        let resp = create_response(404);
        tx.handle_response(resp);

        // For reliable transport, goes directly to Terminated (Timer D = 0)
        assert_eq!(tx.state(), State::Terminated);
    }

    #[test]
    fn test_timer_b_timeout() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, true).unwrap();
        tx.poll_actions();

        tx.handle_timeout(Timer::B);

        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Event(Event::Timeout))));
    }

    #[test]
    fn test_timer_a_retransmit() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        tx.handle_timeout(Timer::A);

        assert_eq!(tx.state(), State::Calling);
        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
    }

    #[test]
    fn test_timer_d_terminates() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        let resp = create_response(404);
        tx.handle_response(resp);
        tx.poll_actions();

        assert_eq!(tx.state(), State::Completed);

        tx.handle_timeout(Timer::D);
        assert_eq!(tx.state(), State::Terminated);
    }
}

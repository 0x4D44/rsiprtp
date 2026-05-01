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

use crate::sip::{Method, SipRequest, SipResponse, Via};
use crate::transaction::timer::{Timer, TimerValues};
use std::time::Duration;

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
            tx.actions
                .push(Action::SetTimer(Timer::A, tx.retransmit_interval));
        }

        // Start Timer B
        tx.actions
            .push(Action::SetTimer(Timer::B, tx.timers.timer_b()));

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
                self.actions
                    .push(Action::SetTimer(Timer::A, self.retransmit_interval));
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
                    self.actions
                        .push(Action::Event(Event::Provisional(response)));
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
                    self.actions
                        .push(Action::Event(Event::Provisional(response)));
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
                // RFC 3261 §13.2.2.4: 2xx responses from forked branches
                // arrive after the transaction has terminated; the TU
                // must still see them so it can ACK each forked 2xx and
                // decide which dialog to keep. Non-2xx responses in
                // Terminated remain ignored.
                if (200..300).contains(&code) {
                    self.actions.push(Action::Event(Event::Success(response)));
                }
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
fn parse_via_or_default(via_raw: Option<&str>, branch: &str) -> Via {
    via_raw
        .and_then(|v| Via::parse(v).ok())
        .unwrap_or_else(|| Via {
            protocol: "UDP".to_string(),
            host: "0.0.0.0".to_string(),
            port: 5060,
            branch: branch.to_string(),
            received: None,
            rport: None,
        })
}

fn build_ack_for_non_2xx(invite: &SipRequest) -> Option<SipRequest> {
    // Per RFC 3261 17.1.1.3:
    // - Request-URI: same as INVITE
    // - Call-ID, From, CSeq (with ACK method): same as INVITE
    // - Via: same top Via as INVITE (same branch)
    // - To: same as INVITE but add tag from response (handled separately)
    let branch = invite.via_branch().ok()?;
    let call_id = invite.call_id().ok()?;
    let (from_tag, from_uri) = invite.from_tag_and_uri().ok()?;

    // Extract Via header information from original INVITE
    let via_raw = invite.via_headers_raw();
    let via = parse_via_or_default(via_raw.first().map(String::as_str), &branch);

    SipRequest::builder()
        .method(Method::Ack)
        .uri(&invite.uri().to_string())
        .via(&via.host, via.port, &via.protocol, &branch)
        .from(&from_uri.to_string(), &from_tag)
        .to(&invite.to_uri().ok()?.to_string())
        .call_id(&call_id)
        .cseq(invite.cseq().ok()?)
        .build()
        .ok()
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

    fn parse_request(raw: &[u8]) -> SipRequest {
        let msg = crate::sip::SipMessage::parse(raw).unwrap();
        msg.as_request().unwrap().clone()
    }

    fn parse_response(raw: &[u8]) -> SipResponse {
        let msg = crate::sip::SipMessage::parse(raw).unwrap();
        msg.as_response().unwrap().clone()
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
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Provisional(_)))));
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
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Success(_)))));
    }

    /// RFC 3261 §13.2.2.4: when a forking proxy fans out an INVITE,
    /// each forked UAS may answer with its own 2xx. The first 2xx
    /// terminates the INVITE client transaction, but every subsequent
    /// 2xx (carrying a *different* To-tag — distinct early dialog) must
    /// still reach the TU so it can ACK that fork and decide which
    /// dialog to keep. The transaction's `Terminated` state must not
    /// swallow these.
    #[test]
    fn test_forked_2xx_after_first_2xx_reaches_tu() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // First 2xx — terminates the transaction normally.
        let first = SipResponse::builder()
            .status(200, "OK")
            .from_request(&invite)
            .to_tag("fork-A")
            .build()
            .unwrap();
        tx.handle_response(first);
        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        let first_tag = actions
            .iter()
            .find_map(|a| match a {
                Action::Event(Event::Success(r)) => r.to_tag(),
                _ => None,
            })
            .expect("first 2xx must produce a Success event");
        assert_eq!(first_tag, "fork-A");

        // Second 2xx — same INVITE, different forked UAS, different
        // To-tag. The TU must see this so it can ACK fork-B and BYE
        // the loser.
        let second = SipResponse::builder()
            .status(200, "OK")
            .from_request(&invite)
            .to_tag("fork-B")
            .build()
            .unwrap();
        tx.handle_response(second);
        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        let second_tag = actions
            .iter()
            .find_map(|a| match a {
                Action::Event(Event::Success(r)) => r.to_tag(),
                _ => None,
            })
            .expect("forked 2xx (fork-B) must reach the TU per RFC 3261 §13.2.2.4");
        assert_eq!(second_tag, "fork-B");
    }

    #[test]
    fn test_calling_response_below_100_ignored() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        let resp = create_response(99);
        tx.handle_response(resp);

        assert_eq!(tx.state(), State::Calling);
        assert!(tx.poll_actions().is_empty());
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
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Failure(_)))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::D, _))));
    }

    #[test]
    fn test_proceeding_response_below_100_ignored() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        let provisional = create_response(180);
        tx.handle_response(provisional);
        tx.poll_actions();

        let resp = create_response(99);
        tx.handle_response(resp);

        assert_eq!(tx.state(), State::Proceeding);
        assert!(tx.poll_actions().is_empty());
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
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Timeout))));
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

    // Additional tests for better coverage

    #[test]
    fn test_transaction_id_from_request() {
        let invite = create_invite();
        let id = TransactionId::from_request(&invite).unwrap();
        assert_eq!(id.branch, "z9hG4bKtest");
        assert_eq!(id.method, Method::Invite);
    }

    #[test]
    fn test_transaction_id_from_response() {
        let resp = create_response(200);
        // The response should have Via and CSeq from the original INVITE
        let id = TransactionId::from_response(&resp).expect("Expected TransactionId");
        assert_eq!(id.branch, "z9hG4bKtest");
        assert_eq!(id.method, Method::Invite);
    }

    #[test]
    fn test_transaction_id_eq() {
        let id1 = TransactionId {
            branch: "z9hG4bKtest".to_string(),
            method: Method::Invite,
        };
        let id2 = TransactionId {
            branch: "z9hG4bKtest".to_string(),
            method: Method::Invite,
        };
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_transaction_id_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        let id = TransactionId {
            branch: "z9hG4bKtest".to_string(),
            method: Method::Invite,
        };
        set.insert(id.clone());
        assert!(set.contains(&id));
    }

    #[test]
    fn test_transaction_id_debug() {
        let id = TransactionId {
            branch: "z9hG4bKtest".to_string(),
            method: Method::Invite,
        };
        let debug = format!("{:?}", id);
        assert!(debug.contains("TransactionId"));
    }

    #[test]
    fn test_new_non_invite_returns_none() {
        let req = SipRequest::builder()
            .method(Method::Register)
            .uri("sip:registrar@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:alice@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();
        let result = InviteClientTransaction::new(req, false);
        assert!(result.is_none());
    }

    #[test]
    fn test_reliable_transport_no_timer_a() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, true).unwrap();
        let actions = tx.poll_actions();

        // Should have Send and SetTimer(B), but NOT SetTimer(A)
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::B, _))));
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::A, _))));
    }

    #[test]
    fn test_transaction_id_accessor() {
        let invite = create_invite();
        let tx = InviteClientTransaction::new(invite, false).unwrap();
        let id = tx.id();
        assert_eq!(id.branch, "z9hG4bKtest");
    }

    #[test]
    fn test_handle_transport_error_calling() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        tx.handle_transport_error();

        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::TransportError))));
    }

    #[test]
    fn test_handle_transport_error_proceeding() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // First go to Proceeding
        let resp = create_response(180);
        tx.handle_response(resp);
        assert_eq!(tx.state(), State::Proceeding);
        tx.poll_actions();

        // Then transport error
        tx.handle_transport_error();
        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::TransportError))));
    }

    #[test]
    fn test_handle_transport_error_completed_ignored() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // Go to Completed
        let resp = create_response(404);
        tx.handle_response(resp);
        assert_eq!(tx.state(), State::Completed);
        tx.poll_actions();

        // Transport error should be ignored in Completed state
        tx.handle_transport_error();
        assert_eq!(tx.state(), State::Completed);
    }

    #[test]
    fn test_timer_b_timeout_in_proceeding() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // Go to Proceeding
        let resp = create_response(180);
        tx.handle_response(resp);
        assert_eq!(tx.state(), State::Proceeding);
        tx.poll_actions();

        // Timer B fires in Proceeding
        tx.handle_timeout(Timer::B);
        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Timeout))));
    }

    #[test]
    fn test_unexpected_timer_ignored() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // Timer D in Calling state should be ignored
        tx.handle_timeout(Timer::D);
        assert_eq!(tx.state(), State::Calling);
    }

    #[test]
    fn test_proceeding_another_provisional() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // First provisional
        let resp1 = create_response(100);
        tx.handle_response(resp1);
        assert_eq!(tx.state(), State::Proceeding);
        tx.poll_actions();

        // Second provisional
        let resp2 = create_response(180);
        tx.handle_response(resp2);
        assert_eq!(tx.state(), State::Proceeding);
        let actions = tx.poll_actions();
        let has_provisional = actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Provisional(_))));
        assert!(has_provisional);
    }

    #[test]
    fn test_proceeding_success_response() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // Go to Proceeding
        let resp1 = create_response(180);
        tx.handle_response(resp1);
        assert_eq!(tx.state(), State::Proceeding);
        tx.poll_actions();

        // Success response
        let resp2 = create_response(200);
        tx.handle_response(resp2);
        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Success(_)))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::CancelTimer(Timer::B))));
    }

    #[test]
    fn test_proceeding_failure_response_unreliable() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // Go to Proceeding
        let resp1 = create_response(180);
        tx.handle_response(resp1);
        assert_eq!(tx.state(), State::Proceeding);
        tx.poll_actions();

        // Failure response
        let resp2 = create_response(486);
        tx.handle_response(resp2);
        assert_eq!(tx.state(), State::Completed);
        let actions = tx.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Failure(_)))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::D, _))));
    }

    #[test]
    fn test_proceeding_failure_response_reliable() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, true).unwrap();
        tx.poll_actions();

        // Go to Proceeding
        let resp1 = create_response(180);
        tx.handle_response(resp1);
        assert_eq!(tx.state(), State::Proceeding);
        tx.poll_actions();

        // Failure response - should terminate immediately for reliable
        let resp2 = create_response(486);
        tx.handle_response(resp2);
        assert_eq!(tx.state(), State::Terminated);
    }

    #[test]
    fn test_completed_retransmitted_response() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // Go to Completed
        let resp = create_response(404);
        tx.handle_response(resp);
        assert_eq!(tx.state(), State::Completed);
        tx.poll_actions();

        // Retransmitted response - should resend ACK
        let resp2 = create_response(404);
        tx.handle_response(resp2);
        assert_eq!(tx.state(), State::Completed);
        let actions = tx.poll_actions();
        // ACK should be sent
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
    }

    #[test]
    fn test_terminated_response_ignored() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // Go to Terminated
        let resp = create_response(200);
        tx.handle_response(resp);
        assert_eq!(tx.state(), State::Terminated);
        tx.poll_actions();

        // Response in Terminated should be ignored
        let resp2 = create_response(180);
        tx.handle_response(resp2);
        assert_eq!(tx.state(), State::Terminated);
        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    #[allow(clippy::clone_on_copy)] // exercise derived Clone for coverage
    fn test_state_enum_clone() {
        let state = State::Calling;
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }

    #[test]
    fn test_state_enum_debug() {
        assert!(format!("{:?}", State::Calling).contains("Calling"));
        assert!(format!("{:?}", State::Proceeding).contains("Proceeding"));
        assert!(format!("{:?}", State::Completed).contains("Completed"));
        assert!(format!("{:?}", State::Terminated).contains("Terminated"));
    }

    #[test]
    fn test_state_enum_copy() {
        let state = State::Proceeding;
        let copied: State = state; // Copy
        assert_eq!(state, copied);
    }

    #[test]
    fn test_action_debug() {
        let action = Action::SetTimer(Timer::A, Duration::from_millis(500));
        let debug = format!("{:?}", action);
        assert!(debug.contains("SetTimer"));
    }

    #[test]
    fn test_action_clone() {
        let action = Action::CancelTimer(Timer::B);
        let cloned = action.clone();
        assert!(format!("{cloned:?}").contains("CancelTimer"));
    }

    #[test]
    fn test_event_debug() {
        let event = Event::Timeout;
        let debug = format!("{:?}", event);
        assert!(debug.contains("Timeout"));
    }

    #[test]
    fn test_event_clone() {
        let event = Event::TransportError;
        let cloned = event.clone();
        assert!(format!("{cloned:?}").contains("TransportError"));
    }

    #[test]
    fn test_invite_client_transaction_debug() {
        let invite = create_invite();
        let tx = InviteClientTransaction::new(invite, false).unwrap();
        let debug = format!("{:?}", tx);
        assert!(debug.contains("InviteClientTransaction"));
    }

    #[test]
    fn test_calling_2xx_cancels_timers() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        let resp = create_response(200);
        tx.handle_response(resp);

        let actions = tx.poll_actions();
        // Should cancel both Timer A and Timer B
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::CancelTimer(Timer::A))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::CancelTimer(Timer::B))));
    }

    #[test]
    fn test_calling_3xx_cancels_timers() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        let resp = create_response(302);
        tx.handle_response(resp);

        let actions = tx.poll_actions();
        // Should cancel both Timer A and Timer B
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::CancelTimer(Timer::A))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::CancelTimer(Timer::B))));
    }

    #[test]
    fn test_proceeding_3xx_transitions_completed() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        let provisional = create_response(180);
        tx.handle_response(provisional);
        assert_eq!(tx.state(), State::Proceeding);
        tx.poll_actions();

        let resp = create_response(404);
        tx.handle_response(resp);
        assert_eq!(tx.state(), State::Completed);
    }

    #[test]
    fn test_send_ack_missing_headers() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060\r\n\
To: <sip:bob@example.com>\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n";
        let req = parse_request(raw);
        tx.request = req.clone();

        let resp = create_response(404);
        tx.send_ack(&resp);
        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_transaction_id_from_response_missing_cseq() {
        let raw = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK123\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>;tag=totag\r\n\
Call-ID: test@example.com\r\n\
Content-Length: 0\r\n\
\r\n";
        let resp = parse_response(raw);
        assert!(TransactionId::from_response(&resp).is_none());
    }

    #[test]
    fn test_invite_client_transaction_new_missing_branch() {
        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060\r\n\
To: <sip:bob@example.com>\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n";
        let req = parse_request(raw);
        let tx = InviteClientTransaction::new(req, false);
        assert!(tx.is_none());
    }

    #[test]
    fn test_build_ack_missing_from_tag() {
        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
To: <sip:bob@example.com>\r\n\
From: <sip:alice@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n";
        let req = parse_request(raw);
        assert!(build_ack_for_non_2xx(&req).is_none());
    }

    #[test]
    fn test_build_ack_missing_call_id() {
        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
To: <sip:bob@example.com>\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n";
        let req = parse_request(raw);
        assert!(build_ack_for_non_2xx(&req).is_none());
    }

    #[test]
    fn test_build_ack_invalid_from_uri() {
        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
To: <sip:bob@example.com>\r\n\
From: <sip:alice@[::1>;tag=fromtag\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n";
        let req = parse_request(raw);
        assert!(build_ack_for_non_2xx(&req).is_none());
    }

    #[test]
    fn test_build_ack_invalid_to_uri() {
        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
To: <sip:bob@[::1>\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n";
        let req = parse_request(raw);
        assert!(build_ack_for_non_2xx(&req).is_none());
    }

    #[test]
    fn test_build_ack_invalid_cseq() {
        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
To: <sip:bob@example.com>\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
Call-ID: test@example.com\r\n\
CSeq: abc INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n";
        let req = parse_request(raw);
        assert!(build_ack_for_non_2xx(&req).is_none());
    }

    #[test]
    fn test_parse_via_or_default_fallback() {
        let via = parse_via_or_default(Some("invalid"), "z9hG4bK-test");
        assert_eq!(via.protocol, "UDP");
        assert_eq!(via.host, "0.0.0.0");
        assert_eq!(via.port, 5060);
        assert_eq!(via.branch, "z9hG4bK-test");
    }

    #[test]
    fn test_completed_response_under_300_ignored() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // Go to Completed
        let resp = create_response(404);
        tx.handle_response(resp);
        assert_eq!(tx.state(), State::Completed);
        tx.poll_actions();

        // 2xx response in Completed state should be ignored
        let resp2 = create_response(200);
        tx.handle_response(resp2);
        assert_eq!(tx.state(), State::Completed);
        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_multiple_retransmits() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // First retransmit
        tx.handle_timeout(Timer::A);
        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::A, _))));

        // Second retransmit
        tx.handle_timeout(Timer::A);
        let actions = tx.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Send(_))));
    }

    #[test]
    fn test_timer_a_ignored_in_proceeding() {
        let invite = create_invite();
        let mut tx = InviteClientTransaction::new(invite, false).unwrap();
        tx.poll_actions();

        // Go to Proceeding
        let resp = create_response(180);
        tx.handle_response(resp);
        assert_eq!(tx.state(), State::Proceeding);
        tx.poll_actions();

        // Timer A should be ignored in Proceeding
        tx.handle_timeout(Timer::A);
        assert_eq!(tx.state(), State::Proceeding);
        let actions = tx.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_various_failure_codes() {
        // Test different 3xx-6xx codes
        for code in [300, 400, 500, 600, 603, 699] {
            let invite = create_invite();
            let mut tx = InviteClientTransaction::new(invite, false).unwrap();
            tx.poll_actions();

            let resp = create_response(code);
            tx.handle_response(resp);

            assert_eq!(tx.state(), State::Completed);
        }
    }

    #[test]
    fn test_various_provisional_codes() {
        for code in [100, 180, 181, 182, 183, 199] {
            let invite = create_invite();
            let mut tx = InviteClientTransaction::new(invite, false).unwrap();
            tx.poll_actions();

            let resp = create_response(code);
            tx.handle_response(resp);

            assert_eq!(tx.state(), State::Proceeding);
        }
    }

    #[test]
    fn test_various_success_codes() {
        for code in [200, 201, 202, 299] {
            let invite = create_invite();
            let mut tx = InviteClientTransaction::new(invite, false).unwrap();
            tx.poll_actions();

            let resp = create_response(code);
            tx.handle_response(resp);

            assert_eq!(tx.state(), State::Terminated);
        }
    }
}

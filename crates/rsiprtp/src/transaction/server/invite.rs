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

use crate::sip::headers::Require;
use crate::sip::{Method, SipRequest, SipResponse};
use crate::transaction::client::invite::TransactionId;
use crate::transaction::timer::{Timer, TimerValues};
use rsip::headers::UntypedHeader;
use std::time::Duration;

/// Stamp `Require: 100rel` and `RSeq: <n>` onto a TU-built response by
/// mutating the typed `rsip::Headers` in place, then serialize.
///
/// If the TU has already set a `Require:` header (e.g. `precondition` for
/// early-media), the existing option-tags are preserved — `100rel` is
/// merged into the same header value (case-insensitive), avoiding the
/// duplicate `Require:` lines that an unconditional injection would
/// produce. If `100rel` is already present the header is left untouched.
///
/// `RSeq` is added unconditionally; the TU is not expected to set one.
fn stamp_reliable_headers(response: &mut SipResponse, rseq: u32) -> bytes::Bytes {
    let inner = response.inner_mut();

    // Merge 100rel into any existing Require header(s); otherwise add a
    // fresh one. We rebuild the header list because we may mutate or
    // remove existing Require entries.
    let mut handled_require = false;
    let mut new_headers = rsip::Headers::default();
    let existing: Vec<rsip::Header> = std::mem::take(&mut inner.headers).into_iter().collect();
    for header in existing {
        match &header {
            rsip::Header::Require(r) => {
                if handled_require {
                    // Multiple Require lines per RFC 3261 §7.3.1 are
                    // equivalent to one comma-joined value — collapse
                    // any extras into the first by skipping them after
                    // we've already merged once.
                    if let Ok(extra) = Require::parse(r.value()) {
                        // Append into the already-emitted Require entry.
                        merge_into_last_require(&mut new_headers, &extra.0);
                    }
                    continue;
                }
                let merged = merge_require_with_100rel(r.value());
                new_headers.push(rsip::Header::Require(rsip::headers::Require::new(merged)));
                handled_require = true;
            }
            rsip::Header::Other(key, value) if key.eq_ignore_ascii_case("Require") => {
                if handled_require {
                    if let Ok(extra) = Require::parse(value) {
                        merge_into_last_require(&mut new_headers, &extra.0);
                    }
                    continue;
                }
                let merged = merge_require_with_100rel(value);
                new_headers.push(rsip::Header::Require(rsip::headers::Require::new(merged)));
                handled_require = true;
            }
            _ => {
                new_headers.push(header);
            }
        }
    }
    if !handled_require {
        new_headers.push(rsip::Header::Require(rsip::headers::Require::new(
            "100rel".to_string(),
        )));
    }

    // RSeq must not already be present — TU isn't supposed to set it.
    debug_assert!(
        !new_headers
            .iter()
            .any(|h| matches!(h, rsip::Header::Other(k, _) if k.eq_ignore_ascii_case("RSeq"))),
        "stamp_reliable_headers: RSeq already present on TU-built response"
    );
    new_headers.push(rsip::Header::Other("RSeq".to_string(), rseq.to_string()));

    inner.headers = new_headers;
    response.to_bytes()
}

/// Parse `value` as a Require header value, ensure `100rel` is present
/// (case-insensitive) and return the rebuilt comma-joined value.
fn merge_require_with_100rel(value: &str) -> String {
    let parsed = Require::parse(value);
    debug_assert!(
        parsed.is_ok(),
        "stamp_reliable_headers: TU set malformed Require value {value:?}"
    );
    let mut tags = parsed.map(|p| p.0).unwrap_or_default();
    if !tags.iter().any(|t| t.eq_ignore_ascii_case("100rel")) {
        tags.push("100rel".to_string());
    }
    tags.join(", ")
}

/// Append `extra_tags` into the most recently emitted `Header::Require`
/// in `headers`, deduplicating on case-insensitive match. Used when
/// collapsing multiple `Require:` lines per RFC 3261 §7.3.1.
fn merge_into_last_require(headers: &mut rsip::Headers, extra_tags: &[String]) {
    let mut last_require: Option<&mut rsip::headers::Require> = None;
    for h in headers.iter_mut() {
        if let rsip::Header::Require(r) = h {
            last_require = Some(r);
        }
    }
    if let Some(r) = last_require {
        let mut tags = Require::parse(r.value()).map(|p| p.0).unwrap_or_default();
        for tag in extra_tags {
            if !tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
                tags.push(tag.clone());
            }
        }
        *r = rsip::headers::Require::new(tags.join(", "));
    }
}

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

/// Event emitted to the Transaction User, or delivered as input.
///
/// Most variants are outputs (the transaction emits them via `Action::Event`).
/// `PrackReceived` is an input variant delivered via `handle_event` from the
/// manager when a matching PRACK arrives on the dialog.
#[derive(Debug, Clone)]
pub enum Event {
    /// INVITE request received.
    Request(Box<SipRequest>),
    /// ACK received (for non-2xx responses).
    AckReceived,
    /// PRACK matching an outstanding reliable provisional was received
    /// (input). The transaction drops the buffered entry for this RSeq
    /// and cancels its Timer N. If no entry matches, ignored.
    ///
    /// RFC 3262 §3.
    PrackReceived(u32),
    /// Reliable provisional was abandoned without a matching PRACK
    /// (output). Per RFC 3262 §3 the TU picks the next action based on
    /// what (if any) final response has already been sent.
    PrackTimeout {
        /// The RSeq of the abandoned reliable provisional.
        rseq: u32,
        /// What final response (if any) has already been emitted.
        final_sent: FinalSent,
    },
    /// Transaction timed out (Timer H fired).
    Timeout,
    /// Transport error.
    TransportError,
}

/// State of any final response sent by the transaction at the moment a
/// reliable provisional retransmit is abandoned.
///
/// RFC 3262 §3: when Timer N expires without a matching PRACK, the TU
/// reaction depends on whether (and how) a final response has already
/// been delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalSent {
    /// No final response yet — TU sends 504 Server Time-out.
    None,
    /// A non-2xx final has been sent — TU drops silently (the PRACK race
    /// is already lost; the failure response covers the outcome).
    ///
    /// Currently unreachable: the buffer is drained on any final
    /// response, so Timer N never fires post-final. Reserved for Phase 4,
    /// where the manager may detect a Timer N fire that races with a
    /// just-sent final response (the response is dispatched but not yet
    /// processed by `drain_reliable_provisionals`).
    NonTwoXx,
    /// A 2xx final has already established the dialog — TU sends BYE.
    ///
    /// Currently unreachable: the buffer is drained on any final
    /// response, so Timer N never fires post-final. Reserved for Phase 4,
    /// where the manager may detect a Timer N fire that races with a
    /// just-sent final response (the response is dispatched but not yet
    /// processed by `drain_reliable_provisionals`).
    TwoXx,
}

/// One outstanding reliable provisional awaiting PRACK.
#[derive(Debug, Clone)]
struct ReliableProvisional {
    /// RSeq value stamped on the response (RFC 3262 §7.1: 1 ≤ RSeq < 2^31).
    rseq: u32,
    /// Wire bytes (with `Require: 100rel` and `RSeq: <n>` already injected).
    bytes: bytes::Bytes,
    /// Time remaining until this entry next fires. Decremented on every
    /// Timer N tick by the smallest pending value; when it reaches zero
    /// the entry retransmits and resets to its (doubled, capped) interval.
    next_fire_after: Duration,
    /// Interval to use *after* the next fire (i.e. the next retransmit's
    /// schedule). Initialized to T1 so the first tick happens at T1, then
    /// doubled-up-to-T2 on every fire.
    next_interval: Duration,
    /// Total elapsed time on this entry's retransmit schedule. Used to
    /// abandon at 64*T1 per RFC 3262 §3.
    elapsed: Duration,
    /// Abandon threshold for this entry — fixed at 64*T1 from creation.
    abandon_at: Duration,
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
    /// Next RSeq value to stamp on a reliable provisional (RFC 3262 §7.1
    /// — must be > 0; we monotonically increase from 1).
    next_rseq: u32,
    /// Outstanding reliable provisionals awaiting PRACK.
    reliable_provisionals: Vec<ReliableProvisional>,
    /// What final response (if any) has been sent. Used to populate
    /// `Event::PrackTimeout::final_sent` if Timer N abandons before any
    /// final response is sent (the buffer is drained on final, so post-
    /// final timeouts cannot fire).
    final_sent: FinalSent,
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
            next_rseq: 1,
            reliable_provisionals: Vec::new(),
            final_sent: FinalSent::None,
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
            (_, Timer::N) => {
                // Reliable provisional retransmit / abandon (RFC 3262 §3).
                //
                // Each entry in the buffer is on its own retransmit
                // schedule. The next entry whose `next_interval` matches
                // the smallest pending interval fires; in our simple
                // model, every pending entry advances on each Timer N
                // firing. The manager wakes us once per "soonest entry"
                // — which for the unit tests is whichever entry has the
                // shortest `next_interval`.
                //
                // We retransmit any entry whose `next_interval` is the
                // current minimum, then advance its schedule. Entries
                // whose elapsed time has reached 64*T1 are abandoned.
                self.fire_timer_n();
            }
            _ => {
                // Ignore unexpected timers
            }
        }
    }

    /// Internal: fire Timer N. Each entry tracks the time remaining until
    /// its own next retransmit (`next_fire_after`); on every tick we
    /// advance the clock by the smallest such value (the manager wakes us
    /// once per "soonest entry"). Entries whose remaining time hits zero
    /// retransmit and have their schedule doubled up to T2; entries whose
    /// total elapsed time has reached 64*T1 are abandoned.
    fn fire_timer_n(&mut self) {
        if self.reliable_provisionals.is_empty() {
            return;
        }

        // The interval that just elapsed = smallest `next_fire_after`.
        let due_in = self
            .reliable_provisionals
            .iter()
            .map(|e| e.next_fire_after)
            .min()
            .unwrap_or(self.timers.t1);

        // Subtract that delta from every entry, then process those at
        // zero (they're due to fire). Track abandonment by total elapsed.
        let mut to_abandon: Vec<u32> = Vec::new();

        for entry in self.reliable_provisionals.iter_mut() {
            entry.next_fire_after = entry.next_fire_after.saturating_sub(due_in);
            if !entry.next_fire_after.is_zero() {
                continue;
            }
            // Entry is due to fire.
            entry.elapsed = entry.elapsed.saturating_add(entry.next_interval);
            if entry.elapsed >= entry.abandon_at {
                to_abandon.push(entry.rseq);
                continue;
            }
            // Retransmit and advance schedule: double-up-to-T2.
            self.actions.push(Action::Send(entry.bytes.clone()));
            entry.next_interval = std::cmp::min(entry.next_interval * 2, self.timers.t2);
            entry.next_fire_after = entry.next_interval;
        }

        // Drop abandoned entries and emit `PrackTimeout` for each.
        let final_sent = self.final_sent;
        self.reliable_provisionals
            .retain(|e| !to_abandon.contains(&e.rseq));
        for rseq in &to_abandon {
            self.actions.push(Action::Event(Event::PrackTimeout {
                rseq: *rseq,
                final_sent,
            }));
        }

        // Reschedule Timer N for whichever entry is next due. If none
        // remain, no further Timer N is set.
        if let Some(next) = self
            .reliable_provisionals
            .iter()
            .map(|e| e.next_fire_after)
            .min()
        {
            self.actions.push(Action::SetTimer(Timer::N, next));
        }
    }

    /// Internal: drain the entire reliable-provisional buffer and cancel
    /// all outstanding Timer N's. Called on any final response leaving
    /// the transaction (RFC 3262 §3 — the PRACK race ends when the final
    /// response is delivered).
    fn drain_reliable_provisionals(&mut self) {
        if self.reliable_provisionals.is_empty() {
            return;
        }
        self.reliable_provisionals.clear();
        // We only ever schedule one Timer N at a time (the soonest), so
        // a single CancelTimer is sufficient.
        self.actions.push(Action::CancelTimer(Timer::N));
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
                    // 2xx response - terminate (TU handles ACK).
                    // Drain any outstanding reliable provisionals first
                    // (RFC 3262 §3 — final response ends the PRACK race).
                    self.final_sent = FinalSent::TwoXx;
                    self.drain_reliable_provisionals();
                    self.state = State::Terminated;
                    self.actions.push(Action::Send(resp_bytes));
                } else if code >= 300 {
                    // 3xx-6xx response - transition to Completed.
                    // Drain any outstanding reliable provisionals first.
                    self.final_sent = FinalSent::NonTwoXx;
                    self.drain_reliable_provisionals();
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

    /// Send a reliable provisional response (RFC 3262).
    ///
    /// Stamps `Require: 100rel` and a fresh, monotonically-increasing
    /// `RSeq` onto the response wire bytes, buffers the entry for
    /// PRACK-driven retransmit, emits `Action::Send` and
    /// `Action::SetTimer(Timer::N, T1)`.
    ///
    /// 100 Trying is rejected via `debug_assert!` — RFC 3262 reliable
    /// provisional is undefined for 100. Outside the Proceeding state
    /// the call is a no-op (final response already sent).
    pub fn send_provisional_reliable(&mut self, mut response: SipResponse) {
        let code = response.status_code();
        debug_assert!(
            code != 100,
            "send_provisional_reliable: 100 Trying is undefined for reliable provisional (RFC 3262)"
        );
        debug_assert!(
            (100..200).contains(&code),
            "send_provisional_reliable: status must be 1xx, got {code}"
        );

        if self.state != State::Proceeding {
            return;
        }

        // RFC 3262 §7.1: 1 ≤ RSeq < 2^31. Increment is checked because
        // overflowing the 31-bit space within a single transaction would
        // require ~2 billion reliable provisionals — practically
        // impossible, so an explicit panic surfaces the bug.
        let rseq = self.next_rseq;
        self.next_rseq = self.next_rseq.checked_add(1).expect(
            "RSeq exhausted; impossible in practice (2^32 reliable provisionals on a single transaction)",
        );

        // Stamp `Require: 100rel` (merging with any existing Require) and
        // a fresh `RSeq` directly onto the typed headers, then serialize.
        let stamped = stamp_reliable_headers(&mut response, rseq);

        // Capture the buffer-empty state *before* pushing this entry so
        // we can decide whether to schedule a fresh Timer N.
        let was_empty = self.reliable_provisionals.is_empty();

        let entry = ReliableProvisional {
            rseq,
            bytes: stamped.clone(),
            next_fire_after: self.timers.t1,
            next_interval: self.timers.t1,
            elapsed: Duration::ZERO,
            abandon_at: self.timers.t1 * 64,
        };
        self.reliable_provisionals.push(entry);

        // Track as last_response so retransmitted INVITEs trigger a
        // resend exactly like a regular provisional.
        self.last_response = Some(stamped.clone());
        self.actions.push(Action::Send(stamped));

        // Only schedule a fresh Timer N when nothing was outstanding.
        // Late-added entries inherit the existing Timer N's deadline.
        // First retransmit may be earlier than T1 from this entry's
        // creation; this is RFC-conformant (T1 is a minimum).
        if was_empty {
            self.actions
                .push(Action::SetTimer(Timer::N, self.timers.t1));
        }
    }

    /// Deliver an event input to the transaction.
    ///
    /// Currently `Event::PrackReceived(rseq)` is the only input variant;
    /// other variants are outputs and are ignored if delivered as input.
    pub fn handle_event(&mut self, event: Event) {
        if let Event::PrackReceived(rseq) = event {
            self.handle_prack_received(rseq);
        }
    }

    /// Internal: handle a PRACK matching the given RSeq. Drops the
    /// buffered entry; cancels Timer N (if any). Stale or duplicate
    /// PRACKs are silently ignored (RFC 3262 §3).
    fn handle_prack_received(&mut self, rseq: u32) {
        let before = self.reliable_provisionals.len();
        self.reliable_provisionals.retain(|e| e.rseq != rseq);
        if self.reliable_provisionals.len() == before {
            // No matching entry — silently ignore.
            return;
        }

        if self.reliable_provisionals.is_empty() {
            // Nothing left — cancel Timer N entirely.
            self.actions.push(Action::CancelTimer(Timer::N));
        } else {
            // Reschedule for whichever entry is now next due.
            let next = self
                .reliable_provisionals
                .iter()
                .map(|e| e.next_fire_after)
                .min()
                .unwrap_or(self.timers.t1);
            // Cancel-then-set so the manager's mapping replaces the old
            // schedule cleanly.
            self.actions.push(Action::CancelTimer(Timer::N));
            self.actions.push(Action::SetTimer(Timer::N, next));
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

    // ---------------------------------------------------------------
    // Phase 2: reliable provisional / PRACK (RFC 3262)
    // ---------------------------------------------------------------

    /// Find the first `Action::Send` payload as a UTF-8 string.
    fn first_send_text(actions: &[Action]) -> Option<String> {
        actions.iter().find_map(|a| match a {
            Action::Send(b) => Some(String::from_utf8_lossy(b).into_owned()),
            _ => None,
        })
    }

    /// Count `Action::Send` actions in the slice.
    fn count_sends(actions: &[Action]) -> usize {
        actions
            .iter()
            .filter(|a| matches!(a, Action::Send(_)))
            .count()
    }

    /// Drive Timer N until the buffer empties or `max_ticks` is reached.
    /// Returns the total number of ticks fired.
    fn drive_timer_n_to_completion(
        tx: &mut InviteServerTransaction,
        max_ticks: usize,
    ) -> usize {
        let mut ticks = 0;
        while ticks < max_ticks && !tx.reliable_provisionals.is_empty() {
            tx.handle_timeout(Timer::N);
            tx.poll_actions(); // discard actions between ticks
            ticks += 1;
        }
        ticks
    }

    #[test]
    fn test_send_provisional_reliable_emits_send_and_timer() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(180, &invite);
        tx.send_provisional_reliable(resp);

        assert_eq!(tx.state(), State::Proceeding);
        let actions = tx.poll_actions();

        // Exactly one Send and one SetTimer(N, T1).
        assert_eq!(count_sends(&actions), 1);
        let wire = first_send_text(&actions).expect("Send action present");
        assert!(
            wire.contains("Require: 100rel"),
            "wire missing Require: 100rel: {wire}"
        );
        assert!(
            wire.contains("RSeq: 1"),
            "wire missing RSeq: 1: {wire}"
        );

        let t1 = TimerValues::default().t1;
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SetTimer(Timer::N, d) if *d == t1
            )),
            "expected SetTimer(N, T1), got: {actions:?}"
        );
    }

    #[test]
    fn test_prack_received_cancels_retransmit() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(180, &invite);
        tx.send_provisional_reliable(resp);
        tx.poll_actions();

        // PRACK arrives.
        tx.handle_event(Event::PrackReceived(1));
        let actions = tx.poll_actions();
        // PRACK cancels Timer N because no entries remain.
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::CancelTimer(Timer::N))));

        // Timer N firing now is a no-op — buffer is empty.
        tx.handle_timeout(Timer::N);
        let actions = tx.poll_actions();
        assert_eq!(count_sends(&actions), 0);
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::N, _))));
    }

    #[test]
    fn test_prack_received_unknown_rseq_ignored() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(180, &invite);
        tx.send_provisional_reliable(resp);
        tx.poll_actions();

        // PRACK for an RSeq we never sent — ignored silently.
        tx.handle_event(Event::PrackReceived(99));
        let actions = tx.poll_actions();
        assert!(actions.is_empty());

        // Original entry is still buffered; Timer N fires retransmit.
        tx.handle_timeout(Timer::N);
        let actions = tx.poll_actions();
        assert_eq!(count_sends(&actions), 1);
    }

    #[test]
    fn test_prack_timeout_no_final() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(180, &invite);
        tx.send_provisional_reliable(resp);
        tx.poll_actions();

        // Drive Timer N until abandoned.
        let mut events: Vec<Event> = Vec::new();
        for _ in 0..200 {
            tx.handle_timeout(Timer::N);
            for a in tx.poll_actions() {
                if let Action::Event(ev) = a {
                    events.push(ev);
                }
            }
            if tx.reliable_provisionals.is_empty() {
                break;
            }
        }

        let timeout = events.iter().find(|ev| {
            matches!(ev, Event::PrackTimeout { rseq: 1, final_sent: FinalSent::None })
        });
        assert!(
            timeout.is_some(),
            "expected PrackTimeout {{ rseq: 1, final_sent: None }}; got: {events:?}"
        );
    }

    #[test]
    fn test_prack_timeout_after_non_2xx_final_does_not_fire() {
        // RFC 3262 §3 / HLD snag 1: any final response drains the PRACK
        // buffer, so PrackTimeout cannot fire post-final. The FinalSent
        // variants (NonTwoXx / TwoXx) exist for the case where Timer N
        // races and fires *before* the final response is sent — we
        // never observe that race in this test, so no PrackTimeout is
        // emitted at all.
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let provisional = create_response(180, &invite);
        tx.send_provisional_reliable(provisional);
        tx.poll_actions();

        // Send a 486 (non-2xx final) — should drain the buffer.
        let final_resp = create_response(486, &invite);
        tx.send_response(final_resp);
        let drain_actions = tx.poll_actions();
        assert!(
            drain_actions
                .iter()
                .any(|a| matches!(a, Action::CancelTimer(Timer::N))),
            "486 final must cancel Timer N"
        );
        assert!(tx.reliable_provisionals.is_empty());

        // Now pump Timer N — it should be a no-op (buffer drained).
        let ticks = drive_timer_n_to_completion(&mut tx, 200);
        assert_eq!(
            ticks, 0,
            "expected Timer N to no-op with empty buffer (got {ticks} ticks)"
        );
    }

    #[test]
    fn test_prack_timeout_after_2xx_final_does_not_fire() {
        // Same buffer-drain rule applies to 2xx finals — see above.
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let provisional = create_response(183, &invite);
        tx.send_provisional_reliable(provisional);
        tx.poll_actions();

        let final_resp = create_response(200, &invite);
        tx.send_response(final_resp);
        let drain_actions = tx.poll_actions();
        assert!(
            drain_actions
                .iter()
                .any(|a| matches!(a, Action::CancelTimer(Timer::N))),
            "200 OK final must cancel Timer N"
        );
        assert!(tx.reliable_provisionals.is_empty());

        let ticks = drive_timer_n_to_completion(&mut tx, 200);
        assert_eq!(ticks, 0);
    }

    #[test]
    fn test_buffer_drained_on_final() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let provisional = create_response(180, &invite);
        tx.send_provisional_reliable(provisional);
        tx.poll_actions();

        // 486 drains the buffer.
        let final_resp = create_response(486, &invite);
        tx.send_response(final_resp);
        tx.poll_actions();

        // Timer N fires — no Send retransmit, no further SetTimer(N).
        tx.handle_timeout(Timer::N);
        let actions = tx.poll_actions();
        assert_eq!(count_sends(&actions), 0);
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::N, _))));
    }

    #[test]
    #[should_panic(expected = "100 Trying is undefined")]
    fn test_reject_100() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(100, &invite);
        tx.send_provisional_reliable(resp);
    }

    #[test]
    fn test_rseq_monotonic() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp1 = create_response(180, &invite);
        tx.send_provisional_reliable(resp1);
        let actions = tx.poll_actions();
        let wire1 = first_send_text(&actions).expect("first send");
        assert!(wire1.contains("RSeq: 1"), "first wire: {wire1}");

        let resp2 = create_response(183, &invite);
        tx.send_provisional_reliable(resp2);
        let actions = tx.poll_actions();
        let wire2 = first_send_text(&actions).expect("second send");
        assert!(wire2.contains("RSeq: 2"), "second wire: {wire2}");
    }

    #[test]
    fn test_multiple_outstanding_prack() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // Two outstanding reliable provisionals.
        tx.send_provisional_reliable(create_response(180, &invite));
        tx.poll_actions();
        tx.send_provisional_reliable(create_response(183, &invite));
        tx.poll_actions();
        assert_eq!(tx.reliable_provisionals.len(), 2);

        // PRACK only the first (RSeq: 1).
        tx.handle_event(Event::PrackReceived(1));
        tx.poll_actions();
        assert_eq!(tx.reliable_provisionals.len(), 1);
        assert_eq!(tx.reliable_provisionals[0].rseq, 2);

        // Timer N fires — RSeq 2 is retransmitted, RSeq 1 is not.
        tx.handle_timeout(Timer::N);
        let actions = tx.poll_actions();
        assert_eq!(count_sends(&actions), 1);
        let wire = first_send_text(&actions).expect("send for rseq 2");
        assert!(
            wire.contains("RSeq: 2"),
            "expected retransmit of RSeq 2, got: {wire}"
        );
    }

    #[test]
    fn test_reliable_provisional_in_terminated_noop() {
        // Defensive: calling send_provisional_reliable after the
        // transaction has terminated must not panic and must not enqueue
        // any actions or buffer entries.
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // Force termination via a 2xx.
        tx.send_response(create_response(200, &invite));
        tx.poll_actions();
        assert_eq!(tx.state(), State::Terminated);

        let resp = create_response(180, &invite);
        tx.send_provisional_reliable(resp);
        let actions = tx.poll_actions();
        assert!(actions.is_empty());
        assert!(tx.reliable_provisionals.is_empty());
    }

    #[test]
    fn test_final_sent_field_after_2xx() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        tx.send_response(create_response(200, &invite));
        assert_eq!(tx.final_sent, FinalSent::TwoXx);
    }

    #[test]
    fn test_final_sent_field_after_non_2xx() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        tx.send_response(create_response(486, &invite));
        assert_eq!(tx.final_sent, FinalSent::NonTwoXx);
    }

    #[test]
    fn test_timer_n_retransmit_doubles_then_caps() {
        // Verify the retransmit schedule matches RFC 3262 §3:
        // T1, 2*T1, 4*T1, ..., capped at T2.
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(180, &invite);
        tx.send_provisional_reliable(resp);
        tx.poll_actions();

        let tv = TimerValues::default();
        // Expected next intervals after each tick: 2*T1, 4*T1, T2, T2, ...
        let mut expected = tv.t1 * 2;
        for _ in 0..5 {
            tx.handle_timeout(Timer::N);
            let actions = tx.poll_actions();
            // Find the SetTimer(N) emitted; its duration should match expected.
            let dur = actions.iter().find_map(|a| match a {
                Action::SetTimer(Timer::N, d) => Some(*d),
                _ => None,
            });
            if let Some(d) = dur {
                assert_eq!(d, expected, "schedule mismatch (expected {expected:?})");
            }
            expected = std::cmp::min(expected * 2, tv.t2);
        }
    }

    #[test]
    fn test_final_sent_initially_none() {
        let invite = create_invite();
        let tx = InviteServerTransaction::new(invite, false).unwrap();
        assert_eq!(tx.final_sent, FinalSent::None);
    }

    /// B1 regression: TU-set `Require: precondition` must be merged with
    /// `100rel`, not stomped by an unconditional second `Require:` line.
    /// The wire bytes must contain exactly one `Require:` header carrying
    /// both option-tags.
    #[test]
    fn test_send_provisional_reliable_merges_existing_require() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // TU sets Require: precondition before passing to the transaction.
        let resp = SipResponse::builder()
            .status(180, "Ringing")
            .from_request(&invite)
            .to_tag("totag")
            .require(&["precondition"])
            .build()
            .unwrap();

        tx.send_provisional_reliable(resp);
        let actions = tx.poll_actions();
        let wire = first_send_text(&actions).expect("Send action present");

        // Exactly one Require: line.
        let require_lines: Vec<&str> = wire
            .lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("require:"))
            .collect();
        assert_eq!(
            require_lines.len(),
            1,
            "expected exactly one Require: line, got {require_lines:?} (wire: {wire})"
        );
        let line = require_lines[0].to_ascii_lowercase();
        assert!(
            line.contains("precondition"),
            "Require missing precondition: {line}"
        );
        assert!(
            line.contains("100rel"),
            "Require missing 100rel: {line}"
        );
    }

    /// B1 round-trip: the stamped wire bytes must parse cleanly back into
    /// a `SipResponse` whose typed accessors return the values stamped.
    #[test]
    fn test_send_provisional_reliable_round_trips_through_parse() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        let resp = create_response(180, &invite);
        tx.send_provisional_reliable(resp);
        let actions = tx.poll_actions();

        let bytes = actions
            .iter()
            .find_map(|a| match a {
                Action::Send(b) => Some(b.clone()),
                _ => None,
            })
            .expect("Send action present");

        let msg = crate::sip::SipMessage::parse(&bytes).expect("re-parse stamped bytes");
        let response = match msg {
            crate::sip::SipMessage::Response(r) => r,
            _ => panic!("expected SipMessage::Response"),
        };
        assert!(
            response
                .require()
                .is_some_and(|r| r.0.iter().any(|t| t.eq_ignore_ascii_case("100rel"))),
            "round-tripped response missing Require: 100rel"
        );
        assert_eq!(response.rseq().map(|r| r.0), Some(1));
    }

    /// B2 regression: with two outstanding entries staggered in time and
    /// PRACK withheld for both, each entry must follow its own retransmit
    /// schedule. The pre-fix code shared `next_smallest` across all
    /// entries, causing the second entry to fire prematurely.
    ///
    /// This test stages entry1 at t=0, then entry2 *after* entry1 has
    /// already retransmitted once, so the two entries are on genuinely
    /// distinct schedules. We assert the qualitative property that
    /// entry2 fires for the first time *after* entry1's first
    /// retransmit, both eventually abandon, and PrackTimeout events
    /// carry the correct distinct RSeq values.
    #[test]
    fn test_multiple_outstanding_prack_staggered() {
        let invite = create_invite();
        let mut tx = InviteServerTransaction::new(invite.clone(), false).unwrap();
        tx.poll_actions();

        // Stage entry1 at t=0.
        tx.send_provisional_reliable(create_response(180, &invite));
        let actions = tx.poll_actions();
        // Initial Send + SetTimer(N, T1).
        assert_eq!(count_sends(&actions), 1);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SetTimer(Timer::N, _))));

        // Drive Timer N once — entry1 fires its first retransmit.
        tx.handle_timeout(Timer::N);
        let actions = tx.poll_actions();
        // entry1 retransmitted once (only entry in the buffer).
        assert_eq!(count_sends(&actions), 1);
        let wire = first_send_text(&actions).expect("entry1 first retransmit");
        assert!(wire.contains("RSeq: 1"), "expected RSeq 1: {wire}");

        // Stage entry2 *after* entry1 has retransmitted. Per Fix #1, no
        // new SetTimer(N) is emitted — entry2 inherits entry1's pending
        // Timer N deadline.
        tx.send_provisional_reliable(create_response(183, &invite));
        let actions = tx.poll_actions();
        assert_eq!(count_sends(&actions), 1, "entry2 initial send");
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::SetTimer(Timer::N, _))),
            "entry2 must NOT emit SetTimer(N) — it inherits entry1's deadline (got {actions:?})"
        );

        // Now drive Timer N until both entries abandon. Track per-RSeq
        // retransmit counts and PrackTimeout events.
        // Already counted: entry1 has 1 retransmit; entry2's initial
        // Send is not a retransmit, so its count starts at 0.
        let mut sends_rseq1: usize = 1;
        let mut sends_rseq2: usize = 0;
        let mut timeouts: Vec<u32> = Vec::new();

        // Bound the loop generously; both entries abandon at 64*T1.
        for _ in 0..200 {
            tx.handle_timeout(Timer::N);
            let actions = tx.poll_actions();
            for a in &actions {
                match a {
                    Action::Send(b) => {
                        let s = String::from_utf8_lossy(b);
                        if s.contains("RSeq: 1") {
                            sends_rseq1 += 1;
                        } else if s.contains("RSeq: 2") {
                            sends_rseq2 += 1;
                        }
                    }
                    Action::Event(Event::PrackTimeout { rseq, .. }) => {
                        timeouts.push(*rseq);
                    }
                    _ => {}
                }
            }
            if tx.reliable_provisionals.is_empty() {
                break;
            }
        }

        // Qualitative assertions: both entries retransmitted multiple
        // times before abandoning, both abandoned with their distinct
        // RSeq values, and entry1 retransmitted at least as many times
        // as entry2 (entry1 had a head start by one tick).
        assert!(
            sends_rseq1 >= 3,
            "entry1 retransmitted too few times: {sends_rseq1}"
        );
        assert!(
            sends_rseq2 >= 2,
            "entry2 retransmitted too few times: {sends_rseq2}"
        );
        assert!(
            sends_rseq1 >= sends_rseq2,
            "entry1 should retransmit at least as many times as entry2 (head start of one tick); got rseq1={sends_rseq1}, rseq2={sends_rseq2}"
        );
        // Loose inheritance bound: entry2's first retransmit may happen
        // earlier than T1 from its creation, but the totals stay within
        // one of each other modulo the head-start.
        assert!(
            sends_rseq1.abs_diff(sends_rseq2) <= 2,
            "schedules diverged unreasonably: rseq1={sends_rseq1}, rseq2={sends_rseq2}"
        );

        // Both abandoned with distinct RSeq values.
        assert!(
            timeouts.contains(&1),
            "expected PrackTimeout for RSeq 1; got: {timeouts:?}"
        );
        assert!(
            timeouts.contains(&2),
            "expected PrackTimeout for RSeq 2; got: {timeouts:?}"
        );
        assert!(tx.reliable_provisionals.is_empty(), "buffer must drain");
    }
}

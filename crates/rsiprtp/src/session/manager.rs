//! Call manager for orchestrating multiple calls.
//!
//! The CallManager handles routing SIP messages to the appropriate calls,
//! managing call lifecycle, and coordinating signaling with media.

use std::collections::HashMap;
use std::sync::Arc;

use crate::dialog::DialogId;
use crate::ice::Candidate;
use crate::sdp::ice_attrs;
use crate::sdp::negotiation::{
    create_answer, create_media_attributes, process_answer, Codec, NegotiatedMedia,
};
use crate::sdp::parser::{Direction, SessionDescription};
use crate::session::call::{
    Call, CallConfig, CallDirection, CallEndReason, CallEvent, CallId, CallState, Dialog,
    PendingAnswer,
};
use crate::session::ice_session::IceLocalParams;

/// Inputs to [`CallManager::build_answer_for`].
///
/// Bundles the default candidate (used to patch `m=`/`c=`) with the full
/// `IceLocalParams` (ufrag / pwd / candidate list). Both come from the
/// same `IceSession`; passing them as one struct prevents the silent
/// misuse of feeding a `default_candidate` that isn't in
/// `ice_local.candidates`. The borrow-only shape keeps it cheap to
/// construct on every call without forcing the caller to clone.
#[derive(Debug, Clone, Copy)]
pub struct IceAnswerInputs<'a> {
    /// Candidate the answer's `c=` and `m=` port should reflect — the
    /// reachable address for non-ICE peers (RFC 8839 §4.3.1). Should be
    /// one of the entries in `local.candidates`; the agent's
    /// `IceSession::default_candidate` is the canonical source.
    pub default_candidate: &'a Candidate,
    /// All gathered local candidates and credentials. Written verbatim
    /// into the answer's `a=ice-ufrag` / `a=ice-pwd` / `a=candidate:`
    /// lines.
    pub local: &'a IceLocalParams,
}

impl<'a> IceAnswerInputs<'a> {
    /// Construct from a candidate and the local ICE params.
    pub fn new(default_candidate: &'a Candidate, local: &'a IceLocalParams) -> Self {
        Self {
            default_candidate,
            local,
        }
    }
}

/// Manager event for the application layer.
#[derive(Debug)]
pub enum ManagerEvent {
    /// New incoming call.
    IncomingCall(CallId),
    /// Call state changed.
    CallStateChanged(CallId, CallState),
    /// Call event.
    CallEvent(CallId, CallEvent),
    /// Error occurred.
    Error(String),
}

/// Call manager configuration.
#[derive(Debug, Clone)]
pub struct ManagerConfig {
    /// Local SIP address (IP:port).
    pub local_sip_addr: String,
    /// Local RTP address (IP).
    pub local_rtp_addr: String,
    /// RTP port range.
    pub rtp_port_range: (u16, u16),
    /// Default call config.
    pub call_config: CallConfig,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            local_sip_addr: "127.0.0.1:5060".to_string(),
            local_rtp_addr: "127.0.0.1".to_string(),
            rtp_port_range: (10000, 20000),
            call_config: CallConfig::default(),
        }
    }
}

/// Manager for handling multiple SIP calls.
pub struct CallManager {
    /// Configuration.
    config: Arc<ManagerConfig>,
    /// Call configuration.
    call_config: Arc<CallConfig>,
    /// Active calls by CallId.
    calls: HashMap<CallId, Call>,
    /// Map from DialogId to CallId.
    dialog_to_call: HashMap<DialogId, CallId>,
    /// Next RTP port to allocate.
    next_rtp_port: u16,
    /// Pending events.
    events: Vec<ManagerEvent>,
}

impl CallManager {
    /// Create a new call manager.
    pub fn new(config: ManagerConfig) -> Self {
        let next_rtp_port = config.rtp_port_range.0;
        let call_config = Arc::new(config.call_config.clone());

        Self {
            config: Arc::new(config),
            call_config,
            calls: HashMap::new(),
            dialog_to_call: HashMap::new(),
            next_rtp_port,
            events: Vec::new(),
        }
    }

    /// Get the number of active calls.
    pub fn call_count(&self) -> usize {
        self.calls.len()
    }

    /// Get a call by ID.
    pub fn get_call(&self, id: &CallId) -> Option<&Call> {
        self.calls.get(id)
    }

    /// Get a mutable call by ID.
    pub fn get_call_mut(&mut self, id: &CallId) -> Option<&mut Call> {
        self.calls.get_mut(id)
    }

    /// Get a call by dialog ID.
    pub fn get_call_by_dialog(&self, dialog_id: &DialogId) -> Option<&Call> {
        self.dialog_to_call
            .get(dialog_id)
            .and_then(|call_id| self.calls.get(call_id))
    }

    /// Allocate the next available RTP port.
    fn allocate_rtp_port(&mut self) -> u16 {
        let port = self.next_rtp_port;
        self.next_rtp_port += 2; // RTP uses even ports, RTCP uses odd
        if self.next_rtp_port > self.config.rtp_port_range.1 {
            self.next_rtp_port = self.config.rtp_port_range.0;
        }
        port
    }

    /// Create a new outbound call.
    ///
    /// `remote_uri` is stored for later use in SIP requests; this method does
    /// **not** resolve the URI to a network address. The manager is Sans-IO
    /// and does not perform DNS or socket I/O. Resolve the URI yourself with
    /// [`SipResolver`](crate::transport::SipResolver) (RFC 3263 NAPTR / SRV /
    /// A) before connecting your transport.
    pub fn create_call(&mut self, remote_uri: String) -> CallId {
        let call = Call::new_outbound(self.call_config.clone(), remote_uri);
        let call_id = call.id().clone();
        self.calls.insert(call_id.clone(), call);
        call_id
    }

    /// Accept an incoming INVITE and create a call.
    ///
    /// Returns the call ID and the SDP answer to send in 200 OK.
    pub fn handle_incoming_invite(
        &mut self,
        dialog: Dialog,
        offer_sdp: &SessionDescription,
    ) -> Option<(CallId, SessionDescription, u16)> {
        let local_port = self.allocate_rtp_port();
        let (answer_sdp, negotiated) =
            create_answer(offer_sdp, &self.call_config.codecs, local_port)?;
        let media = negotiated.into_iter().next().expect("negotiated media");
        let call_id = self.create_inbound_call_internal(dialog, media, local_port)?;
        Some((call_id, answer_sdp, local_port))
    }

    /// Accept an inbound INVITE without building the SDP answer yet.
    ///
    /// This is the deferred-answer entry point used by ICE flows: the
    /// application gathers ICE candidates asynchronously and then calls
    /// [`build_answer_for`](Self::build_answer_for) to produce the answer
    /// SDP once gathering completes. The call is created, the dialog is
    /// mapped, and a [`ManagerEvent::IncomingCall`] event is emitted as
    /// usual; only the SDP answer (and the media session it implies) is
    /// deferred.
    ///
    /// For non-ICE flows prefer [`handle_incoming_invite`](Self::handle_incoming_invite),
    /// which does the same bookkeeping and builds the answer in one
    /// synchronous call.
    ///
    /// Returns `None` if codec negotiation finds no compatible media in
    /// the offer — matching `handle_incoming_invite`'s rejection contract.
    ///
    /// If the application later determines it cannot answer (ICE gather
    /// fails, user abandons the call, etc.), call
    /// [`reject_inbound_invite`](Self::reject_inbound_invite) to clear
    /// the pending state and obtain the dialog ID for a `5xx` response —
    /// `terminate_call` is for established calls and won't act on a
    /// pending one.
    pub fn accept_inbound_invite(
        &mut self,
        dialog: Dialog,
        offer_sdp: &SessionDescription,
    ) -> Option<CallId> {
        // Negotiate exactly once. The `NegotiatedMedia` is cached on the
        // call alongside the offer; `build_answer_for` patches the cached
        // offer with the real ICE port and rebuilds attrs from the cached
        // codec — no second `create_answer` invocation, no port-zero
        // throwaway answer.
        let (_, mut negotiated) = create_answer(offer_sdp, &self.call_config.codecs, 0)?;
        let media = negotiated.pop()?;

        let pending = PendingAnswer {
            offer: offer_sdp.clone(),
            negotiated: media,
        };

        self.create_inbound_call_pending(dialog, pending)
    }

    /// Reject an inbound call accepted via
    /// [`accept_inbound_invite`](Self::accept_inbound_invite) before any
    /// answer was built.
    ///
    /// Use this when the application can no longer answer the call —
    /// ICE gather failed, the user abandoned, or any local-policy
    /// rejection. Transitions the call to `Terminated` and emits
    /// `CallEvent::Ended(CallEndReason::Error)`. Returns the
    /// `DialogId` so the caller can send a `5xx` rejection upstream.
    ///
    /// Returns `None` when the call is unknown, was not created via
    /// `accept_inbound_invite`, or already had its answer built — those
    /// states have other termination paths (`reject_call` while
    /// `Ringing`, `terminate_call` once `Established`).
    pub fn reject_inbound_invite(&mut self, call_id: &CallId) -> Option<DialogId> {
        let call = self.calls.get_mut(call_id)?;

        // Guard the precondition explicitly: `Ringing` AND a pending
        // answer cached. Either alone isn't enough — a normal inbound
        // call is also `Ringing` but routes through `reject_call`.
        if call.state() != CallState::Ringing || !call.has_pending_answer() {
            return None;
        }

        // Drop the cache; nothing else looks at it after rejection.
        let _ = call.take_pending_answer();
        call.handle_ended(CallEndReason::Error);
        let dialog_id = call.dialog_id().cloned();

        self.events.push(ManagerEvent::CallEvent(
            call_id.clone(),
            CallEvent::Ended(CallEndReason::Error),
        ));

        dialog_id
    }

    /// Build the SDP answer for a call accepted via
    /// [`accept_inbound_invite`](Self::accept_inbound_invite).
    ///
    /// Reuses the codec negotiation cached at accept time: the offer
    /// SDP is cloned and patched with the real ICE port, the audio
    /// media's formats / rtpmap / fmtp / direction are rewritten from
    /// the cached `NegotiatedMedia`, and ICE attributes are written.
    /// `c=` is patched to the address family of `inputs.default_candidate`;
    /// the SDP origin (`o=`) line is left as written by the offerer.
    /// Mixed-family SDP (e.g. IPv4 origin with an IPv6 `c=` line) is
    /// allowed by RFC 4566 but rare in the wild; the function does not
    /// normalize. The call's media session is wired up to the ICE port;
    /// the application is expected to drive RTP from the ICE-owned
    /// socket.
    ///
    /// Returns `None` if the call has no pending answer to build —
    /// either the call ID is unknown, the call was not created by
    /// [`accept_inbound_invite`](Self::accept_inbound_invite), or
    /// `build_answer_for` was already called for this call (the cache
    /// is single-use).
    pub fn build_answer_for(
        &mut self,
        call_id: &CallId,
        inputs: &IceAnswerInputs<'_>,
    ) -> Option<SessionDescription> {
        let local_port = inputs.default_candidate.address.port();

        let pending = {
            let call = self.calls.get_mut(call_id)?;
            call.take_pending_answer()?
        };
        let PendingAnswer {
            mut offer,
            negotiated,
        } = pending;

        // Rebuild the answer's audio m= line from the cached negotiation.
        // `create_answer` would do the same patching — but it would also
        // re-run codec matching, which we already paid for at accept time.
        // The patches here are deterministic and small.
        let answer_direction = swap_direction(negotiated.direction);
        let audio = offer
            .media
            .iter_mut()
            .find(|m| m.media_type == crate::sdp::parser::MediaType::Audio)?;
        audio.port = local_port;
        audio.formats = vec![negotiated.codec.payload_type.to_string()];
        audio.attributes = create_media_attributes(&negotiated.codec, answer_direction);

        // Find the audio media's index for `apply_default_candidate`.
        let audio_idx = offer
            .media
            .iter()
            .position(|m| m.media_type == crate::sdp::parser::MediaType::Audio)
            .expect("audio media present (just patched above)");

        ice_attrs::apply_default_candidate(&mut offer, audio_idx, inputs.default_candidate);
        let audio = offer.media.get_mut(audio_idx).expect("audio media present");
        ice_attrs::write_ice_credentials(audio, &inputs.local.ufrag, &inputs.local.pwd);
        ice_attrs::write_candidates(audio, &inputs.local.candidates);
        ice_attrs::write_rtcp_mux(audio);

        let call = self.calls.get_mut(call_id).expect("call exists");
        if let Err(e) = call.set_negotiated_media(negotiated, local_port) {
            tracing::warn!(error = %e, "build_answer_for: media session construction failed");
            return None;
        }

        Some(offer)
    }

    /// Bookkeeping for an inbound call accepted with a pending answer.
    /// Mirrors `create_inbound_call_internal` but constructs the call
    /// directly with the cached `PendingAnswer`, keeping the field
    /// private to `Call`.
    fn create_inbound_call_pending(
        &mut self,
        dialog: Dialog,
        pending: PendingAnswer,
    ) -> Option<CallId> {
        let remote_uri = dialog.remote_uri().to_string();
        let call = Call::new_inbound_pending(self.call_config.clone(), remote_uri, dialog, pending);
        let call_id = call.id().clone();

        self.calls.insert(call_id.clone(), call);

        let call = self.calls.get(&call_id).expect("call inserted");
        let dialog_id = call.dialog_id().expect("dialog id").clone();
        self.dialog_to_call.insert(dialog_id, call_id.clone());

        self.events
            .push(ManagerEvent::IncomingCall(call_id.clone()));

        Some(call_id)
    }

    /// Shared bookkeeping for inbound calls accepted with the answer
    /// already built: register the call, attach negotiated media, map
    /// the dialog, and emit `IncomingCall`. The deferred-answer path
    /// (`accept_inbound_invite`) goes through
    /// `create_inbound_call_pending` instead, which carries the cached
    /// offer + negotiation in place of an attached `MediaSession`.
    fn create_inbound_call_internal(
        &mut self,
        dialog: Dialog,
        media: NegotiatedMedia,
        local_port: u16,
    ) -> Option<CallId> {
        let remote_uri = dialog.remote_uri().to_string();
        let call = Call::new_inbound(self.call_config.clone(), remote_uri, dialog);
        let call_id = call.id().clone();

        self.calls.insert(call_id.clone(), call);

        let call = self.calls.get_mut(&call_id).expect("call inserted");
        if let Err(e) = call.set_negotiated_media(media, local_port) {
            tracing::warn!(error = %e, "rejecting INVITE: media session construction failed");
            self.calls.remove(&call_id);
            return None;
        }

        let dialog_id = call.dialog_id().expect("dialog id");
        self.dialog_to_call
            .insert(dialog_id.clone(), call_id.clone());

        self.events
            .push(ManagerEvent::IncomingCall(call_id.clone()));

        Some(call_id)
    }

    /// Handle a 200 OK response to our INVITE.
    pub fn handle_invite_success(
        &mut self,
        call_id: &CallId,
        dialog: Dialog,
        answer_sdp: &SessionDescription,
    ) -> bool {
        // Process the SDP answer first
        let negotiated = process_answer(answer_sdp);
        let media = match negotiated.into_iter().next() {
            Some(m) => m,
            None => return false,
        };

        // Pre-allocate port before borrowing calls
        let local_port = self.allocate_rtp_port();

        let call = match self.calls.get_mut(call_id) {
            Some(c) => c,
            None => return false,
        };

        call.set_dialog(dialog);
        // Surface a media-session construction error by failing the
        // 200-OK handler — the caller treats `false` as "could not
        // establish call".
        if let Err(e) = call.set_negotiated_media(media, local_port) {
            tracing::warn!(error = %e, "200 OK media setup failed");
            return false;
        }
        call.handle_answer();

        // Register dialog mapping
        let dialog_id = call.dialog_id().expect("dialog id");
        self.dialog_to_call
            .insert(dialog_id.clone(), call_id.clone());

        self.events.push(ManagerEvent::CallStateChanged(
            call_id.clone(),
            CallState::Established,
        ));

        true
    }

    /// Handle a 18x provisional response.
    pub fn handle_provisional(
        &mut self,
        call_id: &CallId,
        has_sdp: bool,
        sdp: Option<&SessionDescription>,
    ) {
        // Pre-allocate port before borrowing calls
        let local_port = self.allocate_rtp_port();

        if let Some(call) = self.calls.get_mut(call_id) {
            // If early media SDP, set up media session. A construction
            // error is surfaced via warn — the call continues without
            // early media, the subsequent 200 OK will retry negotiation.
            if has_sdp {
                if let Some(answer_sdp) = sdp {
                    let negotiated = process_answer(answer_sdp);
                    if let Some(media) = negotiated.into_iter().next() {
                        if let Err(e) = call.set_negotiated_media(media, local_port) {
                            tracing::warn!(error = %e, "early-media setup failed");
                        }
                    }
                }
            }

            call.handle_provisional(has_sdp);
            self.events.push(ManagerEvent::CallStateChanged(
                call_id.clone(),
                call.state(),
            ));
        }
    }

    /// Handle an error response to INVITE.
    pub fn handle_invite_failure(&mut self, call_id: &CallId, status_code: u16) {
        if let Some(call) = self.calls.get_mut(call_id) {
            let reason = match status_code {
                486 => CallEndReason::Busy,
                480 | 408 => CallEndReason::NoAnswer,
                603 => CallEndReason::Rejected,
                _ => CallEndReason::Error,
            };

            call.handle_ended(reason);
            self.events.push(ManagerEvent::CallEvent(
                call_id.clone(),
                CallEvent::Ended(reason),
            ));
        }
    }

    /// Handle a BYE request.
    pub fn handle_bye(&mut self, dialog_id: &DialogId) {
        if let Some(call_id) = self.dialog_to_call.get(dialog_id).cloned() {
            if let Some(call) = self.calls.get_mut(&call_id) {
                call.handle_ended(CallEndReason::NormalClearing);
                self.events.push(ManagerEvent::CallEvent(
                    call_id,
                    CallEvent::Ended(CallEndReason::NormalClearing),
                ));
            }
        }
    }

    /// Terminate a call locally (send BYE).
    ///
    /// Returns the dialog ID that should be used to send BYE. Acts only
    /// on calls in the `Established` state — for inbound calls accepted
    /// via [`accept_inbound_invite`](Self::accept_inbound_invite) but
    /// not yet answered, use
    /// [`reject_inbound_invite`](Self::reject_inbound_invite) instead;
    /// for ordinary `Ringing` calls (via `handle_incoming_invite`), use
    /// [`reject_call`](Self::reject_call).
    pub fn terminate_call(&mut self, call_id: &CallId) -> Option<DialogId> {
        let call = self.calls.get_mut(call_id)?;

        if call.state() != CallState::Established {
            return None;
        }

        call.set_state(CallState::Terminating);
        call.dialog_id().cloned()
    }

    /// Remove a terminated call.
    pub fn remove_call(&mut self, call_id: &CallId) {
        if let Some(call) = self.calls.remove(call_id) {
            if let Some(dialog_id) = call.dialog_id() {
                self.dialog_to_call.remove(dialog_id);
            }
        }
    }

    /// Answer an incoming call.
    pub fn answer_call(&mut self, call_id: &CallId) -> bool {
        if let Some(call) = self.calls.get_mut(call_id) {
            if call.direction() == CallDirection::Inbound && call.state() == CallState::Ringing {
                call.handle_answer();
                self.events.push(ManagerEvent::CallStateChanged(
                    call_id.clone(),
                    CallState::Established,
                ));
                return true;
            }
        }
        false
    }

    /// Reject an incoming call.
    pub fn reject_call(&mut self, call_id: &CallId) -> Option<DialogId> {
        if let Some(call) = self.calls.get_mut(call_id) {
            if call.direction() == CallDirection::Inbound && call.state() == CallState::Ringing {
                call.handle_ended(CallEndReason::Rejected);
                return call.dialog_id().cloned();
            }
        }
        None
    }

    /// Drain pending events.
    pub fn drain_events(&mut self) -> Vec<ManagerEvent> {
        std::mem::take(&mut self.events)
    }

    /// Get all active call IDs.
    pub fn active_calls(&self) -> Vec<CallId> {
        self.calls
            .iter()
            .filter(|(_, call)| call.is_active())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Get the supported codecs.
    pub fn codecs(&self) -> &[Codec] {
        &self.call_config.codecs
    }

    /// Get the local RTP address.
    pub fn local_rtp_addr(&self) -> &str {
        &self.config.local_rtp_addr
    }
}

/// Swap an offered direction to the answer-side direction.
///
/// Mirrors the logic baked into `create_answer`: SendOnly/RecvOnly
/// swap, SendRecv and Inactive stay. Pulled out so the deferred-answer
/// path can apply the same rule without re-running negotiation.
fn swap_direction(d: Direction) -> Direction {
    match d {
        Direction::SendRecv => Direction::SendRecv,
        Direction::SendOnly => Direction::RecvOnly,
        Direction::RecvOnly => Direction::SendOnly,
        Direction::Inactive => Direction::Inactive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sdp() -> SessionDescription {
        let sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 5000 RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
"#;
        SessionDescription::parse(sdp).unwrap()
    }

    fn test_video_only_sdp() -> SessionDescription {
        let sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=video 5000 RTP/AVP 96
a=rtpmap:96 H264/90000
"#;
        SessionDescription::parse(sdp).unwrap()
    }

    // ManagerEvent tests
    #[test]
    fn test_manager_event_debug() {
        let event = ManagerEvent::IncomingCall(CallId::new());
        let debug = format!("{:?}", event);
        assert!(debug.contains("IncomingCall"));

        let event = ManagerEvent::CallStateChanged(CallId::new(), CallState::Established);
        let debug = format!("{:?}", event);
        assert!(debug.contains("CallStateChanged"));

        let event = ManagerEvent::CallEvent(
            CallId::new(),
            CallEvent::Ended(CallEndReason::NormalClearing),
        );
        let debug = format!("{:?}", event);
        assert!(debug.contains("CallEvent"));

        let event = ManagerEvent::Error("test error".to_string());
        let debug = format!("{:?}", event);
        assert!(debug.contains("Error"));
    }

    // ManagerConfig tests
    #[test]
    fn test_manager_config_default() {
        let config = ManagerConfig::default();
        assert_eq!(config.local_sip_addr, "127.0.0.1:5060");
        assert_eq!(config.local_rtp_addr, "127.0.0.1");
        assert_eq!(config.rtp_port_range, (10000, 20000));
    }

    #[test]
    fn test_manager_config_debug() {
        let config = ManagerConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("ManagerConfig"));
    }

    #[test]
    fn test_manager_config_clone() {
        let config = ManagerConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.local_sip_addr, "127.0.0.1:5060");
    }

    // CallManager tests
    #[test]
    fn test_create_outbound_call() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let call_id = manager.create_call("sip:bob@example.com".to_string());

        assert_eq!(manager.call_count(), 1);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Idle);
        assert_eq!(call.direction(), CallDirection::Outbound);
    }

    #[test]
    fn test_get_call_nonexistent() {
        let manager = CallManager::new(ManagerConfig::default());
        let fake_id = CallId::new();
        assert!(manager.get_call(&fake_id).is_none());
    }

    #[test]
    fn test_get_call_mut() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = manager.create_call("sip:bob@example.com".to_string());

        let call = manager.get_call_mut(&call_id);
        assert!(call.is_some());
    }

    #[test]
    fn test_get_call_mut_nonexistent() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let fake_id = CallId::new();
        assert!(manager.get_call_mut(&fake_id).is_none());
    }

    #[test]
    fn test_get_call_by_dialog() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = manager.create_call("sip:bob@example.com".to_string());

        let dialog = Dialog::new_uac(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let answer_sdp = test_sdp();
        manager.handle_invite_success(&call_id, dialog, &answer_sdp);

        let dialog_id = manager
            .get_call(&call_id)
            .unwrap()
            .dialog_id()
            .unwrap()
            .clone();
        let call = manager.get_call_by_dialog(&dialog_id);
        assert!(call.is_some());
    }

    #[test]
    fn test_get_call_by_dialog_nonexistent() {
        let manager = CallManager::new(ManagerConfig::default());
        let fake_dialog_id =
            DialogId::new("call-id".to_string(), "from".to_string(), "to".to_string());
        assert!(manager.get_call_by_dialog(&fake_dialog_id).is_none());
    }

    #[test]
    fn test_handle_incoming_invite() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_sdp();
        let result = manager.handle_incoming_invite(dialog, &offer_sdp);

        assert!(result.is_some());
        let (call_id, answer_sdp, _port) = result.unwrap();

        assert_eq!(manager.call_count(), 1);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.direction(), CallDirection::Inbound);
        assert_eq!(call.state(), CallState::Ringing);

        // Check answer SDP has correct port
        let audio = answer_sdp.audio_media().unwrap();
        assert!(audio.port >= 10000);
    }

    #[test]
    fn test_handle_incoming_invite_no_compatible_media() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-124".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_video_only_sdp();
        let result = manager.handle_incoming_invite(dialog, &offer_sdp);

        assert!(result.is_none());
        assert_eq!(manager.call_count(), 0);
    }

    #[test]
    fn test_handle_invite_success() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let call_id = manager.create_call("sip:bob@example.com".to_string());

        let dialog = Dialog::new_uac(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let answer_sdp = test_sdp();
        let result = manager.handle_invite_success(&call_id, dialog, &answer_sdp);

        assert!(result);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Established);
        assert!(call.media().is_some());
    }

    #[test]
    fn test_handle_invite_success_no_media() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = manager.create_call("sip:bob@example.com".to_string());

        let dialog = Dialog::new_uac(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let answer_sdp = test_video_only_sdp();
        let result = manager.handle_invite_success(&call_id, dialog, &answer_sdp);

        assert!(!result);
    }

    #[test]
    fn test_handle_invite_success_nonexistent_call() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let fake_id = CallId::new();

        let dialog = Dialog::new_uac(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let answer_sdp = test_sdp();
        let result = manager.handle_invite_success(&fake_id, dialog, &answer_sdp);

        assert!(!result);
    }

    #[test]
    fn test_handle_provisional() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let call_id = manager.create_call("sip:bob@example.com".to_string());

        manager.handle_provisional(&call_id, false, None);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Ringing);
    }

    #[test]
    fn test_handle_provisional_with_early_media() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let call_id = manager.create_call("sip:bob@example.com".to_string());
        let early_sdp = test_sdp();

        manager.handle_provisional(&call_id, true, Some(&early_sdp));

        let call = manager.get_call(&call_id).unwrap();
        // With early media, state should be EarlyMedia, not Ringing
        assert_eq!(call.state(), CallState::EarlyMedia);
    }

    #[test]
    fn test_handle_provisional_missing_sdp_body() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let call_id = manager.create_call("sip:bob@example.com".to_string());

        manager.handle_provisional(&call_id, true, None);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::EarlyMedia);
        assert!(call.media().is_none());
    }

    #[test]
    fn test_handle_provisional_unmatched_media() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let call_id = manager.create_call("sip:bob@example.com".to_string());
        let video_sdp = test_video_only_sdp();

        manager.handle_provisional(&call_id, true, Some(&video_sdp));

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::EarlyMedia);
        assert!(call.media().is_none());
    }

    #[test]
    fn test_handle_provisional_nonexistent() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let fake_id = CallId::new();
        manager.handle_provisional(&fake_id, false, None);
        // Should not panic
    }

    #[test]
    fn test_handle_invite_failure_486() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = manager.create_call("sip:bob@example.com".to_string());

        manager.handle_invite_failure(&call_id, 486);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Terminated);
    }

    #[test]
    fn test_handle_invite_failure_480() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = manager.create_call("sip:bob@example.com".to_string());

        manager.handle_invite_failure(&call_id, 480);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Terminated);
    }

    #[test]
    fn test_handle_invite_failure_408() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = manager.create_call("sip:bob@example.com".to_string());

        manager.handle_invite_failure(&call_id, 408);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Terminated);
    }

    #[test]
    fn test_handle_invite_failure_603() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = manager.create_call("sip:bob@example.com".to_string());

        manager.handle_invite_failure(&call_id, 603);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Terminated);
    }

    #[test]
    fn test_handle_invite_failure_other() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = manager.create_call("sip:bob@example.com".to_string());

        manager.handle_invite_failure(&call_id, 500);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Terminated);
    }

    #[test]
    fn test_handle_invite_failure_nonexistent() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let fake_id = CallId::new();
        manager.handle_invite_failure(&fake_id, 486);
        // Should not panic
    }

    #[test]
    fn test_handle_bye() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let call_id = manager.create_call("sip:bob@example.com".to_string());

        let dialog = Dialog::new_uac(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let answer_sdp = test_sdp();
        manager.handle_invite_success(&call_id, dialog, &answer_sdp);

        // Now simulate BYE
        let dialog_id = manager
            .get_call(&call_id)
            .unwrap()
            .dialog_id()
            .cloned()
            .unwrap();
        manager.handle_bye(&dialog_id);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Terminated);
    }

    #[test]
    fn test_handle_bye_nonexistent_dialog() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let fake_dialog_id =
            DialogId::new("call-id".to_string(), "from".to_string(), "to".to_string());
        manager.handle_bye(&fake_dialog_id);
        // Should not panic
    }

    #[test]
    fn test_handle_bye_missing_call_entry() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog_id = DialogId::new("call-id".to_string(), "from".to_string(), "to".to_string());
        let call_id = CallId::new();

        manager.dialog_to_call.insert(dialog_id.clone(), call_id);
        manager.handle_bye(&dialog_id);

        assert!(manager.events.is_empty());
    }

    #[test]
    fn test_terminate_call() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let call_id = manager.create_call("sip:bob@example.com".to_string());

        let dialog = Dialog::new_uac(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let answer_sdp = test_sdp();
        manager.handle_invite_success(&call_id, dialog, &answer_sdp);

        let dialog_id = manager.terminate_call(&call_id);
        assert!(dialog_id.is_some());

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Terminating);
    }

    #[test]
    fn test_terminate_call_not_established() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = manager.create_call("sip:bob@example.com".to_string());

        // Try to terminate a call that's not established
        let result = manager.terminate_call(&call_id);
        assert!(result.is_none());
    }

    #[test]
    fn test_terminate_call_nonexistent() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let fake_id = CallId::new();
        let result = manager.terminate_call(&fake_id);
        assert!(result.is_none());
    }

    #[test]
    fn test_remove_call() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = manager.create_call("sip:bob@example.com".to_string());

        assert_eq!(manager.call_count(), 1);
        manager.remove_call(&call_id);
        assert_eq!(manager.call_count(), 0);
    }

    #[test]
    fn test_remove_call_with_dialog() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = manager.create_call("sip:bob@example.com".to_string());

        let dialog = Dialog::new_uac(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let answer_sdp = test_sdp();
        manager.handle_invite_success(&call_id, dialog, &answer_sdp);

        let dialog_id = manager
            .get_call(&call_id)
            .unwrap()
            .dialog_id()
            .unwrap()
            .clone();

        manager.remove_call(&call_id);
        assert!(manager.get_call_by_dialog(&dialog_id).is_none());
    }

    #[test]
    fn test_remove_call_nonexistent() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let fake_id = CallId::new();
        manager.remove_call(&fake_id);
        // Should not panic
    }

    #[test]
    fn test_answer_call() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_sdp();
        let (call_id, _, _) = manager.handle_incoming_invite(dialog, &offer_sdp).unwrap();

        let result = manager.answer_call(&call_id);
        assert!(result);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Established);
    }

    #[test]
    fn test_answer_call_inbound_not_ringing() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-124".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_sdp();
        let (call_id, _, _) = manager.handle_incoming_invite(dialog, &offer_sdp).unwrap();

        let call = manager.get_call_mut(&call_id).unwrap();
        call.set_state(CallState::Established);

        let result = manager.answer_call(&call_id);
        assert!(!result);
    }

    #[test]
    fn test_answer_call_outbound() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = manager.create_call("sip:bob@example.com".to_string());

        let result = manager.answer_call(&call_id);
        assert!(!result);
    }

    #[test]
    fn test_answer_call_nonexistent() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let fake_id = CallId::new();
        let result = manager.answer_call(&fake_id);
        assert!(!result);
    }

    #[test]
    fn test_reject_call() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_sdp();
        let (call_id, _, _) = manager.handle_incoming_invite(dialog, &offer_sdp).unwrap();

        let result = manager.reject_call(&call_id);
        assert!(result.is_some());

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Terminated);
    }

    #[test]
    fn test_reject_call_inbound_not_ringing() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-125".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_sdp();
        let (call_id, _, _) = manager.handle_incoming_invite(dialog, &offer_sdp).unwrap();

        let call = manager.get_call_mut(&call_id).unwrap();
        call.set_state(CallState::Established);

        let result = manager.reject_call(&call_id);
        assert!(result.is_none());
    }

    #[test]
    fn test_reject_call_outbound() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = manager.create_call("sip:bob@example.com".to_string());

        let result = manager.reject_call(&call_id);
        assert!(result.is_none());
    }

    #[test]
    fn test_reject_call_nonexistent() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let fake_id = CallId::new();
        let result = manager.reject_call(&fake_id);
        assert!(result.is_none());
    }

    #[test]
    fn test_active_calls() {
        let mut manager = CallManager::new(ManagerConfig::default());

        // Create calls (not active yet - calls start in Inviting state)
        let call_id1 = manager.create_call("sip:bob@example.com".to_string());
        let call_id2 = manager.create_call("sip:carol@example.com".to_string());

        // Initially no active calls (calls are in Inviting state)
        let active = manager.active_calls();
        assert_eq!(active.len(), 0);

        // Make one call active by setting state to Established
        let call = manager.get_call_mut(&call_id1).expect("call exists");
        call.set_state(CallState::Established);

        let active = manager.active_calls();
        assert_eq!(active.len(), 1);
        assert!(active.contains(&call_id1));

        // Make second call active
        let call = manager.get_call_mut(&call_id2).expect("call exists");
        call.set_state(CallState::Established);

        let active = manager.active_calls();
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn test_codecs() {
        let manager = CallManager::new(ManagerConfig::default());
        let codecs = manager.codecs();
        assert!(!codecs.is_empty());
    }

    #[test]
    fn test_local_rtp_addr() {
        let manager = CallManager::new(ManagerConfig::default());
        assert_eq!(manager.local_rtp_addr(), "127.0.0.1");
    }

    #[test]
    fn test_port_allocation() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let port1 = manager.allocate_rtp_port();
        let port2 = manager.allocate_rtp_port();

        assert_eq!(port1, 10000);
        assert_eq!(port2, 10002);
    }

    #[test]
    fn test_port_allocation_wrapping() {
        let config = ManagerConfig {
            rtp_port_range: (10000, 10004),
            ..Default::default()
        };
        let mut manager = CallManager::new(config);

        let port1 = manager.allocate_rtp_port();
        let port2 = manager.allocate_rtp_port();
        let port3 = manager.allocate_rtp_port();

        assert_eq!(port1, 10000);
        assert_eq!(port2, 10002);
        assert_eq!(port3, 10004);

        // Should wrap around
        let port4 = manager.allocate_rtp_port();
        assert_eq!(port4, 10000);
    }

    #[test]
    fn test_events() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_sdp();
        manager.handle_incoming_invite(dialog, &offer_sdp);

        let events = manager.drain_events();
        assert!(!events.is_empty());

        // Check for IncomingCall event
        assert!(events
            .iter()
            .any(|e| matches!(e, ManagerEvent::IncomingCall(_))));

        // Events should be drained
        let events2 = manager.drain_events();
        assert!(events2.is_empty());
    }

    #[test]
    fn test_events_call_state_changed() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let call_id = manager.create_call("sip:bob@example.com".to_string());

        let dialog = Dialog::new_uac(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let answer_sdp = test_sdp();
        manager.handle_invite_success(&call_id, dialog, &answer_sdp);

        let events = manager.drain_events();
        assert!(events
            .iter()
            .any(|e| matches!(e, ManagerEvent::CallStateChanged(_, CallState::Established))));
    }

    // accept_inbound_invite / build_answer_for tests

    use crate::ice::Candidate;
    use crate::session::ice_session::IceLocalParams;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn host_candidate(ip: [u8; 4], port: u16) -> Candidate {
        Candidate::host(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port),
            1,
        )
    }

    fn ice_local(host: &Candidate) -> IceLocalParams {
        IceLocalParams {
            ufrag: "abc1234".to_string(),
            pwd: "0123456789abcdef01234567".to_string(),
            candidates: vec![host.clone()],
        }
    }

    #[test]
    fn accept_inbound_invite_creates_call_without_answer() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-300".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_sdp();
        let call_id = manager
            .accept_inbound_invite(dialog, &offer_sdp)
            .expect("accept_inbound_invite");

        assert_eq!(manager.call_count(), 1);

        let call = manager.get_call(&call_id).expect("call exists");
        assert_eq!(call.direction(), CallDirection::Inbound);
        assert_eq!(call.state(), CallState::Ringing);
        assert!(
            call.media().is_none(),
            "media must not be attached until build_answer_for runs"
        );

        let dialog_id = call.dialog_id().expect("dialog id").clone();
        assert!(manager.get_call_by_dialog(&dialog_id).is_some());

        let events = manager.drain_events();
        assert!(events
            .iter()
            .any(|e| matches!(e, ManagerEvent::IncomingCall(_))));
    }

    #[test]
    fn accept_inbound_invite_no_compatible_media() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-301".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_video_only_sdp();
        let result = manager.accept_inbound_invite(dialog, &offer_sdp);

        assert!(result.is_none());
        assert_eq!(manager.call_count(), 0);
    }

    #[test]
    fn build_answer_for_emits_ice_attrs() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-302".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_sdp();
        let call_id = manager
            .accept_inbound_invite(dialog, &offer_sdp)
            .expect("accept_inbound_invite");

        let host = host_candidate([10, 0, 0, 5], 7100);
        let local = ice_local(&host);
        let inputs = IceAnswerInputs::new(&host, &local);

        let answer = manager
            .build_answer_for(&call_id, &inputs)
            .expect("build_answer_for");

        let conn = answer.connection.as_ref().expect("session-level c=");
        assert_eq!(conn.address, "192.168.1.1");

        let audio = answer.audio_media().expect("audio media");
        assert_eq!(audio.port, 7100);
        let mconn = audio.connection.as_ref().expect("media-level c=");
        assert_eq!(mconn.address, "10.0.0.5");
        assert_eq!(mconn.addr_type, "IP4");

        let (ufrag, pwd) =
            ice_attrs::read_ice_credentials(audio).expect("ICE credentials on answer");
        assert_eq!(ufrag, "abc1234");
        assert_eq!(pwd, "0123456789abcdef01234567");

        let cands = ice_attrs::read_candidates(audio);
        assert_eq!(cands, vec![host.clone()]);
        assert!(ice_attrs::read_rtcp_mux(audio));

        let call = manager.get_call(&call_id).expect("call exists");
        assert!(call.media().is_some(), "media wired up after answer build");
        assert_eq!(call.media().unwrap().local_port(), 7100);
    }

    #[test]
    fn build_answer_for_unknown_call() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let host = host_candidate([10, 0, 0, 5], 7100);
        let local = ice_local(&host);
        let inputs = IceAnswerInputs::new(&host, &local);

        let fake = CallId::new();
        let answer = manager.build_answer_for(&fake, &inputs);
        assert!(answer.is_none());
    }

    #[test]
    fn build_answer_for_called_twice() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-303".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_sdp();
        let call_id = manager
            .accept_inbound_invite(dialog, &offer_sdp)
            .expect("accept_inbound_invite");

        let host = host_candidate([10, 0, 0, 5], 7100);
        let local = ice_local(&host);
        let inputs = IceAnswerInputs::new(&host, &local);

        assert!(manager.build_answer_for(&call_id, &inputs).is_some());
        assert!(
            manager.build_answer_for(&call_id, &inputs).is_none(),
            "second call returns None — pending answer cleared"
        );
    }

    #[test]
    fn accept_then_reject_inbound_invite_terminates_cleanly() {
        // R1: a call accepted via `accept_inbound_invite` and never
        // answered (e.g. ICE gather failed) must terminate via
        // `reject_inbound_invite` — `terminate_call` won't act because
        // the call is `Ringing`, not `Established`.
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-304".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_sdp();
        let call_id = manager
            .accept_inbound_invite(dialog, &offer_sdp)
            .expect("accept_inbound_invite");
        // Drain the IncomingCall event so the rejection event is the
        // only thing in the queue at the assert below.
        let _ = manager.drain_events();

        // `terminate_call` refuses the Ringing+pending state.
        assert!(
            manager.terminate_call(&call_id).is_none(),
            "terminate_call must not act on a pending inbound call"
        );

        // `reject_inbound_invite` returns the dialog ID and terminates.
        let dialog_id = manager
            .reject_inbound_invite(&call_id)
            .expect("reject_inbound_invite returns dialog id");

        // Snapshot the call state and the dialog id from the immutable
        // view, then drop the borrow before draining events (which
        // needs `&mut self`).
        {
            let call = manager.get_call(&call_id).expect("call still present");
            assert_eq!(call.state(), CallState::Terminated);
            assert!(
                !call.has_pending_answer(),
                "pending answer must be cleared on rejection"
            );
            assert_eq!(call.dialog_id(), Some(&dialog_id));
        }

        // `Ended(Error)` is emitted.
        let events = manager.drain_events();
        assert!(events.iter().any(|e| matches!(
            e,
            ManagerEvent::CallEvent(_, CallEvent::Ended(CallEndReason::Error))
        )));

        // Second rejection is a no-op.
        assert!(manager.reject_inbound_invite(&call_id).is_none());
    }

    #[test]
    fn reject_inbound_invite_after_build_is_noop() {
        // A call that already had its answer built should not be
        // rejected via `reject_inbound_invite` — the `pending_answer`
        // is cleared, so `has_pending_answer` is false.
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-305".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_sdp();
        let call_id = manager
            .accept_inbound_invite(dialog, &offer_sdp)
            .expect("accept_inbound_invite");

        let host = host_candidate([10, 0, 0, 5], 7100);
        let local = ice_local(&host);
        let inputs = IceAnswerInputs::new(&host, &local);
        manager
            .build_answer_for(&call_id, &inputs)
            .expect("build_answer_for");

        assert!(
            manager.reject_inbound_invite(&call_id).is_none(),
            "reject must be a no-op once the answer is built"
        );
    }

    #[test]
    fn reject_inbound_invite_unknown_call() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let fake = CallId::new();
        assert!(manager.reject_inbound_invite(&fake).is_none());
    }

    #[test]
    fn reject_inbound_invite_on_normal_ringing_call_is_noop() {
        // A Ringing call that came in via `handle_incoming_invite` (i.e.
        // already has media, no pending answer) must NOT be rejected by
        // `reject_inbound_invite` — that's `reject_call`'s job.
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-306".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_sdp();
        let (call_id, _, _) = manager
            .handle_incoming_invite(dialog, &offer_sdp)
            .expect("handle_incoming_invite");

        // State is Ringing, but no pending answer — must no-op.
        assert!(manager.reject_inbound_invite(&call_id).is_none());
    }

    #[test]
    fn inbound_ice_full_flow_unit() {
        // A1: full happy path at the manager layer — accept, build
        // answer, validate the SDP, answer the call, observe media.
        let mut manager = CallManager::new(ManagerConfig::default());

        let dialog = Dialog::new_uas(
            "call-307".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let offer_sdp = test_sdp();
        let call_id = manager
            .accept_inbound_invite(dialog, &offer_sdp)
            .expect("accept_inbound_invite");

        let host = host_candidate([10, 0, 0, 5], 7100);
        let local = ice_local(&host);
        let inputs = IceAnswerInputs::new(&host, &local);

        let answer = manager
            .build_answer_for(&call_id, &inputs)
            .expect("build_answer_for");

        // Wire-format round-trip: the answer must serialize and parse
        // back cleanly.
        let answer_str = answer.to_string();
        let parsed = SessionDescription::parse(&answer_str).expect("answer SDP parses");

        // Connection patched to candidate's family/address.
        let mconn = parsed
            .audio_media()
            .expect("audio media")
            .connection
            .as_ref()
            .expect("media-level c=");
        assert_eq!(mconn.address, "10.0.0.5");
        assert_eq!(mconn.addr_type, "IP4");

        // m= port is the candidate's port.
        let audio = parsed.audio_media().expect("audio media");
        assert_eq!(audio.port, 7100);

        // ICE attrs round-trip.
        let (ufrag, pwd) = ice_attrs::read_ice_credentials(audio).expect("ICE credentials parsed");
        assert_eq!(ufrag, "abc1234");
        assert_eq!(pwd, "0123456789abcdef01234567");
        let cands = ice_attrs::read_candidates(audio);
        assert_eq!(cands, vec![host.clone()]);
        assert!(ice_attrs::read_rtcp_mux(audio));

        // Codec line: PCMU was the offer's preferred codec.
        let rtpmaps = audio.rtpmaps();
        assert!(
            rtpmaps.iter().any(|r| r.encoding == "PCMU"),
            "answer must carry PCMU rtpmap"
        );

        // The call is still Ringing — `build_answer_for` only constructs
        // the answer; sending and `answer_call` are the app's job.
        let call = manager.get_call(&call_id).expect("call");
        assert_eq!(call.state(), CallState::Ringing);

        // `answer_call` flips Established and media is now wired.
        assert!(manager.answer_call(&call_id));
        let call = manager.get_call(&call_id).expect("call");
        assert_eq!(call.state(), CallState::Established);
        assert!(call.media().is_some(), "media must be wired after build");
        assert_eq!(call.media().unwrap().local_port(), 7100);
    }
}

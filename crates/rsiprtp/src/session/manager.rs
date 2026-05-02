//! Call manager for orchestrating multiple calls.
//!
//! The CallManager handles routing SIP messages to the appropriate calls,
//! managing call lifecycle, and coordinating signaling with media.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
use crate::sip::headers::Refresher;
use crate::sip::{Method, SipRequest, SipResponse};

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

/// Headers the application should add to an outbound INVITE for the
/// supported feature set (RFC 4028 session timers + RFC 3262 PRACK).
///
/// When `session_expires` is `None`, session timers are disabled
/// (CallConfig.session_expires == ZERO): emit `supported_tags` and
/// `allow_methods` only. When `Some`, also emit `Session-Expires:
/// <secs>;refresher=uac` and `Min-SE: <secs>`.
#[derive(Debug, Clone)]
pub struct InviteOfferHeaders {
    /// Option-tags for the `Supported` header (e.g. `100rel`, `timer`).
    pub supported_tags: Vec<String>,
    /// Methods for the `Allow` header.
    pub allow_methods: Vec<Method>,
    /// Session-Expires `(delta-seconds, refresher=uac)`. `None` when
    /// `session_expires == ZERO` in `CallConfig`.
    pub session_expires: Option<(u32, Refresher)>,
    /// Min-SE delta-seconds. `None` when session timers are disabled.
    pub min_se: Option<u32>,
}

/// Negotiated session-timer state for an inbound INVITE.
///
/// Returned by [`CallManager::evaluate_inbound_invite_session_timer`]
/// so the application knows whether to reject with 422 or proceed.
#[derive(Debug, Clone)]
pub enum InboundSessionTimer {
    /// Session-Expires omitted by peer or peer didn't advertise `timer`
    /// support — establish the call without session timers.
    Disabled,
    /// Session-Expires present and acceptable. We negotiate the
    /// indicated `(session_expires, refresher)`. `refresher == Uac`
    /// means peer refreshes; `refresher == Uas` means we refresh.
    Accept {
        /// Negotiated interval to echo in our 200 OK and use for deadlines.
        session_expires: Duration,
        /// Refresher we picked (RFC 4028 §7.4): UAC if the peer
        /// advertised `Supported: timer`, else UAS.
        refresher: Refresher,
    },
    /// Peer's `Session-Expires` was below our `Min-SE`; respond 422
    /// with `Min-SE: <secs>` set from the call config.
    Reject422 {
        /// Min-SE to advertise in the 422 response.
        min_se: u32,
    },
}

/// An outbound request emitted by the manager (PRACK, refresh
/// UPDATE/re-INVITE, expiry BYE) for the application to dispatch via
/// its transaction layer.
///
/// The application is responsible for opening the appropriate
/// transaction (NonInvite for PRACK / UPDATE / BYE; InviteClient for
/// a re-INVITE refresh) and threading the response back into the
/// manager via the existing `handle_*` entry points.
#[derive(Debug, Clone)]
pub struct OutboundRequest {
    /// Call this request belongs to.
    pub call_id: CallId,
    /// The request to send.
    pub request: SipRequest,
    /// What kind of request this is (so the app can pick the right
    /// transaction type / response handler).
    pub kind: OutboundRequestKind,
}

/// Classification of an [`OutboundRequest`] so the app can route it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundRequestKind {
    /// PRACK acknowledging a reliable provisional. NonInvite client tx.
    Prack,
    /// Session-timer refresh via UPDATE. NonInvite client tx.
    SessionTimerUpdate,
    /// Session-timer refresh via re-INVITE (UPDATE-not-supported
    /// fallback). InviteClient transaction.
    SessionTimerReInvite,
    /// BYE sent because the peer (the refresher) failed to refresh
    /// within `expiry_at`. NonInvite client tx.
    SessionTimerExpiryBye,
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
    /// Outbound requests the manager has built (PRACK, refresh
    /// UPDATE/re-INVITE, expiry BYE) waiting for the app to dispatch.
    pending_outbound_requests: Vec<OutboundRequest>,
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
            pending_outbound_requests: Vec::new(),
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
    ///
    /// Establishes the call, attaches negotiated media, registers the
    /// dialog mapping, and (when `response` is `Some`) applies any
    /// session-timer state carried by the response — `Session-Expires`
    /// drives `refresh_at`/`expiry_at` per RFC 4028 §7.1, with
    /// `now: Instant` as the reference point. Pass `response = None`
    /// only in test paths that don't exercise session timers.
    ///
    /// `dialog` must be a UAC dialog (caller-side). The route_set and
    /// remote_target on `dialog` are normally populated by the caller
    /// from the response's Record-Route + Contact; this method does
    /// not re-derive them. If the caller forgot to populate them,
    /// in-dialog requests built later will not carry Route headers
    /// (RFC 3261 §12.2.1.1 violation against routed peers).
    pub fn handle_invite_success(
        &mut self,
        call_id: &CallId,
        dialog: Dialog,
        answer_sdp: &SessionDescription,
        response: Option<&SipResponse>,
        now: Instant,
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

        // Populate the dialog's routing state from the 200 OK so
        // future in-dialog requests (PRACK, UPDATE, refresh re-INVITE,
        // expiry BYE) carry correct Route headers + request URI per
        // RFC 3261 §12.2.1.1.
        let mut dialog = dialog;
        if let Some(resp) = response {
            // UAC: Record-Route is reversed (RFC 3261 §12.1.2).
            let record_routes = resp.record_routes();
            if !record_routes.is_empty() {
                dialog.set_route_set_from_record_routes(&record_routes, true);
            }
            if let Some(contact) = resp.contact_uri() {
                dialog.set_remote_target(contact.to_string());
            }
        }
        call.set_dialog(dialog);
        // Surface a media-session construction error by failing the
        // 200-OK handler — the caller treats `false` as "could not
        // establish call".
        if let Err(e) = call.set_negotiated_media(media, local_port) {
            tracing::warn!(error = %e, "200 OK media setup failed");
            return false;
        }
        call.handle_answer();

        // Apply session-timer state from the response in the same
        // call-mut borrow — folds the previously-public
        // `handle_invite_2xx_session_timer` choreography into a single
        // entry point so the app can't forget to make the second call.
        if let Some(resp) = response {
            Self::apply_invite_2xx_session_timer(call, resp, now);
        }

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

    /// Apply a 200 OK's `Session-Expires:` to a call. Internal helper
    /// used by `handle_invite_success`.
    fn apply_invite_2xx_session_timer(call: &mut Call, response: &SipResponse, now: Instant) {
        let Some(se) = response.session_expires() else {
            return;
        };
        // RFC 4028 §7.1: if peer omits the refresher, default to UAC.
        let refresher = se.refresher.unwrap_or(Refresher::Uac);
        let session_expires = Duration::from_secs(se.delta_seconds as u64);

        call.session_expires = Some(session_expires);
        call.refresher = Some(refresher);
        match refresher {
            Refresher::Uac => {
                call.refresh_at = Some(now + session_expires / 2);
                call.expiry_at = None;
            }
            Refresher::Uas => {
                call.expiry_at = Some(now + session_expires);
                call.refresh_at = None;
            }
        }
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

    /// Handle a 18x provisional response, populating the UAC dialog's
    /// routing fields from the response when it carries a To-tag.
    ///
    /// This is the early-dialog populate hook (mirrors `handle_invite_success`'s
    /// 200-OK populate). Without it, PRACK / outbound UPDATE built before
    /// 200 OK arrive at proxies *without* Route headers because the
    /// dialog's `route_set` is empty until 2xx — RFC 3261 §12.2.1.1
    /// requires those headers, and a real carrier with `Record-Route`
    /// stamping will silently drop our PRACK.
    ///
    /// The `local_contact` is what the application advertised as
    /// `Contact:` in the original outbound INVITE. Idempotent —
    /// subsequent 1xx + the 200 OK may all call this, the population
    /// converges to the same triple.
    ///
    /// Falls back to the no-tag case (treats response as `100 Trying`-class)
    /// by simply forwarding to `handle_provisional`.
    pub fn handle_provisional_response(
        &mut self,
        call_id: &CallId,
        response: &SipResponse,
        sdp: Option<&SessionDescription>,
        local_contact: &str,
    ) {
        let has_sdp = sdp.is_some();

        // Populate UAC dialog routing if the response carries a To-tag
        // (i.e. it has established at least an early dialog).
        if response.to_tag().is_some() {
            if let Some(call) = self.calls.get_mut(call_id) {
                if let Some(dialog) = call.dialog_mut() {
                    dialog.populate_uac_from_response(response, local_contact.to_string());
                }
            }
        }

        // Then run the existing provisional handling (state transition,
        // early-media setup).
        self.handle_provisional(call_id, has_sdp, sdp);
    }

    /// Populate the UAS-side dialog's routing fields from an inbound
    /// INVITE.
    ///
    /// The application MUST call this immediately after
    /// [`handle_incoming_invite`](Self::handle_incoming_invite) /
    /// [`accept_inbound_invite`](Self::accept_inbound_invite) on the
    /// inbound path so any UAS-driven in-dialog request (BYE, the 200 OK
    /// to UPDATE, a re-INVITE refresh) carries correct Route + Contact
    /// per RFC 3261 §12.1.1 / §12.2.1.1. `local_contact` is the URI the
    /// UAS will advertise as Contact in its 200 OK (typically derived
    /// from the manager's `local_rtp_addr` and the application's bind
    /// addr).
    ///
    /// This is a no-op when the call is unknown or the dialog is UAC.
    pub fn populate_uas_dialog_routing(
        &mut self,
        call_id: &CallId,
        invite: &SipRequest,
        local_contact: String,
    ) {
        if let Some(call) = self.calls.get_mut(call_id) {
            if let Some(dialog) = call.dialog_mut() {
                dialog.populate_uas_from_invite(invite, local_contact);
            }
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

    /// Headers the application should attach to an outbound INVITE.
    ///
    /// Always returns the PRACK / UPDATE option-tag and matching
    /// `Allow` set. When `CallConfig.session_expires == Duration::ZERO`,
    /// session-timer-related fields are `None` — the app must omit
    /// `Session-Expires` and `Min-SE` and must NOT add `timer` to
    /// `Supported`. Otherwise both are populated and `timer` is
    /// added to `supported_tags`.
    pub fn invite_offer_headers(&self) -> InviteOfferHeaders {
        let allow_methods = vec![
            Method::Invite,
            Method::Ack,
            Method::Bye,
            Method::Cancel,
            Method::Options,
            Method::Prack,
            Method::Update,
        ];

        if self.call_config.session_expires.is_zero() {
            // RFC 4028 surface fully suppressed.
            InviteOfferHeaders {
                supported_tags: vec!["100rel".to_string()],
                allow_methods,
                session_expires: None,
                min_se: None,
            }
        } else {
            let se_secs = self.call_config.session_expires.as_secs() as u32;
            let min_se_secs = self.call_config.min_se.as_secs() as u32;
            InviteOfferHeaders {
                supported_tags: vec!["timer".to_string(), "100rel".to_string()],
                allow_methods,
                session_expires: Some((se_secs, Refresher::Uac)),
                min_se: Some(min_se_secs),
            }
        }
    }

    /// Handle a reliable 1xx provisional and build the matching PRACK.
    ///
    /// Per RFC 3262, when a 1xx (>100) carries `Require: 100rel` and an
    /// `RSeq:`, the UAC must send a PRACK whose `RAck:` echoes the
    /// RSeq, the original INVITE's CSeq, and `INVITE`. The PRACK is
    /// appended to the manager's outbound queue (drainable via
    /// [`drain_outbound_requests`]) and also returned for callers
    /// preferring direct dispatch.
    ///
    /// Returns `None` when the response is not actually reliable
    /// (no `RSeq` or the call is unknown) — the app should fall back
    /// to the existing non-reliable provisional path in that case.
    pub fn handle_provisional_reliable(
        &mut self,
        call_id: &CallId,
        response: &SipResponse,
    ) -> Option<SipRequest> {
        // Sanity-check the response carries RSeq before delegating to
        // the dialog layer (which debug_asserts on missing RSeq).
        let _ = response.rseq()?;

        let call = self.calls.get_mut(call_id)?;
        let dialog = call.dialog_mut()?;

        // Build PRACK through the dialog layer so it picks up the
        // dialog's route_set and remote_target (RFC 3261 §12.2.1.1)
        // and emits Contact. The transient InviteDialog also bumps
        // its own local_seq; we mirror that bump back into the session
        // dialog so subsequent in-dialog requests stay monotonic.
        let mut invite_dialog = dialog.to_invite_dialog();
        let prack = invite_dialog.build_prack(response);
        // Mirror the cseq bump back to the session dialog.
        let _ = dialog.next_cseq();

        self.pending_outbound_requests.push(OutboundRequest {
            call_id: call_id.clone(),
            request: prack.clone(),
            kind: OutboundRequestKind::Prack,
        });
        Some(prack)
    }

    /// Evaluate session-timer headers on an inbound INVITE.
    ///
    /// Use the result to decide between three paths:
    /// - [`InboundSessionTimer::Disabled`] — peer didn't request
    ///   timers; proceed normally.
    /// - [`InboundSessionTimer::Accept`] — proceed; `accept_session_timer`
    ///   should be invoked once the call is established (at 200 OK
    ///   build time) to set the deadlines.
    /// - [`InboundSessionTimer::Reject422`] — respond 422 with the
    ///   embedded `Min-SE` and do NOT establish the call.
    pub fn evaluate_inbound_invite_session_timer(
        &self,
        request: &SipRequest,
    ) -> InboundSessionTimer {
        let Some(se) = request.session_expires() else {
            return InboundSessionTimer::Disabled;
        };

        let min_se_secs = self.call_config.min_se.as_secs() as u32;
        if (se.delta_seconds as u64) < self.call_config.min_se.as_secs() {
            return InboundSessionTimer::Reject422 {
                min_se: min_se_secs,
            };
        }

        // RFC 4028 §7.4 / HLD snag 2: as UAS, pick `uac` when the peer
        // advertised `Supported: timer`, else `uas`.
        let peer_supports_timer = request
            .supported()
            .map(|s| s.0.iter().any(|t| t.eq_ignore_ascii_case("timer")))
            .unwrap_or(false);
        let refresher = if peer_supports_timer {
            Refresher::Uac
        } else {
            Refresher::Uas
        };

        InboundSessionTimer::Accept {
            session_expires: Duration::from_secs(se.delta_seconds as u64),
            refresher,
        }
    }

    /// Apply the negotiated session-timer state to an established call
    /// (UAS side, called when our 200 OK is being sent).
    ///
    /// `refresher == Uac` means peer refreshes → `expiry_at = now + se`.
    /// `refresher == Uas` means we refresh → `refresh_at = now + se/2`.
    pub fn accept_session_timer(
        &mut self,
        call_id: &CallId,
        session_expires: Duration,
        refresher: Refresher,
        now: Instant,
    ) {
        if let Some(call) = self.calls.get_mut(call_id) {
            call.session_expires = Some(session_expires);
            call.refresher = Some(refresher);
            match refresher {
                Refresher::Uac => {
                    call.expiry_at = Some(now + session_expires);
                    call.refresh_at = None;
                }
                Refresher::Uas => {
                    call.refresh_at = Some(now + session_expires / 2);
                    call.expiry_at = None;
                }
            }
        }
    }

    /// Handle an inbound UPDATE request for an existing dialog.
    ///
    /// Builds a 200 OK echoing `Session-Expires` (when present),
    /// slides whichever deadline applies, and returns the response
    /// for the application to send. Returns `None` when no call
    /// matches the dialog ID — the application should respond
    /// `481 Call/Transaction Does Not Exist` itself.
    pub fn handle_inbound_update(
        &mut self,
        dialog_id: &DialogId,
        request: &SipRequest,
        now: Instant,
    ) -> Option<SipResponse> {
        let call_id = self.dialog_to_call.get(dialog_id)?.clone();
        let call = self.calls.get_mut(&call_id)?;

        // RFC 4028 §10.3: if the peer's Session-Expires is below our
        // Min-SE, reject with 422 carrying our Min-SE. Do NOT mutate the
        // call's session_expires or slide deadlines — the UPDATE is
        // rejected outright and our negotiated values stand.
        if let Some(se) = request.session_expires() {
            let min_se_secs = self.call_config.min_se.as_secs();
            if (se.delta_seconds as u64) < min_se_secs {
                let resp = SipResponse::builder()
                    .status(422, "Session Interval Too Small")
                    .from_request(request)
                    .min_se(min_se_secs as u32)
                    .build()
                    .ok()?;
                return Some(resp);
            }
            // Accepted — adopt the peer's Session-Expires for future
            // refresh deadline arithmetic.
            let new_se = Duration::from_secs(se.delta_seconds as u64);
            call.session_expires = Some(new_se);
        }
        call.slide_deadlines(now);

        // Build the 200 OK through the dialog layer so it carries
        // Allow + Contact (RFC 3261 §12.2.1.1) and echoes
        // Session-Expires consistently with PRACK / UPDATE / refresh
        // builders. The transient InviteDialog reads the dialog's
        // route_set + remote_target + local_contact; no session-layer
        // duplication of in-dialog response building.
        let dialog = call.dialog()?;
        let invite_dialog = dialog.to_invite_dialog();
        Some(invite_dialog.handle_update(request))
    }

    /// Slide both session-timer deadlines on the call matching this
    /// dialog ID. Call after any successful in-dialog 2xx for UPDATE
    /// or INVITE (refresh, hold/resume, transfer completion). No-op
    /// when the dialog or call is unknown, or when session timers are
    /// not enabled on the call.
    pub fn slide_deadlines_for_dialog(&mut self, dialog_id: &DialogId, now: Instant) {
        if let Some(call_id) = self.dialog_to_call.get(dialog_id).cloned() {
            if let Some(call) = self.calls.get_mut(&call_id) {
                call.slide_deadlines(now);
            }
        }
    }

    /// Notify the manager that an in-dialog 2xx for `method` was
    /// received on `call_id`.
    ///
    /// The application MUST call this on every successful 2xx response
    /// to an in-dialog `UPDATE` or `INVITE` it dispatched (refresh,
    /// hold-resume, transfer completion), so the session-timer
    /// deadlines slide forward per RFC 4028 §7. Other methods are
    /// ignored: only UPDATE and INVITE 2xx reset the deadline.
    ///
    /// The manager doesn't see outbound transactions itself today, so
    /// this is the only path that keeps `refresh_at` / `expiry_at`
    /// honest after manager-built refreshes succeed. Forgetting it
    /// silently doubles refresh attempts (next tick fires another).
    pub fn mark_in_dialog_2xx(&mut self, call_id: &CallId, method: Method, now: Instant) {
        if !matches!(method, Method::Update | Method::Invite) {
            return;
        }
        if let Some(call) = self.calls.get_mut(call_id) {
            call.slide_deadlines(now);
        }
    }

    /// Set or clear the "UAC transaction in flight" flag for a call.
    ///
    /// `tick` skips firing a refresh while this is `true` so refresh
    /// doesn't race a hold / transfer / re-INVITE the application
    /// already issued. The application is expected to set it on
    /// transaction creation and clear it on terminal response.
    pub fn set_uac_in_flight(&mut self, call_id: &CallId, in_flight: bool) {
        if let Some(call) = self.calls.get_mut(call_id) {
            call.uac_in_flight = in_flight;
        }
    }

    /// App-driven signal: the peer just rejected our outbound UPDATE
    /// with 405 Method Not Allowed or 501 Not Implemented. Future
    /// refreshes on this call will use re-INVITE (RFC 4028 §7).
    ///
    /// The manager doesn't observe transaction-level responses today,
    /// so this can't be flipped automatically — the application
    /// dispatching the UPDATE NonInvite client transaction MUST call
    /// this on receipt of 405 or 501. Renamed from the old
    /// `mark_update_unsupported` to make the app-driven contract
    /// obvious: the manager *notes* what the app observed.
    pub fn note_update_unsupported(&mut self, call_id: &CallId) {
        if let Some(call) = self.calls.get_mut(call_id) {
            call.update_unsupported = true;
        }
    }

    /// Drain the queue of outbound requests built by the manager
    /// (PRACK, refresh UPDATE/re-INVITE, expiry BYE).
    ///
    /// The application is responsible for opening the appropriate
    /// transaction (NonInvite client for PRACK / UPDATE / BYE,
    /// InviteClient for the re-INVITE refresh) and threading the
    /// final response back via the existing entry points.
    pub fn drain_outbound_requests(&mut self) -> Vec<OutboundRequest> {
        std::mem::take(&mut self.pending_outbound_requests)
    }

    /// Fire any session-timer deadlines that have elapsed.
    ///
    /// For each call in `Established`:
    /// - When `refresh_at <= now` and we are the refresher and no UAC
    ///   transaction is in flight: emit a UPDATE refresh (or re-INVITE
    ///   when `update_unsupported`); tentatively slide `refresh_at`.
    /// - When `expiry_at <= now` and the peer is the refresher: emit a
    ///   BYE with `Reason: SIP;cause=200;text="Session timer expired"`,
    ///   transition the call to `Terminating`, and emit a
    ///   `CallStateChanged` event.
    ///
    /// Idempotent: deadlines slide forward as the actions are emitted,
    /// so a second call with the same `now` does nothing.
    pub fn tick(&mut self, now: Instant) {
        // Snapshot the call IDs to avoid borrow issues during mutation.
        let ids: Vec<CallId> = self
            .calls
            .iter()
            .filter(|(_, c)| c.state() == CallState::Established)
            .map(|(id, _)| id.clone())
            .collect();

        for id in ids {
            // Refresh path.
            self.maybe_fire_refresh(&id, now);
            // Expiry path.
            self.maybe_fire_expiry_bye(&id, now);
        }
    }

    /// Soonest deadline across all `Established` calls.
    ///
    /// Returns the earliest of `refresh_at` and `expiry_at` over the
    /// set of established calls; `None` if no established call has
    /// session timers enabled. The application passes this to
    /// `tokio::time::sleep_until` to avoid spinning on `tick`.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.calls
            .values()
            .filter(|c| c.state() == CallState::Established)
            .filter_map(|c| match (c.refresh_at, c.expiry_at) {
                (Some(r), Some(e)) => Some(r.min(e)),
                (Some(r), None) => Some(r),
                (None, Some(e)) => Some(e),
                (None, None) => None,
            })
            .min()
    }

    fn maybe_fire_refresh(&mut self, call_id: &CallId, now: Instant) {
        let (build_update, body) = {
            let call = match self.calls.get(call_id) {
                Some(c) => c,
                None => return,
            };
            let Some(deadline) = call.refresh_at else {
                return;
            };
            if deadline > now {
                return;
            }
            if call.uac_in_flight {
                return;
            }
            let Some(_) = call.dialog() else { return };

            // Pick UPDATE vs re-INVITE based on the unsupported flag.
            let use_update = !call.update_unsupported;

            // For re-INVITE we need to rebuild the offer SDP from the
            // negotiated MediaSession (HLD snag 3). UPDATE has no body.
            let body = if use_update {
                None
            } else {
                Some(self.build_refresh_invite_sdp(call_id))
            };
            (use_update, body)
        };

        // Build the request itself with a separate borrow.
        let request = if build_update {
            self.build_update_request(call_id)
        } else {
            self.build_reinvite_refresh_request(call_id, body.flatten())
        };
        let Some(request) = request else { return };

        let kind = if build_update {
            OutboundRequestKind::SessionTimerUpdate
        } else {
            OutboundRequestKind::SessionTimerReInvite
        };

        // Tentatively slide the refresh deadline forward; the 200 OK
        // would slide it again confirmingly, but a 4xx/5xx leaves the
        // tentative slide which is fine — the next tick will retry
        // after another se/2.
        if let Some(call) = self.calls.get_mut(call_id) {
            if let Some(se) = call.session_expires {
                call.refresh_at = Some(now + se / 2);
            }
        }

        self.pending_outbound_requests.push(OutboundRequest {
            call_id: call_id.clone(),
            request,
            kind,
        });
    }

    fn maybe_fire_expiry_bye(&mut self, call_id: &CallId, now: Instant) {
        let should_fire = {
            let call = match self.calls.get(call_id) {
                Some(c) => c,
                None => return,
            };
            matches!(call.expiry_at, Some(deadline) if deadline <= now)
        };
        if !should_fire {
            return;
        }

        let request = match self.build_expiry_bye_request(call_id) {
            Some(r) => r,
            None => return,
        };

        // Clear the expiry deadline so a second tick doesn't re-fire.
        if let Some(call) = self.calls.get_mut(call_id) {
            call.expiry_at = None;
            call.set_state(CallState::Terminating);
        }

        self.pending_outbound_requests.push(OutboundRequest {
            call_id: call_id.clone(),
            request,
            kind: OutboundRequestKind::SessionTimerExpiryBye,
        });

        self.events.push(ManagerEvent::CallStateChanged(
            call_id.clone(),
            CallState::Terminating,
        ));
    }

    /// Build an in-dialog UPDATE for a session-timer refresh.
    ///
    /// No body. Routed through the dialog layer's `build_update`, so
    /// `Supported: timer`, `Session-Expires: <secs>;refresher=uac`,
    /// `Allow:`, Contact, and Route headers all come from one builder.
    fn build_update_request(&mut self, call_id: &CallId) -> Option<SipRequest> {
        let call = self.calls.get_mut(call_id)?;
        let se = call.session_expires?;
        let dialog = call.dialog_mut()?;

        let mut invite_dialog = dialog.to_invite_dialog();
        let update = invite_dialog.build_update(Some(se.as_secs() as u32));
        // Mirror the cseq bump back to the session dialog.
        let _ = dialog.next_cseq();
        Some(update)
    }

    /// Build a re-INVITE refresh request when the peer doesn't support
    /// UPDATE (the `update_unsupported` fallback). The negotiated SDP
    /// is rebuilt verbatim from `MediaSession` (HLD snag 3) — same
    /// codec, same port, no renegotiation.
    ///
    /// Routed through the dialog layer's
    /// `build_in_dialog_request_with` (via the public-ish
    /// `build_bye_with_reason` shape) so Route + Contact are
    /// consistent. Re-INVITE-with-Reason isn't a use case; we
    /// extend `build_in_dialog_request_with` indirectly by adding
    /// Session-Expires, Supported: timer, Allow, and the SDP body
    /// here using the existing `SipRequestBuilder` chain on top of a
    /// dialog-built skeleton.
    fn build_reinvite_refresh_request(
        &mut self,
        call_id: &CallId,
        body: Option<Vec<u8>>,
    ) -> Option<SipRequest> {
        use crate::dialog::DialogState;

        let call = self.calls.get_mut(call_id)?;
        let se = call.session_expires?;
        let dialog = call.dialog_mut()?;

        // Reconstruct the dialog and pull route_set + remote_target +
        // local_contact for this re-INVITE. We can't use
        // `build_update` (different method) and there is no
        // `build_reinvite` on the dialog layer, so build manually but
        // sourcing routing from the same DialogInfo the dialog layer
        // would use — guaranteeing parity with PRACK / UPDATE / BYE.
        let info = dialog.to_invite_dialog().info().clone();
        let _ = (DialogState::Confirmed,); // doc cross-ref
        let next_cseq = dialog.next_cseq();
        let request_uri = if info.remote_target.is_empty() {
            info.remote_uri.clone()
        } else {
            info.remote_target.clone()
        };
        let routes = info.route_set.routes();
        let branch = format!("z9hG4bK{}", uuid::Uuid::new_v4().simple());

        let mut builder = SipRequest::builder()
            .method(Method::Invite)
            .uri(&request_uri)
            .via(&self.config.local_rtp_addr, 5060, "UDP", &branch)
            .from(&info.local_uri, &info.id.local_tag)
            .to(&info.remote_uri)
            .to_tag(&info.id.remote_tag)
            .call_id(&info.id.call_id)
            .cseq(next_cseq)
            .max_forwards(70)
            .route(routes)
            .session_expires(se.as_secs() as u32, Some(Refresher::Uac))
            .supported(&["timer"])
            .allow(&[
                Method::Invite,
                Method::Ack,
                Method::Bye,
                Method::Cancel,
                Method::Options,
                Method::Prack,
                Method::Update,
            ]);

        // RFC 3261 §12.2.1.1: in-dialog requests SHOULD carry Contact.
        if !info.local_contact.is_empty() {
            builder = builder.contact(&info.local_contact);
        }

        if let Some(body_bytes) = body {
            builder = builder.body(body_bytes, "application/sdp");
        }

        builder.build().ok()
    }

    /// Rebuild the offer SDP for a refresh re-INVITE from the call's
    /// `MediaSession` and the negotiated codec (HLD snag 3).
    ///
    /// Mirrors the established session: same codec at the same port,
    /// same direction. No codec renegotiation is intended. Returns
    /// `None` if the call has no media or the SDP can't be built —
    /// the caller treats `None` as "skip this refresh".
    fn build_refresh_invite_sdp(&self, call_id: &CallId) -> Option<Vec<u8>> {
        use crate::sdp::builder::{MediaBuilder, SdpBuilder};
        let call = self.calls.get(call_id)?;
        let media = call.media()?;
        let codec = call.codec()?;
        let local_addr: std::net::IpAddr = self.config.local_rtp_addr.parse().ok()?;
        let local_port = media.local_port();

        // Rebuild the audio media line from the negotiated codec. This
        // is intentionally minimal — the only semantic difference vs
        // the original offer is that we know exactly which codec the
        // peer accepted, so we offer just that one. RFC 4028 refresh
        // is not codec renegotiation.
        let media_builder = match codec.encoding.to_uppercase().as_str() {
            "PCMU" => MediaBuilder::audio(local_port).pcmu(),
            "PCMA" => MediaBuilder::audio(local_port).pcma(),
            "G722" => MediaBuilder::audio(local_port).g722(),
            // For codecs without a builder shortcut (e.g. Opus) we fall
            // back to a generic dynamic payload-type entry.
            other => MediaBuilder::audio(local_port).codec(
                codec.payload_type,
                other,
                codec.clock_rate,
                Some(codec.channels),
            ),
        };

        let sdp = SdpBuilder::new(local_addr)
            .session_name("rsiprtp refresh")
            .add_media(media_builder)
            .build();
        Some(sdp.to_string().into_bytes())
    }

    /// Build an in-dialog BYE for a session-timer expiry. Adds the
    /// RFC 3326 `Reason: SIP;cause=200;text="Session timer expired"`
    /// header so operators / peers can distinguish this from a normal
    /// hangup.
    ///
    /// Routed through the dialog layer's `build_bye_with_reason` so
    /// Route + Contact are sourced from the dialog's route_set +
    /// remote_target + local_contact (RFC 3261 §12.2.1.1).
    fn build_expiry_bye_request(&mut self, call_id: &CallId) -> Option<SipRequest> {
        let call = self.calls.get_mut(call_id)?;
        let dialog = call.dialog_mut()?;

        let mut invite_dialog = dialog.to_invite_dialog();
        let bye =
            invite_dialog.build_bye_with_reason(r#"SIP;cause=200;text="Session timer expired""#)?;
        // Mirror the cseq bump back to the session dialog.
        let _ = dialog.next_cseq();
        Some(bye)
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
        manager.handle_invite_success(&call_id, dialog, &answer_sdp, None, Instant::now());

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
        let result =
            manager.handle_invite_success(&call_id, dialog, &answer_sdp, None, Instant::now());

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
        let result =
            manager.handle_invite_success(&call_id, dialog, &answer_sdp, None, Instant::now());

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
        let result =
            manager.handle_invite_success(&fake_id, dialog, &answer_sdp, None, Instant::now());

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
        manager.handle_invite_success(&call_id, dialog, &answer_sdp, None, Instant::now());

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
        manager.handle_invite_success(&call_id, dialog, &answer_sdp, None, Instant::now());

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
        manager.handle_invite_success(&call_id, dialog, &answer_sdp, None, Instant::now());

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
        manager.handle_invite_success(&call_id, dialog, &answer_sdp, None, Instant::now());

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

    // ----- Phase 4: session timer / PRACK wiring -----

    fn established_outbound_call(manager: &mut CallManager) -> CallId {
        let call_id = manager.create_call("sip:bob@example.com".to_string());
        let dialog = Dialog::new_uac(
            "call-st-1".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );
        let answer_sdp = test_sdp();
        manager.handle_invite_success(&call_id, dialog, &answer_sdp, None, Instant::now());
        // Drain seed events so test assertions only see what we triggered.
        let _ = manager.drain_events();
        call_id
    }

    #[test]
    fn invite_offer_headers_default_emits_timer_and_min_se() {
        let manager = CallManager::new(ManagerConfig::default());
        let h = manager.invite_offer_headers();
        assert!(h.supported_tags.iter().any(|t| t == "timer"));
        assert!(h.supported_tags.iter().any(|t| t == "100rel"));
        assert!(h.allow_methods.contains(&Method::Prack));
        assert!(h.allow_methods.contains(&Method::Update));
        assert_eq!(h.session_expires.unwrap().0, 1800);
        assert!(matches!(h.session_expires.unwrap().1, Refresher::Uac));
        assert_eq!(h.min_se, Some(90));
    }

    #[test]
    fn invite_offer_headers_zero_session_expires_suppresses_timer() {
        let mut cfg = ManagerConfig::default();
        cfg.call_config.session_expires = Duration::ZERO;
        let manager = CallManager::new(cfg);
        let h = manager.invite_offer_headers();
        // No `timer` tag, no Session-Expires, no Min-SE — but PRACK
        // and Allow remain.
        assert!(!h.supported_tags.iter().any(|t| t == "timer"));
        assert!(h.supported_tags.iter().any(|t| t == "100rel"));
        assert!(h.session_expires.is_none());
        assert!(h.min_se.is_none());
        assert!(h.allow_methods.contains(&Method::Prack));
    }

    /// Helper for the folded session-timer path: build an outbound
    /// call, run `handle_invite_success` with a synthetic 200 OK
    /// carrying the requested Session-Expires, return the call_id.
    fn establish_with_2xx(
        manager: &mut CallManager,
        response: &SipResponse,
        now: Instant,
    ) -> CallId {
        let call_id = manager.create_call("sip:bob@example.com".to_string());
        let dialog = Dialog::new_uac(
            "call-st-1".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );
        let answer_sdp = test_sdp();
        manager.handle_invite_success(&call_id, dialog, &answer_sdp, Some(response), now);
        let _ = manager.drain_events();
        call_id
    }

    #[test]
    fn handle_invite_success_uac_refresher_sets_refresh_at() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let response = SipResponse::builder()
            .status(200, "OK")
            .session_expires(60, Some(Refresher::Uac))
            .build()
            .expect("response");

        let now = Instant::now();
        let call_id = establish_with_2xx(&mut manager, &response, now);

        let call = manager.get_call(&call_id).expect("call");
        assert_eq!(call.session_expires, Some(Duration::from_secs(60)));
        assert!(matches!(call.refresher, Some(Refresher::Uac)));
        // We refresh: refresh_at = now + se/2.
        assert!(call.refresh_at.is_some());
        assert!(call.expiry_at.is_none());
    }

    #[test]
    fn handle_invite_success_uas_refresher_sets_expiry_at() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let response = SipResponse::builder()
            .status(200, "OK")
            .session_expires(60, Some(Refresher::Uas))
            .build()
            .expect("response");

        let now = Instant::now();
        let call_id = establish_with_2xx(&mut manager, &response, now);

        let call = manager.get_call(&call_id).expect("call");
        assert_eq!(call.session_expires, Some(Duration::from_secs(60)));
        // Peer refreshes: expiry_at set, refresh_at clear.
        assert!(call.refresh_at.is_none());
        assert!(call.expiry_at.is_some());
    }

    #[test]
    fn handle_invite_success_no_session_expires_leaves_timers_disabled() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let response = SipResponse::builder()
            .status(200, "OK")
            .build()
            .expect("response");

        let call_id = establish_with_2xx(&mut manager, &response, Instant::now());

        let call = manager.get_call(&call_id).expect("call");
        assert!(call.session_expires.is_none());
        assert!(call.refresh_at.is_none());
        assert!(call.expiry_at.is_none());
    }

    #[test]
    fn handle_invite_success_emits_state_change_in_single_call() {
        // Reviewer's load-bearing claim: the folded entry point sets
        // both call state AND timer deadlines from a single
        // application call. Asserts both effects are visible after
        // ONE handle_invite_success(...) call.
        let mut manager = CallManager::new(ManagerConfig::default());
        let response = SipResponse::builder()
            .status(200, "OK")
            .session_expires(60, Some(Refresher::Uac))
            .build()
            .expect("response");

        let call_id = manager.create_call("sip:bob@example.com".to_string());
        let dialog = Dialog::new_uac(
            "call-st-1".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );
        let answer_sdp = test_sdp();
        let now = Instant::now();
        let ok = manager.handle_invite_success(&call_id, dialog, &answer_sdp, Some(&response), now);
        assert!(ok);

        // State change emitted.
        let events = manager.drain_events();
        assert!(events
            .iter()
            .any(|e| matches!(e, ManagerEvent::CallStateChanged(_, CallState::Established))));

        // Deadlines applied in the SAME call.
        let call = manager.get_call(&call_id).expect("call");
        assert_eq!(call.session_expires, Some(Duration::from_secs(60)));
        assert!(call.refresh_at.is_some());
    }

    #[test]
    fn evaluate_inbound_invite_session_timer_disabled() {
        let manager = CallManager::new(ManagerConfig::default());
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "ftag")
            .to("sip:bob@example.com")
            .call_id("c@h")
            .cseq(1)
            .build()
            .unwrap();
        assert!(matches!(
            manager.evaluate_inbound_invite_session_timer(&req),
            InboundSessionTimer::Disabled
        ));
    }

    #[test]
    fn evaluate_inbound_invite_session_timer_below_min_se_rejects_422() {
        let manager = CallManager::new(ManagerConfig::default());
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "ftag")
            .to("sip:bob@example.com")
            .call_id("c@h")
            .cseq(1)
            .session_expires(30, None)
            .build()
            .unwrap();
        match manager.evaluate_inbound_invite_session_timer(&req) {
            InboundSessionTimer::Reject422 { min_se } => assert_eq!(min_se, 90),
            other => panic!("expected Reject422, got {:?}", other),
        }
    }

    #[test]
    fn evaluate_inbound_invite_session_timer_picks_uac_when_peer_supports() {
        let manager = CallManager::new(ManagerConfig::default());
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "ftag")
            .to("sip:bob@example.com")
            .call_id("c@h")
            .cseq(1)
            .session_expires(120, None)
            .supported(&["timer", "100rel"])
            .build()
            .unwrap();
        match manager.evaluate_inbound_invite_session_timer(&req) {
            InboundSessionTimer::Accept {
                session_expires,
                refresher,
            } => {
                assert_eq!(session_expires, Duration::from_secs(120));
                assert!(matches!(refresher, Refresher::Uac));
            }
            other => panic!("expected Accept, got {:?}", other),
        }
    }

    #[test]
    fn evaluate_inbound_invite_session_timer_picks_uas_when_peer_silent() {
        let manager = CallManager::new(ManagerConfig::default());
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "ftag")
            .to("sip:bob@example.com")
            .call_id("c@h")
            .cseq(1)
            .session_expires(120, None)
            .build()
            .unwrap();
        match manager.evaluate_inbound_invite_session_timer(&req) {
            InboundSessionTimer::Accept { refresher, .. } => {
                assert!(matches!(refresher, Refresher::Uas));
            }
            other => panic!("expected Accept, got {:?}", other),
        }
    }

    #[test]
    fn tick_fires_refresh_when_we_are_refresher() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);

        // Force us to be the refresher with a deadline already past.
        let now = Instant::now();
        let past = now - Duration::from_secs(1);
        {
            let call = manager.get_call_mut(&call_id).unwrap();
            call.session_expires = Some(Duration::from_secs(60));
            call.refresher = Some(Refresher::Uac);
            call.refresh_at = Some(past);
        }

        manager.tick(now);
        let outbound = manager.drain_outbound_requests();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].kind, OutboundRequestKind::SessionTimerUpdate);
        assert_eq!(outbound[0].request.method(), Method::Update);

        // Idempotent: second tick at the same instant should not
        // re-fire (deadline slid forward by tick).
        manager.tick(now);
        assert!(manager.drain_outbound_requests().is_empty());
    }

    #[test]
    fn tick_uses_re_invite_when_update_unsupported() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);

        // Wire up media so the re-INVITE refresh can rebuild the SDP.
        let media = NegotiatedMedia {
            codec: Codec::pcmu(),
            remote_port: 6000,
            remote_addr: Some("10.0.0.1".to_string()),
            direction: Direction::SendRecv,
        };
        manager
            .get_call_mut(&call_id)
            .unwrap()
            .set_negotiated_media(media, 5000)
            .expect("media");

        let now = Instant::now();
        {
            let call = manager.get_call_mut(&call_id).unwrap();
            call.session_expires = Some(Duration::from_secs(60));
            call.refresher = Some(Refresher::Uac);
            call.refresh_at = Some(now - Duration::from_secs(1));
            call.update_unsupported = true;
        }

        manager.tick(now);
        let outbound = manager.drain_outbound_requests();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].kind, OutboundRequestKind::SessionTimerReInvite);
        assert_eq!(outbound[0].request.method(), Method::Invite);
        // Re-INVITE refresh MUST carry SDP — peer answers wouldn't be
        // legal otherwise (HLD snag 3).
        assert!(!outbound[0].request.body().is_empty());
    }

    #[test]
    fn tick_skips_refresh_when_uac_in_flight() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);

        let now = Instant::now();
        {
            let call = manager.get_call_mut(&call_id).unwrap();
            call.session_expires = Some(Duration::from_secs(60));
            call.refresher = Some(Refresher::Uac);
            call.refresh_at = Some(now - Duration::from_secs(1));
            call.uac_in_flight = true;
        }

        manager.tick(now);
        assert!(manager.drain_outbound_requests().is_empty());
    }

    #[test]
    fn tick_byes_call_when_peer_refresher_expired() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);

        let now = Instant::now();
        {
            let call = manager.get_call_mut(&call_id).unwrap();
            call.session_expires = Some(Duration::from_secs(60));
            call.refresher = Some(Refresher::Uas);
            call.expiry_at = Some(now - Duration::from_secs(1));
        }

        manager.tick(now);
        let outbound = manager.drain_outbound_requests();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].kind, OutboundRequestKind::SessionTimerExpiryBye);
        assert_eq!(outbound[0].request.method(), Method::Bye);

        // State transitions to Terminating.
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Terminating);

        // Idempotent: second tick at the same instant must not re-fire.
        manager.tick(now);
        assert!(manager.drain_outbound_requests().is_empty());
    }

    #[test]
    fn tick_skips_non_established_calls() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = manager.create_call("sip:bob@example.com".to_string());
        // Set deadlines on a Ringing/Idle call — tick must not fire.
        let now = Instant::now();
        {
            let call = manager.get_call_mut(&call_id).unwrap();
            call.session_expires = Some(Duration::from_secs(60));
            call.refresher = Some(Refresher::Uac);
            call.refresh_at = Some(now - Duration::from_secs(1));
        }
        manager.tick(now);
        assert!(manager.drain_outbound_requests().is_empty());
    }

    #[test]
    fn next_deadline_returns_soonest() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let id1 = established_outbound_call(&mut manager);

        // Second established call.
        let id2 = manager.create_call("sip:carol@example.com".to_string());
        let dialog = Dialog::new_uac(
            "call-st-2".to_string(),
            "ftag2".to_string(),
            "ttag2".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:carol@example.com".to_string(),
            1,
        );
        manager.handle_invite_success(&id2, dialog, &test_sdp(), None, Instant::now());
        let _ = manager.drain_events();

        let now = Instant::now();
        manager.get_call_mut(&id1).unwrap().refresh_at = Some(now + Duration::from_secs(30));
        manager.get_call_mut(&id2).unwrap().expiry_at = Some(now + Duration::from_secs(10));

        let deadline = manager.next_deadline().expect("deadline");
        // The earlier (id2) wins.
        assert_eq!(deadline, now + Duration::from_secs(10));
    }

    #[test]
    fn next_deadline_none_when_no_timers() {
        let manager = CallManager::new(ManagerConfig::default());
        assert!(manager.next_deadline().is_none());
    }

    #[test]
    fn slide_deadlines_for_dialog_refreshes_expiry() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);

        let early = Instant::now();
        {
            let call = manager.get_call_mut(&call_id).unwrap();
            call.session_expires = Some(Duration::from_secs(60));
            call.refresher = Some(Refresher::Uas);
            call.expiry_at = Some(early + Duration::from_secs(60));
        }

        let dialog_id = manager
            .get_call(&call_id)
            .unwrap()
            .dialog_id()
            .cloned()
            .unwrap();

        let later = early + Duration::from_secs(30);
        manager.slide_deadlines_for_dialog(&dialog_id, later);

        let call = manager.get_call(&call_id).unwrap();
        // expiry_at should now be later + 60s, not the old early + 60s.
        assert_eq!(call.expiry_at, Some(later + Duration::from_secs(60)));
    }

    #[test]
    fn handle_inbound_update_returns_200_and_slides() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);

        let now = Instant::now();
        {
            let call = manager.get_call_mut(&call_id).unwrap();
            // Use 120s — above default min_se (90s) so the UPDATE is
            // accepted rather than rejected with 422 (Fix 4).
            call.session_expires = Some(Duration::from_secs(120));
            call.refresher = Some(Refresher::Uas);
            call.expiry_at = Some(now);
        }
        let dialog_id = manager
            .get_call(&call_id)
            .unwrap()
            .dialog_id()
            .cloned()
            .unwrap();

        // Build a UPDATE request like a peer would send.
        let update = SipRequest::builder()
            .method(Method::Update)
            .uri("sip:alice@host")
            .via("10.0.0.1", 5060, "UDP", "z9hG4bKupd")
            .from("sip:bob@host", "ftag")
            .to("sip:alice@host")
            .to_tag("ttag")
            .call_id("call-st-1")
            .cseq(2)
            .session_expires(120, Some(Refresher::Uac))
            .build()
            .expect("update");

        let later = now + Duration::from_secs(5);
        let response = manager
            .handle_inbound_update(&dialog_id, &update, later)
            .expect("200 OK built");
        assert_eq!(response.status_code(), 200);
        assert!(response.session_expires().is_some());

        let call = manager.get_call(&call_id).unwrap();
        // Deadline slid to later + 120s.
        assert_eq!(call.expiry_at, Some(later + Duration::from_secs(120)));
    }

    #[test]
    fn handle_provisional_reliable_emits_prack() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);

        // Simulated 180 with RSeq + matching CSeq.
        let response = SipResponse::builder()
            .status(180, "Ringing")
            .from_request(
                &SipRequest::builder()
                    .method(Method::Invite)
                    .uri("sip:bob@host")
                    .via("10.0.0.1", 5060, "UDP", "z9hG4bKabc")
                    .from("sip:alice@host", "ftag")
                    .to("sip:bob@host")
                    .call_id("call-st-1")
                    .cseq(1)
                    .build()
                    .unwrap(),
            )
            .require(&["100rel"])
            .rseq(1)
            .build()
            .expect("180");

        let prack = manager
            .handle_provisional_reliable(&call_id, &response)
            .expect("PRACK built");
        assert_eq!(prack.method(), Method::Prack);
        let rack = prack.rack().expect("RAck on PRACK");
        assert_eq!(rack.rseq, 1);
        assert_eq!(rack.cseq, 1);
        assert_eq!(rack.method, Method::Invite);

        // Also queued for app dispatch.
        let outbound = manager.drain_outbound_requests();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].kind, OutboundRequestKind::Prack);
    }

    #[test]
    fn note_update_unsupported_sets_flag() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);
        manager.note_update_unsupported(&call_id);
        assert!(manager.get_call(&call_id).unwrap().update_unsupported);
    }

    /// Reviewer's Fix C oracle: `mark_in_dialog_2xx` slides session-timer
    /// deadlines on UPDATE / INVITE 2xx, ignores other methods.
    #[test]
    fn mark_in_dialog_2xx_slides_only_for_update_and_invite() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);

        let now = Instant::now();
        {
            let call = manager.get_call_mut(&call_id).unwrap();
            call.session_expires = Some(Duration::from_secs(60));
            call.refresher = Some(Refresher::Uas);
            call.expiry_at = Some(now + Duration::from_secs(60));
        }

        // BYE — should NOT slide.
        let later = now + Duration::from_secs(30);
        manager.mark_in_dialog_2xx(&call_id, Method::Bye, later);
        assert_eq!(
            manager.get_call(&call_id).unwrap().expiry_at,
            Some(now + Duration::from_secs(60)),
            "BYE 2xx must not slide deadlines"
        );

        // UPDATE — slides.
        manager.mark_in_dialog_2xx(&call_id, Method::Update, later);
        assert_eq!(
            manager.get_call(&call_id).unwrap().expiry_at,
            Some(later + Duration::from_secs(60)),
            "UPDATE 2xx must slide expiry_at"
        );

        // INVITE — slides again.
        let even_later = later + Duration::from_secs(20);
        manager.mark_in_dialog_2xx(&call_id, Method::Invite, even_later);
        assert_eq!(
            manager.get_call(&call_id).unwrap().expiry_at,
            Some(even_later + Duration::from_secs(60)),
            "INVITE 2xx must slide expiry_at"
        );
    }

    /// Reviewer's Fix A oracle: when the manager builds an in-dialog
    /// UPDATE for a session-timer refresh, the wire format carries the
    /// dialog's Route headers, Contact, and uses the remote_target
    /// as request URI. This is what proves Phase 4 now goes through
    /// Phase 3's dialog API instead of inlining its own builder.
    ///
    /// Uses a *single* proxy so the reversal flag is invisible — the
    /// multi-proxy reversal contract is asserted separately by
    /// `route_set_two_proxies_emit_in_uac_reversed_order`.
    #[test]
    fn refresh_update_carries_route_and_contact_through_dialog_layer() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);

        // Inject route_set + remote_target + local_contact onto the
        // session-layer dialog as if a routed 200 OK had populated them.
        // UAC dialog → reverse=true matches production (manager.rs::handle_invite_success).
        {
            let call = manager.get_call_mut(&call_id).unwrap();
            let dialog = call.dialog_mut().unwrap();
            dialog.set_route_set_from_record_routes(
                &["<sip:proxy.example.com;lr>".to_string()],
                true,
            );
            dialog.set_remote_target("sip:bob@10.0.0.2:5060".to_string());
            dialog.set_local_contact("sip:alice@10.0.0.1:5060".to_string());
            call.session_expires = Some(Duration::from_secs(1800));
            call.refresher = Some(Refresher::Uac);
            call.refresh_at = Some(Instant::now());
        }

        manager.tick(Instant::now() + Duration::from_secs(1));
        let outbound = manager.drain_outbound_requests();
        assert_eq!(outbound.len(), 1, "tick must emit exactly one refresh");
        assert_eq!(outbound[0].kind, OutboundRequestKind::SessionTimerUpdate);

        // Round-trip the request through the wire.
        let bytes = outbound[0].request.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();

        // Route header from the dialog's route set.
        let routes = parsed_req.route_headers();
        assert_eq!(
            routes.len(),
            1,
            "refresh UPDATE must carry the Route header (RFC 3261 §12.2.1.1)"
        );
        assert!(routes[0].contains("proxy.example.com"));

        // Contact emitted from local_contact.
        let contact = parsed_req
            .contact_uri()
            .expect("refresh UPDATE must carry Contact");
        assert!(contact.to_string().contains("10.0.0.1"));

        // Request URI is the remote_target, not the remote_uri.
        assert!(
            parsed_req.uri().to_string().contains("10.0.0.2"),
            "request URI must be the dialog's remote target"
        );
    }

    /// Fix 5 oracle: a UAC dialog with two Record-Route proxies emits
    /// outbound in-dialog requests with `Route:` headers in *reversed*
    /// order per RFC 3261 §12.1.2. With Record-Route as
    /// `<proxy1>, <proxy2>` arriving on the response, the UAC
    /// reverses: subsequent in-dialog requests carry
    /// `Route: <proxy2>` first, then `Route: <proxy1>`.
    #[test]
    fn route_set_two_proxies_emit_in_uac_reversed_order() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);

        // Apply UAC reversal as production does on 200 OK.
        {
            let call = manager.get_call_mut(&call_id).unwrap();
            let dialog = call.dialog_mut().unwrap();
            dialog.set_route_set_from_record_routes(
                &[
                    "<sip:proxy1.example.com;lr>".to_string(),
                    "<sip:proxy2.example.com;lr>".to_string(),
                ],
                true, // UAC reversal — matches production at handle_invite_success.
            );
            dialog.set_remote_target("sip:bob@10.0.0.2:5060".to_string());
            dialog.set_local_contact("sip:alice@10.0.0.1:5060".to_string());
            call.session_expires = Some(Duration::from_secs(1800));
            call.refresher = Some(Refresher::Uac);
            call.refresh_at = Some(Instant::now());
        }

        // Drive a refresh UPDATE through tick.
        manager.tick(Instant::now() + Duration::from_secs(1));
        let outbound = manager.drain_outbound_requests();
        assert_eq!(outbound.len(), 1);

        let bytes = outbound[0].request.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();

        let routes = parsed_req.route_headers();
        assert_eq!(routes.len(), 2);
        // Reversed: proxy2 first, then proxy1.
        assert!(
            routes[0].contains("proxy2"),
            "first Route must be proxy2 (UAC reverses Record-Route per RFC 3261 §12.1.2); got {:?}",
            routes
        );
        assert!(
            routes[1].contains("proxy1"),
            "second Route must be proxy1 (UAC reverses Record-Route per RFC 3261 §12.1.2); got {:?}",
            routes
        );
    }

    /// Reviewer's Fix A oracle for the expiry-BYE path: BYE built by
    /// the manager when peer fails to refresh carries Route, Contact,
    /// and the Reason header. Routed through the dialog layer's
    /// `build_bye_with_reason`.
    #[test]
    fn expiry_bye_carries_route_and_reason_through_dialog_layer() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);

        {
            let call = manager.get_call_mut(&call_id).unwrap();
            let dialog = call.dialog_mut().unwrap();
            // UAC dialog → reverse=true matches production.
            dialog.set_route_set_from_record_routes(
                &["<sip:proxy.example.com;lr>".to_string()],
                true,
            );
            dialog.set_remote_target("sip:bob@10.0.0.2:5060".to_string());
            dialog.set_local_contact("sip:alice@10.0.0.1:5060".to_string());
            call.session_expires = Some(Duration::from_secs(60));
            call.refresher = Some(Refresher::Uas);
            call.expiry_at = Some(Instant::now());
        }

        manager.tick(Instant::now() + Duration::from_secs(1));
        let outbound = manager.drain_outbound_requests();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].kind, OutboundRequestKind::SessionTimerExpiryBye);

        let bytes = outbound[0].request.to_bytes();
        let raw = String::from_utf8(bytes.to_vec()).expect("utf8");
        assert!(
            raw.contains(r#"Reason: SIP;cause=200;text="Session timer expired""#),
            "expiry BYE must carry Reason header verbatim"
        );

        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();
        assert_eq!(parsed_req.method(), Method::Bye);
        assert_eq!(parsed_req.route_headers().len(), 1);
        assert!(parsed_req.contact_uri().is_some());
    }

    /// Fix 2 oracle for PRACK: an early-dialog 18x with To-tag is
    /// delivered through the manager's response handler
    /// (`handle_provisional_response`); that populates the UAC dialog's
    /// routing fields (`route_set`, `remote_target`, `local_contact`)
    /// from the response's `Record-Route` + `Contact`. The subsequent
    /// PRACK built by `handle_provisional_reliable` then carries those
    /// headers — so a routed PRACK actually traverses the same proxy
    /// chain as the INVITE, before any 200 OK has arrived.
    #[test]
    fn prack_carries_route_and_contact_through_dialog_layer() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);

        // Fabricate a 180 carrying Record-Route + Contact by parsing
        // raw text — the SipResponseBuilder doesn't have a generic
        // `header` setter for Record-Route, and we want this test to
        // mimic a proxy stamp rather than the manager's own emission.
        let raw_180 = b"SIP/2.0 180 Ringing\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKabc\r\n\
Record-Route: <sip:proxy.example.com;lr>\r\n\
From: <sip:alice@host>;tag=ftag\r\n\
To: <sip:bob@host>;tag=ttag\r\n\
Contact: <sip:bob@10.0.0.2:5060>\r\n\
Call-ID: call-st-1\r\n\
CSeq: 1 INVITE\r\n\
Require: 100rel\r\n\
RSeq: 1\r\n\
Content-Length: 0\r\n\
\r\n";
        let parsed = crate::sip::SipMessage::parse(raw_180).expect("parse 180");
        let response = parsed.as_response().expect("response").clone();

        // Drive the response through the manager's response handler so
        // the dialog routing fields populate from Record-Route +
        // Contact (Fix 2).
        manager.handle_provisional_response(&call_id, &response, None, "sip:alice@10.0.0.1:5060");

        // Sanity: the dialog routing fields are now populated. (No
        // need to inject anything manually.)
        {
            let call = manager.get_call(&call_id).unwrap();
            let dialog = call.dialog().unwrap();
            assert!(
                !dialog.route_set().is_empty(),
                "route_set must be populated from 18x"
            );
            assert!(
                dialog.remote_target().contains("10.0.0.2"),
                "remote_target must come from Contact in 18x"
            );
            assert!(
                dialog.local_contact().contains("10.0.0.1"),
                "local_contact must come from the supplied UAC contact"
            );
        }

        // Now build the PRACK and assert it carries Route + Contact.
        let prack = manager
            .handle_provisional_reliable(&call_id, &response)
            .expect("PRACK built");
        let bytes = prack.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_req = parsed.as_request().unwrap();

        let routes = parsed_req.route_headers();
        assert_eq!(
            routes.len(),
            1,
            "PRACK must carry the dialog's Route header"
        );
        assert!(routes[0].contains("proxy.example.com"));
        assert!(
            parsed_req.contact_uri().is_some(),
            "PRACK must carry Contact"
        );
    }

    /// Reviewer's Fix A oracle for inbound UPDATE 200 OK: routed
    /// through dialog layer's `handle_update`, so it carries Contact
    /// (RFC 3261 §12.2.1.1).
    #[test]
    fn handle_inbound_update_200_carries_contact() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);

        let dialog_id = {
            let call = manager.get_call_mut(&call_id).unwrap();
            let dialog = call.dialog_mut().unwrap();
            dialog.set_local_contact("sip:alice@10.0.0.1:5060".to_string());
            dialog.set_remote_target("sip:bob@10.0.0.2:5060".to_string());
            // 120s — above default min_se (90s) so we hit the 200 OK
            // path, not the 422 path (Fix 4).
            call.session_expires = Some(Duration::from_secs(120));
            call.refresher = Some(Refresher::Uas);
            call.expiry_at = Some(Instant::now());
            call.dialog_id().unwrap().clone()
        };

        let update = SipRequest::builder()
            .method(Method::Update)
            .uri("sip:alice@host")
            .via("10.0.0.2", 5060, "UDP", "z9hG4bKupd")
            .from("sip:bob@host", "ftag")
            .to("sip:alice@host")
            .to_tag("ttag")
            .call_id("call-st-1")
            .cseq(7)
            .session_expires(120, Some(Refresher::Uac))
            .build()
            .expect("update");

        let resp = manager
            .handle_inbound_update(&dialog_id, &update, Instant::now())
            .expect("200 OK built");
        let bytes = resp.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_resp = parsed.as_response().unwrap();

        assert_eq!(parsed_resp.status_code(), 200);
        let contact = parsed_resp
            .contact_uri()
            .expect("200 OK to UPDATE must carry Contact (RFC 3261 §12.2.1.1)");
        assert!(contact.to_string().contains("10.0.0.1"));
    }

    /// Fix 4 oracle: an inbound UPDATE whose `Session-Expires` is below
    /// our `Min-SE` must be rejected with `422 Session Interval Too Small`
    /// carrying our `Min-SE` (RFC 4028 §10.3). The call's session-timer
    /// state must NOT be mutated and the deadlines must NOT slide — the
    /// rejected UPDATE is as if it never happened.
    #[test]
    fn inbound_update_below_min_se_returns_422() {
        let mut manager = CallManager::new(ManagerConfig::default());
        let call_id = established_outbound_call(&mut manager);

        // Default min_se is 90s. Snapshot pre-state so we can assert
        // unchanged on rejection.
        let dialog_id;
        let pre_session_expires;
        let pre_expiry_at;
        let baseline = Instant::now();
        {
            let call = manager.get_call_mut(&call_id).unwrap();
            let dialog = call.dialog_mut().unwrap();
            dialog.set_local_contact("sip:alice@10.0.0.1:5060".to_string());
            dialog.set_remote_target("sip:bob@10.0.0.2:5060".to_string());
            call.session_expires = Some(Duration::from_secs(1800));
            call.refresher = Some(Refresher::Uac);
            call.expiry_at = Some(baseline + Duration::from_secs(1800));
            dialog_id = call.dialog_id().unwrap().clone();
            pre_session_expires = call.session_expires;
            pre_expiry_at = call.expiry_at;
        }

        // UPDATE with Session-Expires: 30 — below min_se default 90.
        let update = SipRequest::builder()
            .method(Method::Update)
            .uri("sip:alice@host")
            .via("10.0.0.2", 5060, "UDP", "z9hG4bKupd")
            .from("sip:bob@host", "ftag")
            .to("sip:alice@host")
            .to_tag("ttag")
            .call_id("call-st-1")
            .cseq(7)
            .session_expires(30, Some(Refresher::Uac))
            .build()
            .expect("update");

        let resp = manager
            .handle_inbound_update(&dialog_id, &update, baseline + Duration::from_secs(60))
            .expect("422 response built");
        assert_eq!(
            resp.status_code(),
            422,
            "RFC 4028 §10.3: SE < Min-SE must yield 422"
        );

        // 422 must carry our Min-SE.
        let bytes = resp.to_bytes();
        let parsed = crate::sip::SipMessage::parse(&bytes).unwrap();
        let parsed_resp = parsed.as_response().unwrap();
        let min_se = parsed_resp
            .min_se()
            .expect("422 must carry Min-SE per RFC 4028 §10.3");
        assert_eq!(min_se.0, 90);

        // Call state must NOT have changed.
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(
            call.session_expires, pre_session_expires,
            "rejected UPDATE must not mutate session_expires"
        );
        assert_eq!(
            call.expiry_at, pre_expiry_at,
            "rejected UPDATE must not slide expiry_at"
        );
    }

    /// Fix 1 oracle: a UAS-side dialog populated via
    /// `populate_uas_dialog_routing` from an inbound INVITE carries the
    /// INVITE's `Record-Route` (in same order — UAS does NOT reverse,
    /// per RFC 3261 §12.1.1) and `Contact` on subsequent UAS-driven
    /// in-dialog requests (here a BYE).
    #[test]
    fn uas_populated_dialog_emits_route_and_contact_on_bye() {
        let mut manager = CallManager::new(ManagerConfig::default());

        // Construct a UAS-side dialog via the manager's normal inbound path.
        let dialog = Dialog::new_uas(
            "call-uas-1".to_string(),
            "ftag".to_string(),
            "ttag".to_string(),
            "sip:alice@host".to_string(),
            "sip:bob@host".to_string(),
            1,
        );
        let offer_sdp = test_sdp();
        let (call_id, _, _) = manager
            .handle_incoming_invite(dialog, &offer_sdp)
            .expect("incoming");

        // Fabricate the inbound INVITE with Record-Route + Contact.
        // Two proxies — UAS keeps Record-Route order verbatim per
        // RFC 3261 §12.1.1.
        let raw_invite = b"INVITE sip:alice@host SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKxxx\r\n\
Record-Route: <sip:proxy1.example.com;lr>\r\n\
Record-Route: <sip:proxy2.example.com;lr>\r\n\
From: <sip:bob@host>;tag=ftag\r\n\
To: <sip:alice@host>\r\n\
Contact: <sip:bob@10.0.0.2:5060>\r\n\
Call-ID: call-uas-1\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let parsed = crate::sip::SipMessage::parse(raw_invite).expect("parse INVITE");
        let invite = parsed.as_request().expect("request").clone();

        // Apply the populate.
        manager.populate_uas_dialog_routing(
            &call_id,
            &invite,
            "sip:alice@10.0.0.1:5060".to_string(),
        );

        // Establish the call so the BYE can be built — answer it and
        // attach the dialog's confirmed state via the existing
        // `answer_call` choreography.
        manager.answer_call(&call_id);

        // Set up state required for terminate_call to emit a BYE
        // through the dialog layer. The session-layer Dialog already
        // carries the populated routing; we just need to drive
        // terminate.
        // Read back the dialog and assert routing populated.
        let call = manager.get_call(&call_id).unwrap();
        let dialog = call.dialog().expect("dialog");
        assert_eq!(
            dialog.route_set().len(),
            2,
            "UAS dialog must carry both Record-Route entries"
        );
        // UAS keeps Record-Route order verbatim (no reversal).
        assert!(
            dialog.route_set().routes()[0].contains("proxy1"),
            "UAS first route must be proxy1 (no reversal); got {:?}",
            dialog.route_set().routes()
        );
        assert!(
            dialog.route_set().routes()[1].contains("proxy2"),
            "UAS second route must be proxy2 (no reversal); got {:?}",
            dialog.route_set().routes()
        );
        assert!(
            dialog.remote_target().contains("10.0.0.2"),
            "remote_target must come from INVITE Contact"
        );
        assert!(
            dialog.local_contact().contains("10.0.0.1"),
            "local_contact must come from the supplied UAS local Contact"
        );
    }
}

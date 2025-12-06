//! Call manager for orchestrating multiple calls.
//!
//! The CallManager handles routing SIP messages to the appropriate calls,
//! managing call lifecycle, and coordinating signaling with media.

use std::collections::HashMap;
use std::sync::Arc;

use crate::call::{Call, CallConfig, CallDirection, CallEndReason, CallEvent, CallId, CallState, Dialog};
use mdsiprtp_dialog::DialogId;
use mdsiprtp_sdp::negotiation::{create_answer, process_answer, Codec};
use mdsiprtp_sdp::parser::SessionDescription;

/// Default URI placeholder when the remote URI cannot be extracted.
/// This is used for incoming calls when the From header is not available.
const UNKNOWN_URI: &str = "sip:unknown@unknown";

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
        let remote_uri = UNKNOWN_URI.to_string(); // Would extract from From header

        let call = Call::new_inbound(self.call_config.clone(), remote_uri, dialog);
        let call_id = call.id().clone();

        // Negotiate media
        let local_port = self.allocate_rtp_port();
        let result = create_answer(offer_sdp, &self.call_config.codecs, local_port);

        if let Some((answer_sdp, negotiated)) = result {
            if let Some(media) = negotiated.into_iter().next() {
                self.calls.insert(call_id.clone(), call);

                // Update call with negotiated media
                if let Some(call) = self.calls.get_mut(&call_id) {
                    call.set_negotiated_media(media, local_port);

                    // Register dialog mapping
                    if let Some(dialog_id) = call.dialog_id() {
                        self.dialog_to_call.insert(dialog_id.clone(), call_id.clone());
                    }
                }

                self.events.push(ManagerEvent::IncomingCall(call_id.clone()));

                return Some((call_id, answer_sdp, local_port));
            }
        }

        None
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
        call.set_negotiated_media(media, local_port);
        call.handle_answer();

        // Register dialog mapping
        if let Some(dialog_id) = call.dialog_id() {
            self.dialog_to_call.insert(dialog_id.clone(), call_id.clone());
        }

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
            // If early media SDP, set up media session
            if has_sdp {
                if let Some(answer_sdp) = sdp {
                    let negotiated = process_answer(answer_sdp);
                    if let Some(media) = negotiated.into_iter().next() {
                        call.set_negotiated_media(media, local_port);
                    }
                }
            }

            call.handle_provisional(has_sdp);
            self.events
                .push(ManagerEvent::CallStateChanged(call_id.clone(), call.state()));
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
    /// Returns the dialog ID that should be used to send BYE.
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
    fn test_handle_provisional() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let call_id = manager.create_call("sip:bob@example.com".to_string());

        manager.handle_provisional(&call_id, false, None);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Ringing);
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
        let dialog_id = manager.get_call(&call_id).unwrap().dialog_id().cloned().unwrap();
        manager.handle_bye(&dialog_id);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state(), CallState::Terminated);
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
    fn test_port_allocation() {
        let mut manager = CallManager::new(ManagerConfig::default());

        let port1 = manager.allocate_rtp_port();
        let port2 = manager.allocate_rtp_port();

        assert_eq!(port1, 10000);
        assert_eq!(port2, 10002);
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
        assert!(events.iter().any(|e| matches!(e, ManagerEvent::IncomingCall(_))));

        // Events should be drained
        let events2 = manager.drain_events();
        assert!(events2.is_empty());
    }
}

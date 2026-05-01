//! Call manager for orchestrating multiple calls.
//!
//! The CallManager handles routing SIP messages to the appropriate calls,
//! managing call lifecycle, and coordinating signaling with media.

use std::collections::HashMap;
use std::sync::Arc;

use crate::session::call::{
    Call, CallConfig, CallDirection, CallEndReason, CallEvent, CallId, CallState, Dialog,
};
use crate::dialog::DialogId;
use crate::sdp::negotiation::{create_answer, process_answer, Codec};
use crate::sdp::parser::SessionDescription;

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
        // Extract remote URI from the dialog (set when dialog was created from INVITE)
        let remote_uri = dialog.remote_uri().to_string();

        let call = Call::new_inbound(self.call_config.clone(), remote_uri, dialog);
        let call_id = call.id().clone();

        // Negotiate media
        let local_port = self.allocate_rtp_port();
        let result = create_answer(offer_sdp, &self.call_config.codecs, local_port);

        let (answer_sdp, negotiated) = result?;

        let media = negotiated.into_iter().next().expect("negotiated media");

        self.calls.insert(call_id.clone(), call);

        // Update call with negotiated media. If the negotiated codec is
        // unsupported by `MediaSession::for_negotiated`, surface the
        // error by rejecting the INVITE — the call has nothing to do
        // with no media session, and silently accepting would leave a
        // dialog with no media path.
        let call = self.calls.get_mut(&call_id).expect("call inserted");
        if let Err(e) = call.set_negotiated_media(media, local_port) {
            tracing::warn!(error = %e, "rejecting INVITE: media session construction failed");
            self.calls.remove(&call_id);
            return None;
        }

        // Register dialog mapping
        let dialog_id = call.dialog_id().expect("dialog id");
        self.dialog_to_call
            .insert(dialog_id.clone(), call_id.clone());

        self.events
            .push(ManagerEvent::IncomingCall(call_id.clone()));

        Some((call_id, answer_sdp, local_port))
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
}

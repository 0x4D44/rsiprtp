//! Dialog manager for tracking active dialogs.
//!
//! Routes messages to the appropriate dialog and handles dialog lifecycle.

#[cfg(test)]
use crate::invite::Role;
use crate::invite::{Action, Event, InviteDialog, TerminationReason};
use crate::state::{DialogId, DialogState};
use rsiprtp_sip::{Method, SipRequest, SipResponse};
use std::collections::HashMap;

/// Handle to a dialog in the manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DialogHandle(u64);

/// Output action from the dialog manager.
#[derive(Debug, Clone)]
pub enum ManagerAction {
    /// Send a request.
    SendRequest(SipRequest),
    /// Send a response.
    SendResponse(SipResponse),
    /// Dialog event.
    Event(DialogHandle, ManagerEvent),
}

/// Event from the dialog manager.
#[derive(Debug, Clone)]
pub enum ManagerEvent {
    /// New incoming INVITE - dialog created in early state.
    IncomingInvite(SipRequest),
    /// Dialog established.
    Established,
    /// Provisional response received.
    Provisional(SipResponse),
    /// Session progress with early media.
    SessionProgress(SipResponse),
    /// Re-INVITE received.
    ReInvite(SipRequest),
    /// BYE received.
    ByeReceived(SipRequest),
    /// Dialog terminated.
    Terminated(TerminationReason),
}

/// Dialog manager (Sans-IO).
#[derive(Debug)]
pub struct DialogManager {
    /// Next handle ID.
    next_handle: u64,
    /// Active dialogs.
    dialogs: HashMap<DialogHandle, InviteDialog>,
    /// Dialog ID to handle mapping.
    id_to_handle: HashMap<DialogId, DialogHandle>,
    /// Pending (early) dialogs by Call-ID + From-tag (for matching responses).
    pending_uac: HashMap<(String, String), DialogHandle>,
    /// Pending actions.
    actions: Vec<ManagerAction>,
    /// Local contact URI.
    local_contact: String,
}

impl DialogManager {
    /// Create a new dialog manager.
    pub fn new(local_contact: impl Into<String>) -> Self {
        Self {
            next_handle: 1,
            dialogs: HashMap::new(),
            id_to_handle: HashMap::new(),
            pending_uac: HashMap::new(),
            actions: Vec::new(),
            local_contact: local_contact.into(),
        }
    }

    /// Create a new outgoing dialog (UAC).
    ///
    /// Returns the handle and the INVITE request to send.
    pub fn create_dialog(&mut self, invite: SipRequest) -> Option<DialogHandle> {
        if invite.method() != Method::Invite {
            return None;
        }

        let handle = self.alloc_handle();
        let dialog = InviteDialog::new_uac(invite.clone());

        // Track pending dialog by Call-ID + From-tag
        let call_id = invite.call_id().ok()?;
        let from_tag = invite.from_tag().ok()?;
        self.pending_uac.insert((call_id, from_tag), handle);

        self.dialogs.insert(handle, dialog);
        Some(handle)
    }

    /// Handle an incoming request.
    pub fn handle_request(&mut self, request: SipRequest) -> Option<DialogHandle> {
        // Try to find an existing dialog
        if let Some(handle) = self.find_dialog_for_request(&request) {
            if let Some(dialog) = self.dialogs.get_mut(&handle) {
                dialog.handle_request(request);
                self.collect_dialog_actions(handle);
            }
            return Some(handle);
        }

        // New INVITE - create UAS dialog
        if request.method() == Method::Invite {
            return self.create_uas_dialog(request);
        }

        None
    }

    /// Handle an incoming response (for UAC dialogs).
    pub fn handle_response(&mut self, response: SipResponse) -> Option<DialogHandle> {
        // Find the pending dialog
        let call_id = response.call_id().ok()?;
        let from_tag = response.from_tag().ok()?;
        let to_tag = response.to_tag();

        // Look up by pending key first
        let handle = if let Some(&h) = self.pending_uac.get(&(call_id.clone(), from_tag.clone())) {
            h
        } else if let Some(to_tag) = &to_tag {
            // Try established dialog
            let id = DialogId::new(&call_id, &from_tag, to_tag);
            *self.id_to_handle.get(&id)?
        } else {
            return None;
        };

        if let Some(dialog) = self.dialogs.get_mut(&handle) {
            let old_state = dialog.state();
            dialog.handle_response(response);
            let new_state = dialog.state();

            // If dialog transitioned to confirmed, update mappings
            if old_state == DialogState::Early && new_state == DialogState::Confirmed {
                let id = dialog.id().clone();
                self.id_to_handle.insert(id, handle);
                self.pending_uac.remove(&(call_id, from_tag));
            }

            self.collect_dialog_actions(handle);
        }

        Some(handle)
    }

    /// Send a response for a dialog (UAS).
    pub fn send_response(&mut self, handle: DialogHandle, response: SipResponse) {
        if let Some(dialog) = self.dialogs.get_mut(&handle) {
            let old_state = dialog.state();
            dialog.send_response(response);
            let new_state = dialog.state();

            // If dialog transitioned to confirmed, update ID mapping
            if old_state == DialogState::Early && new_state == DialogState::Confirmed {
                let id = dialog.id().clone();
                self.id_to_handle.insert(id, handle);
            }

            self.collect_dialog_actions(handle);
        }
    }

    /// Send a BYE to terminate a dialog.
    pub fn send_bye(&mut self, handle: DialogHandle) -> Option<SipRequest> {
        let dialog = self.dialogs.get_mut(&handle)?;
        let bye = dialog.send_bye();
        self.collect_dialog_actions(handle);
        bye
    }

    /// Mark ACK as sent for a dialog.
    pub fn ack_sent(&mut self, handle: DialogHandle) {
        if let Some(dialog) = self.dialogs.get_mut(&handle) {
            dialog.ack_sent();
        }
    }

    /// Get dialog info.
    pub fn dialog(&self, handle: DialogHandle) -> Option<&InviteDialog> {
        self.dialogs.get(&handle)
    }

    /// Drain pending actions.
    pub fn poll_actions(&mut self) -> Vec<ManagerAction> {
        std::mem::take(&mut self.actions)
    }

    /// Remove terminated dialogs.
    pub fn cleanup_terminated(&mut self) {
        let mut to_remove = Vec::new();

        for (&handle, dialog) in &self.dialogs {
            if dialog.is_terminated() {
                to_remove.push((handle, dialog.id().clone()));
            }
        }

        for (handle, id) in to_remove {
            self.dialogs.remove(&handle);
            self.id_to_handle.remove(&id);
        }
    }

    fn alloc_handle(&mut self) -> DialogHandle {
        let handle = DialogHandle(self.next_handle);
        self.next_handle += 1;
        handle
    }

    fn create_uas_dialog(&mut self, request: SipRequest) -> Option<DialogHandle> {
        let local_tag = format!("{}", uuid::Uuid::new_v4().simple());
        let handle = self.alloc_handle();

        let dialog = InviteDialog::new_uas(request.clone(), &local_tag, &self.local_contact)?;
        let id = dialog.id().clone();

        self.dialogs.insert(handle, dialog);
        self.id_to_handle.insert(id, handle);

        // Emit incoming invite event
        self.actions.push(ManagerAction::Event(
            handle,
            ManagerEvent::IncomingInvite(request),
        ));

        Some(handle)
    }

    fn find_dialog_for_request(&self, request: &SipRequest) -> Option<DialogHandle> {
        let call_id = request.call_id().ok()?;
        let from_tag = request.from_tag().ok()?;
        let to_tag = request.to_tag()?;

        // For incoming requests to UAS, the dialog ID is swapped
        // (remote tag = from tag, local tag = to tag)
        let id = DialogId::new(&call_id, &to_tag, &from_tag);
        self.id_to_handle.get(&id).copied()
    }

    fn collect_dialog_actions(&mut self, handle: DialogHandle) {
        if let Some(dialog) = self.dialogs.get_mut(&handle) {
            for action in dialog.poll_actions() {
                let manager_action = match action {
                    Action::SendRequest(req) => ManagerAction::SendRequest(req),
                    Action::SendResponse(resp) => ManagerAction::SendResponse(resp),
                    Action::Event(event) => {
                        let manager_event = match event {
                            Event::Established => ManagerEvent::Established,
                            Event::Provisional(resp) => ManagerEvent::Provisional(resp),
                            Event::SessionProgress(resp) => ManagerEvent::SessionProgress(resp),
                            Event::ReInvite(req) => ManagerEvent::ReInvite(req),
                            Event::ByeReceived(req) => ManagerEvent::ByeReceived(req),
                            Event::Terminated(reason) => ManagerEvent::Terminated(reason),
                        };
                        ManagerAction::Event(handle, manager_event)
                    }
                };
                self.actions.push(manager_action);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsiprtp_sip::SipMessage;

    fn create_invite() -> SipRequest {
        SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .contact("sip:alice@192.168.1.1:5060")
            .build()
            .unwrap()
    }

    fn create_response(request: &SipRequest, code: u16) -> SipResponse {
        SipResponse::builder()
            .status(code, "Test")
            .from_request(request)
            .to_tag("totag")
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap()
    }

    fn parse_request(raw: &str) -> SipRequest {
        let msg = SipMessage::parse(raw.as_bytes()).unwrap();
        msg.as_request().unwrap().clone()
    }

    fn parse_response(raw: &str) -> SipResponse {
        let msg = SipMessage::parse(raw.as_bytes()).unwrap();
        msg.as_response().unwrap().clone()
    }

    #[test]
    fn test_create_uac_dialog() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = create_invite();

        let handle = mgr.create_dialog(invite).unwrap();
        assert!(handle.0 > 0);

        let dialog = mgr.dialog(handle).unwrap();
        assert_eq!(dialog.role(), Role::Uac);
    }

    #[test]
    fn test_create_dialog_missing_call_id() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        assert!(mgr.create_dialog(invite).is_none());
    }

    #[test]
    fn test_create_dialog_missing_from_tag() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        assert!(mgr.create_dialog(invite).is_none());
    }

    #[test]
    fn test_handle_request_missing_call_id_non_invite() {
        let req = parse_request(
            "BYE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
To: <sip:bob@example.com>;tag=totag\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
CSeq: 1 BYE\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let mut manager = DialogManager::new("sip:me@192.168.1.1:5060");
        let handle = manager.handle_request(req);
        assert!(handle.is_none());
    }

    #[test]
    fn test_handle_response_establishes_dialog() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = create_invite();

        let handle = mgr.create_dialog(invite.clone()).unwrap();
        let response = create_response(&invite, 200);

        let result_handle = mgr.handle_response(response).unwrap();
        assert_eq!(result_handle, handle);

        let dialog = mgr.dialog(handle).unwrap();
        assert_eq!(dialog.state(), DialogState::Confirmed);
    }

    #[test]
    fn test_handle_response_missing_call_id() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let response = parse_response(
            "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>;tag=totag\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@192.168.1.2:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        assert!(mgr.handle_response(response).is_none());
    }

    #[test]
    fn test_handle_response_missing_from_tag() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let response = parse_response(
            "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>\r\n\
To: <sip:bob@example.com>;tag=totag\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@192.168.1.2:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        assert!(mgr.handle_response(response).is_none());
    }

    #[test]
    fn test_handle_response_session_progress_event() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = create_invite();

        let handle = mgr.create_dialog(invite.clone()).unwrap();
        let response = create_response(&invite, 183);

        let result_handle = mgr.handle_response(response).unwrap();
        assert_eq!(result_handle, handle);

        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::SessionProgress(_)))));
    }

    #[test]
    fn test_incoming_invite_creates_dialog() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.2:5060");
        let invite = create_invite();

        let handle = mgr.handle_request(invite).unwrap();

        let dialog = mgr.dialog(handle).unwrap();
        assert_eq!(dialog.role(), Role::Uas);
        assert_eq!(dialog.state(), DialogState::Early);

        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::IncomingInvite(_)))));
    }

    #[test]
    fn test_incoming_invite_missing_from_tag() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.2:5060");
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let handle = mgr.handle_request(invite);
        assert!(handle.is_none());
    }

    #[test]
    fn test_handle_request_reinvite_event() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.2:5060");
        let invite = create_invite();

        let handle = mgr.handle_request(invite.clone()).unwrap();
        let dialog = mgr.dialog(handle).unwrap();
        let local_tag = dialog.id().local_tag.clone();
        let remote_tag = dialog.id().remote_tag.clone();
        let call_id = dialog.id().call_id.clone();

        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&invite)
            .to_tag(&local_tag)
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap();
        mgr.send_response(handle, response);
        mgr.poll_actions();

        let reinvite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKreinvite")
            .from("sip:alice@example.com", &remote_tag)
            .to("sip:bob@example.com")
            .to_tag(&local_tag)
            .call_id(&call_id)
            .cseq(2)
            .build()
            .unwrap();

        let result_handle = mgr.handle_request(reinvite).unwrap();
        assert_eq!(result_handle, handle);

        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::ReInvite(_)))));
    }

    #[test]
    fn test_send_200_establishes_dialog() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.2:5060");
        let invite = create_invite();

        let handle = mgr.handle_request(invite.clone()).unwrap();
        mgr.poll_actions();

        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&invite)
            .to_tag("localtag")
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap();

        mgr.send_response(handle, response);

        let dialog = mgr.dialog(handle).unwrap();
        assert_eq!(dialog.state(), DialogState::Confirmed);
    }

    #[test]
    fn test_send_response_provisional_does_not_confirm() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.2:5060");
        let invite = create_invite();

        let handle = mgr.handle_request(invite.clone()).unwrap();
        mgr.poll_actions();

        let response = SipResponse::builder()
            .status(180, "Ringing")
            .from_request(&invite)
            .to_tag("localtag")
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap();

        mgr.send_response(handle, response);

        let dialog = mgr.dialog(handle).unwrap();
        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_send_response_after_confirmed_does_not_remap() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.2:5060");
        let invite = create_invite();

        let handle = mgr.handle_request(invite.clone()).unwrap();
        mgr.poll_actions();

        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&invite)
            .to_tag("localtag")
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap();

        mgr.send_response(handle, response);
        mgr.poll_actions();

        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&invite)
            .to_tag("localtag")
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap();

        mgr.send_response(handle, response);
        let dialog = mgr.dialog(handle).unwrap();
        assert_eq!(dialog.state(), DialogState::Confirmed);
    }

    // Additional tests for better coverage

    #[test]
    fn test_dialog_handle_debug() {
        let handle = DialogHandle(1);
        let debug = format!("{:?}", handle);
        assert!(debug.contains("DialogHandle"));
    }

    #[test]
    #[allow(clippy::clone_on_copy)] // exercise derived Clone for coverage
    fn test_dialog_handle_clone() {
        let handle = DialogHandle(1);
        let cloned = handle.clone();
        assert_eq!(handle, cloned);
    }

    #[test]
    fn test_dialog_handle_copy() {
        let handle = DialogHandle(1);
        let copied: DialogHandle = handle;
        assert_eq!(handle, copied);
    }

    #[test]
    fn test_dialog_handle_eq() {
        assert_eq!(DialogHandle(1), DialogHandle(1));
        assert_ne!(DialogHandle(1), DialogHandle(2));
    }

    #[test]
    fn test_dialog_handle_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DialogHandle(1));
        set.insert(DialogHandle(2));
        assert_eq!(set.len(), 2);
        assert!(set.contains(&DialogHandle(1)));
    }

    #[test]
    fn test_manager_action_debug() {
        let action = ManagerAction::Event(DialogHandle(1), ManagerEvent::Established);
        let debug = format!("{:?}", action);
        assert!(debug.contains("Event"));
    }

    #[test]
    fn test_manager_action_clone() {
        let action = ManagerAction::Event(DialogHandle(1), ManagerEvent::Established);
        let cloned = action.clone();
        let debug = format!("{:?}", cloned);
        assert!(debug.contains("Established"));
    }

    #[test]
    fn test_manager_event_debug() {
        assert!(format!("{:?}", ManagerEvent::Established).contains("Established"));
        assert!(
            format!("{:?}", ManagerEvent::Terminated(TerminationReason::ByeSent))
                .contains("Terminated")
        );
    }

    #[test]
    fn test_manager_event_clone() {
        let event = ManagerEvent::Established;
        let cloned = event.clone();
        let debug = format!("{:?}", cloned);
        assert!(debug.contains("Established"));
    }

    #[test]
    fn test_dialog_manager_debug() {
        let mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let debug = format!("{:?}", mgr);
        assert!(debug.contains("DialogManager"));
    }

    #[test]
    fn test_create_dialog_non_invite_returns_none() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let register = SipRequest::builder()
            .method(Method::Register)
            .uri("sip:registrar@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:alice@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let result = mgr.create_dialog(register);
        assert!(result.is_none());
    }

    #[test]
    fn test_handle_request_bye_on_existing_dialog() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.2:5060");
        let invite = create_invite();

        // Create and establish dialog
        let handle = mgr.handle_request(invite.clone()).unwrap();
        mgr.poll_actions();

        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&invite)
            .to_tag("localtag")
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap();
        mgr.send_response(handle, response);
        mgr.poll_actions();

        // Now send BYE from the other side
        let dialog = mgr.dialog(handle).unwrap();
        let local_tag = dialog.id().local_tag.clone();

        let bye = SipRequest::builder()
            .method(Method::Bye)
            .uri("sip:bob@192.168.1.2:5060")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKbye")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag(&local_tag)
            .call_id("test@example.com")
            .cseq(2)
            .build()
            .unwrap();

        let result = mgr.handle_request(bye);
        assert!(result.is_some());

        let dialog = mgr.dialog(handle).unwrap();
        assert_eq!(dialog.state(), DialogState::Terminated);
    }

    #[test]
    fn test_handle_request_for_unknown_dialog() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.2:5060");

        // BYE for non-existent dialog
        let bye = SipRequest::builder()
            .method(Method::Bye)
            .uri("sip:bob@192.168.1.2:5060")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKbye")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("unknowntag")
            .call_id("unknown@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let result = mgr.handle_request(bye);
        assert!(result.is_none());
    }

    #[test]
    fn test_handle_request_missing_dialog_entry() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.2:5060");
        let handle = DialogHandle(42);
        let id = DialogId::new("test@example.com", "totag", "fromtag");
        mgr.id_to_handle.insert(id, handle);

        let bye = SipRequest::builder()
            .method(Method::Bye)
            .uri("sip:bob@192.168.1.2:5060")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKbye")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("totag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let result = mgr.handle_request(bye);
        assert_eq!(result, Some(handle));
        assert!(mgr.dialog(handle).is_none());
    }

    #[test]
    fn test_handle_response_without_pending_or_to_tag() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = create_invite();

        // Response has no to-tag and there's no pending dialog.
        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&invite)
            .build()
            .unwrap();

        let result = mgr.handle_response(response);
        assert!(result.is_none());
    }

    #[test]
    fn test_handle_response_missing_dialog_entry() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = create_invite();

        let handle = mgr.create_dialog(invite.clone()).unwrap();
        let response = create_response(&invite, 200);

        mgr.dialogs.remove(&handle);

        let result = mgr.handle_response(response);
        assert_eq!(result, Some(handle));
        assert!(mgr.dialog(handle).is_none());
    }

    #[test]
    fn test_handle_response_uses_established_mapping() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = create_invite();

        let handle = mgr.create_dialog(invite.clone()).unwrap();
        let response = create_response(&invite, 200);
        mgr.handle_response(response);

        // New response should use established dialog mapping (pending removed).
        let followup = create_response(&invite, 200);
        let result = mgr.handle_response(followup).unwrap();
        assert_eq!(result, handle);
    }

    #[test]
    fn test_send_bye_unknown_handle_returns_none() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let bye = mgr.send_bye(DialogHandle(999));
        assert!(bye.is_none());
    }

    #[test]
    fn test_handle_response_provisional() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = create_invite();

        let handle = mgr.create_dialog(invite.clone()).unwrap();

        let response = create_response(&invite, 180);
        let result_handle = mgr.handle_response(response).unwrap();
        assert_eq!(result_handle, handle);

        let dialog = mgr.dialog(handle).unwrap();
        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_handle_response_rejection() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = create_invite();

        let handle = mgr.create_dialog(invite.clone()).unwrap();

        let response = create_response(&invite, 486);
        let result_handle = mgr.handle_response(response).unwrap();
        assert_eq!(result_handle, handle);

        let dialog = mgr.dialog(handle).unwrap();
        assert_eq!(dialog.state(), DialogState::Terminated);
    }

    #[test]
    fn test_handle_response_unknown_dialog() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = create_invite();

        // Response for non-existent dialog
        let response = create_response(&invite, 200);
        let result = mgr.handle_response(response);
        assert!(result.is_none());
    }

    #[test]
    fn test_send_bye() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = create_invite();

        // Create and establish dialog
        let handle = mgr.create_dialog(invite.clone()).unwrap();
        let response = create_response(&invite, 200);
        mgr.handle_response(response);
        mgr.poll_actions();

        // Send BYE
        let bye = mgr.send_bye(handle);
        assert!(bye.is_some());

        let dialog = mgr.dialog(handle).unwrap();
        assert_eq!(dialog.state(), DialogState::Terminating);
    }

    #[test]
    fn test_send_bye_non_existent_dialog() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");

        let bye = mgr.send_bye(DialogHandle(999));
        assert!(bye.is_none());
    }

    #[test]
    fn test_ack_sent() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = create_invite();

        let handle = mgr.create_dialog(invite.clone()).unwrap();
        let response = create_response(&invite, 200);
        mgr.handle_response(response);

        mgr.ack_sent(handle);

        let dialog = mgr.dialog(handle).unwrap();
        assert!(dialog.is_ack_complete());
    }

    #[test]
    fn test_ack_sent_non_existent_dialog() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        // Should not panic
        mgr.ack_sent(DialogHandle(999));
    }

    #[test]
    fn test_collect_dialog_actions_missing_handle() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        mgr.collect_dialog_actions(DialogHandle(999));
        assert!(mgr.poll_actions().is_empty());
    }

    #[test]
    fn test_cleanup_terminated() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = create_invite();

        // Create and reject dialog
        let handle = mgr.create_dialog(invite.clone()).unwrap();
        let response = create_response(&invite, 486);
        mgr.handle_response(response);
        mgr.poll_actions();

        // Dialog should be terminated
        let dialog = mgr.dialog(handle).unwrap();
        assert_eq!(dialog.state(), DialogState::Terminated);

        // Cleanup
        mgr.cleanup_terminated();

        // Dialog should be removed
        assert!(mgr.dialog(handle).is_none());
    }

    #[test]
    fn test_cleanup_terminated_noop_for_active() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");
        let invite = create_invite();

        let handle = mgr.create_dialog(invite).unwrap();
        mgr.cleanup_terminated();

        assert!(mgr.dialog(handle).is_some());
    }

    #[test]
    fn test_poll_actions_clears() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.2:5060");
        let invite = create_invite();

        mgr.handle_request(invite);

        let actions = mgr.poll_actions();
        assert!(!actions.is_empty());

        let actions2 = mgr.poll_actions();
        assert!(actions2.is_empty());
    }

    #[test]
    fn test_send_response_with_invalid_handle() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.2:5060");
        let invite = create_invite();

        let response = create_response(&invite, 200);

        // Should not panic
        mgr.send_response(DialogHandle(999), response);
    }

    #[test]
    fn test_multiple_dialogs() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.1:5060");

        // Create first dialog
        let invite1 = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest1")
            .from("sip:alice@example.com", "fromtag1")
            .to("sip:bob@example.com")
            .call_id("call1@example.com")
            .cseq(1)
            .contact("sip:alice@192.168.1.1:5060")
            .build()
            .unwrap();
        let handle1 = mgr.create_dialog(invite1).unwrap();

        // Create second dialog
        let invite2 = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:carol@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest2")
            .from("sip:alice@example.com", "fromtag2")
            .to("sip:carol@example.com")
            .call_id("call2@example.com")
            .cseq(1)
            .contact("sip:alice@192.168.1.1:5060")
            .build()
            .unwrap();
        let handle2 = mgr.create_dialog(invite2).unwrap();

        assert_ne!(handle1, handle2);
        assert!(mgr.dialog(handle1).is_some());
        assert!(mgr.dialog(handle2).is_some());
    }

    #[test]
    fn test_manager_event_variants() {
        let invite = create_invite();
        let response = create_response(&invite, 180);

        let event1 = ManagerEvent::IncomingInvite(invite.clone());
        assert!(format!("{:?}", event1).contains("IncomingInvite"));

        let event2 = ManagerEvent::Provisional(response.clone());
        assert!(format!("{:?}", event2).contains("Provisional"));

        let event3 = ManagerEvent::SessionProgress(response.clone());
        assert!(format!("{:?}", event3).contains("SessionProgress"));

        let event4 = ManagerEvent::ReInvite(invite.clone());
        assert!(format!("{:?}", event4).contains("ReInvite"));

        let event5 = ManagerEvent::ByeReceived(invite);
        assert!(format!("{:?}", event5).contains("ByeReceived"));
    }

    #[test]
    fn test_manager_action_variants() {
        let invite = create_invite();
        let response = create_response(&invite, 200);

        let action1 = ManagerAction::SendRequest(invite);
        assert!(format!("{:?}", action1).contains("SendRequest"));

        let action2 = ManagerAction::SendResponse(response);
        assert!(format!("{:?}", action2).contains("SendResponse"));
    }
}

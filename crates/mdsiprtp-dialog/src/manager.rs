//! Dialog manager for tracking active dialogs.
//!
//! Routes messages to the appropriate dialog and handles dialog lifecycle.

use std::collections::HashMap;
use mdsiprtp_sip::{SipRequest, SipResponse, Method};
use crate::state::{DialogId, DialogState};
use crate::invite::{InviteDialog, Action, Event, TerminationReason};
#[cfg(test)]
use crate::invite::Role;

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
    fn test_incoming_invite_creates_dialog() {
        let mut mgr = DialogManager::new("sip:me@192.168.1.2:5060");
        let invite = create_invite();

        let handle = mgr.handle_request(invite).unwrap();

        let dialog = mgr.dialog(handle).unwrap();
        assert_eq!(dialog.role(), Role::Uas);
        assert_eq!(dialog.state(), DialogState::Early);

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::IncomingInvite(_)))));
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
}

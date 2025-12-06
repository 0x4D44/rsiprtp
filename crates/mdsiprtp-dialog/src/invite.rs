//! INVITE dialog state machine.
//!
//! Handles the lifecycle of an INVITE-initiated dialog, including:
//! - Dialog establishment via INVITE/2xx/ACK
//! - In-dialog requests (re-INVITE, BYE, etc.)
//! - Dialog termination

use mdsiprtp_sip::{SipRequest, SipResponse, Method};
use crate::state::{DialogId, DialogState, DialogInfo};

/// Role in the dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// User Agent Client - initiated the dialog.
    Uac,
    /// User Agent Server - received the initial INVITE.
    Uas,
}

/// Output action from the dialog.
#[derive(Debug, Clone)]
pub enum Action {
    /// Send a request to the network.
    SendRequest(SipRequest),
    /// Send a response to the network.
    SendResponse(SipResponse),
    /// Emit an event to the user.
    Event(Event),
}

/// Event emitted to the user.
#[derive(Debug, Clone)]
pub enum Event {
    /// Dialog established (2xx received/sent).
    Established,
    /// Provisional response received/sent.
    Provisional(SipResponse),
    /// Re-INVITE received.
    ReInvite(SipRequest),
    /// BYE received.
    ByeReceived(SipRequest),
    /// Dialog terminated.
    Terminated(TerminationReason),
    /// Session progress (183 with SDP).
    SessionProgress(SipResponse),
}

/// Reason for dialog termination.
#[derive(Debug, Clone)]
pub enum TerminationReason {
    /// Normal BYE.
    ByeSent,
    /// Remote BYE.
    ByeReceived,
    /// INVITE rejected.
    Rejected(u16),
    /// INVITE cancelled.
    Cancelled,
    /// Error.
    Error(String),
}

/// INVITE dialog (Sans-IO).
#[derive(Debug)]
pub struct InviteDialog {
    /// Dialog info.
    info: DialogInfo,
    /// Our role.
    role: Role,
    /// Original INVITE request (for reference).
    invite: SipRequest,
    /// Pending actions.
    actions: Vec<Action>,
    /// Whether ACK has been sent/received.
    ack_sent: bool,
}

impl InviteDialog {
    /// Create a new UAC dialog from an outgoing INVITE.
    ///
    /// The dialog is not yet established - call `handle_response` with responses.
    pub fn new_uac(invite: SipRequest) -> Self {
        // Create a placeholder dialog info - will be filled in when response arrives
        let info = DialogInfo {
            id: DialogId::new("", "", ""),
            state: DialogState::Early,
            local_seq: invite.cseq().unwrap_or(1),
            remote_seq: None,
            local_uri: invite.from_uri().ok().map(|u| u.to_string()).unwrap_or_default(),
            remote_uri: invite.to_uri().ok().map(|u| u.to_string()).unwrap_or_default(),
            remote_target: String::new(),
            route_set: Default::default(),
            secure: false,
        };

        Self {
            info,
            role: Role::Uac,
            invite,
            actions: Vec::new(),
            ack_sent: false,
        }
    }

    /// Create a new UAS dialog from an incoming INVITE.
    ///
    /// Call `send_response` to send responses.
    pub fn new_uas(invite: SipRequest, local_tag: &str, local_contact: &str) -> Option<Self> {
        let info = DialogInfo::from_invite_uas(&invite, local_tag, local_contact, DialogState::Early)?;

        Some(Self {
            info,
            role: Role::Uas,
            invite,
            actions: Vec::new(),
            ack_sent: false,
        })
    }

    /// Get the dialog ID.
    pub fn id(&self) -> &DialogId {
        &self.info.id
    }

    /// Get the dialog state.
    pub fn state(&self) -> DialogState {
        self.info.state
    }

    /// Get the dialog info.
    pub fn info(&self) -> &DialogInfo {
        &self.info
    }

    /// Get our role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Check if dialog is terminated.
    pub fn is_terminated(&self) -> bool {
        self.info.state == DialogState::Terminated
    }

    /// Handle a response (UAC only).
    pub fn handle_response(&mut self, response: SipResponse) {
        if self.role != Role::Uac {
            return;
        }

        let code = response.status_code();

        match self.info.state {
            DialogState::Early => {
                if (100..200).contains(&code) {
                    // Provisional response
                    if code != 100 {
                        // Create early dialog if we have a To tag
                        if let Some(new_info) = DialogInfo::from_invite_response_uac(
                            &self.invite,
                            &response,
                            DialogState::Early,
                        ) {
                            self.info = new_info;
                        }

                        if code == 183 {
                            // Session progress - may have SDP for early media
                            self.actions.push(Action::Event(Event::SessionProgress(response.clone())));
                        }
                        self.actions.push(Action::Event(Event::Provisional(response)));
                    }
                } else if (200..300).contains(&code) {
                    // Success - dialog established
                    if let Some(new_info) = DialogInfo::from_invite_response_uac(
                        &self.invite,
                        &response,
                        DialogState::Confirmed,
                    ) {
                        self.info = new_info;
                    } else {
                        self.info.state = DialogState::Confirmed;
                    }
                    self.actions.push(Action::Event(Event::Established));
                    // UAC must send ACK - but that's handled at transaction/session level
                } else if code >= 300 {
                    // Failure - dialog terminates
                    self.info.state = DialogState::Terminated;
                    self.actions.push(Action::Event(Event::Terminated(TerminationReason::Rejected(code))));
                }
            }
            DialogState::Confirmed => {
                // Responses to in-dialog requests (re-INVITE, etc.)
                // Handle at higher level
            }
            _ => {}
        }
    }

    /// Handle an incoming request (both UAC and UAS).
    pub fn handle_request(&mut self, request: SipRequest) {
        // Verify the request is for this dialog
        let cseq = match request.cseq() {
            Ok(seq) => seq,
            Err(_) => return,
        };

        match request.method() {
            Method::Bye => {
                self.info.state = DialogState::Terminated;
                self.actions.push(Action::Event(Event::ByeReceived(request.clone())));
                self.actions.push(Action::Event(Event::Terminated(TerminationReason::ByeReceived)));
            }
            Method::Invite => {
                // Re-INVITE
                if self.info.state == DialogState::Confirmed && self.info.update_remote_seq(cseq) {
                    self.actions.push(Action::Event(Event::ReInvite(request)));
                }
                // else: reject with 500 (CSeq out of order)
            }
            Method::Ack => {
                // ACK for 2xx (UAS side)
                if self.role == Role::Uas && self.info.state == DialogState::Confirmed {
                    self.ack_sent = true;
                }
            }
            Method::Cancel => {
                // CANCEL only applies to early dialogs
                if self.info.state == DialogState::Early && self.role == Role::Uas {
                    self.info.state = DialogState::Terminated;
                    self.actions.push(Action::Event(Event::Terminated(TerminationReason::Cancelled)));
                }
            }
            _ => {
                // Other in-dialog requests (INFO, UPDATE, etc.)
                // Handle at higher level
            }
        }
    }

    /// Send a response (UAS only).
    pub fn send_response(&mut self, response: SipResponse) {
        if self.role != Role::Uas {
            return;
        }

        let code = response.status_code();

        if (200..300).contains(&code) && self.info.state == DialogState::Early {
            // Dialog confirmed
            self.info.state = DialogState::Confirmed;
            self.actions.push(Action::SendResponse(response));
            self.actions.push(Action::Event(Event::Established));
        } else if code >= 300 && self.info.state == DialogState::Early {
            // Dialog rejected
            self.info.state = DialogState::Terminated;
            self.actions.push(Action::SendResponse(response));
            self.actions.push(Action::Event(Event::Terminated(TerminationReason::Rejected(code))));
        } else {
            self.actions.push(Action::SendResponse(response));
        }
    }

    /// Send a BYE to terminate the dialog.
    pub fn send_bye(&mut self) -> Option<SipRequest> {
        if self.info.state != DialogState::Confirmed {
            return None;
        }

        self.info.state = DialogState::Terminating;

        // Build BYE request
        let cseq = self.info.next_local_seq();
        let bye = self.build_in_dialog_request(Method::Bye, cseq)?;

        self.actions.push(Action::SendRequest(bye.clone()));
        Some(bye)
    }

    /// Build an in-dialog request.
    fn build_in_dialog_request(&self, method: Method, cseq: u32) -> Option<SipRequest> {
        let branch = format!("z9hG4bK{}", uuid::Uuid::new_v4().simple());

        // Determine request URI based on route set
        let request_uri = if self.info.route_set.is_empty() {
            self.info.remote_target.clone()
        } else {
            // If route set has lr parameter, use remote target
            // Otherwise, use first route
            // For simplicity, assume lr parameter is present
            self.info.remote_target.clone()
        };

        // Build request - swap From/To based on role
        let (from_uri, from_tag, to_uri, to_tag) = match self.role {
            Role::Uac => (
                &self.info.local_uri,
                &self.info.id.local_tag,
                &self.info.remote_uri,
                &self.info.id.remote_tag,
            ),
            Role::Uas => (
                &self.info.local_uri,
                &self.info.id.local_tag,
                &self.info.remote_uri,
                &self.info.id.remote_tag,
            ),
        };

        let request = SipRequest::builder()
            .method(method)
            .uri(&request_uri)
            .via("0.0.0.0", 5060, "UDP", &branch) // Will be filled in by transport
            .from(from_uri, from_tag)
            .to(to_uri)
            .to_tag(to_tag)
            .call_id(&self.info.id.call_id)
            .cseq(cseq)
            .build()
            .ok()?;

        Some(request)
    }

    /// Drain pending actions.
    pub fn poll_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.actions)
    }

    /// Mark ACK as sent (UAC side).
    pub fn ack_sent(&mut self) {
        self.ack_sent = true;
    }

    /// Check if ACK has been sent/received.
    pub fn is_ack_complete(&self) -> bool {
        self.ack_sent
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
    fn test_uac_dialog_creation() {
        let invite = create_invite();
        let dialog = InviteDialog::new_uac(invite);

        assert_eq!(dialog.role(), Role::Uac);
        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_uac_dialog_established_on_200() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 200);
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Confirmed);
        let actions = dialog.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::Event(Event::Established))));
    }

    #[test]
    fn test_uac_dialog_rejected() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 486);
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Terminated);
    }

    #[test]
    fn test_uas_dialog_creation() {
        let invite = create_invite();
        let dialog = InviteDialog::new_uas(invite, "mytag", "sip:me@192.168.1.2:5060").unwrap();

        assert_eq!(dialog.role(), Role::Uas);
        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_uas_dialog_established_on_200() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&invite)
            .to_tag("mytag")
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap();

        dialog.send_response(response);

        assert_eq!(dialog.state(), DialogState::Confirmed);
    }

    #[test]
    fn test_bye_terminates_dialog() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        let bye = SipRequest::builder()
            .method(Method::Bye)
            .uri("sip:alice@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKbye")
            .from("sip:bob@example.com", "totag")
            .to("sip:alice@example.com")
            .to_tag("fromtag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(bye);
        assert_eq!(dialog.state(), DialogState::Terminated);
    }
}

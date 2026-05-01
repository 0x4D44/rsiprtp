//! INVITE dialog state machine.
//!
//! Handles the lifecycle of an INVITE-initiated dialog, including:
//! - Dialog establishment via INVITE/2xx/ACK
//! - In-dialog requests (re-INVITE, BYE, etc.)
//! - Dialog termination

use crate::dialog::state::{DialogId, DialogInfo, DialogState};
use crate::sip::{Method, SipRequest, SipResponse};

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
            local_uri: invite
                .from_uri()
                .ok()
                .map(|u| u.to_string())
                .unwrap_or_default(),
            remote_uri: invite
                .to_uri()
                .ok()
                .map(|u| u.to_string())
                .unwrap_or_default(),
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
        let info =
            DialogInfo::from_invite_uas(&invite, local_tag, local_contact, DialogState::Early)?;

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
                            self.actions
                                .push(Action::Event(Event::SessionProgress(response.clone())));
                        }
                        self.actions
                            .push(Action::Event(Event::Provisional(response)));
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
                    self.actions.push(Action::Event(Event::Terminated(
                        TerminationReason::Rejected(code),
                    )));
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
                self.actions
                    .push(Action::Event(Event::ByeReceived(request.clone())));
                self.actions.push(Action::Event(Event::Terminated(
                    TerminationReason::ByeReceived,
                )));
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
                    self.actions.push(Action::Event(Event::Terminated(
                        TerminationReason::Cancelled,
                    )));
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
            self.actions.push(Action::Event(Event::Terminated(
                TerminationReason::Rejected(code),
            )));
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
    use crate::sip::SipMessage;

    fn parse_request(raw: &str) -> SipRequest {
        let msg = SipMessage::parse(raw.as_bytes()).unwrap();
        msg.as_request().unwrap().clone()
    }

    fn is_rejected_termination(action: &Action) -> bool {
        matches!(
            action,
            Action::Event(Event::Terminated(TerminationReason::Rejected(_)))
        )
    }

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
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Established))));
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
    fn test_uas_dialog_creation_invalid_invite() {
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
        let dialog = InviteDialog::new_uas(invite, "mytag", "sip:me@192.168.1.2:5060");
        assert!(dialog.is_none());
    }

    #[test]
    fn test_uas_dialog_established_on_200() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

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

    #[test]
    fn test_uac_dialog_provisional_180() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 180);
        dialog.handle_response(response);

        let actions = dialog.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Provisional(_)))));
        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_uac_dialog_provisional_missing_to_tag() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = SipResponse::builder()
            .status(180, "Ringing")
            .from_request(&invite)
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap();

        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Early);
        assert!(dialog.info().id.remote_tag.is_empty());
    }

    #[test]
    fn test_uac_dialog_session_progress_183() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 183);
        dialog.handle_response(response);

        let actions = dialog.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::SessionProgress(_)))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Provisional(_)))));
    }

    #[test]
    fn test_uac_dialog_response_below_100() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 99);
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Early);
        assert!(dialog.poll_actions().is_empty());
    }

    #[test]
    fn test_uac_dialog_ignores_100() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 100);
        dialog.handle_response(response);
        assert!(dialog.poll_actions().is_empty());
    }

    #[test]
    fn test_uac_dialog_200_missing_contact() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&invite)
            .to_tag("totag")
            .build()
            .unwrap();

        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Confirmed);
        assert!(dialog.info().remote_target.is_empty());
    }

    #[test]
    fn test_uas_dialog_handle_response_noop() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        assert!(dialog.poll_actions().is_empty());
    }

    #[test]
    fn test_reinvite_ignored_on_stale_cseq() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();
        dialog.info.remote_seq = Some(2);

        let reinvite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:alice@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKreinvite")
            .from("sip:bob@example.com", "totag")
            .to("sip:alice@example.com")
            .to_tag("fromtag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(reinvite);
        assert!(dialog.poll_actions().is_empty());
    }

    #[test]
    fn test_reinvite_triggers_event() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        let reinvite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:alice@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKreinvite")
            .from("sip:bob@example.com", "totag")
            .to("sip:alice@example.com")
            .to_tag("fromtag")
            .call_id("test@example.com")
            .cseq(2)
            .build()
            .unwrap();

        dialog.handle_request(reinvite);
        let actions = dialog.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::ReInvite(_)))));
    }

    #[test]
    fn test_reinvite_ignored_before_confirmed() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let reinvite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:alice@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKreinvite")
            .from("sip:bob@example.com", "totag")
            .to("sip:alice@example.com")
            .to_tag("fromtag")
            .call_id("test@example.com")
            .cseq(2)
            .build()
            .unwrap();

        dialog.handle_request(reinvite);
        assert!(dialog.poll_actions().is_empty());
    }

    #[test]
    fn test_ack_ignored_for_uac() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        let ack = SipRequest::builder()
            .method(Method::Ack)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKack")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("totag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(ack);
        assert!(!dialog.ack_sent);
    }

    #[test]
    fn test_ack_ignored_before_confirmed_uas() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let ack = SipRequest::builder()
            .method(Method::Ack)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKack")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("mytag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(ack);
        assert!(!dialog.ack_sent);
    }

    #[test]
    fn test_cancel_ignored_for_uac() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let cancel = SipRequest::builder()
            .method(Method::Cancel)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKcancel")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("totag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(cancel);
        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_cancel_ignored_after_confirmed_uas() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 200);
        dialog.send_response(response);
        dialog.poll_actions();
        assert_eq!(dialog.state(), DialogState::Confirmed);

        let cancel = SipRequest::builder()
            .method(Method::Cancel)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKcancel")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("mytag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(cancel);
        assert_eq!(dialog.state(), DialogState::Confirmed);
    }

    #[test]
    fn test_ack_sets_ack_sent_for_uas() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 200);
        dialog.send_response(response);
        dialog.poll_actions();

        let ack = SipRequest::builder()
            .method(Method::Ack)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKack")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("mytag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(ack);
        assert!(dialog.ack_sent);
    }

    #[test]
    fn test_cancel_terminates_early_uas() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let cancel = SipRequest::builder()
            .method(Method::Cancel)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKcancel")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("mytag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(cancel);
        let actions = dialog.poll_actions();
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Event(Event::Terminated(TerminationReason::Cancelled))
        )));
        assert_eq!(dialog.state(), DialogState::Terminated);
    }

    #[test]
    fn test_send_response_rejects_uas_dialog() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 486);
        dialog.send_response(response);

        let actions = dialog.poll_actions();
        assert!(actions.iter().any(|a| {
            matches!(
                a,
                Action::Event(Event::Terminated(TerminationReason::Rejected(486)))
            )
        }));
        assert_eq!(dialog.state(), DialogState::Terminated);
    }

    #[test]
    fn test_send_response_provisional_keeps_state() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 180);
        dialog.send_response(response);

        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_send_response_after_confirmed_does_not_reset_state() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 200);
        dialog.send_response(response);
        dialog.poll_actions();

        let response = create_response(&invite, 200);
        dialog.send_response(response);

        assert_eq!(dialog.state(), DialogState::Confirmed);
    }

    #[test]
    fn test_send_response_failure_after_confirmed_keeps_state() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 200);
        dialog.send_response(response);
        dialog.poll_actions();

        let response = create_response(&invite, 486);
        dialog.send_response(response);

        assert_eq!(dialog.state(), DialogState::Confirmed);
        let actions = dialog.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::SendResponse(_))));
        assert!(!actions.iter().any(is_rejected_termination));
    }

    #[test]
    fn test_send_bye_requires_confirmed() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite);

        let bye = dialog.send_bye();
        assert!(bye.is_none());
    }

    #[test]
    fn test_send_bye_with_route_set() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());
        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        dialog.info.route_set = crate::dialog::state::RouteSet::from_record_route_values(
            &["<sip:proxy.example.com;lr>".to_string()],
            false,
        );

        let bye = dialog.send_bye();
        assert!(bye.is_some());
        assert_eq!(dialog.state(), DialogState::Terminating);
    }

    // Additional tests for better coverage

    #[test]
    fn test_role_debug() {
        assert!(format!("{:?}", Role::Uac).contains("Uac"));
        assert!(format!("{:?}", Role::Uas).contains("Uas"));
    }

    #[test]
    #[allow(clippy::clone_on_copy)] // exercise derived Clone for coverage
    fn test_role_clone() {
        let role = Role::Uac;
        let cloned = role.clone();
        assert_eq!(role, cloned);
    }

    #[test]
    fn test_role_copy() {
        let role = Role::Uas;
        let copied: Role = role;
        assert_eq!(role, copied);
    }

    #[test]
    fn test_role_eq() {
        assert_eq!(Role::Uac, Role::Uac);
        assert_ne!(Role::Uac, Role::Uas);
    }

    #[test]
    fn test_action_debug() {
        let action = Action::Event(Event::Established);
        let debug = format!("{:?}", action);
        assert!(debug.contains("Event"));
    }

    #[test]
    fn test_action_clone() {
        let action = Action::Event(Event::Established);
        let cloned = action.clone();
        let debug = format!("{:?}", cloned);
        assert!(debug.contains("Established"));
    }

    #[test]
    fn test_event_debug() {
        let event = Event::Established;
        assert!(format!("{:?}", event).contains("Established"));

        let event = Event::Terminated(TerminationReason::ByeSent);
        assert!(format!("{:?}", event).contains("Terminated"));
    }

    #[test]
    fn test_event_clone() {
        let event = Event::Established;
        let cloned = event.clone();
        let debug = format!("{:?}", cloned);
        assert!(debug.contains("Established"));
    }

    #[test]
    fn test_termination_reason_debug() {
        assert!(format!("{:?}", TerminationReason::ByeSent).contains("ByeSent"));
        assert!(format!("{:?}", TerminationReason::ByeReceived).contains("ByeReceived"));
        assert!(format!("{:?}", TerminationReason::Rejected(486)).contains("486"));
        assert!(format!("{:?}", TerminationReason::Cancelled).contains("Cancelled"));
        assert!(format!("{:?}", TerminationReason::Error("test".into())).contains("Error"));
    }

    #[test]
    fn test_termination_reason_clone() {
        let reason = TerminationReason::Rejected(404);
        let cloned = reason.clone();
        let debug = format!("{:?}", cloned);
        assert!(debug.contains("Rejected"));
    }

    #[test]
    fn test_invite_dialog_debug() {
        let invite = create_invite();
        let dialog = InviteDialog::new_uac(invite);
        let debug = format!("{:?}", dialog);
        assert!(debug.contains("InviteDialog"));
    }

    #[test]
    fn test_uac_100_trying_no_early_dialog() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // 100 Trying should not create early dialog
        let response = create_response(&invite, 100);
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Early);
        let actions = dialog.poll_actions();
        // No provisional event for 100 Trying
        assert!(actions.is_empty());
    }

    #[test]
    fn test_uac_180_ringing_creates_early_dialog() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 180);
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Early);
        let actions = dialog.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Provisional(_)))));
    }

    #[test]
    fn test_uac_183_session_progress() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 183);
        dialog.handle_response(response);

        let actions = dialog.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::SessionProgress(_)))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::Provisional(_)))));
    }

    #[test]
    fn test_handle_response_uas_ignored() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        // UAS should ignore handle_response
        let response = create_response(&invite, 200);
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Early);
        let actions = dialog.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_handle_response_confirmed_state() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // First establish
        let response = create_response(&invite, 200);
        dialog.handle_response(response.clone());
        dialog.poll_actions();

        // Response in confirmed state (e.g., re-INVITE response)
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Confirmed);
    }

    #[test]
    fn test_handle_request_reinvite() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // First establish
        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        // Re-INVITE
        let reinvite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:alice@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKreinvite")
            .from("sip:bob@example.com", "totag")
            .to("sip:alice@example.com")
            .to_tag("fromtag")
            .call_id("test@example.com")
            .cseq(2)
            .build()
            .unwrap();

        dialog.handle_request(reinvite);

        let actions = dialog.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Event(Event::ReInvite(_)))));
    }

    #[test]
    fn test_handle_request_ack_uas() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        // First send 200
        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&invite)
            .to_tag("mytag")
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap();
        dialog.send_response(response);
        dialog.poll_actions();

        // ACK received
        let ack = SipRequest::builder()
            .method(Method::Ack)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKack")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("mytag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(ack);
        assert!(dialog.is_ack_complete());
    }

    #[test]
    fn test_handle_request_cancel() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        // CANCEL in early state
        let cancel = SipRequest::builder()
            .method(Method::Cancel)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKcancel")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(cancel);
        assert_eq!(dialog.state(), DialogState::Terminated);
        let actions = dialog.poll_actions();
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Event(Event::Terminated(TerminationReason::Cancelled))
        )));
    }

    #[test]
    fn test_handle_request_invalid_cseq_ignored() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let raw = String::from_utf8(invite.to_bytes().to_vec()).unwrap();
        let raw = raw.replace("CSeq: 1 INVITE", "CSeq: abc INVITE");
        assert!(raw.contains("CSeq: abc INVITE"));
        let parsed = SipMessage::parse(raw.as_bytes()).unwrap();
        let request = parsed.as_request().unwrap().clone();

        dialog.handle_request(request);
        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_handle_response_other_state_noop() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        dialog.info.state = DialogState::Terminated;
        let response = create_response(&invite, 200);
        dialog.handle_response(response);

        assert_eq!(dialog.state(), DialogState::Terminated);
        assert!(dialog.poll_actions().is_empty());
    }

    #[test]
    fn test_handle_request_other_method() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // Establish dialog
        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        // INFO request (other method)
        let info = SipRequest::builder()
            .method(Method::Info)
            .uri("sip:alice@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKinfo")
            .from("sip:bob@example.com", "totag")
            .to("sip:alice@example.com")
            .to_tag("fromtag")
            .call_id("test@example.com")
            .cseq(2)
            .build()
            .unwrap();

        dialog.handle_request(info);

        // No state change, no events
        assert_eq!(dialog.state(), DialogState::Confirmed);
    }

    #[test]
    fn test_send_response_uac_ignored() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // UAC should ignore send_response
        let response = create_response(&invite, 200);
        dialog.send_response(response);

        let actions = dialog.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_send_response_provisional() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = SipResponse::builder()
            .status(180, "Ringing")
            .from_request(&invite)
            .to_tag("mytag")
            .build()
            .unwrap();

        dialog.send_response(response);

        assert_eq!(dialog.state(), DialogState::Early);
        let actions = dialog.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, Action::SendResponse(_))));
    }

    #[test]
    fn test_send_response_failure() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = SipResponse::builder()
            .status(486, "Busy Here")
            .from_request(&invite)
            .to_tag("mytag")
            .build()
            .unwrap();

        dialog.send_response(response);

        assert_eq!(dialog.state(), DialogState::Terminated);
        let actions = dialog.poll_actions();
        assert!(actions.iter().any(is_rejected_termination));
    }

    #[test]
    fn test_send_bye_not_confirmed() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite);

        // Can't send BYE when not confirmed
        let bye = dialog.send_bye();
        assert!(bye.is_none());
    }

    #[test]
    fn test_send_bye_confirmed() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // First establish
        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        let bye = dialog.send_bye();
        assert!(bye.is_some());
        assert_eq!(dialog.state(), DialogState::Terminating);
    }

    #[test]
    fn test_send_bye_confirmed_uas() {
        let invite = create_invite();
        let mut dialog =
            InviteDialog::new_uas(invite.clone(), "mytag", "sip:me@192.168.1.2:5060").unwrap();

        let response = create_response(&invite, 200);
        dialog.send_response(response);
        dialog.poll_actions();

        let bye = dialog.send_bye();
        assert!(bye.is_some());
        assert_eq!(dialog.state(), DialogState::Terminating);
    }

    #[test]
    fn test_send_bye_build_failure_returns_none() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite);
        dialog.info.state = DialogState::Confirmed;
        dialog.info.remote_target = "sip:alice@[::1".to_string();

        let bye = dialog.send_bye();
        assert!(bye.is_none());
    }

    #[test]
    fn test_ack_sent() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // First establish
        let response = create_response(&invite, 200);
        dialog.handle_response(response);
        dialog.poll_actions();

        assert!(!dialog.is_ack_complete());
        dialog.ack_sent();
        assert!(dialog.is_ack_complete());
    }

    #[test]
    fn test_is_terminated() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        assert!(!dialog.is_terminated());

        let response = create_response(&invite, 486);
        dialog.handle_response(response);

        assert!(dialog.is_terminated());
    }

    #[test]
    fn test_accessors() {
        let invite = create_invite();
        let dialog = InviteDialog::new_uac(invite);

        let _id = dialog.id();
        let _info = dialog.info();
        let _role = dialog.role();
        let _state = dialog.state();
    }

    #[test]
    fn test_poll_actions_clears() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        let response = create_response(&invite, 200);
        dialog.handle_response(response);

        let actions = dialog.poll_actions();
        assert!(!actions.is_empty());

        // Second poll should be empty
        let actions2 = dialog.poll_actions();
        assert!(actions2.is_empty());
    }

    #[test]
    fn test_cancel_uac_ignored() {
        let invite = create_invite();
        let mut dialog = InviteDialog::new_uac(invite.clone());

        // CANCEL should be ignored for UAC role
        let cancel = SipRequest::builder()
            .method(Method::Cancel)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKcancel")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();

        dialog.handle_request(cancel);
        assert_eq!(dialog.state(), DialogState::Early);
    }

    #[test]
    fn test_uac_multiple_3xx_codes() {
        for code in [300, 301, 302, 400, 401, 404, 486, 500, 503, 600] {
            let invite = create_invite();
            let mut dialog = InviteDialog::new_uac(invite.clone());

            let response = create_response(&invite, code);
            dialog.handle_response(response);

            assert_eq!(dialog.state(), DialogState::Terminated);
        }
    }

    #[test]
    fn test_uac_multiple_2xx_codes() {
        for code in [200, 202] {
            let invite = create_invite();
            let mut dialog = InviteDialog::new_uac(invite.clone());

            let response = create_response(&invite, code);
            dialog.handle_response(response);

            assert_eq!(dialog.state(), DialogState::Confirmed);
        }
    }
}

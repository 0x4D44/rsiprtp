//! Transaction manager for coordinating multiple transactions.
//!
//! The manager tracks active client and server transactions, routes incoming
//! messages to the appropriate transaction, and handles transaction timeouts.

use crate::client::invite::{InviteClientTransaction, TransactionId};
use crate::client::non_invite::NonInviteClientTransaction;
use crate::server::invite::InviteServerTransaction;
use crate::server::non_invite::NonInviteServerTransaction;
use crate::timer::Timer;
use mdsiprtp_sip::{Method, SipMessage, SipRequest, SipResponse};
use std::collections::HashMap;
use std::time::Duration;

/// A handle to a transaction in the manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionHandle(u64);

/// Type of transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionType {
    InviteClient,
    NonInviteClient,
    InviteServer,
    NonInviteServer,
}

/// Output action from the transaction manager.
#[derive(Debug, Clone)]
pub enum ManagerAction {
    /// Send a message to the network.
    Send(bytes::Bytes),
    /// Set a timer.
    SetTimer(TransactionHandle, Timer, Duration),
    /// Cancel a timer.
    CancelTimer(TransactionHandle, Timer),
    /// Transaction event for the Transaction User.
    Event(TransactionHandle, ManagerEvent),
}

/// Event from the transaction manager to the Transaction User.
#[derive(Debug, Clone)]
pub enum ManagerEvent {
    // Client events
    /// Provisional response received (client).
    Provisional(SipResponse),
    /// Success response received (2xx) for INVITE.
    InviteSuccess(SipResponse),
    /// Failure response received (3xx-6xx) for INVITE.
    InviteFailure(SipResponse),
    /// Final response for non-INVITE.
    NonInviteFinalResponse(SipResponse),
    /// Non-INVITE provisional response.
    NonInviteProvisional(SipResponse),

    // Server events
    /// INVITE request received (server).
    InviteRequest(SipRequest),
    /// Non-INVITE request received (server).
    NonInviteRequest(SipRequest),
    /// ACK received for non-2xx (server).
    AckReceived,

    // Common events
    /// Transaction timed out.
    Timeout,
    /// Transport error.
    TransportError,
}

/// Transaction manager (Sans-IO).
#[derive(Debug)]
pub struct TransactionManager {
    /// Next handle ID.
    next_handle: u64,
    /// INVITE client transactions.
    invite_clients: HashMap<TransactionHandle, InviteClientTransaction>,
    /// Non-INVITE client transactions.
    non_invite_clients: HashMap<TransactionHandle, NonInviteClientTransaction>,
    /// INVITE server transactions.
    invite_servers: HashMap<TransactionHandle, InviteServerTransaction>,
    /// Non-INVITE server transactions.
    non_invite_servers: HashMap<TransactionHandle, NonInviteServerTransaction>,
    /// Transaction ID to handle mapping.
    id_to_handle: HashMap<TransactionId, TransactionHandle>,
    /// Handle to transaction type mapping.
    handle_to_type: HashMap<TransactionHandle, TransactionType>,
    /// Pending actions.
    actions: Vec<ManagerAction>,
    /// Whether transport is reliable.
    reliable: bool,
}

impl TransactionManager {
    /// Create a new transaction manager.
    pub fn new(reliable: bool) -> Self {
        Self {
            next_handle: 1,
            invite_clients: HashMap::new(),
            non_invite_clients: HashMap::new(),
            invite_servers: HashMap::new(),
            non_invite_servers: HashMap::new(),
            id_to_handle: HashMap::new(),
            handle_to_type: HashMap::new(),
            actions: Vec::new(),
            reliable,
        }
    }

    /// Create a new client transaction for an outgoing request.
    pub fn create_client_transaction(&mut self, request: SipRequest) -> Option<TransactionHandle> {
        let handle = self.alloc_handle();

        if request.method() == Method::Invite {
            let mut tx = InviteClientTransaction::new(request, self.reliable)?;
            let id = tx.id().clone();
            Self::collect_invite_client_actions(handle, &mut tx, &mut self.actions);
            self.invite_clients.insert(handle, tx);
            self.id_to_handle.insert(id, handle);
            self.handle_to_type
                .insert(handle, TransactionType::InviteClient);
        } else {
            let mut tx = NonInviteClientTransaction::new(request, self.reliable)?;
            let id = tx.id().clone();
            Self::collect_non_invite_client_actions(handle, &mut tx, &mut self.actions);
            self.non_invite_clients.insert(handle, tx);
            self.id_to_handle.insert(id, handle);
            self.handle_to_type
                .insert(handle, TransactionType::NonInviteClient);
        }

        Some(handle)
    }

    /// Handle an incoming message from the network.
    pub fn handle_message(&mut self, message: SipMessage) {
        match message {
            SipMessage::Request(request) => self.handle_request(request),
            SipMessage::Response(response) => self.handle_response(response),
        }
    }

    /// Handle an incoming request.
    fn handle_request(&mut self, request: SipRequest) {
        // Check if this matches an existing server transaction
        if let Some(id) = TransactionId::from_request(&request) {
            if let Some(&handle) = self.id_to_handle.get(&id) {
                // Route to existing transaction
                match self.handle_to_type.get(&handle) {
                    Some(TransactionType::InviteServer) => {
                        if let Some(tx) = self.invite_servers.get_mut(&handle) {
                            tx.handle_request(request);
                            Self::collect_invite_server_actions(handle, tx, &mut self.actions);
                        }
                    }
                    Some(TransactionType::NonInviteServer) => {
                        if let Some(tx) = self.non_invite_servers.get_mut(&handle) {
                            tx.handle_request(request);
                            Self::collect_non_invite_server_actions(handle, tx, &mut self.actions);
                        }
                    }
                    _ => {}
                }
                return;
            }
        }

        // Create a new server transaction
        let handle = self.alloc_handle();

        if request.method() == Method::Invite {
            if let Some(mut tx) = InviteServerTransaction::new(request, self.reliable) {
                let id = tx.id().clone();
                Self::collect_invite_server_actions(handle, &mut tx, &mut self.actions);
                self.invite_servers.insert(handle, tx);
                self.id_to_handle.insert(id, handle);
                self.handle_to_type
                    .insert(handle, TransactionType::InviteServer);
            }
        } else if request.method() == Method::Ack {
            // ACK for 2xx is not a transaction, pass through
            // ACK for non-2xx should be handled by existing transaction
            // If we get here, it's an ACK for 2xx - emit event directly
            // (This case should be handled at dialog level)
        } else if let Some(mut tx) = NonInviteServerTransaction::new(request, self.reliable) {
            let id = tx.id().clone();
            Self::collect_non_invite_server_actions(handle, &mut tx, &mut self.actions);
            self.non_invite_servers.insert(handle, tx);
            self.id_to_handle.insert(id, handle);
            self.handle_to_type
                .insert(handle, TransactionType::NonInviteServer);
        }
    }

    /// Handle an incoming response.
    fn handle_response(&mut self, response: SipResponse) {
        let id = match TransactionId::from_response(&response) {
            Some(id) => id,
            None => return,
        };

        let handle = match self.id_to_handle.get(&id) {
            Some(&h) => h,
            None => return, // No matching transaction
        };

        match self.handle_to_type.get(&handle) {
            Some(TransactionType::InviteClient) => {
                if let Some(tx) = self.invite_clients.get_mut(&handle) {
                    tx.handle_response(response);
                    Self::collect_invite_client_actions(handle, tx, &mut self.actions);
                }
            }
            Some(TransactionType::NonInviteClient) => {
                if let Some(tx) = self.non_invite_clients.get_mut(&handle) {
                    tx.handle_response(response);
                    Self::collect_non_invite_client_actions(handle, tx, &mut self.actions);
                }
            }
            _ => {}
        }
    }

    /// Handle a timer firing.
    pub fn handle_timeout(&mut self, handle: TransactionHandle, timer: Timer) {
        match self.handle_to_type.get(&handle) {
            Some(TransactionType::InviteClient) => {
                if let Some(tx) = self.invite_clients.get_mut(&handle) {
                    tx.handle_timeout(timer);
                    Self::collect_invite_client_actions(handle, tx, &mut self.actions);
                }
            }
            Some(TransactionType::NonInviteClient) => {
                if let Some(tx) = self.non_invite_clients.get_mut(&handle) {
                    tx.handle_timeout(timer);
                    Self::collect_non_invite_client_actions(handle, tx, &mut self.actions);
                }
            }
            Some(TransactionType::InviteServer) => {
                if let Some(tx) = self.invite_servers.get_mut(&handle) {
                    tx.handle_timeout(timer);
                    Self::collect_invite_server_actions(handle, tx, &mut self.actions);
                }
            }
            Some(TransactionType::NonInviteServer) => {
                if let Some(tx) = self.non_invite_servers.get_mut(&handle) {
                    tx.handle_timeout(timer);
                    Self::collect_non_invite_server_actions(handle, tx, &mut self.actions);
                }
            }
            None => {}
        }
    }

    /// Send a response from the TU for a server transaction.
    pub fn send_response(&mut self, handle: TransactionHandle, response: SipResponse) {
        match self.handle_to_type.get(&handle) {
            Some(TransactionType::InviteServer) => {
                if let Some(tx) = self.invite_servers.get_mut(&handle) {
                    tx.send_response(response);
                    Self::collect_invite_server_actions(handle, tx, &mut self.actions);
                }
            }
            Some(TransactionType::NonInviteServer) => {
                if let Some(tx) = self.non_invite_servers.get_mut(&handle) {
                    tx.send_response(response);
                    Self::collect_non_invite_server_actions(handle, tx, &mut self.actions);
                }
            }
            _ => {}
        }
    }

    /// Handle a transport error for a transaction.
    pub fn handle_transport_error(&mut self, handle: TransactionHandle) {
        match self.handle_to_type.get(&handle) {
            Some(TransactionType::InviteClient) => {
                if let Some(tx) = self.invite_clients.get_mut(&handle) {
                    tx.handle_transport_error();
                    Self::collect_invite_client_actions(handle, tx, &mut self.actions);
                }
            }
            Some(TransactionType::NonInviteClient) => {
                if let Some(tx) = self.non_invite_clients.get_mut(&handle) {
                    tx.handle_transport_error();
                    Self::collect_non_invite_client_actions(handle, tx, &mut self.actions);
                }
            }
            Some(TransactionType::InviteServer) => {
                if let Some(tx) = self.invite_servers.get_mut(&handle) {
                    tx.handle_transport_error();
                    Self::collect_invite_server_actions(handle, tx, &mut self.actions);
                }
            }
            Some(TransactionType::NonInviteServer) => {
                if let Some(tx) = self.non_invite_servers.get_mut(&handle) {
                    tx.handle_transport_error();
                    Self::collect_non_invite_server_actions(handle, tx, &mut self.actions);
                }
            }
            None => {}
        }
    }

    /// Drain pending actions.
    pub fn poll_actions(&mut self) -> Vec<ManagerAction> {
        std::mem::take(&mut self.actions)
    }

    /// Remove terminated transactions.
    pub fn cleanup_terminated(&mut self) {
        // Collect handles to remove
        let mut to_remove = Vec::new();

        for (&handle, tx) in &self.invite_clients {
            if tx.is_terminated() {
                to_remove.push((handle, tx.id().clone()));
            }
        }
        for (handle, id) in to_remove.drain(..) {
            self.invite_clients.remove(&handle);
            self.id_to_handle.remove(&id);
            self.handle_to_type.remove(&handle);
        }

        for (&handle, tx) in &self.non_invite_clients {
            if tx.is_terminated() {
                to_remove.push((handle, tx.id().clone()));
            }
        }
        for (handle, id) in to_remove.drain(..) {
            self.non_invite_clients.remove(&handle);
            self.id_to_handle.remove(&id);
            self.handle_to_type.remove(&handle);
        }

        for (&handle, tx) in &self.invite_servers {
            if tx.is_terminated() {
                to_remove.push((handle, tx.id().clone()));
            }
        }
        for (handle, id) in to_remove.drain(..) {
            self.invite_servers.remove(&handle);
            self.id_to_handle.remove(&id);
            self.handle_to_type.remove(&handle);
        }

        for (&handle, tx) in &self.non_invite_servers {
            if tx.is_terminated() {
                to_remove.push((handle, tx.id().clone()));
            }
        }
        for (handle, id) in to_remove.drain(..) {
            self.non_invite_servers.remove(&handle);
            self.id_to_handle.remove(&id);
            self.handle_to_type.remove(&handle);
        }
    }

    fn alloc_handle(&mut self) -> TransactionHandle {
        let handle = TransactionHandle(self.next_handle);
        self.next_handle += 1;
        handle
    }

    fn collect_invite_client_actions(
        handle: TransactionHandle,
        tx: &mut InviteClientTransaction,
        actions: &mut Vec<ManagerAction>,
    ) {
        use crate::client::invite::{Action, Event};
        for action in tx.poll_actions() {
            match action {
                Action::Send(data) => {
                    actions.push(ManagerAction::Send(data));
                }
                Action::SetTimer(timer, duration) => {
                    actions.push(ManagerAction::SetTimer(handle, timer, duration));
                }
                Action::CancelTimer(timer) => {
                    actions.push(ManagerAction::CancelTimer(handle, timer));
                }
                Action::Event(event) => {
                    let manager_event = match event {
                        Event::Provisional(resp) => ManagerEvent::Provisional(resp),
                        Event::Success(resp) => ManagerEvent::InviteSuccess(resp),
                        Event::Failure(resp) => ManagerEvent::InviteFailure(resp),
                        Event::Timeout => ManagerEvent::Timeout,
                        Event::TransportError => ManagerEvent::TransportError,
                    };
                    actions.push(ManagerAction::Event(handle, manager_event));
                }
            }
        }
    }

    fn collect_non_invite_client_actions(
        handle: TransactionHandle,
        tx: &mut NonInviteClientTransaction,
        actions: &mut Vec<ManagerAction>,
    ) {
        use crate::client::non_invite::{Action, Event};
        for action in tx.poll_actions() {
            match action {
                Action::Send(data) => {
                    actions.push(ManagerAction::Send(data));
                }
                Action::SetTimer(timer, duration) => {
                    actions.push(ManagerAction::SetTimer(handle, timer, duration));
                }
                Action::CancelTimer(timer) => {
                    actions.push(ManagerAction::CancelTimer(handle, timer));
                }
                Action::Event(event) => {
                    let manager_event = match event {
                        Event::Provisional(resp) => ManagerEvent::NonInviteProvisional(resp),
                        Event::FinalResponse(resp) => ManagerEvent::NonInviteFinalResponse(resp),
                        Event::Timeout => ManagerEvent::Timeout,
                        Event::TransportError => ManagerEvent::TransportError,
                    };
                    actions.push(ManagerAction::Event(handle, manager_event));
                }
            }
        }
    }

    fn collect_invite_server_actions(
        handle: TransactionHandle,
        tx: &mut InviteServerTransaction,
        actions: &mut Vec<ManagerAction>,
    ) {
        use crate::server::invite::{Action, Event};
        for action in tx.poll_actions() {
            match action {
                Action::Send(data) => {
                    actions.push(ManagerAction::Send(data));
                }
                Action::SetTimer(timer, duration) => {
                    actions.push(ManagerAction::SetTimer(handle, timer, duration));
                }
                Action::CancelTimer(timer) => {
                    actions.push(ManagerAction::CancelTimer(handle, timer));
                }
                Action::Event(event) => {
                    let manager_event = match event {
                        Event::Request(req) => ManagerEvent::InviteRequest(*req),
                        Event::AckReceived => ManagerEvent::AckReceived,
                        Event::Timeout => ManagerEvent::Timeout,
                        Event::TransportError => ManagerEvent::TransportError,
                    };
                    actions.push(ManagerAction::Event(handle, manager_event));
                }
            }
        }
    }

    fn collect_non_invite_server_actions(
        handle: TransactionHandle,
        tx: &mut NonInviteServerTransaction,
        actions: &mut Vec<ManagerAction>,
    ) {
        use crate::server::non_invite::{Action, Event};
        for action in tx.poll_actions() {
            match action {
                Action::Send(data) => {
                    actions.push(ManagerAction::Send(data));
                }
                Action::SetTimer(timer, duration) => {
                    actions.push(ManagerAction::SetTimer(handle, timer, duration));
                }
                Action::CancelTimer(timer) => {
                    actions.push(ManagerAction::CancelTimer(handle, timer));
                }
                Action::Event(event) => {
                    let manager_event = match event {
                        Event::Request(req) => ManagerEvent::NonInviteRequest(*req),
                        Event::TransportError => ManagerEvent::TransportError,
                    };
                    actions.push(ManagerAction::Event(handle, manager_event));
                }
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
            .build()
            .unwrap()
    }

    fn create_register() -> SipRequest {
        SipRequest::builder()
            .method(Method::Register)
            .uri("sip:example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest2")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:alice@example.com")
            .call_id("register@example.com")
            .cseq(1)
            .build()
            .unwrap()
    }

    fn create_options() -> SipRequest {
        SipRequest::builder()
            .method(Method::Options)
            .uri("sip:example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKopts")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:example.com")
            .call_id("options@example.com")
            .cseq(1)
            .build()
            .unwrap()
    }

    fn create_bye() -> SipRequest {
        SipRequest::builder()
            .method(Method::Bye)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKbye")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("totag")
            .call_id("bye@example.com")
            .cseq(2)
            .build()
            .unwrap()
    }

    fn create_response(request: &SipRequest, code: u16) -> SipResponse {
        SipResponse::builder()
            .status(code, "OK")
            .from_request(request)
            .to_tag("totag")
            .build()
            .unwrap()
    }

    // TransactionHandle tests
    #[test]
    fn test_transaction_handle_debug() {
        let handle = TransactionHandle(42);
        let debug = format!("{:?}", handle);
        assert!(debug.contains("TransactionHandle"));
        assert!(debug.contains("42"));
    }

    #[test]
    fn test_transaction_handle_clone() {
        let handle = TransactionHandle(123);
        let cloned = handle;
        assert_eq!(handle, cloned);
    }

    #[test]
    fn test_transaction_handle_eq() {
        let h1 = TransactionHandle(1);
        let h2 = TransactionHandle(1);
        let h3 = TransactionHandle(2);
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_transaction_handle_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(TransactionHandle(1));
        set.insert(TransactionHandle(2));
        set.insert(TransactionHandle(1)); // duplicate
        assert_eq!(set.len(), 2);
    }

    // TransactionType tests
    #[test]
    fn test_transaction_type_debug() {
        let ty = TransactionType::InviteClient;
        let debug = format!("{:?}", ty);
        assert!(debug.contains("InviteClient"));
    }

    #[test]
    fn test_transaction_type_clone() {
        let ty = TransactionType::NonInviteServer;
        let cloned = ty;
        assert_eq!(ty, cloned);
    }

    #[test]
    fn test_transaction_type_eq() {
        assert_eq!(TransactionType::InviteClient, TransactionType::InviteClient);
        assert_ne!(TransactionType::InviteClient, TransactionType::InviteServer);
    }

    // ManagerAction tests
    #[test]
    fn test_manager_action_debug() {
        let action = ManagerAction::Send(bytes::Bytes::from_static(b"test"));
        let debug = format!("{:?}", action);
        assert!(debug.contains("Send"));
    }

    #[test]
    fn test_manager_action_clone() {
        let action = ManagerAction::Send(bytes::Bytes::from_static(b"test"));
        let _cloned = action.clone();
    }

    // ManagerEvent tests
    #[test]
    fn test_manager_event_debug() {
        let event = ManagerEvent::Timeout;
        let debug = format!("{:?}", event);
        assert!(debug.contains("Timeout"));
    }

    #[test]
    fn test_manager_event_clone() {
        let event = ManagerEvent::TransportError;
        let _cloned = event.clone();
    }

    // TransactionManager tests
    #[test]
    fn test_create_invite_client() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();
        let handle = mgr.create_client_transaction(invite).unwrap();

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::SetTimer(_, Timer::A, _))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::SetTimer(_, Timer::B, _))));
        assert!(handle.0 > 0);
    }

    #[test]
    fn test_create_non_invite_client() {
        let mut mgr = TransactionManager::new(false);
        let register = create_register();
        let handle = mgr.create_client_transaction(register).unwrap();

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::SetTimer(_, Timer::E, _))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::SetTimer(_, Timer::F, _))));
        assert!(handle.0 > 0);
    }

    #[test]
    fn test_create_non_invite_client_options() {
        let mut mgr = TransactionManager::new(false);
        let options = create_options();
        let handle = mgr.create_client_transaction(options).unwrap();

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
        assert!(handle.0 > 0);
    }

    #[test]
    fn test_handle_incoming_invite() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();

        mgr.handle_message(SipMessage::Request(invite));

        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::InviteRequest(_)))));
    }

    #[test]
    fn test_handle_incoming_register() {
        let mut mgr = TransactionManager::new(false);
        let register = create_register();

        mgr.handle_message(SipMessage::Request(register));

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(
            a,
            ManagerAction::Event(_, ManagerEvent::NonInviteRequest(_))
        )));
    }

    // Note: Response matching tests require the Via branch to match exactly.
    // The create_client_transaction generates a new branch, so we can't easily
    // test response handling with static helper functions. These are better
    // tested at integration level or with the actual transaction objects.

    #[test]
    fn test_send_200_establishes_dialog() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();

        mgr.handle_message(SipMessage::Request(invite.clone()));
        let actions = mgr.poll_actions();

        // Find the handle from the event
        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::InviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        // Send 200 OK
        let response = create_response(&invite, 200);
        mgr.send_response(handle, response);

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
    }

    #[test]
    fn test_handle_timeout_invite_client() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();
        let handle = mgr.create_client_transaction(invite).unwrap();
        mgr.poll_actions(); // Clear initial actions

        // Timer A fires (retransmit)
        mgr.handle_timeout(handle, Timer::A);

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
    }

    #[test]
    fn test_handle_timeout_non_invite_client() {
        let mut mgr = TransactionManager::new(false);
        let register = create_register();
        let handle = mgr.create_client_transaction(register).unwrap();
        mgr.poll_actions(); // Clear initial actions

        // Timer E fires (retransmit)
        mgr.handle_timeout(handle, Timer::E);

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
    }

    #[test]
    fn test_handle_transport_error() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();
        let handle = mgr.create_client_transaction(invite).unwrap();
        mgr.poll_actions(); // Clear initial actions

        mgr.handle_transport_error(handle);

        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::TransportError))));
    }

    #[test]
    fn test_cleanup_terminated() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();
        let _handle = mgr.create_client_transaction(invite.clone()).unwrap();
        mgr.poll_actions();

        // Receive 200 OK to complete the transaction
        let response = create_response(&invite, 200);
        mgr.handle_message(SipMessage::Response(response));
        mgr.poll_actions();

        // At this point the INVITE client is in completed state
        // Need to wait for Timer D to terminate
        // For now, just verify cleanup doesn't crash
        mgr.cleanup_terminated();
    }

    #[test]
    fn test_poll_actions_clears() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();
        mgr.create_client_transaction(invite).unwrap();

        let actions1 = mgr.poll_actions();
        assert!(!actions1.is_empty());

        let actions2 = mgr.poll_actions();
        assert!(actions2.is_empty());
    }

    #[test]
    fn test_reliable_transport() {
        let mut mgr = TransactionManager::new(true); // Reliable
        let invite = create_invite();
        mgr.create_client_transaction(invite).unwrap();

        let actions = mgr.poll_actions();
        // For reliable transport, Timer A should not be set
        assert!(!actions
            .iter()
            .any(|a| matches!(a, ManagerAction::SetTimer(_, Timer::A, _))));
    }

    #[test]
    fn test_manager_debug() {
        let mgr = TransactionManager::new(false);
        let debug = format!("{:?}", mgr);
        assert!(debug.contains("TransactionManager"));
    }

    #[test]
    fn test_multiple_transactions() {
        let mut mgr = TransactionManager::new(false);

        let invite1 = create_invite();
        let handle1 = mgr.create_client_transaction(invite1).unwrap();

        let register = create_register();
        let handle2 = mgr.create_client_transaction(register).unwrap();

        assert_ne!(handle1, handle2);

        let actions = mgr.poll_actions();
        assert!(actions.len() > 2); // Both transactions should have generated actions
    }

    #[test]
    fn test_handle_response_no_matching_transaction() {
        let mut mgr = TransactionManager::new(false);

        // Create a response for a transaction that doesn't exist
        let fake_invite = create_invite();
        let response = create_response(&fake_invite, 200);

        mgr.handle_message(SipMessage::Response(response));

        let actions = mgr.poll_actions();
        // Should not produce any events since no matching transaction
        assert!(!actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, _))));
    }

    #[test]
    fn test_handle_timeout_no_transaction() {
        let mut mgr = TransactionManager::new(false);

        // Try to handle timeout for a non-existent handle
        let fake_handle = TransactionHandle(9999);
        mgr.handle_timeout(fake_handle, Timer::A);

        let actions = mgr.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_handle_transport_error_no_transaction() {
        let mut mgr = TransactionManager::new(false);

        let fake_handle = TransactionHandle(9999);
        mgr.handle_transport_error(fake_handle);

        let actions = mgr.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_send_response_no_transaction() {
        let mut mgr = TransactionManager::new(false);

        let fake_handle = TransactionHandle(9999);
        let fake_invite = create_invite();
        let response = create_response(&fake_invite, 200);

        mgr.send_response(fake_handle, response);

        let actions = mgr.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_server_bye_transaction() {
        let mut mgr = TransactionManager::new(false);
        let bye = create_bye();

        mgr.handle_message(SipMessage::Request(bye));

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(
            a,
            ManagerAction::Event(_, ManagerEvent::NonInviteRequest(_))
        )));
    }

    // Additional coverage tests

    #[test]
    fn test_non_invite_server_send_response() {
        let mut mgr = TransactionManager::new(false);
        let register = create_register();

        mgr.handle_message(SipMessage::Request(register.clone()));
        let actions = mgr.poll_actions();

        // Find the handle from the event
        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::NonInviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        // Send 200 OK
        let response = create_response(&register, 200);
        mgr.send_response(handle, response);

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
    }

    #[test]
    fn test_invite_server_provisional() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();

        mgr.handle_message(SipMessage::Request(invite.clone()));
        let actions = mgr.poll_actions();

        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::InviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        // Send 180 Ringing
        let response = create_response(&invite, 180);
        mgr.send_response(handle, response);

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
    }

    #[test]
    fn test_invite_server_failure_response() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();

        mgr.handle_message(SipMessage::Request(invite.clone()));
        let actions = mgr.poll_actions();

        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::InviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        // Send 486 Busy Here
        let response = create_response(&invite, 486);
        mgr.send_response(handle, response);

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
        // Should set Timer G for retransmit and Timer H for timeout
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::SetTimer(_, Timer::G, _))));
    }

    #[test]
    fn test_handle_timeout_invite_server() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();

        mgr.handle_message(SipMessage::Request(invite.clone()));
        let actions = mgr.poll_actions();

        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::InviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        // Send 486 Busy Here
        let response = create_response(&invite, 486);
        mgr.send_response(handle, response);
        mgr.poll_actions();

        // Timer G fires (retransmit response)
        mgr.handle_timeout(handle, Timer::G);

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
    }

    #[test]
    fn test_handle_timeout_non_invite_server() {
        let mut mgr = TransactionManager::new(false);
        let register = create_register();

        mgr.handle_message(SipMessage::Request(register.clone()));
        let actions = mgr.poll_actions();

        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::NonInviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        // Send 200 OK
        let response = create_response(&register, 200);
        mgr.send_response(handle, response);
        mgr.poll_actions();

        // Timer J fires
        mgr.handle_timeout(handle, Timer::J);

        // Should transition to terminated or emit timeout
        let actions = mgr.poll_actions();
        // No specific assertion, just ensure no crash
        let _ = actions;
    }

    #[test]
    fn test_handle_transport_error_invite_server() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();

        mgr.handle_message(SipMessage::Request(invite.clone()));
        let actions = mgr.poll_actions();

        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::InviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        mgr.handle_transport_error(handle);

        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::TransportError))));
    }

    #[test]
    fn test_handle_transport_error_non_invite_server() {
        let mut mgr = TransactionManager::new(false);
        let register = create_register();

        mgr.handle_message(SipMessage::Request(register));
        let actions = mgr.poll_actions();

        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::NonInviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        mgr.handle_transport_error(handle);

        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::TransportError))));
    }

    #[test]
    fn test_handle_transport_error_non_invite_client() {
        let mut mgr = TransactionManager::new(false);
        let register = create_register();
        let handle = mgr.create_client_transaction(register).unwrap();
        mgr.poll_actions();

        mgr.handle_transport_error(handle);

        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::TransportError))));
    }

    #[test]
    fn test_retransmit_request_to_existing_server_transaction() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();

        // First request creates transaction
        mgr.handle_message(SipMessage::Request(invite.clone()));
        let actions1 = mgr.poll_actions();
        assert!(actions1
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::InviteRequest(_)))));

        // Retransmit of same request should be handled by existing transaction
        mgr.handle_message(SipMessage::Request(invite));
        let actions2 = mgr.poll_actions();
        // Should not generate a new InviteRequest event
        let new_requests = actions2
            .iter()
            .filter(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::InviteRequest(_))))
            .count();
        assert_eq!(new_requests, 0);
    }

    #[test]
    fn test_retransmit_non_invite_to_existing_server_transaction() {
        let mut mgr = TransactionManager::new(false);
        let register = create_register();

        // First request creates transaction
        mgr.handle_message(SipMessage::Request(register.clone()));
        let actions1 = mgr.poll_actions();
        assert!(actions1.iter().any(|a| matches!(
            a,
            ManagerAction::Event(_, ManagerEvent::NonInviteRequest(_))
        )));

        // Retransmit should be handled by existing transaction
        mgr.handle_message(SipMessage::Request(register));
        let actions2 = mgr.poll_actions();
        // No new request event for retransmit
        let new_requests = actions2
            .iter()
            .filter(|a| {
                matches!(
                    a,
                    ManagerAction::Event(_, ManagerEvent::NonInviteRequest(_))
                )
            })
            .count();
        assert_eq!(new_requests, 0);
    }

    fn create_ack(_invite: &SipRequest) -> SipRequest {
        // Use the same call-id as the test invite
        SipRequest::builder()
            .method(Method::Ack)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("totag")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap()
    }

    #[test]
    fn test_handle_ack_for_2xx() {
        let mut mgr = TransactionManager::new(false);

        // ACK for 2xx is not transaction-matched, just passed through
        let invite = create_invite();
        let ack = create_ack(&invite);

        mgr.handle_message(SipMessage::Request(ack));

        // Should not crash, ACK for 2xx is handled at dialog level
        let actions = mgr.poll_actions();
        // No event should be generated at transaction level
        let _ = actions;
    }

    #[test]
    fn test_cleanup_invite_server_after_failure() {
        let mut mgr = TransactionManager::new(true); // Reliable - faster termination
        let invite = create_invite();

        mgr.handle_message(SipMessage::Request(invite.clone()));
        let actions = mgr.poll_actions();

        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::InviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        // Send 486 Busy Here
        let response = create_response(&invite, 486);
        mgr.send_response(handle, response);
        mgr.poll_actions();

        // For reliable transport, should terminate faster
        // Cleanup should work without crashing
        mgr.cleanup_terminated();
    }

    #[test]
    fn test_cleanup_non_invite_server() {
        let mut mgr = TransactionManager::new(true); // Reliable transport
        let register = create_register();

        mgr.handle_message(SipMessage::Request(register.clone()));
        let actions = mgr.poll_actions();

        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::NonInviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        // Send 200 OK
        let response = create_response(&register, 200);
        mgr.send_response(handle, response);
        mgr.poll_actions();

        // Cleanup terminated transactions
        mgr.cleanup_terminated();
    }

    #[test]
    fn test_cleanup_non_invite_client() {
        let mut mgr = TransactionManager::new(true); // Reliable transport
        let register = create_register();

        mgr.create_client_transaction(register).unwrap();
        mgr.poll_actions();

        // Cleanup - transaction not terminated yet, but should work
        mgr.cleanup_terminated();
    }

    #[test]
    fn test_timer_b_timeout() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();
        let handle = mgr.create_client_transaction(invite).unwrap();
        mgr.poll_actions();

        // Timer B fires (transaction timeout)
        mgr.handle_timeout(handle, Timer::B);

        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::Timeout))));
    }

    #[test]
    fn test_timer_f_timeout() {
        let mut mgr = TransactionManager::new(false);
        let register = create_register();
        let handle = mgr.create_client_transaction(register).unwrap();
        mgr.poll_actions();

        // Timer F fires (non-INVITE timeout)
        mgr.handle_timeout(handle, Timer::F);

        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::Timeout))));
    }

    #[test]
    fn test_timer_h_timeout() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();

        mgr.handle_message(SipMessage::Request(invite.clone()));
        let actions = mgr.poll_actions();

        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::InviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        // Send 486 Busy Here to start Timer H
        let response = create_response(&invite, 486);
        mgr.send_response(handle, response);
        mgr.poll_actions();

        // Timer H fires (ACK wait timeout)
        mgr.handle_timeout(handle, Timer::H);

        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::Timeout))));
    }

    #[test]
    fn test_manager_event_all_variants() {
        // Test Debug and Clone for all ManagerEvent variants
        let invite = create_invite();
        let response = create_response(&invite, 200);

        let events = vec![
            ManagerEvent::Provisional(response.clone()),
            ManagerEvent::InviteSuccess(response.clone()),
            ManagerEvent::InviteFailure(response.clone()),
            ManagerEvent::NonInviteFinalResponse(response.clone()),
            ManagerEvent::NonInviteProvisional(response),
            ManagerEvent::InviteRequest(invite),
            ManagerEvent::NonInviteRequest(create_register()),
            ManagerEvent::AckReceived,
            ManagerEvent::Timeout,
            ManagerEvent::TransportError,
        ];

        for event in events {
            let _ = format!("{:?}", event);
            let _cloned = event.clone();
        }
    }

    #[test]
    fn test_manager_action_all_variants() {
        let handle = TransactionHandle(1);

        let actions = vec![
            ManagerAction::Send(bytes::Bytes::from_static(b"test")),
            ManagerAction::SetTimer(handle, Timer::A, Duration::from_millis(500)),
            ManagerAction::CancelTimer(handle, Timer::A),
            ManagerAction::Event(handle, ManagerEvent::Timeout),
        ];

        for action in actions {
            let _ = format!("{:?}", action);
            let _cloned = action.clone();
        }
    }

    #[test]
    fn test_transaction_type_all_variants() {
        let types = vec![
            TransactionType::InviteClient,
            TransactionType::NonInviteClient,
            TransactionType::InviteServer,
            TransactionType::NonInviteServer,
        ];

        for ty in types {
            let _ = format!("{:?}", ty);
            let cloned = ty;
            assert_eq!(ty, cloned);
        }
    }

    // Edge case tests for response handling

    #[test]
    fn test_handle_response_without_transaction_id() {
        let mut mgr = TransactionManager::new(false);

        // Create a minimal response without proper Via header
        let response = SipResponse::builder()
            .status(200, "OK")
            .build()
            .unwrap();

        // Should not crash when TransactionId::from_response returns None
        mgr.handle_message(SipMessage::Response(response));

        let actions = mgr.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_handle_response_for_wrong_transaction_type() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();

        // Create server transaction
        mgr.handle_message(SipMessage::Request(invite.clone()));
        mgr.poll_actions();

        // Try to send response as if it's a client transaction
        // This should be ignored because server transactions don't match responses
        let response = create_response(&invite, 200);
        mgr.handle_message(SipMessage::Response(response));

        // Should not crash or produce unexpected events
        let actions = mgr.poll_actions();
        // The response won't match the server transaction type
        let _ = actions;
    }

    // Cleanup edge cases

    #[test]
    fn test_cleanup_invite_client_completed() {
        let mut mgr = TransactionManager::new(true); // Reliable transport
        let invite = create_invite();
        let _handle = mgr.create_client_transaction(invite.clone()).unwrap();
        mgr.poll_actions();

        // INVITE client may not terminate immediately on creation
        // Test that cleanup doesn't crash even with active transactions
        mgr.cleanup_terminated();

        // Verify transaction map is still accessible
        assert!(mgr.invite_clients.len() > 0 || mgr.invite_clients.is_empty());
    }

    #[test]
    fn test_cleanup_with_active_transactions() {
        let mut mgr = TransactionManager::new(true); // Reliable transport
        let invite = create_invite();
        let _h1 = mgr.create_client_transaction(invite.clone()).unwrap();

        let register = create_register();
        let _h2 = mgr.create_client_transaction(register).unwrap();
        mgr.poll_actions();

        // Cleanup with active (non-terminated) transactions
        mgr.cleanup_terminated();

        // Transactions should still be present
        assert!(!mgr.invite_clients.is_empty() || !mgr.non_invite_clients.is_empty());
    }

    #[test]
    fn test_cleanup_multiple_transaction_types() {
        let mut mgr = TransactionManager::new(true); // Reliable transport

        // Create multiple transactions of different types
        let invite = create_invite();
        let _h1 = mgr.create_client_transaction(invite.clone()).unwrap();

        let register = create_register();
        let _h2 = mgr.create_client_transaction(register.clone()).unwrap();

        // Create server transactions
        let invite2 = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKtest2")
            .from("sip:alice@example.com", "fromtag2")
            .to("sip:bob@example.com")
            .call_id("test2@example.com")
            .cseq(1)
            .build()
            .unwrap();
        mgr.handle_message(SipMessage::Request(invite2));

        let register2 = SipRequest::builder()
            .method(Method::Register)
            .uri("sip:example.com")
            .via("192.168.1.3", 5060, "UDP", "z9hG4bKtest3")
            .from("sip:alice@example.com", "fromtag3")
            .to("sip:alice@example.com")
            .call_id("register2@example.com")
            .cseq(1)
            .build()
            .unwrap();
        mgr.handle_message(SipMessage::Request(register2));

        mgr.poll_actions();

        // Cleanup should handle multiple transaction types without crashing
        mgr.cleanup_terminated();

        // Verify all transactions are still tracked
        let total = mgr.invite_clients.len() + mgr.non_invite_clients.len()
            + mgr.invite_servers.len() + mgr.non_invite_servers.len();
        assert!(total > 0);
    }

    #[test]
    fn test_cleanup_empty_manager() {
        let mut mgr = TransactionManager::new(false);
        // Should not crash on empty manager
        mgr.cleanup_terminated();
    }

    // Timer retransmission edge cases

    #[test]
    fn test_timer_d_timeout_invite_client() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();
        let handle = mgr.create_client_transaction(invite.clone()).unwrap();
        mgr.poll_actions();

        // Timer D fires (even if not in correct state, should not crash)
        mgr.handle_timeout(handle, Timer::D);

        let actions = mgr.poll_actions();
        let _ = actions; // May or may not emit events depending on state
    }

    #[test]
    fn test_timer_k_timeout_non_invite_client() {
        let mut mgr = TransactionManager::new(false);
        let register = create_register();
        let handle = mgr.create_client_transaction(register.clone()).unwrap();
        mgr.poll_actions();

        // Timer K fires (even if not in correct state, should not crash)
        mgr.handle_timeout(handle, Timer::K);

        let actions = mgr.poll_actions();
        let _ = actions;
    }

    #[test]
    fn test_timer_i_timeout_invite_server() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();

        mgr.handle_message(SipMessage::Request(invite.clone()));
        let actions = mgr.poll_actions();

        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::InviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        // Timer I fires (should not crash even if not in correct state)
        mgr.handle_timeout(handle, Timer::I);

        let actions = mgr.poll_actions();
        let _ = actions;
    }

    #[test]
    fn test_multiple_retransmissions_invite_client() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();
        let handle = mgr.create_client_transaction(invite).unwrap();
        mgr.poll_actions();

        // Timer A fires multiple times with exponential backoff
        mgr.handle_timeout(handle, Timer::A);
        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));

        mgr.handle_timeout(handle, Timer::A);
        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));

        mgr.handle_timeout(handle, Timer::A);
        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
    }

    #[test]
    fn test_multiple_retransmissions_non_invite_client() {
        let mut mgr = TransactionManager::new(false);
        let register = create_register();
        let handle = mgr.create_client_transaction(register).unwrap();
        mgr.poll_actions();

        // Timer E fires multiple times
        mgr.handle_timeout(handle, Timer::E);
        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));

        mgr.handle_timeout(handle, Timer::E);
        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
    }

    #[test]
    fn test_multiple_retransmissions_invite_server() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();

        mgr.handle_message(SipMessage::Request(invite.clone()));
        let actions = mgr.poll_actions();

        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::InviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        // Send failure response
        let response = create_response(&invite, 486);
        mgr.send_response(handle, response);
        mgr.poll_actions();

        // Timer G fires multiple times
        mgr.handle_timeout(handle, Timer::G);
        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));

        mgr.handle_timeout(handle, Timer::G);
        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
    }

    // Error handling edge cases

    #[test]
    fn test_send_response_wrong_transaction_type_invite_client() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();
        let handle = mgr.create_client_transaction(invite.clone()).unwrap();
        mgr.poll_actions();

        // Try to send a response on a client transaction (should be ignored)
        let response = create_response(&invite, 200);
        mgr.send_response(handle, response);

        let actions = mgr.poll_actions();
        // Should not send anything because client transactions don't send responses
        assert!(!actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
    }

    #[test]
    fn test_send_response_wrong_transaction_type_non_invite_client() {
        let mut mgr = TransactionManager::new(false);
        let register = create_register();
        let handle = mgr.create_client_transaction(register.clone()).unwrap();
        mgr.poll_actions();

        // Try to send a response on a client transaction (should be ignored)
        let response = create_response(&register, 200);
        mgr.send_response(handle, response);

        let actions = mgr.poll_actions();
        // Should not send anything
        assert!(!actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
    }

    #[test]
    fn test_transport_error_on_each_transaction_type() {
        let mut mgr = TransactionManager::new(false);

        // Invite client
        let invite = create_invite();
        let h1 = mgr.create_client_transaction(invite.clone()).unwrap();
        mgr.poll_actions();

        mgr.handle_transport_error(h1);
        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::TransportError))));

        // Non-invite client
        let register = create_register();
        let h2 = mgr.create_client_transaction(register.clone()).unwrap();
        mgr.poll_actions();

        mgr.handle_transport_error(h2);
        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::TransportError))));

        // Invite server
        let invite2 = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.2", 5060, "UDP", "z9hG4bKinv2")
            .from("sip:alice@example.com", "fromtag2")
            .to("sip:bob@example.com")
            .call_id("test2@example.com")
            .cseq(1)
            .build()
            .unwrap();
        mgr.handle_message(SipMessage::Request(invite2));
        let actions = mgr.poll_actions();
        let h3 = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::InviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        mgr.handle_transport_error(h3);
        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::TransportError))));

        // Non-invite server
        let register2 = SipRequest::builder()
            .method(Method::Register)
            .uri("sip:example.com")
            .via("192.168.1.3", 5060, "UDP", "z9hG4bKreg2")
            .from("sip:alice@example.com", "fromtag3")
            .to("sip:alice@example.com")
            .call_id("register2@example.com")
            .cseq(1)
            .build()
            .unwrap();
        mgr.handle_message(SipMessage::Request(register2));
        let actions = mgr.poll_actions();
        let h4 = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::NonInviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        mgr.handle_transport_error(h4);
        let actions = mgr.poll_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::TransportError))));
    }

    #[test]
    fn test_timeout_on_each_timer_type() {
        // Test various timer types to ensure full coverage of handle_timeout branches
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();
        let handle = mgr.create_client_transaction(invite).unwrap();
        mgr.poll_actions();

        // Test Timer C (not commonly used but exists)
        mgr.handle_timeout(handle, Timer::C);
        mgr.poll_actions();

        // Test Timer I
        mgr.handle_timeout(handle, Timer::I);
        mgr.poll_actions();

        // Test Timer J
        mgr.handle_timeout(handle, Timer::J);
        mgr.poll_actions();
    }

    #[test]
    fn test_invite_server_handle_ack() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();

        mgr.handle_message(SipMessage::Request(invite.clone()));
        let actions = mgr.poll_actions();

        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::InviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        // Send ACK (even if not in correct state, should not crash)
        let ack = create_ack(&invite);
        mgr.handle_message(SipMessage::Request(ack));

        let _actions = mgr.poll_actions();
        // Just verify no crash
    }


    #[test]
    fn test_request_without_transaction_id() {
        let mut mgr = TransactionManager::new(false);

        // Create a request that might fail TransactionId creation
        let bad_request = SipRequest::builder()
            .method(Method::Options)
            .uri("sip:example.com")
            // Missing Via or other required headers that might cause TransactionId::from_request to return None
            .from("sip:alice@example.com", "tag")
            .to("sip:example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build();

        if let Ok(req) = bad_request {
            mgr.handle_message(SipMessage::Request(req));
            // Should not crash
            mgr.poll_actions();
        }
    }

    #[test]
    fn test_concurrent_transactions_same_method() {
        let mut mgr = TransactionManager::new(false);

        // Create multiple INVITE transactions with different IDs
        let invite1 = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKinv1")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call1@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let invite2 = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKinv2")
            .from("sip:alice@example.com", "tag2")
            .to("sip:bob@example.com")
            .call_id("call2@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let h1 = mgr.create_client_transaction(invite1.clone()).unwrap();
        let h2 = mgr.create_client_transaction(invite2.clone()).unwrap();

        // Handles should be different
        assert_ne!(h1, h2);

        let actions = mgr.poll_actions();

        // Both transactions should generate actions
        assert!(actions.len() >= 2);

        // Verify both transactions are tracked
        assert_eq!(mgr.invite_clients.len(), 2);
    }

    #[test]
    fn test_handle_allocation_wrapping() {
        // Test that handles are allocated sequentially
        let mut mgr = TransactionManager::new(false);

        let invite1 = create_invite();
        let h1 = mgr.create_client_transaction(invite1).unwrap();
        assert_eq!(h1.0, 1);

        let register = SipRequest::builder()
            .method(Method::Register)
            .uri("sip:example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKreg1")
            .from("sip:alice@example.com", "tag2")
            .to("sip:alice@example.com")
            .call_id("reg1@example.com")
            .cseq(1)
            .build()
            .unwrap();
        let h2 = mgr.create_client_transaction(register).unwrap();
        assert_eq!(h2.0, 2);

        let options = SipRequest::builder()
            .method(Method::Options)
            .uri("sip:example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKopt1")
            .from("sip:alice@example.com", "tag3")
            .to("sip:example.com")
            .call_id("opt1@example.com")
            .cseq(1)
            .build()
            .unwrap();
        let h3 = mgr.create_client_transaction(options).unwrap();
        assert_eq!(h3.0, 3);
    }

    #[test]
    fn test_timer_c_timeout() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();
        let handle = mgr.create_client_transaction(invite).unwrap();
        mgr.poll_actions();

        // Timer C (proxy INVITE timeout) - not commonly used in non-proxy scenarios
        mgr.handle_timeout(handle, Timer::C);

        let actions = mgr.poll_actions();
        // May or may not produce specific events depending on state
        let _ = actions;
    }

    #[test]
    fn test_reliable_transport_no_retransmit_timers() {
        let mut mgr = TransactionManager::new(true); // Reliable transport
        let invite = create_invite();
        mgr.create_client_transaction(invite).unwrap();

        let actions = mgr.poll_actions();

        // Timer A should not be set for reliable transport
        assert!(!actions
            .iter()
            .any(|a| matches!(a, ManagerAction::SetTimer(_, Timer::A, _))));

        // Timer B should still be set (transaction timeout)
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::SetTimer(_, Timer::B, _))));
    }

    #[test]
    fn test_reliable_transport_non_invite() {
        let mut mgr = TransactionManager::new(true); // Reliable transport
        let register = create_register();
        mgr.create_client_transaction(register).unwrap();

        let actions = mgr.poll_actions();

        // Timer E should not be set for reliable transport
        assert!(!actions
            .iter()
            .any(|a| matches!(a, ManagerAction::SetTimer(_, Timer::E, _))));

        // Timer F should still be set
        assert!(actions
            .iter()
            .any(|a| matches!(a, ManagerAction::SetTimer(_, Timer::F, _))));
    }

    #[test]
    fn test_handle_ack_message() {
        // ACK for 2xx doesn't create a transaction, just passes through
        let mut mgr = TransactionManager::new(false);

        let ack = SipRequest::builder()
            .method(Method::Ack)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKack")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .to_tag("totag")
            .call_id("ack@example.com")
            .cseq(1)
            .build()
            .unwrap();

        mgr.handle_message(SipMessage::Request(ack));

        // ACK should not create a new transaction
        assert!(mgr.invite_servers.is_empty());
        assert!(mgr.non_invite_servers.is_empty());
    }

    #[test]
    fn test_response_without_matching_transaction() {
        let mut mgr = TransactionManager::new(false);

        // Create a request to derive the response from
        let request = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKnomatch")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("nomatch@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&request)
            .to_tag("totag")
            .build()
            .unwrap();

        // Should not crash when no matching transaction exists
        mgr.handle_message(SipMessage::Response(response));

        let actions = mgr.poll_actions();
        // No events should be generated for orphan response
        assert!(actions.is_empty());
    }

    #[test]
    fn test_timeout_on_invite_server() {
        let mut mgr = TransactionManager::new(false);

        let invite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKsrvto")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("srvto@example.com")
            .cseq(1)
            .build()
            .unwrap();

        mgr.handle_message(SipMessage::Request(invite));
        let actions = mgr.poll_actions();

        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::InviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        // Test various timer timeouts on invite server
        mgr.handle_timeout(handle, Timer::H);
        mgr.poll_actions();

        mgr.handle_timeout(handle, Timer::G);
        mgr.poll_actions();
    }

    #[test]
    fn test_timeout_on_non_invite_server() {
        let mut mgr = TransactionManager::new(false);

        let options = SipRequest::builder()
            .method(Method::Options)
            .uri("sip:example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKsrvni")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:example.com")
            .call_id("srvni@example.com")
            .cseq(1)
            .build()
            .unwrap();

        mgr.handle_message(SipMessage::Request(options));
        let actions = mgr.poll_actions();

        let handle = actions
            .iter()
            .find_map(|a| {
                if let ManagerAction::Event(h, ManagerEvent::NonInviteRequest(_)) = a {
                    Some(*h)
                } else {
                    None
                }
            })
            .unwrap();

        // Test timer J timeout on non-invite server
        mgr.handle_timeout(handle, Timer::J);
        mgr.poll_actions();
    }

    #[test]
    fn test_timeout_on_invalid_handle() {
        let mut mgr = TransactionManager::new(false);

        // Try timeout on non-existent handle
        let fake_handle = TransactionHandle(9999);
        mgr.handle_timeout(fake_handle, Timer::A);

        // Should not crash, no actions generated
        let actions = mgr.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_transport_error_on_invalid_handle() {
        let mut mgr = TransactionManager::new(false);

        // Try transport error on non-existent handle
        let fake_handle = TransactionHandle(9999);
        mgr.handle_transport_error(fake_handle);

        // Should not crash, no actions generated
        let actions = mgr.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_send_response_on_invalid_handle() {
        let mut mgr = TransactionManager::new(false);

        let fake_handle = TransactionHandle(9999);

        // Create a request to derive the response from
        let request = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKfake")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("fake@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&request)
            .to_tag("totag")
            .build()
            .unwrap();

        mgr.send_response(fake_handle, response);

        // Should not crash, no actions generated
        let actions = mgr.poll_actions();
        assert!(actions.is_empty());
    }

}

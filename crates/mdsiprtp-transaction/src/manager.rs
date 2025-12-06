//! Transaction manager for coordinating multiple transactions.
//!
//! The manager tracks active client and server transactions, routes incoming
//! messages to the appropriate transaction, and handles transaction timeouts.

use std::collections::HashMap;
use std::time::Duration;
use mdsiprtp_sip::{SipMessage, SipRequest, SipResponse, Method};
use crate::timer::Timer;
use crate::client::invite::{TransactionId, InviteClientTransaction};
use crate::client::non_invite::NonInviteClientTransaction;
use crate::server::invite::InviteServerTransaction;
use crate::server::non_invite::NonInviteServerTransaction;

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
            self.handle_to_type.insert(handle, TransactionType::InviteClient);
        } else {
            let mut tx = NonInviteClientTransaction::new(request, self.reliable)?;
            let id = tx.id().clone();
            Self::collect_non_invite_client_actions(handle, &mut tx, &mut self.actions);
            self.non_invite_clients.insert(handle, tx);
            self.id_to_handle.insert(id, handle);
            self.handle_to_type.insert(handle, TransactionType::NonInviteClient);
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
                self.handle_to_type.insert(handle, TransactionType::InviteServer);
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
            self.handle_to_type.insert(handle, TransactionType::NonInviteServer);
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

    #[test]
    fn test_create_invite_client() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();
        let handle = mgr.create_client_transaction(invite).unwrap();

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::SetTimer(_, Timer::A, _))));
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::SetTimer(_, Timer::B, _))));
        assert!(handle.0 > 0);
    }

    #[test]
    fn test_create_non_invite_client() {
        let mut mgr = TransactionManager::new(false);
        let register = create_register();
        let handle = mgr.create_client_transaction(register).unwrap();

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Send(_))));
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::SetTimer(_, Timer::E, _))));
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::SetTimer(_, Timer::F, _))));
        assert!(handle.0 > 0);
    }

    #[test]
    fn test_handle_incoming_invite() {
        let mut mgr = TransactionManager::new(false);
        let invite = create_invite();

        mgr.handle_message(SipMessage::Request(invite));

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::InviteRequest(_)))));
    }

    #[test]
    fn test_handle_incoming_register() {
        let mut mgr = TransactionManager::new(false);
        let register = create_register();

        mgr.handle_message(SipMessage::Request(register));

        let actions = mgr.poll_actions();
        assert!(actions.iter().any(|a| matches!(a, ManagerAction::Event(_, ManagerEvent::NonInviteRequest(_)))));
    }
}

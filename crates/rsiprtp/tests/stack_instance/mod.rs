//! Stack instance for B2B testing.
//!
//! Wraps the production SIP/RTP stack with an I/O driver for testing.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use rsiprtp::sdp::negotiation::Codec;
use rsiprtp::sdp::parser::SessionDescription;
use rsiprtp::session::{CallConfig, CallId, CallManager, CallState, Dialog, ManagerConfig};
use rsiprtp::sip::{Method, SipMessage, SipRequest, SipResponse};
use rsiprtp::transaction::{
    ManagerAction, ManagerEvent, Timer, TransactionHandle, TransactionManager,
};

/// Configuration for a stack instance.
#[derive(Debug, Clone)]
pub struct StackConfig {
    /// User name for SIP URI.
    pub user: String,
    /// SIP port (0 = auto-assign).
    pub sip_port: u16,
    /// RTP port (0 = auto-assign).
    pub rtp_port: u16,
}

impl StackConfig {
    /// Create a new configuration.
    pub fn new(user: &str, sip_port: u16, rtp_port: u16) -> Self {
        Self {
            user: user.to_string(),
            sip_port,
            rtp_port,
        }
    }
}

/// Events emitted by the stack for test assertions.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum StackEvent {
    /// Incoming call received.
    IncomingCall { call_id: CallId },
    /// Call is ringing.
    CallRinging { call_id: CallId },
    /// Call established.
    CallEstablished { call_id: CallId },
    /// Call ended.
    CallEnded { call_id: CallId },
    /// Call rejected by remote.
    CallRejected { call_id: CallId, code: u16 },
    /// RTP packet received.
    RtpReceived { call_id: CallId },
}

/// Timer entry for tracking pending timers.
#[derive(Debug)]
struct TimerEntry {
    handle: TransactionHandle,
    timer: Timer,
}

/// Pending incoming call waiting to be answered.
#[derive(Debug)]
struct PendingIncoming {
    #[allow(dead_code)]
    call_id: CallId,
    request: SipRequest,
    server_handle: TransactionHandle,
    source: SocketAddr,
}

/// A complete SIP/RTP stack instance for testing.
pub struct StackInstance {
    // Configuration
    config: StackConfig,
    local_sip_addr: SocketAddr,
    local_rtp_addr: SocketAddr,

    // Transport
    sip_socket: Arc<UdpSocket>,
    #[allow(dead_code)]
    rtp_socket: Arc<UdpSocket>,

    // Production components
    transaction_manager: TransactionManager,
    call_manager: CallManager,

    // Timer management
    pending_timers: BTreeMap<Instant, TimerEntry>,

    // Call tracking
    outbound_calls: HashMap<CallId, TransactionHandle>,
    pending_incoming: HashMap<CallId, PendingIncoming>,
    established_calls: HashMap<CallId, (Dialog, SocketAddr)>,

    // Track server transaction handles by call-id
    server_handles: HashMap<String, TransactionHandle>,

    // Events for test assertions
    events: Vec<StackEvent>,
}

impl StackInstance {
    /// Create a new stack instance.
    pub async fn new(config: StackConfig) -> std::io::Result<Self> {
        // Bind SIP socket
        let sip_addr: SocketAddr = format!("127.0.0.1:{}", config.sip_port).parse().unwrap();
        let sip_socket = UdpSocket::bind(sip_addr).await?;
        let local_sip_addr = sip_socket.local_addr()?;

        // Bind RTP socket
        let rtp_addr: SocketAddr = format!("127.0.0.1:{}", config.rtp_port).parse().unwrap();
        let rtp_socket = UdpSocket::bind(rtp_addr).await?;
        let local_rtp_addr = rtp_socket.local_addr()?;
        let rtp_port = local_rtp_addr.port();
        let rtp_port_end = rtp_port.saturating_add(100);

        // Create call manager config
        let manager_config = ManagerConfig {
            local_sip_addr: local_sip_addr.to_string(),
            local_rtp_addr: local_rtp_addr.ip().to_string(),
            rtp_port_range: (rtp_port, rtp_port_end),
            call_config: CallConfig {
                local_uri: format!("sip:{}@{}", config.user, local_sip_addr),
                local_name: Some(config.user.clone()),
                codecs: vec![Codec::pcmu(), Codec::pcma()],
                rtp_port_start: rtp_port,
                rtp_port_end,
                ..CallConfig::default()
            },
        };

        Ok(Self {
            config,
            local_sip_addr,
            local_rtp_addr,
            sip_socket: Arc::new(sip_socket),
            rtp_socket: Arc::new(rtp_socket),
            transaction_manager: TransactionManager::new(false), // UDP = unreliable
            call_manager: CallManager::new(manager_config),
            pending_timers: BTreeMap::new(),
            outbound_calls: HashMap::new(),
            pending_incoming: HashMap::new(),
            established_calls: HashMap::new(),
            server_handles: HashMap::new(),
            events: Vec::new(),
        })
    }

    /// Get the SIP address.
    pub fn sip_addr(&self) -> SocketAddr {
        self.local_sip_addr
    }

    /// Get the RTP address.
    #[allow(dead_code)]
    pub fn rtp_addr(&self) -> SocketAddr {
        self.local_rtp_addr
    }

    /// Make an outbound call.
    pub fn make_call(&mut self, target_uri: &str) -> CallId {
        let call_id = self.call_manager.create_call(target_uri.to_string());

        // Build INVITE request
        let invite = self.build_invite(target_uri, &call_id);

        // Create client transaction
        if let Some(handle) = self.transaction_manager.create_client_transaction(invite) {
            self.outbound_calls.insert(call_id.clone(), handle);
        }

        // Process actions (sends INVITE)
        self.process_transaction_actions();

        call_id
    }

    /// Answer a pending incoming call.
    pub fn answer_call(&mut self, call_id: &CallId) {
        if let Some(pending) = self.pending_incoming.remove(call_id) {
            // Parse SDP from INVITE
            let sdp_offer = self.parse_sdp_from_request(&pending.request);
            let source = pending.source; // Store source before moving pending

            if let Some(offer) = sdp_offer {
                // Create dialog
                let dialog = self.create_dialog_from_invite(&pending.request, true);

                // Create call in CallManager and get SDP answer
                if let Some((_call_id, answer_sdp, _port)) = self
                    .call_manager
                    .handle_incoming_invite(dialog.clone(), &offer)
                {
                    // Build and send 200 OK
                    let response = self.build_200_ok(&pending.request, &answer_sdp);

                    // Send through transaction - use original source address!
                    self.transaction_manager
                        .send_response(pending.server_handle, response);
                    self.process_transaction_actions_with_source(source);

                    // Store as established
                    self.established_calls
                        .insert(call_id.clone(), (dialog, source));

                    self.events.push(StackEvent::CallEstablished {
                        call_id: call_id.clone(),
                    });
                }
            }
        }
    }

    /// Reject a pending incoming call.
    pub fn reject_call(&mut self, call_id: &CallId, code: u16) {
        if let Some(pending) = self.pending_incoming.remove(call_id) {
            let reason = match code {
                486 => "Busy Here",
                603 => "Decline",
                _ => "Decline",
            };

            let response = self.build_error_response(&pending.request, code, reason);
            self.transaction_manager
                .send_response(pending.server_handle, response);
            self.process_transaction_actions_with_source(pending.source);
        }
    }

    /// Hang up an established call.
    pub fn hangup(&mut self, call_id: &CallId) {
        if let Some((dialog, remote_addr)) = self.established_calls.remove(call_id) {
            // Build BYE request
            let bye = self.build_bye(&dialog, remote_addr);

            // Create client transaction for BYE
            self.transaction_manager.create_client_transaction(bye);
            self.process_transaction_actions();

            self.events.push(StackEvent::CallEnded {
                call_id: call_id.clone(),
            });
        }
    }

    /// Get pending incoming calls.
    pub fn pending_incoming_calls(&self) -> Vec<CallId> {
        self.pending_incoming.keys().cloned().collect()
    }

    /// Check if a call is established.
    pub fn is_call_established(&self, call_id: &CallId) -> bool {
        self.established_calls.contains_key(call_id)
            || self
                .call_manager
                .get_call(call_id)
                .map(|c| c.state() == CallState::Established)
                .unwrap_or(false)
    }

    /// Process one iteration of the event loop.
    pub async fn step(&mut self) -> Option<StackEvent> {
        // Check for incoming SIP messages (non-blocking)
        let mut buf = vec![0u8; 65535];
        if let Ok(Ok((len, source))) = tokio::time::timeout(
            Duration::from_millis(1),
            self.sip_socket.recv_from(&mut buf),
        )
        .await
        {
            buf.truncate(len);
            self.handle_incoming_sip(&buf, source);
        }

        // Check for expired timers
        self.process_expired_timers();

        // Process any pending transaction actions
        self.process_transaction_actions();

        // Cleanup terminated transactions
        self.transaction_manager.cleanup_terminated();

        // Return next event if any
        if !self.events.is_empty() {
            Some(self.events.remove(0))
        } else {
            None
        }
    }

    /// Drain all pending events.
    #[allow(dead_code)]
    pub fn drain_events(&mut self) -> Vec<StackEvent> {
        std::mem::take(&mut self.events)
    }

    // Private helper methods

    fn handle_incoming_sip(&mut self, data: &[u8], source: SocketAddr) {
        // Parse SIP message
        if let Ok(message) = SipMessage::parse(data) {
            match message {
                SipMessage::Request(request) => {
                    self.handle_incoming_request(request, source);
                }
                SipMessage::Response(response) => {
                    self.handle_incoming_response(response, source);
                }
            }
        }
    }

    fn handle_incoming_request(&mut self, request: SipRequest, source: SocketAddr) {
        // Route through transaction manager
        self.transaction_manager
            .handle_message(SipMessage::Request(request.clone()));

        // Process any actions generated
        let actions = self.transaction_manager.poll_actions();
        for action in actions {
            match action {
                ManagerAction::Send(data) => {
                    let _ = self.send_sip(&data, source);
                }
                ManagerAction::SetTimer(handle, timer, duration) => {
                    let deadline = Instant::now() + duration;
                    self.pending_timers
                        .insert(deadline, TimerEntry { handle, timer });
                }
                ManagerAction::CancelTimer(handle, timer) => {
                    self.pending_timers
                        .retain(|_, e| !(e.handle == handle && e.timer == timer));
                }
                ManagerAction::Event(handle, event) => {
                    self.handle_transaction_event(handle, event, Some(source));
                }
            }
        }
    }

    fn handle_incoming_response(&mut self, response: SipResponse, source: SocketAddr) {
        // Route through transaction manager
        self.transaction_manager
            .handle_message(SipMessage::Response(response));

        // Process actions with source
        let actions = self.transaction_manager.poll_actions();
        for action in actions {
            match action {
                ManagerAction::Send(data) => {
                    let dest = self.extract_destination(&data).unwrap_or(source);
                    let _ = self.send_sip(&data, dest);
                }
                ManagerAction::SetTimer(handle, timer, duration) => {
                    let deadline = std::time::Instant::now() + duration;
                    self.pending_timers
                        .insert(deadline, TimerEntry { handle, timer });
                }
                ManagerAction::CancelTimer(handle, timer) => {
                    self.pending_timers
                        .retain(|_, e| !(e.handle == handle && e.timer == timer));
                }
                ManagerAction::Event(handle, event) => {
                    self.handle_transaction_event(handle, event, Some(source));
                }
            }
        }
    }

    fn handle_transaction_event(
        &mut self,
        handle: TransactionHandle,
        event: ManagerEvent,
        source: Option<SocketAddr>,
    ) {
        match event {
            ManagerEvent::InviteRequest(request) => {
                // New incoming INVITE
                let call_id_str = request.call_id().unwrap_or_default();
                let call_id = CallId(call_id_str.clone());

                // Store the server handle for this call
                self.server_handles.insert(call_id_str, handle);

                self.pending_incoming.insert(
                    call_id.clone(),
                    PendingIncoming {
                        call_id: call_id.clone(),
                        request,
                        server_handle: handle,
                        source: source.unwrap_or_else(|| "127.0.0.1:5060".parse().unwrap()),
                    },
                );

                self.events.push(StackEvent::IncomingCall { call_id });
            }
            ManagerEvent::Provisional(_response) => {
                // Remote is ringing — surface the first known outbound call.
                if let Some(call_id) = self.outbound_calls.keys().next() {
                    self.events.push(StackEvent::CallRinging {
                        call_id: call_id.clone(),
                    });
                }
            }
            ManagerEvent::InviteSuccess(response) => {
                // Call answered - need to send ACK and establish call
                if let Some(call_id) = self.find_call_for_response(&response) {
                    // Create dialog from response
                    let dialog = self.create_dialog_from_response(&response);

                    // Parse SDP answer
                    if let Some(answer_sdp) = self.parse_sdp_from_response(&response) {
                        // Update call manager
                        self.call_manager.handle_invite_success(
                            &call_id,
                            dialog.clone(),
                            &answer_sdp,
                            Some(&response),
                            std::time::Instant::now(),
                        );

                        // Build and send ACK
                        let ack = self.build_ack(&response, &dialog);
                        if let Some(source) = source {
                            let _ = self.send_sip(&ack.to_bytes(), source);
                        }

                        // Store established call
                        self.established_calls.insert(
                            call_id.clone(),
                            (
                                dialog,
                                source.unwrap_or_else(|| "127.0.0.1:5060".parse().unwrap()),
                            ),
                        );

                        self.events.push(StackEvent::CallEstablished { call_id });
                    }
                }
            }
            ManagerEvent::InviteFailure(response) => {
                // Call rejected
                if let Some(call_id) = self.find_call_for_response(&response) {
                    self.call_manager
                        .handle_invite_failure(&call_id, response.status_code());
                    self.outbound_calls.remove(&call_id);

                    self.events.push(StackEvent::CallRejected {
                        call_id,
                        code: response.status_code(),
                    });
                }
            }
            ManagerEvent::NonInviteRequest(request) => {
                // Handle BYE
                if request.method() == Method::Bye {
                    // Find the call and end it
                    for (call_id, _) in self.established_calls.drain() {
                        self.events.push(StackEvent::CallEnded { call_id });
                    }
                }
            }
            ManagerEvent::NonInviteFinalResponse(_) => {
                // BYE response or similar - no action needed
            }
            _ => {}
        }
    }

    fn process_transaction_actions(&mut self) {
        self.process_transaction_actions_with_source("127.0.0.1:5060".parse().unwrap());
    }

    fn process_transaction_actions_with_source(&mut self, default_dest: SocketAddr) {
        let actions = self.transaction_manager.poll_actions();
        for action in actions {
            match action {
                ManagerAction::Send(data) => {
                    // Determine destination from Via header or use default
                    let dest = self.extract_destination(&data).unwrap_or(default_dest);
                    let _ = self.send_sip(&data, dest);
                }
                ManagerAction::SetTimer(handle, timer, duration) => {
                    let deadline = Instant::now() + duration;
                    self.pending_timers
                        .insert(deadline, TimerEntry { handle, timer });
                }
                ManagerAction::CancelTimer(handle, timer) => {
                    self.pending_timers
                        .retain(|_, e| !(e.handle == handle && e.timer == timer));
                }
                ManagerAction::Event(handle, event) => {
                    self.handle_transaction_event(handle, event, Some(default_dest));
                }
            }
        }
    }

    fn process_expired_timers(&mut self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .pending_timers
            .range(..=now)
            .map(|(k, v)| (*k, v.handle, v.timer))
            .collect();

        for (deadline, handle, timer) in expired {
            self.pending_timers.remove(&deadline);
            self.transaction_manager.handle_timeout(handle, timer);
        }

        // Process actions from timer handling
        if !self.transaction_manager.poll_actions().is_empty() {
            self.process_transaction_actions();
        }
    }

    fn send_sip(&self, data: &[u8], dest: SocketAddr) -> std::io::Result<usize> {
        let socket = self.sip_socket.clone();
        let data = data.to_vec();
        let len = data.len();

        tokio::spawn(async move {
            let _ = socket.send_to(&data, dest).await;
        });
        Ok(len)
    }

    fn extract_destination(&self, data: &[u8]) -> Option<SocketAddr> {
        let msg_str = String::from_utf8_lossy(data);

        // For responses, extract from Via header's received/rport or sent-by
        // For requests, extract from Request-URI
        if msg_str.starts_with("SIP/2.0") {
            // Response - look at Via header
            for line in msg_str.lines() {
                if line.to_lowercase().starts_with("via:") {
                    // Parse host:port from Via
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        // Via: SIP/2.0/UDP host:port;...
                        let host_part = parts[2].split(';').next()?;
                        return host_part.parse().ok();
                    }
                }
            }
        } else {
            // Request - look at Request-URI or Contact
            let first_line = msg_str.lines().next()?;
            // INVITE sip:user@host:port SIP/2.0
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 2 {
                let uri = parts[1];
                // Extract host:port from sip:user@host:port
                let host = uri.strip_prefix("sip:")?.split('@').next_back()?;
                let host = host.split(';').next()?; // Remove parameters
                return host.parse().ok();
            }
        }

        None
    }

    // SIP message builders

    fn build_invite(&mut self, target_uri: &str, call_id: &CallId) -> SipRequest {
        let branch = format!("z9hG4bK{}", uuid::Uuid::new_v4());
        let from_tag = format!("tag-{}", uuid::Uuid::new_v4());

        let sdp = self.build_sdp_offer();
        let sdp_bytes = sdp.to_string().into_bytes();

        SipRequest::builder()
            .method(Method::Invite)
            .uri(target_uri)
            .via(
                &self.local_sip_addr.ip().to_string(),
                self.local_sip_addr.port(),
                "UDP",
                &branch,
            )
            .from(
                &format!("sip:{}@{}", self.config.user, self.local_sip_addr),
                &from_tag,
            )
            .to(target_uri)
            .call_id(&call_id.0)
            .cseq(1)
            .contact(&format!("sip:{}@{}", self.config.user, self.local_sip_addr))
            .body(sdp_bytes, "application/sdp")
            .build()
            .unwrap()
    }

    fn build_200_ok(&self, invite: &SipRequest, answer_sdp: &SessionDescription) -> SipResponse {
        let sdp_bytes = answer_sdp.to_string().into_bytes();
        let to_tag = format!("tag-{}", uuid::Uuid::new_v4());

        // Build the response by constructing it directly as bytes
        // This works around the Via header parsing bug in from_request
        let from_uri = invite.from_uri().map(|u| u.to_string()).unwrap_or_default();
        let from_tag = invite.from_tag().unwrap_or_default();
        let to_uri = invite.to_uri().map(|u| u.to_string()).unwrap_or_default();
        let call_id = invite.call_id().unwrap_or_default();
        let cseq = invite.cseq().unwrap_or(1);

        // Get the Via info from INVITE
        let invite_via = invite
            .via_headers_raw()
            .into_iter()
            .next()
            .unwrap_or_default();
        let via_value = invite_via
            .strip_prefix("Via: ")
            .map(|s| s.to_string())
            .unwrap_or(invite_via);

        // Build SIP response manually
        let response_str = format!(
            "SIP/2.0 200 OK\r\n\
             Via: {}\r\n\
             From: <{}>;tag={}\r\n\
             To: <{}>;tag={}\r\n\
             Call-ID: {}\r\n\
             CSeq: {} INVITE\r\n\
             Contact: <sip:{}@{}>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n",
            via_value,
            from_uri,
            from_tag,
            to_uri,
            to_tag,
            call_id,
            cseq,
            self.config.user,
            self.local_sip_addr,
            sdp_bytes.len()
        );

        // Combine response with SDP body
        let mut response_bytes = response_str.into_bytes();
        response_bytes.extend(sdp_bytes);

        SipMessage::parse(&response_bytes)
            .expect("Failed to parse built 200 OK")
            .as_response()
            .expect("Expected response")
            .clone()
    }

    fn build_error_response(&self, invite: &SipRequest, code: u16, reason: &str) -> SipResponse {
        let to_tag = format!("tag-{}", uuid::Uuid::new_v4());

        // Build the response by constructing it directly as bytes
        // This works around the Via header parsing bug in from_request
        let from_uri = invite.from_uri().map(|u| u.to_string()).unwrap_or_default();
        let from_tag = invite.from_tag().unwrap_or_default();
        let to_uri = invite.to_uri().map(|u| u.to_string()).unwrap_or_default();
        let call_id = invite.call_id().unwrap_or_default();
        let cseq = invite.cseq().unwrap_or(1);

        // Get the Via info from INVITE
        let invite_via = invite
            .via_headers_raw()
            .into_iter()
            .next()
            .unwrap_or_default();
        let via_value = invite_via
            .strip_prefix("Via: ")
            .map(|s| s.to_string())
            .unwrap_or(invite_via);

        // Build SIP error response manually
        let response_str = format!(
            "SIP/2.0 {} {}\r\n\
             Via: {}\r\n\
             From: <{}>;tag={}\r\n\
             To: <{}>;tag={}\r\n\
             Call-ID: {}\r\n\
             CSeq: {} INVITE\r\n\
             Content-Length: 0\r\n\
             \r\n",
            code, reason, via_value, from_uri, from_tag, to_uri, to_tag, call_id, cseq
        );

        SipMessage::parse(response_str.as_bytes())
            .expect("Failed to parse built error response")
            .as_response()
            .expect("Expected response")
            .clone()
    }

    fn build_ack(&self, response: &SipResponse, dialog: &Dialog) -> SipRequest {
        let branch = format!("z9hG4bK{}", uuid::Uuid::new_v4());

        // Get the Request-URI from Contact or use remote URI
        let request_uri = response
            .contact_uri()
            .map(|u| u.to_string())
            .unwrap_or_else(|| dialog.remote_uri().to_string());

        SipRequest::builder()
            .method(Method::Ack)
            .uri(&request_uri)
            .via(
                &self.local_sip_addr.ip().to_string(),
                self.local_sip_addr.port(),
                "UDP",
                &branch,
            )
            .from(dialog.local_uri(), &dialog.id().local_tag)
            .to(dialog.remote_uri())
            .to_tag(&dialog.id().remote_tag)
            .call_id(&dialog.id().call_id)
            .cseq(1) // ACK uses same CSeq as INVITE
            .build()
            .unwrap()
    }

    fn build_bye(&mut self, dialog: &Dialog, remote_addr: SocketAddr) -> SipRequest {
        let branch = format!("z9hG4bK{}", uuid::Uuid::new_v4());

        SipRequest::builder()
            .method(Method::Bye)
            .uri(&format!("sip:user@{}", remote_addr))
            .via(
                &self.local_sip_addr.ip().to_string(),
                self.local_sip_addr.port(),
                "UDP",
                &branch,
            )
            .from(dialog.local_uri(), &dialog.id().local_tag)
            .to(dialog.remote_uri())
            .to_tag(&dialog.id().remote_tag)
            .call_id(&dialog.id().call_id)
            .cseq(2) // BYE gets new CSeq
            .build()
            .unwrap()
    }

    fn build_sdp_offer(&self) -> SessionDescription {
        let sdp_str = format!(
            "v=0\r\n\
             o=- {} 1 IN IP4 {}\r\n\
             s=-\r\n\
             c=IN IP4 {}\r\n\
             t=0 0\r\n\
             m=audio {} RTP/AVP 0 8 101\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\n\
             a=fmtp:101 0-16\r\n\
             a=sendrecv\r\n",
            chrono::Utc::now().timestamp(),
            self.local_rtp_addr.ip(),
            self.local_rtp_addr.ip(),
            self.local_rtp_addr.port()
        );

        SessionDescription::parse(&sdp_str).unwrap()
    }

    fn parse_sdp_from_request(&self, request: &SipRequest) -> Option<SessionDescription> {
        let body = request.body();
        if body.is_empty() {
            return None;
        }
        let body_str = String::from_utf8_lossy(body);
        SessionDescription::parse(&body_str).ok()
    }

    fn parse_sdp_from_response(&self, response: &SipResponse) -> Option<SessionDescription> {
        let body = response.body();
        if body.is_empty() {
            return None;
        }
        let body_str = String::from_utf8_lossy(body);
        SessionDescription::parse(&body_str).ok()
    }

    fn create_dialog_from_invite(&mut self, request: &SipRequest, as_uas: bool) -> Dialog {
        let call_id = request.call_id().unwrap_or_default();
        let from_tag = request.from_tag().unwrap_or_default();
        let to_tag = format!("tag-{}", uuid::Uuid::new_v4());
        let from_uri = request
            .from_uri()
            .map(|u| u.to_string())
            .unwrap_or_default();
        let to_uri = request.to_uri().map(|u| u.to_string()).unwrap_or_default();
        let cseq = request.cseq().unwrap_or(1);

        if as_uas {
            Dialog::new_uas(call_id, from_tag, to_tag, to_uri, from_uri, cseq)
        } else {
            Dialog::new_uac(call_id, from_tag, to_tag, from_uri, to_uri, cseq)
        }
    }

    fn create_dialog_from_response(&mut self, response: &SipResponse) -> Dialog {
        let call_id = response.call_id().unwrap_or_default();
        let from_tag = response.from_tag().unwrap_or_default();
        let to_tag = response.to_tag().unwrap_or_default();
        let cseq = response.cseq().unwrap_or(1);

        // For UAC, our local URI is the From URI, remote URI comes from Contact or To
        // Since SipResponse doesn't expose from_uri/to_uri methods, we use config
        let local_uri = format!("sip:{}@{}", self.config.user, self.local_sip_addr);
        let remote_uri = response
            .contact_uri()
            .map(|u| u.to_string())
            .unwrap_or_else(|| "sip:remote@unknown".to_string());

        Dialog::new_uac(call_id, from_tag, to_tag, local_uri, remote_uri, cseq)
    }

    fn find_call_for_response(&self, response: &SipResponse) -> Option<CallId> {
        let call_id_str = response.call_id().ok()?;
        let call_id = CallId(call_id_str);

        if self.outbound_calls.contains_key(&call_id) {
            Some(call_id)
        } else {
            None
        }
    }
}

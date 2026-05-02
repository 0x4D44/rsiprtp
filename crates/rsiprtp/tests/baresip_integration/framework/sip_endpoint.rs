//! Test endpoint wrapper for rsiprtp SIP stack.
//!
//! Provides a simplified interface for integration testing.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::config::TestConfig;

/// Error type for test endpoint operations.
#[derive(Debug)]
pub enum EndpointError {
    /// IO error.
    Io(std::io::Error),
    /// SIP parsing error.
    ParseError(String),
    /// Timeout waiting for message.
    Timeout,
    /// Call not found.
    CallNotFound,
    /// Operation failed.
    Failed(String),
}

impl std::fmt::Display for EndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndpointError::Io(e) => write!(f, "IO error: {}", e),
            EndpointError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            EndpointError::Timeout => write!(f, "Timeout"),
            EndpointError::CallNotFound => write!(f, "Call not found"),
            EndpointError::Failed(msg) => write!(f, "Failed: {}", msg),
        }
    }
}

impl std::error::Error for EndpointError {}

impl From<std::io::Error> for EndpointError {
    fn from(e: std::io::Error) -> Self {
        EndpointError::Io(e)
    }
}

/// Result type for test endpoint operations.
pub type Result<T> = std::result::Result<T, EndpointError>;

/// Handle to an active call.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallHandle {
    /// SIP Call-ID.
    pub call_id: String,
    /// Local tag.
    pub local_tag: String,
    /// Remote tag (if established).
    pub remote_tag: Option<String>,
}

/// State of a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestCallState {
    /// Initial state.
    Idle,
    /// INVITE sent, waiting for response.
    Inviting,
    /// Ringing (18x received).
    Ringing,
    /// Call established (200 OK received/sent).
    Established,
    /// BYE sent, waiting for response.
    Terminating,
    /// Call ended.
    Terminated,
}

/// An incoming call waiting to be answered.
#[derive(Debug)]
pub struct IncomingCall {
    /// Call handle.
    pub handle: CallHandle,
    /// Remote URI.
    pub remote_uri: String,
    /// SDP offer from remote.
    pub sdp_offer: Option<String>,
    /// Source address.
    pub source: SocketAddr,
    /// Raw INVITE message for response generation.
    pub invite_data: Vec<u8>,
}

/// RTP statistics for a call.
#[derive(Debug, Clone, Default)]
pub struct RtpStats {
    /// Number of RTP packets sent.
    pub packets_sent: u64,
    /// Number of RTP packets received.
    pub packets_received: u64,
    /// Number of bytes sent.
    pub bytes_sent: u64,
    /// Number of bytes received.
    pub bytes_received: u64,
    /// Estimated packet loss percentage.
    pub packet_loss_percent: f64,
}

/// Internal call state tracking.
struct CallInfo {
    handle: CallHandle,
    state: TestCallState,
    remote_addr: SocketAddr,
    local_cseq: u32,
    rtp_stats: RtpStats,
    received_dtmf: Vec<char>,
}

/// Test endpoint for integration testing.
///
/// Wraps the rsiprtp SIP stack with a simplified interface for tests.
pub struct TestEndpoint {
    /// Configuration.
    config: TestConfig,
    /// Local SIP socket.
    sip_socket: Arc<UdpSocket>,
    /// Local RTP socket.
    rtp_socket: Arc<UdpSocket>,
    /// Active calls.
    calls: HashMap<String, CallInfo>,
    /// Local URI.
    local_uri: String,
    /// Local tag counter.
    tag_counter: u32,
    /// CSeq counter.
    cseq_counter: u32,
    /// Received SIP messages (for debugging).
    received_messages: Vec<(SocketAddr, String)>,
}

impl TestEndpoint {
    /// Create a new test endpoint.
    pub async fn new(config: TestConfig) -> Result<Self> {
        let sip_addr: SocketAddr = format!("127.0.0.1:{}", config.local_sip_port)
            .parse()
            .unwrap();
        let rtp_addr: SocketAddr = format!("127.0.0.1:{}", config.local_rtp_port)
            .parse()
            .unwrap();

        let sip_socket = UdpSocket::bind(sip_addr).await?;
        let rtp_socket = UdpSocket::bind(rtp_addr).await?;

        Ok(Self {
            local_uri: config.local_uri("test"),
            config,
            sip_socket: Arc::new(sip_socket),
            rtp_socket: Arc::new(rtp_socket),
            calls: HashMap::new(),
            tag_counter: 0,
            cseq_counter: 0,
            received_messages: Vec::new(),
        })
    }

    /// Generate a unique tag.
    fn generate_tag(&mut self) -> String {
        self.tag_counter += 1;
        format!("tag-{:08x}", self.tag_counter)
    }

    /// Generate a unique Call-ID.
    fn generate_call_id(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Generate a unique branch.
    fn generate_branch(&self) -> String {
        format!("z9hG4bK-{}", uuid::Uuid::new_v4())
    }

    /// Get next CSeq number.
    fn next_cseq(&mut self) -> u32 {
        self.cseq_counter += 1;
        self.cseq_counter
    }

    /// Get the local SIP port.
    pub fn local_sip_port(&self) -> u16 {
        self.config.local_sip_port
    }

    /// Get the local RTP port.
    pub fn local_rtp_port(&self) -> u16 {
        self.config.local_rtp_port
    }

    /// Make an outgoing call.
    pub async fn call(&mut self, target_uri: &str) -> Result<CallHandle> {
        let call_id = self.generate_call_id();
        let local_tag = self.generate_tag();
        let branch = self.generate_branch();
        let cseq = self.next_cseq();

        // Parse target URI to get host:port
        let target_addr = self.uri_to_socket_addr(target_uri)?;

        // Build INVITE request
        let invite = self.build_invite(target_uri, &call_id, &local_tag, &branch, cseq);

        // Send INVITE
        self.sip_socket
            .send_to(invite.as_bytes(), target_addr)
            .await?;

        let handle = CallHandle {
            call_id: call_id.clone(),
            local_tag: local_tag.clone(),
            remote_tag: None,
        };

        let info = CallInfo {
            handle: handle.clone(),
            state: TestCallState::Inviting,
            remote_addr: target_addr,
            local_cseq: cseq,
            rtp_stats: RtpStats::default(),
            received_dtmf: Vec::new(),
        };

        self.calls.insert(call_id, info);

        Ok(handle)
    }

    /// Wait for an incoming call.
    pub async fn wait_for_incoming(&mut self, timeout_duration: Duration) -> Result<IncomingCall> {
        let deadline = tokio::time::Instant::now() + timeout_duration;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(EndpointError::Timeout);
            }

            let mut buf = vec![0u8; 65535];
            match timeout(remaining, self.sip_socket.recv_from(&mut buf)).await {
                Ok(Ok((len, source))) => {
                    buf.truncate(len);
                    let msg = String::from_utf8_lossy(&buf).to_string();
                    self.received_messages.push((source, msg.clone()));

                    // Check if it's an INVITE
                    if msg.starts_with("INVITE ") {
                        return self.parse_incoming_invite(&buf, source);
                    }
                }
                Ok(Err(e)) => return Err(EndpointError::Io(e)),
                Err(_) => return Err(EndpointError::Timeout),
            }
        }
    }

    /// Parse an incoming INVITE request.
    fn parse_incoming_invite(&mut self, data: &[u8], source: SocketAddr) -> Result<IncomingCall> {
        let msg = String::from_utf8_lossy(data);

        // Extract Call-ID
        let call_id = self
            .extract_header(&msg, "Call-ID")
            .or_else(|| self.extract_header(&msg, "i"))
            .ok_or_else(|| EndpointError::ParseError("Missing Call-ID".to_string()))?;

        // Extract From tag
        let from_line = self
            .extract_header(&msg, "From")
            .or_else(|| self.extract_header(&msg, "f"))
            .ok_or_else(|| EndpointError::ParseError("Missing From".to_string()))?;

        let remote_tag = self.extract_tag(&from_line);
        let remote_uri = self.extract_uri(&from_line);

        // Extract SDP if present
        let sdp_offer = if let Some(idx) = msg.find("\r\n\r\n") {
            let body = &msg[idx + 4..];
            if !body.trim().is_empty() {
                Some(body.to_string())
            } else {
                None
            }
        } else {
            None
        };

        let local_tag = self.generate_tag();

        let handle = CallHandle {
            call_id: call_id.clone(),
            local_tag,
            remote_tag,
        };

        Ok(IncomingCall {
            handle,
            remote_uri,
            sdp_offer,
            source,
            invite_data: data.to_vec(),
        })
    }

    /// Accept an incoming call.
    pub async fn accept_call(&mut self, incoming: IncomingCall) -> Result<CallHandle> {
        let handle = incoming.handle.clone();

        // Build 200 OK response
        let response = self.build_200_ok(&incoming);

        // Send 200 OK
        self.sip_socket
            .send_to(response.as_bytes(), incoming.source)
            .await?;

        let info = CallInfo {
            handle: handle.clone(),
            state: TestCallState::Established,
            remote_addr: incoming.source,
            local_cseq: 0,
            rtp_stats: RtpStats::default(),
            received_dtmf: Vec::new(),
        };

        self.calls.insert(handle.call_id.clone(), info);

        Ok(handle)
    }

    /// Reject an incoming call.
    pub async fn reject_call(&mut self, incoming: &IncomingCall, code: u16) -> Result<()> {
        let reason = match code {
            486 => "Busy Here",
            603 => "Decline",
            404 => "Not Found",
            _ => "Decline",
        };

        let response = self.build_error_response(incoming, code, reason);

        self.sip_socket
            .send_to(response.as_bytes(), incoming.source)
            .await?;

        Ok(())
    }

    /// Hang up an active call.
    pub async fn hangup(&mut self, handle: &CallHandle) -> Result<()> {
        // Extract info we need before borrowing mutably
        let (remote_addr, state) = {
            let info = self
                .calls
                .get(&handle.call_id)
                .ok_or(EndpointError::CallNotFound)?;
            (info.remote_addr, info.state)
        };

        if state != TestCallState::Established {
            return Err(EndpointError::Failed("Call not established".to_string()));
        }

        let cseq = self.next_cseq();
        let bye = self.build_bye(handle, remote_addr, cseq);

        self.sip_socket.send_to(bye.as_bytes(), remote_addr).await?;

        // Now update the call info
        if let Some(info) = self.calls.get_mut(&handle.call_id) {
            info.state = TestCallState::Terminating;
            info.local_cseq = cseq;
        }

        Ok(())
    }

    /// Wait for call to be established (200 OK).
    pub async fn wait_for_answer(
        &mut self,
        handle: &CallHandle,
        timeout_duration: Duration,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout_duration;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(EndpointError::Timeout);
            }

            let mut buf = vec![0u8; 65535];
            match timeout(remaining, self.sip_socket.recv_from(&mut buf)).await {
                Ok(Ok((len, source))) => {
                    buf.truncate(len);
                    let msg = String::from_utf8_lossy(&buf).to_string();
                    self.received_messages.push((source, msg.clone()));

                    // Check for response to our INVITE
                    if msg.starts_with("SIP/2.0 ") {
                        let call_id = self
                            .extract_header(&msg, "Call-ID")
                            .or_else(|| self.extract_header(&msg, "i"));

                        if call_id.as_ref() == Some(&handle.call_id) {
                            // Parse status code
                            let status_line = msg.lines().next().unwrap_or("");
                            let parts: Vec<&str> = status_line.split_whitespace().collect();
                            if parts.len() >= 2 {
                                if let Ok(code) = parts[1].parse::<u16>() {
                                    if (200..300).contains(&code) {
                                        // Extract data before mutable borrow
                                        let to_line = self
                                            .extract_header(&msg, "To")
                                            .or_else(|| self.extract_header(&msg, "t"));
                                        let remote_tag =
                                            to_line.as_ref().and_then(|l| self.extract_tag(l));

                                        // Get remote addr first
                                        let remote_addr = self
                                            .calls
                                            .get(&handle.call_id)
                                            .map(|info| info.remote_addr);

                                        // Update state
                                        if let Some(info) = self.calls.get_mut(&handle.call_id) {
                                            info.handle.remote_tag = remote_tag;
                                            info.state = TestCallState::Established;
                                        }

                                        // Send ACK
                                        if let Some(addr) = remote_addr {
                                            let ack = self.build_ack(handle, addr);
                                            self.sip_socket.send_to(ack.as_bytes(), addr).await?;
                                        }
                                        return Ok(());
                                    } else if (180..200).contains(&code) {
                                        // Provisional - update state to Ringing
                                        if let Some(info) = self.calls.get_mut(&handle.call_id) {
                                            info.state = TestCallState::Ringing;
                                        }
                                        // Continue waiting
                                    } else if code >= 300 {
                                        // Error response
                                        if let Some(info) = self.calls.get_mut(&handle.call_id) {
                                            info.state = TestCallState::Terminated;
                                        }
                                        return Err(EndpointError::Failed(format!(
                                            "Call rejected: {}",
                                            code
                                        )));
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(Err(e)) => return Err(EndpointError::Io(e)),
                Err(_) => return Err(EndpointError::Timeout),
            }
        }
    }

    /// Wait for BYE from remote.
    pub async fn wait_for_hangup(
        &mut self,
        handle: &CallHandle,
        timeout_duration: Duration,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout_duration;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(EndpointError::Timeout);
            }

            let mut buf = vec![0u8; 65535];
            match timeout(remaining, self.sip_socket.recv_from(&mut buf)).await {
                Ok(Ok((len, source))) => {
                    buf.truncate(len);
                    let msg = String::from_utf8_lossy(&buf).to_string();
                    self.received_messages.push((source, msg.clone()));

                    // Check for BYE
                    if msg.starts_with("BYE ") {
                        let call_id = self
                            .extract_header(&msg, "Call-ID")
                            .or_else(|| self.extract_header(&msg, "i"));

                        if call_id.as_ref() == Some(&handle.call_id) {
                            // Send 200 OK to BYE
                            let response = self.build_response_to_request(&msg, 200, "OK");
                            self.sip_socket.send_to(response.as_bytes(), source).await?;

                            if let Some(info) = self.calls.get_mut(&handle.call_id) {
                                info.state = TestCallState::Terminated;
                            }
                            return Ok(());
                        }
                    }
                }
                Ok(Err(e)) => return Err(EndpointError::Io(e)),
                Err(_) => return Err(EndpointError::Timeout),
            }
        }
    }

    /// Get call state.
    pub fn call_state(&self, handle: &CallHandle) -> Option<TestCallState> {
        self.calls.get(&handle.call_id).map(|info| info.state)
    }

    /// Get RTP statistics for a call.
    pub fn rtp_stats(&self, handle: &CallHandle) -> RtpStats {
        self.calls
            .get(&handle.call_id)
            .map(|info| info.rtp_stats.clone())
            .unwrap_or_default()
    }

    /// Get received DTMF digits for a call.
    pub fn received_dtmf(&self, handle: &CallHandle) -> Vec<char> {
        self.calls
            .get(&handle.call_id)
            .map(|info| info.received_dtmf.clone())
            .unwrap_or_default()
    }

    /// Send RTP packet for testing.
    pub async fn send_rtp(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        self.rtp_socket.send_to(data, dest).await?;
        Ok(())
    }

    /// Receive RTP packet.
    pub async fn recv_rtp(&self, timeout_duration: Duration) -> Result<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; 2048];
        match timeout(timeout_duration, self.rtp_socket.recv_from(&mut buf)).await {
            Ok(Ok((len, source))) => {
                buf.truncate(len);
                Ok((buf, source))
            }
            Ok(Err(e)) => Err(EndpointError::Io(e)),
            Err(_) => Err(EndpointError::Timeout),
        }
    }

    /// Get received SIP messages (for debugging).
    pub fn received_messages(&self) -> &[(SocketAddr, String)] {
        &self.received_messages
    }

    /// Send raw SIP message to destination.
    pub async fn send_raw(&self, message: &str, dest: SocketAddr) -> Result<()> {
        self.sip_socket.send_to(message.as_bytes(), dest).await?;
        Ok(())
    }

    /// Receive a raw SIP datagram on the SIP socket.
    ///
    /// Used by tests that exchange messages outside the canned INVITE/BYE
    /// flows (e.g. REGISTER, OPTIONS).
    pub async fn recv_raw(&self, timeout_duration: Duration) -> Result<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; 65535];
        match timeout(timeout_duration, self.sip_socket.recv_from(&mut buf)).await {
            Ok(Ok((len, source))) => {
                buf.truncate(len);
                Ok((buf, source))
            }
            Ok(Err(e)) => Err(EndpointError::Io(e)),
            Err(_) => Err(EndpointError::Timeout),
        }
    }

    // Helper methods for parsing SIP messages

    fn extract_header(&self, msg: &str, name: &str) -> Option<String> {
        let name_lower = name.to_lowercase();
        for line in msg.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with(&format!("{}:", name_lower))
                || line_lower.starts_with(&format!("{} :", name_lower))
            {
                let colon_idx = line.find(':')?;
                return Some(line[colon_idx + 1..].trim().to_string());
            }
        }
        None
    }

    fn extract_tag(&self, header_value: &str) -> Option<String> {
        for part in header_value.split(';') {
            let part = part.trim();
            if let Some(tag) = part.strip_prefix("tag=") {
                return Some(tag.to_string());
            }
        }
        None
    }

    fn extract_uri(&self, header_value: &str) -> String {
        if let Some(start) = header_value.find('<') {
            if let Some(end) = header_value.find('>') {
                return header_value[start + 1..end].to_string();
            }
        }
        header_value
            .split(';')
            .next()
            .unwrap_or(header_value)
            .to_string()
    }

    fn uri_to_socket_addr(&self, uri: &str) -> Result<SocketAddr> {
        // Simple URI parsing: sip:user@host:port
        let uri = uri.strip_prefix("sip:").unwrap_or(uri);
        let uri = uri.strip_prefix("sips:").unwrap_or(uri);

        let host_part = if let Some(at_idx) = uri.find('@') {
            &uri[at_idx + 1..]
        } else {
            uri
        };

        // Remove any parameters
        let host_part = host_part.split(';').next().unwrap_or(host_part);

        // Parse host:port
        let addr: SocketAddr = if host_part.contains(':') {
            host_part
                .parse()
                .map_err(|_| EndpointError::ParseError(format!("Invalid address: {}", host_part)))?
        } else {
            format!("{}:5060", host_part)
                .parse()
                .map_err(|_| EndpointError::ParseError(format!("Invalid address: {}", host_part)))?
        };

        Ok(addr)
    }

    // Message building helpers

    fn build_invite(
        &self,
        target: &str,
        call_id: &str,
        local_tag: &str,
        branch: &str,
        cseq: u32,
    ) -> String {
        let sdp = self.build_sdp_offer();
        let content_length = sdp.len();

        format!(
            "INVITE {} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:{};branch={};rport\r\n\
             Max-Forwards: 70\r\n\
             From: <{}>;tag={}\r\n\
             To: <{}>\r\n\
             Call-ID: {}\r\n\
             CSeq: {} INVITE\r\n\
             Contact: <{}>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            target,
            self.config.local_sip_port,
            branch,
            self.local_uri,
            local_tag,
            target,
            call_id,
            cseq,
            self.local_uri,
            content_length,
            sdp
        )
    }

    fn build_sdp_offer(&self) -> String {
        format!(
            "v=0\r\n\
             o=- {} 1 IN IP4 127.0.0.1\r\n\
             s=-\r\n\
             c=IN IP4 127.0.0.1\r\n\
             t=0 0\r\n\
             m=audio {} RTP/AVP 0 8 101\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\n\
             a=fmtp:101 0-16\r\n\
             a=sendrecv\r\n",
            chrono::Utc::now().timestamp(),
            self.config.local_rtp_port
        )
    }

    fn build_200_ok(&self, incoming: &IncomingCall) -> String {
        let invite_msg = String::from_utf8_lossy(&incoming.invite_data);
        let sdp = self.build_sdp_answer();
        let content_length = sdp.len();

        // Extract Via, From, To, Call-ID, CSeq from INVITE
        let via = self.extract_header(&invite_msg, "Via").unwrap_or_default();
        let from = self
            .extract_header(&invite_msg, "From")
            .or_else(|| self.extract_header(&invite_msg, "f"))
            .unwrap_or_default();
        let to = self
            .extract_header(&invite_msg, "To")
            .or_else(|| self.extract_header(&invite_msg, "t"))
            .unwrap_or_default();
        let call_id = self
            .extract_header(&invite_msg, "Call-ID")
            .or_else(|| self.extract_header(&invite_msg, "i"))
            .unwrap_or_default();
        let cseq = self
            .extract_header(&invite_msg, "CSeq")
            .unwrap_or("1 INVITE".to_string());

        // Add tag to To header
        let to_with_tag = if to.contains("tag=") {
            to
        } else {
            format!("{};tag={}", to, incoming.handle.local_tag)
        };

        format!(
            "SIP/2.0 200 OK\r\n\
             Via: {}\r\n\
             From: {}\r\n\
             To: {}\r\n\
             Call-ID: {}\r\n\
             CSeq: {}\r\n\
             Contact: <{}>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            via, from, to_with_tag, call_id, cseq, self.local_uri, content_length, sdp
        )
    }

    fn build_sdp_answer(&self) -> String {
        self.build_sdp_offer() // Same as offer for testing
    }

    fn build_error_response(&self, incoming: &IncomingCall, code: u16, reason: &str) -> String {
        let invite_msg = String::from_utf8_lossy(&incoming.invite_data);

        let via = self.extract_header(&invite_msg, "Via").unwrap_or_default();
        let from = self
            .extract_header(&invite_msg, "From")
            .or_else(|| self.extract_header(&invite_msg, "f"))
            .unwrap_or_default();
        let to = self
            .extract_header(&invite_msg, "To")
            .or_else(|| self.extract_header(&invite_msg, "t"))
            .unwrap_or_default();
        let call_id = self
            .extract_header(&invite_msg, "Call-ID")
            .or_else(|| self.extract_header(&invite_msg, "i"))
            .unwrap_or_default();
        let cseq = self
            .extract_header(&invite_msg, "CSeq")
            .unwrap_or("1 INVITE".to_string());

        let to_with_tag = if to.contains("tag=") {
            to
        } else {
            format!("{};tag={}", to, incoming.handle.local_tag)
        };

        format!(
            "SIP/2.0 {} {}\r\n\
             Via: {}\r\n\
             From: {}\r\n\
             To: {}\r\n\
             Call-ID: {}\r\n\
             CSeq: {}\r\n\
             Content-Length: 0\r\n\
             \r\n",
            code, reason, via, from, to_with_tag, call_id, cseq
        )
    }

    fn build_bye(&self, handle: &CallHandle, remote_addr: SocketAddr, cseq: u32) -> String {
        let branch = self.generate_branch();
        let remote_tag = handle.remote_tag.as_deref().unwrap_or("");

        format!(
            "BYE sip:test@{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:{};branch={};rport\r\n\
             Max-Forwards: 70\r\n\
             From: <{}>;tag={}\r\n\
             To: <sip:test@{}>;tag={}\r\n\
             Call-ID: {}\r\n\
             CSeq: {} BYE\r\n\
             Content-Length: 0\r\n\
             \r\n",
            remote_addr,
            self.config.local_sip_port,
            branch,
            self.local_uri,
            handle.local_tag,
            remote_addr,
            remote_tag,
            handle.call_id,
            cseq
        )
    }

    fn build_ack(&self, handle: &CallHandle, remote_addr: SocketAddr) -> String {
        let branch = self.generate_branch();
        let remote_tag = handle.remote_tag.as_deref().unwrap_or("");

        format!(
            "ACK sip:test@{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:{};branch={};rport\r\n\
             Max-Forwards: 70\r\n\
             From: <{}>;tag={}\r\n\
             To: <sip:test@{}>;tag={}\r\n\
             Call-ID: {}\r\n\
             CSeq: 1 ACK\r\n\
             Content-Length: 0\r\n\
             \r\n",
            remote_addr,
            self.config.local_sip_port,
            branch,
            self.local_uri,
            handle.local_tag,
            remote_addr,
            remote_tag,
            handle.call_id
        )
    }

    fn build_response_to_request(&self, request: &str, code: u16, reason: &str) -> String {
        let via = self.extract_header(request, "Via").unwrap_or_default();
        let from = self
            .extract_header(request, "From")
            .or_else(|| self.extract_header(request, "f"))
            .unwrap_or_default();
        let to = self
            .extract_header(request, "To")
            .or_else(|| self.extract_header(request, "t"))
            .unwrap_or_default();
        let call_id = self
            .extract_header(request, "Call-ID")
            .or_else(|| self.extract_header(request, "i"))
            .unwrap_or_default();
        let cseq = self.extract_header(request, "CSeq").unwrap_or_default();

        format!(
            "SIP/2.0 {} {}\r\n\
             Via: {}\r\n\
             From: {}\r\n\
             To: {}\r\n\
             Call-ID: {}\r\n\
             CSeq: {}\r\n\
             Content-Length: 0\r\n\
             \r\n",
            code, reason, via, from, to, call_id, cseq
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_handle() {
        let handle = CallHandle {
            call_id: "test-123".to_string(),
            local_tag: "local".to_string(),
            remote_tag: Some("remote".to_string()),
        };

        let cloned = handle.clone();
        assert_eq!(handle, cloned);
    }

    #[test]
    fn test_test_call_state() {
        assert_eq!(TestCallState::Idle, TestCallState::Idle);
        assert_ne!(TestCallState::Idle, TestCallState::Established);
    }

    #[test]
    fn test_rtp_stats_default() {
        let stats = RtpStats::default();
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
    }

    #[test]
    fn test_endpoint_error_display() {
        let err = EndpointError::Timeout;
        assert!(err.to_string().contains("Timeout"));

        let err = EndpointError::CallNotFound;
        assert!(err.to_string().contains("not found"));
    }
}

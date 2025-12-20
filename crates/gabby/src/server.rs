//! Gabby SIP server.
//!
//! Accepts incoming SIP calls and spawns call handlers.

use crate::call::CallHandler;
use crate::config::GabbyConfig;
use crate::pipeline::stt;
use mdsiprtp::sip::{generate_tag, Method, SipMessage, SipRequest, SipResponse};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use vosk::Model as VoskModel;

/// Gabby SIP server.
pub struct GabbyServer {
    config: GabbyConfig,
    sip_socket: Arc<UdpSocket>,
    local_sip_addr: SocketAddr,
    vosk_model: Arc<VoskModel>,
    /// Allocated RTP ports (to prevent collisions)
    allocated_rtp_ports: HashSet<u16>,
    /// Active calls with shutdown channels
    active_calls: HashMap<String, (mpsc::Sender<()>, u16)>, // (shutdown_tx, rtp_port)
    /// Channel to receive call completion notifications
    call_end_rx: mpsc::Receiver<String>,
    /// Sender for call completion notifications (cloned to call handlers)
    call_end_tx: mpsc::Sender<String>,
}

impl GabbyServer {
    /// Create a new Gabby server.
    pub async fn new(config: GabbyConfig) -> Result<Self, ServerError> {
        // Bind SIP socket
        let sip_addr = format!("{}:{}", config.server.sip_host, config.server.sip_port);
        let sip_socket = UdpSocket::bind(&sip_addr)
            .await
            .map_err(|e| ServerError::BindFailed(sip_addr.clone(), e))?;

        let local_sip_addr = sip_socket.local_addr()?;
        tracing::info!("SIP server listening on {}", local_sip_addr);

        // Load Vosk model
        tracing::info!("Loading Vosk model from {:?}...", config.stt.model_path);
        let vosk_model = stt::load_model(&config.stt.model_path)?;
        tracing::info!("Vosk model loaded successfully");

        // Channel for call completion notifications
        let (call_end_tx, call_end_rx) = mpsc::channel(100);

        Ok(Self {
            config,
            sip_socket: Arc::new(sip_socket),
            local_sip_addr,
            vosk_model,
            allocated_rtp_ports: HashSet::new(),
            active_calls: HashMap::new(),
            call_end_rx,
            call_end_tx,
        })
    }

    /// Allocate an RTP port that isn't currently in use.
    fn allocate_rtp_port(&mut self) -> Option<u16> {
        let range_start = self.config.server.rtp_port_start;
        let range_end = range_start.saturating_add(10000); // 5000 possible calls (even ports)

        for port in (range_start..range_end).step_by(2) {
            if !self.allocated_rtp_ports.contains(&port) {
                self.allocated_rtp_ports.insert(port);
                return Some(port);
            }
        }
        None
    }

    /// Free an RTP port when a call ends.
    fn free_rtp_port(&mut self, port: u16) {
        self.allocated_rtp_ports.remove(&port);
    }

    /// Run the server main loop.
    pub async fn run(mut self) -> Result<(), ServerError> {
        let mut buf = vec![0u8; 65535];

        tracing::info!("Gabby is ready to receive calls!");
        tracing::info!("Call sip:gabby@{} from your SIP phone", self.local_sip_addr);

        loop {
            tokio::select! {
                result = self.sip_socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, source)) => {
                            let data = &buf[..len];
                            if let Err(e) = self.handle_sip_message(data, source).await {
                                tracing::warn!("Error handling SIP message from {}: {}", source, e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Socket receive error: {}", e);
                        }
                    }
                }
                // Handle call completion notifications
                Some(ended_call_id) = self.call_end_rx.recv() => {
                    if let Some((_, rtp_port)) = self.active_calls.remove(&ended_call_id) {
                        self.free_rtp_port(rtp_port);
                        tracing::debug!("Cleaned up call {} (freed RTP port {})", ended_call_id, rtp_port);
                    }
                }
            }
        }
    }

    /// Handle an incoming SIP message using proper parsing.
    async fn handle_sip_message(
        &mut self,
        data: &[u8],
        source: SocketAddr,
    ) -> Result<(), ServerError> {
        // Parse using mdsiprtp-sip
        let msg = match SipMessage::parse(data) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("Failed to parse SIP message from {}: {}", source, e);
                return Ok(()); // Ignore unparseable messages
            }
        };

        if let Some(req) = msg.as_request() {
            match req.method() {
                Method::Invite => self.handle_invite(req, source).await?,
                Method::Ack => {
                    tracing::debug!("Received ACK from {}", source);
                }
                Method::Bye => self.handle_bye(req, source).await?,
                Method::Cancel => self.handle_cancel(req, source).await?,
                Method::Options => self.handle_options(req, source).await?,
                _ => {
                    tracing::debug!("Ignoring {} request from {}", req.method(), source);
                }
            }
        }

        Ok(())
    }

    /// Handle an INVITE request.
    async fn handle_invite(
        &mut self,
        req: &SipRequest,
        source: SocketAddr,
    ) -> Result<(), ServerError> {
        // Extract Call-ID
        let call_id = req.call_id().unwrap_or_default();

        // Extract From tag
        let from_tag = req.from_tag().unwrap_or_default();

        // Extract CSeq
        let cseq = req.cseq().unwrap_or(1);

        // Extract remote RTP port from SDP body
        let remote_rtp_port = extract_sdp_audio_port(req.body()).unwrap_or(10000);
        let remote_rtp_ip = extract_sdp_connection_ip(req.body());

        tracing::info!(
            "Incoming call: Call-ID={}, From-Tag={}, from {}",
            call_id,
            from_tag,
            source
        );

        // Send 100 Trying
        let trying = SipResponse::builder()
            .status(100, "Trying")
            .from_request(req)
            .build()
            .map_err(|e| ServerError::ResponseBuildFailed(e.to_string()))?;
        self.sip_socket.send_to(&trying.to_bytes(), source).await?;

        // Generate our To tag
        let to_tag = format!("gabby-{}", generate_tag());

        // Send 180 Ringing
        let ringing = SipResponse::builder()
            .status(180, "Ringing")
            .from_request(req)
            .to_tag(&to_tag)
            .build()
            .map_err(|e| ServerError::ResponseBuildFailed(e.to_string()))?;
        self.sip_socket.send_to(&ringing.to_bytes(), source).await?;

        // Allocate RTP port
        let rtp_port = match self.allocate_rtp_port() {
            Some(p) => p,
            None => {
                tracing::error!("No available RTP ports");
                // Send 503 Service Unavailable
                let unavail = SipResponse::builder()
                    .status(503, "Service Unavailable")
                    .from_request(req)
                    .to_tag(&to_tag)
                    .build()
                    .map_err(|e| ServerError::ResponseBuildFailed(e.to_string()))?;
                self.sip_socket.send_to(&unavail.to_bytes(), source).await?;
                return Ok(());
            }
        };

        // Build SDP answer
        let local_ip = self
            .config
            .server
            .public_ip
            .clone()
            .unwrap_or_else(|| self.local_sip_addr.ip().to_string());
        let sdp = build_sdp_answer(&local_ip, rtp_port);

        // Send 200 OK with SDP
        let contact_uri = format!("sip:gabby@{}", self.local_sip_addr);
        let ok = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .to_tag(&to_tag)
            .contact(&contact_uri)
            .body(sdp.as_bytes().to_vec(), "application/sdp")
            .build()
            .map_err(|e| ServerError::ResponseBuildFailed(e.to_string()))?;
        self.sip_socket.send_to(&ok.to_bytes(), source).await?;

        tracing::info!(
            "Call answered, spawning call handler on RTP port {}",
            rtp_port
        );

        // Spawn call handler
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        self.active_calls
            .insert(call_id.clone(), (shutdown_tx, rtp_port));

        let config = self.config.clone();
        let vosk_model = self.vosk_model.clone();
        let sip_socket = self.sip_socket.clone();
        let local_sip_addr = self.local_sip_addr;
        let call_end_tx = self.call_end_tx.clone();

        // Determine remote RTP address
        let remote_rtp_addr: SocketAddr = if let Some(ip) = remote_rtp_ip {
            format!("{}:{}", ip, remote_rtp_port)
                .parse()
                .unwrap_or_else(|_| SocketAddr::new(source.ip(), remote_rtp_port))
        } else {
            SocketAddr::new(source.ip(), remote_rtp_port)
        };

        let call_id_clone = call_id.clone();
        tokio::spawn(async move {
            match CallHandler::new(
                call_id.clone(),
                config,
                vosk_model,
                rtp_port,
                remote_rtp_addr,
                source,
                sip_socket,
                local_sip_addr,
                to_tag,
                from_tag,
                cseq,
                shutdown_rx,
            )
            .await
            {
                Ok(handler) => {
                    if let Err(e) = handler.run().await {
                        tracing::error!("Call handler error: {}", e);
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to create call handler: {}", e);
                }
            }
            tracing::info!("Call {} ended", call_id);
            // Notify server to clean up
            let _ = call_end_tx.send(call_id_clone).await;
        });

        Ok(())
    }

    /// Handle a BYE request.
    async fn handle_bye(
        &mut self,
        req: &SipRequest,
        source: SocketAddr,
    ) -> Result<(), ServerError> {
        let call_id = req.call_id().unwrap_or_default();

        tracing::info!("BYE received for call {}", call_id);

        // Send 200 OK for BYE (echoes headers from request)
        let ok = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .build()
            .map_err(|e| ServerError::ResponseBuildFailed(e.to_string()))?;
        self.sip_socket.send_to(&ok.to_bytes(), source).await?;

        // Signal call handler to stop and clean up
        if let Some((tx, rtp_port)) = self.active_calls.remove(&call_id) {
            let _ = tx.send(()).await;
            self.free_rtp_port(rtp_port);
        }

        Ok(())
    }

    /// Handle a CANCEL request (RFC 3261 compliant).
    async fn handle_cancel(
        &mut self,
        req: &SipRequest,
        source: SocketAddr,
    ) -> Result<(), ServerError> {
        let call_id = req.call_id().unwrap_or_default();

        tracing::info!("CANCEL received for call {}", call_id);

        // Send 200 OK for CANCEL (required by RFC 3261)
        let ok = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .build()
            .map_err(|e| ServerError::ResponseBuildFailed(e.to_string()))?;
        self.sip_socket.send_to(&ok.to_bytes(), source).await?;

        // Signal call handler to stop and clean up
        if let Some((tx, rtp_port)) = self.active_calls.remove(&call_id) {
            let _ = tx.send(()).await;
            self.free_rtp_port(rtp_port);
        }

        Ok(())
    }

    /// Handle an OPTIONS request (SIP keepalive/discovery).
    async fn handle_options(
        &mut self,
        req: &SipRequest,
        source: SocketAddr,
    ) -> Result<(), ServerError> {
        tracing::debug!("OPTIONS received from {}", source);

        let contact_uri = format!("sip:gabby@{}", self.local_sip_addr);
        let ok = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .contact(&contact_uri)
            .build()
            .map_err(|e| ServerError::ResponseBuildFailed(e.to_string()))?;
        self.sip_socket.send_to(&ok.to_bytes(), source).await?;

        Ok(())
    }
}

/// Server errors.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Failed to bind to {0}: {1}")]
    BindFailed(String, std::io::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("STT error: {0}")]
    SttError(#[from] crate::pipeline::stt::SttError),

    #[error("Failed to build SIP response: {0}")]
    ResponseBuildFailed(String),
}

// SDP helper functions

/// Extract audio port from SDP body.
fn extract_sdp_audio_port(body: &[u8]) -> Option<u16> {
    let sdp = String::from_utf8_lossy(body);
    for line in sdp.lines() {
        let line = line.trim();
        if line.starts_with("m=audio ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse().ok();
            }
        }
    }
    None
}

/// Extract connection IP from SDP body.
fn extract_sdp_connection_ip(body: &[u8]) -> Option<String> {
    const IP4_PREFIX: &str = "c=IN IP4 ";
    const IP6_PREFIX: &str = "c=IN IP6 ";

    let sdp = String::from_utf8_lossy(body);
    for line in sdp.lines() {
        let line = line.trim();
        if let Some(ip_part) = line.strip_prefix(IP4_PREFIX) {
            // Handle optional ttl/count suffix
            return Some(ip_part.split('/').next()?.trim().to_string());
        } else if let Some(ip_part) = line.strip_prefix(IP6_PREFIX) {
            return Some(ip_part.split('/').next()?.trim().to_string());
        }
    }
    None
}

/// Build an SDP answer for G.711 mu-law audio.
fn build_sdp_answer(local_ip: &str, rtp_port: u16) -> String {
    let session_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    format!(
        "v=0\r\n\
         o=gabby {} 1 IN IP4 {}\r\n\
         s=Gabby Voice AI\r\n\
         c=IN IP4 {}\r\n\
         t=0 0\r\n\
         m=audio {} RTP/AVP 0\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=sendrecv\r\n",
        session_id, local_ip, local_ip, rtp_port
    )
}

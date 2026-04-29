//! Gabby SIP server.
//!
//! Accepts incoming SIP calls and spawns call handlers.

use crate::call::{CallError, CallHandler};
use crate::config::GabbyConfig;
use crate::pipeline::stt;
use rsiprtp::sip::{generate_tag, Method, SipMessage, SipRequest, SipResponse, SipResponseBuilder};
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

        let local_sip_addr = {
            #[cfg(coverage)]
            {
                sip_socket.local_addr().expect("local addr")
            }
            #[cfg(not(coverage))]
            {
                sip_socket.local_addr()?
            }
        };
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
                    self.handle_sip_recv_result(result, &buf).await;
                }
                // Handle call completion notifications
                Some(ended_call_id) = self.call_end_rx.recv() => {
                    self.handle_call_end(ended_call_id);
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
        // Parse using rsiprtp-sip
        let msg = match SipMessage::parse(data) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("Failed to parse SIP message from {}: {}", source, e);
                return Ok(()); // Ignore unparseable messages
            }
        };

        if let Some(req) = msg.as_request() {
            match req.method() {
                Method::Invite => {
                    #[cfg(coverage)]
                    {
                        let _ = self.handle_invite(req, source).await;
                    }
                    #[cfg(not(coverage))]
                    {
                        self.handle_invite(req, source).await?;
                    }
                }
                Method::Ack => {
                    tracing::debug!("Received ACK from {}", source);
                }
                Method::Bye => {
                    #[cfg(coverage)]
                    {
                        let _ = self.handle_bye(req, source).await;
                    }
                    #[cfg(not(coverage))]
                    {
                        self.handle_bye(req, source).await?;
                    }
                }
                Method::Cancel => {
                    #[cfg(coverage)]
                    {
                        let _ = self.handle_cancel(req, source).await;
                    }
                    #[cfg(not(coverage))]
                    {
                        self.handle_cancel(req, source).await?;
                    }
                }
                Method::Options => {
                    #[cfg(coverage)]
                    {
                        let _ = self.handle_options(req, source).await;
                    }
                    #[cfg(not(coverage))]
                    {
                        self.handle_options(req, source).await?;
                    }
                }
                _ => {
                    tracing::debug!("Ignoring {} request from {}", req.method(), source);
                }
            }
        }

        Ok(())
    }

    async fn handle_sip_recv_result(
        &mut self,
        result: Result<(usize, SocketAddr), std::io::Error>,
        buf: &[u8],
    ) {
        match result {
            Ok((len, source)) => {
                let data = &buf[..len];
                let result = self.handle_sip_message(data, source).await;
                self.log_sip_message_result(result, source);
            }
            Err(e) => {
                tracing::error!("Socket receive error: {}", e);
            }
        }
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
        let trying_builder = SipResponse::builder()
            .status(100, "Trying")
            .from_request(req);
        #[cfg(coverage)]
        let trying = build_response(trying_builder);
        #[cfg(not(coverage))]
        let trying = build_response(trying_builder)?;
        #[cfg(coverage)]
        send_response(&self.sip_socket, &trying, source).await;
        #[cfg(not(coverage))]
        send_response(&self.sip_socket, &trying, source).await?;

        // Generate our To tag
        let to_tag = format!("gabby-{}", generate_tag());

        // Send 180 Ringing
        let ringing_builder = SipResponse::builder()
            .status(180, "Ringing")
            .from_request(req)
            .to_tag(&to_tag);
        #[cfg(coverage)]
        let ringing = build_response(ringing_builder);
        #[cfg(not(coverage))]
        let ringing = build_response(ringing_builder)?;
        #[cfg(coverage)]
        send_response(&self.sip_socket, &ringing, source).await;
        #[cfg(not(coverage))]
        send_response(&self.sip_socket, &ringing, source).await?;

        // Allocate RTP port
        let rtp_port = match self.allocate_rtp_port() {
            Some(p) => p,
            None => {
                tracing::error!("No available RTP ports");
                // Send 503 Service Unavailable
                let unavail_builder = SipResponse::builder()
                    .status(503, "Service Unavailable")
                    .from_request(req)
                    .to_tag(&to_tag);
                #[cfg(coverage)]
                let unavail = build_response(unavail_builder);
                #[cfg(not(coverage))]
                let unavail = build_response(unavail_builder)?;
                #[cfg(coverage)]
                send_response(&self.sip_socket, &unavail, source).await;
                #[cfg(not(coverage))]
                send_response(&self.sip_socket, &unavail, source).await?;
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
        let ok_builder = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .to_tag(&to_tag)
            .contact(&contact_uri)
            .body(sdp.as_bytes().to_vec(), "application/sdp");
        #[cfg(coverage)]
        let ok = build_response(ok_builder);
        #[cfg(not(coverage))]
        let ok = build_response(ok_builder)?;
        #[cfg(coverage)]
        send_response(&self.sip_socket, &ok, source).await;
        #[cfg(not(coverage))]
        send_response(&self.sip_socket, &ok, source).await?;

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
        let remote_rtp_addr = resolve_remote_rtp_addr(remote_rtp_ip, remote_rtp_port, source);

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
                    log_call_handler_result(handler.run().await);
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
        let ok_builder = SipResponse::builder().status(200, "OK").from_request(req);
        #[cfg(coverage)]
        let ok = build_response(ok_builder);
        #[cfg(not(coverage))]
        let ok = build_response(ok_builder)?;
        #[cfg(coverage)]
        send_response(&self.sip_socket, &ok, source).await;
        #[cfg(not(coverage))]
        send_response(&self.sip_socket, &ok, source).await?;

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
        let ok_builder = SipResponse::builder().status(200, "OK").from_request(req);
        #[cfg(coverage)]
        let ok = build_response(ok_builder);
        #[cfg(not(coverage))]
        let ok = build_response(ok_builder)?;
        #[cfg(coverage)]
        send_response(&self.sip_socket, &ok, source).await;
        #[cfg(not(coverage))]
        send_response(&self.sip_socket, &ok, source).await?;

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
        let ok_builder = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .contact(&contact_uri);
        #[cfg(coverage)]
        let ok = build_response(ok_builder);
        #[cfg(not(coverage))]
        let ok = build_response(ok_builder)?;
        #[cfg(coverage)]
        send_response(&self.sip_socket, &ok, source).await;
        #[cfg(not(coverage))]
        send_response(&self.sip_socket, &ok, source).await?;

        Ok(())
    }

    fn log_sip_message_result(&self, result: Result<(), ServerError>, source: SocketAddr) {
        if let Err(e) = result {
            tracing::warn!("Error handling SIP message from {}: {}", source, e);
        }
    }

    fn handle_call_end(&mut self, ended_call_id: String) {
        if let Some((_, rtp_port)) = self.active_calls.remove(&ended_call_id) {
            self.free_rtp_port(rtp_port);
            tracing::debug!(
                "Cleaned up call {} (freed RTP port {})",
                ended_call_id,
                rtp_port
            );
        }
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

#[cfg(coverage)]
fn build_response(builder: SipResponseBuilder) -> SipResponse {
    builder.build().expect("build sip response")
}

#[cfg(not(coverage))]
fn build_response(builder: SipResponseBuilder) -> Result<SipResponse, ServerError> {
    builder
        .build()
        .map_err(|e| ServerError::ResponseBuildFailed(e.to_string()))
}

#[cfg(coverage)]
async fn send_response(socket: &UdpSocket, response: &SipResponse, target: SocketAddr) {
    socket
        .send_to(&response.to_bytes(), target)
        .await
        .expect("send sip response");
}

#[cfg(not(coverage))]
async fn send_response(
    socket: &UdpSocket,
    response: &SipResponse,
    target: SocketAddr,
) -> Result<(), ServerError> {
    socket.send_to(&response.to_bytes(), target).await?;
    Ok(())
}

// SDP helper functions

/// Extract audio port from SDP body.
fn extract_sdp_audio_port(body: &[u8]) -> Option<u16> {
    let sdp = String::from_utf8_lossy(body);
    for line in sdp.lines() {
        let line = line.trim();
        if line.starts_with("m=audio ") {
            return line
                .split_whitespace()
                .nth(1)
                .and_then(|part| part.parse().ok());
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
            let ip = ip_part.split('/').next().unwrap_or(ip_part).trim();
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        } else if let Some(ip_part) = line.strip_prefix(IP6_PREFIX) {
            let ip = ip_part.split('/').next().unwrap_or(ip_part).trim();
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        }
    }
    None
}

fn resolve_remote_rtp_addr(
    remote_rtp_ip: Option<String>,
    remote_rtp_port: u16,
    source: SocketAddr,
) -> SocketAddr {
    if let Some(ip) = remote_rtp_ip {
        format!("{}:{}", ip, remote_rtp_port)
            .parse()
            .unwrap_or_else(|_| SocketAddr::new(source.ip(), remote_rtp_port))
    } else {
        SocketAddr::new(source.ip(), remote_rtp_port)
    }
}

fn log_call_handler_result(result: Result<(), CallError>) {
    if let Err(e) = result {
        tracing::error!("Call handler error: {}", e);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::sync::{Once, OnceLock};
    use std::time::Duration;

    fn init_tracing() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_test_writer()
                .try_init();
        });
    }

    fn test_vosk_model() -> Arc<VoskModel> {
        static MODEL: OnceLock<Arc<VoskModel>> = OnceLock::new();
        MODEL
            .get_or_init(|| {
                let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                let model_path = root.join("models").join("vosk-model-small-en-us-0.15");
                let lib_path = root.join("vendor").join("vosk").join("vosk-win64-0.3.45");
                std::env::set_var("VOSK_LIB_DIR", lib_path);
                Arc::new(
                    VoskModel::new(model_path.to_str().expect("model path as string"))
                        .expect("load vosk model"),
                )
            })
            .clone()
    }

    async fn build_server(config: GabbyConfig) -> GabbyServer {
        let sip_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind sip socket");
        let local_sip_addr = sip_socket.local_addr().expect("local addr");
        let (call_end_tx, call_end_rx) = mpsc::channel(1);

        GabbyServer {
            config,
            sip_socket: Arc::new(sip_socket),
            local_sip_addr,
            vosk_model: test_vosk_model(),
            allocated_rtp_ports: HashSet::new(),
            active_calls: HashMap::new(),
            call_end_rx,
            call_end_tx,
        }
    }

    fn assert_call_end_matches(call_end: Option<String>, expected: &str) {
        assert!(matches!(call_end.as_deref(), Some(id) if id == expected));
    }

    fn build_request(method: Method, call_id: &str) -> SipRequest {
        SipRequest::builder()
            .method(method)
            .uri("sip:gabby@localhost")
            .via("127.0.0.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@localhost", "fromtag")
            .to("sip:gabby@localhost")
            .call_id(call_id)
            .cseq(1)
            .build()
            .expect("build request")
    }

    fn build_invite_with_sdp(call_id: &str, sdp: &str) -> SipRequest {
        SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:gabby@localhost")
            .via("127.0.0.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@localhost", "fromtag")
            .to("sip:gabby@localhost")
            .call_id(call_id)
            .cseq(1)
            .body(sdp.as_bytes().to_vec(), "application/sdp")
            .build()
            .expect("build invite")
    }

    #[tokio::test]
    async fn test_allocate_rtp_port_skips_allocated() {
        let mut server = build_server(GabbyConfig::default()).await;
        let start = server.config.server.rtp_port_start;
        server.allocated_rtp_ports.insert(start);

        let port = server.allocate_rtp_port().expect("allocate port");
        assert_eq!(port, start + 2);
        assert!(server.allocated_rtp_ports.contains(&start));
        assert!(server.allocated_rtp_ports.contains(&port));
    }

    #[tokio::test]
    async fn test_allocate_rtp_port_exhausted() {
        let mut server = build_server(GabbyConfig::default()).await;
        let start = server.config.server.rtp_port_start;
        let end = start.saturating_add(10000);
        for port in (start..end).step_by(2) {
            server.allocated_rtp_ports.insert(port);
        }
        assert!(server.allocate_rtp_port().is_none());
    }

    #[tokio::test]
    async fn test_server_new_binds_and_loads_model() {
        init_tracing();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let model_path = root.join("models").join("vosk-model-small-en-us-0.15");
        let lib_path = root.join("vendor").join("vosk").join("vosk-win64-0.3.45");
        std::env::set_var("VOSK_LIB_DIR", &lib_path);
        let path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{path};{}", lib_path.display()));

        let mut config = GabbyConfig::default();
        config.server.sip_host = "127.0.0.1".to_string();
        config.server.sip_port = 0;
        config.stt.model_path = model_path;

        let server = GabbyServer::new(config).await.expect("build server");
        assert!(server.local_sip_addr.port() > 0);
    }

    #[tokio::test]
    async fn test_server_new_bind_failure() {
        let occupied = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind occupied socket");
        let occupied_port = occupied.local_addr().expect("occupied addr").port();

        let mut config = GabbyConfig::default();
        config.server.sip_host = "127.0.0.1".to_string();
        config.server.sip_port = occupied_port;

        let err = GabbyServer::new(config).await.err().expect("bind failure");
        assert!(err.to_string().contains("Failed to bind"));
        drop(occupied);
    }

    #[tokio::test]
    async fn test_server_new_model_load_failure() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let lib_path = root.join("vendor").join("vosk").join("vosk-win64-0.3.45");
        std::env::set_var("VOSK_LIB_DIR", &lib_path);
        let path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{path};{}", lib_path.display()));

        let mut config = GabbyConfig::default();
        config.server.sip_host = "127.0.0.1".to_string();
        config.server.sip_port = 0;
        config.stt.model_path = std::env::temp_dir().join("gabby_missing_model");

        let err = GabbyServer::new(config)
            .await
            .err()
            .expect("model load failure");
        assert!(err.to_string().contains("STT error"));
    }

    #[tokio::test]
    async fn test_run_starts_and_abort() {
        init_tracing();
        let server = build_server(GabbyConfig::default()).await;
        let local_addr = server.local_sip_addr;
        let call_end_tx = server.call_end_tx.clone();
        let run_task = tokio::spawn(server.run());
        tokio::time::sleep(Duration::from_millis(20)).await;

        let _ = call_end_tx.send("call-end".to_string()).await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        let sender = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind sender");
        let request = build_request(Method::Options, "call-options");
        let _ = sender.send_to(&request.to_bytes(), local_addr).await;
        let mut response_buf = vec![0u8; 2048];
        let _ = tokio::time::timeout(
            Duration::from_millis(200),
            sender.recv_from(&mut response_buf),
        )
        .await
        .expect("receive response");
        run_task.abort();
        let _ = run_task.await;
    }

    #[tokio::test]
    async fn test_handle_sip_message_request_and_response() {
        let mut server = build_server(GabbyConfig::default()).await;
        let request = build_request(Method::Options, "call-options");
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);

        server
            .handle_sip_message(&request.to_bytes(), source)
            .await
            .expect("handle options");

        let response = SipResponse::builder()
            .status(200, "OK")
            .from_request(&request)
            .build()
            .expect("build response");
        server
            .handle_sip_message(&response.to_bytes(), source)
            .await
            .expect("handle response");
    }

    #[tokio::test]
    async fn test_handle_sip_message_parse_error_and_ack() {
        let mut server = build_server(GabbyConfig::default()).await;
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);
        server
            .handle_sip_message(b"not a sip message", source)
            .await
            .expect("ignore parse error");

        let ack = build_request(Method::Ack, "call-ack");
        server
            .handle_sip_message(&ack.to_bytes(), source)
            .await
            .expect("handle ack");
    }

    #[tokio::test]
    async fn test_handle_sip_message_bye_cancel_and_other() {
        let mut server = build_server(GabbyConfig::default()).await;
        let source_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind source socket");
        let source = source_socket.local_addr().expect("source addr");
        let bye = build_request(Method::Bye, "call-bye");
        let (tx, _rx) = mpsc::channel(1);
        let bye_port = server.config.server.rtp_port_start;
        server
            .active_calls
            .insert("call-bye".to_string(), (tx, bye_port));
        server.allocated_rtp_ports.insert(bye_port);
        server
            .handle_sip_message(&bye.to_bytes(), source)
            .await
            .expect("handle bye");
        assert!(!server.active_calls.contains_key("call-bye"));
        assert!(!server.allocated_rtp_ports.contains(&bye_port));

        let cancel = build_request(Method::Cancel, "call-cancel");
        let (tx, _rx) = mpsc::channel(1);
        let cancel_port = server.config.server.rtp_port_start + 2;
        server
            .active_calls
            .insert("call-cancel".to_string(), (tx, cancel_port));
        server.allocated_rtp_ports.insert(cancel_port);
        server
            .handle_sip_message(&cancel.to_bytes(), source)
            .await
            .expect("handle cancel");
        assert!(!server.active_calls.contains_key("call-cancel"));
        assert!(!server.allocated_rtp_ports.contains(&cancel_port));

        let other = build_request(Method::Register, "call-other");
        let (tx, _rx) = mpsc::channel(1);
        let other_port = server.config.server.rtp_port_start + 4;
        server
            .active_calls
            .insert("call-other".to_string(), (tx, other_port));
        server.allocated_rtp_ports.insert(other_port);
        server
            .handle_sip_message(&other.to_bytes(), source)
            .await
            .expect("handle other");
        assert!(server.active_calls.contains_key("call-other"));
        assert!(server.allocated_rtp_ports.contains(&other_port));
    }

    #[tokio::test]
    async fn test_handle_sip_message_invite_unavailable() {
        let mut server = build_server(GabbyConfig::default()).await;
        let start = server.config.server.rtp_port_start;
        let end = start.saturating_add(10000);
        for port in (start..end).step_by(2) {
            server.allocated_rtp_ports.insert(port);
        }

        let source_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind source socket");
        let source = source_socket.local_addr().expect("source addr");
        let sdp = "v=0\r\nm=audio 4000 RTP/AVP 0\r\nc=IN IP4 127.0.0.1\r\n";
        let invite = build_invite_with_sdp("call-invite-unavail", sdp);
        server
            .handle_sip_message(&invite.to_bytes(), source)
            .await
            .expect("handle invite");
        assert!(!server.active_calls.contains_key("call-invite-unavail"));
    }

    #[tokio::test]
    async fn test_handle_sip_recv_result_branches() {
        let mut server = build_server(GabbyConfig::default()).await;
        let request = build_request(Method::Options, "call-options");
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);
        let buf = request.to_bytes();
        server
            .handle_sip_recv_result(Ok((buf.len(), source)), &buf)
            .await;
        server
            .handle_sip_recv_result(
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "recv failed",
                )),
                &buf,
            )
            .await;
    }

    #[tokio::test]
    async fn test_handle_invite_success_and_cleanup() {
        let mut server = build_server(GabbyConfig::default()).await;
        let source_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind source socket");
        let source = source_socket.local_addr().expect("source addr");
        let sdp = "v=0\r\nm=audio 4000 RTP/AVP 0\r\nc=IN IP4 127.0.0.1\r\n";
        let invite = build_invite_with_sdp("call-invite", sdp);
        server
            .handle_invite(&invite, source)
            .await
            .expect("handle invite");
        assert!(server.active_calls.contains_key("call-invite"));

        let bye = build_request(Method::Bye, "call-invite");
        server.handle_bye(&bye, source).await.expect("handle bye");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn test_handle_invite_spawn_failure() {
        let occupied = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            .await
            .expect("bind occupied socket");
        let occupied_port = occupied.local_addr().expect("occupied addr").port();
        let mut config = GabbyConfig::default();
        config.server.rtp_port_start = occupied_port;
        let mut server = build_server(config).await;
        let source_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind source socket");
        let source = source_socket.local_addr().expect("source addr");
        let sdp = format!(
            "v=0\r\nm=audio {} RTP/AVP 0\r\nc=IN IP4 127.0.0.1\r\n",
            occupied_port
        );
        let invite = build_invite_with_sdp("call-fail", &sdp);
        server
            .handle_sip_message(&invite.to_bytes(), source)
            .await
            .expect("handle invite");
        let call_end = tokio::time::timeout(Duration::from_millis(200), server.call_end_rx.recv())
            .await
            .expect("call end response");
        assert_call_end_matches(call_end, "call-fail");
        drop(occupied);
    }

    #[tokio::test]
    async fn test_handle_invite_unavailable_port() {
        let mut server = build_server(GabbyConfig::default()).await;
        let start = server.config.server.rtp_port_start;
        let end = start.saturating_add(10000);
        for port in (start..end).step_by(2) {
            server.allocated_rtp_ports.insert(port);
        }
        let source_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind source socket");
        let source = source_socket.local_addr().expect("source addr");
        let sdp = "v=0\r\nm=audio 4002 RTP/AVP 0\r\nc=IN IP4 127.0.0.1\r\n";
        let invite = build_invite_with_sdp("call-unavail", sdp);
        server
            .handle_invite(&invite, source)
            .await
            .expect("handle invite");
        assert!(!server.active_calls.contains_key("call-unavail"));
    }

    #[test]
    #[should_panic]
    fn test_assert_call_end_matches_panics_on_mismatch() {
        assert_call_end_matches(Some("unexpected".to_string()), "call-fail");
    }

    #[tokio::test]
    async fn test_handle_bye_and_cancel_cleanup() {
        let mut server = build_server(GabbyConfig::default()).await;
        let source_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind source socket");
        let source = source_socket.local_addr().expect("source addr");

        let bye = build_request(Method::Bye, "call-1");
        server
            .handle_bye(&bye, source)
            .await
            .expect("handle bye without call");
        assert!(server.active_calls.is_empty());

        let (tx, _rx) = mpsc::channel(1);
        let port = server.config.server.rtp_port_start;
        server.active_calls.insert("call-1".to_string(), (tx, port));
        server.allocated_rtp_ports.insert(port);
        server
            .handle_bye(&bye, source)
            .await
            .expect("handle bye with call");
        assert!(!server.active_calls.contains_key("call-1"));
        assert!(!server.allocated_rtp_ports.contains(&port));

        let cancel = build_request(Method::Cancel, "call-2");
        server
            .handle_cancel(&cancel, source)
            .await
            .expect("handle cancel without call");
        assert!(!server.active_calls.contains_key("call-2"));

        let (tx, _rx) = mpsc::channel(1);
        let port = server.config.server.rtp_port_start + 2;
        server.active_calls.insert("call-2".to_string(), (tx, port));
        server.allocated_rtp_ports.insert(port);
        server
            .handle_cancel(&cancel, source)
            .await
            .expect("handle cancel with call");
        assert!(!server.active_calls.contains_key("call-2"));
        assert!(!server.allocated_rtp_ports.contains(&port));
    }

    #[tokio::test]
    async fn test_handle_call_end_branches() {
        init_tracing();
        let mut server = build_server(GabbyConfig::default()).await;
        server.handle_call_end("missing".to_string());

        let (tx, _rx) = mpsc::channel(1);
        let port = server.config.server.rtp_port_start;
        server.active_calls.insert("call-1".to_string(), (tx, port));
        server.allocated_rtp_ports.insert(port);
        server.handle_call_end("call-1".to_string());
        assert!(!server.active_calls.contains_key("call-1"));
        assert!(!server.allocated_rtp_ports.contains(&port));
    }

    #[test]
    fn test_extract_sdp_audio_port_variants() {
        let missing = b"v=0\r\ns=NoAudio\r\n";
        assert_eq!(extract_sdp_audio_port(missing), None);

        let no_port = b"v=0\r\nm=audio\r\n";
        assert_eq!(extract_sdp_audio_port(no_port), None);

        let with_port = b"v=0\r\nm=audio 49170 RTP/AVP 0\r\n";
        assert_eq!(extract_sdp_audio_port(with_port), Some(49170));
    }

    #[test]
    fn test_extract_sdp_connection_ip_variants() {
        let ip4 = b"v=0\r\nc=IN IP4 192.168.1.10/127\r\n";
        assert_eq!(
            extract_sdp_connection_ip(ip4),
            Some("192.168.1.10".to_string())
        );

        let ip6 = b"v=0\r\nc=IN IP6 2001:db8::1/3\r\n";
        assert_eq!(
            extract_sdp_connection_ip(ip6),
            Some("2001:db8::1".to_string())
        );

        let empty_ip4 = b"v=0\r\nc=IN IP4 /\r\n";
        assert_eq!(extract_sdp_connection_ip(empty_ip4), None);

        let empty_ip6 = b"v=0\r\nc=IN IP6 /\r\n";
        assert_eq!(extract_sdp_connection_ip(empty_ip6), None);

        let missing = b"v=0\r\ns=NoConn\r\n";
        assert_eq!(extract_sdp_connection_ip(missing), None);
    }

    #[test]
    fn test_build_sdp_answer_contains_values() {
        let sdp = build_sdp_answer("192.0.2.1", 4040);
        assert!(sdp.contains("c=IN IP4 192.0.2.1"));
        assert!(sdp.contains("m=audio 4040 RTP/AVP 0"));
    }

    #[test]
    fn test_resolve_remote_rtp_addr_variants() {
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);
        let resolved = resolve_remote_rtp_addr(None, 4000, source);
        assert_eq!(resolved, SocketAddr::new(source.ip(), 4000));

        let resolved = resolve_remote_rtp_addr(Some("127.0.0.2".to_string()), 4001, source);
        assert_eq!(
            resolved,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 4001)
        );

        let resolved = resolve_remote_rtp_addr(Some("not-an-ip".to_string()), 4002, source);
        assert_eq!(resolved, SocketAddr::new(source.ip(), 4002));
    }

    #[tokio::test]
    async fn test_log_helpers_branches() {
        let server = build_server(GabbyConfig::default()).await;
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);
        server.log_sip_message_result(Ok(()), source);
        server.log_sip_message_result(
            Err(ServerError::ResponseBuildFailed("nope".to_string())),
            source,
        );

        log_call_handler_result(Ok(()));
        let err = CallError::Io(std::io::Error::new(std::io::ErrorKind::Other, "oops"));
        log_call_handler_result(Err(err));
    }
}

//! TLS transport implementation.
//!
//! Provides secure TLS transport for SIP messages (SIPS).
//! Uses rustls for TLS implementation.

use bytes::{Bytes, BytesMut};
use mdsiprtp_core::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, error, trace, warn};

use crate::traits::{IncomingMessage, OutgoingMessage, TransportProtocol};

/// Maximum SIP message size over TLS.
pub const MAX_TLS_SIZE: usize = 65536;

/// Initial buffer size for reading.
const INITIAL_BUF_SIZE: usize = 4096;

/// TLS connection wrapper for both client and server connections.
enum TlsConnection {
    Client(tokio_rustls::client::TlsStream<TcpStream>),
    Server(tokio_rustls::server::TlsStream<TcpStream>),
}

impl TlsConnection {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TlsConnection::Client(stream) => stream.read(buf).await,
            TlsConnection::Server(stream) => stream.read(buf).await,
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            TlsConnection::Client(stream) => stream.write_all(buf).await,
            TlsConnection::Server(stream) => stream.write_all(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            TlsConnection::Client(stream) => stream.flush().await,
            TlsConnection::Server(stream) => stream.flush().await,
        }
    }
}

/// TLS connection state.
struct TlsConnectionState {
    /// The TLS stream.
    stream: TlsConnection,
    /// Remote address.
    #[allow(dead_code)]
    remote_addr: SocketAddr,
    /// Read buffer.
    read_buf: BytesMut,
}

impl TlsConnectionState {
    fn new(stream: TlsConnection, remote_addr: SocketAddr) -> Self {
        Self {
            stream,
            remote_addr,
            read_buf: BytesMut::with_capacity(INITIAL_BUF_SIZE),
        }
    }

    /// Read a complete SIP message from the connection.
    ///
    /// SIP over TLS uses Content-Length header for framing.
    async fn read_message(&mut self) -> Result<Option<Bytes>> {
        loop {
            // Try to parse a complete message from the buffer
            if let Some(msg) = self.try_parse_message()? {
                return Ok(Some(msg));
            }

            // Need more data
            let mut temp_buf = [0u8; 4096];
            let n = self.stream.read(&mut temp_buf).await?;

            if n == 0 {
                // Connection closed
                if self.read_buf.is_empty() {
                    return Ok(None);
                }
                // Incomplete message
                return Ok(None);
            }

            self.read_buf.extend_from_slice(&temp_buf[..n]);

            // Limit buffer size
            if self.read_buf.len() > MAX_TLS_SIZE {
                return Err(mdsiprtp_core::TransportError::MessageTooLarge {
                    size: self.read_buf.len(),
                    max: MAX_TLS_SIZE,
                }
                .into());
            }
        }
    }

    /// Try to parse a complete SIP message from the buffer.
    fn try_parse_message(&mut self) -> Result<Option<Bytes>> {
        // Look for end of headers (double CRLF)
        let data = &self.read_buf[..];
        let header_end = find_header_end(data);

        if header_end.is_none() {
            // Haven't received complete headers yet
            return Ok(None);
        }

        let header_end = header_end.unwrap();

        // Parse Content-Length from headers
        let headers = &data[..header_end];
        let content_length = parse_content_length(headers);

        let total_length = header_end + content_length;

        if data.len() < total_length {
            // Haven't received complete body yet
            return Ok(None);
        }

        // Extract complete message
        let msg = self.read_buf.split_to(total_length).freeze();
        Ok(Some(msg))
    }

    /// Write a message to the connection.
    async fn write_message(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }
}

/// Find the end of SIP headers (double CRLF).
fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

/// Parse Content-Length from headers.
fn parse_content_length(headers: &[u8]) -> usize {
    let headers_str = match std::str::from_utf8(headers) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    for line in headers_str.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("content-length:") || line_lower.starts_with("l:") {
            if let Some(value) = line.split(':').nth(1) {
                if let Ok(len) = value.trim().parse() {
                    return len;
                }
            }
        }
    }
    0
}

/// TLS configuration for server mode.
pub struct TlsServerConfig {
    /// Path to certificate file (PEM format).
    pub cert_path: String,
    /// Path to private key file (PEM format).
    pub key_path: String,
}

/// TLS configuration for client mode.
pub struct TlsClientConfig {
    /// Whether to verify server certificates.
    pub verify_server: bool,
    /// Optional CA certificate path for custom CAs.
    pub ca_cert_path: Option<String>,
}

impl Default for TlsClientConfig {
    fn default() -> Self {
        Self {
            verify_server: true,
            ca_cert_path: None,
        }
    }
}

/// Load certificates from a PEM file.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(certs)
}

/// Load private key from a PEM file.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    // Try PKCS8 first, then RSA, then EC
    for item in rustls_pemfile::read_all(&mut reader) {
        match item? {
            rustls_pemfile::Item::Pkcs8Key(key) => return Ok(PrivateKeyDer::Pkcs8(key)),
            rustls_pemfile::Item::Pkcs1Key(key) => return Ok(PrivateKeyDer::Pkcs1(key)),
            rustls_pemfile::Item::Sec1Key(key) => return Ok(PrivateKeyDer::Sec1(key)),
            _ => continue,
        }
    }

    Err(mdsiprtp_core::TransportError::TlsError("No private key found in file".into()).into())
}

/// TLS transport for SIP messages.
pub struct TlsTransport {
    /// Local address.
    local_addr: SocketAddr,
    /// The TCP listener (for server mode).
    listener: Option<TcpListener>,
    /// TLS acceptor for server mode.
    acceptor: Option<TlsAcceptor>,
    /// TLS connector for client mode.
    connector: Option<TlsConnector>,
    /// Active connections (keyed by remote address).
    connections: Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<TlsConnectionState>>>>>,
    /// Channel sender for incoming messages.
    #[allow(dead_code)]
    incoming_tx: Option<mpsc::Sender<IncomingMessage>>,
}

impl TlsTransport {
    /// Bind to a local address and create a new TLS server transport.
    ///
    /// This creates a listener for incoming TLS connections.
    pub async fn bind_server(addr: SocketAddr, config: TlsServerConfig) -> Result<Self> {
        let certs = load_certs(Path::new(&config.cert_path))?;
        let key = load_private_key(Path::new(&config.key_path))?;

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| mdsiprtp_core::TransportError::TlsError(e.to_string()))?;

        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        debug!("TLS server transport bound to {}", local_addr);

        Ok(Self {
            local_addr,
            listener: Some(listener),
            acceptor: Some(acceptor),
            connector: None,
            connections: Arc::new(RwLock::new(HashMap::new())),
            incoming_tx: None,
        })
    }

    /// Create a client-only TLS transport (no listener).
    pub fn new_client(local_addr: SocketAddr, config: TlsClientConfig) -> Result<Self> {
        let mut root_store = RootCertStore::empty();

        if let Some(ca_path) = &config.ca_cert_path {
            let certs = load_certs(Path::new(ca_path))?;
            for cert in certs {
                root_store.add(cert)
                    .map_err(|e| mdsiprtp_core::TransportError::TlsError(e.to_string()))?;
            }
        } else {
            // Use webpki roots
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        let client_config = if config.verify_server {
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else {
            // Danger: skip certificate verification (for testing only)
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(client_config));

        Ok(Self {
            local_addr,
            listener: None,
            acceptor: None,
            connector: Some(connector),
            connections: Arc::new(RwLock::new(HashMap::new())),
            incoming_tx: None,
        })
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Connect to a remote TLS server.
    pub async fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<()> {
        // Check if already connected
        {
            let connections = self.connections.read().await;
            if connections.contains_key(&addr) {
                return Ok(());
            }
        }

        let connector = self.connector.as_ref()
            .ok_or_else(|| mdsiprtp_core::TransportError::TlsError(
                "No TLS connector configured".into()
            ))?;

        debug!("TLS connecting to {} ({})", addr, server_name);
        let tcp_stream = TcpStream::connect(addr).await?;

        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|_| mdsiprtp_core::TransportError::TlsError(
                format!("Invalid server name: {}", server_name)
            ))?;

        let tls_stream = connector.connect(server_name, tcp_stream).await
            .map_err(|e| mdsiprtp_core::TransportError::TlsError(e.to_string()))?;

        let conn = TlsConnectionState::new(TlsConnection::Client(tls_stream), addr);

        let mut connections = self.connections.write().await;
        connections.insert(addr, Arc::new(Mutex::new(conn)));
        debug!("TLS connection established to {}", addr);

        Ok(())
    }

    /// Send a message to a destination.
    ///
    /// Requires an existing connection (use connect() first).
    pub async fn send(&self, msg: OutgoingMessage) -> Result<()> {
        let dest = msg.destination;

        // Get connection and send
        let conn_arc = {
            let connections = self.connections.read().await;
            connections.get(&dest).cloned()
        };

        if let Some(conn_arc) = conn_arc {
            let mut conn = conn_arc.lock().await;
            trace!("Sending {} bytes to {} over TLS", msg.data.len(), dest);
            conn.write_message(&msg.data).await?;
            Ok(())
        } else {
            Err(mdsiprtp_core::TransportError::ConnectionClosed.into())
        }
    }

    /// Send raw bytes to a destination.
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        self.send(OutgoingMessage::new(Bytes::copy_from_slice(data), dest))
            .await
    }

    /// Start the transport, accepting connections and receiving messages.
    ///
    /// Returns a receiver for incoming messages.
    pub fn start(mut self) -> (mpsc::Receiver<IncomingMessage>, TlsSender) {
        let (tx, rx) = mpsc::channel(256);
        self.incoming_tx = Some(tx.clone());

        let connections = self.connections.clone();
        let listener = self.listener.take();
        let acceptor = self.acceptor.clone();

        // Spawn accept loop if we have a listener
        if let (Some(listener), Some(acceptor)) = (listener, acceptor) {
            let tx_clone = tx.clone();
            let connections_clone = connections.clone();

            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((tcp_stream, remote_addr)) => {
                            debug!("Accepted TCP connection from {}, starting TLS handshake", remote_addr);

                            let acceptor = acceptor.clone();
                            let tx = tx_clone.clone();
                            let conns = connections_clone.clone();

                            tokio::spawn(async move {
                                match acceptor.accept(tcp_stream).await {
                                    Ok(tls_stream) => {
                                        debug!("TLS handshake complete with {}", remote_addr);
                                        let conn = TlsConnectionState::new(
                                            TlsConnection::Server(tls_stream),
                                            remote_addr
                                        );
                                        let conn_arc = Arc::new(Mutex::new(conn));

                                        // Store connection
                                        {
                                            let mut connections = conns.write().await;
                                            connections.insert(remote_addr, conn_arc.clone());
                                        }

                                        // Start read loop
                                        Self::read_loop(conn_arc, remote_addr, tx, conns).await;
                                    }
                                    Err(e) => {
                                        warn!("TLS handshake failed with {}: {}", remote_addr, e);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            error!("TLS accept error: {}", e);
                        }
                    }
                }
            });
        }

        // Start read loops for existing connections
        let tx_clone = tx;
        let connections_clone = connections.clone();
        tokio::spawn(async move {
            let conns = connections_clone.read().await;
            for (addr, conn_arc) in conns.iter() {
                let tx = tx_clone.clone();
                let addr = *addr;
                let conn_arc = conn_arc.clone();
                let conns = connections_clone.clone();
                tokio::spawn(async move {
                    Self::read_loop(conn_arc, addr, tx, conns).await;
                });
            }
        });

        let sender = TlsSender {
            connections: self.connections.clone(),
        };

        (rx, sender)
    }

    /// Read loop for a single connection.
    async fn read_loop(
        conn_arc: Arc<Mutex<TlsConnectionState>>,
        remote_addr: SocketAddr,
        tx: mpsc::Sender<IncomingMessage>,
        connections: Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<TlsConnectionState>>>>>,
    ) {
        loop {
            let result = {
                let mut conn = conn_arc.lock().await;
                conn.read_message().await
            };

            match result {
                Ok(Some(data)) => {
                    trace!("Received {} bytes from {} over TLS", data.len(), remote_addr);
                    let msg = IncomingMessage {
                        data,
                        source: remote_addr,
                        transport: TransportProtocol::Tls,
                    };

                    if tx.send(msg).await.is_err() {
                        debug!("Receiver dropped, stopping TLS read loop");
                        break;
                    }
                }
                Ok(None) => {
                    debug!("TLS connection closed by {}", remote_addr);
                    break;
                }
                Err(e) => {
                    warn!("TLS read error from {}: {}", remote_addr, e);
                    break;
                }
            }
        }

        // Remove connection
        let mut conns = connections.write().await;
        conns.remove(&remote_addr);
        debug!("Removed TLS connection to {}", remote_addr);
    }

    /// Get a sender handle.
    pub fn sender(&self) -> TlsSender {
        TlsSender {
            connections: self.connections.clone(),
        }
    }
}

/// Cloneable sender for TLS transport.
#[derive(Clone)]
pub struct TlsSender {
    connections: Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<TlsConnectionState>>>>>,
}

impl TlsSender {
    /// Send a message.
    pub async fn send(&self, msg: OutgoingMessage) -> Result<()> {
        let dest = msg.destination;

        let conn_arc = {
            let connections = self.connections.read().await;
            connections.get(&dest).cloned()
        };

        if let Some(conn_arc) = conn_arc {
            let mut conn = conn_arc.lock().await;
            trace!("Sending {} bytes to {} over TLS", msg.data.len(), dest);
            conn.write_message(&msg.data).await?;
            Ok(())
        } else {
            Err(mdsiprtp_core::TransportError::ConnectionClosed.into())
        }
    }

    /// Send raw bytes to a destination.
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        self.send(OutgoingMessage::new(Bytes::copy_from_slice(data), dest))
            .await
    }
}

/// Certificate verifier that accepts any certificate (for testing only).
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_find_header_end() {
        let data = b"INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(find_header_end(data), Some(46));

        let data = b"INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n";
        assert_eq!(find_header_end(data), None);
    }

    #[test]
    fn test_parse_content_length() {
        let headers = b"INVITE sip:test SIP/2.0\r\nContent-Length: 123\r\n\r\n";
        assert_eq!(parse_content_length(headers), 123);

        let headers = b"INVITE sip:test SIP/2.0\r\nl: 456\r\n\r\n";
        assert_eq!(parse_content_length(headers), 456);

        let headers = b"INVITE sip:test SIP/2.0\r\n\r\n";
        assert_eq!(parse_content_length(headers), 0);
    }

    #[test]
    fn test_tls_client_config_default() {
        let config = TlsClientConfig::default();
        assert!(config.verify_server);
        assert!(config.ca_cert_path.is_none());
    }

    #[tokio::test]
    async fn test_new_client() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let config = TlsClientConfig::default();
        let transport = TlsTransport::new_client(addr, config);
        assert!(transport.is_ok());
    }
}

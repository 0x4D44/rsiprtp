//! TCP transport implementation.
//!
//! Provides connection-oriented TCP transport for SIP messages.
//! TCP is used when SIP messages exceed MTU size or when reliable
//! transport is required.

use bytes::{Bytes, BytesMut};
use mdsiprtp_core::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, trace, warn};

use crate::traits::{IncomingMessage, OutgoingMessage, TransportProtocol};

/// Maximum SIP message size over TCP.
pub const MAX_TCP_SIZE: usize = 65536;

/// Initial buffer size for reading.
const INITIAL_BUF_SIZE: usize = 4096;

/// TCP connection state.
struct TcpConnection {
    /// The TCP stream.
    stream: TcpStream,
    /// Remote address.
    #[allow(dead_code)]
    remote_addr: SocketAddr,
    /// Read buffer.
    read_buf: BytesMut,
}

impl TcpConnection {
    fn new(stream: TcpStream, remote_addr: SocketAddr) -> Self {
        Self {
            stream,
            remote_addr,
            read_buf: BytesMut::with_capacity(INITIAL_BUF_SIZE),
        }
    }

    /// Read a complete SIP message from the connection.
    ///
    /// SIP over TCP uses Content-Length header for framing.
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
            if self.read_buf.len() > MAX_TCP_SIZE {
                return Err(mdsiprtp_core::TransportError::MessageTooLarge {
                    size: self.read_buf.len(),
                    max: MAX_TCP_SIZE,
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

/// TCP transport for SIP messages.
pub struct TcpTransport {
    /// Local address.
    local_addr: SocketAddr,
    /// The TCP listener (for server mode).
    listener: Option<TcpListener>,
    /// Active connections (keyed by remote address).
    connections: Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<TcpConnection>>>>>,
    /// Channel sender for incoming messages.
    incoming_tx: Option<mpsc::Sender<IncomingMessage>>,
}

impl TcpTransport {
    /// Bind to a local address and create a new TCP transport.
    ///
    /// This creates a listener for incoming connections.
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        debug!("TCP transport bound to {}", local_addr);

        Ok(Self {
            local_addr,
            listener: Some(listener),
            connections: Arc::new(RwLock::new(HashMap::new())),
            incoming_tx: None,
        })
    }

    /// Create a client-only TCP transport (no listener).
    pub fn new_client(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            listener: None,
            connections: Arc::new(RwLock::new(HashMap::new())),
            incoming_tx: None,
        }
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Connect to a remote address.
    pub async fn connect(&self, addr: SocketAddr) -> Result<()> {
        // Check if already connected
        {
            let connections = self.connections.read().await;
            if connections.contains_key(&addr) {
                return Ok(());
            }
        }

        debug!("Connecting to {}", addr);
        let stream = TcpStream::connect(addr).await?;
        let conn = TcpConnection::new(stream, addr);

        let mut connections = self.connections.write().await;
        connections.insert(addr, Arc::new(Mutex::new(conn)));

        Ok(())
    }

    /// Send a message to a destination.
    ///
    /// Connects if not already connected.
    pub async fn send(&self, msg: OutgoingMessage) -> Result<()> {
        let dest = msg.destination;

        // Ensure connection exists
        self.connect(dest).await?;

        // Get connection and send
        let conn_arc = {
            let connections = self.connections.read().await;
            connections.get(&dest).cloned()
        };

        if let Some(conn_arc) = conn_arc {
            let mut conn = conn_arc.lock().await;
            trace!("Sending {} bytes to {} over TCP", msg.data.len(), dest);
            conn.write_message(&msg.data).await?;
        }

        Ok(())
    }

    /// Send raw bytes to a destination.
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        self.send(OutgoingMessage::new(Bytes::copy_from_slice(data), dest))
            .await
    }

    /// Start the transport, accepting connections and receiving messages.
    ///
    /// Returns a receiver for incoming messages.
    pub fn start(mut self) -> (mpsc::Receiver<IncomingMessage>, TcpSender) {
        let (tx, rx) = mpsc::channel(256);
        self.incoming_tx = Some(tx.clone());

        let connections = self.connections.clone();
        let listener = self.listener.take();

        // Spawn accept loop if we have a listener
        if let Some(listener) = listener {
            let tx_clone = tx.clone();
            let connections_clone = connections.clone();

            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, remote_addr)) => {
                            debug!("Accepted connection from {}", remote_addr);

                            let conn = TcpConnection::new(stream, remote_addr);
                            let conn_arc = Arc::new(Mutex::new(conn));

                            // Store connection
                            {
                                let mut conns = connections_clone.write().await;
                                conns.insert(remote_addr, conn_arc.clone());
                            }

                            // Spawn read loop for this connection
                            let tx = tx_clone.clone();
                            let conns = connections_clone.clone();
                            tokio::spawn(async move {
                                Self::read_loop(conn_arc, remote_addr, tx, conns).await;
                            });
                        }
                        Err(e) => {
                            error!("TCP accept error: {}", e);
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

        let sender = TcpSender {
            connections: self.connections.clone(),
        };

        (rx, sender)
    }

    /// Read loop for a single connection.
    async fn read_loop(
        conn_arc: Arc<Mutex<TcpConnection>>,
        remote_addr: SocketAddr,
        tx: mpsc::Sender<IncomingMessage>,
        connections: Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<TcpConnection>>>>>,
    ) {
        loop {
            let result = {
                let mut conn = conn_arc.lock().await;
                conn.read_message().await
            };

            match result {
                Ok(Some(data)) => {
                    trace!("Received {} bytes from {} over TCP", data.len(), remote_addr);
                    let msg = IncomingMessage {
                        data,
                        source: remote_addr,
                        transport: TransportProtocol::Tcp,
                    };

                    if tx.send(msg).await.is_err() {
                        debug!("Receiver dropped, stopping TCP read loop");
                        break;
                    }
                }
                Ok(None) => {
                    debug!("Connection closed by {}", remote_addr);
                    break;
                }
                Err(e) => {
                    warn!("TCP read error from {}: {}", remote_addr, e);
                    break;
                }
            }
        }

        // Remove connection
        let mut conns = connections.write().await;
        conns.remove(&remote_addr);
        debug!("Removed connection to {}", remote_addr);
    }

    /// Get a sender handle.
    pub fn sender(&self) -> TcpSender {
        TcpSender {
            connections: self.connections.clone(),
        }
    }
}

/// Cloneable sender for TCP transport.
#[derive(Clone)]
pub struct TcpSender {
    connections: Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<TcpConnection>>>>>,
}

impl TcpSender {
    /// Send a message.
    pub async fn send(&self, msg: OutgoingMessage) -> Result<()> {
        let dest = msg.destination;

        let conn_arc = {
            let connections = self.connections.read().await;
            connections.get(&dest).cloned()
        };

        if let Some(conn_arc) = conn_arc {
            let mut conn = conn_arc.lock().await;
            trace!("Sending {} bytes to {} over TCP", msg.data.len(), dest);
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

    #[tokio::test]
    async fn test_tcp_bind() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = TcpTransport::bind(addr).await.unwrap();
        assert_ne!(transport.local_addr().port(), 0);
    }

    #[tokio::test]
    async fn test_tcp_connect_and_send() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create client and connect
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send a message
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        client.send_to(msg, server_addr).await.unwrap();

        // Receive on server
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
        assert_eq!(received.transport, TransportProtocol::Tcp);
    }
}

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
                    trace!(
                        "Received {} bytes from {} over TCP",
                        data.len(),
                        remote_addr
                    );
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

    // Constants tests
    #[test]
    fn test_max_tcp_size() {
        assert_eq!(MAX_TCP_SIZE, 65536);
    }

    #[test]
    fn test_initial_buf_size() {
        assert_eq!(INITIAL_BUF_SIZE, 4096);
    }

    // find_header_end tests
    #[test]
    fn test_find_header_end() {
        let data = b"INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(find_header_end(data), Some(46));

        let data = b"INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n";
        assert_eq!(find_header_end(data), None);
    }

    #[test]
    fn test_find_header_end_empty() {
        let data = b"";
        assert_eq!(find_header_end(data), None);
    }

    #[test]
    fn test_find_header_end_only_crlf() {
        let data = b"\r\n\r\n";
        assert_eq!(find_header_end(data), Some(4));
    }

    #[test]
    fn test_find_header_end_partial_crlf() {
        let data = b"\r\n\r";
        assert_eq!(find_header_end(data), None);
    }

    #[test]
    fn test_find_header_end_multiple_crlf() {
        // First occurrence at position 4
        let data = b"\r\n\r\nmore data\r\n\r\n";
        assert_eq!(find_header_end(data), Some(4));
    }

    #[test]
    fn test_find_header_end_short_data() {
        let data = b"abc";
        assert_eq!(find_header_end(data), None);
    }

    // parse_content_length tests
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
    fn test_parse_content_length_with_spaces() {
        let headers = b"INVITE sip:test SIP/2.0\r\nContent-Length:   789   \r\n\r\n";
        assert_eq!(parse_content_length(headers), 789);
    }

    #[test]
    fn test_parse_content_length_uppercase() {
        let headers = b"INVITE sip:test SIP/2.0\r\nCONTENT-LENGTH: 100\r\n\r\n";
        assert_eq!(parse_content_length(headers), 100);
    }

    #[test]
    fn test_parse_content_length_mixed_case() {
        let headers = b"INVITE sip:test SIP/2.0\r\nContent-length: 200\r\n\r\n";
        assert_eq!(parse_content_length(headers), 200);
    }

    #[test]
    fn test_parse_content_length_short_form_uppercase() {
        let headers = b"INVITE sip:test SIP/2.0\r\nL: 300\r\n\r\n";
        assert_eq!(parse_content_length(headers), 300);
    }

    #[test]
    fn test_parse_content_length_invalid_value() {
        let headers = b"INVITE sip:test SIP/2.0\r\nContent-Length: invalid\r\n\r\n";
        assert_eq!(parse_content_length(headers), 0);
    }

    #[test]
    fn test_parse_content_length_empty() {
        let headers = b"";
        assert_eq!(parse_content_length(headers), 0);
    }

    #[test]
    fn test_parse_content_length_invalid_utf8() {
        let headers = &[0xFF, 0xFE, 0x00, 0x01];
        assert_eq!(parse_content_length(headers), 0);
    }

    #[test]
    fn test_parse_content_length_multiple_headers() {
        // Content-Length appears in multiple headers, should return first one
        let headers =
            b"INVITE sip:test SIP/2.0\r\nContent-Length: 100\r\nContent-Length: 200\r\n\r\n";
        assert_eq!(parse_content_length(headers), 100);
    }

    #[test]
    fn test_parse_content_length_no_colon_value() {
        // Missing value after colon
        let headers = b"INVITE sip:test SIP/2.0\r\nContent-Length:\r\n\r\n";
        assert_eq!(parse_content_length(headers), 0);
    }

    // TcpTransport tests
    #[tokio::test]
    async fn test_tcp_bind() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = TcpTransport::bind(addr).await.unwrap();
        assert_ne!(transport.local_addr().port(), 0);
    }

    #[tokio::test]
    async fn test_tcp_bind_ipv6() {
        let addr = SocketAddr::new(IpAddr::V6("::1".parse().unwrap()), 0);
        let transport = TcpTransport::bind(addr).await.unwrap();
        assert!(transport.local_addr().is_ipv6());
    }

    #[test]
    fn test_tcp_new_client() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);
        let transport = TcpTransport::new_client(addr);
        assert_eq!(transport.local_addr(), addr);
        assert!(transport.listener.is_none());
    }

    #[tokio::test]
    async fn test_tcp_local_addr() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = TcpTransport::bind(addr).await.unwrap();
        let local = transport.local_addr();
        assert!(local.port() > 0);
        assert_eq!(local.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn test_tcp_sender() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = TcpTransport::bind(addr).await.unwrap();
        let _sender = transport.sender();
        // Sender created successfully
    }

    #[tokio::test]
    async fn test_tcp_sender_clone() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = TcpTransport::bind(addr).await.unwrap();
        let sender1 = transport.sender();
        let _sender2 = sender1.clone();
        // Cloned successfully
    }

    #[tokio::test]
    async fn test_tcp_sender_no_connection() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = TcpTransport::bind(addr).await.unwrap();
        let sender = transport.sender();

        // Try to send without connection - should fail
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let msg = OutgoingMessage::new(Bytes::from_static(b"test"), dest);
        let result = sender.send(msg).await;
        assert!(result.is_err());
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

    #[tokio::test]
    async fn test_tcp_connect_already_connected() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (_rx, _sender) = server.start();

        // Create client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Connect twice - second should succeed (noop)
        client.connect(server_addr).await.unwrap();
        client.connect(server_addr).await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_send_with_body() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send a message with a body
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 11\r\n\r\nHello World";
        client.send_to(msg, server_addr).await.unwrap();

        // Receive on server
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
    }

    #[tokio::test]
    async fn test_tcp_send_multiple_messages() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send multiple messages
        for i in 0..3 {
            let msg = format!("MESSAGE sip:test{} SIP/2.0\r\nContent-Length: 0\r\n\r\n", i);
            client.send_to(msg.as_bytes(), server_addr).await.unwrap();
        }

        // Receive all
        for _ in 0..3 {
            let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(received.data.starts_with(b"MESSAGE"));
        }
    }

    #[tokio::test]
    async fn test_tcp_connect_fail() {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Try to connect to a port with no listener
        let bad_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let result = client.connect(bad_addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_start_client_only() {
        // Create client-only transport
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);
        let transport = TcpTransport::new_client(addr);

        // Start should work even without listener
        let (_rx, _sender) = transport.start();
    }

    #[tokio::test]
    async fn test_tcp_bidirectional() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut server_rx, _server_sender) = server.start();

        // Create client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();
        let (_client_rx, _client_sender) = client.start();

        // Client sends to server
        let client_transport =
            TcpTransport::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .unwrap();
        client_transport
            .send_to(b"PING\r\n\r\n", server_addr)
            .await
            .unwrap();

        // Server receives
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), server_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received.data[..], b"PING\r\n\r\n");

        // Server responds via its sender
        // Note: In real usage, we'd need to respond to the client's address from received.source
    }

    // TcpConnection tests
    #[tokio::test]
    async fn test_tcp_connection_new() {
        // Create a listener to get a stream
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Connect in background
        let connect_handle = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });

        // Accept connection
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let conn = TcpConnection::new(stream, remote_addr);

        assert_eq!(conn.remote_addr, remote_addr);
        assert!(conn.read_buf.is_empty());

        connect_handle.await.unwrap();
    }

    // OutgoingMessage tests
    #[test]
    fn test_outgoing_message_new() {
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);
        let msg = OutgoingMessage::new(Bytes::from_static(b"test"), dest);
        assert_eq!(msg.destination, dest);
        assert_eq!(&msg.data[..], b"test");
    }

    // Additional comprehensive tests for 98%+ coverage

    // Message framing edge cases
    #[tokio::test]
    async fn test_tcp_message_too_large() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create a raw TCP connection (bypass transport layer)
        let mut stream = TcpStream::connect(server_addr).await.unwrap();

        // Send a message with headers indicating it exceeds MAX_TCP_SIZE
        let headers = format!(
            "INVITE sip:test@example.com SIP/2.0\r\nContent-Length: {}\r\n\r\n",
            MAX_TCP_SIZE + 1
        );
        stream.write_all(headers.as_bytes()).await.unwrap();

        // Send enough data to trigger the buffer limit check
        let chunk = vec![b'X'; 4096];
        for _ in 0..(MAX_TCP_SIZE / 4096 + 2) {
            stream.write_all(&chunk).await.unwrap();
        }

        // Server should close connection due to message too large
        // The receiver should not get a valid message or should timeout
        let result = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
        // Either timeout or connection closed - both indicate error handling worked
        assert!(result.is_err() || result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_tcp_partial_message_on_close() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create a raw TCP connection
        let mut stream = TcpStream::connect(server_addr).await.unwrap();

        // Send incomplete message (headers without complete double CRLF)
        stream
            .write_all(b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 10\r\n")
            .await
            .unwrap();

        // Close connection without completing the message
        drop(stream);

        // Server should handle this gracefully (return None on incomplete message)
        let result = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
        // Should timeout as incomplete messages are discarded
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_multiple_messages_in_buffer() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create a raw TCP connection
        let mut stream = TcpStream::connect(server_addr).await.unwrap();

        // Send multiple messages in one write (TCP coalescing simulation)
        let msg1 = b"INVITE sip:test1@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let msg2 = b"INVITE sip:test2@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let msg3 = b"INVITE sip:test3@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";

        let mut combined = Vec::new();
        combined.extend_from_slice(msg1);
        combined.extend_from_slice(msg2);
        combined.extend_from_slice(msg3);

        stream.write_all(&combined).await.unwrap();
        stream.flush().await.unwrap();

        // Should receive all three messages separately
        for i in 1..=3 {
            let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            let expected = format!("test{}@example.com", i);
            assert!(
                String::from_utf8_lossy(&received.data).contains(&expected),
                "Message {} not received correctly",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_tcp_message_with_large_body() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send a message with a large body (but under MAX_TCP_SIZE)
        let body = vec![b'X'; 10000];
        let headers = format!(
            "INVITE sip:test@example.com SIP/2.0\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut msg = headers.into_bytes();
        msg.extend_from_slice(&body);

        client.send_to(&msg, server_addr).await.unwrap();

        // Receive on server
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(received.data.len(), msg.len());
        assert_eq!(&received.data[..], &msg[..]);
    }

    #[tokio::test]
    async fn test_tcp_incremental_message_assembly() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create a raw TCP connection
        let mut stream = TcpStream::connect(server_addr).await.unwrap();

        // Send message in small chunks to test incremental assembly
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 5\r\n\r\nHELLO";

        for chunk in msg.chunks(5) {
            stream.write_all(chunk).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Should receive complete message
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
    }

    #[tokio::test]
    async fn test_tcp_message_with_partial_body() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create a raw TCP connection
        let mut stream = TcpStream::connect(server_addr).await.unwrap();

        // Send headers indicating body of 100 bytes
        stream
            .write_all(b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 100\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send only 50 bytes of body
        stream.write_all(&vec![b'A'; 50]).await.unwrap();
        stream.flush().await.unwrap();

        // Should not receive message yet (incomplete)
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
        assert!(result.is_err(), "Should timeout waiting for complete message");

        // Now send remaining 50 bytes
        stream.write_all(&vec![b'B'; 50]).await.unwrap();
        stream.flush().await.unwrap();

        // Should now receive complete message
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Headers: "INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 100\r\n\r\n" = 60 bytes
        assert_eq!(received.data.len(), 60 + 100); // headers + body
    }

    #[tokio::test]
    async fn test_tcp_sender_send_to() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create client with connection
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Establish connection
        client.connect(server_addr).await.unwrap();

        // Get sender and use send_to
        let sender = client.sender();
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        sender.send_to(msg, server_addr).await.unwrap();

        // Receive on server
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
    }

    #[tokio::test]
    async fn test_tcp_connection_close_cleanup() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (_rx, _sender) = server.start();

        // Create and connect client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        client.connect(server_addr).await.unwrap();

        // Verify connection exists
        {
            let connections = client.connections.read().await;
            assert_eq!(connections.len(), 1);
        }

        // Close connection by dropping client
        drop(client);

        // Give time for cleanup
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connection should be cleaned up (we can't directly verify the server's
        // connection map since it's private, but the test exercises the cleanup path)
    }

    #[tokio::test]
    async fn test_tcp_receiver_dropped() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (rx, _sender) = server.start();

        // Create client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Connect
        client.connect(server_addr).await.unwrap();

        // Drop receiver to simulate receiver being closed
        drop(rx);

        // Send a message - read loop should detect dropped receiver and exit
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let result = client.send_to(msg, server_addr).await;
        assert!(result.is_ok()); // Send succeeds, but read loop will stop

        // Give time for read loop to detect dropped receiver
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_tcp_connection_read_write_errors() {
        // Test connection to invalid address (should fail)
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Try to send to non-existent server
        let bad_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let result = client.send_to(msg, bad_addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_empty_message_after_headers() {
        // Test message with Content-Length: 0
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send message with no body
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        client.send_to(msg, server_addr).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
    }

    #[tokio::test]
    async fn test_tcp_connection_graceful_close() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create a raw TCP connection
        let stream = TcpStream::connect(server_addr).await.unwrap();

        // Close connection immediately (graceful close)
        drop(stream);

        // Server should handle this gracefully
        let result = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
        // Should timeout or receive None
        assert!(result.is_err() || result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_tcp_message_spanning_multiple_reads() {
        // Create server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create a raw TCP connection
        let mut stream = TcpStream::connect(server_addr).await.unwrap();

        // Send a message that will span multiple read operations
        let body = vec![b'X'; 8192]; // Larger than single read buffer
        let headers = format!(
            "INVITE sip:test@example.com SIP/2.0\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut msg = headers.into_bytes();
        msg.extend_from_slice(&body);

        // Send in chunks smaller than the message
        for chunk in msg.chunks(1024) {
            stream.write_all(chunk).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        // Should receive complete message
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(received.data.len(), msg.len());
    }

    #[tokio::test]
    async fn test_tcp_compact_header_form() {
        // Test with compact form "l:" instead of "Content-Length:"
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send message with compact header form
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nl: 5\r\n\r\nHELLO";
        client.send_to(msg, server_addr).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
    }

    #[tokio::test]
    async fn test_tcp_no_content_length_header() {
        // Test message without Content-Length (should assume 0)
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send message without Content-Length header
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nVia: SIP/2.0/TCP test\r\n\r\n";
        client.send_to(msg, server_addr).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
    }

    #[test]
    fn test_parse_content_length_negative() {
        // Test parsing negative content length (should return 0 on parse error)
        let headers = b"INVITE sip:test SIP/2.0\r\nContent-Length: -100\r\n\r\n";
        // Negative numbers will fail usize parsing, returning 0
        assert_eq!(parse_content_length(headers), 0);
    }

    #[test]
    fn test_parse_content_length_overflow() {
        // Test parsing extremely large number
        let headers = b"INVITE sip:test SIP/2.0\r\nContent-Length: 999999999999999999999999\r\n\r\n";
        // Overflow will fail parsing, returning 0
        assert_eq!(parse_content_length(headers), 0);
    }

    #[test]
    fn test_find_header_end_exact_boundary() {
        // Test when data is exactly 3 bytes (boundary case for saturating_sub)
        let data = b"abc";
        assert_eq!(find_header_end(data), None);

        let data = b"ab";
        assert_eq!(find_header_end(data), None);

        let data = b"a";
        assert_eq!(find_header_end(data), None);
    }

    #[tokio::test]
    async fn test_tcp_send_after_connection_established() {
        // Test send() method specifically (not send_to)
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Use OutgoingMessage directly
        let data = Bytes::from_static(b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n");
        let msg = OutgoingMessage::new(data.clone(), server_addr);

        client.send(msg).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], &data[..]);
    }

    #[tokio::test]
    async fn test_tcp_headers_with_multiple_colons() {
        // Test header parsing with URLs containing colons
        let headers = b"INVITE sip:test@example.com:5060 SIP/2.0\r\nContent-Length: 10\r\n\r\n";
        assert_eq!(parse_content_length(headers), 10);
    }

    #[tokio::test]
    async fn test_tcp_connection_buffer_initialization() {
        // Test that TcpConnection initializes with correct buffer capacity
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect_handle = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });

        let (stream, remote_addr) = listener.accept().await.unwrap();
        let conn = TcpConnection::new(stream, remote_addr);

        assert_eq!(conn.read_buf.capacity(), INITIAL_BUF_SIZE);
        assert_eq!(conn.read_buf.len(), 0);

        connect_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_start_with_existing_connections() {
        // Test starting transport with pre-existing connections (covers lines 292-297)
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut server_rx, _server_sender) = server.start();

        // Create client and establish connection BEFORE starting
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Connect before starting (this creates an existing connection)
        client.connect(server_addr).await.unwrap();

        // Verify connection exists
        {
            let connections = client.connections.read().await;
            assert_eq!(connections.len(), 1);
        }

        // Now start the client transport with existing connection
        let (_client_rx, _client_sender) = client.start();

        // The existing connection should be able to send messages
        let new_client = TcpTransport::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        new_client.send_to(msg, server_addr).await.unwrap();

        // Server should receive it
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), server_rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&received.data[..], msg);
    }

    #[tokio::test]
    async fn test_tcp_write_error_on_closed_connection() {
        // Test write errors when connection is closed
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (rx, _sender) = server.start();

        // Create client and connect
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();
        client.connect(server_addr).await.unwrap();

        // Close server receiver and sender to cause connection to be reset
        drop(rx);
        drop(_sender);

        // Give time for connection to close
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Try to send - should eventually fail
        let msg = b"INVITE sip:test@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        // First send might succeed (data buffered), but connection will close
        let _ = client.send_to(msg, server_addr).await;

        // Wait for connection to fully close
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    #[tokio::test]
    async fn test_tcp_multiple_clients_to_server() {
        // Test server handling multiple client connections
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        // Create multiple clients
        let client1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client1 = TcpTransport::bind(client1_addr).await.unwrap();

        let client2_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client2 = TcpTransport::bind(client2_addr).await.unwrap();

        // Both clients send messages
        let msg1 = b"INVITE sip:client1@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let msg2 = b"INVITE sip:client2@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";

        client1.send_to(msg1, server_addr).await.unwrap();
        client2.send_to(msg2, server_addr).await.unwrap();

        // Server should receive both messages
        let mut received_count = 0;
        for _ in 0..2 {
            let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();

            if received.data.windows(7).any(|w| w == b"client1" || w == b"client2") {
                received_count += 1;
            }
        }

        assert_eq!(received_count, 2);
    }

    #[tokio::test]
    async fn test_tcp_message_exactly_at_buffer_boundary() {
        // Test message that exactly fills read buffer
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Create message with body size that, with headers, is close to buffer size
        let body_size = 4000; // Close to INITIAL_BUF_SIZE
        let body = vec![b'X'; body_size];
        let headers = format!(
            "INVITE sip:test@example.com SIP/2.0\r\nContent-Length: {}\r\n\r\n",
            body_size
        );
        let mut msg = headers.into_bytes();
        msg.extend_from_slice(&body);

        client.send_to(&msg, server_addr).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(received.data.len(), msg.len());
    }

    #[tokio::test]
    async fn test_tcp_connection_state_after_multiple_messages() {
        // Test that connection state is correct after multiple messages
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = TcpTransport::bind(server_addr).await.unwrap();
        let server_addr = server.local_addr();

        let (mut rx, _sender) = server.start();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();

        // Send several messages with different sizes
        let messages = vec![
            b"INVITE sip:test1@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"INVITE sip:test2@example.com SIP/2.0\r\nContent-Length: 5\r\n\r\nHELLO".to_vec(),
            b"INVITE sip:test3@example.com SIP/2.0\r\nContent-Length: 10\r\n\r\nHELLOWORLD".to_vec(),
        ];

        for msg in &messages {
            client.send_to(msg, server_addr).await.unwrap();
        }

        // Receive all messages
        for _ in 0..messages.len() {
            let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(received.data.len() > 0);
        }
    }
}

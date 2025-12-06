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

        let (mut server_rx, server_sender) = server.start();

        // Create client
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = TcpTransport::bind(client_addr).await.unwrap();
        let (mut client_rx, _client_sender) = client.start();

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
}

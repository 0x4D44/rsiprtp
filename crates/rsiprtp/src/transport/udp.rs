//! UDP transport implementation.
//!
//! Provides asynchronous UDP socket for SIP message transport.

use bytes::Bytes;
use crate::core::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, trace};

use crate::transport::traits::{IncomingMessage, OutgoingMessage, TransportProtocol};

#[cfg(test)]
use std::sync::{
    atomic::{AtomicU64, Ordering},
    LazyLock, Mutex as StdMutex,
};

/// Maximum SIP message size over UDP (per RFC 3261).
/// Messages larger than this should use TCP.
pub const MAX_UDP_SIZE: usize = 65535;

/// Recommended MTU-safe size for SIP over UDP.
pub const MTU_SAFE_SIZE: usize = 1300;

// Forced-error flags use thread-id-keyed storage so parallel tests can each
// arm a forced error on their own thread without disturbing siblings. A flag
// is "armed" when its value equals the arming thread's `current_thread_id()`;
// only that thread will then consume it. Zero means "not set".
#[cfg(test)]
static FORCE_RECV_ERROR: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static FORCE_BIND_ERROR: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static FORCE_LOCAL_ADDR_ERROR: AtomicU64 = AtomicU64::new(0);
// FORCE_SEND_ERROR_DEST keys on the destination SocketAddr, not thread id;
// each test uses a unique bound port so this is already isolated.
#[cfg(test)]
static FORCE_SEND_ERROR_DEST: LazyLock<StdMutex<Option<SocketAddr>>> =
    LazyLock::new(|| StdMutex::new(None));

#[cfg(test)]
fn force_recv_error_once() {
    FORCE_RECV_ERROR.store(current_thread_id(), Ordering::SeqCst);
}

#[cfg(test)]
fn force_bind_error_once() {
    FORCE_BIND_ERROR.store(current_thread_id(), Ordering::SeqCst);
}

#[cfg(test)]
fn force_local_addr_error_once() {
    FORCE_LOCAL_ADDR_ERROR.store(current_thread_id(), Ordering::SeqCst);
}

#[cfg(test)]
fn force_send_error_once(dest: SocketAddr) {
    let mut guard = FORCE_SEND_ERROR_DEST.lock().unwrap();
    *guard = Some(dest);
}

#[cfg(test)]
fn take_forced_send_error(dest: SocketAddr) -> Option<std::io::Error> {
    let mut guard = FORCE_SEND_ERROR_DEST.lock().unwrap();
    if guard.as_ref() == Some(&dest) {
        *guard = None;
        Some(std::io::Error::other("forced send error"))
    } else {
        None
    }
}

#[cfg(test)]
fn take_forced_error(flag: &AtomicU64, message: &str) -> Option<std::io::Error> {
    let current = current_thread_id();
    if flag.load(Ordering::SeqCst) == current
        && flag
            .compare_exchange(current, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    {
        Some(std::io::Error::other(message))
    } else {
        None
    }
}

#[cfg(test)]
fn current_thread_id() -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    normalize_thread_id(hasher.finish())
}

#[cfg(test)]
fn normalize_thread_id(id: u64) -> u64 {
    if id == 0 {
        1
    } else {
        id
    }
}

async fn bind_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    #[cfg(test)]
    if let Some(err) = take_forced_error(&FORCE_BIND_ERROR, "forced bind error") {
        return Err(err);
    }
    UdpSocket::bind(addr).await
}

fn socket_local_addr(socket: &UdpSocket) -> std::io::Result<SocketAddr> {
    #[cfg(test)]
    if let Some(err) = take_forced_error(&FORCE_LOCAL_ADDR_ERROR, "forced local_addr error") {
        return Err(err);
    }
    socket.local_addr()
}

async fn socket_send_to(
    socket: &UdpSocket,
    data: &[u8],
    dest: SocketAddr,
) -> std::io::Result<usize> {
    #[cfg(test)]
    if let Some(err) = take_forced_send_error(dest) {
        return Err(err);
    }
    socket.send_to(data, dest).await
}

async fn socket_recv_from(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    #[cfg(test)]
    if let Some(err) = take_forced_error(&FORCE_RECV_ERROR, "forced recv error") {
        return Err(err);
    }
    socket.recv_from(buf).await
}

/// UDP transport for SIP messages.
pub struct UdpTransport {
    /// The UDP socket.
    socket: Arc<UdpSocket>,
    /// Local address.
    local_addr: SocketAddr,
}

impl UdpTransport {
    /// Bind to a local address and create a new UDP transport.
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = bind_socket(addr).await?;
        let local_addr = socket_local_addr(&socket)?;
        debug!("UDP transport bound to {}", local_addr);

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
        })
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Send a message to a destination.
    pub async fn send(&self, msg: OutgoingMessage) -> Result<()> {
        trace!("Sending {} bytes to {}", msg.data.len(), msg.destination);
        socket_send_to(&self.socket, &msg.data, msg.destination).await?;
        Ok(())
    }

    /// Send raw bytes to a destination.
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        trace!("Sending {} bytes to {}", data.len(), dest);
        socket_send_to(&self.socket, data, dest).await?;
        Ok(())
    }

    /// Receive a single message.
    ///
    /// Returns the message data and source address.
    pub async fn recv(&self) -> Result<IncomingMessage> {
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let (len, source) = socket_recv_from(&self.socket, &mut buf).await?;
        buf.truncate(len);

        trace!("Received {} bytes from {}", len, source);

        Ok(IncomingMessage {
            data: Bytes::from(buf),
            source,
            transport: TransportProtocol::Udp,
        })
    }

    /// Start a receive loop that sends messages to a channel.
    ///
    /// Returns a receiver for incoming messages and a handle to the socket.
    pub fn into_receiver(self) -> (mpsc::Receiver<IncomingMessage>, UdpSender) {
        let (tx, rx) = mpsc::channel(256);
        let socket = self.socket.clone();
        let recv_socket = socket.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_SIZE];
            loop {
                let recv_result = async {
                    #[cfg(test)]
                    if let Some(err) = take_forced_error(&FORCE_RECV_ERROR, "forced recv error") {
                        return Err(err);
                    }
                    recv_socket.recv_from(&mut buf).await
                }
                .await;

                match recv_result {
                    Ok((len, source)) => {
                        let data = Bytes::from(buf[..len].to_vec());
                        trace!("Received {} bytes from {}", len, source);

                        let msg = IncomingMessage {
                            data,
                            source,
                            transport: TransportProtocol::Udp,
                        };

                        if tx.send(msg).await.is_err() {
                            debug!("Receiver dropped, stopping UDP receive loop");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("UDP receive error: {}", e);
                        // Continue receiving despite errors
                    }
                }
            }
        });

        (rx, UdpSender { socket })
    }

    /// Get a sender handle that can be cloned.
    pub fn sender(&self) -> UdpSender {
        UdpSender {
            socket: self.socket.clone(),
        }
    }
}

/// Cloneable sender for UDP transport.
#[derive(Clone)]
pub struct UdpSender {
    socket: Arc<UdpSocket>,
}

impl UdpSender {
    /// Send a message.
    pub async fn send(&self, msg: OutgoingMessage) -> Result<()> {
        trace!("Sending {} bytes to {}", msg.data.len(), msg.destination);
        socket_send_to(&self.socket, &msg.data, msg.destination).await?;
        Ok(())
    }

    /// Send raw bytes to a destination.
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        trace!("Sending {} bytes to {}", data.len(), dest);
        socket_send_to(&self.socket, data, dest).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Once;
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

    // Constants tests
    #[test]
    fn test_max_udp_size() {
        assert_eq!(MAX_UDP_SIZE, 65535);
    }

    #[test]
    fn test_mtu_safe_size() {
        assert_eq!(MTU_SAFE_SIZE, 1300);
    }

    // UdpTransport tests
    #[tokio::test]
    async fn test_udp_bind() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = UdpTransport::bind(addr).await.unwrap();
        assert_ne!(transport.local_addr().port(), 0);
    }

    #[tokio::test]
    async fn test_udp_bind_ipv6() {
        let addr = SocketAddr::new(IpAddr::V6("::1".parse().unwrap()), 0);
        let transport = UdpTransport::bind(addr).await.unwrap();
        assert!(transport.local_addr().is_ipv6());
    }

    #[tokio::test]
    async fn test_udp_bind_forced_error() {
        force_bind_error_once();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let result = UdpTransport::bind(addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_udp_bind_forced_local_addr_error() {
        force_local_addr_error_once();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let result = UdpTransport::bind(addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_udp_local_addr() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = UdpTransport::bind(addr).await.unwrap();
        let local = transport.local_addr();
        assert!(local.port() > 0);
        assert_eq!(local.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn test_udp_recv_error_logged() {
        init_tracing();
        force_recv_error_once();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = UdpTransport::bind(addr).await.unwrap();

        let (_rx, _sender) = transport.into_receiver();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn test_udp_recv_forced_error() {
        force_recv_error_once();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = UdpTransport::bind(addr).await.unwrap();
        let result = transport.recv().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_udp_send() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let t1 = UdpTransport::bind(addr1).await.unwrap();
        let t2 = UdpTransport::bind(addr2).await.unwrap();
        let t2_addr = t2.local_addr();

        // Send using OutgoingMessage
        let msg = OutgoingMessage::new(Bytes::from_static(b"SIP/2.0 200 OK\r\n\r\n"), t2_addr);
        t1.send(msg).await.unwrap();

        // Receive on t2
        let received = t2.recv().await.unwrap();
        assert_eq!(&received.data[..], b"SIP/2.0 200 OK\r\n\r\n");
    }

    #[tokio::test]
    async fn test_udp_send_forced_error() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = UdpTransport::bind(addr).await.unwrap();

        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        force_send_error_once(dest);
        let msg = OutgoingMessage::new(Bytes::from_static(b"test"), dest);
        let result = transport.send(msg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_udp_send_to_forced_error() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = UdpTransport::bind(addr).await.unwrap();

        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        force_send_error_once(dest);
        let result = transport.send_to(b"test", dest).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_udp_send_recv() {
        // Create two transports
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let t1 = UdpTransport::bind(addr1).await.unwrap();
        let t2 = UdpTransport::bind(addr2).await.unwrap();

        let t1_addr = t1.local_addr();
        let t2_addr = t2.local_addr();

        // Send from t1 to t2
        let data = b"INVITE sip:test@example.com SIP/2.0\r\n\r\n";
        t1.send_to(data, t2_addr).await.unwrap();

        // Receive on t2
        let msg = t2.recv().await.unwrap();
        assert_eq!(msg.source, t1_addr);
        assert_eq!(&msg.data[..], data);
        assert_eq!(msg.transport, TransportProtocol::Udp);
    }

    #[tokio::test]
    async fn test_udp_send_recv_large() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let t1 = UdpTransport::bind(addr1).await.unwrap();
        let t2 = UdpTransport::bind(addr2).await.unwrap();
        let t2_addr = t2.local_addr();

        // Send a larger message (close to MTU_SAFE_SIZE)
        let data = vec![b'X'; MTU_SAFE_SIZE];
        t1.send_to(&data, t2_addr).await.unwrap();

        let received = t2.recv().await.unwrap();
        assert_eq!(received.data.len(), MTU_SAFE_SIZE);
    }

    #[tokio::test]
    async fn test_udp_receiver_drop_stops_loop() {
        let receiver_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let sender_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let receiver = UdpTransport::bind(receiver_addr).await.unwrap();
        let receiver_addr = receiver.local_addr();
        let (rx, _sender) = receiver.into_receiver();
        drop(rx);

        let sender = UdpTransport::bind(sender_addr).await.unwrap();
        sender.send_to(b"ping", receiver_addr).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn test_udp_sender() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let t1 = UdpTransport::bind(addr1).await.unwrap();
        let t2 = UdpTransport::bind(addr2).await.unwrap();

        let sender = t1.sender();
        let t2_addr = t2.local_addr();

        // Send using the sender
        let msg = OutgoingMessage::new(Bytes::from_static(b"TEST"), t2_addr);
        sender.send(msg).await.unwrap();

        // Receive
        let received = t2.recv().await.unwrap();
        assert_eq!(&received.data[..], b"TEST");
    }

    #[tokio::test]
    async fn test_udp_sender_clone() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let t1 = UdpTransport::bind(addr1).await.unwrap();
        let t2 = UdpTransport::bind(addr2).await.unwrap();

        let sender1 = t1.sender();
        let sender2 = sender1.clone();
        let t2_addr = t2.local_addr();

        // Send using the cloned sender
        sender2.send_to(b"CLONED", t2_addr).await.unwrap();

        let received = t2.recv().await.unwrap();
        assert_eq!(&received.data[..], b"CLONED");
    }

    #[tokio::test]
    async fn test_udp_sender_send_to() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let t1 = UdpTransport::bind(addr1).await.unwrap();
        let t2 = UdpTransport::bind(addr2).await.unwrap();

        let sender = t1.sender();
        let t2_addr = t2.local_addr();

        // Send raw bytes using sender
        sender.send_to(b"RAW_BYTES", t2_addr).await.unwrap();

        let received = t2.recv().await.unwrap();
        assert_eq!(&received.data[..], b"RAW_BYTES");
    }

    #[tokio::test]
    async fn test_udp_sender_send_forced_error() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = UdpTransport::bind(addr).await.unwrap();
        let sender = transport.sender();

        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        force_send_error_once(dest);
        let msg = OutgoingMessage::new(Bytes::from_static(b"TEST"), dest);
        let result = sender.send(msg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_udp_sender_send_to_forced_error() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = UdpTransport::bind(addr).await.unwrap();
        let sender = transport.sender();

        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        force_send_error_once(dest);
        let result = sender.send_to(b"TEST", dest).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_udp_into_receiver() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let t1 = UdpTransport::bind(addr1).await.unwrap();
        let t2 = UdpTransport::bind(addr2).await.unwrap();

        let t1_addr = t1.local_addr();
        let (mut rx, sender) = t2.into_receiver();

        // Send a message to t2
        t1.send_to(b"VIA_RECEIVER", sender.socket.local_addr().unwrap())
            .await
            .unwrap();

        // Receive via the channel
        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.source, t1_addr);
        assert_eq!(&msg.data[..], b"VIA_RECEIVER");
    }

    #[tokio::test]
    async fn test_udp_into_receiver_multiple() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let t1 = UdpTransport::bind(addr1).await.unwrap();
        let t2 = UdpTransport::bind(addr2).await.unwrap();

        let t2_local = t2.local_addr();
        let (mut rx, _sender) = t2.into_receiver();

        // Send multiple messages
        for i in 0..3 {
            let data = format!("MSG_{}", i);
            t1.send_to(data.as_bytes(), t2_local).await.unwrap();
        }

        // Receive all
        for _ in 0..3 {
            let msg = rx.recv().await.unwrap();
            assert!(msg.data.starts_with(b"MSG_"));
        }
    }

    #[tokio::test]
    async fn test_udp_bidirectional() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let t1 = UdpTransport::bind(addr1).await.unwrap();
        let t2 = UdpTransport::bind(addr2).await.unwrap();

        let t1_addr = t1.local_addr();
        let t2_addr = t2.local_addr();

        // t1 -> t2
        t1.send_to(b"PING", t2_addr).await.unwrap();
        let msg = t2.recv().await.unwrap();
        assert_eq!(&msg.data[..], b"PING");

        // t2 -> t1
        t2.send_to(b"PONG", t1_addr).await.unwrap();
        let msg = t1.recv().await.unwrap();
        assert_eq!(&msg.data[..], b"PONG");
    }
}

//! UDP transport implementation.
//!
//! Provides asynchronous UDP socket for SIP message transport.

use bytes::Bytes;
use mdsiprtp_core::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, trace};

use crate::traits::{IncomingMessage, OutgoingMessage, TransportProtocol};

/// Maximum SIP message size over UDP (per RFC 3261).
/// Messages larger than this should use TCP.
pub const MAX_UDP_SIZE: usize = 65535;

/// Recommended MTU-safe size for SIP over UDP.
pub const MTU_SAFE_SIZE: usize = 1300;

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
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
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
        trace!(
            "Sending {} bytes to {}",
            msg.data.len(),
            msg.destination
        );
        self.socket.send_to(&msg.data, msg.destination).await?;
        Ok(())
    }

    /// Send raw bytes to a destination.
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        trace!("Sending {} bytes to {}", data.len(), dest);
        self.socket.send_to(data, dest).await?;
        Ok(())
    }

    /// Receive a single message.
    ///
    /// Returns the message data and source address.
    pub async fn recv(&self) -> Result<IncomingMessage> {
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let (len, source) = self.socket.recv_from(&mut buf).await?;
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

        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_SIZE];
            loop {
                match self.socket.recv_from(&mut buf).await {
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
        trace!(
            "Sending {} bytes to {}",
            msg.data.len(),
            msg.destination
        );
        self.socket.send_to(&msg.data, msg.destination).await?;
        Ok(())
    }

    /// Send raw bytes to a destination.
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        trace!("Sending {} bytes to {}", data.len(), dest);
        self.socket.send_to(data, dest).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_udp_bind() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let transport = UdpTransport::bind(addr).await.unwrap();
        assert_ne!(transport.local_addr().port(), 0);
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
    async fn test_udp_sender() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let t1 = UdpTransport::bind(addr1).await.unwrap();
        let t2 = UdpTransport::bind(addr2).await.unwrap();

        let sender = t1.sender();
        let t2_addr = t2.local_addr();

        // Send using the sender
        let msg = OutgoingMessage::new(
            Bytes::from_static(b"TEST"),
            t2_addr,
        );
        sender.send(msg).await.unwrap();

        // Receive
        let received = t2.recv().await.unwrap();
        assert_eq!(&received.data[..], b"TEST");
    }
}

//! RTP/RTCP packet handling per RFC 3550.
//!
//! # Overview
//!
//! This crate provides RTP/RTCP packet parsing, building, and session management.
//!
//! # Example
//!
//! ```
//! use mdsiprtp_rtp::{RtpPacket, RtpSession};
//!
//! // Create an RTP session
//! let mut session = RtpSession::new(12345, 0, 8000);
//!
//! // Create a packet
//! let payload = vec![0u8; 160]; // 20ms of G.711 audio
//! let packet = session.create_packet(payload, 160, true);
//!
//! // Serialize to bytes
//! let bytes = packet.build();
//! ```

pub mod dtmf;
pub mod packet;
pub mod rtcp;
pub mod session;

// Re-export main types
pub use packet::{
    ExtensionHeader, RtpPacket, RtpParseError, RTP_HEADER_SIZE, MAX_CSRC,
    sequence_diff, sequence_newer,
};
pub use rtcp::{
    Goodbye, NtpTimestamp, ReceiverReport, ReportBlock, RtcpCompound,
    RtcpPacket, RtcpParseError, RtcpType, SenderReport, SourceDescription,
};
pub use session::{ReceiverState, RtpSession};
pub use dtmf::{DtmfDigit, DtmfEvent, DtmfReceiver, DtmfSender};

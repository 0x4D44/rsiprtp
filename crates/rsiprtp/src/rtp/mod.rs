//! RTP/RTCP packet handling per RFC 3550.
//!
//! # Overview
//!
//! This crate provides RTP/RTCP packet parsing, building, and session management.
//!
//! # Example
//!
//! ```
//! use rsiprtp::rtp::{RtpPacket, RtpSession};
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

pub(crate) mod dtmf;
pub(crate) mod packet;
pub mod rtcp;
pub mod session;

#[cfg(test)]
mod tests;

// Re-export main types
pub use dtmf::{DtmfDigit, DtmfEvent, DtmfReceiver, DtmfSender};
pub use packet::{
    sequence_diff, sequence_newer, ExtensionHeader, RtpPacket, RtpParseError, MAX_CSRC,
    RTP_HEADER_SIZE,
};
pub use rtcp::{
    Goodbye, NtpTimestamp, ReceiverReport, ReportBlock, RtcpCompound, RtcpPacket, RtcpParseError,
    RtcpType, SenderReport, SourceDescription,
};
pub use session::{ReceiverState, RtpSession};

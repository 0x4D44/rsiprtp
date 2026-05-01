#![warn(missing_docs)]
//! rsiprtp - SIP/RTP stack for Rust
//!
//! A production-ready SIP/RTP communications stack designed for:
//! - Voicemail applications
//! - AI agent call bridges with mixing
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use rsiprtp::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Error> {
//!     // Create a call manager
//!     let config = ManagerConfig::default();
//!     let mut manager = CallManager::new(config);
//!
//!     // Create an outbound call
//!     let call_id = manager.create_call("sip:bob@example.com".to_string());
//!
//!     // ... handle call events ...
//!
//!     Ok(())
//! }
//! ```
//!
//! # Architecture
//!
//! The stack is organized into modules:
//!
//! - [`core`]: Common types, errors, configuration
//! - [`sip`]: SIP message parsing and building (wraps rsip)
//! - [`transaction`]: RFC 3261 transaction state machines (Sans-IO)
//! - [`dialog`]: Dialog management for INVITE sessions
//! - [`transport`]: UDP/TCP/TLS network transport
//! - [`sdp`]: SDP parsing and offer/answer negotiation
//! - [`rtp`]: RTP packet handling
//! - [`srtp`]: SRTP encryption (SDES key exchange; DTLS-SRTP framing types
//!   are present, but the DTLS handshake itself is not yet implemented)
//! - [`ice`]: ICE/STUN/TURN for NAT traversal
//! - [`media`]: Audio codecs and jitter buffer
//! - [`session`]: High-level call management

pub mod core;
pub mod dialog;
pub mod ice;
pub mod media;
pub mod rtp;
pub mod sdp;
pub mod session;
pub mod sip;
pub mod srtp;
pub mod transaction;
pub mod transport;

/// Prelude for convenient imports.
pub mod prelude {
    // Core types
    pub use crate::core::{CodecConfig, Error, Result, StackConfig};

    // Session management
    pub use crate::session::{
        Call, CallConfig, CallDirection, CallEndReason, CallEvent, CallId, CallManager, CallState,
        Dialog, ManagerConfig, ManagerEvent, MediaSession, RegistrationConfig, RegistrationError,
        RegistrationManager, RegistrationState,
    };

    // SIP messaging
    pub use crate::sip::{
        generate_branch, generate_call_id, generate_tag, DigestChallenge, DigestCredentials,
        DigestResponse, Method, SipMessage, SipRequest, SipResponse,
    };

    // SDP negotiation
    pub use crate::sdp::builder::SdpBuilder;
    pub use crate::sdp::negotiation::{Codec, NegotiatedMedia};
    pub use crate::sdp::parser::{Direction, MediaDescription, SessionDescription};

    // RTP/RTCP
    pub use crate::rtp::{ReceiverReport, RtcpCompound, RtpPacket, RtpSession, SenderReport};

    // Media
    pub use crate::media::{
        G711Codec, G711Variant, JitterBuffer, JitterBufferConfig, PlayoutDecision,
    };

    // Dialog
    pub use crate::dialog::DialogId;

    // Transport
    pub use crate::transport::UdpTransport;
}

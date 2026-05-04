#![deny(missing_docs)]
//! rsiprtp - SIP/RTP stack for Rust
//!
//! An audio-focused SIP user-agent (UA) stack designed for:
//! - Voicemail applications
//! - AI agent call bridges with mixing
//!
//! `rsiprtp` targets traditional VoIP / SIP-trunking use cases. It is **not**
//! a WebRTC stack: there is no DTLS-SRTP handshake (SDES per RFC 4568),
//! no video, and no SIP-over-WebSocket transport. See the README for the
//! full scope.
//!
//! Carrier-interop signalling features are supported: PRACK / 100rel
//! reliable provisional responses (RFC 3262, no offer/answer body in
//! PRACK; reliable provisional acks only), the UPDATE method
//! (RFC 3311), and session timers (RFC 4028) — both the refresher path
//! (UPDATE / re-INVITE refresh) and the non-refresher path (BYE on peer
//! silence) drive from the `CallManager::tick` / `next_deadline` hooks.
//!
//! Auto-detection of `Allow:` lacking UPDATE on the 200 OK is not
//! implemented; the app calls
//! [`session::CallManager::note_update_unsupported`] on observing a
//! 405 / 501 to UPDATE, or after parsing the 200 OK's Allow header
//! itself.
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
//! - [`sip`]: SIP message parsing and building (in-tree parser)
//! - [`transaction`]: RFC 3261 transaction state machines (Sans-IO)
//! - [`dialog`]: Dialog management for INVITE sessions
//! - [`transport`]: UDP/TCP/TLS network transport
//! - [`sdp`]: SDP parsing and offer/answer negotiation
//! - [`rtp`]: RTP packet handling
//! - [`srtp`]: SRTP encryption with SDES key exchange (RFC 4568)
//! - [`ice`]: ICE/STUN/TURN for NAT traversal (host + server-reflexive
//!   candidates; TURN relay candidates, trickle, ICE restart, IPv6
//!   dual-stack interop, symmetric-NAT prflx, and RFC 7675 consent
//!   freshness are not yet supported). Drive it via
//!   [`session::IceSession`] alongside [`session::CallManager`].
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
        Dialog, InboundSessionTimer, InviteOfferHeaders, ManagerConfig, ManagerEvent, MediaSession,
        OutboundRequest, OutboundRequestKind, RegistrationConfig, RegistrationError,
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
    pub use crate::transport::{ResolvedTarget, SipResolver, TransportProtocol, UdpTransport};
}

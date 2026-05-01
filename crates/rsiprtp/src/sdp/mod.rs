//! SDP (Session Description Protocol) handling.
//!
//! Implements SDP parsing, building, and the offer/answer model per RFC 3264.
//!
//! # Overview
//!
//! This crate provides:
//! - SDP parsing (`SessionDescription::parse`)
//! - SDP building (`SdpBuilder`)
//! - Offer/answer negotiation (`create_answer`, `process_answer`)
//!
//! # Example
//!
//! ```
//! use rsiprtp::sdp::{SessionDescription, SdpBuilder, MediaBuilder, Codec, create_answer};
//! use std::net::{IpAddr, Ipv4Addr};
//!
//! // Build an SDP offer
//! let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
//! let offer = SdpBuilder::new(addr)
//!     .add_media(MediaBuilder::audio(49170).pcmu().pcma())
//!     .build();
//!
//! // Parse SDP from string
//! let sdp_str = offer.to_string();
//! let parsed = SessionDescription::parse(&sdp_str).unwrap();
//! ```

pub mod builder;
pub mod negotiation;
pub mod parser;

#[cfg(test)]
mod tests;

// Re-export main types
pub use builder::{MediaBuilder, SdpBuilder};
pub use negotiation::{create_answer, process_answer, Codec, NegotiatedMedia};
pub use parser::{
    Attribute, Connection, Direction, Fmtp, MediaDescription, MediaType, Origin, RtpMap,
    SdpParseError, SessionDescription, Timing,
};

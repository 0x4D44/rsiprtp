//! SRTP (Secure Real-time Transport Protocol) implementation.
//!
//! Implements RFC 3711 (SRTP) and RFC 4568 (SDES for key exchange).
//!
//! # Overview
//!
//! This crate provides SRTP encryption and decryption for RTP packets.
//! Keys are exchanged using SDES (Session Description Protocol Security
//! Descriptions) as defined in RFC 4568.
//!
//! # Example
//!
//! ```rust,ignore
//! use rsiprtp::srtp::{SrtpContext, CryptoSuite, SdesAttribute};
//!
//! // Parse SDES attribute from SDP
//! let sdes = SdesAttribute::parse("1 AES_CM_128_HMAC_SHA1_80 inline:base64key")?;
//!
//! // Create SRTP context
//! let mut ctx = SrtpContext::new(sdes.crypto_suite, &sdes.master_key, &sdes.master_salt)?;
//!
//! // Encrypt RTP packet
//! let encrypted = ctx.protect(&rtp_packet)?;
//!
//! // Decrypt SRTP packet
//! let decrypted = ctx.unprotect(&srtp_packet)?;
//! ```

mod context;
pub mod dtls;
mod kdf;
mod sdes;

pub use context::{SrtcpContext, SrtpContext};
pub use dtls::{
    DtlsConfig, DtlsError, DtlsRole, DtlsSrtpKeys, DtlsState, Fingerprint, FingerprintHash,
    SrtpProfile,
};
pub use kdf::{CryptoSuite, SessionKeys};
pub use sdes::SdesAttribute;

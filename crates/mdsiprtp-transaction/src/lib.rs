//! RFC 3261 SIP transaction layer implementation.
//!
//! This crate implements the SIP transaction layer as a Sans-IO state machine.
//! The transaction layer handles retransmissions, timeouts, and message matching.

pub mod timer;
pub mod client;
pub mod server;
pub mod manager;

// TODO: Export main types

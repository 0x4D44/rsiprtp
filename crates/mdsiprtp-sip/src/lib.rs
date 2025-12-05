//! SIP message parsing and building for mdsiprtp.
//!
//! This crate wraps the `rsip` crate and provides convenience methods
//! for common SIP operations.

pub mod message;
pub mod headers;
pub mod uri;

pub use message::*;

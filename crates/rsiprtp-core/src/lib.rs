//! Core types, errors, and configuration for the rsiprtp SIP/RTP stack.

pub mod config;
pub mod error;
pub mod util;

pub use config::*;
pub use error::*;
pub use util::{random_u16, random_u32, random_u64};

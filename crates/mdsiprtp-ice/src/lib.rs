//! STUN/ICE implementation for NAT traversal.
//!
//! This crate provides:
//! - STUN client (RFC 5389) for server reflexive address discovery
//! - ICE agent (RFC 8445) for connectivity checks
//! - ICE candidate types and utilities
//!
//! # Example
//!
//! ```rust,ignore
//! use mdsiprtp_ice::{IceAgent, IceConfig, IceRole, StunServer};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create ICE agent
//!     let config = IceConfig::default();
//!     let agent = IceAgent::new(config, IceRole::Controlling);
//!
//!     // Gather local candidates
//!     let candidates = agent.gather_candidates().await?;
//!     println!("Gathered {} candidates", candidates.len());
//!
//!     Ok(())
//! }
//! ```

pub mod agent;
pub mod candidate;
pub mod stun;
pub mod turn;

pub use agent::{CandidatePair, IceAgent, IceConfig, IceError, IceRole, IceState, PairState};
pub use candidate::{Candidate, CandidateType, Transport};
pub use stun::{StunClient, StunError, StunServer};
pub use turn::{TurnAllocation, TurnClient, TurnError, TurnServer};

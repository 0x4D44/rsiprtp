//! RFC 3261 SIP transaction layer implementation.
//!
//! This crate implements the SIP transaction layer as a Sans-IO state machine.
//! The transaction layer handles retransmissions, timeouts, and message matching.
//!
//! # Overview
//!
//! The transaction layer sits between the transport layer and the transaction user (TU).
//! It provides reliable request/response matching and retransmission handling.
//!
//! # Client Transactions
//!
//! - [`InviteClientTransaction`]: Handles outgoing INVITE requests (RFC 3261 Section 17.1.1)
//! - [`NonInviteClientTransaction`]: Handles outgoing non-INVITE requests (RFC 3261 Section 17.1.2)
//!
//! # Server Transactions
//!
//! - [`InviteServerTransaction`]: Handles incoming INVITE requests (RFC 3261 Section 17.2.1)
//! - [`NonInviteServerTransaction`]: Handles incoming non-INVITE requests (RFC 3261 Section 17.2.2)
//!
//! # Transaction Manager
//!
//! The [`TransactionManager`] coordinates multiple transactions and routes messages
//! to the appropriate transaction based on transaction ID matching.

pub mod timer;
pub mod client;
pub mod server;
pub mod manager;

// Re-export main types
pub use timer::{Timer, TimerValues, ActiveTimer};
pub use client::invite::{TransactionId, InviteClientTransaction};
pub use client::invite::{State as InviteClientState, Action as InviteClientAction, Event as InviteClientEvent};
pub use client::non_invite::NonInviteClientTransaction;
pub use client::non_invite::{State as NonInviteClientState, Action as NonInviteClientAction, Event as NonInviteClientEvent};
pub use server::invite::InviteServerTransaction;
pub use server::invite::{State as InviteServerState, Action as InviteServerAction, Event as InviteServerEvent};
pub use server::non_invite::NonInviteServerTransaction;
pub use server::non_invite::{State as NonInviteServerState, Action as NonInviteServerAction, Event as NonInviteServerEvent};
pub use manager::{TransactionManager, TransactionHandle, TransactionType, ManagerAction, ManagerEvent};

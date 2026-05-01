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

pub mod client;
pub mod manager;
pub mod server;
pub mod timer;

// Re-export main types
pub use client::invite::{
    Action as InviteClientAction, Event as InviteClientEvent, State as InviteClientState,
};
pub use client::invite::{InviteClientTransaction, TransactionId};
pub use client::non_invite::NonInviteClientTransaction;
pub use client::non_invite::{
    Action as NonInviteClientAction, Event as NonInviteClientEvent, State as NonInviteClientState,
};
pub use manager::{
    ManagerAction, ManagerEvent, TransactionHandle, TransactionManager, TransactionType,
};
pub use server::invite::InviteServerTransaction;
pub use server::invite::{
    Action as InviteServerAction, Event as InviteServerEvent, State as InviteServerState,
};
pub use server::non_invite::NonInviteServerTransaction;
pub use server::non_invite::{
    Action as NonInviteServerAction, Event as NonInviteServerEvent, State as NonInviteServerState,
};
pub use timer::{ActiveTimer, Timer, TimerValues};

#[cfg(test)]
mod tests;

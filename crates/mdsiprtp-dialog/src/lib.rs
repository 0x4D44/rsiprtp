//! SIP dialog management.
//!
//! Implements dialog state machines for INVITE-initiated sessions per RFC 3261.
//!
//! # Overview
//!
//! A dialog is a peer-to-peer SIP relationship between two UAs that persists
//! for some time. It facilitates sequencing of messages between the UAs and
//! proper routing of requests between both of them.
//!
//! # Main Types
//!
//! - [`DialogId`]: Unique identifier for a dialog (Call-ID + local tag + remote tag)
//! - [`InviteDialog`]: State machine for INVITE-initiated dialogs
//! - [`DialogManager`]: Manages multiple dialogs, routes messages

pub mod state;
pub mod invite;
pub mod manager;

// Re-export main types
pub use state::{DialogId, DialogState, DialogInfo, RouteSet};
pub use invite::{InviteDialog, Role, Action as DialogAction, Event as DialogEvent, TerminationReason};
pub use manager::{DialogManager, DialogHandle, ManagerAction, ManagerEvent};

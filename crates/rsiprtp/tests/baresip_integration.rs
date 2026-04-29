//! Baresip integration tests entry point.
//!
//! Run with: `cargo test --package rsiprtp --test baresip_integration`

#[path = "baresip_integration/framework/mod.rs"]
mod framework;

#[path = "baresip_integration/scenarios/mod.rs"]
mod scenarios;

// Re-export for use in tests

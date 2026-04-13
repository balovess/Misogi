//! Misogi Sender — Pluggable file transfer client.
//!
//! Provides the [`TransferDriverInstance`] enum for runtime driver selection
//! and [`AppState`] for shared state management across async tasks.

pub mod cli;
pub mod config;
pub mod state;
pub mod driver_instance;
pub mod upload_engine;

pub use driver_instance::TransferDriverInstance;
pub use state::{AppState, SharedState};

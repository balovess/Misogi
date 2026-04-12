//! Pull-mode transfer driver (Mode B) for Misogi multi-mode transport architecture.
//!
//! This module implements a **poll-based pull** transfer pattern where:
//!
//! **Sender side**: Writes sanitized files into a local buffer zone and waits.
//! The sender does NOT push data; it deposits files into the buffer and the
//! receiver actively polls and pulls them at its own pace.
//!
//! **Receiver side**: Executes a periodic gRPC-style poll cycle:
//! ```text
//!   list_pending_files() --> pull_file(id) --> ack_file(id)
//! ```
//!
//! # Architecture
//!
//! ```text
//!  Sender                    Buffer Zone                  Receiver
//!  ┌──────┐    write()     ┌──────────────┐   poll()   ┌──────────┐
//!  │      │ ─────────────► │ PullBuffer   │ ◄───────── │          │
//!  │ Send │                │ [entry, ...] │            │  Receive │
//!  │ er   │                ├──────────────┤   pull()   │          │
//!  │      │                │              │ ─────────► │          │
//!  └──────┘                └──────────────┘   ack()    └──────────┘
//! ```
//!
//! # Sub-modules
//!
//! - [`types`] — Configuration, buffer entry types, and serialization helpers.
//! - [`driver`] — Core [`PullDriver`] struct with inherent methods (constructors, poll/pull/ack API).
//! - [`driver_impl`] — [`TransferDriver`](crate::traits::TransferDriver) trait implementation for PullDriver.
//! - [`tests`] — Comprehensive unit test suite (22 tests).

pub mod driver;
pub mod driver_impl;
pub mod types;

#[cfg(test)]
mod tests;

// Re-export primary public API surface at module root for ergonomic imports.
pub use driver::PullDriver;
pub use types::{
    PullConfig, PullBufferEntry, PullEntryStatus,
};

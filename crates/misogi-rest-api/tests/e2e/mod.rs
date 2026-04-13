//! End-to-end test harness for Misogi workspace integration.
//!
//! Validates cross-crate integration points:
//! - NoCode health router merged into REST API
//! - Pluggable TransferDriver dispatch via enum
//! - REST API lifecycle with optional components

pub mod nocode_health_e2e;
pub mod sender_transfer_e2e;
pub mod rest_api_lifecycle_e2e;

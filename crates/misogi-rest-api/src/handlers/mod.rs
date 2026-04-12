//! Handler Module — Re-exports for All Request Handlers
//!
//! This module aggregates and re-exports every handler function from
//! submodules so that the router can import them from a single location.

pub mod files;
pub mod scan;
pub mod policies;
pub mod audit;
pub mod health;
pub mod metrics;

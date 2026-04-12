// =============================================================================
// Misogi Core Engine Module
// =============================================================================
// This module provides the runtime execution engines for the Misogi system,
// including the generic finite state machine (FSM) for workflow management
// and built-in trigger executors for external event handling.
//
// Architecture:
// - state_machine.rs: Generic FSM with configurable transitions, guards, and
//   async-safe concurrent access via RwLock.
// - webhook.rs: Built-in trigger implementations (HTTP callback, file polling,
//   gRPC stub) that satisfy the ApprovalTrigger trait contract.
//
// Thread Safety Guarantee:
// All public types in this module are Send + Sync safe. The StateMachine uses
// internal RwLock for atomic state access. Trigger implementations use Arc<>
// sharing and proper async synchronization.
//
// Design Principles:
// - Zero-cost abstractions: Generic over state type S with monomorphization.
// - Guard functions: Optional pre-transition validation via Arc<dyn Fn>.
// - Event-driven: Triggers subscribe to state change events via closures.
// - Idempotent operations: Duplicate transitions and trigger calls are safe.
// =============================================================================

pub mod state_machine;
pub mod webhook;

pub use state_machine::*;
pub use webhook::*;

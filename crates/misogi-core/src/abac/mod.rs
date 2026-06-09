//! Attribute-Based Access Control (ABAC) engine core module.
//!
//! This module implements a complete ABAC policy evaluation framework for
//! the Misogi secure file transfer system. It provides:
//!
//! - **Attribute types** ([`attribute`]) — Subject, resource, and environmental
//!   attribute definitions with strongly-typed value system.
//! - **Policy types** ([`policy`]) — Rule definitions, condition operators,
//!   obligations, and approval workflow templates.
//! - **Decision types** ([`decision`]) — Evaluation outcomes and error
//!   enumeration for audit trails and downstream processing.
//! - **Configuration** ([`config`]) — Top-level configuration structure with
//!   built-in validation for administrative safety.
//! - **Attribute resolver** ([`resolver`]) — Normalizes raw input parameters
//!   into unified attribute maps with TTL-based caching.
//! - **Condition evaluator** ([`evaluator`]) — Stateless operator evaluation
//!   engine supporting Eq/Neq/In/NotIn/Gt/Lt/Regex/IpInRange.
//! - **Policy engine** ([`engine`]) — Core orchestration layer that evaluates
//!   rules in priority order, applies deny-precedence semantics, manages
//!   decision caching, and supports hot-reload of rule sets.
//! - **Approval executor** ([`executor`]) — Manages approval request lifecycle
//!   for obligation fulfillment (approver selection, timeout, auto-complete).
//! - **Hot reload** ([`hot_reload`]) — File-based and in-memory configuration
//!   reloading with mtime-based change detection and atomic component updates.
//!
//! # Architecture Overview
//!
//! The ABAC engine follows the NIST ABAC model (SP 800-162) with extensions
//! for Japanese government compliance requirements:
//!
//! ```text
//! Access Request
//!     |
//!     ▼
//! ┌─────────────────┐
//! │  Attribute       │  Extract subject/resource/environment attributes
//! │  Resolver        │  (resolver module)
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │  Condition       │  Evaluate individual predicates (evaluator module)
//! │  Evaluator       │  Eq / Neq / In / NotIn / Gt / Lt / Regex / IpInRange
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │  Policy Engine   │  Sort rules by priority, evaluate AND logic,
//! │                  │  Deny short-circuit, cache decisions (engine module)
//! └────────┬────────┘
//!          │
//!     ┌────┴────┐
//!     ▼         ▼
//! ┌───────┐ ┌──────────┐
//! │Decision│ │Approval  │  Return decision + obligation info
//! │ + Oblig│ │Executor  │  Execute approval workflow if required
//! └───────┘ └────┬─────┘
//!                 │
//!                 ▼
//!         ┌──────────────┐
//!         │ Hot Reload    │  Monitor config file, atomic updates
//!         └──────────────┘
//! ```
//!
//! # Safety Guarantees
//!
//! - **Fail-closed**: Missing attributes, type mismatches, and evaluation
//!   errors all default to `false` (condition not satisfied), which leads to
//!   deny-by-default behavior.
//! - **No panic paths**: All condition evaluators handle edge cases gracefully;
//!   invalid regex patterns return `false` rather than panicking.
//! - **Immutable rules**: Policy rules are evaluated as read-only data structures,
//!   preventing concurrent modification during evaluation.
//! - **Deny precedence**: A matching Deny at any priority level overrides all
//!   matched Permits, implementing the principle of least privilege.

pub mod attribute;
pub mod config;
pub mod decision;
pub mod engine;
pub mod evaluator;
pub mod executor;
pub mod hot_reload;
pub mod policy;
pub mod resolver;

// Re-export primary types at module level for ergonomic imports.

// -- Core data types --
pub use attribute::{AbacAttribute, AbacValue, DayMask, TimeWindow};

// -- Configuration --
pub use config::{AbacConfig, ConfigValidationError};

// -- Decision output --
pub use decision::{AbacDecision, AbacDecisionError};

// -- Policy definition --
pub use policy::{
    AbacPolicyRule, ApprovalTemplate, ApproverPool, ConditionOperator, Obligation, PolicyCondition,
    PolicyEffect, PolicyTarget,
};

// -- Attribute resolution --
pub use resolver::AttributeResolver;

// -- Condition evaluation --
pub use evaluator::{ConditionEvaluator, EvalError};

// -- Policy engine --
pub use engine::AbacEngine;

// -- Approval execution --
pub use executor::{AbacApprovalStatus, ApprovalExecutor, ApprovalRequest, ExecutorError};

// -- Hot reload --
pub use hot_reload::{AbacHotReload, ReloadError};

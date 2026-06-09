//! Decision types and error enumeration for ABAC evaluation results.
//!
//! This module defines the output of the ABAC policy engine: a structured
//! decision that includes not only the permit/deny outcome but also metadata
//! for audit trails, performance analysis, and obligation dispatch.
//!
//! # Decision Lifecycle
//!
//! 1. The engine receives an access request with associated attributes.
//! 2. Rules are evaluated in priority order; each rule's conditions are checked.
//! 3. On first match, an [`AbacDecision`] is produced with the matched rule's
//!    effect and any attached obligations.
//! 4. If no rule matches, an [`AbacDecisionError::NoMatchingRule`] is returned
//!    (or a default-deny decision, depending on engine configuration).
//! 5. The caller inspects the decision and fulfills obligations before granting
//!    access.

use thiserror::Error;

use super::policy::{Obligation, PolicyEffect};

// ===========================================================================
// AbacDecision
// ===========================================================================

/// Structured output of the ABAC policy evaluation engine.
///
/// Every access request that passes through the ABAC engine produces exactly
/// one `AbacDecision` (or one `AbacDecisionError`). This struct captures all
/// information needed by downstream consumers:
///
/// - **Effect**: Permit or Deny — the core access control result.
/// - **Matched rule**: Which rule produced this decision (for audit logging).
/// - **Obligation**: Any additional requirements (approval, MFA, etc.).
/// - **Performance metrics**: Rule count evaluated and cache status.
///
/// # Cache Awareness
///
/// The `cache_hit` field allows callers to distinguish between freshly-evaluated
/// decisions and those served from the decision cache. This is important for
/// audit integrity: cache-served decisions may have been evaluated under
/// different attribute state and should be re-evaluated for high-assurance
/// operations.
#[derive(Debug, Clone)]
pub struct AbacDecision {
    /// Access control effect: `Permit` or `Deny`.
    pub effect: PolicyEffect,

    /// Identifier of the rule that produced this decision.
    ///
    /// `None` when the decision results from the default-effect fallback
    /// (no rule matched and the engine is configured to apply a default).
    pub matched_rule_id: Option<String>,

    /// Obligation to fulfill before permitting the action.
    ///
    /// `Some(...)` when the matched rule has a non-`None` obligation;
    /// `None` when there is no obligation, or when the effect is `Deny`.
    pub obligation: Option<Obligation>,

    /// Number of rules that were evaluated (conditions checked) before
    /// this decision was reached. Useful for performance monitoring:
    /// high values may indicate inefficient rule ordering.
    pub evaluated_rules: u32,

    /// Whether this decision was served from the evaluation cache rather
    /// than computed fresh from rule evaluation.
    ///
    /// Cache hits are acceptable for low-risk operations but should trigger
    /// re-evaluation for high-sensitivity transfers.
    pub cache_hit: bool,
}

impl AbacDecision {
    /// Returns `true` if this decision permits the requested action.
    #[inline]
    pub fn is_permitted(&self) -> bool {
        self.effect == PolicyEffect::Permit
    }

    /// Returns `true` if this decision denies the requested action.
    #[inline]
    pub fn is_denied(&self) -> bool {
        self.effect == PolicyEffect::Deny
    }

    /// Constructs a deny decision with no matched rule (default-deny).
    pub fn default_deny(evaluated_rules: u32) -> Self {
        Self {
            effect: PolicyEffect::Deny,
            matched_rule_id: None,
            obligation: None,
            evaluated_rules,
            cache_hit: false,
        }
    }
}

// ===========================================================================
// AbacDecisionError
// ===========================================================================

/// Error type for ABAC policy evaluation failures.
///
/// Unlike application-level errors, these represent structural or runtime
/// failures in the evaluation process itself (e.g., no matching rule found,
/// internal evaluation error). They do NOT represent "access denied" outcomes,
/// which are represented as successful `AbacDecision` with `effect: Deny`.
#[derive(Error, Debug)]
pub enum AbacDecisionError {
    /// No policy rule matched the request attributes and no default effect
    /// is configured. The caller must decide how to handle this case
    /// (typically: deny-by-default).
    #[error("no matching ABAC rule found for the given attribute set")]
    NoMatchingRule,

    /// A specific rule failed during condition evaluation due to an
    /// unexpected error (e.g., malformed regex, type mismatch in numeric
    /// comparison). The rule ID is included for diagnostic purposes.
    #[error("rule '{rule_id}' evaluation failed: {reason}")]
    RuleEvaluationError {
        /// Identifier of the rule that caused the error.
        rule_id: String,
        /// Human-readable description of why evaluation failed.
        reason: String,
    },

    /// An error occurred while reading from or writing to the decision cache.
    /// Cache errors are non-fatal: the engine can fall back to direct
    /// evaluation, but this error surfaces for operational awareness.
    #[error("decision cache error: {0}")]
    CacheError(String),
}

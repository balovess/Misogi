//! Type definitions for the approval execution engine.
//!
//! Contains [`ApprovalRequest`], [`AbacApprovalStatus`], and [`ExecutorError`] —
//! the core data types used by [`super::ApprovalExecutor`] to manage approval
//! request lifecycles.

use serde::{Deserialize, Serialize};

// ===========================================================================
// AbacApprovalStatus
// ===========================================================================

/// Current state of an approval request in its lifecycle.
///
/// Status transitions follow a strict state machine:
///
/// ```text
/// Pending --(enough approvals)--> Approved
/// Pending --(any rejection)-----> Rejected
/// Pending --(timeout+escalate)--> Escalated
/// Pending --(timeout)-----------> TimedOut
/// Pending --(cancel)------------> Cancelled
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbacApprovalStatus {
    /// Request created and awaiting approver responses.
    Pending,

    /// Sufficient approvals received; action may proceed.
    Approved,

    /// At least one approver rejected; action is blocked.
    Rejected,

    /// Timeout elapsed without sufficient approvals and escalation is not configured.
    TimedOut,

    /// Timeout elapsed with escalation enabled; forwarded to higher authority.
    Escalated,

    /// Request cancelled by initiator or administrator before completion.
    Cancelled,
}

impl AbacApprovalStatus {
    /// Returns `true` if this status is a terminal (non-transitionable) state.
    ///
    /// Terminal states: `Approved`, `Rejected`, `TimedOut`, `Escalated`, `Cancelled`.
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Pending)
    }
}

// ===========================================================================
// ApprovalRequest
// ===========================================================================

/// Represents an approval request created by the ABAC engine's obligation system.
///
/// Each request is associated with exactly one [`super::ApprovalTemplate`] and tracks
/// the full approval lifecycle from creation through completion or timeout.
///
/// # Thread Safety
///
/// This struct is designed to be cloned for read-only access. Mutable operations
/// on individual requests go through [`super::ApprovalExecutor`] methods which hold
/// the appropriate locks.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// Globally unique identifier for this request instance.
    ///
    /// Generated via UUID v4 at creation time. Used as the primary key
    /// for all subsequent operations (approval recording, status queries, cancellation).
    pub request_id: String,

    /// Identifier of the [`super::ApprovalTemplate`] that defines workflow parameters
    /// (required approvers, timeout, escalation settings).
    pub template_id: String,

    /// ID of the policy rule that triggered this approval obligation.
    ///
    /// Enables audit trail correlation: which rule required this approval?
    pub triggered_by_rule: String,

    /// User ID of the subject whose action requires approval.
    pub subject_user_id: String,

    /// Human-readable description of the resource/action being approved.
    ///
    /// Example: "Transfer confidential report to external zone".
    pub resource_description: String,

    /// Minimum number of distinct approvers who must grant approval.
    ///
    /// Copied from the template's `required_approvers` field at creation time.
    pub required_approvers: u8,

    /// Ordered list of user IDs selected from the approver pool.
    ///
    /// These are the users who are eligible and expected to respond.
    /// The list length may exceed `required_approvers` (oversubscription).
    pub selected_approvers: Vec<String>,

    /// Maximum hours this request may remain pending before timeout/escalation.
    ///
    /// A value of `0` means no timeout (request remains pending indefinitely).
    pub timeout_hours: u32,

    /// UTC timestamp of when this request was created.
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Current lifecycle state of this request.
    pub status: AbacApprovalStatus,

    /// Whether unapproved requests should be escalated rather than auto-rejected
    /// when `timeout_hours` elapses.
    pub escalation_on_timeout: bool,
}

impl ApprovalRequest {
    /// Returns `true` if this request is still awaiting responses.
    #[inline]
    pub fn is_pending(&self) -> bool {
        self.status == AbacApprovalStatus::Pending
    }
}

// ===========================================================================
// Internal tracking for per-approver decisions
// ===========================================================================

/// Tracks which approvers have responded and their decisions.
pub(crate) struct ApproverDecisionTracker {
    /// Set of approver user IDs who have already recorded a decision.
    pub(crate) responded: std::collections::HashSet<String>,
    /// Number of approvals received so far.
    pub(crate) approval_count: u8,
    /// Whether any rejection has been received.
    pub(crate) has_rejection: bool,
}

impl ApproverDecisionTracker {
    pub(crate) fn new() -> Self {
        Self {
            responded: std::collections::HashSet::new(),
            approval_count: 0,
            has_rejection: false,
        }
    }
}

// ===========================================================================
// ExecutorError
// ===========================================================================

/// Error type for approval executor operations.
///
/// These errors represent operational failures within the approval workflow
/// (template not found, invalid state transitions, etc.) and do NOT represent
/// access control denials (which are `AbacDecision` with `effect: Deny`).
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    /// The specified approval template does not exist in the executor's registry.
    #[error("template '{0}' not found")]
    TemplateNotFound(String),

    /// The approver pool resolved to zero eligible approvers.
    ///
    /// This can occur when role-based pools reference roles with no current members,
    /// or department-head pools cannot resolve a department head for the subject.
    #[error("no approvers could be selected from pool")]
    NoApproversAvailable,

    /// The specified approval request does not exist in the active request store.
    #[error("request '{0}' not found")]
    RequestNotFound(String),

    /// Attempted a state transition that is not permitted from the current state.
    ///
    /// For example, trying to record an approval on a request that is already
    /// `Approved` or `Cancelled`.
    #[error("request '{request_id}' is not in pending state (current: {current_state:?})")]
    InvalidStateTransition {
        /// ID of the target request.
        request_id: String,
        /// The actual current state that blocked the transition.
        current_state: AbacApprovalStatus,
    },

    /// An approver attempted to record a decision more than once for the same request.
    #[error("approval already recorded by approver '{0}'")]
    DuplicateApproval(String),
}

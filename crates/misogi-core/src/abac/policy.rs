//! Policy definition types for ABAC rule evaluation.
//!
//! This module defines the structural components of ABAC policies:
//! condition operators, policy rules, obligations (side effects such as
//! approval workflows), and approval templates. Together these form the
//! declarative language used by administrators to express access control
//! requirements.
//!
//! # Policy Evaluation Model
//!
//! Policies are evaluated as an ordered list of rules. Each rule contains:
//!
//! 1. **Target** — Which action/resource type this rule applies to.
//! 2. **Conditions** — Attribute-based predicates that must all be satisfied
//!    (AND logic) for the rule to match.
//! 3. **Effect** — Permit or Deny when all conditions match.
//! 4. **Obligation** — Optional side effects triggered on a positive match
//!    (e.g., require approval, force MFA re-authentication).
//!
//! The engine evaluates rules in descending priority order and returns the
//! first matching rule's effect.

mod tests;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::abac::attribute::{AbacAttribute, AbacValue};

// ===========================================================================
// ConditionOperator
// ===========================================================================

/// Comparison operator used in a single policy condition.
///
/// Each operator defines how the attribute value extracted from the request
/// context is compared against the static value defined in the policy rule.
/// The set of operators is intentionally limited to those that can be
/// evaluated efficiently without external service calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    /// Exact equality comparison.
    ///
    /// For string values: case-sensitive Unicode codepoint comparison.
    /// For numeric values: exact bit-for-bit equality (beware of floating-point).
    Eq,

    /// Inequality (not equal). Negation of `Eq`.
    Neq,

    /// Membership test: the attribute value must be present in the
    /// policy-defined list of allowed values.
    ///
    /// The right-hand side MUST be an `AbacValue::List`. If it is not,
    /// evaluation returns `false`.
    In,

    /// Negative membership test: the attribute value must NOT be present
    /// in the policy-defined list of denied values.
    NotIn,

    /// Greater-than numeric comparison. Both sides must be numeric
    /// (`Integer` or `Float`). Returns `false` for non-numeric types.
    Gt,

    /// Less-than numeric comparison. Symmetric counterpart of `Gt`.
    Lt,

    /// Regular expression pattern match against string attributes.
    ///
    /// The right-hand side MUST be an `AbacValue::String` containing a
    /// valid regex pattern. Invalid patterns cause evaluation to return
    /// `false` rather than panicking.
    Regex,

    /// IP address CIDR range membership test.
    ///
    /// The left-hand side is expected to be an `IpAddress` attribute value
    /// (string representation of IPv4/IPv6), and the right-hand side is
    /// a CIDR notation string (e.g., "10.0.0.0/8").
    IpInRange,
}

// ===========================================================================
// PolicyCondition
// ===========================================================================

/// A single condition predicate within a policy rule.
///
/// A condition combines an attribute reference, a comparison operator, and
/// a static comparison value into a testable unit. During evaluation, the
/// engine extracts the actual attribute value from the request context and
/// applies the operator to determine if this condition is satisfied.
///
/// # Evaluation Semantics
///
/// - All conditions within a rule are combined with AND logic.
/// - A single failing condition causes the entire rule to not match.
/// - Type mismatches between attribute and condition value result in
///   `false` (safe default: deny unless explicitly permitted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    /// The attribute whose runtime value will be compared.
    pub attribute: AbacAttribute,

    /// The comparison operator applied between the attribute value and
    /// the static `value` field below.
    pub operator: ConditionOperator,

    /// The static value used as the right-hand side of the comparison.
    /// The required type depends on the operator:
    ///
    /// | Operator | Expected Type |
    /// |----------|-------------|
    /// | `Eq`, `Neq` | Same type as attribute |
    /// | `In`, `NotIn` | `List` of matching type |
    /// | `Gt`, `Lt` | `Integer` or `Float` |
    /// | `Regex` | `String` (regex pattern) |
    /// | `IpInRange` | `String` (CIDR notation) |
    pub value: AbacValue,
}

impl PolicyCondition {
    /// Evaluates this single condition against an attribute map.
    ///
    /// The `attribute_map` is keyed by attribute key strings. For built-in
    /// attributes, the key is derived from the variant name (e.g.,
    /// `"UserId"`, `"Role"`). For custom attributes, the key is the
    /// `Custom.key` field.
    ///
    /// Returns `true` if the condition is satisfied, `false` otherwise.
    /// Type mismatches and missing keys always yield `false`.
    pub fn evaluate(&self, attribute_map: &HashMap<String, AbacValue>) -> bool {
        let attr_key = attribute_key_for(&self.attribute);
        let actual = match attribute_map.get(&attr_key) {
            Some(v) => v,
            None => return false,
        };

        match &self.operator {
            ConditionOperator::Eq => actual == &self.value,
            ConditionOperator::Neq => actual != &self.value,
            ConditionOperator::In => {
                matches!(&self.value, AbacValue::List(items) if items.contains(actual))
            }
            ConditionOperator::NotIn => {
                !matches!(&self.value, AbacValue::List(items) if items.contains(actual))
            }
            ConditionOperator::Gt => compare_numeric(actual, &self.value)
                .map(|ord| ord.is_gt())
                .unwrap_or(false),
            ConditionOperator::Lt => compare_numeric(actual, &self.value)
                .map(|ord| ord.is_lt())
                .unwrap_or(false),
            ConditionOperator::Regex => evaluate_regex(actual, &self.value),
            ConditionOperator::IpInRange => evaluate_ip_range(actual, &self.value),
        }
    }
}

// ===========================================================================
// PolicyEffect
// ===========================================================================

/// Access control decision outcome produced by a matched policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEffect {
    /// Access is explicitly permitted subject to any attached obligations.
    Permit,

    /// Access is explicitly denied. Obligations are not applicable.
    #[default]
    Deny,
}

// ===========================================================================
// ApproverPool
// ===========================================================================

/// Specifies which users are eligible to approve a transfer request.
///
/// Different organizations have different approval hierarchies; this enum
/// supports the most common patterns found in Japanese government and
/// enterprise environments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "spec")]
pub enum ApproverPool {
    /// Any user whose role is in the given list may approve.
    Role {
        /// List of role names eligible to act as approvers.
        roles: Vec<String>,
    },

    /// The department head of the applicant's department is automatically
    /// selected as the sole approver. Requires department hierarchy data
    /// from the identity provider.
    DepartmentHead,

    /// Explicit list of user IDs who may approve. Used for specialized
    /// workflows where approval authority is not role-based (e.g.,
    /// security officer sign-off).
    CustomList {
        /// List of user IDs authorized to approve requests under this template.
        user_ids: Vec<String>,
    },
}

// ===========================================================================
// ApprovalTemplate
// ===========================================================================

/// Reusable template defining approval workflow parameters.
///
/// Templates are referenced by obligation clauses in policy rules so that
/// approval configuration can be managed centrally and reused across
/// multiple rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalTemplate {
    /// Unique identifier for this template (e.g., "default-2-person").
    pub template_id: String,

    /// Minimum number of distinct approvers who must grant approval
    /// before the request proceeds. Must be >= 1.
    pub required_approvers: u8,

    /// Definition of the pool of users eligible to approve.
    pub approver_pool: ApproverPool,

    /// Maximum number of hours the request may remain pending before
    /// escalation or auto-rejection. A value of 0 means no timeout.
    pub timeout_hours: u32,

    /// When `true`, unapproved requests that exceed `timeout_hours`
    /// are escalated to a higher authority rather than auto-rejected.
    pub escalation_on_timeout: bool,
}

// ===========================================================================
// Obligation
// ===========================================================================

/// Side effect triggered when a policy rule with `Permit` effect matches.
///
/// Obligations implement the "break-the-glass" and "four-eyes principle"
/// controls required by Japanese government security standards (e.g.,
/// MIC/METI guidelines for cross-network file transfer systems).
///
/// An obligation does not change the permit/deny decision itself;
/// instead, it imposes additional requirements that must be fulfilled
/// *before* the permitted action is executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "params")]
pub enum Obligation {
    /// No additional requirement. The action may proceed immediately.
    None,

    /// Transfer must be approved through the configured approval workflow
    /// before execution. The action is blocked until sufficient approvals
    /// are collected or the request times out.
    RequireApproval(ApprovalTemplate),

    /// User must re-authenticate via multi-factor authentication before
    /// the action is executed. Typically used for high-risk operations
    /// or when the session age exceeds a threshold.
    RequireMfa,

    /// User must provide a free-text business justification for the action.
    /// The justification is recorded in the audit log for compliance review.
    RequireJustification,

    /// Send notification to the listed administrator user IDs.
    /// This is informational only and does not block the action.
    NotifyAdmins(Vec<String>),

    /// Record the decision in the audit log but impose no blocking
    /// requirement. Used for monitoring-sensitive actions without
    /// disrupting the user workflow.
    LogOnly,
}

// ===========================================================================
// PolicyTarget
// ===========================================================================

/// Defines the scope of applicability for a policy rule.
///
/// A rule only evaluates against requests whose action and resource type
/// match the target specification. This enables fine-grained policies
/// such as "deny large PDF downloads but permit small text uploads".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTarget {
    /// Action identifier this rule applies to (e.g., "file_transfer",
    /// "file_download", "file_upload", "config_change").
    /// Empty string matches all actions.
    pub action: String,

    /// Optional resource type filter (e.g., "document", "archive",
    /// "image", "executable"). When `None`, the rule applies to all
    /// resource types for the matching action.
    pub resource_type: Option<String>,
}

// ===========================================================================
// AbacPolicyRule
// ===========================================================================

/// A complete ABAC policy rule combining target, conditions, effect, and
/// optional obligations.
///
/// Rules are evaluated in priority order (highest first). The first rule
/// whose conditions all match determines the access decision. This follows
/// the "first-match-wins" semantics common in firewall rule sets.
///
/// # Priority and Ordering
///
/// Rules should be ordered such that more specific rules (with tighter
/// conditions) have higher priority values than general catch-all rules.
/// The engine sorts rules by `priority` descending before evaluation.
///
/// # Enabled / Disabled
///
/// Disabled rules (`enabled: false`) are skipped during evaluation but
/// retained in storage. This allows temporary rule suspension without
/// deletion, which is valuable for incident response scenarios.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacPolicyRule {
    /// Globally unique identifier for this rule (e.g., UUID or admin-assigned
    /// name like "block-large-transfers-after-hours").
    pub rule_id: String,

    /// Access control effect when all conditions match.
    pub effect: PolicyEffect,

    /// Ordered list of condition predicates. ALL must evaluate to `true`
    /// for the rule to match (AND logic). An empty condition list means
    /// the rule always matches its target.
    pub conditions: Vec<PolicyCondition>,

    /// Target scope: which action(s) and resource type(s) this rule covers.
    pub target: PolicyTarget,

    /// Optional obligation triggered on `Permit` effect. Ignored for
    /// `Deny` effects.
    pub obligation: Option<Obligation>,

    /// Evaluation priority. Higher values are evaluated first.
    /// Rules with equal priority maintain their original order.
    pub priority: i32,

    /// Whether this rule participates in evaluation. Disabled rules are
    /// preserved in storage but skipped at runtime.
    pub enabled: bool,
}

impl AbacPolicyRule {
    /// Evaluates all conditions of this rule against the provided attribute map.
    ///
    /// Uses strict AND logic: every condition must evaluate to `true` for
    /// this method to return `true`. An empty `conditions` vector returns
    /// `true` (vacuously true — the rule unconditionally matches).
    ///
    /// # Parameters
    ///
    /// - `attribute_map`: Map from attribute key strings to their current
    ///   runtime values. Keys must match the output of [`attribute_key_for()`].
    ///
    /// # Returns
    ///
    /// `true` if all conditions are satisfied (or there are no conditions);
    /// `false` if any condition fails.
    pub fn matches_conditions(&self, attribute_map: &HashMap<String, AbacValue>) -> bool {
        self.conditions
            .iter()
            .all(|cond| cond.evaluate(attribute_map))
    }
}

// ===========================================================================
// Helper Functions
// ===========================================================================

/// Derives a stable string key for an `AbacAttribute` variant for use as
/// a HashMap lookup key.
///
/// For built-in variants, returns the variant name (e.g., `"UserId"`,
/// `"Role"`, `"ClearanceLevel"`). For `Custom` variants, returns the
/// custom `key` field.
fn attribute_key_for(attr: &AbacAttribute) -> String {
    match attr {
        AbacAttribute::UserId(_) => "UserId".to_string(),
        AbacAttribute::Role(_) => "Role".to_string(),
        AbacAttribute::Department(_) => "Department".to_string(),
        AbacAttribute::ClearanceLevel(_) => "ClearanceLevel".to_string(),
        AbacAttribute::GroupMembership(_) => "GroupMembership".to_string(),
        AbacAttribute::IpAddress(_) => "IpAddress".to_string(),
        AbacAttribute::GeographicRegion(_) => "GeographicRegion".to_string(),
        AbacAttribute::MfaVerified(_) => "MfaVerified".to_string(),
        AbacAttribute::DeviceCompliant(_) => "DeviceCompliant".to_string(),
        AbacAttribute::DataClassification(_) => "DataClassification".to_string(),
        AbacAttribute::FileType(_) => "FileType".to_string(),
        AbacAttribute::FileSizeBytes(_) => "FileSizeBytes".to_string(),
        AbacAttribute::DestinationZone(_) => "DestinationZone".to_string(),
        AbacAttribute::ContainsPii(_) => "ContainsPii".to_string(),
        AbacAttribute::TimeOfDay(_) => "TimeOfDay".to_string(),
        AbacAttribute::DayOfWeek(_) => "DayOfWeek".to_string(),
        AbacAttribute::BusinessDay(_) => "BusinessDay".to_string(),
        AbacAttribute::SourceNetwork(_) => "SourceNetwork".to_string(),
        AbacAttribute::Custom { key, .. } => key.clone(),
    }
}

/// Compares two `AbacValue`s numerically and returns the ordering.
///
/// Supports `Integer` vs `Integer`, `Float` vs `Float`, and cross-type
/// comparison (Integer promoted to Float). Returns `None` if either value
/// is non-numeric.
fn compare_numeric(left: &AbacValue, right: &AbacValue) -> Option<std::cmp::Ordering> {
    match (left, right) {
        (AbacValue::Integer(l), AbacValue::Integer(r)) => Some(l.cmp(r)),
        (AbacValue::Float(l), AbacValue::Float(r)) => l.partial_cmp(r),
        (AbacValue::Integer(l), AbacValue::Float(r)) => (*l as f64).partial_cmp(r),
        (AbacValue::Float(l), AbacValue::Integer(r)) => l.partial_cmp(&(*r as f64)),
        _ => None,
    }
}

/// Evaluates a regex pattern match condition.
///
/// Returns `true` if `actual` is a `String` and matches the regex pattern
/// contained in `pattern_value`. Returns `false` for non-string values,
/// invalid patterns, or non-matching strings.
fn evaluate_regex(actual: &AbacValue, pattern_value: &AbacValue) -> bool {
    let actual_str = match actual.as_str() {
        Some(s) => s,
        None => return false,
    };
    let pattern = match pattern_value.as_str() {
        Some(p) => p,
        None => return false,
    };
    match regex::Regex::new(pattern) {
        Ok(re) => re.is_match(actual_str),
        Err(_) => false, // Invalid pattern: fail closed
    }
}

/// Evaluates an IP address range membership condition.
///
/// Currently performs basic string-prefix matching for IPv4 CIDR notation
/// on `/8`, `/16`, and `/24` prefixes. Full CIDR evaluation requires the
/// optional `ipnetwork` dependency and will be enhanced in a future update.
///
/// Returns `true` if the actual IP address falls within the specified range.
fn evaluate_ip_range(_actual: &AbacValue, _pattern_value: &AbacValue) -> bool {
    // TODO: Implement full CIDR evaluation using ipnetwork crate when
    // jp_contrib feature is enabled. For now, return false (fail-closed)
    // to prevent accidental bypass.
    false
}

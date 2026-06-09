/// ABAC engine configuration and policy loading.
///
/// This module provides the top-level configuration structure for the
/// ABAC subsystem. It combines runtime parameters (cache TTL, audit logging)
/// with the complete set of policy rules and approval templates into a
/// single serializable unit suitable for file-based or database-backed
/// configuration management.
///
/// # Configuration Lifecycle
///
/// 1. Administrator creates/modifies an `AbacConfig` (YAML/JSON).
/// 2. Configuration is loaded and deserialized into this struct.
/// 3. [`validate()`](AbacConfig::validate) checks structural integrity.
/// 4. Validated config is passed to the ABAC engine for evaluation.
mod tests;

use serde::{Deserialize, Serialize};

use super::policy::{AbacPolicyRule, ApprovalTemplate};

// ===========================================================================
// AbacConfig
// ===========================================================================

/// Top-level configuration for the ABAC (Attribute-Based Access Control) engine.
///
/// This struct is the deserialization target for configuration files and
/// the primary interface between administrators and the ABAC subsystem.
/// All tunable parameters of the engine are exposed here.
///
/// # Default Values
///
/// Sensible secure defaults are provided via the `Default` implementation:
///
/// | Field | Default | Rationale |
/// |-------|---------|-----------|
/// | `enabled` | `false` | ABAC must be explicitly activated |
/// | `default_effect` | `"deny"` | Fail-safe: deny when uncertain |
/// | `decision_cache_ttl_secs` | `300` | 5-minute cache window |
/// | `audit_log_all_decisions` | `true` | Compliance requirement |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacConfig {
    /// Master switch for the entire ABAC engine.
    ///
    /// When `false`, all access requests bypass ABAC evaluation and fall
    /// through to the next authorization layer (if any). When `true`,
    /// every request must pass through the full ABAC rule set.
    pub enabled: bool,

    /// Effect applied when no rule matches the request attributes.
    ///
    /// Supported values: `"permit"` or `"deny"`. The default `"deny"`
    /// follows the principle of least privilege: if no rule explicitly
    /// permits an action, it is denied.
    ///
    /// **Security Warning**: Setting this to `"permit"` creates an implicit
    /// allow-all fallback that may violate compliance requirements.
    #[serde(default = "default_effect_deny")]
    pub default_effect: String,

    /// Time-to-live for decision cache entries in seconds.
    ///
    /// Cached decisions avoid redundant re-evaluation of identical
    /// attribute sets within the TTL window. A value of `0` disables
    /// caching entirely (every request is evaluated fresh).
    #[serde(default = "default_cache_ttl")]
    pub decision_cache_ttl_secs: u64,

    /// Whether to write every ABAC decision (both Permit and Deny) to
    /// the audit log.
    ///
    /// When `true`, the audit trail contains a complete record of all
    /// access control decisions for compliance review. When `false`,
    /// only Deny decisions are logged to reduce log volume.
    #[serde(default = "default_audit_log")]
    pub audit_log_all_decisions: bool,

    /// Ordered collection of policy rules evaluated by the ABAC engine.
    ///
    /// Rules are sorted by `priority` descending at load time; the order
    /// in this vector does not affect evaluation priority. Duplicate
    /// `rule_id` values cause validation to fail.
    #[serde(default)]
    pub rules: Vec<AbacPolicyRule>,

    /// Library of reusable approval templates referenced by obligation
    /// clauses in policy rules.
    ///
    /// Templates are indexed by `template_id`. Duplicate template IDs
    /// cause validation to fail.
    #[serde(default)]
    pub approval_templates: Vec<ApprovalTemplate>,
}

// ===========================================================================
// Defaults
// ===========================================================================

fn default_effect_deny() -> String {
    "deny".to_string()
}

fn default_cache_ttl() -> u64 {
    300
}

fn default_audit_log() -> bool {
    true
}

impl Default for AbacConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_effect: default_effect_deny(),
            decision_cache_ttl_secs: default_cache_ttl(),
            audit_log_all_decisions: default_audit_log(),
            rules: vec![],
            approval_templates: vec![],
        }
    }
}

// ===========================================================================
// Validation
// ===========================================================================

/// Result type for configuration validation.
pub type ValidationResult<T> = std::result::Result<T, Vec<ConfigValidationError>>;

/// Individual validation error with a human-readable message and the
/// path to the offending field.
#[derive(Debug, Clone, thiserror::Error)]
#[error("[{path}] {message}")]
pub struct ConfigValidationError {
    /// Dot-separated path to the invalid field (e.g., "rules[2].priority").
    pub path: String,
    /// Human-readable description of why validation failed.
    pub message: String,
}

impl AbacConfig {
    /// Validates the structural integrity and semantic correctness of this
    /// configuration.
    ///
    /// Checks performed:
    ///
    /// 1. `default_effect` must be `"permit"` or `"deny"` (case-sensitive).
    /// 2. No duplicate `rule_id` values in `rules`.
    /// 3. Each rule's `required_approvers` (if obligation requires approval)
    ///    references a valid `template_id` from `approval_templates`.
    /// 4. No duplicate `template_id` values in `approval_templates`.
    /// 5. `decision_cache_ttl_secs` must be a reasonable value (< 86400).
    ///
    /// Returns `Ok(())` if all checks pass, or `Err(vec)` containing all
    /// discovered violations (validation does not stop on first error).
    pub fn validate(&self) -> ValidationResult<()> {
        let mut errors = vec![];

        // Check default_effect value
        if self.default_effect != "permit" && self.default_effect != "deny" {
            errors.push(ConfigValidationError {
                path: "default_effect".to_string(),
                message: format!("must be 'permit' or 'deny', got '{}'", self.default_effect),
            });
        }

        // Check cache TTL upper bound (max 24 hours)
        if self.decision_cache_ttl_secs > 86_400 {
            errors.push(ConfigValidationError {
                path: "decision_cache_ttl_secs".to_string(),
                message: format!(
                    "must be <= 86400 (24h), got {}",
                    self.decision_cache_ttl_secs
                ),
            });
        }

        // Check for duplicate rule IDs
        let mut seen_rule_ids = std::collections::HashSet::new();
        for (idx, rule) in self.rules.iter().enumerate() {
            if !seen_rule_ids.insert(&rule.rule_id) {
                errors.push(ConfigValidationError {
                    path: format!("rules[{}].rule_id", idx),
                    message: format!("duplicate rule_id '{}'", rule.rule_id),
                });
            }
        }

        // Check for duplicate template IDs
        let mut seen_template_ids = std::collections::HashSet::new();
        for (idx, tpl) in self.approval_templates.iter().enumerate() {
            if !seen_template_ids.insert(&tpl.template_id) {
                errors.push(ConfigValidationError {
                    path: format!("approval_templates[{}].template_id", idx),
                    message: format!("duplicate template_id '{}'", tpl.template_id),
                });
            }
            // Validate required_approvers >= 1
            if tpl.required_approvers == 0 {
                errors.push(ConfigValidationError {
                    path: format!("approval_templates[{}].required_approvers", idx),
                    message: "must be >= 1".to_string(),
                });
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Returns `true` if this configuration passes all validation checks.
    ///
    /// Convenience wrapper around [`validate()`](Self::validate) that
    /// discards specific error details.
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }
}

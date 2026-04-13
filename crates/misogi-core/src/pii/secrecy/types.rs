// =============================================================================
// Misogi Core — PII Secrecy Level Classification Types
// =============================================================================
// Data structures for user-customizable secrecy/confidentiality classification.
//
// ## Design Philosophy (Three Iron Rules)
//
// 1. **No hardcoded level schemes** — User defines any scheme: 3-tier, 4-tier,
//    HIPAA, PCI-DSS, government-specific, or fully custom.
//
// 2. **All rules externally configurable** — Levels, names, colors, controls,
//    retention periods, and classification logic all from YAML/JSON/Builder.
//
// 3. **Universal defaults as starting point** — Built-in generic-4-tier template
//    is intentionally international, not Japan-government-specific.
// =============================================================================

use serde::{Deserialize, Serialize};

/// Security control requirement for a secrecy level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlRequirement {
    /// Unique identifier for this control.
    pub id: String,

    /// Human-readable name.
    pub name: String,

    /// Whether this control is mandatory for this level.
    pub required: bool,

    /// Specification or standard reference (e.g., "AES-256+", "TLS 1.2+").
    #[serde(default)]
    pub spec: String,
}

/// Definition of a single secrecy/confidentiality level.
///
/// Users define the complete set of levels in their configuration.
/// Misogi does not assume any specific naming or count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecrecyLevelDef {
    /// Unique level identifier (e.g., "critical", "3a", "top_secret").
    pub id: String,

    /// Human-readable display name.
    pub display_name: String,

    /// Numeric rank for ordering (higher = more sensitive).
    pub rank: u32,

    /// UI color code (hex).
    #[serde(default = "default_color")]
    pub color: String,

    /// Required security controls at this level.
    #[serde(default)]
    pub required_controls: Vec<ControlRequirement>,

    /// Data retention period in years.
    #[serde(default = "default_retention")]
    pub retention_years: u32,
}

fn default_color() -> String {
    "#6B7280".to_string()
}
fn default_retention() -> u32 {
    1
}

impl SecrecyLevelDef {
    /// Check if this level has mandatory controls.
    pub fn has_mandatory_controls(&self) -> bool {
        self.required_controls.iter().any(|c| c.required)
    }

    /// Get mandatory controls only.
    pub fn mandatory_controls(&self) -> Vec<&ControlRequirement> {
        self.required_controls.iter().filter(|c| c.required).collect()
    }
}

/// Condition for a classification rule to trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    /// PII types must ALL be present (AND logic).
    RequireAllOf {
        pii_types: Vec<String>,
    },

    /// At least one PII type must be present (OR logic).
    RequireAnyOf {
        pii_types: Vec<String>,
    },

    /// Exact set of PII types with minimum counts.
    PiiTypesPresent {
        pii_types: Vec<String>,
        min_count: usize,
    },

    /// All listed types must be absent (exclusion filter).
    ExcludeAllOf {
        pii_types: Vec<String>,
    },

    /// Any of listed types must be absent.
    ExcludeAnyOf {
        pii_types: Vec<String>,
    },
}

/// Result produced when a classification rule matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResult {
    /// Assigned secrecy level ID.
    pub level: String,

    /// Human-readable reason for this classification.
    pub reason: String,
}

/// A single classification rule mapping PII patterns to secrecy levels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationRule {
    /// Unique rule identifier.
    pub id: String,

    /// Condition that triggers this rule.
    pub condition: Condition,

    /// Result when condition matches.
    pub result: RuleResult,
}

/// Fallback policy when no rule matches or conflicts occur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackPolicy {
    /// Default level for content with no matching rules.
    #[serde(default = "default_medium_level")]
    pub unknown_default: String,

    /// How to resolve multiple matching rules: "highest" or "lowest" rank.
    #[serde(default = "default_conflict_resolution")]
    pub conflict_resolution: String,

    /// Minimum confidence to apply a rule's result.
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f64,
}

fn default_medium_level() -> String {
    "medium".to_string()
}
fn default_conflict_resolution() -> String {
    "highest".to_string()
}
fn default_min_confidence() -> f64 {
    0.3
}

impl Default for FallbackPolicy {
    fn default() -> Self {
        Self {
            unknown_default: "medium".to_string(),
            conflict_resolution: "highest".to_string(),
            min_confidence: 0.3,
        }
    }
}

/// Complete secrecy classification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecrecyClassificationResult {
    /// Assigned secrecy level ID.
    pub level_id: String,

    /// Display name of assigned level.
    pub level_display_name: String,

    /// Rank of assigned level (for sorting/comparison).
    pub level_rank: u32,

    /// Color code for UI rendering.
    pub level_color: String,

    /// Which rule(s) triggered this classification.
    #[serde(default)]
    pub matched_rules: Vec<String>,

    /// Human-readable explanation.
    pub reason: String,

    /// Required security controls for this level.
    pub required_controls: Vec<ControlRequirement>,

    /// Retention period in years.
    pub retention_years: u32,
}

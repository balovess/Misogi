// =============================================================================
// Misogi Core — PII Structured Data Scanner Types
// =============================================================================
// Shared types for structured data (CSV/JSON/XML) field-level PII scanning.
//
// ## Core Concept
//
// Unlike text scanning which treats content as flat string, structured scanners
// understand data semantics:
// - CSV: column headers → PII type mapping
// - JSON: object keys → PII type mapping (recursive)
// - XML: element/attribute names → PII type mapping
//
// All mappings are 100% externally configurable via YAML/JSON/Builder API.
// =============================================================================

use serde::{Deserialize, Serialize};

use crate::traits::PIIAction;

/// Action to take when PII is detected in a structured field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldAction {
    /// Mask the detected value (replace with asterisks).
    Mask,

    /// Redact entirely (remove value).
    Redact,

    /// Log but allow through.
    AlertOnly,

    /// Log only (lowest severity).
    LogOnly,
}

impl From<PIIAction> for FieldAction {
    fn from(action: PIIAction) -> Self {
        match action {
            PIIAction::Block => FieldAction::Redact,
            PIIAction::Mask => FieldAction::Mask,
            PIIAction::AlertOnly => FieldAction::AlertOnly,
        }
    }
}

/// Single field name → PII type mapping rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMapping {
    /// Regex pattern or literal string to match against field names.
    ///
    /// Supports:
    /// - Literal: `"email"` matches exact field name "email"
    /// - Wildcard suffix: `"*_id"` matches "user_id", "order_id"
    /// - Full regex: `"(?i)^name$"` case-insensitive exact match
    pub field_pattern: String,

    /// PII type identifier when this pattern matches.
    pub pii_type: String,

    /// Confidence score for this mapping [0.0, 1.0].
    #[serde(default = "default_confidence")]
    pub confidence: f64,

    /// Action to apply when PII is found in this field.
    #[serde(default)]
    pub action: FieldAction,
}

fn default_confidence() -> f64 {
    0.8
}

impl FieldMapping {
    /// Check if this mapping's pattern matches the given field name.
    pub fn matches_field(&self, field_name: &str) -> bool {
        if self.field_pattern.contains('*') {
            let prefix = self.field_pattern.trim_end_matches("*");
            let suffix = self.field_pattern.trim_start_matches("*");

            if self.field_pattern.starts_with('*') && self.field_pattern.ends_with('*') {
                field_name.contains(&suffix)
            } else if self.field_pattern.ends_with('*') {
                field_name.starts_with(prefix)
            } else if self.field_pattern.starts_with('*') {
                field_name.ends_with(suffix)
            } else {
                false
            }
        } else if self.field_pattern.starts_with("(?i)") || self.field_pattern.starts_with("(?i:") {
            if let Ok(re) = regex::Regex::new(&self.field_pattern) {
                re.is_match(field_name)
            } else {
                false
            }
        } else {
            self.field_pattern == field_name
                || self.field_pattern.to_lowercase() == field_name.to_lowercase()
        }
    }

    /// Create a simple literal field mapping.
    pub fn literal(
        field_name: impl Into<String>,
        pii_type: impl Into<String>,
        confidence: f64,
        action: FieldAction,
    ) -> Self {
        Self {
            field_pattern: field_name.into(),
            pii_type: pii_type.into(),
            confidence,
            action,
        }
    }

    /// Create a wildcard suffix mapping (e.g., "*_id").
    pub fn wildcard(
        pattern: impl Into<String>,
        pii_type: impl Into<String>,
        confidence: f64,
        action: FieldAction,
    ) -> Self {
        Self {
            field_pattern: pattern.into(),
            pii_type: pii_type.into(),
            confidence,
            action,
        }
    }
}

/// Result of scanning a single field within a structured document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldScanResult {
    /// Path to this field (e.g., "users[0].email" or "row[2].col[5]").
    pub field_path: String,

    /// Original field name.
    pub field_name: String,

    /// Raw field value (may contain PII).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub raw_value: String,

    /// Masked/redacted version of the value.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub masked_value: String,

    /// Matched PII type from field classification.
    pub pii_type: String,

    /// Confidence that this field contains PII.
    pub confidence: f64,

    /// Action taken on this field.
    pub action: FieldAction,

    /// Row/index location (for tabular data like CSV).
    #[serde(default)]
    pub row_index: Option<usize>,

    /// Column index (for tabular data).
    #[serde(default)]
    pub col_index: Option<usize>,
}

/// Aggregated result of scanning an entire structured document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredScanResult {
    /// Document format that was scanned.
    pub format: StructuredFormat,

    /// Total fields scanned.
    pub total_fields: usize,

    /// Fields where PII was detected.
    pub pii_fields: Vec<FieldScanResult>,

    /// Overall strictest action across all findings.
    pub overall_action: FieldAction,

    /// Total bytes processed.
    pub bytes_processed: u64,

    /// Scan duration in milliseconds.
    pub scan_duration_ms: u64,
}

/// Supported structured data formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StructuredFormat {
    Csv,
    Json,
    Xml,
}

// =============================================================================
// Misogi Core — JSON PII Scanner
// =============================================================================
// Recursive field-level PII scanning for JSON documents.
//
// ## Algorithm
//
// 1. Parse JSON into serde_json::Value tree
// 2. Recursively traverse the tree:
//    - Object keys → classify via FieldClassifier
//    - String values → apply masking based on classification
//    - Arrays → process each element
// 3. Collect FieldScanResult entries with dot-notation paths
// =============================================================================

use std::time::Instant;

use super::field_classifier::FieldClassifier;
use super::types::{
    FieldAction, FieldScanResult, StructuredFormat, StructuredScanResult,
};

/// Configuration for JSON scanning behavior.
#[derive(Debug, Clone)]
pub struct JsonScannerConfig {
    /// Maximum nesting depth to traverse.
    pub max_depth: usize,

    /// How to handle array elements: "scan_each" or "skip".
    pub array_handling: ArrayHandling,

    /// Maximum document size in MB before rejection.
    pub max_size_mb: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrayHandling {
    ScanEach,
    Skip,
}

impl Default for JsonScannerConfig {
    fn default() -> Self {
        Self {
            max_depth: 10,
            array_handling: ArrayHandling::ScanEach,
            max_size_mb: 10,
        }
    }
}

/// JSON-specific PII scanner with recursive field-level classification.
pub struct JsonPiiScanner {
    classifier: FieldClassifier,
    config: JsonScannerConfig,
}

impl JsonPiiScanner {
    /// Create scanner with default universal field mappings.
    pub fn with_defaults() -> Self {
        Self {
            classifier: FieldClassifier::with_defaults(),
            config: JsonScannerConfig::default(),
        }
    }

    /// Create scanner with custom configuration.
    pub fn new(classifier: FieldClassifier, config: JsonScannerConfig) -> Self {
        Self { classifier, config }
    }

    /// Scan JSON content for field-level PII.
    pub fn scan(&self, content: &str) -> crate::error::Result<StructuredScanResult> {
        let start = Instant::now();
        let bytes_processed = content.len() as u64;

        if content.len() > self.config.max_size_mb * 1024 * 1024 {
            return Err(crate::error::MisogiError::Protocol(format!(
                "JSON document exceeds maximum size of {} MB",
                self.config.max_size_mb
            )));
        }

        let value: serde_json::Value =
            serde_json::from_str(content).map_err(|e| {
                crate::error::MisogiError::Protocol(format!("Invalid JSON: {}", e))
            })?;

        let mut pii_fields: Vec<FieldScanResult> = Vec::new();
        self.traverse_json(&value, "", 0, &mut pii_fields);

        let overall_action = Self::resolve_strictest_action(&pii_fields);
        let elapsed_ms = start.elapsed().as_millis() as u64;

        Ok(StructuredScanResult {
            format: StructuredFormat::Json,
            total_fields: pii_fields.len(),
            pii_fields,
            overall_action,
            bytes_processed,
            scan_duration_ms: elapsed_ms,
        })
    }

    fn traverse_json(
        &self,
        value: &serde_json::Value,
        path: &str,
        depth: usize,
        results: &mut Vec<FieldScanResult>,
    ) {
        if depth > self.config.max_depth {
            return;
        }

        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    let child_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };
                    let classification = self.classifier.classify(key);

                    if let serde_json::Value::String(s) = val {
                        if classification.matched && !s.is_empty() && classification.confidence >= 0.3 {
                            results.push(FieldScanResult {
                                field_path: child_path.clone(),
                                field_name: key.clone(),
                                raw_value: s.clone(),
                                masked_value: Self::mask_value(s, classification.action),
                                pii_type: classification.pii_type.clone(),
                                confidence: classification.confidence,
                                action: classification.action,
                                row_index: None,
                                col_index: None,
                            });
                        }
                    } else {
                        self.traverse_json(val, &child_path, depth + 1, results);
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                match self.config.array_handling {
                    ArrayHandling::ScanEach => {
                        for (idx, item) in arr.iter().enumerate() {
                            let child_path = format!("{}[{}]", path, idx);
                            self.traverse_json(item, &child_path, depth + 1, results);
                        }
                    }
                    ArrayHandling::Skip => {}
                }
            }
            _ => {}
        }
    }

    fn mask_value(value: &str, action: FieldAction) -> String {
        match action {
            FieldAction::Mask => {
                if value.len() <= 2 {
                    "*".repeat(value.len())
                } else {
                    let chars: Vec<char> = value.chars().collect();
                    format!(
                        "{}{}",
                        chars[0],
                        "*".repeat(chars.len() - 2).as_str(),
                        chars[chars.len() - 1]
                    )
                }
            }
            FieldAction::Redact => "[REDACTED]".to_string(),
            _ => value.to_string(),
        }
    }

    fn resolve_strictest_action(results: &[FieldScanResult]) -> FieldAction {
        if results.iter().any(|r| r.action == FieldAction::Redact) {
            FieldAction::Redact
        } else if results.iter().any(|r| r.action == FieldAction::Mask) {
            FieldAction::Mask
        } else if results.iter().any(|r| r.action == FieldAction::AlertOnly) {
            FieldAction::AlertOnly
        } else {
            FieldAction::LogOnly
        }
    }
}

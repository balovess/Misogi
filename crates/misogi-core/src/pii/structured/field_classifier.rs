// =============================================================================
// Misogi Core — Field Classifier (Configurable Field Mapping Engine)
// =============================================================================
// Maps field names to PII types using user-configurable rules.
//
// ## How It Works
//
// 1. User provides FieldMapping rules (YAML/JSON/Builder)
// 2. For each field name encountered during scanning:
//    a. Test against all mapping patterns (literal/wildcard/regex)
//    b. Return best match (highest confidence)
// 3. Scanner uses the mapped PII type + confidence to decide action
// =============================================================================

use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use super::types::{FieldAction, FieldMapping, FieldScanResult};

/// Configuration for field classifier behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldClassifierConfig {
    /// When multiple patterns match, select highest confidence.
    #[serde(default = "default_true")]
    pub select_highest_confidence: bool,

    /// Default action when no mapping matches a field.
    #[serde(default)]
    pub default_action: FieldAction,

    /// Default confidence for unmatched fields.
    #[serde(default = "default_zero_f64")]
    pub default_unmatched_confidence: f64,
}

fn default_true() -> bool {
    true
}
fn default_zero_f64() -> f64 {
    0.0
}

impl Default for FieldClassifierConfig {
    fn default() -> Self {
        Self {
            select_highest_confidence: true,
            default_action: FieldAction::AlertOnly,
            default_unmatched_confidence: 0.0,
        }
    }
}

/// Classifies field names into PII types using configurable mapping rules.
pub struct FieldClassifier {
    mappings: Arc<RwLock<Vec<FieldMapping>>>,
    config: Arc<RwLock<FieldClassifierConfig>>,
}

impl FieldClassifier {
    /// Create classifier with built-in universal defaults.
    pub fn with_defaults() -> Self {
        let yaml_str = include_str!("../../../config/pii-structured-defaults.yaml");
        let config_data: StructuredScannerConfig =
            serde_yaml::from_str(yaml_str).unwrap_or_default();

        Self {
            mappings: Arc::new(RwLock::new(config_data.field_mappings)),
            config: Arc::new(RwLock::new(FieldClassifierConfig::default())),
        }
    }

    /// Load mappings from YAML file.
    pub fn from_yaml_file(path: &str) -> crate::error::Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::error::MisogiError::Protocol(format!(
                "Failed to read field mappings '{}': {}",
                path, e
            ))
        })?;

        let config_data: StructuredScannerConfig =
            serde_yaml::from_str(&content).map_err(|e| {
                crate::error::MisogiError::Protocol(format!(
                    "Invalid YAML in field mappings '{}': {}",
                    path, e
                ))
            })?;

        Ok(Self {
            mappings: Arc::new(RwLock::new(config_data.field_mappings)),
            config: Arc::new(RwLock::new(FieldClassifierConfig::default())),
        })
    }

    /// Classify a single field name → PII type + confidence + action.
    pub fn classify(&self, field_name: &str) -> FieldClassification {
        let mappings = match self.mappings.read() {
            Ok(m) => m,
            Err(_) => return FieldClassification::unmatched(field_name),
        };

        let mut best_match: Option<&FieldMapping> = None;
        let config = self.config.read().unwrap_or_else(|_| FieldClassifierConfig::default());

        for mapping in mappings.iter() {
            if mapping.matches_field(field_name) {
                match &best_match {
                    Some(current) => {
                        if config.select_highest_confidence && mapping.confidence > current.confidence
                        {
                            best_match = Some(mapping);
                        }
                    }
                    None => {
                        best_match = Some(mapping);
                    }
                }
            }
        }

        match best_match {
            Some(m) => FieldClassification {
                pii_type: m.pii_type.clone(),
                confidence: m.confidence,
                action: m.action,
                matched: true,
            },
            None => FieldClassification::unmatched(field_name),
        }
    }

    /// Add a mapping rule at runtime.
    pub fn add_mapping(&self, mapping: FieldMapping) -> crate::error::Result<()> {
        let mut mappings = self.mappings.write().map_err(|e| {
            crate::error::MisogiError::Protocol(format!("Mappings lock poisoned: {}", e))
        })?;
        mappings.push(mapping);
        Ok(())
    }

    /// Remove all mappings matching a given field pattern.
    pub fn remove_by_pattern(&self, pattern: &str) -> crate::error::Result<usize> {
        let mut mappings = self.mappings.write().map_err(|e| {
            crate::error::MisogiError::Protocol(format!("Mappings lock poisoned: {}", e))
        })?;
        let original_len = mappings.len();
        mappings.retain(|m| m.field_pattern != pattern);
        Ok(original_len - mappings.len())
    }

    /// Get current number of loaded mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.read().map(|m| m.len()).unwrap_or(0)
    }
}

/// Result of classifying a single field name.
#[derive(Debug, Clone)]
pub struct FieldClassification {
    /// Detected PII type (empty if unmatched).
    pub pii_type: String,

    /// Confidence [0.0, 1.0].
    pub confidence: f64,

    /// Recommended action.
    pub action: FieldAction,

    /// Whether any mapping rule matched.
    pub matched: bool,
}

impl FieldClassification {
    fn unmatched(_field_name: &str) -> Self {
        Self {
            pii_type: String::new(),
            confidence: 0.0,
            action: FieldAction::AlertOnly,
            matched: false,
        }
    }
}

/// Top-level configuration structure for structured scanner (YAML format).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StructuredScannerConfig {
    /// Field name → PII type mappings.
    #[serde(default)]
    pub field_mappings: Vec<FieldMapping>,
}

/// Fluent builder for constructing [`FieldClassifier`] programmatically.
pub struct FieldClassifierBuilder {
    mappings: Vec<FieldMapping>,
    config: FieldClassifierConfig,
}

impl FieldClassifierBuilder {
    pub fn new() -> Self {
        Self {
            mappings: Vec::new(),
            config: FieldClassifierConfig::default(),
        }
    }

    pub fn add_literal(
        mut self,
        field: impl Into<String>,
        pii_type: impl Into<String>,
        confidence: f64,
        action: FieldAction,
    ) -> Self {
        self.mappings.push(FieldMapping::literal(field, pii_type, confidence, action));
        self
    }

    pub fn add_wildcard(
        mut self,
        pattern: impl Into<String>,
        pii_type: impl Into<String>,
        confidence: f64,
        action: FieldAction,
    ) -> Self {
        self.mappings.push(FieldMapping::wildcard(pattern, pii_type, confidence, action));
        self
    }

    pub fn default_action(mut self, action: FieldAction) -> Self {
        self.config.default_action = action;
        self
    }

    pub fn build(self) -> FieldClassifier {
        FieldClassifier {
            mappings: Arc::new(RwLock::new(self.mappings)),
            config: Arc::new(RwLock::new(self.config)),
        }
    }
}

impl Default for FieldClassifierBuilder {
    fn default() -> Self {
        Self::new()
    }
}

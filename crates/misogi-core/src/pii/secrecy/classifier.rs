// =============================================================================
// Misogi Core — Secrecy Level Classifier
// =============================================================================
// User-customizable confidentiality classification engine.
//
// ## How It Works
//
// 1. User defines level scheme via YAML/JSON/Builder (any number of levels)
// 2. User defines classification rules (PII type combinations → level)
// 3. For each scan result:
//    a. Collect detected PII types
//    b. Evaluate all rules against the type set
//    c. Resolve conflicts (highest/lowest rank wins)
//    d. Return [`SecrecyClassificationResult`] with level + controls
//
// ## Built-in Defaults
//
// Generic 4-tier template (Critical/High/Medium/Low/Public) provided as
// universal starting point. NOT Japan-government-specific.
// =============================================================================

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::error::{MisogiError, Result};

use super::types::{
    ClassificationRule, Condition, ControlRequirement, FallbackPolicy,
    RuleResult, SecrecyClassificationResult, SecrecyLevelDef,
};

/// Top-level secrecy scheme configuration (YAML structure).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecrecySchemeConfig {
    /// Scheme identifier (for documentation/logging).
    #[serde(default)]
    pub scheme: String,

    /// Level definitions keyed by level ID.
    #[serde(default)]
    pub levels: HashMap<String, SecrecyLevelDef>,

    /// Classification rules evaluated in order.
    #[serde(default)]
    pub classification_rules: Vec<ClassificationRule>,

    /// Fallback behavior.
    #[serde(default)]
    pub fallback: FallbackPolicy,
}

/// User-customizable secrecy level classifier.
pub struct SecrecyClassifier {
    scheme: Arc<RwLock<SecrecySchemeConfig>>,
    level_index: Arc<RwLock<HashMap<String, u32>>,
}

impl SecrecyClassifier {
    /// Create classifier with built-in generic 4-tier template.
    ///
    /// Levels: Critical(4) > High(3) > Medium(2) > Low(1) > Public(0)
    pub fn with_generic_tier() -> Result<Self> {
        let yaml_str = include_str!("../../../config/pii-secrecy-defaults.yaml");
        let config: SecrecySchemeConfig = serde_yaml::from_str(yaml_str).map_err(|e| {
            MisogiError::Protocol(format!("Invalid built-in secrecy config: {}", e))
        })?;

        Self::from_config(config)
    }

    /// Load classifier configuration from YAML file.
    pub fn from_yaml_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            MisogiError::Protocol(format!(
                "Failed to read secrecy config '{}': {}",
                path, e
            ))
        })?;

        let config: SecrecySchemeConfig =
            serde_yaml::from_str(&content).map_err(|e| {
                MisogiError::Protocol(format!(
                    "Invalid YAML in secrecy config '{}': {}",
                    path, e
                ))
            })?;

        Self::from_config(config)
    }

    fn from_config(config: SecrecySchemeConfig) -> Result<Self> {
        let mut index = HashMap::new();
        for (level_id, level_def) in &config.levels {
            index.insert(level_id.clone(), level_def.rank);
        }

        Ok(Self {
            scheme: Arc::new(RwLock::new(config)),
            level_index: Arc::new(RwLock::new(index)),
        })
    }

    /// Classify a set of detected PII types into a secrecy level.
    ///
    /// # Arguments
    /// * `pii_types` — Set of PII type identifiers found during scanning.
    ///
    /// # Returns
    /// Classification result with assigned level, controls, and reasoning.
    pub fn classify(
        &self,
        pii_types: &[&str],
    ) -> Result<SecrecyClassificationResult> {
        let scheme = self.scheme.read().map_err(|e| {
            MisogiError::Internal(format!("Scheme lock poisoned: {}", e))
        })?;

        let type_set: HashSet<&str> = pii_types.iter().copied().collect();

        let mut matches: Vec<(String, &SecrecyLevelDef, String)> = Vec::new();

        for rule in &scheme.classification_rules {
            if Self::evaluate_condition(&rule.condition, &type_set) {
                if let Some(level_def) = scheme.levels.get(&rule.result.level) {
                    matches.push((
                        rule.id.clone(),
                        level_def,
                        rule.result.reason.clone(),
                    ));
                }
            }
        }

        let (level_id, reason) = if matches.is_empty() {
            let fallback_level = scheme.fallback.unknown_default.clone();
            (
                fallback_level.clone(),
                format!(
                    "No rules matched; using fallback level: {}",
                    fallback_level
                ),
            )
        } else if matches.len() == 1 {
            let (rule_id, _, rule_reason) = &matches[0];
            (
                scheme.levels.get(&matches[0].1.id).map(|l| l.id.clone()).unwrap_or_default(),
                format!("Rule '{}' matched: {}", rule_id, rule_reason),
            )
        } else {
            match scheme.fallback.conflict_resolution.as_str() {
                "highest" => {
                    let best = matches
                        .iter()
                        .max_by_key(|(_, def, _)| def.rank)
                        .unwrap();
                    (best.1.id.clone(), best.2.clone())
                }
                "lowest" => {
                    let best = matches
                        .iter()
                        .min_by_key(|(_, def, _)| def.rank)
                        .unwrap();
                    (best.1.id.clone(), best.2.clone())
                }
                _ => {
                    let first = &matches[0];
                    (first.1.id.clone(), first.2.clone())
                }
            }
        };

        let level_def = scheme
            .levels
            .get(&level_id)
            .cloned()
            .unwrap_or(SecrecyLevelDef {
                id: level_id.clone(),
                display_name: level_id.clone(),
                rank: 0,
                color: "#6B7280".to_string(),
                required_controls: vec![],
                retention_years: 1,
            });

        Ok(SecrecyClassificationResult {
            level_id: level_def.id.clone(),
            level_display_name: level_def.display_name.clone(),
            level_rank: level_def.rank,
            level_color: level_def.color.clone(),
            matched_rules: matches.into_iter().map(|(id, _, _)| id).collect(),
            reason,
            required_controls: level_def.required_controls.clone(),
            retention_years: level_def.retention_years,
        })
    }

    fn evaluate_condition(condition: &Condition, type_set: &HashSet<&str>) -> bool {
        match condition {
            Condition::RequireAllOf { pii_types } => {
                pii_types.iter().all(|t| type_set.contains(t.as_str()))
            }
            Condition::RequireAnyOf { pii_types } => {
                pii_types.iter().any(|t| type_set.contains(t.as_str()))
            }
            Condition::PiiTypesPresent {
                pii_types,
                min_count,
            } => {
                let count = pii_types
                    .iter()
                    .filter(|t| type_set.contains(t.as_str()))
                    .count();
                count >= *min_count
            }
            Condition::ExcludeAllOf { pii_types } => {
                !pii_types.iter().any(|t| type_set.contains(t.as_str()))
            }
            Condition::ExcludeAnyOf { pii_types } => {
                !pii_types.iter().all(|t| type_set.contains(t.as_str()))
            }
        }
    }

    /// Hot-reload configuration from a YAML file.
    pub fn reload_scheme(&self, path: &str) -> Result<()> {
        let new_classifier = Self::from_yaml_file(path)?;
        let mut scheme = self.scheme.write().map_err(|e| {
            MisogiError::Internal(format!("Scheme write lock poisoned: {}", e))
        })?;
        *scheme = new_classifier.scheme.read().unwrap().clone();
        Ok(())
    }

    /// Get list of defined level IDs.
    pub fn level_ids(&self) -> Vec<String> {
        self.scheme
            .read()
            .map(|s| s.levels.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Get definition for a specific level.
    pub fn get_level(&self, level_id: &str) -> Option<SecrecyLevelDef> {
        self.scheme
            .read()
            .ok()
            .and_then(|s| s.levels.get(level_id).cloned())
    }
}

/// Fluent builder for constructing [`SecrecyClassifier`] programmatically.
pub struct SecrecySchemeBuilder {
    config: SecrecySchemeConfig,
}

impl SecrecySchemeBuilder {
    pub fn new() -> Self {
        Self {
            config: SecrecySchemeConfig::default(),
        }
    }

    pub fn set_scheme(mut self, name: impl Into<String>) -> Self {
        self.config.scheme = name.into();
        self
    }

    pub fn add_level(
        mut self,
        id: impl Into<String>,
        display_name: impl Into<String>,
        rank: u32,
        color: impl Into<String>,
    ) -> Self {
        self.config.levels.insert(
            id.into(),
            SecrecyLevelDef {
                id: String::new(),
                display_name: display_name.into(),
                rank,
                color: color.into(),
                required_controls: vec![],
                retention_years: 1,
            },
        );

        if let Some(level) = self.config.levels.get_mut(&id.into().into()) {
            level.id = id.into();
        }

        self
    }

    pub fn add_rule(
        mut self,
        rule_id: impl Into<String>,
        condition: Condition,
        level: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        self.config.classification_rules.push(ClassificationRule {
            id: rule_id.into(),
            condition,
            result: RuleResult {
                level: level.into(),
                reason: reason.into(),
            },
        });
        self
    }

    pub fn fallback_default(mut self, level: impl Into<String>) -> Self {
        self.config.fallback.unknown_default = level.into();
        self
    }

    pub fn build(self) -> Result<SecrecyClassifier> {
        SecrecyClassifier::from_config(self.config)
    }
}

impl Default for SecrecySchemeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

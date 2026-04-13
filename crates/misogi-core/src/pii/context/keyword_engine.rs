// =============================================================================
// Misogi Core — Keyword Rule Engine for Context-Aware PII Detection
// =============================================================================
// Configurable keyword-based context analyzer (zero-cost fallback when no NLP).
//
// ## How It Works
//
// Instead of expensive ML/NLP calls, this engine uses weighted keyword matching:
//
// 1. Extract context window around the regex-matched candidate
// 2. Search for **positive keywords** (suggests real PII)
// 3. Search for **anti-keywords** (suggests false positive)
// 4. Compute weighted score: Σ(positive_weights) - Σ(anti_weights)
// 5. Compare against configurable thresholds → is_pii decision
//
// ## Configuration
//
// All rules loaded from YAML/JSON or built programmatically via Builder pattern.
// No hardcoded rules — universal defaults provided as optional starting point.
// =============================================================================

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::error::{MisogiError, Result};

use super::types::{
    ContextAnalysisRequest, ContextAnalysisResponse, ContextError,
};

// =============================================================================
// Constants
// =============================================================================

const DEFAULT_CONTEXT_WINDOW: usize = 100;
const DEFAULT_POSITIVE_THRESHOLD: f64 = 0.7;
const DEFAULT_NEGATIVE_THRESHOLD: f64 = 0.3;
const DEFAULT_CONFIDENCE_BOOST: f64 = 0.15;
const DEFAULT_CONFIDENCE_PENALTY: f64 = 0.20;

// =============================================================================
// Keyword Position
// =============================================================================

/// Where to look for keywords relative to the matched text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeywordPosition {
    /// Only before the candidate text.
    Before,

    /// Only after the candidate text.
    After,

    /// Either before or after (both sides checked).
    BeforeOrAfter,

    /// Either side (same as BeforeOrAfter, alias for readability).
    Either,
}

impl Default for KeywordPosition {
    fn default() -> Self {
        Self::Either
    }
}

// =============================================================================
// Keyword Rule
// =============================================================================

/// Single keyword entry with weight and position constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeywordRule {
    /// The keyword text to search for (case-insensitive by default).
    pub keyword: String,

    /// Weight contribution when this keyword matches [0.0, 1.0].
    ///
    /// Higher values = stronger signal. Typical range: 0.50–0.95.
    #[serde(rename = "weight")]
    pub weight: f64,

    /// Where to look for this keyword relative to the candidate.
    #[serde(default)]
    pub position: KeywordPosition,
}

impl KeywordRule {
    /// Check if this keyword appears in the given context region.
    pub fn matches_in(&self, text: &str, case_sensitive: bool) -> bool {
        if text.is_empty() || self.keyword.is_empty() {
            return false;
        }

        let search_text = if case_sensitive {
            text.to_string()
        } else {
            text.to_lowercase()
        };
        let kw = if case_sensitive {
            self.keyword.clone()
        } else {
            self.keyword.to_lowercase()
        };

        search_text.contains(&kw)
    }
}

// =============================================================================
// PII Type Rules
// =============================================================================

/// Complete keyword rule set for one PII type.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PiiTypeRules {
    /// Human-readable display name for this PII category.
    #[serde(default)]
    pub display_name: String,

    /// Keywords that suggest this IS real PII (positive signals).
    #[serde(default)]
    pub positive: Vec<KeywordRule>,

    /// Keywords that suggest this is NOT PII (false positive signals).
    #[serde(default)]
    pub anti: Vec<KeywordRule>,
}

// =============================================================================
// Engine Configuration
// =============================================================================

/// Configuration for the keyword rule engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeywordEngineConfig {
    /// Maximum characters to extract before/after the candidate.
    #[serde(default = "default_context_window")]
    pub context_window_size: usize,

    /// Minimum weighted score to confirm as PII [0.0, 1.0].
    #[serde(default = "default_positive_threshold")]
    pub positive_threshold: f64,

    /// Maximum weighted score to reject as false positive [0.0, 1.0].
    #[serde(default = "default_negative_threshold")]
    pub negative_threshold: f64,

    /// Perform case-sensitive keyword matching.
    #[serde(default)]
    pub case_sensitive: bool,

    /// Profile identifier (for config inheritance).
    #[serde(default)]
    pub profile: String,
}

fn default_context_window() -> usize {
    DEFAULT_CONTEXT_WINDOW
}
fn default_positive_threshold() -> f64 {
    DEFAULT_POSITIVE_THRESHOLD
}
fn default_negative_threshold() -> f64 {
    DEFAULT_NEGATIVE_THRESHOLD
}

impl Default for KeywordEngineConfig {
    fn default() -> Self {
        Self {
            context_window_size: DEFAULT_CONTEXT_WINDOW,
            positive_threshold: DEFAULT_POSITIVE_THRESHOLD,
            negative_threshold: DEFAULT_NEGATIVE_THRESHOLD,
            case_sensitive: false,
            profile: "universal".to_string(),
        }
    }
}

// =============================================================================
// Global Anti-Keywords (apply to ALL PII types)
// =============================================================================

/// Rule set containing global anti-keywords and per-type specific rules.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeywordRuleSet {
    /// Global configuration settings.
    #[serde(default)]
    pub global_settings: KeywordEngineConfig,

    /// Anti-keywords that apply across all PII types (false positive signals).
    #[serde(default, rename = "global_anti_keywords")]
    pub global_anti_keywords: Vec<KeywordRule>,

    /// Per-PII-type keyword rules keyed by type identifier.
    #[serde(default)]
    pub pii_types: HashMap<String, PiiTypeRules>,
}

// =============================================================================
// KeywordRuleEngine
// =============================================================================

/// Configurable keyword-based context analyzer.
///
/// Provides zero-cost context analysis using weighted keyword matching.
/// All rules are externally configurable via YAML/JSON/Builder API.
pub struct KeywordRuleEngine {
    /// Loaded rule set (Arc+RwLock for runtime reload support).
    rules: Arc<RwLock<KeywordRuleSet>>,

    /// Configuration snapshot (cached for fast access).
    config: Arc<RwLock<KeywordEngineConfig>>,
}

impl KeywordRuleEngine {
    /// Create engine with built-in universal defaults.
    ///
    /// Loads international通用 keyword set covering common PII categories.
    /// Use this for quick start; customize later via YAML or Builder.
    pub fn with_defaults() -> Result<Self> {
        let rules = Self::builtin_universal_rules();
        let config = rules.global_settings.clone();
        Ok(Self {
            rules: Arc::new(RwLock::new(rules)),
            config: Arc::new(RwLock::new(config)),
        })
    }

    /// Load rules from a YAML file path.
    pub fn from_yaml_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            MisogiError::Protocol(format!("Failed to read context rules file '{}': {}", path, e))
        })?;

        let rule_set: KeywordRuleSet = serde_yaml::from_str(&content).map_err(|e| {
            MisogiError::Protocol(format!("Invalid YAML in context rules file '{}': {}", path, e))
        })?;

        let config = rule_set.global_settings.clone();
        Ok(Self {
            rules: Arc::new(RwLock::new(rule_set)),
            config: Arc::new(RwLock::new(config)),
        })
    }

    /// Merge multiple rule sources (later sources override earlier ones).
    pub fn merge(sources: Vec<KeywordRuleSource>) -> Result<Self> {
        let mut merged = KeywordRuleSet::default();

        for source in sources {
            let source_rules = match source {
                KeywordRuleSource::BuiltinUniversal => Self::builtin_universal_rules(),
                KeywordRuleSource::File(path) => {
                    let content = std::fs::read_to_string(&path).map_err(|e| {
                        MisogiError::Protocol(format!(
                            "Failed to read rule file '{}': {}", path, e
                        ))
                    })?;
                    serde_yaml::from_str(&content).map_err(|e| {
                        MisogiError::Protocol(format!(
                            "Invalid YAML in rule file '{}': {}", path, e
                        ))
                    })?
                }
                KeywordRuleSource::Inline(rules) => rules,
            };

            merged.global_anti_keywords.extend(source_rules.global_anti_keywords);
            for (type_id, type_rules) in source_rules.pii_types {
                merged.pii_types.insert(type_id, type_rules);
            }
        }

        let config = merged.global_settings.clone();
        Ok(Self {
            rules: Arc::new(RwLock::new(merged)),
            config: Arc::new(RwLock::new(config)),
        })
    }

    /// Analyze context using keyword matching.
    pub fn analyze(
        &self,
        request: &ContextAnalysisRequest,
    ) -> Result<ContextAnalysisResponse, ContextError> {
        let rules = self.rules.read().map_err(|e| {
            ContextError::Internal(format!("Rules lock poisoned: {}", e))
        })?;
        let config = self.config.read().map_err(|e| {
            ContextError::Internal(format!("Config lock poisoned: {}", e))
        })?;

        let pii_type = &request.pii_type;
        let combined = request.combined_context();

        let type_rules = rules.pii_types.get(pii_type);

        let mut positive_score = 0.0_f64;
        let mut negative_score = 0.0_f64;
        let mut matched_positives: Vec<String> = Vec::new();
        let mut matched_negatives: Vec<String> = Vec::new();

        if let Some(tr) = type_rules {
            for kw in &tr.positive {
                if self.keyword_matches_position(&kw, &request.prefix, &request.suffix, config.case_sensitive) {
                    positive_score += kw.weight;
                    matched_positives.push(kw.keyword.clone());
                }
            }

            for kw in &tr.anti {
                if self.keyword_matches_position(&kw, &request.prefix, &request.suffix, config.case_sensitive) {
                    negative_score += kw.weight;
                    matched_negatives.push(kw.keyword.clone());
                }
            }
        }

        for kw in &rules.global_anti_keywords {
            if self.keyword_matches_position(kw, &request.prefix, &request.suffix, config.case_sensitive) {
                negative_score += kw.weight;
                matched_negatives.push(format!("global:{}", kw.keyword));
            }
        }

        let net_score = positive_score - negative_score;
        let normalized_score = Self::normalize_score(net_score);
        let is_pii = normalized_score >= config.positive_threshold;
        let confidence = if is_pii {
            (normalized_score + DEFAULT_CONFIDENCE_BOOST).min(1.0)
        } else {
            (1.0 - normalized_score + DEFAULT_CONFIDENCE_PENALTY).min(1.0)
        };

        let reason = if is_pii {
            if !matched_positives.is_empty() {
                format!(
                    "Confirmed as PII: positive indicators [{}] outweigh negatives [{}]",
                    matched_positives.join(", "),
                    matched_negatives.join(", ")
                )
            } else {
                format!(
                    "Confirmed as PII (default): no strong anti-signals [{}]",
                    matched_negatives.join(", ")
                )
            }
        } else {
            format!(
                "Rejected as false positive: anti-signals [{}] outweigh positives [{}]",
                matched_negatives.join(", "),
                matched_positives.join(", ")
            )
        };

        Ok(ContextAnalysisResponse {
            is_pii,
            confidence_score: confidence,
            reason,
            matched_indicators: matched_positives,
            false_positive_signals: matched_negatives,
        })
    }

    /// Add a keyword rule at runtime (hot-update).
    pub fn add_keyword(
        &self,
        pii_type: &str,
        keyword: KeywordRule,
    ) -> Result<()> {
        let mut rules = self.rules.write().map_err(|e| {
            ContextError::Internal(format!("Rules write lock poisoned: {}", e))
        })?;

        rules
            .pii_types
            .entry(pii_type.to_string())
            .or_default()
            .positive
            .push(keyword);

        Ok(())
    }

    /// Remove a keyword rule at runtime.
    pub fn remove_keyword(
        &self,
        pii_type: &str,
        keyword_text: &str,
    ) -> Result<bool> {
        let mut rules = self.rules.write().map_err(|e| {
            ContextError::Internal(format!("Rules write lock poisoned: {}", e))
        })?;

        if let Some(type_rules) = rules.pii_types.get_mut(pii_type) {
            let original_len = type_rules.positive.len();
            type_rules.positive.retain(|kw| kw.keyword != keyword_text);
            Ok(type_rules.positive.len() < original_len)
        } else {
            Ok(false)
        }
    }

    /// Hot-reload rules from a YAML file (runtime update without restart).
    pub fn reload_from_file(&self, path: &str) -> Result<()> {
        let new_rules = Self::from_yaml_file(path)?;
        let mut rules = self.rules.write().map_err(|e| {
            ContextError::Internal(format!("Rules write lock poisoned: {}", e))
        })?;
        *rules = new_rules.rules.read().unwrap().clone();
        Ok(())
    }

    fn keyword_matches_position(
        &self,
        kw: &KeywordRule,
        prefix: &str,
        suffix: &str,
        case_sensitive: bool,
    ) -> bool {
        match kw.position {
            KeywordPosition::Before => kw.matches_in(prefix, case_sensitive),
            KeywordPosition::After => kw.matches_in(suffix, case_sensitive),
            KeywordPosition::BeforeOrAfter | KeywordPosition::Either => {
                kw.matches_in(prefix, case_sensitive) || kw.matches_in(suffix, case_sensitive)
            }
        }
    }

    fn normalize_score(raw_score: f64) -> f64 {
        (raw_score.tanh() + 1.0) / 2.0
    }

    fn builtin_universal_rules() -> KeywordRuleSet {
        let yaml_str = include_str!("../../../config/pii-context-defaults.yaml");
        serde_yaml::from_str(yaml_str).unwrap_or_default()
    }
}

// =============================================================================
// Builder Pattern
// =============================================================================

/// Fluent builder for constructing [`KeywordRuleEngine`] programmatically.
///
/// Use when YAML configuration is insufficient (dynamic rule generation, etc.).
pub struct RuleEngineBuilder {
    rule_set: KeywordRuleSet,
}

impl RuleEngineBuilder {
    /// Create a new builder with empty rules.
    pub fn new() -> Self {
        Self {
            rule_set: KeywordRuleSet::default(),
        }
    }

    /// Set the profile identifier.
    pub fn set_profile(mut self, profile: impl Into<String>) -> Self {
        self.rule_set.global_settings.profile = profile.into();
        self
    }

    /// Set context window size.
    pub fn set_context_window(mut self, size: usize) -> Self {
        self.rule_set.global_settings.context_window_size = size;
        self
    }

    /// Set positive/negative thresholds.
    pub fn set_thresholds(mut self, positive: f64, negative: f64) -> Self {
        self.rule_set.global_settings.positive_threshold = positive;
        self.rule_set.global_settings.negative_threshold = negative;
        self
    }

    /// Enable/disable case-sensitive matching.
    pub fn set_case_sensitive(mut self, sensitive: bool) -> Self {
        self.rule_set.global_settings.case_sensitive = sensitive;
        self
    }

    /// Add a PII type with rules.
    pub fn add_pii_type(
        mut self,
        type_id: impl Into<String>,
        display_name: impl Into<String>,
    ) -> PiiTypeRuleBuilder<'_> {
        let type_id = type_id.into();
        let display_name = display_name.into();
        self.rule_set.pii_types.insert(
            type_id.clone(),
            PiiTypeRules {
                display_name,
                ..Default::default()
            },
        );
        PiiTypeRuleBuilder {
            parent: self,
            type_id,
        }
    }

    /// Add a global anti-keyword.
    pub fn add_global_anti(
        mut self,
        keyword: impl Into<String>,
        weight: f64,
        position: KeywordPosition,
    ) -> Self {
        self.rule_set.global_anti_keywords.push(KeywordRule {
            keyword: keyword.into(),
            weight,
            position,
        });
        self
    }

    /// Build the finalized engine.
    pub fn build(self) -> Result<KeywordRuleEngine> {
        let config = self.rule_set.global_settings.clone();
        Ok(KeywordRuleEngine {
            rules: Arc::new(RwLock::new(self.rule_set)),
            config: Arc::new(RwLock::new(config)),
        })
    }
}

impl Default for RuleEngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Sub-builder for adding rules to a specific PII type.
pub struct PiiTypeRuleBuilder<'a> {
    parent: RuleEngineBuilder,
    type_id: String,
}

impl<'a> PiiTypeRuleBuilder<'a> {
    /// Add a positive keyword for this PII type.
    pub fn add_positive(
        mut self,
        keyword: impl Into<String>,
        weight: f64,
        position: KeywordPosition,
    ) -> Self {
        if let Some(rules) = self.parent.rule_set.pii_types.get_mut(&self.type_id) {
            rules.positive.push(KeywordRule {
                keyword: keyword.into(),
                weight,
                position,
            });
        }
        self
    }

    /// Add an anti-keyword for this PII type.
    pub fn add_anti(
        mut self,
        keyword: impl Into<String>,
        weight: f64,
        position: KeywordPosition,
    ) -> Self {
        if let Some(rules) = self.parent.rule_set.pii_types.get_mut(&self.type_id) {
            rules.anti.push(KeywordRule {
                keyword: keyword.into(),
                weight,
                position,
            });
        }
        self
    }

    /// Finish this PII type and return to parent builder.
    pub fn done(self) -> RuleEngineBuilder {
        self.parent
    }
}

// =============================================================================
// Rule Source (for merge operation)
// =============================================================================

/// Source of keyword rules for merging.
pub enum KeywordRuleSource {
    /// Built-in universal defaults.
    BuiltinUniversal,

    /// Load from file path.
    File(String),

    /// Inline rule set (already parsed).
    Inline(KeywordRuleSet),
}

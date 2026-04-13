// =============================================================================
// Misogi Core — PII Context Analysis Types
// =============================================================================
// Shared data structures for context-aware PII detection.
//
// ## Design Philosophy
//
// All context analysis follows a request/response pattern:
// - Input: candidate text matched by regex + surrounding context + PII type hint
// - Output: is_pii boolean + confidence score + reasoning
//
// These types are serialization-friendly (serde) for both:
// - YAML/JSON configuration loading (KeywordRuleEngine)
// - External NLP provider communication (ContextProvider trait)
// =============================================================================

use serde::{Deserialize, Serialize};

// =============================================================================
// A. Context Analysis Request
// =============================================================================

/// Request payload for context analysis.
///
/// Carries the regex-matched candidate text along with its surrounding context
/// to enable disambiguation of false positives (e.g., "123456789012" as My Number
/// vs. invoice number vs. serial number).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextAnalysisRequest {
    /// The exact text matched by the regex pattern.
    ///
    /// Example: `"123456789012"` when scanning for My Number.
    pub candidate_text: String,

    /// PII type identifier from the matching rule.
    ///
    /// Example: `"my_number"`, `"credit_card"`, `"national_id"`.
    /// Used to select type-specific analysis rules.
    pub pii_type: String,

    /// Text immediately preceding the match (within context window).
    ///
    /// Used for keyword-based positive/negative signal detection.
    /// Example: `"My Number: "` before a 12-digit number.
    pub prefix: String,

    /// Text immediately following the match (within context window).
    ///
    /// Example: `" is your ID"` after a number.
    pub suffix: String,

    /// Optional full document text for deep NLP analysis.
    ///
    /// May be omitted for performance; prefix/suffix are usually sufficient.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_text: Option<String>,

    /// Additional metadata for context enrichment.
    #[serde(default)]
    pub metadata: ContextMetadata,
}

/// Metadata attached to context analysis requests.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContextMetadata {
    /// Source filename or identifier.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source_file: String,

    /// Document language hint (ISO 639-1).
    ///
    /// Example: `"en"`, `"ja"`, `"zh"`, `"auto"`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub language: String,

    /// Document MIME type if known.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mime_type: String,

    /// Custom key-value pairs for extensibility.
    #[serde(flatten, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub extra: std::collections::HashMap<String, String>,
}

impl ContextAnalysisRequest {
    /// Create a minimal request with required fields only.
    pub fn new(
        candidate_text: impl Into<String>,
        pii_type: impl Into<String>,
        prefix: impl Into<String>,
        suffix: impl Into<String>,
    ) -> Self {
        Self {
            candidate_text: candidate_text.into(),
            pii_type: pii_type.into(),
            prefix: prefix.into(),
            suffix: suffix.into(),
            full_text: None,
            metadata: ContextMetadata::default(),
        }
    }

    /// Combined context text (prefix + candidate + suffix).
    pub fn combined_context(&self) -> String {
        format!("{}{}{}", self.prefix, self.candidate_text, self.suffix)
    }
}

// =============================================================================
// B. Context Analysis Response
// =============================================================================

/// Response from context analysis (either NLP provider or rule engine).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextAnalysisResponse {
    /// Whether the candidate text is confirmed as real PII.
    ///
    /// `true` = keep the regex match; `false` = discard as false positive.
    pub is_pii: bool,

    /// Confidence score in [0.0, 1.0].
    ///
    /// Higher values indicate stronger confidence in the classification.
    /// Thresholds are configurable per-engine (default: positive ≥ 0.7, negative ≤ 0.3).
    #[serde(rename = "confidence")]
    pub confidence_score: f64,

    /// Human-readable explanation for the decision.
    ///
    /// Included in audit logs for compliance review.
    pub reason: String,

    /// Keywords or signals that supported the "is PII" conclusion.
    #[serde(default)]
    pub matched_indicators: Vec<String>,

    /// Keywords or signals that suggested "not PII" (false positive).
    #[serde(default)]
    pub false_positive_signals: Vec<String>},

// =============================================================================
// C. Context Error Types
// =============================================================================

/// Errors from context analysis operations.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    /// The configured NLP provider is unavailable or misconfigured.
    #[error("Context provider '{provider}' unavailable: {message}")]
    ProviderUnavailable {
        provider: String,
        message: String,
    },

    /// Network or communication failure with external NLP service.
    #[error("Provider communication failed: {0}")]
    Communication(String),

    /// Invalid request parameters (empty candidate, unknown PII type, etc.).
    #[error("Invalid context analysis request: {0}")]
    InvalidRequest(String),

    /// Rate limit or quota exceeded on external service.
    #[error("Rate limited by provider '{provider}': retry_after={retry_after_secs}s")]
    RateLimited {
        provider: String,
        retry_after_secs: u64,
    },

    /// Authentication failure with external NLP service.
    #[error("Authentication failed for provider '{provider}': {0}")]
    Authentication {
        provider: String,
        message: String,
    },

    /// Timeout waiting for NLP provider response.
    #[error("Provider timeout after {timeout_ms}ms")]
    Timeout {
        timeout_ms: u64,
    },

    /// Configuration error (missing API key, invalid YAML, etc.).
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Internal engine error (rule loading, cache corruption, etc.).
    #[error("Internal context engine error: {0}")]
    Internal(String),
}

impl ContextError {
    /// Whether this error is transient (retryable).
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Communication(_)
                | Self::RateLimited { .. }
                | Self::Timeout { .. }
                | Self::ProviderUnavailable { .. }
        )
    }

    /// Extract provider name if available.
    pub fn provider_name(&self) -> Option<&str> {
        match self {
            Self::ProviderUnavailable { provider, .. } => Some(provider),
            Self::RateLimited { provider, .. } => Some(provider),
            Self::Authentication { provider, .. } => Some(provider),
            _ => None,
        }
    }
}

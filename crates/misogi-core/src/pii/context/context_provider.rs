// =============================================================================
// Misogi Core — PII Context Provider Trait
// =============================================================================
// Standard interface for pluggable NLP/ML context analysis providers.
//
// ## Architecture
//
// Misogi does NOT bundle any NLP implementation. This trait defines the
// contract that external providers must fulfill:
//
// - OpenAI GPT-4 / Azure OpenAI
// - AWS Comprehend / Google Cloud NLP
// - Ollama (local LLM)
// - Custom self-hosted services
//
// Users implement this trait and inject it into [`ContextAnalyzer`].
// If no provider is configured, the system falls back to [`KeywordRuleEngine`].
// =============================================================================

use async_trait::async_trait;

use super::types::{
    ContextAnalysisRequest, ContextAnalysisResponse, ContextError,
};

// =============================================================================
// ContextProvider Trait
// =============================================================================

/// Standard trait for context-aware PII analysis providers.
///
/// Implementors receive regex-matched candidates and determine whether they
/// represent genuine PII based on linguistic context, not just pattern shape.
///
/// # Interface Contract
///
/// **Input**: Candidate text + surrounding context window + PII type hint
/// **Output**: Binary decision (is_pii) + confidence + explanation
///
/// # Recommended Implementation Patterns
///
/// | Provider Type | Latency | Cost | Accuracy |
/// |--------------|---------|------|----------|
/// | GPT-4 / Claude | 500ms-2s | $$ | Very High |
/// | Azure Language | 100-300ms | $ | High |
/// | Ollama local | 200ms-800ms | Free | Medium-High |
/// | Keyword rules | <1ms | Free | Medium |
///
/// # Example Implementation (OpenAI)
///
/// ```ignore
/// struct OpenAiContextProvider {
///     client: reqwest::Client,
///     api_key: String,
///     model: String,
/// }
///
/// #[async_trait]
/// impl ContextProvider for OpenAiContextProvider {
///     async fn analyze_context(
///         &self,
///         request: &ContextAnalysisRequest,
///     ) -> Result<ContextAnalysisResponse, ContextError> {
///         // Call OpenAI Chat Completions API
///         // Parse structured JSON response
///         // Return ContextAnalysisResponse
///     }
///     // ... other methods
/// }
/// ```
#[async_trait]
pub trait ContextProvider: Send + Sync {
    /// Analyze whether a regex-matched candidate is genuine PII.
    ///
    /// This is the primary method called for each regex match that needs
    /// context disambiguation.
    ///
    /// # Arguments
    /// * `request` — Contains candidate text, context window, PII type hint.
    ///
    /// # Returns
    /// * `Ok(ContextAnalysisResponse)` — Classification result with confidence.
    /// * `Err(ContextError)` — Provider-specific error (network, auth, etc.).
    async fn analyze_context(
        &self,
        request: &ContextAnalysisRequest,
    ) -> Result<ContextAnalysisResponse, ContextError>;

    /// Batch-analyze multiple candidates (performance optimization).
    ///
    /// Implementations may batch requests to reduce per-call overhead.
    /// Default implementation calls `analyze_context()` sequentially.
    ///
    /// # Arguments
    /// * `requests` — Multiple context analysis requests.
    ///
    /// # Returns
    /// Vector of responses in the same order as input requests.
    async fn analyze_batch(
        &self,
        requests: &[ContextAnalysisRequest],
    ) -> Result<Vec<ContextAnalysisResponse>, ContextError> {
        let mut results = Vec::with_capacity(requests.len());
        for req in requests {
            results.push(self.analyze_context(req).await?);
        }
        Ok(results)
    }

    /// Human-readable name of this provider instance.
    ///
    /// Used in logs and audit trails for traceability.
    /// Examples: `"openai-gpt4"`, `"azure-language"`, `"ollama-llama3"`.
    fn provider_name(&self) -> &str;

    /// Check if this provider is currently available and healthy.
    ///
    /// Called at startup and periodically for health monitoring.
    /// Should perform lightweight connectivity check (not full model inference).
    ///
    /// # Returns
    /// * `Ok(true)` — Provider is ready to accept requests.
    /// * `Ok(false)` — Provider exists but is temporarily down.
    /// * `Err(ContextError)` — Health check itself failed.
    async fn is_available(&self) -> Result<bool, ContextError>;
}

// =============================================================================
// MockContextProvider (for testing)
// =============================================================================

/// Deterministic mock implementation of [`ContextProvider`] for testing.
///
/// Returns pre-configured responses without any network calls.
/// Supports both always-PII and never-PII modes for test coverage.
pub struct MockContextProvider {
    name: String,
    available: bool,
    always_pii: bool,
    fixed_confidence: f64,
}

impl MockContextProvider {
    /// Create a mock provider that always confirms PII.
    pub fn always_confirm() -> Self {
        Self {
            name: "mock-always-pii".to_string(),
            available: true,
            always_pii: true,
            fixed_confidence: 0.95,
        }
    }

    /// Create a mock provider that always rejects (marks as false positive).
    pub fn always_reject() -> Self {
        Self {
            name: "mock-always-reject".to_string(),
            available: true,
            always_pii: false,
            fixed_confidence: 0.05,
        }
    }

    /// Create a mock provider with custom settings.
    pub fn with_config(
        name: impl Into<String>,
        available: bool,
        always_pii: bool,
        confidence: f64,
    ) -> Self {
        Self {
            name: name.into(),
            available,
            always_pii,
            fixed_confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

#[async_trait]
impl ContextProvider for MockContextProvider {
    async fn analyze_context(
        &self,
        request: &ContextAnalysisRequest,
    ) -> Result<ContextAnalysisResponse, ContextError> {
        if !self.available {
            return Err(ContextError::ProviderUnavailable {
                provider: self.name.clone(),
                message: "Mock provider configured as unavailable".to_string(),
            });
        }

        Ok(ContextAnalysisResponse {
            is_pii: self.always_pii,
            confidence_score: self.fixed_confidence,
            reason: if self.always_pii {
                format!("Mock confirmed '{}' as {} PII", request.candidate_text, request.pii_type)
            } else {
                format!("Mock rejected '{}' as false positive", request.candidate_text)
            },
            matched_indicators: if self.always_pii {
                vec!["mock-positive".to_string()]
            } else {
                vec![]
            },
            false_positive_signals: if !self.always_pii {
                vec!["mock-negative".to_string()]
            } else {
                vec![]
            },
        })
    }

    fn provider_name(&self) -> &str {
        &self.name
    }

    async fn is_available(&self) -> Result<bool, ContextError> {
        Ok(self.available)
    }
}

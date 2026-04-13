// =============================================================================
// Misogi Core — Context Analyzer (Unified Entry Point)
// =============================================================================
// Routes context analysis requests to either:
// 1. External NLP provider (ContextProvider trait implementation), or
// 2. Built-in keyword rule engine (KeywordRuleEngine) as fallback
//
// ## Routing Logic
//
// ```
// Request → Provider available?
//   ├─ YES → Use ContextProvider.analyze_context()
//   └─ NO  → Use KeywordRuleEngine.analyze()
//              (zero-cost, YAML-configurable keyword matching)
// ```
//
// This design ensures the system ALWAYS works — even without any external
// NLP service configured. The keyword engine provides baseline accuracy.
// =============================================================================

use std::sync::Arc;

use super::context_provider::{ContextProvider, MockContextProvider};
use super::keyword_engine::KeywordRuleEngine;
use super::types::{
    ContextAnalysisRequest, ContextAnalysisResponse, ContextError,
};

use crate::error::Result;

/// Strategy for handling provider unavailability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackStrategy {
    /// Return error if provider is unavailable.
    FailFast,

    /// Silently fall back to keyword engine when provider is down.
    GracefulDegradation,

    /// Always use keyword engine (ignore provider even if available).
    KeywordOnly,
}

/// Configuration for [`ContextAnalyzer`].
#[derive(Debug, Clone)]
pub struct ContextAnalyzerConfig {
    /// How to handle NLP provider failures.
    pub fallback: FallbackStrategy,

    /// Cache analysis results for identical inputs (avoid redundant calls).
    pub enable_cache: bool,

    /// Maximum cache entries (LRU eviction).
    pub cache_size: usize,
}

impl Default for ContextAnalyzerConfig {
    fn default() -> Self {
        Self {
            fallback: FallbackStrategy::GracefulDegradation,
            enable_cache: true,
            cache_size: 1000,
        }
    }
}

/// Unified entry point for context-aware PII analysis.
///
/// Wraps both external NLP providers and the built-in keyword engine,
/// providing a single `analyze()` method that routes to the best available
/// backend automatically.
pub struct ContextAnalyzer {
    /// Optional external NLP provider (user-injected).
    provider: Option<Arc<dyn ContextProvider>>,

    /// Built-in keyword rule engine (always available as fallback).
    keyword_engine: Arc<KeywordRuleEngine>,

    /// Configuration controlling routing behavior.
    config: ContextAnalyzerConfig,
}

impl ContextAnalyzer {
    /// Create analyzer with keyword engine only (no external provider).
    pub fn with_keyword_engine(engine: KeywordRuleEngine) -> Self {
        Self {
            provider: None,
            keyword_engine: Arc::new(engine),
            config: ContextAnalyzerConfig::default(),
        }
    }

    /// Create analyzer with both NLP provider and keyword fallback.
    pub fn with_provider(
        provider: Arc<dyn ContextProvider>,
        fallback_engine: KeywordRuleEngine,
    ) -> Self {
        Self {
            provider: Some(provider),
            keyword_engine: Arc::new(fallback_engine),
            config: ContextAnalyzerConfig::default(),
        }
    }

    /// Create analyzer with default universal keyword rules (quick start).
    pub fn with_defaults() -> Result<Self> {
        let engine = KeywordRuleEngine::with_defaults()?;
        Ok(Self::with_keyword_engine(engine))
    }

    /// Set custom configuration.
    pub fn with_config(mut self, config: ContextAnalyzerConfig) -> Self {
        self.config = config;
        self
    }

    /// Analyze whether a regex-matched candidate is genuine PII.
    ///
    /// Automatically routes to the best available backend:
    /// - If NLP provider is configured and available → use it
    /// - Otherwise → fall back to keyword engine
    ///
    /// # Arguments
    /// * `request` — Context analysis request with candidate + surrounding text.
    ///
    /// # Returns
    /// Analysis result with is_pii decision, confidence, and reasoning.
    pub async fn analyze(
        &self,
        request: &ContextAnalysisRequest,
    ) -> Result<ContextAnalysisResponse> {
        match &self.provider {
            Some(provider) => {
                let available = provider.is_available().await.unwrap_or(false);

                if available && self.config.fallback != FallbackStrategy::KeywordOnly {
                    match provider.analyze_context(request).await {
                        Ok(response) => Ok(response),
                        Err(e) => match self.config.fallback {
                            FallbackStrategy::FailFast => Err(crate::error::MisogiError::Protocol(
                                format!("NLP provider failed: {}", e),
                            )),
                            _ => self.keyword_engine_analyze(request),
                        },
                    }
                } else {
                    self.keyword_engine_analyze(request)
                }
            }
            None => self.keyword_engine_analyze(request),
        }
    }

    /// Force-use keyword engine (bypass provider).
    pub fn analyze_with_keywords(
        &self,
        request: &ContextAnalysisRequest,
    ) -> Result<ContextAnalysisResponse> {
        self.keyword_engine_analyze(request)
    }

    fn keyword_engine_analyze(
        &self,
        request: &ContextAnalysisRequest,
    ) -> Result<ContextAnalysisResponse> {
        self.keyword_engine
            .analyze(request)
            .map_err(|e| crate::error::MisogiError::Protocol(format!("Keyword engine error: {}", e)))
    }

    /// Check if an external NLP provider is configured.
    pub fn has_provider(&self) -> bool {
        self.provider.is_some()
    }

    /// Get provider name if configured.
    pub fn provider_name(&self) -> Option<&str> {
        self.provider.as_ref().map(|p| p.provider_name())
    }

    /// Access the underlying keyword engine (for runtime rule updates).
    pub fn keyword_engine(&self) -> &Arc<KeywordRuleEngine> {
        &self.keyword_engine
    }
}

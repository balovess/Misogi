// =============================================================================
// Misogi Core — PII Context Analysis Module
// =============================================================================
// Context-aware PII detection via pluggable NLP interface + configurable rules.
//
// ## Submodules
//
// | Module | Description |
// |--------|-------------|
// | [`types`] | Shared Request/Response/Error data structures |
// | [`context_provider`] | **ContextProvider trait** (standard NLP interface) |
// | [`keyword_engine`] | Configurable keyword-based rule engine |
// | [`context_analyzer`] | Unified entry point (routes to provider or keywords) |

pub mod types;
pub mod context_provider;
pub mod keyword_engine;
pub mod context_analyzer;

pub use types::{
    ContextAnalysisRequest,
    ContextAnalysisResponse,
    ContextError,
    ContextMetadata,
};

pub use context_provider::{
    ContextProvider,
    MockContextProvider,
};

pub use keyword_engine::{
    KeywordRuleEngine,
    KeywordRuleSet,
    KeywordRule,
    PiiTypeRules,
    KeywordEngineConfig,
    KeywordPosition,
    RuleEngineBuilder,
    KeywordRuleSource,
};

pub use context_analyzer::{
    ContextAnalyzer,
    ContextAnalyzerConfig,
    FallbackStrategy,
};

// =============================================================================
// Misogi Core — PII Secrecy Level Classification Module
// =============================================================================
// User-customizable confidentiality classification engine.
//
// ## Submodules
//
// | Module | Description |
// |--------|-------------|
// | [`types`] | SecrecyLevelDef, ClassificationRule, Condition, etc. |
// | [`classifier`] | SecrecyClassifier (configurable classification engine) |

pub mod types;
pub mod classifier;

pub use types::{
    Condition,
    ControlRequirement,
    FallbackPolicy,
    RuleResult,
    SecrecyClassificationResult,
    SecrecyLevelDef,
    ClassificationRule,
};

pub use classifier::{
    SecrecyClassifier,
    SecrecySchemeBuilder,
    SecrecySchemeConfig,
};

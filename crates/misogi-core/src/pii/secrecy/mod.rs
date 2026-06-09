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

pub mod classifier;
pub mod types;

pub use types::{
    ClassificationRule, Condition, ControlRequirement, FallbackPolicy, RuleResult,
    SecrecyClassificationResult, SecrecyLevelDef,
};

pub use classifier::{SecrecyClassifier, SecrecySchemeBuilder, SecrecySchemeConfig};

//! Configuration types for self-healing transport behavior tuning.
//!
//! Provides fine-grained control over repair strategy, checkpoint-based
//! resume, post-transfer verification strictness, and core integrity
//! settings. All configuration types implement `Serialize`/`Deserialize`
//! for persistence to TOML/JSON configuration files.
//!
//! # Hierarchy
//!
//! [`IntegrityConfig`] is the top-level container that holds all sub-configs:
//!
//! ```text
//! IntegrityConfig
//! +-- hash_algorithm: String
//! +-- chunk_linking: bool
//! +-- anti_replay_nonce: bool
//! +-- repair: RepairConfig
//! |   +-- auto_repair: bool
//! |   +-- max_repair_attempts: u32
//! |   +-- repair_timeout_secs: u64
//! |   +-- parallel_repair: bool
//! +-- resume: ResumeConfig
//! |   +-- checkpoint_interval_chunks: u32
//! |   +-- resume_from_checkpoint: bool
//! |   +-- session_persistence_path: String
//! +-- verification: VerificationConfig
//!     +-- post_transfer_full_verify: bool
//!     +-- zero_tolerance: bool
//! ```

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ===========================================================================
// Error Types
// ===========================================================================

/// Error type for integrity configuration parsing and validation.
///
/// Covers TOML deserialization failures, file I/O errors, semantic
/// validation violations, and unsupported algorithm identifiers.
#[derive(Debug, Error)]
pub enum IntegrityConfigError {
    /// Underlying TOML parser reported a syntax or type error.
    #[error("TOML parse error: {0}")]
    ParseError(#[from] toml::de::Error),

    /// File system operation failed during config loading.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Semantic validation detected an invalid parameter combination.
    #[error("validation failed: {0}")]
    ValidationFailed(String),

    /// The hash algorithm string is not in the supported set.
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

// ===========================================================================
// Serde Default Functions (const where possible)
// ===========================================================================

// -- RepairConfig defaults --

const fn default_auto_repair() -> bool {
    true
}

const fn default_max_repair_attempts() -> u32 {
    3
}

const fn default_repair_timeout_secs() -> u64 {
    30
}

// -- ResumeConfig defaults --

const fn default_checkpoint_interval() -> u32 {
    50
}

const fn default_resume_from_checkpoint() -> bool {
    true
}

fn default_persistence_path() -> String {
    "./misogi_sessions".to_string()
}

// -- VerificationConfig defaults --

const fn default_post_transfer_verify() -> bool {
    true
}

// -- IntegrityConfig top-level defaults --

fn default_hash_algorithm() -> String {
    "sha256".to_string()
}

const fn default_chunk_linking() -> bool {
    true
}

const fn default_anti_replay_nonce() -> bool {
    true
}

const fn default_enabled() -> bool {
    true
}

// ===========================================================================
// Repair Configuration
// ===========================================================================

/// Configuration for automatic chunk repair behavior.
///
/// Controls how the transport layer responds to missing or corrupted
/// chunks detected during verification. Tuning these parameters affects
/// both latency (repair time) and reliability (recovery probability).
///
/// All fields carry `#[serde(default)]` so omitted TOML keys receive
/// sensible production-ready defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairConfig {
    /// If true, automatically initiate repair when verification finds issues.
    #[serde(default = "default_auto_repair")]
    pub auto_repair: bool,

    /// Maximum number of retransmission attempts per chunk before giving up.
    #[serde(default = "default_max_repair_attempts")]
    pub max_repair_attempts: u32,

    /// Timeout in seconds for a single repair request round-trip.
    #[serde(default = "default_repair_timeout_secs")]
    pub repair_timeout_secs: u64,

    /// If true, request multiple missing chunks in parallel.
    #[serde(default)]
    pub parallel_repair: bool,
}

impl Default for RepairConfig {
    fn default() -> Self {
        Self {
            auto_repair: true,
            max_repair_attempts: 3,
            repair_timeout_secs: 30,
            parallel_repair: false,
        }
    }
}

// ===========================================================================
// Resume Configuration
// ===========================================================================

/// Configuration for checkpoint-based session resume.
///
/// Enables interrupted transfers to resume from the last confirmed
/// checkpoint rather than restarting from the beginning. Checkpoints
/// are persisted to disk at configurable intervals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeConfig {
    /// Number of chunks between consecutive checkpoints.
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval_chunks: u32,

    /// If true, automatically resume from the most recent checkpoint.
    #[serde(default = "default_resume_from_checkpoint")]
    pub resume_from_checkpoint: bool,

    /// File system path where session state is persisted.
    #[serde(default = "default_persistence_path")]
    pub session_persistence_path: String,
}

impl Default for ResumeConfig {
    fn default() -> Self {
        Self {
            checkpoint_interval_chunks: 50,
            resume_from_checkpoint: true,
            session_persistence_path: "./misogi_sessions".to_string(),
        }
    }
}

// ===========================================================================
// Verification Configuration
// ===========================================================================

/// Configuration for post-transfer integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    /// If true, run full verification after all chunks are transferred.
    #[serde(default = "default_post_transfer_verify")]
    pub post_transfer_full_verify: bool,

    /// If true, treat ANY integrity failure as fatal (zero tolerance mode).
    #[serde(default)]
    pub zero_tolerance: bool,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            post_transfer_full_verify: true,
            zero_tolerance: false,
        }
    }
}

// ===========================================================================
// Integrity Configuration (Top-Level)
// ===========================================================================

/// Top-level configuration for the integrity subsystem.
///
/// Aggregates all sub-configurations into a single structure that can be
/// deserialized from a configuration file (TOML/JSON). All fields carry
/// `#[serde(default)]` so minimal TOML documents (e.g. just `enabled =
/// true`) produce fully valid configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityConfig {
    /// Master switch for the entire integrity subsystem.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Hash algorithm identifier (case-insensitive; canonical: lowercase).
    ///
    /// Supported values: `"sha256"`, `"sha512"`, `"blake3"`.
    #[serde(default = "default_hash_algorithm")]
    pub hash_algorithm: String,

    /// If true, each envelope references the previous chunk's hash.
    #[serde(default = "default_chunk_linking")]
    pub chunk_linking: bool,

    /// If true, include monotonically increasing sequence nonces.
    #[serde(default = "default_anti_replay_nonce")]
    pub anti_replay_nonce: bool,

    /// Automatic repair behavior configuration.
    #[serde(default)]
    pub repair: RepairConfig,

    /// Checkpoint-based resume configuration.
    #[serde(default)]
    pub resume: ResumeConfig,

    /// Post-transfer verification configuration.
    #[serde(default)]
    pub verification: VerificationConfig,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hash_algorithm: "sha256".to_string(),
            chunk_linking: true,
            anti_replay_nonce: true,
            repair: RepairConfig::default(),
            resume: ResumeConfig::default(),
            verification: VerificationConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Factory methods
// ---------------------------------------------------------------------------

impl IntegrityConfig {
    /// Create a secure default configuration using SHA-256 hashing.
    ///
    /// Produces a production-ready configuration suitable for most
    /// deployments where security and reliability are both important.
    pub fn sha256_default() -> Self {
        Self::default()
    }

    /// Create a configuration optimized for high-throughput transfers.
    ///
    /// Uses BLAKE3 for superior hashing throughput, disables chunk-linking
    /// overhead, enables parallel repair, and uses shorter timeouts.
    pub fn high_throughput() -> Self {
        Self {
            enabled: true,
            hash_algorithm: "blake3".to_string(),
            chunk_linking: false,
            anti_replay_nonce: true,
            repair: RepairConfig {
                auto_repair: true,
                max_repair_attempts: 2,
                repair_timeout_secs: 15,
                parallel_repair: true,
            },
            resume: ResumeConfig {
                checkpoint_interval_chunks: 100,
                resume_from_checkpoint: true,
                session_persistence_path: "./misogi_sessions".to_string(),
            },
            verification: VerificationConfig {
                post_transfer_full_verify: true,
                zero_tolerance: false,
            },
        }
    }

    /// Create a configuration with maximum security settings.
    ///
    /// Uses SHA-512, sequential (auditable) repair, frequent checkpoints,
    /// and zero-tolerance mode where any corruption causes total failure.
    pub fn maximum_security() -> Self {
        Self {
            enabled: true,
            hash_algorithm: "sha512".to_string(),
            chunk_linking: true,
            anti_replay_nonce: true,
            repair: RepairConfig {
                auto_repair: true,
                max_repair_attempts: 5,
                repair_timeout_secs: 60,
                parallel_repair: false,
            },
            resume: ResumeConfig {
                checkpoint_interval_chunks: 10,
                resume_from_checkpoint: true,
                session_persistence_path: "./misogi_sessions".to_string(),
            },
            verification: VerificationConfig {
                post_transfer_full_verify: true,
                zero_tolerance: true,
            },
        }
    }

    // ---------------------------------------------------------------------------
    // TOML loading
    // ---------------------------------------------------------------------------

    /// Deserialize an [`IntegrityConfig`] from a TOML-formatted string.
    ///
    /// Parses the provided TOML text, applies defaults via `#[serde(default)]`,
    /// then runs [`Self::validate()`] for semantic correctness.
    ///
    /// # Errors
    ///
    /// - [`IntegrityConfigError::ParseError`] on invalid TOML syntax.
    /// - [`IntegrityConfigError::ValidationFailed`] on semantic violations.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, IntegrityConfigError> {
        let config: Self = toml::from_str(toml_str).map_err(IntegrityConfigError::ParseError)?;
        config
            .validate()
            .map_err(IntegrityConfigError::ValidationFailed)?;
        Ok(config)
    }

    /// Read and deserialize an [`IntegrityConfig`] from a TOML file on disk.
    ///
    /// Opens the file at `path`, reads its contents as UTF-8, then delegates
    /// to [`Self::from_toml_str()`].
    ///
    /// # Errors
    ///
    /// - [`IntegrityConfigError::IoError`] on file I/O failure.
    /// - Propagates parse/validation errors from [`Self::from_toml_str()`].
    pub fn load_from_file(path: &Path) -> Result<Self, IntegrityConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml_str(&content)
    }

    // ---------------------------------------------------------------------------
    // Validation
    // ---------------------------------------------------------------------------

    /// Validate all configuration parameters for semantic correctness.
    ///
    /// Checks performed:
    /// 1. Hash algorithm is one of `"sha256"`, `"sha512"`, `"blake3"`
    ///    (case-insensitive).
    /// 2. `repair_timeout_secs > 0` when `auto_repair` is enabled.
    /// 3. `checkpoint_interval_chunks > 0` when `resume_from_checkpoint`
    ///    is enabled.
    /// 4. `session_persistence_path` is non-empty when
    ///    `resume_from_checkpoint` is enabled.
    pub fn validate(&self) -> Result<(), String> {
        // Normalize: lowercase + strip hyphens for tolerant matching.
        let algo = self.hash_algorithm.to_lowercase().replace('-', "");
        let valid_algos = ["sha256", "sha512", "blake3"];
        if !valid_algos.contains(&algo.as_str()) {
            return Err(format!(
                "unsupported hash algorithm '{}'. Supported algorithms: {}",
                self.hash_algorithm,
                valid_algos.join(", ")
            ));
        }

        if self.repair.auto_repair && self.repair.repair_timeout_secs == 0 {
            return Err("repair_timeout_secs must be > 0 when auto_repair is enabled".to_string());
        }

        if self.resume.resume_from_checkpoint && self.resume.checkpoint_interval_chunks == 0 {
            return Err(
                "checkpoint_interval_chunks must be > 0 when resume_from_checkpoint is enabled"
                    .to_string(),
            );
        }

        if self.resume.resume_from_checkpoint && self.resume.session_persistence_path.is_empty() {
            return Err(
                "session_persistence_path must be set when resume_from_checkpoint is enabled"
                    .to_string(),
            );
        }

        Ok(())
    }
}

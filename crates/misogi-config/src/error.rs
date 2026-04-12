//! Configuration error types for Misogi system.
//!
//! Provides comprehensive error handling for all configuration operations
//! including file I/O, TOML parsing, validation, and environment variable
//! processing. All errors are non-recoverable without external intervention.

use std::path::PathBuf;

/// Comprehensive error type for configuration operations.
///
/// Covers all failure modes in the configuration lifecycle:
/// - File not found or permission denied
/// - Invalid TOML syntax
/// - Missing required sections or fields
/// - Type mismatches (e.g., string where integer expected)
/// - Validation failures (out-of-range values, invalid enums)
/// - Environment variable processing errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Configuration file does not exist at the specified path.
    #[error("configuration file not found: {0}")]
    FileNotFound(PathBuf),

    /// I/O error during configuration file read operation.
    #[error("I/O error reading configuration: {0}")]
    IoError(#[from] std::io::Error),

    /// TOML syntax error in configuration file.
    ///
    /// Includes line/column information when available from the parser.
    #[error("TOML parse error at {line}:{column}: {message}")]
    TomlParseError {
        /// 1-based line number where the error occurred.
        line: usize,
        /// 1-based column number where the error occurred.
        column: usize,
        /// Human-readable description of the syntax error.
        message: String,
    },

    /// Required configuration section is missing.
    #[error("missing required section: [{section}]")]
    MissingSection {
        /// Name of the missing TOML section (e.g., "jwt", "storage").
        section: String,
    },

    /// Required field within a section is missing.
    #[error("missing required field '{field}' in section [{section}]")]
    MissingField {
        /// Section containing the missing field.
        section: String,
        /// Name of the missing field.
        field: String,
    },

    /// Type mismatch between expected and actual value.
    ///
    /// Occurs when TOML value cannot be deserialized into the target Rust type.
    #[error("type mismatch for field '{field}' in section [{section}]: expected {expected}, found {actual}")]
    TypeMismatch {
        /// Section containing the mismatched field.
        section: String,
        /// Name of the mismatched field.
        field: String,
        /// Expected Rust type name (e.g., "String", "i64", "bool").
        expected: String,
        /// Actual type found in TOML (inferred from parse failure).
        actual: String,
    },

    /// Value validation failed (out of range, invalid enum variant, etc.).
    #[error("validation failed for field '{field}' in section [{section}]: {reason}")]
    ValidationError {
        /// Section containing the invalid value.
        section: String,
        /// Name of the invalid field.
        field: String,
        /// Human-readable explanation of why the value is invalid.
        reason: String,
    },

    /// Environment variable could not be read or has invalid value.
    #[error("environment variable error for MISOGI_{var}: {message}")]
    EnvVarError {
        /// Name of the environment variable (without MISOGI_ prefix).
        var: String,
        /// Description of what went wrong.
        message: String,
    },

    /// Generic serialization/deserialization error from serde.
    #[error("serialization error: {0}")]
    SerializationError(String),
}

impl ConfigError {
    /// Create a `TomlParseError` from a `toml::de::Error`.
    ///
    /// Extracts span information when available (toml 0.8+), otherwise uses
    /// (0, 0) for line/column with the error message.
    pub fn from_toml_error(err: toml::de::Error) -> Self {
        // toml 0.8+ uses span() instead of line()/col()
        // For simplicity, we use (0, 0) and include the full message
        // which contains position information in the error string
        ConfigError::TomlParseError {
            line: 0,
            column: 0,
            message: err.to_string(),
        }
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(err: toml::de::Error) -> Self {
        Self::from_toml_error(err)
    }
}

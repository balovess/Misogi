//! Unified error types for the No-Code Integration Layer.
//!
//! This module defines hierarchical error types that provide actionable context
//! for debugging configuration issues while preventing information leakage in
//! production environments.
//!
//! # Error Hierarchy
//!
//! ```text
//! YamlError (top-level)
//! ├── ParseError          — YAML syntax/structure errors
//! ├── ValidationError    — Schema constraint violations
//! ├── CompileError        — Transformation failures
//! ├── RuntimeError       — Runtime operation failures
//! └── ApiError            — HTTP API errors
//! ```

use std::path::PathBuf;
use thiserror::Error;

// =============================================================================
// Top-Level Error Enum
// =============================================================================

/// Comprehensive error type for all No-Code layer operations.
///
/// This enum aggregates all sub-error types into a single type for ergonomic
/// error propagation using the `?` operator throughout the codebase.
#[derive(Debug, Error)]
pub enum YamlError {
    /// YAML parsing or syntax error.
    #[error("YAML parse error: {message}")]
    Parse {
        /// Human-readable error message describing the parse failure.
        message: String,
        /// Line number where the error occurred (if available).
        line: Option<usize>,
        /// Column number where the error occurred (if available).
        column: Option<usize>,
    },

    /// Schema validation error — one or more constraint violations detected.
    #[error("Validation failed with {count} error(s)")]
    Validation {
        /// Number of validation errors detected.
        count: usize,
        /// Collection of individual validation errors.
        errors: Vec<ValidationError>,
    },

    /// Configuration compilation error during YAML → MisogiConfig transformation.
    #[error("Compilation failed: {message}")]
    Compilation {
        /// Human-readable error message describing the compilation failure.
        message: String,
        /// Source location in the YAML file (if applicable).
        path: Option<String>,
    },

    /// Runtime engine error during config application or hot-reload.
    #[error("Runtime error: {message}")]
    Runtime {
        /// Human-readable error message describing the runtime failure.
        message: String,
    },

    /// I/O error during file operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Environment variable resolution error.
    #[error("Environment variable '{name}' not found or empty")]
    EnvVarNotFound {
        /// Name of the missing environment variable.
        name: String,
    },
}

// =============================================================================
// Validation Error Types
// =============================================================================

/// Individual validation error with precise location information.
///
/// Each validation error captures exactly one constraint violation with enough
/// context for IT staff to locate and fix the issue in their YAML configuration.
#[derive(Debug, Clone, Error)]
#[error("[{field}] {message}")]
pub struct ValidationError {
    /// Dot-separated field path (e.g., "authentication.identity_providers[0].url").
    pub field: String,

    /// Human-readable validation error message.
    pub message: String,

    /// Severity level of this validation error.
    pub severity: ValidationSeverity,

    /// Suggested fix for this validation error (when available).
    pub suggestion: Option<String>,
}

/// Severity classification for validation errors.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValidationSeverity {
    /// Critical error that prevents configuration from being used.
    Error,

    /// Warning that indicates potential issues but allows continuation.
    Warning,
}

impl ValidationError {
    /// Create a new validation error with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `field` - Dot-separated field path identifying the invalid field.
    /// * `message` - Human-readable description of the validation failure.
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            severity: ValidationSeverity::Error,
            suggestion: None,
        }
    }

    /// Create a warning-level validation error.
    ///
    /// Warnings do not prevent configuration from being compiled but should
    /// be reviewed by IT staff before deployment.
    pub fn warning(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            severity: ValidationSeverity::Warning,
            suggestion: None,
        }
    }

    /// Add a suggested fix to this validation error.
    ///
    /// Returns `self` for method chaining.
    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }

    /// Check if this error is at error severity (not just a warning).
    pub fn is_error(&self) -> bool {
        self.severity == ValidationSeverity::Error
    }
}

// =============================================================================
// Compilation Error Types
// =============================================================================

/// Error occurring during YAML-to-MisogiConfig compilation phase.
#[derive(Debug, Error)]
pub enum CompileError {
    /// Cross-reference integrity violation (e.g., routing rule references
    /// non-existent identity provider).
    #[error("Cross-reference error at '{path}': {message}")]
    CrossReference {
        /// Field path where the cross-reference was found.
        path: String,
        /// Description of the reference violation.
        message: String,
    },

    /// Environment variable could not be resolved during compilation.
    #[error("Failed to resolve environment variable '{var_name}' at '{path}'")]
    EnvResolution {
        /// Name of the unresolved environment variable.
        var_name: String,
        /// Field path where the reference was found.
        path: String,
    },

    /// Value transformation error (e.g., string to integer conversion failure).
    #[error("Value transformation error at '{path}': {message}")]
    ValueTransform {
        /// Field path where the transformation failed.
        path: String,
        /// Description of the transformation failure.
        message: String,
    },

    /// Internal MisogiConfig construction error.
    #[error("Internal config construction error: {0}")]
    Internal(String),
}

impl CompileError {
    /// Get the field path associated with this compilation error.
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::CrossReference { path, .. } => Some(path),
            Self::EnvResolution { path, .. } => Some(path),
            Self::ValueTransform { path, .. } => Some(path),
            Self::Internal(_) => None,
        }
    }
}

// =============================================================================
// Runtime Error Types
// =============================================================================

/// Errors occurring during runtime engine operations.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Configuration application failed after validation passed.
    #[error("Failed to apply configuration: {0}")]
    ApplyFailed(String),

    /// Rollback to previous configuration failed after failed apply.
    #[error("Rollback failed: {original_error}; rollback error: {rollback_error}")]
    RollbackFailed {
        /// Error that triggered the rollback attempt.
        original_error: String,
        /// Error that occurred during rollback itself.
        rollback_error: String,
    },

    /// File watcher initialization or operation error.
    #[error("File watcher error: {0}")]
    WatcherError(String),

    /// Configuration file not found or inaccessible.
    #[error("Configuration file not found: {0}", .path.display())]
    ConfigNotFound {
        /// Path to the missing configuration file.
        path: PathBuf,
    },

    /// Concurrent modification conflict detected.
    #[error("Concurrent modification conflict: {0}")]
    Conflict(String),
}

impl From<YamlError> for RuntimeError {
    fn from(err: YamlError) -> Self {
        RuntimeError::ApplyFailed(format!("YAML error: {}", err))
    }
}

// =============================================================================
// API Error Types
// =============================================================================

/// Errors returned by Admin REST API endpoints.
///
/// These errors are serialized to JSON responses with appropriate HTTP status
/// codes for client consumption.
#[derive(Debug, Error)]
pub enum ApiError {
    /// Request body parsing or validation error (400 Bad Request).
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Authentication or authorization failure (401 Unauthorized / 403 Forbidden).
    #[error("Authentication required")]
    Unauthorized,

    /// Requested resource not found (404 Not Found).
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Internal server error (500 Internal Server Error).
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Configuration conflict during update (409 Conflict).
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Service unavailable due to ongoing operation (503 Service Unavailable).
    #[error("Service temporarily unavailable: {0}")]
    Unavailable(String),
}

impl ApiError {
    /// Map this API error to its corresponding HTTP status code.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Unauthorized => 401,
            Self::NotFound(_) => 404,
            Self::Internal(_) => 500,
            Self::Conflict(_) => 409,
            Self::Unavailable(_) => 503,
        }
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Test: ValidationError Creation and Properties
    // =========================================================================

    #[test]
    fn test_validation_error_creation() {
        let err = ValidationError::new("field.path", "value is required");
        assert_eq!(err.field, "field.path");
        assert_eq!(err.message, "value is required");
        assert!(err.is_error());
        assert_eq!(err.severity, ValidationSeverity::Error);
        assert!(err.suggestion.is_none());
    }

    #[test]
    fn test_validation_warning_creation() {
        let warn = ValidationError::warning("field.path", "value is deprecated");
        assert!(!warn.is_error());
        assert_eq!(warn.severity, ValidationSeverity::Warning);
    }

    #[test]
    fn test_validation_error_with_suggestion() {
        let err = ValidationError::new("port", "must be between 1-65535")
            .with_suggestion("Use port 8080 for HTTP or 443 for HTTPS");
        assert!(err.suggestion.is_some());
        assert!(err.suggestion.unwrap().contains("8080"));
    }

    // =========================================================================
    // Test: ApiError Status Code Mapping
    // =========================================================================

    #[test]
    fn test_api_error_status_codes() {
        assert_eq!(ApiError::BadRequest("test".to_string()).status_code(), 400);
        assert_eq!(ApiError::Unauthorized.status_code(), 401);
        assert_eq!(ApiError::NotFound("test".to_string()).status_code(), 404);
        assert_eq!(ApiError::Internal("test".to_string()).status_code(), 500);
        assert_eq!(ApiError::Conflict("test".to_string()).status_code(), 409);
        assert_eq!(ApiError::Unavailable("test".to_string()).status_code(), 503);
    }

    // =========================================================================
    // Test: CompileError Path Extraction
    // =========================================================================

    #[test]
    fn test_compile_error_path_extraction() {
        let err = CompileError::CrossReference {
            path: "routing.rules[0]".to_string(),
            message: "provider not found".to_string(),
        };
        assert_eq!(err.path().unwrap(), "routing.rules[0]");
    }

    #[test]
    fn test_compile_error_internal_no_path() {
        let err = CompileError::Internal("internal failure".to_string());
        assert!(err.path().is_none());
    }
}

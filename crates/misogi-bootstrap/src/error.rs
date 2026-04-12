//! Bootstrap Error Types — Comprehensive error handling for application assembly
//!
//! This module defines the [`BootstrapError`] enum which wraps all possible
//! failures that can occur during the Misogi application bootstrap process.
//! Each variant carries sufficient context for operator diagnostics and
//! automated retry decisions.
//!
//! # Error Classification
//!
//! | Category          | Variants                              | Retryable? |
//! |-------------------|---------------------------------------|------------|
//! | Configuration     | MissingConfig, InvalidConfig, ConfigIOError | No    |
//! | Component init    | JwtValidationError, JwtIssuerError, AuthEngineError | No |
//! | Provider errors   | ProviderRegistrationError, UnknownProviderType | No |
//! | Storage errors    | StorageBackendError                   | Depends*  |
//! | Dependency errors | MissingDependency, BuildOrderViolation | No        |
//! | Runtime errors    | StartupFailure, ShutdownError         | Depends*  |


use thiserror::Error;

// =============================================================================
// BootstrapError — Comprehensive error type for bootstrap operations
// =============================================================================

/// Comprehensive error type for all Misogi bootstrap operations.
///
/// This enum covers the full spectrum of failure modes that can occur during
/// application initialization, from configuration parsing errors to component
/// construction failures. Each variant carries actionable diagnostic context.
///
/// # Usage Example
///
/// ```ignore
/// use misogi_bootstrap::BootstrapError;
///
/// match result {
///     Ok(app) => app.start().await,
///     Err(BootstrapError::MissingConfig(section)) => {
///         eprintln!("Required config section missing: {section}");
///     }
///     Err(e) => eprintln!("Bootstrap failed: {e}"),
/// }
/// ```
#[derive(Error, Debug)]
pub enum BootstrapError {
    /// A required configuration section is missing from the config file.
    ///
    /// Returned when a mandatory section (e.g., `jwt`, `storage`, `transport`)
    /// is not present in the loaded configuration. The wrapped string identifies
    /// the missing section name.
    #[error("missing required configuration section: '{0}'")]
    MissingConfig(String),

    /// The configuration data is invalid or malformed.
    ///
    /// Returned when configuration values fail validation (e.g., invalid paths,
    /// out-of-range numbers, missing required fields within a section).
    /// The wrapped string contains validation details.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// An I/O error occurred while reading or writing configuration files.
    ///
    /// Wraps standard library I/O errors from file read/write operations
    /// during configuration loading.
    #[error("configuration I/O error: {0}")]
    ConfigIOError(#[source] std::io::Error),

    /// JWT validator construction or initialization failed.
    ///
    /// Wraps errors from [`misogi_auth::jwt::JwtValidator::new()`] including
    /// key load failures, invalid key format, etc.
    #[error("JWT validator initialization failed: {0}")]
    JwtValidationError(String),

    /// JWT issuer construction or initialization failed.
    ///
    /// Wraps errors from [`misogi_auth::jwt::JwtIssuer::new()`] including
    /// private key load failures, encoding setup errors, etc.
    #[error("JWT issuer initialization failed: {0}")]
    JwtIssuerError(String),

    /// Authentication engine construction or initialization failed.
    ///
    /// Wraps errors from [`misogi_auth::engine::AuthEngine::new()`] including
    /// validator initialization, registry attachment failures, etc.
    #[error("authentication engine initialization failed: {0}")]
    AuthEngineError(String),

    /// Identity provider registration failed.
    ///
    /// Returned when an identity provider cannot be registered with the
    /// [`IdentityRegistry`](misogi_auth::registry::IdentityRegistry), typically
    /// due to duplicate provider IDs or configuration errors.
    #[error("identity provider registration failed for '{provider_id}': {reason}")]
    ProviderRegistrationError {
        /// The provider ID that failed to register.
        provider_id: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// An unknown or unsupported identity provider type was specified in config.
    ///
    /// Returned when the `type` field of an identity provider entry does not
    /// match any known provider type (`ldap`, `oidc`, `saml`).
    #[error("unknown identity provider type: '{0}' (supported: ldap, oidc, saml)")]
    UnknownProviderType(String),

    /// Storage backend construction or initialization failed.
    ///
    /// Wraps errors from storage backend implementations (local filesystem,
    /// S3, Azure Blob, etc.) including connection failures, permission errors,
    /// and misconfiguration.
    #[error("storage backend initialization failed: {0}")]
    StorageBackendError(String),

    /// Transport layer construction or initialization failed.
    ///
    /// Wraps errors from HTTP/gRPC server binding, TLS certificate loading,
    /// port conflicts, etc.
    #[error("transport layer initialization failed: {0}")]
    TransportLayerError(String),

    /// Parser registry construction or parser registration failed.
    ///
    /// Wraps errors from CDR parser initialization and registration into
    /// the [`ParserRegistry`](misogi_cdr::ParserRegistry).
    #[error("parser registry initialization failed: {0}")]
    ParserRegistryError(String),

    /// A required dependency component has not been built yet.
    ///
    /// Returned when attempting to build a component that depends on another
    /// component that has not been constructed. Enforces build order.
    #[error("required dependency not built: '{0}' (build dependencies first)")]
    MissingDependency(String),

    /// Build order was violated — a component was built before its dependency.
    ///
    /// Internal consistency error indicating that the builder methods were
    /// called in an incorrect order. This should never happen in normal usage.
    #[error("build order violation: '{component}' requires '{dependency}' to be built first")]
    BuildOrderViolation {
        /// The component that was being built.
        component: String,
        /// The dependency that should have been built first.
        dependency: String,
    },

    /// Application startup failed after all components were assembled.
    ///
    /// Wraps errors from server binding, port conflicts, resource acquisition, etc.
    /// that occur during the final startup phase.
    #[error("application startup failed: {0}")]
    StartupFailure(String),

    /// Graceful shutdown encountered an error.
    ///
    /// Non-fatal errors during shutdown sequence (e.g., connection drain timeout).
    /// Applications SHOULD log these but exit anyway.
    #[error("shutdown error: {0}")]
    ShutdownError(String),
}

impl BootstrapError {
    /// Check if this error is recoverable by fixing configuration and retrying.
    ///
    /// Returns `true` for configuration-related errors that can be fixed by
    /// the operator without code changes. Returns `false` for programming
    /// errors or systemic failures.
    pub fn is_config_error(&self) -> bool {
        matches!(
            self,
            Self::MissingConfig(_)
                | Self::InvalidConfig(_)
                | Self::ConfigIOError(_)
                | Self::UnknownProviderType(_)
        )
    }

    /// Check if this error indicates a missing or out-of-order dependency.
    ///
    /// Returns `true` for dependency-related errors that indicate the caller
    /// needs to adjust their build method call order.
    pub fn is_dependency_error(&self) -> bool {
        matches!(self, Self::MissingDependency(_) | Self::BuildOrderViolation { .. })
    }

    /// Get the name of the configuration section related to this error, if any.
    ///
    /// Useful for generating targeted error messages that tell operators exactly
    /// which part of the configuration file needs attention.
    pub fn config_section(&self) -> Option<&str> {
        match self {
            Self::MissingConfig(section) => Some(section),
            Self::InvalidConfig(_) => None,
            _ => None,
        }
    }
}

// =============================================================================
// Type conversions from underlying crate errors
// =============================================================================

impl From<std::io::Error> for BootstrapError {
    /// Convert a standard I/O error into a config I/O error.
    fn from(err: std::io::Error) -> Self {
        Self::ConfigIOError(err)
    }
}

impl From<serde_json::Error> for BootstrapError {
    /// Convert a JSON parsing error into an invalid config error.
    fn from(err: serde_json::Error) -> Self {
        Self::InvalidConfig(format!("JSON parse error: {err}"))
    }
}

impl From<toml::de::Error> for BootstrapError {
    /// Convert a TOML parsing error into an invalid config error.
    fn from(err: toml::de::Error) -> Self {
        Self::InvalidConfig(format!("TOML parse error: {err}"))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test Group 1: Error Classification
    // -----------------------------------------------------------------------

    #[test]
    fn test_missing_config_is_config_error() {
        let err = BootstrapError::MissingConfig("jwt".to_string());
        assert!(err.is_config_error());
        assert!(!err.is_dependency_error());
    }

    #[test]
    fn test_invalid_config_is_config_error() {
        let err = BootstrapError::InvalidConfig("bad value".to_string());
        assert!(err.is_config_error());
        assert!(!err.is_dependency_error());
    }

    #[test]
    fn test_unknown_provider_is_config_error() {
        let err = BootstrapError::UnknownProviderType("kerberos".to_string());
        assert!(err.is_config_error());
        assert!(!err.is_dependency_error());
    }

    #[test]
    fn test_missing_dependency_is_dependency_error() {
        let err = BootstrapError::MissingDependency("jwt_validator".to_string());
        assert!(!err.is_config_error());
        assert!(err.is_dependency_error());
    }

    #[test]
    fn test_build_order_violation_is_dependency_error() {
        let err = BootstrapError::BuildOrderViolation {
            component: "auth_engine".to_string(),
            dependency: "jwt_validator".to_string(),
        };
        assert!(!err.is_config_error());
        assert!(err.is_dependency_error());
    }

    // -----------------------------------------------------------------------
    // Test Group 2: Config Section Extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_section_for_missing_config() {
        let err = BootstrapError::MissingConfig("storage".to_string());
        assert_eq!(err.config_section(), Some("storage"));
    }

    #[test]
    fn test_config_section_for_other_errors() {
        let err = BootstrapError::JwtValidationError("key not found".to_string());
        assert_eq!(err.config_section(), None);
    }

    // -----------------------------------------------------------------------
    // Test Group 3: Error Display Messages
    // -----------------------------------------------------------------------

    #[test]
    fn test_error_display_includes_context() {
        let err = BootstrapError::ProviderRegistrationError {
            provider_id: "ldap-1".to_string(),
            reason: "duplicate ID".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("ldap-1"));
        assert!(msg.contains("duplicate ID"));
    }

    #[test]
    fn test_build_order_violation_display() {
        let err = BootstrapError::BuildOrderViolation {
            component: "auth_engine".to_string(),
            dependency: "jwt_validator".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("auth_engine"));
        assert!(msg.contains("jwt_validator"));
    }

    // -----------------------------------------------------------------------
    // Test Group 4: Type Conversions
    // -----------------------------------------------------------------------

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let boot_err = BootstrapError::from(io_err);
        assert!(matches!(boot_err, BootstrapError::ConfigIOError(_)));
    }

    #[test]
    fn test_from_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let boot_err = BootstrapError::from(json_err);
        assert!(matches!(boot_err, BootstrapError::InvalidConfig(_)));
    }
}

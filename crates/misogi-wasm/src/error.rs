//! Comprehensive error types for WASM plugin runtime operations.
//!
//! This module defines all error conditions that can occur during WASM module
//! loading, instantiation, execution, and lifecycle management.

use std::path::PathBuf;
use thiserror::Error;

// ===========================================================================
// WASM Runtime Error Enumeration
// ===========================================================================

/// Unified error type for all WASM runtime operations.
///
/// This enum covers the complete error surface of the plugin system,
/// from file I/O failures during loading to runtime traps during execution.
/// Each variant carries sufficient context for debugging without exposing
/// sensitive internal details that could aid attackers.
///
/// ## Error Categories
///
/// 1. **Loading Errors**: File not found, invalid WASM format, corrupted modules
/// 2. **Validation Errors**: Missing exports, ABI violations, signature mismatches
/// 3. **Execution Errors**: Traps, out-of-memory, timeout exceeded
/// 4. **Configuration Errors**: Invalid settings, resource limits violated
/// 5. **Lifecycle Errors**: Plugin already loaded, not found, reload failures
///
/// # Example
///
/// ```ignore
/// use misogi_wasm::WasmError;
///
/// match result {
///     Err(WasmError::ModuleLoadFailed { path, .. }) => {
///         eprintln!("Cannot load plugin from: {}", path.display());
///     }
///     Err(WasmError::ExecutionTimeout { .. }) => {
///         eprintln!("Plugin execution exceeded time limit");
///     }
///     Ok(output) => println!("Success: {} bytes", output.len()),
/// }
/// ```
#[derive(Debug, Error)]
pub enum WasmError {
    /// Failed to load WASM module from filesystem.
    ///
    /// This error occurs when the `.wasm` file cannot be read or does not exist.
    /// The `source` field preserves the original I/O error for debugging.
    #[error("failed to load WASM module from {path}: {message}")]
    ModuleLoadFailed {
        /// Filesystem path to the `.wasm` file that failed to load.
        path: PathBuf,

        /// Human-readable description of what went wrong.
        message: String,

        /// Underlying I/O error (if available).
        #[source]
        source: Option<std::io::Error>,
    },

    /// WASM module validation failed.
    ///
    /// The module exists but contains invalid bytecode, unknown sections,
    /// or malformed structures that prevent wasmi from parsing it.
    #[error("invalid WASM module format in {path}: {reason}")]
    InvalidModuleFormat {
        /// Path to the malformed `.wasm` file.
        path: PathBuf,

        /// Specific reason why validation failed.
        reason: String,
    },

    /// Missing required export function from WASM module.
    ///
    /// Plugins MUST export `misogi_parse` and `misogi_supported_types`
    /// to conform to the Misogi CDR parser ABI.
    #[error("missing required export function '{function}' in module at {path}")]
    MissingExport {
        /// Name of the missing function.
        function: String,

        /// Path to the non-compliant module.
        path: PathBuf,
    },

    /// Function signature mismatch between expected and actual WASM export.
    ///
    /// This indicates an ABI version mismatch or incorrectly compiled plugin.
    #[error("signature mismatch for export '{function}' in {path}: expected {expected}, got {actual}")]
    SignatureMismatch {
        /// Exported function with wrong signature.
        function: String,

        /// Module containing the bad export.
        path: PathBuf,

        /// Expected signature string (e.g., "(i32, i32) -> i32").
        expected: String,

        /// Actual signature found in the module.
        actual: String,
    },

    /// WASM execution trap (division by zero, out-of-bounds access, etc.).
    ///
    /// Traps are fatal errors that indicate bugs in the plugin code or
    /// malicious attempts to violate memory safety guarantees.
    #[error("WASM execution trap in module '{module}': {message}")]
    ExecutionTrap {
        /// Identifier of the module that trapped.
        module: String,

        /// Human-readable trap description.
        message: String,
    },

    /// Plugin execution exceeded configured CPU timeout.
    ///
    /// This is a safety mechanism to prevent infinite loops or
    /// computationally expensive attacks from blocking the CDR pipeline.
    #[error("execution timeout after {timeout_secs}s in module '{module}'")]
    ExecutionTimeout {
        /// Configured timeout limit in seconds.
        timeout_secs: u64,

        /// Module that exceeded the time limit.
        module: String,
    },

    /// WASM module exceeded allocated memory limit.
    ///
    /// Memory exhaustion attacks attempt to allocate large amounts of
    /// linear memory to cause OOM conditions in the host process.
    #[error("memory limit exceeded: {requested} bytes requested, {limit} bytes allowed")]
    MemoryLimitExceeded {
        /// Amount of memory the plugin tried to allocate.
        requested: u64,

        /// Configured maximum allowed allocation.
        limit: u64,
    },

    /// Plugin with this name is already loaded.
    ///
    /// Each plugin must have a unique identifier within the manager.
    #[error("plugin '{name}' is already loaded from {existing_path}")]
    AlreadyLoaded {
        /// Duplicate plugin name/identifier.
        name: String,

        /// Path where the plugin was previously loaded from.
        existing_path: PathBuf,
    },

    /// Requested plugin not found in the manager.
    ///
    /// Occurs when trying to unload or query a plugin that was never registered.
    #[error("plugin '{name}' not found in plugin manager")]
    NotFound {
        /// Name of the missing plugin.
        name: String,
    },

    /// Configuration error for sandbox or plugin settings.
    ///
    /// Invalid values in TOML config or programmatically constructed settings.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// Hot-reload operation failed.
    ///
    /// File watching error or module re-instantiation failure during reload.
    #[error("hot-reload failed for plugin '{name}': {reason}")]
    HotReloadFailed {
        /// Plugin that failed to reload.
        name: String,

        /// Specific failure reason.
        reason: String,
    },

    /// Internal error indicating a bug in the runtime itself.
    ///
    /// These should never occur in production and indicate programming errors.
    #[error("internal WASM runtime error: {0}")]
    Internal(String),
}

/// Type alias for Result with WasmError as the error type.
///
/// Provides ergonomic shorthand for functions returning WASM-related results.
pub type WasmResult<T> = Result<T, WasmError>;

impl WasmError {
    /// Check if this error is recoverable (allows retry).
    ///
    /// Recoverable errors include transient failures like timeouts or
    /// temporary resource constraints that might succeed on retry.
    ///
    /// # Returns
    ///
    /// `true` if the error is potentially recoverable, `false` otherwise.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::ExecutionTimeout { .. } | Self::HotReloadFailed { .. }
        )
    }

    /// Get the associated filesystem path (if applicable).
    ///
    /// Useful for error reporting and logging to identify which plugin
    /// caused the failure.
    ///
    /// # Returns
    ///
    /// `Some(PathBuf)` if the error relates to a specific file, `None` otherwise.
    pub fn path(&self) -> Option<&PathBuf> {
        match self {
            Self::ModuleLoadFailed { path, .. } => Some(path),
            Self::InvalidModuleFormat { path, .. } => Some(path),
            Self::MissingExport { path, .. } => Some(path),
            Self::SignatureMismatch { path, .. } => Some(path),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // -----------------------------------------------------------------------
    // Test: Error Construction and Display
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_load_error_display() {
        let err = WasmError::ModuleLoadFailed {
            path: PathBuf::from("/test/plugin.wasm"),
            message: "file not found".to_string(),
            source: None,
        };

        let display = format!("{}", err);
        assert!(display.contains("plugin.wasm"));
        assert!(display.contains("file not found"));
    }

    #[test]
    fn test_execution_timeout_error() {
        let err = WasmError::ExecutionTimeout {
            timeout_secs: 30,
            module: "test_parser".to_string(),
        };

        assert!(err.is_recoverable());
        assert!(format!("{}", err).contains("30"));
    }

    #[test]
    fn test_missing_export_error_has_path() {
        let err = WasmError::MissingExport {
            function: "misogi_parse".to_string(),
            path: PathBuf::from("/plugins/bad.wasm"),
        };

        assert!(err.path().is_some());
        assert_eq!(err.path().unwrap(), Path::new("/plugins/bad.wasm"));
    }

    #[test]
    fn test_internal_error_not_recoverable() {
        let err = WasmError::Internal("unexpected state".to_string());
        assert!(!err.is_recoverable());
        assert!(err.path().is_none());
    }

    #[test]
    fn test_memory_limit_exceeded_details() {
        let err = WasmError::MemoryLimitExceeded {
            requested: 128 * 1024 * 1024,
            limit: 64 * 1024 * 1024,
        };

        let msg = format!("{}", err);
        assert!(msg.contains("134217728")); // 128 MB in bytes
        assert!(msg.contains("67108864"));   // 64 MB in bytes
    }

    #[test]
    fn test_signature_mismatch_comprehensive() {
        let err = WasmError::SignatureMismatch {
            function: "misogi_parse".to_string(),
            path: PathBuf::from("/bad_plugin.wasm"),
            expected: "(i32, i32) -> i32".to_string(),
            actual: "() -> i32".to_string(),
        };

        let msg = format!("{}", err);
        assert!(msg.contains("misogi_parse"));
        assert!(msg.contains("(i32, i32) -> i32"));
        assert!(msg.contains("() -> i32"));
    }
}

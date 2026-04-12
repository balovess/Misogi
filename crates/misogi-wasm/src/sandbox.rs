//! Sandbox configuration and enforcement for WASM plugin isolation.
//!
//! This module implements the **security boundary** between untrusted WASM plugins
//! and the host Misogi CDR runtime. All resource limits and access controls
//! are defined and enforced here.
//!
//! ## Security Principles
//!
//! 1. **Defense in Depth**: Multiple independent layers of protection
//! 2. **Fail-Safe Defaults**: Most restrictive settings by default
//! 3. **Least Privilege**: Plugins get only what they absolutely need
//! 4. **Audit Trail**: All security events are logged with full context

use serde::{Deserialize, Serialize};

// ===========================================================================
// Sandbox Configuration Structure
// ===========================================================================

/// Comprehensive sandbox configuration for WASM plugin execution.
///
/// This struct defines all security constraints applied to plugin instances,
/// including memory limits, CPU timeouts, and feature flags for optional
/// capabilities (currently all disabled for maximum security).
///
/// ## Configuration Sources
///
/// Settings can be loaded from:
/// - TOML configuration file (`[parsers.wasm_plugins]` section)
/// - Programmatic construction (for testing or dynamic scenarios)
/// - Environment variable overrides (future enhancement)
///
/// # Example
///
/// ```ignore
/// use misogi_wasm::SandboxConfig;
///
/// // Strict sandbox for untrusted third-party plugins
/// let strict = SandboxConfig {
///     max_memory_bytes: 32 * 1024 * 1024, // 32 MB
///     timeout_secs: 10,
///     ..Default::default()
/// };
///
/// // Relaxed sandbox for first-party verified plugins
/// let relaxed = SandboxConfig {
///     max_memory_bytes: 256 * 1024 * 1024, // 256 MB
///     timeout_secs: 120,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SandboxConfig {
    /// Maximum WASM linear memory allocation in bytes.
    ///
    /// **Security Rationale**: Prevents OOM attacks where malicious plugins
    /// attempt to exhaust host memory through large allocations. The default
    /// 64 MB is sufficient for document parsing while limiting blast radius.
    ///
    /// **Recommendation**: Set to 16-64 MB for unknown plugins, up to 256 MB
    /// for verified parsers handling complex formats like OOXML or PDF.
    ///
    /// Default: [`DEFAULT_MEMORY_LIMIT_BYTES`](crate::DEFAULT_MEMORY_LIMIT_BYTES) (64 MB)
    #[serde(default = "default_memory_limit")]
    pub max_memory_bytes: u64,

    /// Maximum CPU execution time per function call in seconds.
    ///
    /// **Security Rationale**: Prevents infinite loops and computational
    /// denial-of-service attacks. Complex parsing operations on large files
    /// may require longer timeouts; adjust based on expected workloads.
    ///
    /// **Warning**: This is a **soft limit** checked periodically during
    /// execution, not a hard interrupt. Actual timeout may exceed this value
    /// by up to one check interval (~100ms).
    ///
    /// Default: [`DEFAULT_TIMEOUT_SECS`](crate::DEFAULT_TIMEOUT_SECS) (30 seconds)
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Enable filesystem access imports (DANGEROUS - keep disabled).
    ///
    /// **CRITICAL SECURITY WARNING**: When enabled, plugins can read/write
    /// arbitrary files on the host system. This should NEVER be enabled
    /// for untrusted third-party plugins under any circumstances.
    ///
    /// Valid use cases: Internal development/testing only.
    ///
    /// Default: `false` (disabled)
    #[serde(default)]
    pub allow_filesystem: bool,

    /// Enable network socket imports (DANGEROUS - keep disabled).
    ///
    /// **CRITICAL SECURITY WARNING**: Network access allows data exfiltration,
    /// command-and-control communication, and lateral movement within networks.
    /// Must remain disabled in production deployments.
    ///
    /// Default: `false` (disabled)
    #[serde(default)]
    pub allow_network: bool,

    /// Maximum number of function calls before forced termination.
    ///
    /// Provides an additional layer of protection against deeply recursive
    /// or excessively long-running computations that might evade timeout checks.
    ///
    /// Set to `0` to disable this check (not recommended for production).
    ///
    /// Default: `1_000_000` (one million calls)
    #[serde(default = "default_max_calls")]
    pub max_function_calls: usize,

    /// Enable detailed execution logging for debugging.
    ///
    /// When enabled, logs every function call, memory operation, and import
    /// invocation. Useful for development but incurs significant performance
    /// overhead in production.
    ///
    /// Default: `false` (disabled)
    #[serde(default)]
    pub debug_logging: bool,
}

// Default value functions for serde deserialization

fn default_memory_limit() -> u64 {
    crate::DEFAULT_MEMORY_LIMIT_BYTES
}

fn default_timeout() -> u64 {
    crate::DEFAULT_TIMEOUT_SECS
}

fn default_max_calls() -> usize {
    1_000_000
}

impl Default for SandboxConfig {
    /// Create a secure-by-default sandbox configuration.
    ///
    /// All dangerous capabilities (filesystem, network) are disabled.
    /// Memory and CPU limits are set to conservative safe values.
    fn default() -> Self {
        Self {
            max_memory_bytes: crate::DEFAULT_MEMORY_LIMIT_BYTES,
            timeout_secs: crate::DEFAULT_TIMEOUT_SECS,
            allow_filesystem: false,
            allow_network: false,
            max_function_calls: 1_000_000,
            debug_logging: false,
        }
    }
}

impl SandboxConfig {
    /// Create a strict low-resource sandbox for untrusted plugins.
    ///
    /// Applies minimal memory (16 MB) and short timeout (10 seconds).
    /// Suitable for processing small documents from unknown sources.
    ///
    /// # Returns
    ///
    /// A `SandboxConfig` instance with restrictive settings.
    pub fn strict() -> Self {
        Self {
            max_memory_bytes: 16 * 1024 * 1024, // 16 MB
            timeout_secs: 10,
            ..Default::default()
        }
    }

    /// Create a relaxed high-resource sandbox for trusted plugins.
    ///
    /// Allows larger memory (256 MB) and longer timeout (120 seconds).
    /// Only use for internally developed or thoroughly audited plugins.
    ///
    /// # Returns
    ///
    /// A `SandboxConfig` instance with permissive settings.
    pub fn relaxed() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024, // 256 MB
            timeout_secs: 120,
            ..Default::default()
        }
    }

    /// Validate that configuration values are within acceptable ranges.
    ///
    /// # Errors
    ///
    /// Returns descriptive string if any value is invalid:
    /// - Memory limit must be >= 1 MB (1048576 bytes)
    /// - Timeout must be >= 1 second and <= 3600 seconds (1 hour)
    /// - Max calls must be >= 1000 or 0 (disabled)
    ///
    /// # Returns
    ///
    /// `Ok(())` if configuration is valid, `Err(String)` otherwise.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_memory_bytes < 1024 * 1024 {
            return Err(format!(
                "max_memory_bytes ({}) must be at least 1 MB",
                self.max_memory_bytes
            ));
        }

        if self.timeout_secs == 0 || self.timeout_secs > 3600 {
            return Err(format!(
                "timeout_secs ({}) must be between 1 and 3600",
                self.timeout_secs
            ));
        }

        if self.max_function_calls != 0 && self.max_function_calls < 1000 {
            return Err(format!(
                "max_function_calls ({}) must be >= 1000 or 0 (disabled)",
                self.max_function_calls
            ));
        }

        // Security audit log for dangerous settings
        if self.allow_filesystem {
            tracing::warn!(
                "[SECURITY] Filesystem access enabled in WASM sandbox - DANGEROUS"
            );
        }

        if self.allow_network {
            tracing::warn!(
                "[SECURITY] Network access enabled in WASM sandbox - DANGEROUS"
            );
        }

        Ok(())
    }

    /// Check if this sandbox allows any dangerous capabilities.
    ///
    /// Used for security audits and compliance reporting.
    ///
    /// # Returns
    ///
    /// `true` if either filesystem or network access is permitted.
    #[inline]
    pub fn has_dangerous_capabilities(&self) -> bool {
        self.allow_filesystem || self.allow_network
    }

    /// Convert memory limit to megabytes for human-readable display.
    ///
    /// # Returns
    ///
    /// Memory limit rounded to nearest whole MB.
    #[inline]
    pub fn max_memory_mb(&self) -> u64 {
        self.max_memory_bytes / (1024 * 1024)
    }
}

// ===========================================================================
// Runtime State Tracking
// ===========================================================================

/// Tracks resource usage during WASM module execution for limit enforcement.
///
/// This struct is instantiated per-invocation and updated as the plugin executes,
/// enabling real-time detection of limit violations.
#[derive(Debug, Clone)]
pub struct ExecutionState {
    /// Number of WASM function calls made so far in this invocation.
    pub call_count: usize,

    /// Current memory usage in bytes (approximate).
    pub memory_used: u64,

    /// Timestamp when execution started (for timeout calculation).
    pub start_time: std::time::Instant,

    /// Reference to the sandbox config being enforced.
    config: SandboxConfig,
}

impl ExecutionState {
    /// Create new execution state tracker for the given sandbox config.
    ///
    /// # Arguments
    ///
    /// * `config` - Sandbox configuration to enforce during tracking
    ///
    /// # Returns
    ///
    /// A new `ExecutionState` initialized with zero usage and current timestamp.
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            call_count: 0,
            memory_used: 0,
            start_time: std::time::Instant::now(),
            config,
        }
    }

    /// Record a function call and check if limit exceeded.
    ///
    /// Should be called before each WASM function invocation.
    ///
    /// # Returns
    ///
    /// `Ok(())` if within limits, `Err(String)` if max calls exceeded.
    #[inline]
    pub fn record_call(&mut self) -> Result<(), String> {
        self.call_count += 1;

        if self.config.max_function_calls > 0 && self.call_count > self.config.max_function_calls {
            Err(format!(
                "function call limit exceeded: {} > {}",
                self.call_count,
                self.config.max_function_calls
            ))
        } else {
            Ok(())
        }
    }

    /// Check if CPU timeout has been exceeded.
    ///
    /// Should be called periodically during long-running operations.
    ///
    /// # Returns
    ///
    /// `true` if execution has exceeded configured timeout.
    #[inline]
    pub fn is_timeout_exceeded(&self) -> bool {
        self.start_time.elapsed().as_secs() >= self.config.timeout_secs
    }

    /// Get elapsed execution time in seconds.
    ///
    /// # Returns
    ///
    /// Fractional seconds since execution started.
    #[inline]
    pub fn elapsed_secs(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    /// Update tracked memory usage and check against limit.
    ///
    /// # Arguments
    ///
    /// * `bytes` - New total memory usage to record
    ///
    /// # Returns
    ///
    /// `Ok(())` if within limit, `Err(String)` if exceeded.
    #[inline]
    pub fn update_memory(&mut self, bytes: u64) -> Result<(), String> {
        self.memory_used = bytes;

        if bytes > self.config.max_memory_bytes {
            Err(format!(
                "memory limit exceeded: {} bytes > {} bytes",
                bytes, self.config.max_memory_bytes
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test: Default Configuration Values
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config_values() {
        let config = SandboxConfig::default();
        assert_eq!(config.max_memory_bytes, 64 * 1024 * 1024); // 64 MB
        assert_eq!(config.timeout_secs, 30);
        assert!(!config.allow_filesystem);
        assert!(!config.allow_network);
        assert_eq!(config.max_function_calls, 1_000_000);
        assert!(!config.debug_logging);
    }

    // -----------------------------------------------------------------------
    // Test: Preset Configurations
    // -----------------------------------------------------------------------

    #[test]
    fn test_strict_config_is_restrictive() {
        let strict = SandboxConfig::strict();
        assert_eq!(strict.max_memory_bytes, 16 * 1024 * 1024); // 16 MB
        assert_eq!(strict.timeout_secs, 10);
        assert!(strict.max_memory_bytes < SandboxConfig::default().max_memory_bytes);
    }

    #[test]
    fn test_relaxed_config_is_permissive() {
        let relaxed = SandboxConfig::relaxed();
        assert_eq!(relaxed.max_memory_bytes, 256 * 1024 * 1024); // 256 MB
        assert_eq!(relaxed.timeout_secs, 120);
        assert!(relaxed.max_memory_bytes > SandboxConfig::default().max_memory_bytes);
    }

    // -----------------------------------------------------------------------
    // Test: Configuration Validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_config_passes_validation() {
        let config = SandboxConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_too_small_memory_fails_validation() {
        let config = SandboxConfig {
            max_memory_bytes: 512, // Less than 1 MB
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_zero_timeout_fails_validation() {
        let config = SandboxConfig {
            timeout_secs: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_excessive_timeout_fails_validation() {
        let config = SandboxConfig {
            timeout_secs: 5000, // More than 1 hour
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    // -----------------------------------------------------------------------
    // Test: Dangerous Capability Detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_safe_config_no_dangerous_caps() {
        let config = SandboxConfig::default();
        assert!(!config.has_dangerous_capabilities());
    }

    #[test]
    fn test_filesystem_enabled_is_dangerous() {
        let config = SandboxConfig {
            allow_filesystem: true,
            ..Default::default()
        };
        assert!(config.has_dangerous_capabilities());
    }

    #[test]
    fn test_network_enabled_is_dangerous() {
        let config = SandboxConfig {
            allow_network: true,
            ..Default::default()
        };
        assert!(config.has_dangerous_capabilities());
    }

    // -----------------------------------------------------------------------
    // Test: Utility Functions
    // -----------------------------------------------------------------------

    #[test]
    fn test_max_memory_mb_conversion() {
        let config = SandboxConfig {
            max_memory_bytes: 128 * 1024 * 1024, // 128 MB
            ..Default::default()
        };
        assert_eq!(config.max_memory_mb(), 128);
    }

    // -----------------------------------------------------------------------
    // Test: Execution State Tracking
    // -----------------------------------------------------------------------

    #[test]
    fn test_execution_state_initializes_correctly() {
        let config = SandboxConfig::default();
        let state = ExecutionState::new(config);

        assert_eq!(state.call_count, 0);
        assert_eq!(state.memory_used, 0);
        assert!(!state.is_timeout_exceeded());
    }

    #[test]
    fn test_call_count_tracking_and_limit() {
        let config = SandboxConfig {
            max_function_calls: 5,
            ..Default::default()
        };
        let mut state = ExecutionState::new(config);

        // First 5 calls should succeed
        for _ in 0..5 {
            assert!(state.record_call().is_ok());
        }

        // 6th call should fail
        assert!(state.record_call().is_err());
        assert_eq!(state.call_count, 6);
    }

    #[test]
    fn test_memory_tracking_enforcement() {
        let config = SandboxConfig {
            max_memory_bytes: 1000,
            ..Default::default()
        };
        let mut state = ExecutionState::new(config);

        assert!(state.update_memory(500).is_ok());
        assert!(state.update_memory(1000).is_ok());
        assert!(state.update_memory(1001).is_err());
    }
}

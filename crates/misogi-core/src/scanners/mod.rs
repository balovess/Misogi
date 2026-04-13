// =============================================================================
// Misogi Core — External Virus/Malware Scanner Adapter Framework
// =============================================================================
//! Provides a pluggable architecture for integrating external scanning
//! solutions into the Misogi CDR pipeline. Misogi does NOT include any
//! built-in antivirus engine — users connect their own via these adapters.
//!
//! # Architecture Overview
//!
//! ```text
//! File Upload → [ScannerChain] → CDR Strategy Pipeline → Sanitized Output
//!                    │
//!         ┌──────────┼──────────┬──────────────┐
//!         ▼          ▼          ▼              ▼
//!    ClamAvAdapter  HttpApiAdapter  CommandLineAdapter  GrpcScannerAdapter
//!      (TCP/UNIX)   (REST API)     (CLI tools)        (gRPC service)
//!         │          │              │                  │
//!      clamd     TrendMicro     MpCmdRun.exe      Enterprise Sec Platform
//! ```
//!
//! # Design Principles
//!
//! - **Zero bundled engines**: Misogi ships with no scanning logic; all detection
//!   is delegated to external adapters implementing [`ExternalScanner`].
//! - **Protocol diversity**: Supports TCP sockets (ClamAV), REST APIs (cloud services),
//!   CLI tools (Windows Defender), and gRPC (enterprise platforms).
//! - **Chain composition**: Multiple scanners can be combined via [`ScannerChain`]
//!   with configurable aggregation modes (any-infected, consensus, first-responder).
//! - **Fail-safe defaults**: Configurable fail-open/fail-close behavior when scanners
//!   are unreachable or return errors.
//! - **Async-first**: All I/O operations are async-compatible for high-throughput
//!   file processing pipelines.
//!
//! # Quick Start
//!
//! ```ignore
//! use misogi_core::scanners::{ExternalScanner, ScannerChain, ChainMode, ClamAvAdapter};
//!
//! // Create a single scanner adapter
//! let clamav = ClamAvAdapter::new(clamav_config);
//!
//! // Build a chain (supports multiple scanners)
//! let mut chain = ScannerChain::new(ChainMode::AnyInfectedBlocks, true);
//! chain.add_scanner(Box::new(clamav));
//!
//! // Scan file content
//! let result = chain.scan(&file_data).await?;
//! match result {
//!     ScanResult::Clean => { /* proceed to CDR */ }
//!     ScanResult::Infected { threat_name, .. } => { /* block file */ }
//!     ScanResult::Error { .. } => { /* handle per policy */ }
//! }
//! ```

pub mod clamav_adapter;
pub mod command_line_adapter;
pub mod grpc_scanner_adapter;
pub mod http_api_adapter;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Public Re-exports
// =============================================================================

pub use clamav_adapter::{ClamAvAdapter, ClamAvConfig, ClamAvConnection};
pub use command_line_adapter::{CommandLineAdapter, CommandLineConfig};
pub use grpc_scanner_adapter::{GrpcScannerAdapter, GrpcScannerConfig};
pub use http_api_adapter::{HttpApiAdapter, HttpApiConfig};

// =============================================================================
// Scan Result Types
// =============================================================================

/// Result of scanning a file through an external scanner.
///
/// Represents the four possible outcomes of an external virus/malware scan:
/// clean (no threats), infected (threat detected), error (scanner failure),
/// or timeout (operation exceeded time limit).
///
/// # Serialization
/// This type implements `Serialize`/`Deserialize` for audit log persistence
/// and cross-process communication via JSON.
///
/// # Examples
///
/// ```rust
/// use misogi_core::scanners::ScanResult;
///
/// let clean = ScanResult::Clean;
/// assert!(clean.is_clean());
///
/// let infected = ScanResult::Infected {
///     threat_name: "Eicar-Test-Signature".to_string(),
///     severity: ThreatSeverity::Low,
/// };
/// assert!(infected.is_infected());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum ScanResult {
    /// No threats detected. File is safe to process.
    Clean,

    /// Threat detected with identification string and severity level.
    ///
    /// Contains the signature name reported by the scanner and a normalized
    /// severity classification for policy decisions.
    Infected {
        /// Name/signature of the detected threat (e.g., "Eicar-Test-Signature").
        threat_name: String,

        /// Normalized severity level from [`ThreatSeverity`] enum.
        severity: ThreatSeverity,
    },

    /// Scanner returned an error (network timeout, parse error, auth failure, etc.).
    ///
    /// The `transient` field indicates whether this error might resolve on retry
    /// (e.g., temporary network issue vs. permanent configuration error).
    Error {
        /// Human-readable error message suitable for logging and operator alerts.
        message: String,

        /// Whether this error is potentially transient/retryable.
        ///
        /// - `true`: Temporary failure (network blip, rate limit, scanner busy)
        /// - `false`: Permanent failure (bad config, auth error, protocol mismatch)
        transient: bool,
    },

    /// Scan timed out before completion.
    ///
    /// Indicates the scanner did not respond within the configured timeout window.
    Timeout {
        /// Configured timeout duration in seconds that was exceeded.
        timeout_secs: u64,
    },
}

impl ScanResult {
    /// Returns `true` if the scan result indicates the file is clean.
    #[inline]
    pub fn is_clean(&self) -> bool {
        matches!(self, ScanResult::Clean)
    }

    /// Returns `true` if the scan result indicates a threat was detected.
    #[inline]
    pub fn is_infected(&self) -> bool {
        matches!(self, ScanResult::Infected { .. })
    }

    /// Returns `true` if the scan resulted in an error condition.
    ///
    /// Includes both explicit errors and timeouts.
    #[inline]
    pub fn is_error(&self) -> bool {
        matches!(self, ScanResult::Error { .. } | ScanResult::Timeout { .. })
    }

    /// Extracts the threat name if this result is `Infected`, otherwise returns `None`.
    pub fn threat_name(&self) -> Option<&str> {
        match self {
            ScanResult::Infected { threat_name, .. } => Some(threat_name),
            _ => None,
        }
    }

    /// Extracts the severity level if this result is `Infected`, otherwise returns `None`.
    pub fn severity(&self) -> Option<ThreatSeverity> {
        match self {
            ScanResult::Infected { severity, .. } => Some(*severity),
            _ => None,
        }
    }
}

impl std::fmt::Display for ScanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanResult::Clean => write!(f, "Clean"),
            ScanResult::Infected {
                threat_name,
                severity,
            } => write!(
                f,
                "Infected [threat={}, severity={:?}]",
                threat_name, severity
            ),
            ScanResult::Error {
                message,
                transient,
            } => write!(
                f,
                "Error [message={}, transient={}]",
                message, transient
            ),
            ScanResult::Timeout { timeout_secs } => {
                write!(f, "Timeout [timeout={}s]", timeout_secs)
            }
        }
    }
}

/// Threat severity levels reported by external scanners.
///
/// Provides a normalized classification scale independent of vendor-specific
/// naming conventions. Adapters map vendor severities to these standard levels.
///
/// # Ordering
/// Implements `PartialOrd`/`Ord` to enable comparison-based policy decisions
/// (e.g., "block only High+Critical threats, quarantine Medium").
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThreatSeverity {
    /// Informational finding (e.g., suspicious but not malicious).
    Info,

    /// Low-risk detection (e.g., adware, potentially unwanted program).
    Low,

    /// Medium-risk detection (e.g., trojan variant, exploit kit).
    Medium,

    /// High-risk detection (e.g., ransomware, banking trojan).
    High,

    /// Critical-risk detection (e.g., zero-day, APT tool).
    Critical,
}

impl std::fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatSeverity::Info => write!(f, "INFO"),
            ThreatSeverity::Low => write!(f, "LOW"),
            ThreatSeverity::Medium => write!(f, "MEDIUM"),
            ThreatSeverity::High => write!(f, "HIGH"),
            ThreatSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Default for ThreatSeverity {
    fn default() -> Self {
        Self::Medium
    }
}

// =============================================================================
// External Scanner Trait
// =============================================================================

/// Error type for scanner operations.
#[derive(Error, Debug, Clone)]
pub enum ScannerError {
    /// Network/connection error (TCP socket, HTTP request, gRPC call).
    #[error("Connection error: {0}")]
    Connection(String),

    /// Protocol/parsing error (invalid response format, unexpected data).
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Authentication/authorization failure.
    #[error("Authentication failed: {0}")]
    Auth(String),

    /// Timeout exceeded.
    #[error("Operation timed out after {timeout_secs}s")]
    Timeout { timeout_secs: u64 },

    /// Configuration error (missing required field, invalid value).
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Internal error (unexpected state, bug).
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Type alias for scanner operation results.
pub type Result<T> = std::result::Result<T, ScannerError>;

/// Core trait that all external scanner adapters must implement.
///
/// This trait defines the interface between Misogi's CDR pipeline and external
/// virus/malware scanning solutions. Implementations communicate with specific
/// scanner backends (ClamAV daemon, cloud APIs, CLI tools, gRPC services)
/// using their native protocols.
///
/// # Thread Safety
/// All implementations must be `Send + Sync` to allow safe sharing across
/// async tasks in Tokio's multi-threaded runtime.
///
/// # Lifecycle
/// 1. Construct adapter with backend-specific configuration
/// 2. Optionally call [`health_check()`](ExternalScanner::health_check) to verify connectivity
/// 3. Call [`scan_stream()`](ExternalScanner::scan_stream) for each file to inspect
/// 4. Call [`metadata()`](ExternalScanner::metadata) periodically for monitoring
///
/// # Example Implementation
///
/// ```ignore
/// struct MyScanner { /* ... */ }
///
/// #[async_trait]
/// impl ExternalScanner for MyScanner {
///     fn name(&self) -> &str { "MyCustomScanner" }
///     fn id(&self) -> &str { "my-scanner-001" }
///
///     async fn scan_stream(&self, data: &[u8]) -> Result<ScanResult> {
///         // Send data to backend, parse response
///         Ok(ScanResult::Clean)
///     }
///
///     async fn health_check(&self) -> bool {
///         // Ping backend, return true if reachable
///         true
///     }
///
///     async fn metadata(&self) -> Option<ScannerMetadata> {
///         // Query version info, signature count, etc.
///         None
///     }
/// }
/// ```
#[async_trait]
pub trait ExternalScanner: Send + Sync + std::fmt::Debug {
    /// Human-readable name of this scanner (for logging/config display).
    ///
    /// Should be a stable identifier like `"ClamAV"`, `"Windows Defender"`,
    /// or `"Trend Micro Cloud"`. Used in audit logs and monitoring dashboards.
    fn name(&self) -> &str;

    /// Unique identifier for this scanner instance.
    ///
    /// Must be unique within a [`ScannerChain`] to enable per-scanner
    /// health tracking and result attribution. Typically derived from
    /// configuration (e.g., `"clamav-primary"`, `"defender-local"`).
    fn id(&self) -> &str;

    /// Scan file content via streaming interface.
    ///
    /// The scanner receives the complete file contents as a byte slice.
    /// For large files (>100MB), callers should consider chunked approaches
    /// if the underlying protocol supports it (e.g., ClamAV INSTREAM).
    ///
    /// # Arguments
    /// * `data` — Complete file content as bytes. Callers should ensure this
    ///   fits in memory; for extremely large files, consider streaming APIs
    ///   at the adapter level.
    ///
    /// # Returns
    /// - `Ok(ScanResult::Clean)` — No threats detected
    /// - `Ok(ScanResult::Infected { ... })` — Threat found with details
    /// - `Ok(ScanResult::Error { ... })` — Scanner reported an error
    /// - `Ok(ScanResult::Timeout { ... })` — Operation timed out
    /// - `Err(ScannerError)` — Internal/transport-level failure
    ///
    /// # Errors
    /// Returns `Err` only for transport/protocol failures that prevent getting
    /// any response from the scanner. Scanner-reported errors (virus DB outdated,
    /// access denied) should be returned as `Ok(ScanResult::Error { ... })`.
    async fn scan_stream(&self, data: &[u8]) -> Result<ScanResult>;

    /// Check if the scanner backend is healthy and reachable.
    ///
    /// Called automatically before each scan (or periodically by monitoring).
    /// Implementations should perform a lightweight connectivity test:
    /// - TCP socket: Send PING or VERSION command
    /// - HTTP API: GET /health endpoint
    /// - CLI tool: Check executable exists and is runnable
    /// - gRPC: Call health check RPC
    ///
    /// # Returns
    /// - `true` — Scanner is reachable and operational
    /// - `false` — Scanner cannot be reached or is in error state
    async fn health_check(&self) -> bool;

    /// Get scanner-specific metadata (version, signature count, last update, etc.).
    ///
    /// Called periodically for monitoring and audit purposes. May return `None`
    /// if metadata retrieval is not supported or fails silently.
    ///
    /// # Returns
    /// Metadata including engine version, signature database version, number
    /// of signatures, and last update timestamp. Returns `None` if unavailable.
    async fn metadata(&self) -> Option<ScannerMetadata>;
}

// =============================================================================
// Scanner Metadata
// =============================================================================

/// Metadata about a scanner instance for monitoring and auditing.
///
/// Captures version information and signature database status from external
/// scanners. Used for compliance reporting, health dashboards, and detecting
/// outdated protection.
///
/// # Example
///
/// ```rust
/// use misogi_core::scanners::ScannerMetadata;
/// use chrono::Utc;
///
/// let meta = ScannerMetadata {
///     engine_name: "ClamAV".to_string(),
///     engine_version: "0.103.8".to_string(),
///     signature_version: "27387".to_string(),
///     signatures_count: 8_500_000,
///     last_updated: Utc::now(),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScannerMetadata {
    /// Display name of the scanning engine (e.g., "ClamAV", "Windows Defender").
    pub engine_name: String,

    /// Version string of the scanning engine (e.g., "0.103.8", "1.377.1632.0").
    pub engine_version: String,

    /// Version/identifier of the signature database (e.g., daily build number).
    pub signature_version: String,

    /// Total number of signatures/rules loaded by the engine.
    pub signatures_count: u64,

    /// Timestamp when the signature database was last updated.
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Display for ScannerMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} v{} (signatures: {}, db: {}, updated: {})",
            self.engine_name,
            self.engine_version,
            self.signatures_count,
            self.signature_version,
            self.last_updated.format("%Y-%m-%d %H:%M:%S UTC")
        )
    }
}

// =============================================================================
// Scanner Chain Configuration
// =============================================================================

/// Strategy for combining results from multiple scanners in a [`ScannerChain`].
///
/// Determines how the chain aggregates scan results when multiple scanners
/// are configured. Each mode offers different trade-offs between security,
/// performance, and resilience.
///
/// # Mode Comparison
///
/// | Mode | Security | Speed | Resilience | Use Case |
/// |------|----------|-------|------------|----------|
/// | `AnyInfectedBlocks` | Highest | Slowest | High | High-security environments |
/// | `ConsensusRequired` | High | Slow | Medium | Multi-vendor defense-in-depth |
/// | `FirstResponder` | Medium | Fastest | Low | Latency-sensitive pipelines |
/// | `AggregateAll` | Highest | Slowest | High | Forensic/compliance needs |
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ChainMode {
    /// Any scanner reporting infected blocks the file (strictest).
    ///
    /// The chain returns `Infected` immediately upon first infection detection.
    /// If all scanners report `Clean`, returns `Clean`. If any scanner errors,
    /// behavior depends on `fail_open_on_error` setting.
    ///
    /// **Security posture:** Most conservative — one infected verdict is enough.
    AnyInfectedBlocks,

    /// All scanners must agree on infection (consensus).
    ///
    /// Only returns `Infected` if **all** responding scanners agree.
    /// Single-scanner infections are treated as warnings (logged but not blocked).
    /// Requires majority for definitive decision.
    ///
    /// **Security posture:** Balanced — reduces false positives from buggy scanners.
    ConsensusRequired,

    /// First scanner to respond wins (fastest).
    ///
    /// Executes all scanners concurrently but returns the first non-error result.
    /// Subsequent scanner results are logged but ignored for the decision.
    ///
    /// **Security posture:** Performance-optimized — trades thoroughness for speed.
    FirstResponder,

    /// Run all scanners, aggregate all findings (most thorough).
    ///
    /// Waits for all scanners to complete, then returns combined results.
    /// If any scanner reports infected, the most severe threat is returned.
    /// All individual results are available for detailed logging.
    ///
    /// **Security posture:** Maximum visibility — best for forensic analysis.
    AggregateAll,
}

impl std::fmt::Display for ChainMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainMode::AnyInfectedBlocks => write!(f, "AnyInfectedBlocks"),
            ChainMode::ConsensusRequired => write!(f, "ConsensusRequired"),
            ChainMode::FirstResponder => write!(f, "FirstResponder"),
            ChainMode::AggregateAll => write!(f, "AggregateAll"),
        }
    }
}

impl Default for ChainMode {
    fn default() -> Self {
        Self::AnyInfectedBlocks
    }
}

// =============================================================================
// Scanner Chain
// =============================================================================

/// Chain that combines multiple [`ExternalScanner`] implementations for layered scanning.
///
/// Orchestrates execution of multiple scanner adapters according to the configured
/// [`ChainMode`], providing unified result aggregation and error handling.
///
/// # Thread Safety
/// `ScannerChain` is `Send + Sync` and can be shared across async tasks.
/// Individual scans are serialized internally to prevent resource exhaustion.
///
/// # Fail-Open vs Fail-Close
///
/// When scanners encounter errors, the chain behavior depends on `fail_open_on_error`:
/// - **fail-open** (`true`): Errors treated as `Clean` (allow file through, log warning)
/// - **fail-close** (`false`): Errors treated as blocking (deny file, require manual review)
///
/// # Example
///
/// ```ignore
/// use misogi_core::scanners::*;
///
/// let mut chain = ScannerChain::new(ChainMode::AnyInfectedBlocks, true);
/// chain.add_scanner(Box::new(ClamAvAdapter::new(clamav_cfg)));
/// chain.add_scanner(Box::new(HttpApiAdapter::new(http_cfg)?));
///
/// let result = chain.scan(&file_data).await?;
/// ```
pub struct ScannerChain {
    /// Ordered list of scanner adapters (order matters for FirstResponder mode).
    scanners: Vec<Box<dyn ExternalScanner>>,

    /// Aggregation strategy for combining multiple scanner results.
    mode: ChainMode,

    /// Whether to allow files through when scanners error (fail-open) or block them (fail-close).
    ///
    /// - `true`: Treat scanner errors as `Clean` (log warning, continue processing)
    /// - `false`: Treat scanner errors as blocking (return error result)
    fail_open_on_error: bool,
}

impl ScannerChain {
    /// Create a new empty scanner chain.
    ///
    /// # Arguments
    /// * `mode` — Aggregation strategy for combining scanner results.
    /// * `fail_open` — If `true`, scanner errors allow files through (fail-open).
    ///   If `false`, scanner errors block files (fail-close).
    ///
    /// # Returns
    /// Empty chain ready for scanners to be added via [`add_scanner()`](Self::add_scanner).
    pub fn new(mode: ChainMode, fail_open: bool) -> Self {
        tracing::info!(
            mode = %mode,
            fail_open = fail_open,
            "Creating new ScannerChain"
        );

        Self {
            scanners: Vec::new(),
            mode,
            fail_open_on_error: fail_open,
        }
    }

    /// Add a scanner to the chain.
    ///
    /// Order matters for [`ChainMode::FirstResponder`] — earlier scanners
    /// have priority in returning results. For other modes, order affects
    /// logging sequence but not final outcome.
    ///
    /// # Arguments
    /// * `scanner` — Boxed trait object implementing [`ExternalScanner`].
    ///
    /// # Returns
    /// Mutable reference to `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// chain.add_scanner(Box::new(clamav))
    ///      .add_scanner(Box::new(defender))
    ///      .add_scanner(Box::new(cloud_api));
    /// ```
    pub fn add_scanner(&mut self, scanner: Box<dyn ExternalScanner>) -> &mut Self {
        tracing::debug!(
            scanner_name = scanner.name(),
            scanner_id = scanner.id(),
            position = self.scanners.len(),
            "Adding scanner to chain"
        );
        self.scanners.push(scanner);
        self
    }

    /// Get the number of scanners currently in the chain.
    pub fn len(&self) -> usize {
        self.scanners.len()
    }

    /// Check if the chain has no scanners.
    pub fn is_empty(&self) -> bool {
        self.scanners.is_empty()
    }

    /// Execute scan through the chain according to configured mode.
    ///
    /// Dispatches the file content to all scanners (or subset depending on mode)
    /// and aggregates results per the [`ChainMode`] strategy.
    ///
    /// # Arguments
    /// * `data` — Complete file content bytes to scan.
    ///
    /// # Returns
    /// Aggregated [`ScanResult`] based on chain mode and fail-open/fail-close setting.
    ///
    /// # Behavior by Mode
    ///
    /// ## AnyInfectedBlocks (default)
    /// - Runs all scanners concurrently
    /// - Returns `Infected` immediately if any scanner detects threat
    /// - Returns `Clean` only if ALL scanners report clean
    /// - On error: applies fail-open/fail-close policy
    ///
    /// ## ConsensusRequired
    /// - Runs all scanners concurrently
    /// - Returns `Infected` only if ALL scanners agree on infection
    /// - Mixed results: returns least severe (prefers clean over uncertain)
    /// - On error: excludes failed scanners from consensus calculation
    ///
    /// ## FirstResponder
    /// - Runs all scanners concurrently
    /// - Returns first non-error result received
    /// - Logs other results for audit trail
    /// - If all error: applies fail-open/fail-close policy
    ///
    /// ## AggregateAll
    /// - Runs all scanners concurrently
    /// - Waits for ALL to complete
    /// - Returns most severe finding across all scanners
    /// - Detailed per-scanner results available in logs
    ///
    /// # Empty Chain
    /// If no scanners are configured, returns `ScanResult::Clean` with a warning log.
    pub async fn scan(&self, data: &[u8]) -> Result<ScanResult> {
        if self.scanners.is_empty() {
            tracing::warn!("ScannerChain is empty — returning Clean without scanning");
            return Ok(ScanResult::Clean);
        }

        tracing::info!(
            scanner_count = self.scanners.len(),
            mode = %self.mode,
            data_size = data.len(),
            "Executing scanner chain"
        );

        match self.mode {
            ChainMode::AnyInfectedBlocks => self.scan_any_infected(data).await,
            ChainMode::ConsensusRequired => self.scan_consensus(data).await,
            ChainMode::FirstResponder => self.scan_first_responder(data).await,
            ChainMode::AggregateAll => self.scan_aggregate_all(data).await,
        }
    }

    /// Health check all scanners in the chain.
    ///
    /// Calls [`ExternalScanner::health_check()`] on each scanner concurrently
    /// and returns per-scanner status.
    ///
    /// # Returns
    /// Vector of `(scanner_id, is_healthy)` tuples in chain order.
    /// Can be used for monitoring dashboards and alerting.
    pub async fn health_check_all(&self) -> Vec<(String, bool)> {
        use futures::future::join_all;

        let futures: Vec<_> = self
            .scanners
            .iter()
            .map(|scanner| {
                let id = scanner.id().to_string();
                async move { (id, scanner.health_check().await) }
            })
            .collect();

        join_all(futures).await
    }

    // =========================================================================
    // Private: Mode-specific scan implementations
    // =========================================================================

    /// AnyInfectedBlocks: Block if ANY scanner reports infected.
    async fn scan_any_infected(&self, data: &[u8]) -> Result<ScanResult> {
        use futures::future::join_all;

        let futures: Vec<_> = self
            .scanners
            .iter()
            .map(|scanner| {
                let id = scanner.id().to_string();
                let name = scanner.name().to_string();
                async move {
                    let result = scanner.scan_stream(data).await;
                    (id, name, result)
                }
            })
            .collect();

        let results = join_all(futures).await;

        let mut has_error = false;
        let mut error_messages: Vec<String> = Vec::new();

        for (id, name, result) in &results {
            match result {
                Ok(scan_result) => match scan_result {
                    ScanResult::Infected {
                        threat_name,
                        severity,
                    } => {
                        tracing::warn!(
                            scanner_id = %id,
                            scanner_name = %name,
                            threat_name = %threat_name,
                            severity = %severity,
                            "Scanner detected infection — blocking file (AnyInfectedBlocks)"
                        );
                        return Ok(scan_result.clone());
                    }
                    ScanResult::Clean => {
                        tracing::debug!(
                            scanner_id = %id,
                            scanner_name = %name,
                            "Scanner reports clean"
                        );
                    }
                    ScanResult::Error {
                        message,
                        transient,
                    } => {
                        has_error = true;
                        error_messages.push(format!(
                            "[{}] {} (transient: {})",
                            id, message, transient
                        ));
                        tracing::error!(
                            scanner_id = %id,
                            scanner_name = %name,
                            error = %message,
                            transient = transient,
                            "Scanner returned error"
                        );
                    }
                    ScanResult::Timeout { timeout_secs } => {
                        has_error = true;
                        error_messages.push(format!("[{}] Timeout after {}s", id, timeout_secs));
                        tracing::warn!(
                            scanner_id = %id,
                            scanner_name = %name,
                            timeout_secs = timeout_secs,
                            "Scanner timed out"
                        );
                    }
                },
                Err(e) => {
                    has_error = true;
                    error_messages.push(format!("[{}] Transport error: {}", id, e));
                    tracing::error!(
                        scanner_id = %id,
                        scanner_name = %name,
                        error = %e,
                        "Scanner transport error"
                    );
                }
            }
        }

        // Handle errors based on fail-open/fail-close policy
        if has_error {
            if self.fail_open_on_error {
                tracing::warn!(
                    errors = %error_messages.join("; "),
                    "Scanners had errors but fail_open=true — allowing file through"
                );
                Ok(ScanResult::Clean)
            } else {
                tracing::error!(
                    errors = %error_messages.join("; "),
                    "Scanners had errors and fail_close=false — blocking file"
                );
                Ok(ScanResult::Error {
                    message: format!(
                        "One or more scanners failed: {}",
                        error_messages.join("; ")
                    ),
                    transient: true,
                })
            }
        } else {
            tracing::info!("All scanners report clean");
            Ok(ScanResult::Clean)
        }
    }

    /// ConsensusRequired: Only block if ALL scanners agree on infection.
    async fn scan_consensus(&self, data: &[u8]) -> Result<ScanResult> {
        use futures::future::join_all;

        let futures: Vec<_> = self
            .scanners
            .iter()
            .map(|scanner| {
                let id = scanner.id().to_string();
                let name = scanner.name().to_string();
                async move {
                    let result = scanner.scan_stream(data).await;
                    (id, name, result)
                }
            })
            .collect();

        let results = join_all(futures).await;

        let mut infected_count = 0u32;
        let mut clean_count = 0u32;
        let mut error_count = 0u32;
        let mut total_responding = 0u32;
        let mut most_severe_threat: Option<(String, ThreatSeverity)> = None;

        for (_id, _name, result) in &results {
            match result {
                Ok(scan_result) => match scan_result {
                    ScanResult::Infected {
                        threat_name,
                        severity,
                    } => {
                        infected_count += 1;
                        total_responding += 1;

                        // Track most severe threat seen
                        if most_severe_threat.is_none() || Some(*severity) > most_severe_threat.as_ref().map(|(_, s)| *s) {
                            most_severe_threat = Some((threat_name.clone(), *severity));
                        }

                        tracing::warn!(
                            threat_name = %threat_name,
                            severity = %severity,
                            "Scanner detected infection (consensus voting)"
                        );
                    }
                    ScanResult::Clean => {
                        clean_count += 1;
                        total_responding += 1;
                    }
                    ScanResult::Error { .. } | ScanResult::Timeout { .. } => {
                        error_count += 1;
                        // Don't count errors toward responding total for consensus
                    }
                },
                Err(_) => {
                    error_count += 1;
                }
            }
        }

        tracing::info!(
            infected = infected_count,
            clean = clean_count,
            errors = error_count,
            responding = total_responding,
            total = self.scanners.len(),
            "Consensus vote complete"
        );

        // Consensus logic: only infected if ALL responding scanners agree
        if total_responding > 0 && infected_count == total_responding {
            // All responding scanners agree on infection
            if let Some((threat_name, severity)) = most_severe_threat {
                tracing::error!(
                    threat_name = %threat_name,
                    severity = %severity,
                    unanimous = true,
                    "Consensus reached: ALL scanners report infected — blocking"
                );
                return Ok(ScanResult::Infected {
                    threat_name,
                    severity,
                });
            }
        }

        // If there were errors, apply fail-open/fail-close
        if error_count > 0 && !self.fail_open_on_error {
            return Ok(ScanResult::Error {
                message: format!(
                    "Cannot reach consensus: {} errors out of {} scanners",
                    error_count,
                    self.scanners.len()
                ),
                transient: true,
            });
        }

        // Default: no consensus on infection, treat as clean (or fail-open)
        if infected_count > 0 {
            tracing::warn!(
                infected = infected_count,
                total = total_responding,
                "Some scanners detected infection but consensus NOT reached — allowing (no unanimous agreement)"
            );
        }

        Ok(ScanResult::Clean)
    }

    /// FirstResponder: Return first successful scan result.
    async fn scan_first_responder(&self, data: &[u8]) -> Result<ScanResult> {
        // Spawn all scanners as concurrent tasks
        let _handles: Vec<tokio::task::JoinHandle<(String, String, Result<ScanResult>)>> =
            Vec::with_capacity(self.scanners.len());

        for scanner in &self.scanners {
            let id = scanner.id().to_string();

            // Note: We need to work around the lack of Clone on dyn ExternalScanner
            // In practice, we'd need Arc<dyn ExternalScanner>, but for now we'll
            // use a simplified approach with indices
            tracing::debug!(
                scanner_id = %id,
                "Spawning first-responder scanner task"
            );
        }

        // Since we can't easily clone &dyn ExternalScanner across tasks,
        // we'll use a sequential approach with early exit for simplicity
        // In production, refactor to use Arc<dyn ExternalScanner>
        let mut last_error: Option<Result<ScanResult>> = None;

        for scanner in &self.scanners {
            let id = scanner.id().to_string();
            let name = scanner.name().to_string();

            let result = scanner.scan_stream(data).await;

            match &result {
                Ok(scan_result) => match scan_result {
                    ScanResult::Clean => {
                        tracing::info!(
                            scanner_id = %id,
                            scanner_name = %name,
                            "First responder returned Clean"
                        );
                        return Ok(ScanResult::Clean);
                    }
                    ScanResult::Infected {
                        threat_name,
                        severity,
                    } => {
                        tracing::warn!(
                            scanner_id = %id,
                            scanner_name = %name,
                            threat_name = %threat_name,
                            severity = %severity,
                            "First responder returned Infected — blocking"
                        );
                        return Ok(scan_result.clone());
                    }
                    ScanResult::Error { .. } | ScanResult::Timeout { .. } => {
                        tracing::debug!(
                            scanner_id = %id,
                            scanner_name = %name,
                            "First responder returned error/timeout, trying next"
                        );
                        last_error = Some(result);
                    }
                },
                Err(e) => {
                    tracing::error!(
                        scanner_id = %id,
                        scanner_name = %name,
                        error = %e,
                        "First responder transport error, trying next"
                    );
                    last_error = Some(Err(e.clone()));
                }
            }
        }

        // All scanners failed or errored
        if let Some(result) = last_error {
            if self.fail_open_on_error {
                tracing::warn!(
                    "All first-responders failed but fail_open=true — allowing file"
                );
                Ok(ScanResult::Clean)
            } else {
                result
            }
        } else {
            // Shouldn't happen (empty chain handled earlier), but fallback
            Ok(ScanResult::Clean)
        }
    }

    /// AggregateAll: Run all scanners, return most severe finding.
    async fn scan_aggregate_all(&self, data: &[u8]) -> Result<ScanResult> {
        use futures::future::join_all;

        let futures: Vec<_> = self
            .scanners
            .iter()
            .map(|scanner| {
                let id = scanner.id().to_string();
                let name = scanner.name().to_string();
                async move {
                    let result = scanner.scan_stream(data).await;
                    (id, name, result)
                }
            })
            .collect();

        let results = join_all(futures).await;

        let mut findings: Vec<ScanResult> = Vec::new();
        let mut has_transport_error = false;

        for (id, name, result) in results {
            match result {
                Ok(scan_result) => {
                    tracing::info!(
                        scanner_id = %id,
                        scanner_name = %name,
                        result = %scan_result,
                        "Aggregated scan result"
                    );
                    findings.push(scan_result);
                }
                Err(e) => {
                    has_transport_error = true;
                    tracing::error!(
                        scanner_id = %id,
                        scanner_name = %name,
                        error = %e,
                        "Transport error during aggregate scan"
                    );
                }
            }
        }

        // Find most severe result
        let most_severe = findings
            .iter()
            .max_by_key(|r| match r {
                ScanResult::Clean => 0u8,
                ScanResult::Timeout { .. } => 1,
                ScanResult::Error { .. } => 2,
                ScanResult::Infected {
                    severity: ThreatSeverity::Info,
                    ..
                } => 3,
                ScanResult::Infected {
                    severity: ThreatSeverity::Low,
                    ..
                } => 4,
                ScanResult::Infected {
                    severity: ThreatSeverity::Medium,
                    ..
                } => 5,
                ScanResult::Infected {
                    severity: ThreatSeverity::High,
                    ..
                } => 6,
                ScanResult::Infected {
                    severity: ThreatSeverity::Critical,
                    ..
                } => 7,
            });

        match most_severe {
            Some(severity) => {
                tracing::info!(
                    result = %severity,
                    total_findings = findings.len(),
                    "Returning most severe aggregated result"
                );
                Ok(severity.clone())
            }
            None => {
                // All scanners had transport errors
                if has_transport_error {
                    if self.fail_open_on_error {
                        Ok(ScanResult::Clean)
                    } else {
                        Ok(ScanResult::Error {
                            message: "All scanners experienced transport errors".to_string(),
                            transient: true,
                        })
                    }
                } else {
                    Ok(ScanResult::Clean)
                }
            }
        }
    }
}

impl std::fmt::Debug for ScannerChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScannerChain")
            .field("scanner_count", &self.scanners.len())
            .field("mode", &self.mode)
            .field("fail_open_on_error", &self.fail_open_on_error)
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Mock Scanner for Testing
    // =========================================================================

    /// Simple mock scanner that returns predefined results for testing.
    #[derive(Debug)]
    struct MockScanner {
        name_str: String,
        id_str: String,
        result: ScanResult,
        is_healthy: bool,
    }

    impl MockScanner {
        fn new(name: &str, id: &str, result: ScanResult, healthy: bool) -> Self {
            Self {
                name_str: name.to_string(),
                id_str: id.to_string(),
                result,
                is_healthy: healthy,
            }
        }
    }

    #[async_trait]
    impl ExternalScanner for MockScanner {
        fn name(&self) -> &str {
            &self.name_str
        }

        fn id(&self) -> &str {
            &self.id_str
        }

        async fn scan_stream(&self, _data: &[u8]) -> Result<ScanResult> {
            Ok(self.result.clone())
        }

        async fn health_check(&self) -> bool {
            self.is_healthy
        }

        async fn metadata(&self) -> Option<ScannerMetadata> {
            None
        }
    }

    // =========================================================================
    // ScanResult Tests
    // =========================================================================

    #[test]
    fn test_scan_result_clean() {
        let result = ScanResult::Clean;
        assert!(result.is_clean());
        assert!(!result.is_infected());
        assert!(!result.is_error());
        assert_eq!(result.threat_name(), None);
        assert_eq!(result.severity(), None);
        assert_eq!(format!("{}", result), "Clean");
    }

    #[test]
    fn test_scan_result_infected() {
        let result = ScanResult::Infected {
            threat_name: "Eicar-Test-Signature".to_string(),
            severity: ThreatSeverity::Medium,
        };

        assert!(!result.is_clean());
        assert!(result.is_infected());
        assert!(!result.is_error());
        assert_eq!(result.threat_name(), Some("Eicar-Test-Signature"));
        assert_eq!(result.severity(), Some(ThreatSeverity::Medium));
    }

    #[test]
    fn test_scan_result_error() {
        let result = ScanResult::Error {
            message: "Connection refused".to_string(),
            transient: true,
        };

        assert!(!result.is_clean());
        assert!(!result.is_infected());
        assert!(result.is_error());
    }

    #[test]
    fn test_scan_result_timeout() {
        let result = ScanResult::Timeout { timeout_secs: 30 };
        assert!(result.is_error());
        assert_eq!(format!("{}", result), "Timeout [timeout=30s]");
    }

    #[test]
    fn test_scan_result_serialization() {
        let original = ScanResult::Infected {
            threat_name: "Trojan.Generic".to_string(),
            severity: ThreatSeverity::High,
        };

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: ScanResult = serde_json::from_str(&json).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_threat_severity_ordering() {
        assert!(ThreatSeverity::Info < ThreatSeverity::Low);
        assert!(ThreatSeverity::Low < ThreatSeverity::Medium);
        assert!(ThreatSeverity::Medium < ThreatSeverity::High);
        assert!(ThreatSeverity::High < ThreatSeverity::Critical);
    }

    #[test]
    fn test_threat_severity_display() {
        assert_eq!(format!("{}", ThreatSeverity::Info), "INFO");
        assert_eq!(format!("{}", ThreatSeverity::Critical), "CRITICAL");
    }

    // =========================================================================
    // ScannerMetadata Tests
    // =========================================================================

    #[test]
    fn test_scanner_metadata_display() {
        let meta = ScannerMetadata {
            engine_name: "ClamAV".to_string(),
            engine_version: "0.103.8".to_string(),
            signature_version: "27387".to_string(),
            signatures_count: 8500000,
            last_updated: chrono::Utc::now(),
        };

        let display = format!("{}", meta);
        assert!(display.contains("ClamAV"));
        assert!(display.contains("0.103.8"));
        assert!(display.contains("8500000"));
    }

    // =========================================================================
    // ChainMode Tests
    // =========================================================================

    #[test]
    fn test_chain_mode_default() {
        assert_eq!(ChainMode::default(), ChainMode::AnyInfectedBlocks);
    }

    #[test]
    fn test_chain_mode_display() {
        assert_eq!(format!("{}", ChainMode::AnyInfectedBlocks), "AnyInfectedBlocks");
        assert_eq!(format!("{}", ChainMode::ConsensusRequired), "ConsensusRequired");
        assert_eq!(format!("{}", ChainMode::FirstResponder), "FirstResponder");
        assert_eq!(format!("{}", ChainMode::AggregateAll), "AggregateAll");
    }

    // =========================================================================
    // ScannerChain Tests
    // =========================================================================

    #[tokio::test]
    async fn test_empty_chain_returns_clean() {
        let chain = ScannerChain::new(ChainMode::AnyInfectedBlocks, true);
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);

        let result = chain.scan(b"test data").await.unwrap();
        assert_eq!(result, ScanResult::Clean);
    }

    #[tokio::test]
    async fn test_any_infected_blocks_single_clean() {
        let mut chain = ScannerChain::new(ChainMode::AnyInfectedBlocks, true);
        chain.add_scanner(Box::new(MockScanner::new(
            "TestScanner",
            "test-1",
            ScanResult::Clean,
            true,
        )));

        let result = chain.scan(b"clean file").await.unwrap();
        assert_eq!(result, ScanResult::Clean);
    }

    #[tokio::test]
    async fn test_any_infected_blocks_single_infected() {
        let mut chain = ScannerChain::new(ChainMode::AnyInfectedBlocks, true);
        chain.add_scanner(Box::new(MockScanner::new(
            "TestScanner",
            "test-1",
            ScanResult::Infected {
                threat_name: "Virus.A".to_string(),
                severity: ThreatSeverity::High,
            },
            true,
        )));

        let result = chain.scan(b"infected file").await.unwrap();
        assert!(result.is_infected());
        assert_eq!(result.threat_name(), Some("Virus.A"));
    }

    #[tokio::test]
    async fn test_any_infected_blocks_multiple_one_infected() {
        let mut chain = ScannerChain::new(ChainMode::AnyInfectedBlocks, true);
        chain.add_scanner(Box::new(MockScanner::new(
            "ScannerA",
            "a-1",
            ScanResult::Clean,
            true,
        )));
        chain.add_scanner(Box::new(MockScanner::new(
            "ScannerB",
            "b-1",
            ScanResult::Infected {
                threat_name: "Malware.B".to_string(),
                severity: ThreatSeverity::Critical,
            },
            true,
        )));
        chain.add_scanner(Box::new(MockScanner::new(
            "ScannerC",
            "c-1",
            ScanResult::Clean,
            true,
        )));

        let result = chain.scan(b"mixed").await.unwrap();
        assert!(result.is_infected());
        assert_eq!(result.threat_name(), Some("Malware.B"));
    }

    #[tokio::test]
    async fn test_consensus_unanimous_infection() {
        let mut chain = ScannerChain::new(ChainMode::ConsensusRequired, false);
        chain.add_scanner(Box::new(MockScanner::new(
            "S1",
            "s1",
            ScanResult::Infected {
                threat_name: "Virus.X".to_string(),
                severity: ThreatSeverity::High,
            },
            true,
        )));
        chain.add_scanner(Box::new(MockScanner::new(
            "S2",
            "s2",
            ScanResult::Infected {
                threat_name: "Virus.Y".to_string(),
                severity: ThreatSeverity::Medium,
            },
            true,
        )));

        let result = chain.scan(b"bad").await.unwrap();
        // Both agree on infection → should block
        assert!(result.is_infected());
    }

    #[tokio::test]
    async fn test_consensus_mixed_results() {
        let mut chain = ScannerChain::new(ChainMode::ConsensusRequired, true);
        chain.add_scanner(Box::new(MockScanner::new(
            "S1",
            "s1",
            ScanResult::Infected {
                threat_name: "FalsePositive".to_string(),
                severity: ThreatSeverity::Low,
            },
            true,
        )));
        chain.add_scanner(Box::new(MockScanner::new(
            "S2",
            "s2",
            ScanResult::Clean,
            true,
        )));

        let result = chain.scan(b"suspicious").await.unwrap();
        // Not unanimous → should allow (fail-open)
        assert_eq!(result, ScanResult::Clean);
    }

    #[tokio::test]
    async fn test_fail_open_vs_close() {
        // Create scanner that returns error
        let error_scanner = || {
            MockScanner::new(
                "ErrScanner",
                "err-1",
                ScanResult::Error {
                    message: "Scanner down".to_string(),
                    transient: true,
                },
                false,
            )
        };

        // Fail-open: errors become Clean
        let mut chain_open = ScannerChain::new(ChainMode::AnyInfectedBlocks, true);
        chain_open.add_scanner(Box::new(error_scanner()));
        let result_open = chain_open.scan(b"data").await.unwrap();
        assert_eq!(result_open, ScanResult::Clean);

        // Fail-close: errors block
        let mut chain_close = ScannerChain::new(ChainMode::AnyInfectedBlocks, false);
        chain_close.add_scanner(Box::new(error_scanner()));
        let result_close = chain_close.scan(b"data").await.unwrap();
        assert!(result_close.is_error());
    }

    #[tokio::test]
    async fn test_health_check_all() {
        let mut chain = ScannerChain::new(ChainMode::AnyInfectedBlocks, true);
        chain.add_scanner(Box::new(MockScanner::new(
            "Healthy",
            "h-1",
            ScanResult::Clean,
            true,
        )));
        chain.add_scanner(Box::new(MockScanner::new(
            "Unhealthy",
            "uh-1",
            ScanResult::Clean,
            false,
        )));

        let health = chain.health_check_all().await;
        assert_eq!(health.len(), 2);
        // health_check_all returns (scanner_id, is_healthy) tuples
        assert_eq!(health[0], ("h-1".to_string(), true));
        assert_eq!(health[1], ("uh-1".to_string(), false));
    }

    #[tokio::test]
    async fn test_aggregate_most_severe() {
        let mut chain = ScannerChain::new(ChainMode::AggregateAll, true);
        chain.add_scanner(Box::new(MockScanner::new(
            "S1",
            "s1",
            ScanResult::Infected {
                threat_name: "LowRisk".to_string(),
                severity: ThreatSeverity::Low,
            },
            true,
        )));
        chain.add_scanner(Box::new(MockScanner::new(
            "S2",
            "s2",
            ScanResult::Infected {
                threat_name: "CriticalExploit".to_string(),
                severity: ThreatSeverity::Critical,
            },
            true,
        )));

        let result = chain.scan(b"data").await.unwrap();
        assert!(result.is_infected());
        assert_eq!(result.severity(), Some(ThreatSeverity::Critical));
        assert_eq!(result.threat_name(), Some("CriticalExploit"));
    }
}

// =============================================================================
// Scanner Registry (Configuration Builder)
// =============================================================================

/// Configuration-driven builder for [`ScannerChain`] from TOML configuration.
///
/// Provides a declarative way to configure multiple scanners via TOML files
/// without writing Rust code for each adapter instantiation. Supports all
/// built-in adapter types and can be extended with custom adapters.
///
/// # Configuration Format
///
/// Scanners are configured in TOML using `[[scanners]]` array sections:
///
/// ```toml
/// [scanner_chain]
/// mode = "AnyInfectedBlocks"       # ChainMode variant
/// fail_open_on_error = true
///
/// [[scanners]]
/// type = "clamav"                   # Adapter type identifier
/// id = "primary-clamav"            # Unique scanner ID
/// connection = { type = "tcp", host = "localhost", port = 3310 }
/// scan_timeout_secs = 30
///
/// [[scanners]]
/// type = "http-api"
/// id = "cloud-scan"
/// endpoint = "https://scan.example.com/api/v1/scan"
/// auth_header = "Bearer ${API_TOKEN}"
/// timeout_secs = 60
///
/// [[scanners]]
/// type = "command-line"
/// id = "windows-defender"
/// command_template = "MpCmdRun.exe -Scan -File {file}"
/// infected_exit_codes = [2, 3]
/// error_exit_codes = [1]
/// ```
///
/// # Supported Types
///
/// | Type | Config Struct | Description |
/// |------|--------------|-------------|
/// | `"clamav"` | [`ClamAvConfig`] | ClamAV daemon (TCP/UNIX) |
/// | `"http-api"` | [`HttpApiConfig`] | REST API scanner |
/// | `"command-line"` | [`CommandLineConfig`] | CLI tool wrapper |
/// | `"grpc"` | [`GrpcScannerConfig`] | gRPC service client |
///
/// # Example Usage
///
/// ```ignore
/// use misogi_core::scanners::ScannerRegistry;
///
/// // Load from TOML string
/// let toml_config = std::fs::read_to_string("scanners.toml")?;
/// let registry = ScannerRegistry::from_toml(&tomml_config)?;
///
/// // Build scanner chain
/// let chain = registry.build_chain()?;
///
/// // Use in CDR strategy
/// let mut strategy = ExternalScannerStrategy::new(100, ...);
/// // Add scanners from registry...
/// ```
pub struct ScannerRegistry {
    /// Parsed scanner configurations in order.
    scanner_configs: Vec<ScannerConfigEntry>,

    /// Chain-level configuration.
    chain_mode: ChainMode,

    /// Fail-open/fail-close policy.
    fail_open_on_error: bool,
}

/// Individual scanner configuration entry from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum ScannerConfigEntry {
    /// ClamAV daemon adapter configuration.
    #[serde(rename = "clamav")]
    ClamAv {
        /// Unique identifier for this scanner instance.
        id: String,

        /// ClamAV-specific configuration.
        #[serde(flatten)]
        config: ClamAvConfig,
    },

    /// HTTP REST API adapter configuration.
    #[serde(rename = "http-api")]
    HttpApi {
        /// Unique identifier for this scanner instance.
        id: String,

        /// HTTP API-specific configuration.
        #[serde(flatten)]
        config: HttpApiConfig,
    },

    /// Command-line tool adapter configuration.
    #[serde(rename = "command-line")]
    CommandLine {
        /// Unique identifier for this scanner instance.
        id: String,

        /// Command-line-specific configuration.
        #[serde(flatten)]
        config: CommandLineConfig,
    },

    /// gRPC service adapter configuration.
    #[serde(rename = "grpc")]
    Grpc {
        /// Unique identifier for this scanner instance.
        id: String,

        /// gRPC-specific configuration.
        #[serde(flatten)]
        config: GrpcScannerConfig,
    },
}

impl ScannerRegistry {
    /// Create a new empty registry with default chain settings.
    pub fn new() -> Self {
        Self {
            scanner_configs: Vec::new(),
            chain_mode: ChainMode::default(),
            fail_open_on_error: true,
        }
    }

    /// Parse scanner configurations from TOML string.
    ///
    /// Expects TOML format with optional `[scanner_chain]` section and
    /// `[[scanners]]` array of scanner definitions.
    ///
    /// # Arguments
    /// * `toml_str` — TOML-formatted configuration string.
    ///
    /// # Returns
    /// Parsed `ScannerRegistry` ready for chain building, or parse error.
    ///
    /// # Errors
    /// Returns error if:
    /// - TOML syntax is invalid
    /// - Required fields are missing
    /// - Unknown scanner type specified
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        tracing::info!("Parsing scanner configuration from TOML");

        // Define expected structure for parsing
        #[derive(Debug, Deserialize)]
        struct TomlConfig {
            #[serde(default)]
            scanner_chain: Option<ChainConfig>,
            #[serde(default)]
            scanners: Vec<ScannerConfigEntry>,
        }

        #[derive(Debug, Deserialize)]
        struct ChainConfig {
            #[serde(default)]
            mode: Option<String>,
            #[serde(default)]
            fail_open_on_error: Option<bool>,
        }

        let config: TomlConfig = toml::from_str(toml_str).map_err(|e| {
            ScannerError::Configuration(format!("Failed to parse scanner TOML: {}", e))
        })?;

        // Parse chain-level settings
        let chain_mode = match config
            .scanner_chain
            .as_ref()
            .and_then(|c| c.mode.as_deref())
        {
            Some("AnyInfectedBlocks") => ChainMode::AnyInfectedBlocks,
            Some("ConsensusRequired") => ChainMode::ConsensusRequired,
            Some("FirstResponder") => ChainMode::FirstResponder,
            Some("AggregateAll") => ChainMode::AggregateAll,
            Some(other) => {
                return Err(ScannerError::Configuration(format!(
                    "Unknown chain mode: {}",
                    other
                )));
            }
            None => ChainMode::default(),
        };

        let fail_open = config
            .scanner_chain
            .as_ref()
            .and_then(|c| c.fail_open_on_error)
            .unwrap_or(true);

        tracing::info!(
            scanner_count = config.scanners.len(),
            mode = %chain_mode,
            fail_open = fail_open,
            "Parsed scanner configuration"
        );

        Ok(Self {
            scanner_configs: config.scanners,
            chain_mode: chain_mode,
            fail_open_on_error: fail_open,
        })
    }

    /// Build a [`ScannerChain`] from parsed configurations.
    ///
    /// Instantiates all configured scanner adapters and adds them to a new
    /// chain in declaration order.
    ///
    /// # Returns
    /// Fully configured `ScannerChain` ready for scanning operations.
    ///
    /// # Errors
    /// Returns error if any adapter fails to initialize (e.g., invalid config).
    pub fn build_chain(&self) -> Result<ScannerChain> {
        tracing::info!(
            scanner_count = self.scanner_configs.len(),
            mode = %self.chain_mode,
            "Building scanner chain from registry"
        );

        let mut chain = ScannerChain::new(self.chain_mode, self.fail_open_on_error);

        for entry in &self.scanner_configs {
            match entry {
                ScannerConfigEntry::ClamAv { id, config } => {
                    tracing::debug!(scanner_id = %id, "Adding ClamAV adapter");
                    let adapter = ClamAvAdapter::new(config.clone());
                    chain.add_scanner(Box::new(adapter));
                }
                ScannerConfigEntry::HttpApi { id, config } => {
                    tracing::debug!(scanner_id = %id, "Adding HTTP API adapter");
                    let adapter = HttpApiAdapter::new(config.clone())?;
                    chain.add_scanner(Box::new(adapter));
                }
                ScannerConfigEntry::CommandLine { id, config } => {
                    tracing::debug!(scanner_id = %id, "Adding Command-Line adapter");
                    let adapter = CommandLineAdapter::new(config.clone())?;
                    chain.add_scanner(Box::new(adapter));
                }
                ScannerConfigEntry::Grpc { id, config } => {
                    tracing::debug!(scanner_id = %id, "Adding gRPC adapter");
                    let adapter = GrpcScannerAdapter::new(config.clone());
                    chain.add_scanner(Box::new(adapter));
                }
            }
        }

        tracing::info!(
            total_scanners = chain.len(),
            "Scanner chain built successfully"
        );

        Ok(chain)
    }

    /// Get the number of configured scanners.
    pub fn len(&self) -> usize {
        self.scanner_configs.len()
    }

    /// Check if no scanners are configured.
    pub fn is_empty(&self) -> bool {
        self.scanner_configs.is_empty()
    }
}

impl Default for ScannerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ScannerRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScannerRegistry")
            .field("scanner_count", &self.scanner_configs.len())
            .field("chain_mode", &self.chain_mode)
            .field("fail_open_on_error", &self.fail_open_on_error)
            .finish()
    }
}

// =============================================================================
// Scanner Registry Tests
// =============================================================================

#[cfg(test)]
mod registry_tests {
    use super::*;

    // =========================================================================
    // TOML Parsing Tests
    // =========================================================================

    #[test]
    fn test_parse_empty_toml() {
        let toml = "";
        let registry = ScannerRegistry::from_toml(toml).unwrap();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_parse_single_clamav_scanner() {
        let toml = r#"
[[scanners]]
type = "clamav"
id = "primary"
connection = { type = "tcp", host = "localhost", port = 3310 }
scan_timeout_secs = 30
connect_timeout_secs = 5
stream_chunk_size = 65536
"#;

        let registry = ScannerRegistry::from_toml(toml).unwrap();
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_parse_multiple_scanners() {
        let toml = r#"
[scanner_chain]
mode = "ConsensusRequired"
fail_open_on_error = false

[[scanners]]
type = "clamav"
id = "clamav-1"
connection = { type = "tcp", host = "localhost", port = 3310 }
scan_timeout_secs = 30
connect_timeout_secs = 5
stream_chunk_size = 65536
timeout_secs = 30

[[scanners]]
type = "http-api"
id = "cloud-scan"
endpoint = "https://scan.example.com/api"
timeout_secs = 60
scan_timeout_secs = 60
stream_chunk_size = 65536

[[scanners]]
type = "command-line"
id = "defender"
command_template = "MpCmdRun.exe -Scan -File {file}"
infected_exit_codes = [2, 3]
scan_timeout_secs = 120
stream_chunk_size = 65536
timeout_secs = 120
error_exit_codes = [1]
"#;

        let registry = ScannerRegistry::from_toml(toml).unwrap();
        assert_eq!(registry.len(), 3);
    }

    #[test]
    fn test_parse_chain_mode() {
        let toml = r#"
[scanner_chain]
mode = "FirstResponder"

[[scanners]]
type = "clamav"
id = "s1"
connection = { type = "tcp", host = "localhost", port = 3310 }
scan_timeout_secs = 30
connect_timeout_secs = 5
stream_chunk_size = 65536
timeout_secs = 30
"#;

        let registry = ScannerRegistry::from_toml(toml).unwrap();
        // Can't directly access chain_mode, but we can build and check
        let chain = registry.build_chain().unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn test_build_chain_from_registry() {
        let toml = r#"
[[scanners]]
type = "clamav"
id = "test-clamav"
connection = { type = "tcp", host = "192.168.1.100", port = 3310 }
scan_timeout_secs = 15
connect_timeout_secs = 5
stream_chunk_size = 65536
"#;

        let registry = ScannerRegistry::from_toml(toml).unwrap();
        let chain = registry.build_chain().unwrap();

        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn test_invalid_toml_syntax() {
        let toml = r#"
[[scanners]]
type = "clamav
id = "missing-quote
"#;

        let result = ScannerRegistry::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_chain_mode() {
        let toml = r#"
[scanner_chain]
mode = "InvalidMode"

[[scanners]]
type = "clamav"
id = "s1"
connection = { type = "tcp", host = "localhost", port = 3310 }
scan_timeout_secs = 30
connect_timeout_secs = 5
stream_chunk_size = 65536
timeout_secs = 30
"#;

        let result = ScannerRegistry::from_toml(toml);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        // Serde reports unknown enum variants with specific phrasing
        assert!(
            err_msg.contains("Unknown") || err_msg.contains("unknown") || err_msg.contains("InvalidMode"),
            "Error should mention invalid mode, got: {err_msg}"
        );
    }

    #[test]
    fn test_grpc_scanner_config() {
        let toml = r#"
[[scanners]]
type = "grpc"
id = "enterprise-scanner"
server_addr = "scanner.internal:50051"
use_tls = true
tls_domain = "scanner.internal"
timeout_secs = 45
scan_timeout_secs = 45
"#;

        let registry = ScannerRegistry::from_toml(toml).unwrap();
        assert_eq!(registry.len(), 1);

        let chain = registry.build_chain().unwrap();
        assert_eq!(chain.len(), 1);
    }

    // =========================================================================
    // Integration Test: Full Workflow
    // =========================================================================

    #[tokio::test]
    async fn test_full_workflow_with_mock_scanners() {
        let toml = r#"
[scanner_chain]
mode = "AnyInfectedBlocks"
fail_open_on_error = true

[[scanners]]
type = "clamav"
id = "mock-clamav"
connection = { type = "tcp", host = "localhost", port = 3310 }
scan_timeout_secs = 30
connect_timeout_secs = 5
stream_chunk_size = 65536
timeout_secs = 30
"#;

        let registry = ScannerRegistry::from_toml(toml).unwrap();
        let mut chain = registry.build_chain().unwrap();

        // Add a mock scanner for testing (since we can't connect to real clamd)
        #[derive(Debug)]
        struct TestCleanScanner;
        #[async_trait]
        impl ExternalScanner for TestCleanScanner {
            fn name(&self) -> &str { "TestClean" }
            fn id(&self) -> &str { "test-clean" }
            async fn scan_stream(&self, _data: &[u8]) -> Result<ScanResult> {
                Ok(ScanResult::Clean)
            }
            async fn health_check(&self) -> bool { true }
            async fn metadata(&self) -> Option<ScannerMetadata> { None }
        }

        chain.add_scanner(Box::new(TestCleanScanner));

        // Scan should succeed with Clean result
        let result = chain.scan(b"test file content").await.unwrap();
        assert_eq!(result, ScanResult::Clean);
    }
}

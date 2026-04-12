// =============================================================================
// Misogi Core Traits Module
// =============================================================================
// This module defines the pluggable architecture interfaces for the Misogi system.
// Each trait abstracts a specific subsystem to enable runtime-swappable implementations.
//
// Design Principles:
// - All traits require Send + Sync for safe concurrent usage across async tasks.
// - All async methods use #[async_trait] for ergonomic trait object compatibility.
// - Every associated type is fully documented with invariants and safety contracts.
// - Error handling consistently uses crate::error::{MisogiError, Result}.
//
// Thread Safety Guarantee:
// All implementors MUST be Send + Sync. The Misogi runtime holds trait objects
// behind Arc<> and shares them across tokio tasks without additional locking.
// Implementors that hold internal mutable state must use Arc<RwLock<T>> or
// equivalent synchronization primitives internally.
// =============================================================================

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use crate::audit_log::AuditLogEntry;
use crate::error::Result;

// =============================================================================
// StateMachine Trait (implemented in engine::state_machine module)
// =============================================================================
// The concrete StateMachine<S> struct is defined in crate::engine::state_machine
// and fully implements this trait interface with thread-safe RwLock-based state
// management, configurable transition rules, and optional guard functions.
//
// This trait definition is retained here for:
// 1. API documentation and contract specification.
// 2. Trait object usage in ApprovalTrigger<S>::start() signature.
// 3. Backward compatibility for code referencing traits::StateMachine<S>.
//
// Implementation Location: crate::engine::state_machine::StateMachine<S>
// See: src/engine/state_machine.rs for full implementation details.
//
// Type Parameters
// - `S`: The state enum type (e.g., FileLifecycleState from engine::webhook)
pub trait StateMachine<S>: Send + Sync {
    /// Subscribe to state change events from this machine.
    ///
    /// Returns a closure invoked on each successful transition.
    /// Production implementations integrate with event bus systems.
    fn subscribe(&self) -> Box<dyn Fn(S) + Send + Sync>;

    /// Query the current state of the machine.
    ///
    /// Returns a clone of the current state value.
    /// Thread-safe via internal RwLock (shared read access).
    fn current_state(&self) -> S;
}

// =============================================================================
// Trait 1: TransferDriver
// =============================================================================

/// Configuration payload for initializing a [`TransferDriver`] implementation.
///
/// Each driver implementation defines its own concrete config struct that
/// implements this trait's required interface. This enables heterogeneous
/// configuration across different transport backends (HTTP, gRPC, raw TCP, etc.)
/// while maintaining a uniform initialization contract.
///
/// # Example
/// ```ignore
/// pub struct HttpDriverConfig {
///     base_url: String,
///     timeout_secs: u64,
///     max_retries: u32,
/// }
/// impl TransferDriverConfig for HttpDriverConfig { /* ... */ }
/// ```
pub trait TransferDriverConfig: Send + Sync + 'static {
    /// Validate that all required fields are present and semantically correct.
    ///
    /// # Errors
    /// Returns [`MisogiError::Protocol`] if any field violates its constraints.
    fn validate(&self) -> Result<()>;
}

/// Acknowledgment returned by the remote endpoint after receiving a chunk.
///
/// This structure serves as the cryptographic proof-of-receipt that enables
/// the sender to confirm data integrity at the chunk level before proceeding
/// to the next chunk or marking the transfer as complete.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChunkAck {
    /// Unique identifier of the file this chunk belongs to.
    pub file_id: String,

    /// Zero-based index of the acknowledged chunk within the file.
    pub chunk_index: u32,

    /// MD5 hash of the received chunk data as computed by the receiver.
    /// The sender MUST compare this against the locally computed hash to
    /// detect in-transit corruption or tampering.
    pub received_md5: String,

    /// Number of bytes actually received by the remote endpoint.
    /// Must equal `ChunkMeta.size` for a valid acknowledgment.
    pub received_size: u64,

    /// Timestamp when the receiver generated this acknowledgment (UTC, RFC3339).
    pub ack_timestamp: String,

    /// Optional error message if the chunk was rejected by the receiver.
    /// When `Some(_)`, the acknowledgment indicates a failure condition.
    pub error: Option<String>,
}

impl ChunkAck {
    /// Determine whether this acknowledgment indicates successful receipt.
    ///
    /// A chunk is considered successfully received when:
    /// - No error message is present
    /// - The received MD5 hash is non-empty
    /// - The received size is greater than zero
    pub fn is_success(&self) -> bool {
        self.error.is_none() && !self.received_md5.is_empty() && self.received_size > 0
    }
}

/// Health status report from a [`TransferDriver`] implementation.
///
/// Returned by [`TransferDriver::health_check()`] to enable monitoring systems
/// to assess the operational readiness of each transport backend without
/// requiring full integration test cycles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriverHealthStatus {
    /// Human-readable identifier of the driver instance.
    pub driver_name: String,

    /// Whether the driver is currently operational and accepting requests.
    pub is_healthy: bool,

    /// Detailed status description suitable for operator dashboards.
    /// Contains diagnostic information when `is_healthy` is false.
    pub status_message: String,

    /// Round-trip latency of the most recent health probe in milliseconds.
    /// `None` if no probe has been executed yet or the probe timed out.
    pub latency_ms: Option<u64>,

    /// ISO8601 timestamp of when this health status was captured.
    pub checked_at: DateTime<Utc>,

    /// Sequential counter incremented on each health check invocation.
    /// Useful for detecting stale cached values in monitoring pipelines.
    pub check_sequence: u64,
}

/// Abstracts the file transfer transport layer for cross-network communication.
///
/// [`TransferDriver`] is the core abstraction enabling Misogi to operate over
/// arbitrary transport protocols (HTTP/2, gRPC, raw TCP tunnels, message queues)
/// without coupling the business logic to any specific networking stack.
///
/// # Lifecycle Contract
/// 1. Caller invokes [`init()`](TransferDriver::init) with driver-specific configuration.
/// 2. Caller sends individual chunks via [`send_chunk()`](TransferDriver::send_chunk).
/// 3. After all chunks are sent, caller invokes [`send_complete()`](TransferDriver::send_complete).
/// 4. Periodic health monitoring via [`health_check()`](TransferDriver::health_check).
/// 5. Graceful teardown via [`shutdown()`](TransferDriver::shutdown).
///
/// # Concurrency Model
/// Implementations MAY process multiple concurrent `send_chunk` calls for
/// different files, but MUST serialize chunks within the same `file_id` to
/// preserve ordering guarantees. Use per-file mutexes or channel-based
/// serialization internally.
///
/// # Error Handling
/// All methods return [`Result<T>`]. Transient network errors SHOULD be
/// retried by the caller using exponential backoff. Permanent errors
/// (authentication failure, protocol mismatch) MUST surface immediately.
#[async_trait]
pub trait TransferDriver: Send + Sync {
    /// Concrete configuration type for this driver implementation.
    ///
    /// Each driver (HttpDriver, GrpcDriver, TunnelDriver, etc.) defines
    /// its own configuration struct implementing [`TransferDriverConfig`].
    type Config: TransferDriverConfig;

    /// Return the human-readable name of this driver implementation.
    ///
    /// Used for logging, audit trails, and driver registry lookups.
    /// MUST be unique across all registered drivers within a single runtime.
    ///
    /// # Examples
    /// - `"http-v2-driver"`
    /// - `"grpc-tls-driver"`
    /// - `"raw-tunnel-driver"`
    fn name(&self) -> &str;

    /// Initialize the driver with the provided configuration.
    ///
    /// This method MUST be called exactly once before any other operation.
    /// Subsequent calls SHOULD return `Ok(())` as a no-op (idempotent),
    /// or return an error if re-initialization with different config is detected.
    ///
    /// # Arguments
    /// * `config` - Driver-specific configuration validated via
    ///   [`TransferDriverConfig::validate()`].
    ///
    /// # Errors
    /// - [`MisogiError::Io`] if underlying socket/connection creation fails.
    /// - [`MisogiError::Protocol`] if configuration is invalid post-validation.
    async fn init(&mut self, config: Self::Config) -> Result<()>;

    /// Transmit a single file chunk to the remote endpoint.
    ///
    /// The caller is responsible for ensuring chunks are sent in order
    /// (`chunk_index` 0, 1, 2, ...). Out-of-order transmission behavior
    /// is implementation-defined but SHOULD result in an error.
    ///
    /// # Arguments
    /// * `file_id` - Unique identifier of the file being transferred.
    /// * `chunk_index` - Zero-based position of this chunk within the file.
    /// * `data` - Raw bytes of the chunk payload. Ownership is transferred
    ///   to allow zero-copy send paths where the transport supports it.
    ///
    /// # Returns
    /// A [`ChunkAck`] from the remote endpoint confirming (or rejecting) receipt.
    ///
    /// # Errors
    /// - [`MisogiError::Io`] if the transport layer fails mid-transmission.
    /// - [`MisogiError::Protocol`] if the remote rejects the chunk format.
    async fn send_chunk(
        &self,
        file_id: &str,
        chunk_index: u32,
        data: Bytes,
    ) -> Result<ChunkAck>;

    /// Signal that all chunks for a file have been transmitted.
    ///
    /// The remote endpoint uses this signal to perform end-to-end integrity
    /// verification (reconstructing full-file hash from chunk hashes) and
    /// mark the transfer as complete in its local store.
    ///
    /// # Arguments
    /// * `file_id` - Unique identifier of the completed transfer.
    /// * `total_chunks` - Total number of chunks that were sent.
    /// * `file_md5` - Expected MD5 hash of the complete reconstructed file.
    ///
    /// # Returns
    /// The final acknowledgment containing the receiver's computed file hash
    /// for caller-side verification.
    ///
    /// # Errors
    /// - [`MisogiError::HashMismatch`] if the receiver's recomputed hash differs.
    /// - [`MisogiError::Protocol`] if not all chunks were received.
    async fn send_complete(
        &self,
        file_id: &str,
        total_chunks: u32,
        file_md5: &str,
    ) -> Result<ChunkAck>;

    /// Perform a lightweight health check against the transport backend.
    ///
    /// This operation MUST be fast (target <100ms) and non-destructive.
    /// It SHOULD NOT create, modify, or delete any resources on either side.
    /// Implementations typically send a minimal ping/heartbeat packet.
    ///
    /// # Returns
    /// A [`DriverHealthStatus`] snapshot suitable for monitoring dashboards.
    async fn health_check(&self) -> Result<DriverHealthStatus>;

    /// Gracefully shut down the driver and release all held resources.
    ///
    /// After this method returns:
    /// - All open connections MUST be closed cleanly (FIN packets sent).
    /// - All in-flight transfers MUST be completed or cancelled with notification.
    /// - Internal buffers and temporary files MUST be cleaned up.
    /// - The driver MUST NOT accept new `send_chunk` calls (return error).
    ///
    /// # Idempotency
    /// Calling `shutdown()` multiple times MUST be safe; subsequent calls
    /// after the first SHOULD return `Ok(())` immediately.
    async fn shutdown(&self) -> Result<()>;
}

// =============================================================================
// Trait 2: CDRStrategy
// =============================================================================

/// Decision emitted by a [`CDRStrategy`] after evaluating a file for sanitization.
///
/// Content Disarmament and Reconstruction (CDR) is the core security mechanism
/// preventing malicious payloads from traversing network boundaries. Each strategy
/// produces one of these decisions to guide the pipeline's next action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StrategyDecision {
    /// The file requires sanitization (disarm and reconstruct).
    /// The pipeline SHALL invoke [`CDRStrategy::apply()`] with this decision.
    Sanitize,

    /// The file is safe as-is and may bypass sanitization.
    /// Typically used for already-sanitized formats or whitelisted sources.
    Skip,

    /// The file must be blocked entirely — no transfer permitted.
    /// Used when the file matches known-bad signatures or policy violations.
    Block {
        /// Human-readable reason for the block decision, logged to audit trail.
        reason: String,
    },

    /// Delegate sanitization to a different strategy (specialist handler).
    /// Enables chained/recursive CDR processing for complex nested formats.
    Delegate {
        /// Name of the target strategy to delegate processing to.
        target_strategy: String,
        /// Contextual metadata passed to the delegate strategy.
        context: SanitizeContext,
    },
}

/// Contextual information provided to the CDR evaluation and application phases.
///
/// Carries metadata about the file, its origin, and the current processing
/// state to enable context-aware sanitization decisions (e.g., stricter
/// policies for files originating from untrusted networks).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SanitizeContext {
    /// Original filename including extension (not filesystem path).
    pub filename: String,

    /// Declared MIME type from the upload request header.
    pub mime_type: String,

    /// Total file size in bytes. Used for resource-limit decisions.
    pub file_size: u64,

    /// MD5 hash of the original (unsanitized) file content.
    pub original_hash: String,

    /// Source network identifier where the file originated.
    /// Used for zone-aware policy enforcement (e.g., LGWAN vs Internet).
    pub source_zone: String,

    /// Target network identifier for the intended destination.
    pub destination_zone: String,

    /// ID of the user who uploaded/initiated the transfer.
    pub uploader_id: String,

    /// Filesystem path to the original file for reading during sanitization.
    pub file_path: PathBuf,

    /// Output path where the sanitized file should be written.
    pub output_path: PathBuf,
}

/// Report produced by [`CDRStrategy::apply()`] documenting sanitization results.
///
/// This structure forms part of the immutable audit chain of custody.
/// Every field is serialized to JSONL for long-term retention compliance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationReport {
    /// Unique identifier correlating this report to its source file transfer.
    pub file_id: String,

    /// Name of the strategy that performed the sanitization.
    pub strategy_name: String,

    /// Whether the sanitization completed without errors.
    pub success: bool,

    /// Number of discrete sanitization actions performed (e.g., macro removal,
    /// script stripping, embedded-object extraction).
    pub actions_performed: u32,

    /// Human-readable description of what was modified or removed.
    pub details: String,

    /// MD5 hash of the sanitized output file (differs from original_hash if
    /// content was modified during disarm/reconstruction).
    pub sanitized_hash: String,

    /// Size of the sanitized output in bytes (may differ from input).
    pub sanitized_size: u64,

    /// Wall-clock time spent performing sanitization in milliseconds.
    pub processing_time_ms: u64,

    /// Error message if `success` is false.
    pub error: Option<String>,
}

/// Abstracts Content Disarmament and Reconstruction (CDR) strategies.
///
/// CDR is the primary defense-in-depth mechanism preventing malicious file
/// payloads from crossing network boundaries. Rather than scanning for known
/// threats (which fails against zero-day), CDR disarms files by removing
/// executable content and reconstructing them into safe canonical forms.
///
/// # Plugin Architecture
/// Each file format family (Office documents, PDFs, images, archives) has
/// its own CDR strategy implementation registered at runtime. The pipeline
/// selects the appropriate strategy based on file extension and magic bytes.
///
/// # Processing Flow
/// 1. [`supported_extensions()`](CDRStrategy::supported_extensions) determines applicability.
/// 2. [`evaluate()`](CDRStrategy::evaluate) inspects the file and returns a [`StrategyDecision`].
/// 3. If decision is `Sanitize`, [`apply()`](CDRStrategy::apply) performs the actual disarm/reconstruction.
/// 4. The resulting [`SanitizationReport`] is appended to the audit log.
///
/// # Safety Requirements
/// Implementations MUST:
/// - Never execute embedded macros, scripts, or active content during evaluation.
/// - Write sanitized output to a separate file (never modify in-place).
/// - Validate output file structure before returning success.
/// - Handle malformed/corrupt input gracefully (return error, never panic).
#[async_trait]
pub trait CDRStrategy: Send + Sync {
    /// Return the human-readable name of this CDR strategy.
    ///
    /// Used for strategy selection, audit logging, and configuration references.
    /// Examples: `"office-cdr"`, `"pdf-sanitizer"`, `"image-defanger"`.
    fn name(&self) -> &str;

    /// Return the set of file extensions this strategy can handle.
    ///
    /// Extensions are returned lowercase without the leading dot.
    /// The pipeline uses this list for initial strategy routing before
    /// invoking the more expensive [`evaluate()`](CDRStrategy::evaluate) method.
    ///
    /// # Examples
    /// `["docx", "xlsx", "pptx", "doc", "xls", "ppt"]` for Office CDR.
    fn supported_extensions(&self) -> Vec<&'static str>;

    /// Evaluate whether a file requires sanitization and determine the action.
    ///
    /// This inspection phase analyzes file metadata and structure WITHOUT
    /// executing any embedded active content. It produces a [`StrategyDecision`]
    /// guiding the pipeline's next step.
    ///
    /// # Arguments
    /// * `context` - Metadata and paths for the file under evaluation.
    ///
    /// # Returns
    /// A [`StrategyDecision`] indicating sanitize/skip/block/delegate.
    ///
    /// # Performance
    /// This method SHOULD complete quickly (<500ms for typical files) since
    /// it runs synchronously in the critical upload path. Heavy analysis
    /// (deep format parsing) should be deferred to [`apply()`](CDRStrategy::apply).
    async fn evaluate(&self, context: &SanitizeContext) -> Result<StrategyDecision>;

    /// Perform the actual content disarmament and reconstruction.
    ///
    /// This is the security-critical phase where potentially dangerous content
    /// is stripped and the file is rebuilt into a safe canonical form.
    ///
    /// # Arguments
    /// * `context` - Same context from [`evaluate()`](CDRStrategy::evaluate), possibly enriched.
    /// * `decision` - The [`StrategyDecision::Sanitize`] variant from evaluation.
    ///
    /// # Returns
    /// A [`SanitizationReport`] documenting all actions taken and their outcomes.
    ///
    /// # Safety Invariants
    /// - Input file at `context.file_path` MUST NOT be modified.
    /// - Output MUST be written to `context.output_path`.
    /// - On error, `context.output_path` MUST NOT contain partial/corrupt data.
    async fn apply(
        &self,
        context: &SanitizeContext,
        decision: &StrategyDecision,
    ) -> Result<SanitizationReport>;
}

// =============================================================================
// Trait 3: FileTypeDetector
// =============================================================================

/// Result of a file type detection operation performed by [`FileTypeDetector`].
///
/// Combines the detected type classification with confidence scoring and
/// actionable metadata for downstream processing (sanitizer selection,
/// blocklist enforcement, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDetectionResult {
    /// Detected MIME type or format identifier (e.g., "application/pdf").
    /// Empty string if detection failed completely.
    pub detected_type: String,

    /// Confidence score ranging from 0.0 (guess) to 1.0 (certain).
    /// Values below 0.5 indicate low-confidence detections that should
    /// trigger fallback heuristics or human review.
    pub confidence: f64,

    /// File extension inferred from the detected format (lowercase, no dot).
    /// May differ from the original filename extension if mismatch detected.
    pub extension: String,

    /// Hex-encoded magic bytes that were matched for this detection.
    /// Useful for audit logging and forensic analysis of detection decisions.
    pub magic_hex: String,

    /// Name of the recommended CDR sanitizer for this file type.
    /// Empty string if no sanitizer is applicable or the type is blocked.
    pub recommended_sanitizer: String,

    /// Whether this file type is explicitly blocked by policy.
    /// When true, the pipeline MUST reject the file regardless of other factors.
    pub is_blocked: bool,

    /// Human-readable explanation for why the file is blocked.
    /// Non-empty only when `is_blocked` is true.
    pub block_reason: Option<String>,
}

impl FileDetectionResult {
    /// Create a successful detection result with high confidence.
    pub fn detected(
        detected_type: impl Into<String>,
        extension: impl Into<String>,
        magic_hex: impl Into<String>,
        recommended_sanitizer: impl Into<String>,
    ) -> Self {
        Self {
            detected_type: detected_type.into(),
            confidence: 1.0,
            extension: extension.into(),
            magic_hex: magic_hex.into(),
            recommended_sanitizer: recommended_sanitizer.into(),
            is_blocked: false,
            block_reason: None,
        }
    }

    /// Create a detection result indicating the file type is blocked.
    pub fn blocked(
        detected_type: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            detected_type: detected_type.into(),
            confidence: 1.0,
            extension: String::new(),
            magic_hex: String::new(),
            recommended_sanitizer: String::new(),
            is_blocked: true,
            block_reason: Some(reason.into()),
        }
    }

    /// Create an unknown/undetermined detection result.
    pub fn unknown() -> Self {
        Self {
            detected_type: String::new(),
            confidence: 0.0,
            extension: String::new(),
            magic_hex: String::new(),
            recommended_sanitizer: String::new(),
            is_blocked: false,
            block_reason: None,
        }
    }

    /// Check whether this detection has sufficient confidence for automated processing.
    ///
    /// Threshold is configurable but defaults to 0.5 (50% confidence minimum).
    pub fn is_confident(&self, threshold: f64) -> bool {
        self.confidence >= threshold && !self.detected_type.is_empty()
    }
}

/// Abstracts file type identification via magic number (file signature) analysis.
///
/// Unlike naive extension-based detection which is trivially spoofed, magic number
/// analysis inspects the actual binary header of each file to determine its real
/// format. This is essential for security: a renamed `.txt` file that is actually
/// an executable MUST be detected and blocked.
///
/// # Detection Priority
/// Multiple detectors can be registered; they are consulted in priority order.
/// The first detector returning `confidence >= threshold` wins. Fallback detectors
/// handle edge cases (encrypted files, custom formats, corrupted headers).
///
/// # Implementation Notes
/// Detectors SHOULD read only the minimum number of bytes needed for signature
/// matching (typically 4-262 bytes depending on format) to avoid loading large
/// files entirely into memory during the detection phase.
#[async_trait]
pub trait FileTypeDetector: Send + Sync {
    /// Return the human-readable name of this detector implementation.
    ///
    /// Examples: `"magic-bytes-detector"`, `"libmagic-detector"`, `"custom-detector"`.
    fn name(&self) -> &str;

    /// Analyze the file at the given path and determine its actual type.
    ///
    /// Reads the file header (magic bytes) and compares against known signatures
    /// to produce a [`FileDetectionResult`] with confidence scoring.
    ///
    /// # Arguments
    /// * `file_path` - Absolute path to the file to analyze.
    /// * `declared_extension` - Extension from the filename (without dot), used
    ///   for mismatch detection (e.g., file claims .txt but is actually .exe).
    ///
    /// # Returns
    /// A [`FileDetectionResult`] with type classification and action metadata.
    ///
    /// # Errors
    /// - [`MisogiError::NotFound`] if the file does not exist.
    /// - [`MisogiError::Io`] if the file cannot be read (permissions, etc.).
    async fn detect(
        &self,
        file_path: &PathBuf,
        declared_extension: &str,
    ) -> Result<FileDetectionResult>;

    /// Return the set of file extensions this detector can identify.
    ///
    /// Used by the pipeline to short-circuit detection when a file's declared
    /// extension is not in any detector's supported set (fast rejection).
    fn supported_extensions(&self) -> Vec<&'static str>;
}

// =============================================================================
// Trait 4: PIIDetector
// =============================================================================

/// Action to take when PII (Personally Identifiable Information) is found.
///
/// Determines how the system responds to detected sensitive data patterns
/// in transferred files. Action selection depends on organizational policy
/// and the sensitivity level of the matched pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PIIAction {
    /// Block the entire file transfer. No data leaves the boundary.
    /// Used for highly sensitive patterns (e.g., classified document markers).
    Block,

    /// Mask/redact the matched PII in-place before allowing transfer.
    /// The original file is preserved; only the sanitized copy is forwarded.
    Mask,

    /// Log the finding but allow the transfer to proceed unchanged.
    /// Used for informational patterns where awareness suffices (e.g., names).
    AlertOnly,
}

/// Single match of a PII pattern found within scanned content.
///
/// Each match records precisely what was found, where, and how it was
/// identified — forming the evidentiary record for compliance audits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PIIMatch {
    /// Human-readable name of the PII pattern category.
    /// Examples: `"japanese_my_number"`, `"ssn_us"`, `"credit_card"`,
    /// `"kr_resident_id"`, `"eu_national_id"`, `"phone_number"`.
    pub pattern_name: String,

    /// The exact text substring that matched the PII pattern.
    /// Stored for audit purposes; MUST be handled as sensitive data.
    pub matched_text: String,

    /// Redacted version of `matched_text` with PII obscured.
    /// Format: preserve first and last character, replace middle with asterisks.
    /// Examples (region-dependent):
    /// - Japanese: `"田中 太郎"` → `"田**郎"`
    /// - English: `"John Smith"` → `"J***h"`
    /// - Korean: `"김철수"` → `"김*수"`
    pub masked_text: String,

    /// Byte offset of the match start within the scanned content.
    /// Used for precise location reporting and targeted redaction.
    pub offset: usize,

    /// Length of the matched text in bytes (may differ from `matched_text.len()`
    /// for multi-byte encodings like UTF-8 CJK characters, Korean Hangul syllables,
    /// or any non-Latin script).
    pub length: usize,

    /// The regular expression pattern string that produced this match.
    /// Documented for transparency and pattern tuning.
    pub pattern_regex: String,
}

/// Aggregate result of a PII scan operation performed by [`PIIDetector`].
///
/// Summarizes all findings from scanning a single file and provides the
/// recommended action based on the highest-sensitivity match found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PIIScanResult {
    /// Whether any PII patterns were found in the scanned content.
    pub found: bool,

    /// Individual PII matches discovered during the scan.
    /// Ordered by offset (appearance order in the file).
    pub matches: Vec<PIIMatch>,

    /// Recommended action based on the most sensitive match found.
    /// If multiple matches have different action levels, the strictest wins.
    pub action: PIIAction,

    /// Total number of bytes scanned (for throughput metrics).
    pub bytes_scanned: u64,

    /// Wall-clock scan duration in milliseconds (for performance monitoring).
    pub scan_duration_ms: u64,
}

impl PIIScanResult {
    /// Create a clean result indicating no PII was found.
    pub fn clean(bytes_scanned: u64, duration_ms: u64) -> Self {
        Self {
            found: false,
            matches: Vec::new(),
            action: PIIAction::AlertOnly,
            bytes_scanned,
            scan_duration_ms: duration_ms,
        }
    }

    /// Determine the strictest action among all matches.
    ///
    /// Precedence (strictest first): Block > Mask > AlertOnly.
    pub fn strictest_action(&self) -> &PIIAction {
        &self.action
    }
}

/// Abstracts PII (Personally Identifiable Information) detection and scanning.
///
/// Data privacy regulations across jurisdictions mandate proactive scanning of
/// outbound files for sensitive data patterns. This trait provides the plugin
/// interface for swappable scanning engines with different pattern sets and
/// detection algorithms.
///
/// # Scanning Scope
/// Detectors MAY operate on:
/// - Raw text content (extracted from documents via text extraction)
/// - Metadata fields (document properties, EXIF data, PDF info dictionary)
/// - Embedded content (attachments inside archives, OLE objects in Office docs)
///
/// # Pattern Categories (Region-Specific Examples)
///
/// **Japan (APPI / My Number Act):**
/// - My Number (マイナンバー, 12-digit national ID)
/// - Driver's license numbers
/// - Postal codes (〒XXX-XXXX format)
///
/// **Korea (PIPA / FSS Guidelines):**
/// - Resident Registration Number (주민등록번호, 13-digit)
/// - Driver's license number
/// - Phone number (with carrier prefix: 010, 011, etc.)
///
/// **EU (GDPR / ePrivacy Directive):**
/// - National ID numbers (varies by member state)
/// - Tax identification numbers (TIN)
/// - EU health insurance numbers
///
/// **US (FTC / State Privacy Laws):**
/// - Social Security Number (SSN, XXX-XX-XXXX format)
/// - Driver's license numbers (state-specific)
/// - Passport numbers
///
/// **Universal (All Regions):**
/// - Credit card numbers (PCI-DSS scope: Visa, MC, Amex, JCB, UnionPay)
/// - IBAN (International Bank Account Number)
/// - Email addresses
/// - IP addresses (both IPv4 and IPv6)
#[async_trait]
pub trait PIIDetector: Send + Sync {
    /// Return the human-readable name of this PII detector implementation.
    ///
    /// Examples: `"regex-pii-scanner"`, `"ml-pii-detector"`, `"government-pattern-engine"`.
    fn name(&self) -> &str;

    /// Scan the provided content for PII patterns and return all findings.
    ///
    /// # Arguments
    /// * `content` - Raw text content to scan (already extracted from file).
    ///   Encoding normalization is the caller's responsibility.
    /// * `file_id` - Correlation identifier linking results to the source file.
    /// * `filename` - Original filename for context-aware pattern selection
    ///   (e.g., stricter scanning for spreadsheets with "customer" in name).
    ///
    /// # Returns
    /// A [`PIIScanResult`] containing all matches and the recommended action.
    ///
    /// # Performance
    /// Scanning SHOULD be proportional to content size. For files larger than
    /// 100MB, consider streaming/chunked scanning to avoid memory pressure.
    async fn scan(
        &self,
        content: &str,
        file_id: &str,
        filename: &str,
    ) -> Result<PIIScanResult>;
}

// =============================================================================
// Trait 5: LogFormatter
// =============================================================================

/// Abstracts log output formatting for audit entries.
///
/// The Misogi audit system produces structured [`AuditLogEntry`] records that
/// must be rendered into various output formats for different consumers:
/// - JSONL for persistent storage and SIEM ingestion
/// - CSV for spreadsheet export and compliance reporting
/// - Human-readable text for email notifications and dashboard display
/// - Structured syslog for centralized log management
///
/// Each [`LogFormatter`] implementation handles one output format, enabling
/// the same audit data to be simultaneously written in multiple formats.
///
/// # Thread Safety
/// Formatters are typically stateless (pure functions of entry -> string).
/// If internal state is required (e.g., template caching), it MUST be
/// protected by synchronization primitives since formatters are shared
/// across concurrent audit writing tasks.
#[async_trait]
pub trait LogFormatter: Send + Sync {
    /// Format a single [`AuditLogEntry`] into the target output representation.
    ///
    /// # Arguments
    /// * `entry` - The audit log entry to format.
    ///
    /// # Returns
    /// The formatted string ready for writing to the output sink.
    ///
    /// # Errors
    /// - [`MisogiError::Serialization`] if the entry cannot be serialized
    ///   to the target format (e.g., contains unencodable characters).
    async fn format(&self, entry: &AuditLogEntry) -> Result<String>;

    /// Format multiple [`AuditLogEntry`] records into a batch output.
    ///
    /// Batch formatting is more efficient than calling [`format()`](LogFormatter::format)
    /// in a loop because it allows:
    /// - Header/footer emission (CSV headers, JSON array brackets)
    /// - Compression opportunity hints for the caller
    /// - Batch-level statistics (record count, timestamp range)
    ///
    /// # Arguments
    /// * `entries` - Slice of audit log entries to format as a batch.
    ///
    /// # Returns
    /// The complete formatted batch string. Entries appear in the same
    /// order as the input slice.
    ///
    /// # Errors
    /// - [`MisogiError::Serialization`] if any entry fails to format.
    ///   Implementations SHOULD attempt to format all entries and collect
    ///   errors rather than failing on the first bad entry.
    async fn format_batch(&self, entries: &[AuditLogEntry]) -> Result<String>;
}

// =============================================================================
// Trait 6: ApprovalTrigger
// =============================================================================

/// Abstracts external event triggers for the approval workflow state machine.
///
/// Enterprise and government workflows across regions require multi-channel
/// approval triggering tailored to local communication infrastructure:
///
/// - Email notifications with approval/rejection links (universal)
/// - Calendar reminders for pending approvals approaching deadline (universal)
/// - Webhook callbacks to external workflow systems:
///   - Japan: KENSI, e-Gov, LGWAN workflow engines
///   - Korea: NASDAQ/e-screening integrations, FSS-approved systems
///   - US/EU: ServiceNow, SAP, Microsoft Power Automate connectors
/// - SMS/push notifications for urgent time-sensitive transfers
/// - Proprietary messaging systems (region-specific internal tools)
///
/// Each [`ApprovalTrigger`] implementation connects to one external channel
/// and translates state machine events into channel-appropriate notifications.
///
/// # Lifecycle
/// 1. [`start()`](ApprovalTrigger::start) registers the trigger with the state machine.
/// 2. The trigger listens for state transitions (PendingApproval -> Approved, etc.)
/// 3. On relevant transitions, the trigger sends external notifications.
/// 4. [`stop()`](ApprovalTrigger::stop) unregisters and releases resources.
///
/// # State Machine Integration
/// The trigger receives an `Arc<StateMachine<S>>` and subscribes to state
/// change events. When a monitored transition occurs, the trigger constructs
/// and sends the appropriate notification for its channel.
///
/// # Generic Parameter `S`
/// The state type `S` is generic to avoid coupling this trait definition
/// to a specific state enum. Task 5.2 will define `FileLifecycleState`
/// which will be used as the concrete type parameter at call sites.
#[async_trait]
pub trait ApprovalTrigger<S>: Send + Sync
where
    S: Clone + Send + Sync + 'static,
{
    /// Return the human-readable name of this trigger implementation.
    ///
    /// Examples: `"email-approval-trigger"`, `"webhook-trigger"`, `"sms-reminder-trigger"`.
    fn name(&self) -> &str;

    /// Activate this trigger by registering with the given state machine.
    ///
    /// After this call returns, the trigger MUST be actively listening for
    /// state transitions and sending notifications accordingly.
    ///
    /// # Arguments
    /// * `state_machine` - Shared reference to the approval workflow state machine.
    ///   The trigger subscribes to state change events via
    ///   [`StateMachine::subscribe()`](StateMachine::subscribe).
    ///
    /// # Errors
    /// - [`MisogiError::Protocol`] if the trigger cannot connect to its
    ///   external service (email server, webhook endpoint, SMS gateway).
    /// - [`MisogiError::Io`] if required configuration files are missing.
    async fn start(&mut self, state_machine: Arc<dyn StateMachine<S>>) -> Result<()>;

    /// Deactivate this trigger and release all held resources.
    ///
    /// After this call returns:
    /// - The trigger MUST unsubscribe from the state machine.
    /// - All pending/outstanding notifications MUST be flushed or cancelled.
    /// - External connections MUST be closed cleanly.
    ///
    /// # Idempotency
    /// Calling `stop()` on an already-stopped trigger MUST return `Ok(())`.
    async fn stop(&mut self) -> Result<()>;
}

// =============================================================================
// Trait 7: CalendarProvider
// =============================================================================

/// Represents a single holiday entry in a regional calendar system.
///
/// Government and enterprise operations across different regions follow complex
/// calendars combining multiple dating systems:
/// - Western Gregorian dates (universal day-to-day operations)
/// - Regional era dates (e.g., Wareki for Japan, lunar calendar variants)
/// - National/public holidays (quantity varies by country's labor laws)
/// - Sub-national or organizational custom holidays (state/province level)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Holiday {
    /// Gregorian date of the holiday.
    pub date: NaiveDate,

    /// Official name of the holiday in Japanese.
    pub name_ja: String,

    /// English description of the holiday for international systems.
    pub name_en: String,

    /// Holiday category determining business logic impact.
    pub category: HolidayCategory,
}

/// Classification of holidays affecting business day calculations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HolidayCategory {
    /// Nationally recognized public holiday (New Year's Day, Emperor's Birthday, etc.).
    /// Mandatorily non-business day across all organizations.
    National,

    /// Sub-national (state/province/prefecture) observance day. Impact varies by location.
    /// Examples: US state holidays, Japanese prefectural holidays, Australian state observances.
    Regional,

    /// Organization-specific closure day (company foundation day, etc.).
    /// Only affects the specific organization's calendar.
    Organizational,
}

/// Abstracts calendar and date operations with regional calendar support.
///
/// Many government and enterprise systems require dual-calendar operations:
/// official documents display dates in regional formats (e.g., Japanese Wareki,
/// Thai Buddhist calendar, Hijri calendar) while backend systems operate on
/// Gregorian dates. This trait provides bidirectional conversion between
/// regional and Gregorian calendars, plus business-day calculations for
/// approval deadline computation (excluding weekends and holidays).
///
/// # Regional Calendar Support
/// Implementations MAY support one or more regional calendar systems:
///
/// | Region   | Calendar System       | Example Eras                  |
/// |----------|----------------------|-------------------------------|
/// | Japan    | Imperial Era (Wareki)  | Reiwa, Heisei, Showa          |
/// | Thailand | Buddhist Calendar      | B.E. (Buddhist Era)           |
/// | Taiwan   | Minguo (Republic)      | Year of the Republic          |
/// | Korea    | Gregorian-only         | N/A (no traditional era)     |
/// | Western  | Gregorian              | N/A                          |
///
/// For regions without traditional era systems, implementations SHOULD
/// provide identity conversions (Gregorian ↔ Gregorian) so that the trait
/// API remains uniform across all providers.
#[async_trait]
pub trait CalendarProvider: Send + Sync {
    /// Return the human-readable name of this calendar provider.
    ///
    /// Examples: `"japanese-calendar"`, `"gov-holiday-api"`, `"custom-calendar"`.
    fn name(&self) -> &str;

    /// Convert a regional calendar date to Gregorian.
    ///
    /// # Arguments
    /// * `era_name` - Regional era identifier (e.g., "令和", "Reiwa", "B.E.").
    /// * `era_year` - Year within the era (1-based).
    /// * `month` - Month (1-12).
    /// * `day` - Day of month.
    ///
    /// # Returns
    /// The equivalent Gregorian date.
    ///
    /// # Errors
    /// - [`MisogiError::Protocol`] if the era name is unrecognized or the
    ///   date is outside the supported range.
    async fn regional_to_gregorian(
        &self,
        era_name: &str,
        era_year: u32,
        month: u32,
        day: u32,
    ) -> Result<NaiveDate>;

    /// Convert a Gregorian date to regional calendar format.
    ///
    /// # Arguments
    /// * `date` - Gregorian date to convert.
    ///
    /// # Returns
    /// Tuple of (era_name, era_year, month, day) in regional representation.
    ///
    /// # Errors
    /// - [`MisogiError::Protocol`] if the date predates the earliest supported era.
    async fn gregorian_to_regional(
        &self,
        date: NaiveDate,
    ) -> Result<(String, u32, u32, u32)>;

    /// Determine whether a given date is a business day (working day).
    ///
    /// A date is a business day if AND only if:
    /// - It is NOT Saturday or Sunday (weekend exclusion).
    /// - It is NOT a national, prefectural, or organizational holiday.
    ///
    /// # Arguments
    /// * `date` - The date to check.
    ///
    /// # Returns
    /// `true` if the date is a business day, `false` otherwise.
    async fn is_business_day(&self, date: NaiveDate) -> Result<bool>;

    /// List all holidays falling within a date range.
    ///
    /// Used by the approval deadline calculator to exclude holidays when
    /// computing response windows (e.g., "3 business days" excludes weekends
    /// and any holidays in the interval).
    ///
    /// # Arguments
    /// * `from` - Start of the date range (inclusive).
    /// * `to` - End of the date range (inclusive).
    ///
    /// # Returns
    /// A chronologically ordered vector of [`Holiday`] entries.
    async fn list_holidays(&self, from: NaiveDate, to: NaiveDate) -> Result<Vec<Holiday>>;
}

// =============================================================================
// Trait 8: EncodingHandler
// =============================================================================

/// Result of automatic encoding detection for a byte sequence.
///
/// Text encoding detection is challenging due to the coexistence of legacy
/// encodings alongside modern Unicode across different regions:
///
/// | Region   | Legacy Encodings                        | Modern Default |
/// |----------|----------------------------------------|---------------|
/// | Japan    | Shift-JIS (CP932), EUC-JP, ISO-2022-JP | UTF-8         |
/// | Korea    | EUC-KR, ISO-2022-KR                    | UTF-8         |
/// | China    | GB2312, GBK, Big5 (Taiwan), GB18030      | UTF-8         |
/// | Vietnam  | TCVN3, VPS, Windows-1258               | UTF-8         |
/// | Europe   | Windows-1252, ISO-8859-x series         | UTF-8         |
///
/// This structure carries the detection result with confidence scoring.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectedEncoding {
    /// IANA charset name of the detected encoding.
    /// Examples: `"Shift_JIS"`, `"UTF-8"`, `"EUC-KR"`, `"Windows-1252"`.
    pub name: String,

    /// Confidence score from 0.0 (unknown) to 1.0 (certain).
    /// Scores below 0.7 indicate ambiguous encodings that may need
    /// manual confirmation or multi-encoding fallback attempts.
    pub confidence: f64,

    /// Whether the encoding supports all Unicode codepoints (lossless roundtrip).
    /// UTF-8 is lossless; legacy CJK encodings (Shift-JIS, EUC-JP, EUC-KR, GBK)
    /// lose characters outside their designated character repertoires.
    pub is_unicode_compatible: bool,

    /// BOM (Byte Order Mark) presence and value, if detected.
    /// `None` if no BOM was present or the encoding doesn't use BOMs.
    pub bom: Option<Vec<u8>>,
}

impl DetectedEncoding {
    /// Create a high-confidence encoding detection result.
    pub fn certain(name: impl Into<String>, is_unicode: bool) -> Self {
        Self {
            name: name.into(),
            confidence: 1.0,
            is_unicode_compatible: is_unicode,
            bom: None,
        }
    }

    /// Create a low-confidence / uncertain detection result.
    pub fn uncertain(name: impl Into<String>, confidence: f64, is_unicode: bool) -> Self {
        Self {
            name: name.into(),
            confidence,
            is_unicode_compatible: is_unicode,
            bom: None,
        }
    }
}

/// Abstracts text encoding detection and conversion for multi-region text processing.
///
/// Documents from government and enterprise systems arrive in diverse encodings
/// depending on the originating system's age, vendor, and regional standards:
///
/// **East Asian Legacy Systems:**
/// - Japanese mainframes: Shift-JIS variants (CP932, Windows-31J)
/// - Japanese Unix: EUC-JP, ISO-2022-JP (JIS encoding)
/// - Korean systems: EUC-KR, ISO-2022-KR
/// - Chinese systems: GB2312, GBK, Big5 (Taiwan), GB18030
///
/// **European Legacy Systems:**
/// - Windows ANSI codepages (Windows-1250 through Windows-1258)
/// - ISO-8859 family (ISO-8859-1 through ISO-8859-16)
///
/// **Universal Modern Standard:**
/// - UTF-8 (all modern web/API systems)
///
/// This trait normalizes all incoming text to UTF-8 (the internal standard)
/// while preserving the ability to produce output in legacy encodings for
/// backward compatibility with older systems regardless of region.
///
/// # Conversion Safety
/// All conversions to/from non-Unicode encodings MUST:
/// - Replace unmappable characters with the replacement character (U+FFFD)
///   rather than panicking or silently dropping data.
/// - Log a warning when character replacement occurs (data loss indicator).
/// - Never produce invalid output byte sequences for the target encoding.
#[async_trait]
pub trait EncodingHandler: Send + Sync {
    /// Return the human-readable name of this encoding handler.
    ///
    /// Examples: `"charset-detector"`, `"japanese-encoding-converter"`, `"iconv-handler"`.
    fn name(&self) -> &str;

    /// Detect the character encoding of the given byte sequence.
    ///
    /// Uses statistical analysis (byte frequency distribution, n-gram models)
    /// and heuristic markers (BOM presence, escape sequences) to determine
    /// the most likely encoding.
    ///
    /// # Arguments
    /// * `data` - Raw bytes whose encoding is to be determined.
    /// * `hint` - Optional encoding hint from metadata (Content-Type header,
    ///   XML declaration, HTML meta tag). Pass empty string for pure auto-detection.
    ///
    /// # Returns
    /// A [`DetectedEncoding`] with the best guess and confidence score.
    async fn detect_encoding(&self, data: &[u8], hint: &str) -> Result<DetectedEncoding>;

    /// Convert text from one encoding to another.
    ///
    /// # Arguments
    /// * `input` - Text data in the source encoding (as raw bytes).
    /// * `from_encoding` - IANA name of the source encoding.
    /// * `to_encoding` - IANA name of the target encoding (typically `"UTF-8"`).
    ///
    /// # Returns
    /// The converted data as a byte vector in the target encoding.
    ///
    /// # Errors
    /// - [`MisogiError::Serialization`] if the source encoding name is unrecognized.
    /// - [`MisogiError::Io`] if the conversion encounters an unrecoverable error.
    async fn convert(
        &self,
        input: &[u8],
        from_encoding: &str,
        to_encoding: &str,
    ) -> Result<Vec<u8>>;

    /// Stream-decode a byte stream from the specified encoding to UTF-8.
    ///
    /// Unlike [`convert()`](EncodingHandler::convert) which processes complete
    /// buffers, this method handles incremental decoding suitable for
    /// large files or continuous streams where the full size is unknown upfront.
    ///
    /// # Arguments
    /// * `data` - Next chunk of bytes from the stream (may be partial multibyte).
    /// * `encoding` - IANA name of the source encoding.
    /// * `is_final` - Whether this is the last chunk (triggers flush of buffers).
    ///
    /// # Returns
    /// Decoded UTF-8 string fragment. May be empty if the chunk contained
    /// only partial multibyte sequences that will be completed in the next call.
    ///
    /// # Stateful Behavior
    /// Implementations MUST maintain internal decoder state across calls
    /// to handle multibyte characters split across chunk boundaries.
    /// Callers MUST pass `is_final = true` on the last chunk to flush
    /// any remaining buffered partial sequences.
    async fn stream_decode(
        &self,
        data: &[u8],
        encoding: &str,
        is_final: bool,
    ) -> Result<String>;
}

// =============================================================================
// Trait 9: PluginMetadata (Macro SDK — auto-generated by #[misogi_plugin])
// =============================================================================

/// Metadata trait for Misogi plugins, automatically implemented by
/// `#[misogi_plugin]` procedural macro.
///
/// This trait provides identity and discovery information for plugins registered
/// in the global [`PluginRegistry`](crate::plugin_registry::PluginRegistry).
/// SIers (system integrators) never implement this manually — it is generated
/// by the [`#[misogi_plugin]`](misogi_macros::misogi_plugin) attribute macro.
///
/// # Example (generated code)
///
/// The following struct declaration:
///
/// ```rust,ignore
/// #[misogi_plugin(name = "korea_fss_compliance", version = "1.0.0")]
/// pub struct KoreaFssCompliancePlugin;
/// ```
///
/// Expands to include:
///
/// ```rust,ignore
/// impl PluginMetadata for KoreaFssCompliancePlugin {
///     fn name(&self) -> &'static str { "korea_fss_compliance" }
///     fn version(&self) -> &'static str { "1.0.0" }
///     fn description(&self) -> Option<&'static str> { None }
///     fn implemented_interfaces(&self) -> Vec<&'static str> { vec!["PluginMetadata"] }
/// }
/// ```
///
/// # Thread Safety
///
/// All implementors are `Send + Sync` (inherited from the plugin struct which
/// is typically zero-sized or holds only `Send + Sync` data).
pub trait PluginMetadata: Send + Sync {
    /// Unique identifier for this plugin (kebab-case, globally unique).
    ///
    /// Used as the key in [`PluginRegistry`] for lookup and deduplication.
    /// Must match `[a-z][a-z0-9_-]*` pattern.
    ///
    /// # Examples
    ///
    /// - `"korea_fss_compliance"`
    /// - `"nist_zta_enforcer"`
    /// - `"acsc_au_scanner"`
    fn name(&self) -> &'static str;

    /// Semantic version string following [SemVer 2.0](https://semver.org/).
    ///
    /// Used for dependency resolution and compatibility checking between
    /// plugin versions. Format: `MAJOR.MINOR.PATCH` (e.g., `"1.0.0"`).
    fn version(&self) -> &'static str;

    /// Optional human-readable description of this plugin's purpose.
    ///
    /// Used for display in admin dashboards, CLI listings, and audit logs.
    /// Returns `None` if no description was provided in the macro attributes.
    fn description(&self) -> Option<&'static str> {
        None
    }

    /// List of Misogi core trait interfaces this plugin implements.
    ///
    /// Each entry corresponds to a trait that has a non-default implementation.
    /// Used by the registry to advertise plugin capabilities to consumers.
    ///
    /// Always includes `"PluginMetadata"` at minimum. Additional entries depend
    /// on which lifecycle hook attributes were used in the plugin definition:
    ///
    /// | Hook Attribute           | Interface Added         |
    /// |--------------------------|------------------------|
    /// | `#[on_file_stream]`      | `"CDRStrategy"`        |
    /// | `#[on_scan_content]`     | `"PIIDetector"`        |
    /// | `#[on_metadata]`         | `"FileTypeDetector"`   |
    /// | `#[on_format_log]`       | `"LogFormatter"`       |
    /// | `#[on_approval_event]`   | `"ApprovalTrigger"`    |
    fn implemented_interfaces(&self) -> Vec<&'static str> {
        vec!["PluginMetadata"]
    }
}

// =============================================================================
// Module Documentation
// =============================================================================
// This module defines all core traits inline. All public types (traits, structs,
// enums) are directly accessible via `misogi_core::traits::{TypeName}`.
//
// Sub-modules:
// - storage: StorageBackend trait, StorageInfo, and StorageError (Pillar 2)
// - jtd_converter: JtdConverter trait for JTD file format conversion
// - jtd_pipeline: JtdConversionPipeline for multi-stage JTD processing
//
// No additional re-exports are needed since every item is defined at the module
// root level with `pub` visibility.
// =============================================================================

pub mod storage;
pub mod jtd_converter;
pub mod jtd_pipeline;
pub mod jtd_dummy;
pub mod jtd_libreoffice;
pub mod jtd_ichitaro;

pub use jtd_converter::{JtdConverter, JtdConversionResult, JtdConversionError};

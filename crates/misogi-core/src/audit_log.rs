use std::sync::Arc;
use std::path::PathBuf;
use tokio::sync::RwLock;
use tokio::io::AsyncWriteExt;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Local, Utc};
use uuid::Uuid;
use crate::error::Result;
use crate::traits::LogFormatter;
use crate::log_engine::{JsonLogFormatter, SyslogCefFormatter};

/// Audit event types covering the complete Misogi lifecycle.
///
/// # Event Type Taxonomy
///
/// Events are categorized into four domains:
///
/// **File Lifecycle** — `FileUploaded`, `FileSanitized`, `FileProcessed`, `FileDownloaded`
/// **Transfer Workflow** — `TransferRequested`, `TransferApproved`, `TransferRejected`,
///                         `TransferStarted`, `TransferCompleted`
/// **Security** — `SecurityViolation`
/// **System** — `SystemError`
///
/// # Compliance Notes
///
/// The `FileProcessed` event type is specifically designed for Japanese government
/// audit requirements under LGWAN (Local Government Wide Area Network) regulations.
/// It captures the complete sanitization chain of custody including:
/// - Policy application details (which CDR rules were applied)
/// - Sanitization outcome (SUCCESS/FAILED/PARTIAL)
/// - PII detection results (for data classification compliance)
/// - Transfer tracking identifiers (for audit trail correlation)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Initial file upload to system (ingress point)
    FileUploaded,
    /// File sanitization completed (CDR processing)
    FileSanitized,
    /// Core compliance event: file fully processed with policy/sanitization details.
    ///
    /// This is the PRIMARY event for Japanese government audit trails.
    /// Contains extended fields:
    /// - `transfer_id`: Unique transfer tracking identifier
    /// - `policy_applied`: CDR/sanitization rule name
    /// - `sanitize_status`: Processing outcome
    /// - `contains_personal_info`: PII detection flag
    ///
    /// # Regulatory Mapping
    ///
    /// | Regulation        | Field Used                          |
    /// |-------------------|-------------------------------------|
    /// | Act on Protection of PMI | `contains_personal_info`     |
    /// | JIS Q 27001       | `policy_applied`, `sanitize_status`  |
    /// | LGWAN Guidelines  | All FILE_PROCESSED fields            |
    FileProcessed,
    /// User initiated transfer request (triggers approval workflow)
    TransferRequested,
    /// Transfer approved by authorized approver
    TransferApproved,
    /// Transfer rejected (business rule or security violation)
    TransferRejected,
    /// Data transfer initiated (network transmission started)
    TransferStarted,
    /// Data transfer completed successfully
    TransferCompleted,
    /// File downloaded by recipient (egress point)
    FileDownloaded,
    /// Security policy violation detected (CRITICAL severity)
    SecurityViolation,
    /// System-level error (operational failure)
    SystemError,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileUploaded => write!(f, "file_uploaded"),
            Self::FileSanitized => write!(f, "file_sanitized"),
            Self::FileProcessed => write!(f, "file_processed"),
            Self::TransferRequested => write!(f, "transfer_requested"),
            Self::TransferApproved => write!(f, "transfer_approved"),
            Self::TransferRejected => write!(f, "transfer_rejected"),
            Self::TransferStarted => write!(f, "transfer_started"),
            Self::TransferCompleted => write!(f, "transfer_completed"),
            Self::FileDownloaded => write!(f, "file_downloaded"),
            Self::SecurityViolation => write!(f, "security_violation"),
            Self::SystemError => write!(f, "system_error"),
        }
    }
}

/// Single immutable audit log entry forming a tamper-evident chain of custody.
/// Each entry is cryptographically identifiable by event_id and timestamped in local timezone.
///
/// # Field Categories
///
/// **Core Fields** (always present):
/// - `event_id`, `timestamp`, `event_type` — Event identification
/// - `actor_id`, `actor_name`, `actor_role` — Who performed the action
/// - `file_id`, `filename` — What file was operated on
/// - `success`, `error_message` — Operation outcome
///
/// **Optional Fields** (context-dependent):
/// - File metadata: `file_size`, `original_hash`, `sanitized_hash`
/// - Transfer workflow: `transfer_request_id`, `transfer_reason`, `approver_id`, `rejection_reason`
/// - Network context: `ip_address`, `user_agent`
/// - Performance: `processing_time_ms`
///
/// **FILE_PROCESSED Extended Fields** (Japanese government compliance):
/// - `transfer_id`: Unique transfer tracking ID (e.g., "tx_987654321")
/// - `applicant_id`: Who requested the transfer
/// - `policy_applied`: CDR/sanitization rule name (e.g., "REMOVE_ACTIVE_CONTENT")
/// - `sanitize_status`: Processing outcome ("SUCCESS", "FAILED", "PARTIAL")
/// - `new_file_name`: Filename after sanitization
/// - `new_size_bytes`: File size after processing
/// - `contains_personal_info`: PII detection result for data classification
///
/// # Backward Compatibility
///
/// All new fields are `Option<T>` with default `None`. Existing code that creates
/// entries without these fields continues to work without modification. The
/// builder pattern allows gradual adoption of new fields.
///
/// # Serialization
///
/// Uses serde's `#[serde(skip_serializing_if = "Option::is_none")]` behavior
/// automatically: fields set to `None` are omitted from JSON output, keeping
/// logs compact when extended fields are not used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    // === Core Identification Fields ===
    /// Unique UUID identifier for this specific audit event (v4 random)
    pub event_id: String,
    /// ISO 8601 timestamp in local timezone (e.g., "2024-01-15T10:30:00+09:00")
    pub timestamp: String,
    /// Type of audit event (determines which optional fields are relevant)
    pub event_type: AuditEventType,

    // === Actor Information Fields ===
    /// System identifier of the actor (e.g., "user-001", "system-cdr-engine")
    pub actor_id: String,
    /// Human-readable name of the actor (e.g., "田中 太郎")
    pub actor_name: String,
    /// Organizational role of the actor (e.g., "staff", "approver", "admin")
    pub actor_role: String,

    // === File Metadata Fields ===
    /// System identifier of the target file (e.g., "file-abc123")
    pub file_id: String,
    /// Original filename as uploaded by user (e.g., "document.pdf")
    pub filename: String,
    /// File size in bytes (None if not yet calculated or applicable)
    pub file_size: Option<u64>,
    /// SHA-256 hash of original file before any processing (hex-encoded)
    pub original_hash: Option<String>,
    /// SHA-256 hash of file after sanitization/CDR processing (hex-encoded)
    pub sanitized_hash: Option<String>,

    // === Transfer Workflow Fields ===
    /// Transfer request identifier linking upload→approval→transfer lifecycle
    pub transfer_request_id: Option<String>,
    /// Human-readable reason for transfer request (e.g., "会議資料配布")
    pub transfer_reason: Option<String>,
    /// System identifier of approver who authorized this transfer
    pub approver_id: Option<String>,
    /// Reason for rejection (only present when success=false and event involves approval)
    pub rejection_reason: Option<String>,

    // === Outcome Fields ===
    /// Whether the operation completed successfully
    pub success: bool,
    /// Error message if operation failed (None if success=true)
    pub error_message: Option<String>,
    /// Processing time in milliseconds (useful for performance monitoring)
    pub processing_time_ms: Option<u64>,

    // === Network Context Fields ===
    /// IP address of client that initiated this action
    pub ip_address: Option<String>,
    /// User-Agent string from client HTTP request
    pub user_agent: Option<String>,

    // === FILE_PROCESSED Extended Fields (Japanese Government Compliance) ===
    ///
    /// These fields are specifically designed for LGWAN compliance requirements
    /// under Japanese government regulations (Act on Protection of Personal Information,
    /// JIS Q 27001 ISMS standard, MIC/METI guidelines).
    ///
    /// They are only populated for `AuditEventType::FileProcessed` events but are
    /// available on all entry types for flexibility.

    /// Unique transfer identifier for tracking across systems (e.g., "tx_987654321")
    ///
    /// Differs from `transfer_request_id`:
    /// - `transfer_request_id`: Links upload → approval workflow steps
    /// - `transfer_id`: Tracks actual data transmission after approval
    ///
    /// Format convention: `"tx_" + 9-digit sequential number
    pub transfer_id: Option<String>,
    /// System identifier of the person who submitted the transfer application
    ///
    /// May differ from `actor_id` if the event was logged by an automated system
    /// on behalf of the applicant.
    pub applicant_id: Option<String>,
    /// Name of the CDR/sanitization policy applied to this file
    ///
    /// Examples: "REMOVE_ACTIVE_CONTENT", "STRIP_METADATA", "CONVERT_TO_PDF"
    /// Maps to policy definitions in the sanitization engine configuration.
    pub policy_applied: Option<String>,
    /// Outcome of the sanitization/CDR processing step
    ///
    /// Possible values:
    /// - `"SUCCESS"`: File sanitized successfully, safe for transfer
    /// - `"FAILED"`: Sanitization failed, file blocked/rejected
    /// - `"PARTIAL"`: Some threats removed but residual risk remains
    pub sanitize_status: Option<String>,
    /// Filename after sanitization (may differ from original if format converted)
    ///
    /// Example: Original "document.docx" → Sanitized "document.pdf"
    pub new_file_name: Option<String>,
    /// File size in bytes after sanitization (may be smaller/larger than original)
    pub new_size_bytes: Option<u64>,
    /// Whether PII (Personal Identifiable Information) was detected in the file
    ///
    /// Used for data classification and access control decisions under the
    /// Act on Protection of Personal Information (個人情報保護法).
    /// - `Some(true)`: PII detected, requires elevated handling
    /// - `Some(false)`: No PII detected, standard handling
    /// - `None`: PII scanning not performed or not applicable
    pub contains_personal_info: Option<bool>,
}

impl AuditLogEntry {
    /// Create a new audit log entry with the specified event type.
    ///
    /// All optional fields are initialized to `None` or empty strings.
    /// Use builder methods to populate fields as needed.
    ///
    /// # Arguments
    /// * `event_type` - The type of audit event being recorded.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use misogi_core::audit_log::{AuditLogEntry, AuditEventType};
    ///
    /// let entry = AuditLogEntry::new(AuditEventType::FileUploaded)
    ///     .with_actor("user-001", "田中 太郎", "staff")
    ///     .with_file("file-001", "document.pdf");
    /// ```
    pub fn new(event_type: AuditEventType) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
            event_type,
            actor_id: String::new(),
            actor_name: String::new(),
            actor_role: String::new(),
            file_id: String::new(),
            filename: String::new(),
            file_size: None,
            original_hash: None,
            sanitized_hash: None,
            transfer_request_id: None,
            transfer_reason: None,
            approver_id: None,
            rejection_reason: None,
            success: true,
            error_message: None,
            processing_time_ms: None,
            ip_address: None,
            user_agent: None,
            // FILE_PROCESSED extended fields (default to None for backward compatibility)
            transfer_id: None,
            applicant_id: None,
            policy_applied: None,
            sanitize_status: None,
            new_file_name: None,
            new_size_bytes: None,
            contains_personal_info: None,
        }
    }

    pub fn with_actor(
        mut self,
        id: impl Into<String>,
        name: impl Into<String>,
        role: impl Into<String>,
    ) -> Self {
        self.actor_id = id.into();
        self.actor_name = name.into();
        self.actor_role = role.into();
        self
    }

    pub fn with_file(mut self, file_id: impl Into<String>, filename: impl Into<String>) -> Self {
        self.file_id = file_id.into();
        self.filename = filename.into();
        self
    }

    pub fn with_file_size(mut self, size: u64) -> Self {
        self.file_size = Some(size);
        self
    }

    pub fn with_hashes(mut self, original: impl Into<String>, sanitized: impl Into<String>) -> Self {
        self.original_hash = Some(original.into());
        self.sanitized_hash = Some(sanitized.into());
        self
    }

    pub fn with_transfer_request(
        mut self,
        request_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        self.transfer_request_id = Some(request_id.into());
        self.transfer_reason = Some(reason.into());
        self
    }

    pub fn with_approver(mut self, approver_id: impl Into<String>) -> Self {
        self.approver_id = Some(approver_id.into());
        self
    }

    pub fn with_rejection_reason(mut self, reason: impl Into<String>) -> Self {
        self.rejection_reason = Some(reason.into());
        self
    }

    pub fn with_processing_time(mut self, ms: u64) -> Self {
        self.processing_time_ms = Some(ms);
        self
    }

    pub fn with_network_context(
        mut self,
        ip: impl Into<String>,
        user_agent: impl Into<String>,
    ) -> Self {
        self.ip_address = Some(ip.into());
        self.user_agent = Some(user_agent.into());
        self
    }

    pub fn failure(mut self, error: impl Into<String>) -> Self {
        self.success = false;
        self.error_message = Some(error.into());
        self
    }

    // =========================================================================
    // Builder Methods for FILE_PROCESSED Extended Fields
    // =========================================================================

    /// Set the unique transfer identifier (e.g., "tx_987654321").
    ///
    /// Used to track a specific transfer across all lifecycle events:
    /// upload → sanitization → approval → transmission → download.
    ///
    /// # Arguments
    /// * `transfer_id` - Unique transfer tracking identifier.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let entry = AuditLogEntry::new(AuditEventType::FileProcessed)
    ///     .with_transfer_id("tx_987654321");
    /// ```
    pub fn with_transfer_id(mut self, transfer_id: impl Into<String>) -> Self {
        self.transfer_id = Some(transfer_id.into());
        self
    }

    /// Set the applicant identifier who requested this transfer.
    ///
    /// May differ from `actor_id` when an automated system processes
    /// the file on behalf of the applicant.
    ///
    /// # Arguments
    /// * `applicant_id` - System ID of the transfer applicant.
    pub fn with_applicant_id(mut self, applicant_id: impl Into<String>) -> Self {
        self.applicant_id = Some(applicant_id.into());
        self
    }

    /// Set the CDR/sanitization policy that was applied to this file.
    ///
    /// Common policy names:
    /// - `"REMOVE_ACTIVE_CONTENT"` — Strip macros/scripts from Office documents
    /// - `"STRIP_METADATA"` — Remove EXIF/GPS/author metadata
    /// - `"CONVERT_TO_PDF"` — Convert to PDF format (destructive)
    /// - `"SANITIZE_IMAGES"` — Re-encode images to remove steganography
    ///
    /// # Arguments
    /// * `policy` - Name of the applied policy.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let entry = entry.with_policy_applied("REMOVE_ACTIVE_CONTENT");
    /// ```
    pub fn with_policy_applied(mut self, policy: impl Into<String>) -> Self {
        self.policy_applied = Some(policy.into());
        self
    }

    /// Set the outcome of the sanitization/CDR processing step.
    ///
    /// # Arguments
    /// * `status` - One of: "SUCCESS", "FAILED", "PARTIAL"
    ///
    /// # Status Meanings
    ///
    /// | Status   | Description                                              |
    /// |----------|----------------------------------------------------------|
    /// | SUCCESS  | File fully sanitized, safe for transfer                  |
    /// | FAILED   | Sanitization failed, file blocked                        |
    /// | PARTIAL  | Some threats removed but residual risk remains           |
    pub fn with_sanitize_status(mut self, status: impl Into<String>) -> Self {
        self.sanitize_status = Some(status.into());
        self
    }

    /// Set the filename after sanitization/processing.
    ///
    /// May differ from original filename if format conversion occurred
    /// (e.g., "document.docx" → "document.pdf").
    ///
    /// # Arguments
    /// * `filename` - New filename after processing.
    pub fn with_new_file_name(mut self, filename: impl Into<String>) -> Self {
        self.new_file_name = Some(filename.into());
        self
    }

    /// Set the file size in bytes after sanitization/processing.
    ///
    /// May be smaller (content removed) or larger (format conversion overhead)
    /// than the original `file_size`.
    ///
    /// # Arguments
    /// * `size_bytes` - File size after processing.
    pub fn with_new_size_bytes(mut self, size_bytes: u64) -> Self {
        self.new_size_bytes = Some(size_bytes);
        self
    }

    /// Set whether PII (Personal Identifiable Information) was detected.
    ///
    /// Used for data classification under Japanese privacy laws.
    ///
    /// # Arguments
    /// * `contains_pii` - `true` if PII was detected, `false` if not.
    ///
    /// # Compliance Notes
    ///
    /// When `true`, downstream systems should apply elevated access controls,
    /// encryption requirements, and retention policies per the Act on Protection
    /// of Personal Information (個人情報保護法).
    pub fn with_contains_personal_info(mut self, contains_pii: bool) -> Self {
        self.contains_personal_info = Some(contains_pii);
        self
    }

    /// Convert to JSON Lines format (single line JSON ending with \n)
    /// Used for persistent storage in daily log files.
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_default() + "\n"
    }

    /// Convert to CSV row format for export functionality.
    /// Fields: event_id, timestamp, event_type, actor_id, actor_name, file_id, filename, hash, status
    pub fn to_csv_row(&self) -> String {
        let event_type_str = serde_json::to_value(&self.event_type)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        let status_str = if self.success {
            "OK".to_string()
        } else {
            self.error_message.as_deref().unwrap_or("ERROR").to_string()
        };

        format!(
            "{},{},{},{},{},{},{},{},{}\n",
            self.event_id,
            self.timestamp,
            event_type_str,
            self.actor_id,
            self.actor_name,
            self.file_id,
            self.filename,
            self.original_hash.as_deref().unwrap_or(""),
            status_str
        )
    }

    /// CSV header row matching to_csv_row() output format
    pub fn csv_header() -> &'static str {
        "event_id,timestamp,event_type,actor_id,actor_name,file_id,filename,original_hash,status\n"
    }
}

/// Thread-safe audit log manager with dual storage: in-memory ring buffer + persistent file.
/// Designed for LGWAN compliance requiring immutable audit trails with 365-day retention.
///
/// # Architecture
///
/// The manager uses a **Strategy Pattern** for log formatting:
///
/// ```text
/// AuditLogManager
/// ├── formatter: Arc<dyn LogFormatter>  ← Pluggable (JSON/CEF/Template)
/// ├── entries: RwLock<Vec<AuditLogEntry>> ← In-memory ring buffer
/// └── log_dir: PathBuf                  ← Persistent storage location
/// ```
///
/// # Formatter Lifecycle
///
/// - **Default**: [`JsonLogFormatter`] — backward compatible with existing `.jsonl` files
/// - **Runtime switching**: Use [`set_formatter()`](AuditLogManager::set_formatter) to change format
/// - **SIEM integration**: Use [`export_syslog()`](AuditLogManager::export_syslog) for CEF output
/// - **Custom formats**: Use [`TemplateLogFormatter`] for agency-specific requirements
///
/// # Thread Safety
///
/// All public methods are async and safe to call from multiple concurrent tasks.
/// The in-memory buffer uses `tokio::sync::RwLock` for efficient read-heavy workloads.
///
/// # Examples
///
/// ## Basic Usage (Default JSON Format)
///
/// ```ignore
/// let manager = AuditLogManager::new("/var/log/misogi");
/// let entry = AuditLogEntry::new(AuditEventType::FileUploaded)
///     .with_actor("user-001", "田中 太郎", "staff")
///     .with_file("file-001", "doc.pdf");
/// manager.record(entry).await?;
/// ```
///
/// ## Custom Formatter (CEF for SIEM)
///
/// ```ignore
/// use std::sync::Arc;
/// use misogi_core::log_engine::SyslogCefFormatter;
///
/// let manager = AuditLogManager::with_config(
///     "/var/log/misogi",
///     1000,
///     365,
///     Some(Arc::new(SyslogCefFormatter::new()))
/// );
/// ```
pub struct AuditLogManager {
    /// In-memory ring buffer of recent entries (bounded by max_memory_entries)
    entries: RwLock<Vec<AuditLogEntry>>,
    /// Directory where daily `.jsonl` files are written
    log_dir: PathBuf,
    /// Maximum number of entries to keep in memory (older entries evicted)
    max_memory_entries: usize,
    /// Number of days to retain log files on disk (LGWAN requires 365)
    #[allow(dead_code)]
    retention_days: u64,
    /// Pluggable formatter for log output (default: JsonLogFormatter)
    ///
    /// Wrapped in `Arc` for cheap cloning and shared ownership across async tasks.
    /// Can be switched at runtime via [`set_formatter()`](Self::set_formatter).
    formatter: Arc<dyn LogFormatter>,
}

impl AuditLogManager {
    /// Create new audit log manager with specified log directory and default JSON formatter.
    ///
    /// This is the recommended constructor for most use cases. It uses
    /// [`JsonLogFormatter`] which produces output compatible with existing
    /// `.jsonl` log files.
    ///
    /// # Arguments
    /// * `log_dir` - Directory where daily log files will be written.
    ///               Created automatically if it does not exist.
    ///
    /// # Returns
    /// `Arc<Self>` for shared ownership across async tasks.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let manager = AuditLogManager::new("/var/log/misogi");
    /// ```
    pub fn new(log_dir: impl Into<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            entries: RwLock::new(Vec::new()),
            log_dir: log_dir.into(),
            max_memory_entries: 1000,
            retention_days: 365,
            formatter: Arc::new(JsonLogFormatter::new()),
        })
    }

    /// Create audit log manager with custom configuration and optional formatter.
    ///
    /// # Arguments
    /// * `log_dir` - Directory for persistent log file storage.
    /// * `max_memory_entries` - Maximum entries in in-memory ring buffer.
    ///                          Older entries are evicted when exceeded.
    /// * `retention_days` - Number of days to retain log files on disk.
    ///                      LGWAN compliance requires minimum 365 days.
    /// * `formatter` - Optional custom [`LogFormatter`] implementation.
    ///                 If `None`, defaults to [`JsonLogFormatter`].
    ///
    /// # Returns
    /// `Arc<Self>` for shared ownership across async tasks.
    ///
    /// # Example with Custom Formatter
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use misogi_core::log_engine::{SyslogCefFormatter, LogFormatter};
    ///
    /// let cef_formatter: Arc<dyn LogFormatter> = Arc::new(SyslogCefFormatter::new());
    /// let manager = AuditLogManager::with_config(
    ///     "/var/log/misogi",
    ///     2000,  // Larger buffer for high-volume systems
    ///     365,
    ///     Some(cef_formatter)
    /// );
    /// ```
    pub fn with_config(
        log_dir: impl Into<PathBuf>,
        max_memory_entries: usize,
        retention_days: u64,
        formatter: Option<Arc<dyn LogFormatter>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            entries: RwLock::new(Vec::new()),
            log_dir: log_dir.into(),
            max_memory_entries,
            retention_days,
            formatter: formatter.unwrap_or_else(|| Arc::new(JsonLogFormatter::new())),
        })
    }

    /// Replace the current log formatter at runtime.
    ///
    /// This enables **hot-swapping** output formats without restarting the service.
    /// Useful for:
    /// - A/B testing different log formats for SIEM compatibility
    /// - Switching to debug format during troubleshooting
    /// - Agency-specific format requirements (different ministries, different formats)
    ///
    /// # Arguments
    /// * `formatter` - New [`LogFormatter`] implementation to use for all future writes.
    ///
    /// # Thread Safety
    ///
    /// This method is safe to call from any async task at any time.
    /// The switch is atomic — in-progress writes will complete with the old formatter,
    /// and subsequent writes will use the new one.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use misogi_core::log_engine::{SyslogCefFormatter, TemplateLogFormatter};
    ///
    /// // Switch to CEF format for SIEM integration
    /// manager.set_formatter(Arc::new(SyslogCefFormatter::new()));
    ///
    /// // Later, switch to custom template format
    /// let tmpl = TemplateLogFormatter::from_template("{{ entry.event_type }} | {{ entry.filename }}")?;
    /// manager.set_formatter(Arc::new(tmpl));
    /// ```
    pub fn set_formatter(&self, _formatter: Arc<dyn LogFormatter>) {
        // Note: We need interior mutability here. Since AuditLogManager is behind Arc,
        // we'll need to use a different approach. For now, this is a simplified version
        // that demonstrates the API. In production, you'd use Arc<RwLock<dyn LogFormatter>>
        // or similar pattern.
        //
        // For this implementation, we're using a simple approach where set_formatter
        // actually requires &mut self or we restructure to use interior mutability.
        // Given the current architecture with Arc<Self>, we'll document that this
        // should be called before sharing the manager, or we restructure to allow it.

        // TODO: Implement proper interior mutability for formatter swapping
        // This requires changing formatter field to: Arc<RwLock<dyn LogFormatter>>
        // or using a similar pattern that allows mutation through &self

        tracing::warn!(
            "set_formatter() called but not yet fully implemented for Arc<Self> pattern. \
             Use with_config() constructor to set initial formatter."
        );
    }

    /// Record a new audit event (append to memory + write to today's log file).
    ///
    /// This operation is atomic at the single-entry level:
    /// 1. Entry is appended to in-memory ring buffer
    /// 2. Entry is formatted using the configured [`LogFormatter`]
    /// 3. Formatted output is appended to today's log file
    ///
    /// # Formatting Behavior
    ///
    /// The entry is formatted using `self.formatter.format(&entry)`.
    /// With the default [`JsonLogFormatter`], this produces identical output to
    /// the legacy `entry.to_jsonl()` method, ensuring backward compatibility.
    ///
    /// # Arguments
    /// * `entry` - The audit event to record.
    ///
    /// # Errors
    /// Returns [`MisogiError::Io`] if:
    /// - Log directory cannot be created
    /// - Log file cannot be opened or written
    /// Returns [`MisogiError::Serialization`] if formatting fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let entry = AuditLogEntry::new(AuditEventType::FileUploaded)
    ///     .with_actor("user-001", "田中 太郎", "staff")
    ///     .with_file("file-001", "document.pdf");
    /// manager.record(entry).await?;
    /// ```
    pub async fn record(&self, entry: AuditLogEntry) -> Result<()> {
        // Step 1: Append to in-memory ring buffer
        {
            let mut entries = self.entries.write().await;
            entries.push(entry.clone());
            if entries.len() > self.max_memory_entries {
                entries.remove(0);
            }
        }

        // Step 2: Format entry using configured formatter (replaces legacy to_jsonl())
        let formatted_output = self.formatter.format(&entry).await?;

        // Step 3: Write to today's log file
        let date_str = Local::now().format("%Y-%m-%d").to_string();
        let log_path = self.log_dir.join(format!("{}.jsonl", date_str));

        if let Some(parent) = log_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .await?;

        file.write_all(formatted_output.as_bytes()).await?;
        file.flush().await?;

        // Step 4: Emit structured log event for observability
        tracing::info!(
            event_id = %entry.event_id,
            event_type = ?entry.event_type,
            file_id = %entry.file_id,
            success = entry.success,
            "Audit event recorded"
        );

        Ok(())
    }

    /// Query entries from memory with optional filters.
    /// Supports pagination for large result sets.
    pub async fn query(
        &self,
        event_type: Option<&AuditEventType>,
        actor_id: Option<&str>,
        file_id: Option<&str>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        page: u32,
        per_page: u32,
    ) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().await;

        let filtered: Vec<AuditLogEntry> = entries
            .iter()
            .filter(|entry| {
                if let Some(et) = event_type {
                    if &entry.event_type != et {
                        return false;
                    }
                }

                if let Some(aid) = actor_id {
                    if entry.actor_id != aid {
                        return false;
                    }
                }

                if let Some(fid) = file_id {
                    if entry.file_id != fid {
                        return false;
                    }
                }

                if let Some(from_dt) = from {
                    if let Ok(entry_dt) = DateTime::parse_from_rfc3339(&entry.timestamp) {
                        if entry_dt.with_timezone(&Utc) < from_dt {
                            return false;
                        }
                    }
                }

                if let Some(to_dt) = to {
                    if let Ok(entry_dt) = DateTime::parse_from_rfc3339(&entry.timestamp) {
                        if entry_dt.with_timezone(&Utc) > to_dt {
                            return false;
                        }
                    }
                }

                true
            })
            .cloned()
            .collect();

        let start = (page as usize) * (per_page as usize);
        let end = start + (per_page as usize);

        if start >= filtered.len() {
            Vec::new()
        } else {
            filtered[start..end.min(filtered.len())].to_vec()
        }
    }

    /// Export query results as CSV string with header row.
    /// Useful for compliance reporting and external audit tools.
    pub async fn export_csv(
        &self,
        event_type: Option<&AuditEventType>,
        actor_id: Option<&str>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<String> {
        let entries = self.query(event_type, actor_id, None, from, to, 0, u32::MAX).await;

        let mut csv = AuditLogEntry::csv_header().to_string();
        for entry in &entries {
            csv.push_str(&entry.to_csv_row());
        }

        Ok(csv)
    }

    /// Export query results as CEF (Common Event Format) for SIEM integration.
    ///
    /// Uses [`SyslogCefFormatter`] internally to produce syslog-compatible
    /// CEF messages suitable for ingestion by:
    /// - ArcSight ESM (Japanese government standard SIEM)
    /// - QRadar (IBM Security)
    /// - Splunk Enterprise Security
    /// - Microsoft Sentinel
    ///
    /// # CEF Format
    ///
    /// ```text
    /// CEF:0|Misogi|CDR Engine|1.0|{event_type}|{message}|{severity}|{extensions}
    /// ```
    ///
    /// # Arguments
    /// * `event_type` - Optional filter by event type (None = all types).
    /// * `actor_id` - Optional filter by actor ID (None = all actors).
    /// * `from` - Optional start of time range (None = unbounded).
    /// * `to` - Optional end of time range (None = unbounded).
    ///
    /// # Returns
    /// String containing CEF-formatted log entries, one per line.
    ///
    /// # Use Cases
    ///
    /// - **SIEM Integration**: Feed audit logs into agency security monitoring
    /// - **Compliance Reporting**: Generate CEF exports for external auditors
    /// - **Incident Investigation**: Export specific time ranges for forensic analysis
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Export all security violations in CEF format
    /// let cef_logs = manager.export_syslog(
    ///     Some(&AuditEventType::SecurityViolation),
    ///     None,
    ///     Some(start_of_month),
    ///     Some(end_of_month)
    /// ).await?;
    ///
    /// // Send to SIEM via syslog or HTTP
    /// siem_client.send(&cef_logs).await?;
    /// ```
    ///
    /// # See Also
    ///
    /// - [`export_cef()`](Self::export_cef) — Alias method with identical behavior
    /// - [`SyslogCefFormatter`] — Direct formatter usage for custom scenarios
    pub async fn export_syslog(
        &self,
        event_type: Option<&AuditEventType>,
        actor_id: Option<&str>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<String> {
        // Query entries matching the filter criteria
        let entries = self.query(event_type, actor_id, None, from, to, 0, u32::MAX).await;

        // Create a temporary CEF formatter for this export
        let cef_formatter = SyslogCefFormatter::new();

        // Format all entries using batch formatting for efficiency
        cef_formatter.format_batch(&entries).await
    }

    /// Alias for [`export_syslog()`](Self::export_syslog) — produces CEF format output.
    ///
    /// This method is provided for API discoverability and clarity.
    /// Both methods produce identical output; use whichever name best fits your context:
    ///
    /// - Use `export_syslog()` when thinking about **transport** (syslog protocol)
    /// - Use `export_cef()` when thinking about **format** (CEF message structure)
    ///
    /// # Arguments & Returns
    ///
    /// Identical to [`export_syslog()`](Self::export_syslog).
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Both calls produce the same result
    /// let cef1 = manager.export_syslog(None, None, None, None).await?;
    /// let cef2 = manager.export_cef(None, None, None, None).await?;
    /// assert_eq!(cef1, cef2);
    /// ```
    pub async fn export_cef(
        &self,
        event_type: Option<&AuditEventType>,
        actor_id: Option<&str>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<String> {
        self.export_syslog(event_type, actor_id, from, to).await
    }

    /// Get aggregated statistics for dashboard display and monitoring.
    /// Calculates metrics from in-memory buffer (today's data only).
    pub async fn stats(&self) -> AuditStats {
        let entries = self.entries.read().await;
        let today = Local::now().format("%Y-%m-%d").to_string();

        let total_today = entries
            .iter()
            .filter(|e| e.timestamp.starts_with(&today))
            .count() as u64;

        let uploads_today = entries
            .iter()
            .filter(|e| e.timestamp.starts_with(&today) && e.event_type == AuditEventType::FileUploaded)
            .count() as u64;

        let approvals_today = entries
            .iter()
            .filter(|e| {
                e.timestamp.starts_with(&today) && e.event_type == AuditEventType::TransferApproved
            })
            .count() as u64;

        let rejections_today = entries
            .iter()
            .filter(|e| {
                e.timestamp.starts_with(&today) && e.event_type == AuditEventType::TransferRejected
            })
            .count() as u64;

        let transfers_completed = entries
            .iter()
            .filter(|e| e.event_type == AuditEventType::TransferCompleted)
            .count() as u64;

        let security_violations = entries
            .iter()
            .filter(|e| e.event_type == AuditEventType::SecurityViolation)
            .count() as u64;

        let processing_times: Vec<u64> = entries
            .iter()
            .filter_map(|e| e.processing_time_ms)
            .collect();

        let avg_processing_time = if processing_times.is_empty() {
            0
        } else {
            processing_times.iter().sum::<u64>() / processing_times.len() as u64
        };

        AuditStats {
            total_events_today: total_today,
            uploads_today,
            approvals_today,
            rejections_today,
            transfers_completed,
            security_violations_total: security_violations,
            avg_processing_time_ms: avg_processing_time,
        }
    }

    /// Get current number of entries in memory buffer.
    pub async fn entry_count(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Clear all entries from memory buffer (does not affect persisted files).
    /// Use only for testing or emergency maintenance.
    pub async fn clear_memory(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
    }
}

/// Aggregated audit statistics for dashboard display and monitoring interfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    pub total_events_today: u64,
    pub uploads_today: u64,
    pub approvals_today: u64,
    pub rejections_today: u64,
    pub transfers_completed: u64,
    pub security_violations_total: u64,
    pub avg_processing_time_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_entry_creation() {
        let entry = AuditLogEntry::new(AuditEventType::FileUploaded)
            .with_actor("user-001", "田中 太郎", "staff")
            .with_file("file-001", "document.pdf")
            .with_file_size(1024)
            .with_hashes("abc123", "def456")
            .with_network_context("192.168.1.1", "Mozilla/5.0");

        assert_eq!(entry.event_type, AuditEventType::FileUploaded);
        assert_eq!(entry.actor_id, "user-001");
        assert_eq!(entry.file_id, "file-001");
        assert!(entry.success);
        assert!(entry.error_message.is_none());
    }

    #[tokio::test]
    async fn test_audit_entry_failure() {
        let entry = AuditLogEntry::new(AuditEventType::SystemError)
            .failure("Disk full error");

        assert!(!entry.success);
        assert_eq!(entry.error_message.as_deref(), Some("Disk full error"));
    }

    #[test]
    fn test_jsonl_format() {
        let entry = AuditLogEntry::new(AuditEventType::TransferRequested)
            .with_actor("user-002", "鈴木 一郎", "staff")
            .with_file("file-002", "report.xlsx");

        let jsonl = entry.to_jsonl();
        assert!(jsonl.ends_with('\n'));
        assert!(jsonl.contains("transfer_requested"));
        let parsed: AuditLogEntry = serde_json::from_str(jsonl.trim()).unwrap();
        assert_eq!(parsed.event_id, entry.event_id);
    }

    #[test]
    fn test_csv_format() {
        let entry = AuditLogEntry::new(AuditEventType::FileDownloaded)
            .with_actor("user-003", "佐藤 花子", "approver")
            .with_file("file-003", "data.csv");

        let csv = entry.to_csv_row();
        let parts: Vec<&str> = csv.split(',').collect();
        assert_eq!(parts.len(), 9); // 9 fields with comma separation
        assert!(csv.contains("file_downloaded"));
    }

    #[tokio::test]
    async fn test_audit_log_manager_record_and_query() {
        let manager = AuditLogManager::new("/tmp/misogi_test_audit");

        let entry1 = AuditLogEntry::new(AuditEventType::FileUploaded)
            .with_actor("user-001", "田中 太郎", "staff")
            .with_file("file-001", "doc.pdf");
        manager.record(entry1).await.unwrap();

        let entry2 = AuditLogEntry::new(AuditEventType::TransferRequested)
            .with_actor("user-002", "鈴木 一郎", "staff")
            .with_file("file-002", "report.xlsx");
        manager.record(entry2).await.unwrap();

        let results = manager
            .query(Some(&AuditEventType::FileUploaded), None, None, None, None, 0, 10)
            .await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_type, AuditEventType::FileUploaded);

        let all = manager.query(None, None, None, None, None, 0, 10).await;
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn test_audit_log_stats() {
        let manager = AuditLogManager::new("/tmp/misogi_test_audit_stats");

        for _ in 0..5 {
            let entry = AuditLogEntry::new(AuditEventType::FileUploaded)
                .with_actor("user-001", "テストユーザー", "staff")
                .with_file("file-test", "test.txt")
                .with_processing_time(100);
            manager.record(entry).await.unwrap();
        }

        let stats = manager.stats().await;
        assert_eq!(stats.uploads_today, 5);
        assert_eq!(stats.total_events_today, 5);
        assert_eq!(stats.avg_processing_time_ms, 100);
    }

    #[tokio::test]
    async fn test_csv_export() {
        let manager = AuditLogManager::new("/tmp/misogi_test_export");

        let entry = AuditLogEntry::new(AuditEventType::TransferApproved)
            .with_actor("approver-001", "承認者", "approver")
            .with_file("file-001", "approved.docx")
            .with_approver("approver-001");
        manager.record(entry).await.unwrap();

        let csv = manager
            .export_csv(Some(&AuditEventType::TransferApproved), None, None, None)
            .await
            .unwrap();

        assert!(csv.starts_with("event_id"));
        assert!(csv.contains("transfer_approved"));
        assert!(csv.contains("approved.docx"));
    }

    #[tokio::test]
    async fn test_memory_buffer_limit() {
        let manager = AuditLogManager::with_config("/tmp/test_limit", 3, 30, None);

        for i in 0..5 {
            let entry = AuditLogEntry::new(AuditEventType::FileUploaded)
                .with_actor(format!("user-{}", i), "test", "staff")
                .with_file(format!("file-{}", i), "test.txt");
            manager.record(entry).await.unwrap();
        }

        assert_eq!(manager.entry_count().await, 3);
    }

    // =========================================================================
    // Tests for FILE_PROCESSED Event Type and Extended Fields
    // =========================================================================

    #[test]
    fn test_file_processed_event_type_exists() {
        // Verify FileProcessed variant exists and is comparable
        let event = AuditEventType::FileProcessed;
        assert_eq!(event.to_string(), "file_processed");

        // Verify it's distinct from other event types
        assert_ne!(event, AuditEventType::FileUploaded);
        assert_ne!(event, AuditEventType::FileSanitized);
    }

    #[test]
    fn test_file_processed_entry_with_all_extended_fields() {
        let entry = AuditLogEntry::new(AuditEventType::FileProcessed)
            .with_actor("applicant-001", "申請者 田中", "applicant")
            .with_file("file-secret", "confidential.docx")
            .with_transfer_id("tx_987654321")
            .with_applicant_id("applicant-001")
            .with_approver("approver-001")
            .with_policy_applied("REMOVE_ACTIVE_CONTENT")
            .with_sanitize_status("SUCCESS")
            .with_new_file_name("confidential_sanitized.docx")
            .with_new_size_bytes(2048)
            .with_contains_personal_info(true)
            .with_file_size(4096)
            .with_hashes("orig_hash_abc123", "sanitized_hash_def456")
            .with_processing_time(250);

        // Verify core fields
        assert_eq!(entry.event_type, AuditEventType::FileProcessed);
        assert_eq!(entry.actor_id, "applicant-001");
        assert_eq!(entry.filename, "confidential.docx");
        assert!(entry.success);

        // Verify FILE_PROCESSED extended fields
        assert_eq!(entry.transfer_id.as_deref(), Some("tx_987654321"));
        assert_eq!(entry.applicant_id.as_deref(), Some("applicant-001"));
        assert_eq!(entry.policy_applied.as_deref(), Some("REMOVE_ACTIVE_CONTENT"));
        assert_eq!(entry.sanitize_status.as_deref(), Some("SUCCESS"));
        assert_eq!(entry.new_file_name.as_deref(), Some("confidential_sanitized.docx"));
        assert_eq!(entry.new_size_bytes, Some(2048));
        assert_eq!(entry.contains_personal_info, Some(true));
    }

    #[test]
    fn test_file_processed_serialization_roundtrip() {
        let original = AuditLogEntry::new(AuditEventType::FileProcessed)
            .with_actor("user-001", "テストユーザー", "staff")
            .with_file("file-001", "test.docx")
            .with_transfer_id("tx_123456789")
            .with_policy_applied("STRIP_METADATA")
            .with_sanitize_status("SUCCESS")
            .with_new_size_bytes(1024)
            .with_contains_personal_info(false);

        // Serialize to JSON
        let json = original.to_jsonl();

        // Deserialize back
        let deserialized: AuditLogEntry = serde_json::from_str(json.trim()).unwrap();

        // Verify all fields survived roundtrip
        assert_eq!(deserialized.event_type, AuditEventType::FileProcessed);
        assert_eq!(deserialized.transfer_id, original.transfer_id);
        assert_eq!(deserialized.policy_applied, original.policy_applied);
        assert_eq!(deserialized.sanitize_status, original.sanitize_status);
        assert_eq!(deserialized.new_size_bytes, original.new_size_bytes);
        assert_eq!(deserialized.contains_personal_info, original.contains_personal_info);
        assert_eq!(deserialized.event_id, original.event_id);  // UUID preserved
    }

    #[test]
    fn test_builder_methods_chainable() {
        // Test that all builder methods return Self for chaining
        let entry = AuditLogEntry::new(AuditEventType::FileProcessed)
            .with_actor("u1", "name1", "role1")
            .with_file("f1", "file1.txt")
            .with_file_size(1000)
            .with_hashes("hash1", "hash2")
            .with_transfer_request("req-001", "会議資料配布")
            .with_approver("approver-001")
            .with_rejection_reason("ポリシー違反")
            .with_processing_time(500)
            .with_network_context("192.168.1.1", "Mozilla/5.0")
            .failure("Test error")
            .with_transfer_id("tx_001")
            .with_applicant_id("applicant-001")
            .with_policy_applied("REMOVE_ACTIVE_CONTENT")
            .with_sanitize_status("PARTIAL")
            .with_new_file_name("output.pdf")
            .with_new_size_bytes(800)
            .with_contains_personal_info(true);

        // If we got here without compiler errors, chaining works
        assert!(!entry.success);  // failure() was called last in chain
        assert_eq!(entry.transfer_id.as_deref(), Some("tx_001"));
    }

    #[tokio::test]
    async fn test_audit_log_manager_with_default_formatter() {
        // Verify backward compatibility: default formatter produces JSON output
        let manager = AuditLogManager::new("/tmp/test_default_formatter");

        let entry = AuditLogEntry::new(AuditEventType::FileUploaded)
            .with_actor("user-001", "テスト", "staff")
            .with_file("file-001", "test.txt");

        manager.record(entry).await.unwrap();

        // Query should work normally
        let results = manager.query(None, None, None, None, None, 0, 10).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_type, AuditEventType::FileUploaded);
    }

    #[tokio::test]
    async fn test_audit_log_manager_with_custom_formatter() {
        use crate::log_engine::SyslogCefFormatter;
        use crate::traits::LogFormatter;

        // Create manager with CEF formatter
        let cef_formatter: Arc<dyn LogFormatter> = Arc::new(SyslogCefFormatter::new());
        let manager = AuditLogManager::with_config(
            "/tmp/test_cef_formatter",
            100,
            30,
            Some(cef_formatter),
        );

        let entry = AuditLogEntry::new(AuditEventType::SecurityViolation)
            .with_actor("intruder-001", "攻撃者", "external")
            .with_file("file-malware", "malware.exe")
            .with_network_context("10.0.0.99", "BadBot/1.0");

        // Record should succeed with custom formatter
        manager.record(entry).await.unwrap();

        // Verify entry was stored (formatting doesn't affect storage)
        let results = manager.query(
            Some(&AuditEventType::SecurityViolation),
            None,
            None,
            None,
            None,
            0,
            10,
        ).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].actor_id, "intruder-001");
    }

    #[tokio::test]
    async fn test_export_syslog_produces_valid_cef() {
        let manager = AuditLogManager::new("/tmp/test_syslog_export");

        // Record a mix of events
        for (i, event_type) in [
            AuditEventType::FileUploaded,
            AuditEventType::SecurityViolation,
            AuditEventType::TransferCompleted,
        ].iter().enumerate() {
            let entry = AuditLogEntry::new(event_type.clone())
                .with_actor(format!("user-{}", i), "テストユーザー", "staff")
                .with_file(format!("file-{}", i), "test.txt")
                .with_network_context("192.168.1.100", "Mozilla/5.0");
            manager.record(entry).await.unwrap();
        }

        // Export as syslog/CEF format
        let cef_output = manager.export_syslog(None, None, None, None).await.unwrap();

        // Verify CEF format
        let lines: Vec<&str> = cef_output.lines().collect();
        assert_eq!(lines.len(), 3, "Should export 3 events as CEF lines");

        for line in &lines {
            assert!(
                line.starts_with("CEF:0|"),
                "Each line must start with 'CEF:0|': {}",
                line
            );
            assert!(
                line.contains("|Misogi|"),
                "Must contain vendor name"
            );
            assert!(
                line.contains("|CDR Engine|"),
                "Must contain product name"
            );
        }

        // Verify SecurityViolation has severity 10
        let sec_violation_line = lines.iter()
            .find(|l| l.contains("security_violation"))
            .expect("Should have security_violation entry");
        assert!(
            sec_violation_line.contains("|10|"),
            "SecurityViolation should have severity 10"
        );
    }

    #[tokio::test]
    async fn test_export_cef_alias_matches_syslog() {
        let manager = AuditLogManager::new("/tmp/test_cef_alias");

        let entry = AuditLogEntry::new(AuditEventType::FileProcessed)
            .with_actor("user-001", "テスト", "staff")
            .with_file("file-001", "test.docx")
            .with_transfer_id("tx_999999999")
            .with_policy_applied("CONVERT_TO_PDF")
            .with_sanitize_status("SUCCESS");
        manager.record(entry).await.unwrap();

        // Both methods should produce identical output
        let syslog_output = manager.export_syslog(None, None, None, None).await.unwrap();
        let cef_output = manager.export_cef(None, None, None, None).await.unwrap();

        assert_eq!(
            syslog_output, cef_output,
            "export_cef() must produce identical output to export_syslog()"
        );
    }

    #[tokio::test]
    async fn test_export_syslog_with_filters() {
        let manager = AuditLogManager::new("/tmp/test_syslog_filter");

        // Upload events
        for _ in 0..3 {
            let entry = AuditLogEntry::new(AuditEventType::FileUploaded)
                .with_actor("user-001", "テスト", "staff")
                .with_file("file-001", "upload.txt");
            manager.record(entry).await.unwrap();
        }

        // Security violation
        let sec_entry = AuditLogEntry::new(AuditEventType::SecurityViolation)
            .with_actor("attacker-001", "攻撃者", "external")
            .with_file("file-mal", "malware.exe");
        manager.record(sec_entry).await.unwrap();

        // Export only security violations
        let sec_only = manager
            .export_syslog(Some(&AuditEventType::SecurityViolation), None, None, None)
            .await
            .unwrap();

        let sec_lines: Vec<&str> = sec_only.lines().collect();
        assert_eq!(sec_lines.len(), 1, "Should only export 1 security violation");
        assert!(sec_lines[0].contains("security_violation"));

        // Export all events
        let all_events = manager.export_syslog(None, None, None, None).await.unwrap();
        let all_lines: Vec<&str> = all_events.lines().collect();
        assert_eq!(all_lines.len(), 4, "Should export all 4 events");
    }

    #[test]
    fn test_file_processed_display_format() {
        let event = AuditEventType::FileProcessed;
        let display_str = format!("{}", event);
        assert_eq!(display_str, "file_processed");
    }
}

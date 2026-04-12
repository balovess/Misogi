//! Core type definitions for PPAP (Password Protected Attachment Protocol) detection and handling.
//!
//! PPAP (パスワード付きZIPファイル送付) is Japan's infamous insecure file transfer
//! practice where documents are sent as password-protected ZIP files with passwords
//! transmitted via out-of-band channels (email body, phone, fax).
//!
//! Japan's MIC (Ministry of Internal Affairs and Communications, 総務省) issued
//! official guidance to discontinue PPAP in April 2024 (「PPAPの廃止について」),
//! but adoption remains incomplete across government agencies and enterprises.
//!
//! # Architecture
//!
//! This module defines the data types shared between:
//! - [`PpapDetector`] — detection engine that identifies PPAP indicators
//! - [`PpapHandler`] — policy executor that applies organizational rules
//! - [`ZipScanner`] — CDR pipeline integration point for pre-extraction checks

use serde::{Deserialize, Serialize};

// =============================================================================
// Detection Result Types
// =============================================================================

/// Result of scanning a file for PPAP (Password Protected Attachment Protocol) indicators.
///
/// PPAP is the notorious Japanese practice of sending password-protected ZIP files
/// with passwords transmitted via insecure channels (email body, phone, fax).
/// Japan's MIC (Ministry of Internal Affairs and Communications) issued guidance
/// to discontinue PPAP in 2024, but adoption remains incomplete.
///
/// The confidence score is computed from a weighted combination of detected indicators:
/// - Encrypted ZIP entries carry the highest weight (primary signal)
/// - Sensitive filename patterns add moderate weight (heuristic signal)
/// - Container extension adds minimal weight (contextual signal)
///
/// # Example
///
/// ```rust,no_run
/// let result = detector.detect(&file_path).await?;
/// if result.is_ppap && result.confidence >= 0.7 {
///     println!("PPAP detected! Reason: {}", result.reason);
///     for indicator in &result.indicators {
///         println!("  - {:?}", indicator);
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PpapDetectionResult {
    /// Whether this file exhibits PPAP characteristics above the configured threshold.
    pub is_ppap: bool,

    /// Confidence score from 0.0 (not PPAP) to 1.0 (definitely PPAP).
    ///
    /// Computed from weighted indicator analysis:
    /// - `EncryptedZipEntry`: +0.8 base weight per encrypted entry
    /// - `SensitiveFilenamePattern`: +0.3 weight per pattern match
    /// - `ContainerExtension`: +0.1 weight for archive extensions
    ///
    /// Multiple indicators compound multiplicatively, not additively,
    /// to avoid false positives from coincidental matches.
    pub confidence: f64,

    /// Specific indicators that contributed to this detection result.
    ///
    /// Empty when `is_ppap == false`. Populated with all matching
    /// indicators when `is_ppap == true` for audit trail purposes.
    pub indicators: Vec<PpapIndicator>,

    /// Detected encryption method if applicable (e.g., "ZipCrypto", "AES-256").
    ///
    /// Populated when encrypted ZIP entries are found during structural analysis.
    /// `None` when detection is based solely on filename heuristics or other signals.
    pub encryption_method: Option<String>,

    /// Human-readable explanation of why this file was flagged (or not flagged) as PPAP.
    ///
    /// Used in audit logs and admin UI notifications to provide clear context
    /// for security reviewers who may not be familiar with PPAP terminology.
    pub reason: String,
}

impl PpapDetectionResult {
    /// Create a clean result indicating no PPAP characteristics were found.
    pub fn clean() -> Self {
        Self {
            is_ppap: false,
            confidence: 0.0,
            indicators: Vec::new(),
            encryption_method: None,
            reason: "No PPAP indicators detected".to_string(),
        }
    }

    /// Create a positive PPAP detection result with full details.
    pub fn ppap_detected(
        confidence: f64,
        indicators: Vec<PpapIndicator>,
        encryption_method: Option<String>,
        reason: String,
    ) -> Self {
        Self {
            is_ppap: true,
            confidence,
            indicators,
            encryption_method,
            reason,
        }
    }
}

// =============================================================================
// Indicator Types
// =============================================================================

/// Individual indicator that contributes to PPAP detection confidence.
///
/// Each indicator represents an independent signal that a file may be part of
/// a PPAP workflow. The detection engine combines multiple indicators using
/// a weighted scoring algorithm to produce the final confidence score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PpapIndicator {
    /// ZIP archive contains one or more encrypted entries.
    ///
    /// This is the **primary** PPAP indicator. In the PPAP workflow, documents
    /// are always placed inside password-protected containers before transmission.
    /// Detecting encrypted entries within a ZIP file is the strongest possible
    /// signal that the file is a PPAP artifact.
    ///
    /// # Encryption Methods Detected
    ///
    /// - **ZipCrypto** (PKWARE traditional): Weak, used by legacy tools.
    ///   Extremely common in Japanese government PPAP workflows.
    /// - **AES-256**: Stronger encryption, sometimes used by modern tools
    ///   that still follow the PPAP pattern despite better crypto.
    EncryptedZipEntry {
        /// Name of the encrypted entry within the archive.
        entry_name: String,
    },

    /// File uses a container extension commonly associated with PPAP.
    ///
    /// While `.zip` is the most common PPAP container, Japanese organizations
    /// also use `.lzh` (LHA/LZH format, popular in legacy systems) and `.7z`
    /// (7-Zip, gaining adoption). This indicator carries low weight on its own
    /// but compounds significantly when combined with other signals.
    ContainerExtension {
        /// File extension including the dot (e.g., ".zip", ".lzh", ".7z").
        extension: String,
    },

    /// Filename matches known Japanese sensitive document naming patterns.
    ///
    /// Japanese government and enterprise organizations follow predictable
    /// naming conventions for sensitive documents that are frequently sent via PPAP:
    ///
    /// | Pattern | Meaning | Typical Context |
    /// |---------|---------|-----------------|
    /// | `*機密*` | Confidential | Internal restricted docs |
    /// | `*重要*` | Important | Executive/management docs |
    /// | `*秘*` | Secret | Classified information |
    /// | `*内覧*` | Internal review | Drafts under review |
    /// | `*非公開*` | Non-public | External-facing restricted |
    /// | `YYYYMMDD*` | Date-prefixed | Meeting materials, reports |
    /// | `*第N回*` | Nth meeting | Recurring committee docs |
    /// | `*提出*` / `*送付*` | Submission/Delivery | Formal correspondence |
    SensitiveFilenamePattern {
        /// The regex pattern string that matched the filename.
        pattern: String,
    },

    /// File originates from a known PPAP-prone sender.
    ///
    /// When sender identification is available (from upload metadata, API token,
    /// or previous transfer history), this indicator flags senders who have a
    /// historical pattern of submitting PPAP-style files.
    KnownPpapSender {
        /// Sender identifier (email domain, user ID, or organization name).
        sender_hint: String,
    },
}

impl std::fmt::Display for PpapIndicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncryptedZipEntry { entry_name } => {
                write!(f, "encrypted_zip_entry({})", entry_name)
            }
            Self::ContainerExtension { extension } => {
                write!(f, "container_extension({})", extension)
            }
            Self::SensitiveFilenamePattern { pattern } => {
                write!(f, "sensitive_filename({})", pattern)
            }
            Self::KnownPpapSender { sender_hint } => {
                write!(f, "known_ppap_sender({})", sender_hint)
            }
        }
    }
}

// =============================================================================
// Policy Types
// =============================================================================

/// Policy for handling detected PPAP files in the transfer pipeline.
///
/// Defines the system's response when a file matching PPAP characteristics
/// is encountered during upload or transfer processing.
///
/// # Policy Selection Guide
///
/// | Policy | Use Case | Security Level | Migration Friendly |
/// |--------|----------|---------------|-------------------|
/// | `Block` | High-security orgs that officially banned PPAP | Maximum | No |
/// | `WarnAndSanitize` | Organizations transitioning away from PPAP | High | Yes (recommended default) |
/// | `Quarantine` | Orgs needing manual review before disposition | Medium-High | Partial |
/// | `ConvertToSecure` | Full PPAP replacement mode ("手刃PPAP") | High | Yes (full automation) |
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PpapPolicy {
    /// Block the transfer entirely. Generate audit event explaining PPAP risk.
    ///
    /// Recommended for high-security environments that have officially banned PPAP
    /// per MIC guidance. The uploader receives a clear error message explaining
    /// that password-protected archives are prohibited and suggesting Misogi's
    /// secure transfer as the replacement.
    Block,

    /// Allow transfer after stripping encryption (if weakly protected) and applying CDR.
    ///
    /// Logs a prominent warning in the audit trail but does not block the transfer.
    /// Ideal for migration periods where some senders still use PPAP out of habit.
    /// Only ZipCrypto-encrypted archives with detectable weak passwords are stripped;
    /// AES-256 encrypted files are blocked even under this policy.
    WarnAndSanitize,

    /// Quarantine the file for manual security review before any processing.
    ///
    /// The file enters a held state requiring explicit administrator release.
    /// Useful when automated decisions are too risky (legal department review needed)
    /// or when building evidence of PPAP usage patterns before enforcing stricter policies.
    Quarantine,

    /// Convert PPAP workflow to secure Misogi transfer automatically.
    ///
    /// This is the **"kill PPAP" (手刃PPAP)** mode — replaces the insecure practice
    /// transparently:
    /// 1. Attempt controlled decryption (known-weak-password only, never brute-force)
    /// 2. Run full CDR sanitization on extracted contents
    /// 3. Re-package as clean, non-encrypted archive
    /// 4. Transfer via secure Misogi tunnel
    /// 5. Generate "PPAP replaced" audit trail entry
    ///
    /// The receiver gets a clean, sanitized file with no indication it ever was PPAP.
    ConvertToSecure,
}

impl Default for PpapPolicy {
    fn default() -> Self {
        Self::WarnAndSanitize
    }
}

impl std::fmt::Display for PpapPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block => write!(f, "block"),
            Self::WarnAndSanitize => write!(f, "warn_and_sanitize"),
            Self::Quarantine => write!(f, "quarantine"),
            Self::ConvertToSecure => write!(f, "convert_to_secure"),
        }
    }
}

impl PpapPolicy {
    /// Parse a policy from a case-insensitive string (for CLI/TOML config).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "block" => Some(Self::Block),
            "warn_and_sanitize" | "warn-and-sanitize" | "warn" => Some(Self::WarnAndSanitize),
            "quarantine" => Some(Self::Quarantine),
            "convert_to_secure" | "convert-to-secure" | "convert" => Some(Self::ConvertToSecure),
            _ => None,
        }
    }

    /// Returns whether this policy allows the file to proceed after handling
    /// (as opposed to blocking it entirely).
    pub fn allows_transfer(&self) -> bool {
        !matches!(self, Self::Block)
    }

    /// Returns whether this policy requires quarantining the file.
    pub fn requires_quarantine(&self) -> bool {
        matches!(self, Self::Quarantine)
    }

    /// Returns whether this policy attempts automatic conversion.
    pub fn attempts_conversion(&self) -> bool {
        matches!(self, Self::ConvertToSecure)
    }
}

// =============================================================================
// Handling Report Types
// =============================================================================

/// Detailed report of PPAP handling actions taken on a single file.
///
/// Serves as both operational record and compliance evidence that
/// PPAP was detected and properly handled per organizational policy.
///
/// This report is written to the audit log and can be queried via the
/// `/api/v1/ppap/statistics` endpoint for dashboard display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PpapHandlingReport {
    /// Correlation ID linking this report to the original transfer request.
    pub file_id: String,

    /// Original filename of the submitted file.
    pub original_filename: String,

    /// Detection result that triggered handling.
    pub detection: PpapDetectionResult,

    /// Policy that was applied.
    pub policy: PpapPolicy,

    /// Final disposition of the file.
    pub disposition: PpapDisposition,

    /// Actions taken during handling (audit trail).
    pub actions_taken: Vec<PpapAction>,

    /// Warning messages generated during processing.
    pub warnings: Vec<String>,

    /// Processing time in milliseconds.
    pub processing_time_ms: u64,

    /// Whether handling completed successfully.
    pub success: bool,
}

impl PpapHandlingReport {
    /// Create a new empty report skeleton for the given file.
    pub fn new(file_id: String, original_filename: String) -> Self {
        Self {
            file_id,
            original_filename,
            detection: PpapDetectionResult::clean(),
            policy: PpapPolicy::default(),
            disposition: PpapDisposition::PassedThrough,
            actions_taken: Vec::new(),
            warnings: Vec::new(),
            processing_time_ms: 0,
            success: false,
        }
    }
}

/// Final disposition of a file after PPAP handling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PpapDisposition {
    /// File was blocked from transfer.
    Blocked,

    /// File was sanitized (encryption stripped) and transferred with warning.
    SanitizedWithWarning,

    /// File quarantined for manual review.
    Quarantined,

    /// PPAP converted to secure Misogi transfer.
    ConvertedToSecure,

    /// File passed through (false positive, below confidence threshold).
    PassedThrough,
}

/// Individual action taken during PPAP handling.
///
/// Each variant captures enough context for audit trail reconstruction
/// and compliance reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "detail")]
pub enum PpapAction {
    /// PPAP detected and logged.
    PpapDetected {
        /// Confidence score at time of detection.
        confidence: f64,
    },

    /// Transfer blocked due to PPAP policy violation.
    TransferBlocked {
        /// Human-readable reason for the block decision.
        reason: String,
    },

    /// ZIP encryption stripped (weak password identified, contents extracted).
    EncryptionStripped {
        /// Original encryption method (e.g., "ZipCrypto", "AES-256").
        method: String,
    },

    /// File moved to quarantine directory.
    Quarantined {
        /// Absolute path of the quarantine location.
        quarantine_path: String,
    },

    /// Administrator notification sent for manual review.
    AdminNotified {
        /// Notification channel used (e.g., "webhook", "email", "slack").
        channel: String,
    },

    /// Compliance event generated for audit trail.
    ComplianceEventGenerated {
        /// Type of compliance event (e.g., "ppap_detected", "ppap_blocked").
        event_type: String,
    },
}

// =============================================================================
// Configuration Types
// =============================================================================

/// Configuration for PPAP detection behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PpapDetectorConfig {
    /// Minimum confidence threshold (0.0-1.0) to classify a file as PPAP.
    ///
    /// Files scoring below this threshold pass through without PPAP handling.
    /// Recommended values:
    /// - `0.5`: Lenient — catches obvious PPAP, may have false positives
    /// - `0.7`: Balanced (default) — good precision/recall tradeoff
    /// - `0.9`: Strict — only flag near-certain PPAP, may miss edge cases
    #[serde(default = "default_ppap_confidence_threshold")]
    pub confidence_threshold: f64,

    /// Enable filename heuristic analysis (Japanese sensitive document patterns).
    ///
    /// When enabled, filenames are checked against regex patterns matching
    /// common Japanese government/enterprise naming conventions for sensitive
    /// documents that are frequently sent via PPAP.
    #[serde(default = "default_true")]
    pub enable_filename_heuristics: bool,

    /// List of filename regex patterns that indicate potential PPAP usage.
    ///
    /// Each pattern is tested against the filename (without directory path).
    /// Patterns should use Rust regex syntax. Case-insensitive matching is applied.
    #[serde(default = "default_sensitive_filename_patterns")]
    pub sensitive_filename_patterns: Vec<String>,

    /// Maximum file size (bytes) to subject to PPAP scanning.
    ///
    /// Files larger than this are skipped (assumed not to be typical PPAP).
    /// PPAP files are typically small document collections (< 100MB).
    /// Large files (video, disk images, database dumps) are unlikely to be PPAP.
    #[serde(default = "default_max_ppap_scan_size")]
    pub max_scan_size_bytes: u64,
}

impl Default for PpapDetectorConfig {
    fn default() -> Self {
        Self {
            confidence_threshold: default_ppap_confidence_threshold(),
            enable_filename_heuristics: default_true(),
            sensitive_filename_patterns: default_sensitive_filename_patterns(),
            max_scan_size_bytes: default_max_ppap_scan_size(),
        }
    }
}

fn default_ppap_confidence_threshold() -> f64 {
    0.7
}

fn default_true() -> bool {
    true
}

fn default_max_ppap_scan_size() -> u64 {
    500 * 1024 * 1024 // 500MB
}

pub(crate) fn default_sensitive_filename_patterns() -> Vec<String> {
    vec![
        // Japanese sensitivity keywords commonly found in PPAP filenames
        r"(?i)(機密|重要|秘|内覧|非公開|限|別紙|添付|御中)".to_string(),
        // Date-patterned names: YYYYMMDD + archive extension
        r"\d{8}.*\.(zip|lzh|7z)$".to_string(),
        // Meeting/conference numbering
        r"(?i)(.*第\d+回.*)+\.(zip|lzh|7z)$".to_string(),
        // Submission/delivery language patterns
        r"(?i)(.*提出.*|.*送付.*|.*参考.*|.*照会.*)+\.(zip|lzh|7z)$".to_string(),
    ]
}

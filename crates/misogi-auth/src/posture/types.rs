//! Device Posture Data Structures
//!
//! Defines all data types for representing device security posture information.
//! These structures are serialized from client-side reports or EDR API responses.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Core Posture Types
// ---------------------------------------------------------------------------

/// Comprehensive device posture assessment result.
///
/// Aggregates operating system health, security software status, patch
/// compliance, and individual check results into a single scoreable entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePosture {
    /// Operating system identification and version info.
    pub os_info: OsPosture,

    /// Antivirus / EDR / encryption status.
    pub security_software: SecuritySoftwarePosture,

    /// Security patch compliance assessment.
    pub patch_status: PatchStatus,

    /// Overall posture score (0–100).
    ///
    /// Computed by [`PostureChecker`] from individual check results:
    /// - 90–100: Excellent (all checks pass)
    /// - 70–89: Good (minor warnings)
    /// - 50–69: Fair (some issues)
    /// - 0–49: Poor (critical failures)
    pub posture_score: u8,

    /// When this posture was assessed.
    pub assessed_at: DateTime<Utc>,

    /// Individual check results (for detailed reporting).
    pub checks: Vec<PostureCheckResult>,
}

/// Operating system identification and support status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsPosture {
    /// Detected platform family.
    pub platform: OsPlatform,

    /// Full OS version string (e.g., "10.0.19045" for Windows 11 22H2).
    pub version: String,

    /// OS build number (e.g., "19045" for Windows).
    pub build_number: String,

    /// Whether this OS version is supported by organizational policy.
    pub is_supported: bool,

    /// Minimum required version per policy (if unsupported).
    pub minimum_required_version: Option<String>,
}

/// Supported operating system platforms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OsPlatform {
    /// Microsoft Windows (7, 8.1, 10, 11).
    Windows,

    /// Apple macOS (Monterey, Ventura, Sonoma, etc.).
    MacOS,

    /// Linux distributions (Ubuntu, RHEL, etc.).
    Linux,

    /// Apple iOS / iPadOS.
    Ios,

    /// Google Android.
    Android,

    /// Unknown or unclassified platform.
    Unknown(String),
}

impl std::fmt::Display for OsPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Windows => write!(f, "windows"),
            Self::MacOS => write!(f, "macos"),
            Self::Linux => write!(f, "linux"),
            Self::Ios => write!(f, "ios"),
            Self::Android => write!(f, "android"),
            Self::Unknown(s) => write!(f, "unknown({s})"),
        }
    }
}

/// Security software detection results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySoftwarePosture {
    /// Detected antivirus product name (if any).
    pub antivirus_name: Option<String>,

    /// Whether antivirus real-time protection is enabled.
    pub antivirus_enabled: bool,

    /// Age of antivirus signature database in days (if detectable).
    ///
    /// Values > 7 days may indicate outdated signatures.
    pub antivirus_signature_age_days: Option<u32>,

    /// Whether an EDR (Endpoint Detection & Response) agent is present.
    pub edr_present: bool,

    /// Detected EDR product name (if present).
    pub edr_name: Option<String>,

    /// Whether host firewall is enabled.
    pub firewall_enabled: bool,

    /// Disk encryption status (Windows BitLocker / macOS FileVault).
    pub bitlocker_status: Option<EncryptionStatus>,
}

/// Disk encryption status enumeration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionStatus {
    /// Encryption active and verified.
    Encrypted,

    /// Encryption not enabled.
    NotEncrypted,

    /// Unable to determine encryption status.
    Unknown,
}

/// Security patch compliance assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchStatus {
    /// Date of the most recent security patch installation.
    pub last_patch_date: Option<DateTime<Utc>>,

    /// Days elapsed since the last security patch.
    pub days_since_last_patch: Option<i64>,

    /// Number of missing critical/security patches.
    pub critical_patches_missing: u32,

    /// Whether the device meets the patch compliance policy.
    pub is_compliant: bool,
}

/// Result of an individual posture check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureCheckResult {
    /// Unique identifier for this check type.
    pub check_id: String,

    /// Human-readable check name.
    pub check_name: String,

    /// Whether this check passed.
    pub passed: bool,

    /// Severity level if check failed.
    pub severity: CheckSeverity,

    /// Additional details about the check result.
    pub details: String,
}

/// Severity levels for failed posture checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CheckSeverity {
    /// Must pass — authentication blocked on failure.
    Critical,

    /// Should pass — generates warning but allows access.
    Warning,

    /// Informational only — no impact on access decision.
    Info,
}

impl std::fmt::Display for CheckSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::Warning => write!(f, "warning"),
            Self::Info => write!(f, "info"),
        }
    }
}

// ---------------------------------------------------------------------------
// Policy Configuration
// ---------------------------------------------------------------------------

/// Posture evaluation policy definition.
///
/// Controls which checks are required, what thresholds apply, and
/// what action to take when the device fails posture evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PosturePolicy {
    /// Minimum acceptable posture score (0–100).
    ///
    /// Devices scoring below this threshold are subject to `failure_action`.
    pub min_posture_score: u8,

    /// List of check IDs that MUST pass (Critical severity).
    ///
    /// If any of these checks fail, authentication is blocked regardless
    /// of overall score.
    pub required_checks: Vec<String>,

    /// OS version requirements per platform.
    pub os_requirements: HashMap<OsPlatform, OsRequirement>,

    /// Maximum allowed days since last security patch.
    pub max_patch_age_days: u32,

    /// Whether antivirus must be present and enabled.
    pub require_antivirus: bool,

    /// Whether EDR presence is mandatory.
    pub require_edr: bool,

    /// Action to take when posture evaluation fails.
    pub failure_action: FailureAction,
}

/// Per-platform OS version requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsRequirement {
    /// Minimum accepted version string.
    pub min_version: String,

    /// Human-readable OS name for error messages.
    pub display_name: String,
}

/// Action to take when device fails posture evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FailureAction {
    /// Reject authentication entirely.
    Block,

    /// Allow authentication but emit warning in audit log.
    Warn,

    /// Allow silently (audit-only recording).
    Allow,
}

impl std::fmt::Display for FailureAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block => write!(f, "block"),
            Self::Warn => write!(f, "warn"),
            Self::Allow => write!(f, "allow"),
        }
    }
}

impl Default for PosturePolicy {
    fn default() -> Self {
        let mut os_requirements = HashMap::new();
        os_requirements.insert(
            OsPlatform::Windows,
            OsRequirement {
                min_version: "10.0.19045".to_string(),
                display_name: "Windows 10 22H2 / Windows 11".to_string(),
            },
        );
        os_requirements.insert(
            OsPlatform::MacOS,
            OsRequirement {
                min_version: "12.0".to_string(),
                display_name: "macOS Monterey".to_string(),
            },
        );

        Self {
            min_posture_score: 70,
            required_checks: vec![
                "os_supported".to_string(),
                "antivirus_enabled".to_string(),
            ],
            os_requirements,
            max_patch_age_days: 30,
            require_antivirus: true,
            require_edr: false,
            failure_action: FailureAction::Warn,
        }
    }
}

#[cfg(test)]
mod tests;

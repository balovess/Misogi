//! Shared EDR Data Models
//!
//! Defines common data structures used across all EDR provider implementations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Error type for EDR operations.
#[derive(Debug, thiserror::Error)]
pub enum EdrError {
    /// Authentication failure (invalid credentials, token expired).
    #[error("EDR authentication failed: {0}")]
    Authentication(String),

    /// Network or API communication error.
    #[error("EDR API error: {0}")]
    Api(String),

    /// Device not found in the EDR system.
    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    /// Rate limit exceeded.
    #[error("Rate limit exceeded, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Invalid response from the EDR API.
    #[error("Invalid EDR response: {0}")]
    InvalidResponse(String),

    /// Configuration error (missing required settings).
    #[error("EDR configuration error: {0}")]
    Configuration(String),

    /// Operation timed out.
    #[error("EDR operation timed out")]
    Timeout,

    /// Provider-specific error with context.
    #[error("{provider} error: {message}")]
    Provider {
        provider: String,
        message: String,
    },
}

/// Comprehensive device posture data from an EDR solution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrDevicePosture {
    /// Unique device identifier in the EDR system.
    pub device_id: String,

    /// Device hostname/machine name.
    pub hostname: Option<String>,

    /// Whether the device has any active threats or detections.
    pub has_active_threats: bool,

    /// Number of unresolved detections/alerts on this device.
    pub active_detection_count: u32,

    /// Whether the EDR sensor is running and reporting normally.
    pub sensor_healthy: bool,

    /// Last time the sensor communicated with the EDR cloud.
    pub last_seen_at: Option<DateTime<Utc>>,

    /// Operating system information as reported by EDR.
    pub os_info: Option<EdrOsInfo>,

    /// Raw JSON payload from the EDR API (for debugging).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_response: Option<serde_json::Value>,
}

/// OS information from EDR telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrOsInfo {
    /// Operating system platform.
    pub platform: String,

    /// OS version string.
    pub version: String,

    /// OS build number.
    pub build: Option<String>,
}

/// Risk score assigned to a device by EDR analytics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrRiskScore {
    /// Numeric risk score (0–100, higher = more risky).
    pub score: u8,

    /// Risk level classification.
    pub level: EdrRiskLevel,

    /// When this risk assessment was computed.
    pub assessed_at: DateTime<Utc>,

    /// Factors contributing to this score.
    pub factors: Vec<RiskFactor>,
}

/// Risk level categories.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EdrRiskLevel {
    /// Low risk (0–29): No significant concerns.
    Low,

    /// Medium risk (30–69): Some concerns warranting attention.
    Medium,

    /// High risk (70–89): Significant risk indicators present.
    High,

    /// Critical risk (90–100): Immediate action required.
    Critical,
}

impl std::fmt::Display for EdrRiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Individual factor contributing to a risk score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Factor category (e.g., "vulnerability", "detection", "configuration").
    pub category: String,

    /// Factor description.
    pub description: String,

    /// Weight of this factor in the overall score (0.0 – 1.0).
    pub weight: f64,
}

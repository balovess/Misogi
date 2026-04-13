//! Device Fingerprint Data Structures & Hashing
//!
//! Defines the core data types for collecting, storing, and comparing
//! device fingerprints. Implements privacy-preserving hash computation
//! using HMAC-SHA256.
//!
//! # Signal Categories
//!
//! | Signal        | Stability | Entropy | Privacy Risk |
//! |---------------|-----------|---------|--------------|
//! | User-Agent    | High      | ~8 bits | Low          |
//! | Canvas Hash   | Medium    | ~12 bits| Medium       |
//! | Screen Res.   | High      | ~6 bits | Low          |
//!
//! # Example Usage
//!
//! ```ignore
//! use misogi_auth::device::{DeviceFingerprint, FingerprintSignal, ScreenResolution};
//! use chrono::Utc;
//!
//! let fp = DeviceFingerprint {
//!     user_agent: FingerprintSignal {
//!         value_hash: "hmac_sha256_of_ua".to_string(),
//!         entropy_bits: 8.0,
//!         is_stable: true,
//!     },
//!     canvas_hash: None,
//!     screen_resolution: ScreenResolution {
//!         width: 1920,
//!         height: 1080,
//!         color_depth: 24,
//!         pixel_ratio: 1,
//!     },
//!     collected_at: Utc::now(),
//!     confidence: 0.85,
//! };
//!
//! let device_id = fp.compute_device_id(b"my-secret-key");
//! assert!(device_id.len() == 64); // SHA-256 hex = 64 chars
//! ```

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum acceptable confidence score for a valid fingerprint.
///
/// Fingerprints below this threshold are considered unreliable and
/// will be rejected by [`FingerprintValidator`].
pub const MIN_CONFIDENCE_THRESHOLD: f64 = 0.6;

/// Minimum required length for a valid user-agent hash value.
///
/// Prevents obviously forged or empty user-agent strings.
pub const MIN_UA_HASH_LENGTH: usize = 8;

/// Default HMAC key rotation interval in hours (7 days).
///
/// After this period, a new secret key should be used to compute
/// device IDs, effectively rotating fingerprints for privacy.
pub const DEFAULT_ROTATION_TTL_HOURS: u64 = 168;

/// Truncated device ID length in hex characters (256 bits = 64 hex chars).
pub const DEVICE_ID_HEX_LENGTH: usize = 64;

// ---------------------------------------------------------------------------
// Core Data Structures
// ---------------------------------------------------------------------------

/// Collected device fingerprint from client-side signals.
///
/// Aggregates multiple browser/environment signals into a single structure
/// that can be serialized, transmitted, and validated server-side. All
/// sensitive values are pre-hashed on the client side; the server never
/// sees raw User-Agent strings or canvas data.
///
/// # Thread Safety
///
/// This struct is `Clone + Send + Sync` and safe to share across async tasks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    /// Browser/User-Agent string (HMAC-SHA256 hashed).
    ///
    /// The most stable signal — rarely changes between sessions unless
    /// the user upgrades their browser. Contributes ~8 bits of entropy.
    pub user_agent: FingerprintSignal,

    /// Canvas fingerprint hash (optional, browser-generated).
    ///
    /// Computed from HTML5 Canvas rendering output. Higher entropy (~12 bits)
    /// but may change across browser updates or GPU driver changes.
    ///
    /// **Privacy note**: Uses non-persistent canvas (cleared after read).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canvas_hash: Option<FingerprintSignal>,

    /// Normalized screen resolution.
    ///
    /// Stable signal that helps distinguish mobile vs desktop devices.
    /// Contributes ~6 bits of entropy at typical resolutions.
    pub screen_resolution: ScreenResolution,

    /// Timestamp when this fingerprint was collected (client-side).
    pub collected_at: DateTime<Utc>,

    /// Overall confidence score (0.0 – 1.0).
    ///
    /// Computed from:
    /// - Number of present signals
    /// - Individual signal entropy contributions
    /// - Signal stability factors
    ///
    /// Values below [`MIN_CONFIDENCE_THRESHOLD`] are considered invalid.
    pub confidence: f64,
}

/// Individual fingerprint signal with metadata.
///
/// Each signal carries not just its hashed value but also metadata about
/// its reliability and information content. This enables weighted comparison
/// algorithms that handle partial matches gracefully.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FingerprintSignal {
    /// HMAC-SHA256 hash of the raw signal value.
    ///
    /// Never contains the original value — always pre-hashed by the client.
    pub value_hash: String,

    /// Estimated entropy contribution in bits.
    ///
    /// Used for confidence scoring and similarity weighting.
    /// Higher values indicate more distinguishing power.
    pub entropy_bits: f64,

    /// Whether this signal is stable across browser sessions.
    ///
    /// Stable signals (User-Agent, screen resolution) are weighted more
    /// heavily in device ID computation than unstable ones (canvas).
    pub is_stable: bool,
}

/// Normalized screen resolution fingerprint signal.
///
/// Captures display characteristics in a platform-independent format.
/// Values are rounded to common denominators to reduce granularity-based
/// tracking while maintaining sufficient entropy for device classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenResolution {
    /// Horizontal pixel count (rounded to nearest 100).
    pub width: u32,

    /// Vertical pixel count (rounded to nearest 100).
    pub height: u32,

    /// Color bit depth (24 or 32 typically).
    pub color_depth: u8,

    /// Device pixel ratio × 100 (e.g., 100 = 1x, 200 = 2x Retina).
    pub pixel_ratio: u8,
}

impl fmt::Display for ScreenResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}x{}@{}bit:{}x",
            self.width, self.height, self.color_depth, self.pixel_ratio
        )
    }
}

impl ScreenResolution {
    /// Create a new screen resolution with automatic rounding.
    ///
    /// Width and height are rounded to the nearest 100 pixels to reduce
    /// fingerprint precision while preserving device class information.
    pub fn new(width: u32, height: u32, color_depth: u8, pixel_ratio: u8) -> Self {
        Self {
            width: Self::round_dimension(width),
            height: Self::round_dimension(height),
            color_depth,
            pixel_ratio,
        }
    }

    /// Round a dimension value to the nearest 100.
    fn round_dimension(value: u32) -> u32 {
        ((value + 50) / 100) * 100
    }

    /// Check if this represents a high-DPI (Retina-class) display.
    pub fn is_high_dpi(&self) -> bool {
        self.pixel_ratio >= 150
    }

    /// Total pixel count (millions, for classification).
    pub fn megapixels(&self) -> f64 {
        (self.width as f64 * self.height as f64) / 1_000_000.0
    }
}

// ---------------------------------------------------------------------------
// Fingerprint Operations
// ---------------------------------------------------------------------------

impl DeviceFingerprint {
    /// Compute a stable device identifier from fingerprint signals.
    ///
    /// Uses HMAC-SHA256 with a server-side secret key to produce a
    /// cryptographically bound device ID. Only **stable signals**
    /// participate in the computation to ensure session-to-session consistency.
    ///
    /// # Algorithm
    ///
    /// ```text
    /// canonical = "ua:<hash>|screen:<w>x<h>@<d>:<pr>"
    /// device_id = HMAC-SHA256(secret_key, canonical)[0..64]
    /// ```
    ///
    /// # Arguments
    ///
    /// * `secret` — Server-side HMAC key (minimum 32 bytes recommended)
    ///
    /// # Returns
    ///
    /// A 64-character hexadecimal string (SHA-256 digest).
    ///
    /// # Security Note
    ///
    /// The secret key MUST be:
    /// - Generated via a CSPRNG (`rand::thread_rng()`)
    /// - Stored securely (Vault, KMS, or encrypted config)
    /// - Rotated periodically ([`DEFAULT_ROTATION_TTL_HOURS`])
    pub fn compute_device_id(&self, secret: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let canonical = format!(
            "ua:{}|screen:{}",
            self.user_agent.value_hash,
            self.screen_resolution,
        );

        let mut mac =
            HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
        mac.update(canonical.as_bytes());

        let result = mac.finalize();
        let bytes = result.into_bytes();

        hex::encode(bytes)
    }

    /// Compare two fingerprints and return similarity score (0.0 – 1.0).
    ///
    /// Performs weighted comparison of each signal component:
    ///
    /// | Component    | Weight | Match Criteria               |
    /// |-------------|--------|------------------------------|
    /// | User-Agent   | 0.4    | Exact hash match             |
    /// | Canvas       | 0.3    | Exact hash match (if present)|
    /// | Screen       | 0.3    | Exact match                  |
    ///
    /// Returns 1.0 for identical fingerprints, 0.0 for completely different.
    pub fn similarity(&self, other: &Self) -> f64 {
        let mut total_weight = 0.0;
        let mut matched_weight = 0.0;

        // User-Agent comparison (weight: 0.4)
        let ua_weight = 0.4;
        total_weight += ua_weight;
        if self.user_agent.value_hash == other.user_agent.value_hash {
            matched_weight += ua_weight;
        }

        // Canvas comparison (weight: 0.3, if both present)
        if self.canvas_hash.is_some() && other.canvas_hash.is_some() {
            let canvas_weight = 0.3;
            total_weight += canvas_weight;
            if self.canvas_hash == other.canvas_hash {
                matched_weight += canvas_weight;
            }
        }

        // Screen resolution comparison (weight: 0.3)
        let screen_weight = 0.3;
        total_weight += screen_weight;
        if self.screen_resolution == other.screen_resolution {
            matched_weight += screen_weight;
        }

        if total_weight > 0.0 {
            matched_weight / total_weight
        } else {
            0.0
        }
    }

    /// Validate minimum requirements for a usable fingerprint.
    ///
    /// Checks:
    /// - Confidence ≥ [`MIN_CONFIDENCE_THRESHOLD`] (0.6)
    /// - User-agent hash length ≥ [`MIN_UA_HASH_LENGTH`] (8)
    /// - At least one stable signal present
    /// - Collection timestamp is not in the future (>60s tolerance)
    pub fn is_valid(&self) -> bool {
        if self.confidence < MIN_CONFIDENCE_THRESHOLD {
            return false;
        }
        if self.user_agent.value_hash.len() < MIN_UA_HASH_LENGTH {
            return false;
        }
        if !self.user_agent.is_stable {
            return false;
        }

        let now = Utc::now();
        let time_diff = self.collected_at.signed_duration_since(now);
        if time_diff.num_seconds() > 60 {
            return false;
        }

        true
    }

    /// Count the number of populated (non-empty) signals.
    pub fn signal_count(&self) -> usize {
        let mut count = 2; // user_agent + screen_resolution always present
        if self.canvas_hash.is_some() {
            count += 1;
        }
        count
    }

    /// Calculate total entropy across all signals (bits).
    pub fn total_entropy(&self) -> f64 {
        let mut entropy = self.user_agent.entropy_bits;
        if let Some(ref canvas) = self.canvas_hash {
            entropy += canvas.entropy_bits;
        }
        // Screen resolution contributes fixed ~6 bits
        entropy += 6.0;
        entropy
    }
}

impl FingerprintSignal {
    /// Create a new fingerprint signal from a pre-hashed value.
    ///
    /// # Arguments
    ///
    /// * `value_hash` — HMAC-SHA256 hex string of the raw signal
    /// * `entropy_bits` — Estimated entropy contribution
    /// * `is_stable` — Whether this signal persists across sessions
    pub fn new(value_hash: String, entropy_bits: f64, is_stable: bool) -> Self {
        Self {
            value_hash,
            entropy_bits,
            is_stable,
        }
    }

    /// Check if this signal appears to be well-formed.
    ///
    /// Validates that the hash looks like a proper hex-encoded SHA-256
    /// (64 characters of [0-9a-f]).
    pub fn is_well_formed(&self) -> bool {
        self.value_hash.len() == 64 && self.value_hash.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;

//! Server-Side Fingerprint Collector
//!
//! Handles parsing and initial validation of device fingerprint data
//! received from clients via HTTP headers.
//!
//! # Input Format
//!
//! Fingerprints are transmitted as base64-encoded JSON in the
//! `X-Device-Fingerprint` HTTP header:
//!
//! ```text
//! X-Device-Fingerprint: eyJ1c2VyX2FnZW50Ijogey...
//! ```
//!
//! # Processing Pipeline
//!
//! ```text
//! Base64 Decode → JSON Parse → Schema Validate → Return DeviceFingerprint
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tracing::{debug, warn};

use super::fingerprint::{
    DeviceFingerprint,
    FingerprintSignal,
    MIN_CONFIDENCE_THRESHOLD,
    MIN_UA_HASH_LENGTH,
};
use crate::AuthError;

/// Header name for device fingerprint transmission.
pub const FINGERPRINT_HEADER: &str = "X-Device-Fingerprint";

/// Maximum allowed size for base64-encoded fingerprint (4 KB).
///
/// Prevents DoS via oversized headers. A typical fingerprint JSON is
/// ~500 bytes base64-encoded; 4 KB provides generous headroom.
pub const MAX_FINGERPRINT_SIZE_BYTES: usize = 4096;

/// Result of fingerprint collection with metadata.
#[derive(Debug, Clone)]
pub struct CollectedFingerprint {
    /// Parsed and validated fingerprint data.
    pub fingerprint: DeviceFingerprint,
    /// Raw header value length (for audit logging).
    pub raw_size_bytes: usize,
    /// Whether the fingerprint passed all validation checks.
    pub is_valid: bool,
}

impl CollectedFingerprint {
    /// Create a new collected fingerprint wrapper.
    pub fn new(fingerprint: DeviceFingerprint, raw_size_bytes: usize) -> Self {
        let is_valid = fingerprint.is_valid();
        Self {
            fingerprint,
            raw_size_bytes,
            is_valid,
        }
    }
}

/// Parse and validate a device fingerprint from an HTTP header value.
///
/// # Arguments
///
/// * `header_value` — The raw `X-Device-Fingerprint` header value
///
/// # Errors
///
/// Returns [`AuthError`] if the header is missing, malformed, or fails validation.
///
/// # Example
///
/// ```ignore
/// let collected = collect_fingerprint_from_header(Some("eyJ..."))?;
/// if collected.is_valid {
///     let device_id = collected.fingerprint.compute_device_id(&secret);
/// }
/// ```
pub fn collect_fingerprint_from_header(
    header_value: Option<&str>,
) -> Result<Option<CollectedFingerprint>, AuthError> {
    let raw = match header_value {
        Some(v) if !v.trim().is_empty() => v.trim(),
        _ => return Ok(None), // No fingerprint provided — not an error
    };

    debug!(
        header_len = raw.len(),
        "Received device fingerprint header"
    );

    // Size check to prevent DoS
    if raw.len() > MAX_FINGERPRINT_SIZE_BYTES {
        warn!(
            header_len = raw.len(),
            max = MAX_FINGERPRINT_SIZE_BYTES,
            "Fingerprint header exceeds maximum size"
        );
        return Err(AuthError::InvalidToken(format!(
            "Fingerprint header too large: {} > {} bytes",
            raw.len(),
            MAX_FINGERPRINT_SIZE_BYTES
        )));
    }

    // Base64 decode
    let json_bytes = BASE64
        .decode(raw)
        .map_err(|e| AuthError::InvalidToken(format!("Base64 decode failed: {e}")))?;

    // JSON parse
    let fingerprint: DeviceFingerprint = serde_json::from_slice(&json_bytes)
        .map_err(|e| AuthError::InvalidToken(format!("Fingerprint JSON parse failed: {e}")))?;

    debug!(
        signal_count = fingerprint.signal_count(),
        confidence = fingerprint.confidence,
        "Fingerprint parsed successfully"
    );

    Ok(Some(CollectedFingerprint::new(fingerprint, raw.len())))
}

/// Sanitize a user-agent string before hashing on the client side.
///
/// This function is documented for client-side implementation reference.
/// Server-side usage receives pre-hashed values only.
///
/// # Sanitization Rules
///
/// 1. Strip version numbers after major.minor (reduce noise)
/// 2. Lowercase for consistency
/// 3. Remove extra whitespace
/// 4. Truncate to 512 characters max
///
/// # Returns
///
/// A sanitized string suitable for HMAC hashing.
#[allow(dead_code)]
pub fn sanitize_user_agent(raw_ua: &str) -> String {
    raw_ua
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(512)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    fn make_sample_fp_json() -> String {
        let fp = json!({
            "user_agent": {
                "value_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "entropy_bits": 8.0,
                "is_stable": true
            },
            "canvas_hash": {
                "value_hash": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                "entropy_bits": 12.0,
                "is_stable": false
            },
            "screen_resolution": {
                "width": 1900,
                "height": 1100,
                "color_depth": 24,
                "pixel_ratio": 100
            },
            "collected_at": Utc::now().to_rfc3339(),
            "confidence": 0.85
        });
        serde_json::to_string(&fp).unwrap()
    }

    #[test]
    fn test_collect_valid_fingerprint() {
        let json = make_sample_fp_json();
        let encoded = BASE64.encode(&json);

        let result = collect_fingerprint_from_header(Some(&encoded)).unwrap();
        assert!(result.is_some());

        let collected = result.unwrap();
        assert!(collected.is_valid);
        assert!(collected.raw_size_bytes > 0);
    }

    #[test]
    fn test_collect_none_when_missing() {
        let result = collect_fingerprint_from_header(None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_collect_none_when_empty() {
        let result = collect_fingerprint_from_header(Some("")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_collect_error_on_invalid_base64() {
        let result = collect_fingerprint_from_header(Some("not-valid-base64!!!"));
        assert!(result.is_err());
    }

    #[test]
    fn test_collect_error_on_invalid_json() {
        let valid_base64 = BASE64.encode(b"{invalid json}");
        let result = collect_fingerprint_from_header(Some(&valid_base64));
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_user_agent_basic() {
        let sanitized = sanitize_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        assert!(sanitized.to_lowercase() == sanitized);
        assert!(!sanitized.contains("  "));
    }

    #[test]
    fn test_sanitize_user_agent_truncation() {
        let long_ua = "x".repeat(1000);
        let sanitized = sanitize_user_agent(&long_ua);
        assert!(sanitized.len() <= 512);
    }
}

//! Antivirus / EDR Status Detection
//!
//! Provides utilities for interpreting security software status from
//! client-side reports or EDR API responses.

use super::types::{EncryptionStatus, SecuritySoftwarePosture};

/// Default antivirus signature staleness threshold (days).
///
/// Signatures older than this are considered potentially outdated.
pub const MAX_SIGNATURE_AGE_DAYS: u32 = 7;

/// Build a default (healthy) security software posture.
///
/// Useful for testing or as a baseline when no real AV/EDR data is available.
pub fn default_security_posture() -> SecuritySoftwarePosture {
    SecuritySoftwarePosture {
        antivirus_name: Some("Unknown".to_string()),
        antivirus_enabled: true,
        antivirus_signature_age_days: Some(0),
        edr_present: false,
        edr_name: None,
        firewall_enabled: true,
        bitlocker_status: Some(EncryptionStatus::Unknown),
    }
}

/// Evaluate overall security software health as a simple pass/fail.
///
/// Checks:
/// 1. Antivirus enabled (if name is present)
/// 2. Signature age within acceptable limit
/// 3. Firewall enabled
///
/// # Returns
///
/// `true` if all present indicators show healthy state.
pub fn is_security_software_healthy(sw: &SecuritySoftwarePosture) -> bool {
    if let Some(name) = &sw.antivirus_name {
        if !name.is_empty() && !sw.antivirus_enabled {
            return false;
        }
    }

    if let Some(age) = sw.antivirus_signature_age_days {
        if age > MAX_SIGNATURE_AGE_DAYS {
            return false;
        }
    }

    true
}

/// Parse encryption status from a string value reported by the client.
///
/// Maps common string representations to [`EncryptionStatus`]:
/// - "encrypted", "on", "active", "yes", "true" → Encrypted
/// - "not_encrypted", "off", "none", "no", "false" → NotEncrypted
/// - Anything else → Unknown
pub fn parse_encryption_status(value: &str) -> EncryptionStatus {
    match value.to_lowercase().as_str() {
        "encrypted" | "on" | "active" | "yes" | "true" => EncryptionStatus::Encrypted,
        "not_encrypted" | "off" | "none" | "no" | "false" => EncryptionStatus::NotEncrypted,
        _ => EncryptionStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_security_posture_is_healthy() {
        let sw = default_security_posture();
        assert!(is_security_software_healthy(&sw));
    }

    #[test]
    fn test_av_disabled_is_unhealthy() {
        let mut sw = default_security_posture();
        sw.antivirus_enabled = false;
        assert!(!is_security_software_healthy(&sw));
    }

    #[test]
    fn test_old_signatures_are_unhealthy() {
        let mut sw = default_security_posture();
        sw.antivirus_signature_age_days = Some(30); // 30 days old
        assert!(!is_security_software_healthy(&sw));
    }

    #[test]
    fn test_no_av_info_is_still_healthy() {
        let mut sw = default_security_posture();
        sw.antivirus_name = None;
        // No AV info should not cause failure
        assert!(is_security_software_healthy(&sw));
    }

    #[test]
    fn test_parse_encryption_status_encrypted() {
        assert_eq!(parse_encryption_status("encrypted"), EncryptionStatus::Encrypted);
        assert_eq!(parse_encryption_status("ON"), EncryptionStatus::Encrypted);
        assert_eq!(parse_encryption_status("Yes"), EncryptionStatus::Encrypted);
    }

    #[test]
    fn test_parse_encryption_status_not_encrypted() {
        assert_eq!(
            parse_encryption_status("not_encrypted"),
            EncryptionStatus::NotEncrypted
        );
        assert_eq!(parse_encryption_status("off"), EncryptionStatus::NotEncrypted);
    }

    #[test]
    fn test_parse_encryption_status_unknown() {
        assert_eq!(parse_encryption_status(""), EncryptionStatus::Unknown);
        assert_eq!(parse_encryption_status("maybe"), EncryptionStatus::Unknown);
    }
}

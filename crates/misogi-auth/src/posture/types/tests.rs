//! Unit tests for posture types

use super::*;
use chrono::Duration;

#[test]
fn test_os_platform_display() {
    assert_eq!(OsPlatform::Windows.to_string(), "windows");
    assert_eq!(OsPlatform::MacOS.to_string(), "macos");
    assert_eq!(OsPlatform::Linux.to_string(), "linux");
    assert_eq!(OsPlatform::Unknown("freebsd".to_string()).to_string(), "unknown(freebsd)");
}

#[test]
fn test_os_platform_equality() {
    assert_eq!(OsPlatform::Windows, OsPlatform::Windows);
    assert_ne!(OsPlatform::Windows, OsPlatform::MacOS);
}

#[test]
fn test_check_severity_display() {
    assert_eq!(CheckSeverity::Critical.to_string(), "critical");
    assert_eq!(CheckSeverity::Warning.to_string(), "warning");
    assert_eq!(CheckSeverity::Info.to_string(), "info");
}

#[test]
fn test_failure_action_display() {
    assert_eq!(FailureAction::Block.to_string(), "block");
    assert_eq!(FailureAction::Warn.to_string(), "warn");
    assert_eq!(FailureAction::Allow.to_string(), "allow");
}

#[test]
fn test_default_posture_policy() {
    let policy = PosturePolicy::default();
    assert!(policy.min_posture_score >= 50);
    assert!(policy.max_patch_age_days > 0);
    assert!(!policy.required_checks.is_empty());
    assert!(policy.os_requirements.contains_key(&OsPlatform::Windows));
    assert!(policy.os_requirements.contains_key(&OsPlatform::MacOS));
}

#[test]
fn test_encryption_status_equality() {
    assert_eq!(EncryptionStatus::Encrypted, EncryptionStatus::Encrypted);
    assert_ne!(EncryptionStatus::Encrypted, EncryptionStatus::NotEncrypted);
}

#[test]
fn test_device_posture_serialization_roundtrip() {
    let posture = DevicePosture {
        os_info: OsPosture {
            platform: OsPlatform::Windows,
            version: "10.0.19045".to_string(),
            build_number: "19045".to_string(),
            is_supported: true,
            minimum_required_version: None,
        },
        security_software: SecuritySoftwarePosture {
            antivirus_name: Some("Windows Defender".to_string()),
            antivirus_enabled: true,
            antivirus_signature_age_days: Some(2),
            edr_present: true,
            edr_name: Some("Microsoft Defender for Endpoint".to_string()),
            firewall_enabled: true,
            bitlocker_status: Some(EncryptionStatus::Encrypted),
        },
        patch_status: PatchStatus {
            last_patch_date: Some(Utc::now() - Duration::days(5)),
            days_since_last_patch: Some(5),
            critical_patches_missing: 0,
            is_compliant: true,
        },
        posture_score: 95,
        assessed_at: Utc::now(),
        checks: vec![
            PostureCheckResult {
                check_id: "os_supported".to_string(),
                check_name: "OS Version Supported".to_string(),
                passed: true,
                severity: CheckSeverity::Critical,
                details: "Windows 10 22H2 is supported".to_string(),
            },
        ],
    };

    let json = serde_json::to_string(&posture).unwrap();
    assert!(json.contains("Windows"));
    assert!(json.contains("95"));

    let deserialized: DevicePosture = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.posture_score, 95);
    assert_eq!(deserialized.os_info.platform, OsPlatform::Windows);
}

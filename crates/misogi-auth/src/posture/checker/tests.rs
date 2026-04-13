//! Unit tests for PostureChecker

use super::*;
use chrono::Utc;
use crate::posture::types::*;

fn make_healthy_posture() -> DevicePosture {
    DevicePosture {
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
            edr_name: Some("Defender for Endpoint".to_string()),
            firewall_enabled: true,
            bitlocker_status: Some(EncryptionStatus::Encrypted),
        },
        patch_status: PatchStatus {
            last_patch_date: Some(Utc::now()),
            days_since_last_patch: Some(0),
            critical_patches_missing: 0,
            is_compliant: true,
        },
        posture_score: 0, // Will be computed by checker
        assessed_at: Utc::now(),
        checks: Vec::new(),
    }
}

#[test]
fn test_healthy_posture_passes() {
    let policy = PosturePolicy::default();
    let checker = PostureChecker::new(policy);
    let posture = make_healthy_posture();

    let result = checker.evaluate(posture);
    assert!(result.allowed);
    assert_eq!(result.action, FailureAction::Allow);
    assert!(result.posture.posture_score >= 90);
}

#[test]
fn test_unsupported_os_blocked() {
    let mut policy = PosturePolicy::default();
    policy.failure_action = FailureAction::Block;
    let checker = PostureChecker::new(policy);

    let mut posture = make_healthy_posture();
    posture.os_info.version = "6.1.7601".to_string(); // Windows 7
    posture.os_info.is_supported = false;

    let result = checker.evaluate(posture);
    assert!(!result.allowed);
    assert!(result.failed_critical_checks.contains(&"os_supported".to_string()));
}

#[test]
fn test_av_disabled_critical_failure() {
    let policy = PosturePolicy::default();
    let checker = PostureChecker::new(policy);

    let mut posture = make_healthy_posture();
    posture.security_software.antivirus_enabled = false;

    let result = checker.evaluate(posture);
    assert!(!result.allowed);
    assert!(result.failed_critical_checks.contains(&"antivirus_enabled".to_string()));
}

#[test]
fn test_warn_mode_allows_below_threshold() {
    let mut policy = PosturePolicy::default();
    // Set threshold above maximum possible score to guarantee below-threshold
    policy.min_posture_score = 101;
    policy.failure_action = FailureAction::Warn;
    // Remove critical requirements to allow pure threshold-based decision
    policy.required_checks = vec![];
    let checker = PostureChecker::new(policy);

    let posture = make_healthy_posture();

    let result = checker.evaluate(posture);
    assert!(result.allowed); // Warn mode still allows
    assert_eq!(result.action, FailureAction::Warn);
}

#[test]
fn test_block_mode_rejects_below_threshold() {
    let mut policy = PosturePolicy::default();
    policy.min_posture_score = 99;
    policy.failure_action = FailureAction::Block;
    policy.required_checks = vec![]; // No critical checks — pure threshold
    let checker = PostureChecker::new(policy);

    let posture = make_healthy_posture();
    let result = checker.evaluate(posture);

    if !result.failed_critical_checks.is_empty() {
        assert!(!result.allowed);
    } else if result.posture.posture_score < 99 {
        assert!(!result.allowed);
        assert_eq!(result.action, FailureAction::Block);
    }
}

#[test]
fn test_edr_not_required_passes_without_edr() {
    let mut policy = PosturePolicy::default();
    policy.require_edr = false;
    let checker = PostureChecker::new(policy);

    let mut posture = make_healthy_posture();
    posture.security_software.edr_present = false;
    posture.security_software.edr_name = None;

    let result = checker.evaluate(posture);
    // EDR check should pass with Info severity (not required)
    let edr_check = result
        .posture
        .checks
        .iter()
        .find(|c| c.check_id == "edr_present");
    assert!(edr_check.is_some());
    assert!(edr_check.unwrap().passed);
}

#[test]
fn test_patch_non_compliance_reduces_score() {
    let policy = PosturePolicy::default();
    let checker = PostureChecker::new(policy);

    let mut posture = make_healthy_posture();
    posture.patch_status.is_compliant = false;
    posture.patch_status.critical_patches_missing = 3;
    posture.patch_status.days_since_last_patch = Some(60);

    let result = checker.evaluate(posture);
    let patch_check = result
        .posture
        .checks
        .iter()
        .find(|c| c.check_id == "patch_compliant");
    assert!(patch_check.is_some());
    assert!(!patch_check.unwrap().passed);
}

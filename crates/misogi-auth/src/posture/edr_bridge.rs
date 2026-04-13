//! EDR → Posture Data Bridge
//!
//! Converts vendor-specific EDR posture data ([`EdrDevicePosture`] from Defender/Falcon)
//! into Misogi's canonical [`DevicePosture`] format consumed by [`PostureChecker`].
//!
//! # Two Modes
//!
//! | Mode               | Source                  | Confidence |
//! |--------------------|-------------------------|------------|
//! | **EDR-sourced**    | Defender ATP / Falcon   | High       |
//! | **Client-report**  | User-Agent + Fingerprint| Low        |
//!
//! When no EDR provider is configured, the bridge falls back to client-reported
//! posture assessment with reduced confidence scoring.

use chrono::{DateTime, Utc};
use tracing::{debug, warn};

use crate::device::fingerprint::DeviceFingerprint;

#[cfg(any(feature = "defender", feature = "falcon"))]
use crate::edr::models::{EdrDevicePosture, EdrOsInfo};

use super::types::{
    CheckSeverity,
    DevicePosture,
    EncryptionStatus,
    OsPlatform,
    OsPosture,
    PatchStatus,
    PostureCheckResult,
    SecuritySoftwarePosture,
};

// ---------------------------------------------------------------------------
// Public API — Client-Report Mode (always available)
// ---------------------------------------------------------------------------

/// Build a best-effort [`DevicePosture`] from client-reported data only.
///
/// Used when no EDR provider is configured (`client-report-only` mode).
/// Relies on:
/// - User-Agent parsed OS information ([`OsPosture`])
/// - Device fingerprint entropy as a trust signal ([`DeviceFingerprint`])
///
/// # Confidence Note
///
/// Client-reported data is inherently less reliable than EDR-sourced telemetry
/// because it cannot verify actual AV/patch/encryption status. This is reflected
/// in:
/// - Lower base posture score (50–100 vs 0–100 range)
/// - An informational check flagging the mode
/// - `security_software.antivirus_name = None` (unknown)
pub fn build_client_report_posture(
    detected_os: &OsPosture,
    fingerprint: &DeviceFingerprint,
) -> DevicePosture {
    let total_ent = fingerprint.total_entropy();
    let entropy_bonus = ((total_ent * 5.0) as u8).min(50);

    debug!(
        platform = %detected_os.platform,
        total_entropy = total_ent,
        bonus = entropy_bonus,
        "Building client-report-only posture (no EDR integration)"
    );

    DevicePosture {
        os_info: OsPosture {
            platform: detected_os.platform.clone(),
            version: detected_os.version.clone(),
            build_number: detected_os.build_number.clone(),
            is_supported: detected_os.is_supported,
            minimum_required_version: None,
        },
        security_software: SecuritySoftwarePosture {
            antivirus_name: None,
            antivirus_enabled: true,
            antivirus_signature_age_days: None,
            edr_present: false,
            edr_name: None,
            firewall_enabled: true,
            bitlocker_status: None,
        },
        patch_status: PatchStatus {
            last_patch_date: None,
            days_since_last_patch: None,
            critical_patches_missing: 0,
            is_compliant: true,
        },
        posture_score: 50u8.saturating_add(entropy_bonus),
        assessed_at: Utc::now(),
        checks: vec![PostureCheckResult {
            check_id: "client_report_mode".into(),
            check_name: "Client Report Mode".into(),
            passed: true,
            severity: CheckSeverity::Info,
            details: "Posture assessed from client-reported data; \
                      no EDR integration available. \
                      AV/patch/encryption status could not be verified."
                .into(),
        }],
    }
}

// ---------------------------------------------------------------------------
// Public API — EDR-Sourced Mode (requires defender or falcon feature)
// ---------------------------------------------------------------------------

#[cfg(any(feature = "defender", feature = "falcon"))]
/// Convert an EDR provider's device posture into the canonical [`DevicePosture`] format.
///
/// Maps EDR-specific fields (Defender for Endpoint / CrowdStrike Falcon) to
/// Misogi's generic posture model so that [`super::checker::PostureChecker`]
/// can evaluate them uniformly regardless of which EDR backend is active.
///
/// # Field Mapping
///
/// | EDR Field (`EdrDevicePosture`)    | `DevicePosture` Field           | Logic                           |
/// |-----------------------------------|----------------------------------|---------------------------------|
/// | `os_info.platform`                | `os_info.platform`              | String → [`OsPlatform`] enum    |
/// | `os_info.version`                 | `os_info.version`               | Direct copy                     |
/// | `has_active_threats`              | `security_software.av_enabled`  | Inverted (!threats)             |
/// | `has_active_threats`              | `security_software.edr_present` | Implied true when EDR responds  |
/// | `sensor_healthy`                  | `security_software.edr_present` | Must be healthy                  |
/// | `last_seen_at`                    | `patch_status.last_patch_date`  | Infer contact recency            |
/// | `active_detection_count`          | `patch_status.critical_missing` | Detections as critical count     |
///
/// # Parameters
///
/// - `edr`: Raw posture data returned by an EDR provider implementation.
/// - `detected_os`: OS info parsed from the client's User-Agent header by
///   [`super::os_detector::parse_os_from_user_agent`]. Used as primary source;
///   falls back to EDR's own `os_info` if `None`.
pub fn convert_edr_to_posture(
    edr: &EdrDevicePosture,
    detected_os: Option<&OsPosture>,
) -> DevicePosture {
    let os_info = resolve_os_info(edr, detected_os);
    let sec_soft = build_security_from_edr(edr);
    let patch_status = build_patch_from_edr(edr);
    let checks = build_checks_from_edr(edr);
    let base_score = compute_base_score(edr);

    debug!(
        device_id = %edr.device_id,
        score = base_score,
        threats = edr.has_active_threats,
        sensor_healthy = edr.sensor_healthy,
        "EDR posture converted to canonical format"
    );

    DevicePosture {
        os_info,
        security_software: sec_soft,
        patch_status,
        posture_score: base_score,
        assessed_at: Utc::now(),
        checks,
    }
}

// ---------------------------------------------------------------------------
// Internal: OS Info Resolution (EDR-sourced)
// ---------------------------------------------------------------------------

#[cfg(any(feature = "defender", feature = "falcon"))]
fn resolve_os_info(edr: &EdrDevicePosture, detected_os: Option<&OsPosture>) -> OsPosture {
    if let Some(os) = detected_os {
        return OsPosture {
            platform: os.platform.clone(),
            version: os.version.clone(),
            build_number: os.build_number.clone().unwrap_or_default(),
            is_supported: os.is_supported,
            minimum_required_version: None,
        };
    }

    parse_edr_os_fallback(edr.os_info.as_ref())
}

#[cfg(any(feature = "defender", feature = "falcon"))]
fn parse_edr_os_fallback(edr_os: Option<&EdrOsInfo>) -> OsPosture {
    match edr_os {
        Some(info) => OsPosture {
            platform: map_platform_string(&info.platform),
            version: info.version.clone(),
            build_number: info.clone().build.unwrap_or_default(),
            is_supported: true,
            minimum_required_version: None,
        },
        no_info => {
            warn!("No OS info from EDR or User-Agent; defaulting to Unknown");
            OsPosture {
                platform: OsPlatform::Unknown("edr-unavailable".into()),
                version: String::new(),
                build_number: String::new(),
                is_supported: false,
                minimum_required_version: None,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Internal: Platform String Mapping
// ---------------------------------------------------------------------------

#[cfg(any(feature = "defender", feature = "falcon"))]
fn map_platform_string(platform: &str) -> OsPlatform {
    match platform.to_lowercase().as_str() {
        s if s.contains("windows") => OsPlatform::Windows,
        s if s.contains("mac") || s.contains("darwin") => OsPlatform::MacOS,
        s if s.contains("linux") => OsPlatform::Linux,
        s if s.contains("ios") || s.contains("iphone") || s.contains("ipad") => OsPlatform::Ios,
        s if s.contains("android") => OsPlatform::Android,
        other => OsPlatform::Unknown(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Internal: Security Software from EDR
// ---------------------------------------------------------------------------

#[cfg(any(feature = "defender", feature = "falcon"))]
fn build_security_from_edr(edr: &EdrDevicePosture) -> SecuritySoftwarePosture {
    SecuritySoftwarePosture {
        antivirus_name: None,
        antivirus_enabled: !edr.has_active_threats,
        antivirus_signature_age_days: Some(0),
        edr_present: edr.sensor_healthy,
        edr_name: if edr.sensor_healthy {
            Some("EDR Integrated".into())
        } else {
            None
        },
        firewall_enabled: edr.sensor_healthy,
        bitlocker_status: Some(EncryptionStatus::Encrypted),
    }
}

// ---------------------------------------------------------------------------
// Internal: Patch Status from EDR
// ---------------------------------------------------------------------------

#[cfg(any(feature = "defender", feature = "falcon"))]
fn build_patch_from_edr(edr: &EdrDevicePosture) -> PatchStatus {
    let last_seen = edr.last_seen_at.unwrap_or_else(Utc::now);
    let days_since_contact = utc_days_since(last_seen);
    let critical_missing = if edr.has_active_threats {
        edr.active_detection_count.min(10) as usize
    } else {
        0
    };

    PatchStatus {
        last_patch_date: Some(last_seen),
        days_since_last_patch: Some(days_since_contact),
        critical_patches_missing: critical_missing,
        is_compliant: days_since_contact <= 30 && !edr.has_active_threats && edr.sensor_healthy,
    }
}

#[cfg(any(feature = "defender", feature = "falcon"))]
fn utc_days_since(since: DateTime<Utc>) -> u64 {
    (Utc::now() - since).num_days().max(0) as u64
}

// ---------------------------------------------------------------------------
// Internal: Check Results from EDR
// ---------------------------------------------------------------------------

#[cfg(any(feature = "defender", feature = "falcon"))]
fn build_checks_from_edr(edr: &EdrDevicePosture) -> Vec<PostureCheckResult> {
    let mut checks = Vec::with_capacity(3);

    checks.push(PostureCheckResult {
        check_id: "sensor_healthy".into(),
        check_name: "EDR Sensor Health".into(),
        passed: edr.sensor_healthy,
        severity: CheckSeverity::Critical,
        details: if edr.sensor_healthy {
            "EDR sensor reporting normally".into()
        } else {
            "EDR sensor unhealthy or offline".into()
        },
    });

    checks.push(PostureCheckResult {
        check_id: "no_active_threats".into(),
        check_name: "Active Threats".into(),
        passed: !edr.has_active_threats,
        severity: CheckSeverity::Critical,
        details: if edr.has_active_threats {
            format!("{} active detection(s) on device", edr.active_detection_count)
        } else {
            "No active threats detected".into()
        },
    });

    checks.push(PostureCheckResult {
        check_id: "edr_contact_freshness".into(),
        check_name: "EDR Contact Freshness".into(),
        passed: edr
            .last_seen_at
            .map(|t| utc_days_since(t) <= 30)
            .unwrap_or(false),
        severity: CheckSeverity::Warning,
        details: edr
            .last_seen_at
            .map(|t| format!("Last EDR contact: {} day(s) ago", utc_days_since(t)))
            .unwrap_or_else(|| "Never contacted EDR".into()),
    });

    checks
}

// ---------------------------------------------------------------------------
// Internal: Base Score Computation
// ---------------------------------------------------------------------------

#[cfg(any(feature = "defender", feature = "falcon"))]
fn compute_base_score(edr: &EdrDevicePosture) -> u8 {
    let mut score: u8 = 100;

    if !edr.sensor_healthy {
        score = score.saturating_sub(40);
    }

    if edr.has_active_threats {
        let threat_penalty = (edr.active_detection_count.min(5) as u8) * 10;
        score = score.saturating_sub(threat_penalty);
    }

    if let Some(last_seen) = edr.last_seen_at {
        let stale_days = utc_days_since(last_seen);
        if stale_days > 30 {
            score = score.saturating_sub(20);
        } else if stale_days > 14 {
            score = score.saturating_sub(10);
        }
    } else {
        score = score.saturating_sub(30);
    }

    score.max(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::fingerprint::{FingerprintSignal, ScreenResolution};

    fn make_test_fp(ua_entropy: f64, confidence: f64) -> DeviceFingerprint {
        DeviceFingerprint {
            user_agent: FingerprintSignal {
                value_hash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
                entropy_bits: ua_entropy,
                is_stable: true,
            },
            canvas_hash: None,
            screen_resolution: ScreenResolution::new(1920, 1080, 24, 100),
            collected_at: Utc::now(),
            confidence,
        }
    }

    // ===================================================================
    // Client-Report Mode Tests (always available)
    // ===================================================================

    #[test]
    fn test_build_client_report_basic() {
        let detected = OsPosture {
            platform: OsPlatform::Windows,
            version: "10.0".into(),
            build_number: "19045".into(),
            is_supported: true,
            minimum_required_version: None,
        };

        let fp = make_test_fp(8.0, 0.9);
        let posture = build_client_report_posture(&detected, &fp);

        assert_eq!(posture.os_info.platform, OsPlatform::Windows);
        assert!(!posture.security_software.edr_present);
        assert!(posture.posture_score >= 50);
        assert!(posture.posture_score <= 100);

        let cr_check = posture
            .checks
            .iter()
            .find(|c| c.check_id == "client_report_mode");
        assert!(cr_check.is_some());
        assert!(cr_check.unwrap().passed);
    }

    #[test]
    fn test_high_entropy_increases_score() {
        let detected = OsPosture {
            platform: OsPlatform::Linux,
            version: "5.15".into(),
            build_number: String::new(),
            is_supported: true,
            minimum_required_version: None,
        };

        let low_fp = make_test_fp(2.0, 0.6);
        let high_fp = make_test_fp(12.0, 0.95);

        let low_posture = build_client_report_posture(&detected, &low_fp);
        let high_posture = build_client_report_posture(&detected, &high_fp);

        assert!(high_posture.posture_score > low_posture.posture_score);
    }

    #[test]
    fn test_canvas_hash_adds_entropy() {
        let detected = OsPosture {
            platform: OsPlatform::MacOS,
            version: "14.0".into(),
            build_number: "23A344".into(),
            is_supported: true,
            minimum_required_version: None,
        };

        let mut without_canvas = make_test_fp(8.0, 0.85);
        without_canvas.canvas_hash = None;

        let mut with_canvas = make_test_fp(8.0, 0.85);
        with_canvas.canvas_hash = Some(FingerprintSignal {
            value_hash: "ffffeeeeddddccccbbbbaaaa9999888877776666555544443333222211110000".into(),
            entropy_bits: 12.0,
            is_stable: false,
        });

        let p1 = build_client_report_posture(&detected, &without_canvas);
        let p2 = build_client_report_posture(&detected, &with_canvas);

        assert!(p2.posture_score > p1.posture_score);
    }

    // ===================================================================
    // Platform String Mapping Tests (EDR mode only)
    // ===================================================================

    #[test]
    #[cfg(any(feature = "defender", feature = "falcon"))]
    fn test_platform_string_mapping() {
        assert_eq!(map_platform_string("Windows 10"), OsPlatform::Windows);
        assert_eq!(map_platform_string("macOS"), OsPlatform::MacOS);
        assert_eq!(map_platform_string("Linux"), OsPlatform::Linux);
        assert_eq!(map_platform_string("iOS"), OsPlatform::Ios);
        assert_eq!(map_platform_string("Android 14"), OsPlatform::Android);
        assert!(matches!(map_platform_string("FreeBSD"), OsPlatform::Unknown(_)));
    }

    // ===================================================================
    // EDR-Sourced Mode Tests (require defender or falcon feature)
    // ===================================================================

    #[cfg(any(feature = "defender", feature = "falcon"))]
    fn make_healthy_edr() -> EdrDevicePosture {
        EdrDevicePosture {
            device_id: "test-device-001".into(),
            hostname: Some("DESKTOP-TEST".into()),
            has_active_threats: false,
            active_detection_count: 0,
            sensor_healthy: true,
            last_seen_at: Some(Utc::now()),
            os_info: Some(EdrOsInfo {
                platform: "Windows".into(),
                version: "10.0.19045".into(),
                build: Some("19045".into()),
            }),
            raw_response: None,
        }
    }

    #[test]
    #[cfg(any(feature = "defender", feature = "falcon"))]
    fn test_convert_healthy_edr_to_posture() {
        let edr = make_healthy_edr();
        let posture = convert_edr_to_posture(&edr, None);

        assert_eq!(posture.os_info.platform, OsPlatform::Windows);
        assert!(posture.security_software.edr_present);
        assert!(posture.security_software.antivirus_enabled);
        assert!(posture.patch_status.is_compliant);
        assert!(posture.posture_score >= 90);
    }

    #[test]
    #[cfg(any(feature = "defender", feature = "falcon"))]
    fn test_convert_with_detected_os_precedence() {
        let edr = make_healthy_edr();
        let detected = OsPosture {
            platform: OsPlatform::MacOS,
            version: "14.0".into(),
            build_number: Some("23A344".into()),
            is_supported: true,
            minimum_required_version: None,
        };

        let posture = convert_edr_to_posture(&edr, Some(&detected));

        assert_eq!(posture.os_info.platform, OsPlatform::MacOS);
        assert_eq!(posture.os_info.version, "14.0");
    }

    #[test]
    #[cfg(any(feature = "defender", feature = "falcon"))]
    fn test_active_threats_reduces_score() {
        let mut edr = make_healthy_edr();
        edr.has_active_threats = true;
        edr.active_detection_count = 3;

        let posture = convert_edr_to_posture(&edr, None);

        assert!(!posture.security_software.antivirus_enabled);
        assert!(posture.posture_score < 90);
        assert_eq!(posture.patch_status.critical_patches_missing, 3);
    }

    #[test]
    #[cfg(any(feature = "defender", feature = "falcon"))]
    fn test_unhealthy_sensor_heavily_penalized() {
        let mut edr = make_healthy_edr();
        edr.sensor_healthy = false;

        let posture = convert_edr_to_posture(&edr, None);

        assert!(!posture.security_software.edr_present);
        assert!(posture.posture_score <= 60);
    }

    #[test]
    #[cfg(any(feature = "defender", feature = "falcon"))]
    fn test_stale_device_penalized() {
        let mut edr = make_healthy_edr();
        edr.last_seen_at = Some(Utc::now() - chrono::Duration::days(45));

        let posture = convert_edr_to_posture(&edr, None);

        assert!(posture.posture_score < 90);
    }

    #[test]
    #[cfg(any(feature = "defender", feature = "falcon"))]
    fn test_no_os_info_defaults_to_unknown() {
        let mut edr = make_healthy_edr();
        edr.os_info = None;

        let posture = convert_edr_to_posture(&edr, None);

        assert!(matches!(posture.os_info.platform, OsPlatform::Unknown(_)));
        assert!(!posture.os_info.is_supported);
    }
}

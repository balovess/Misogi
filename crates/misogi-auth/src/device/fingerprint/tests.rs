//! Unit tests for Device Fingerprint module

use super::*;
use chrono::Duration;

// ===========================================================================
// Test: ScreenResolution
// ===========================================================================

#[test]
fn test_screen_resolution_rounding() {
    let res = ScreenResolution::new(1920, 1080, 24, 100);
    assert_eq!(res.width, 1900); // (1920+50)/100*100 = 1900
    assert_eq!(res.height, 1100); // (1080+50)/100*100 = 1100
}

#[test]
fn test_screen_resolution_display() {
    let res = ScreenResolution::new(1920, 1080, 24, 100);
    let display = format!("{res}");
    assert!(display.contains("1900"));
    assert!(display.contains("1100"));
}

#[test]
fn test_screen_resolution_high_dpi() {
    let normal = ScreenResolution::new(1920, 1080, 24, 100);
    let retina = ScreenResolution::new(1920, 1080, 24, 200);
    assert!(!normal.is_high_dpi());
    assert!(retina.is_high_dpi());
}

#[test]
fn test_screen_resolution_megapixels() {
    let res = ScreenResolution::new(1920, 1080, 24, 100);
    let mp = res.megapixels();
    // ~2.07 MP (1900 * 1100 / 1M)
    assert!((mp - 2.09).abs() < 0.1);
}

#[test]
fn test_screen_resolution_equality() {
    let a = ScreenResolution::new(1920, 1080, 24, 100);
    let b = ScreenResolution::new(1920, 1080, 24, 100);
    let c = ScreenResolution::new(2560, 1440, 24, 100);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ===========================================================================
// Test: FingerprintSignal
// ===========================================================================

#[test]
fn test_fingerprint_signal_new() {
    let signal = FingerprintSignal::new(
        "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd".to_string(),
        8.0,
        true,
    );
    assert!(signal.is_stable);
    assert!((signal.entropy_bits - 8.0).abs() < f64::EPSILON);
}

#[test]
fn test_fingerprint_signal_well_formed_valid() {
    let valid_hash = "a".repeat(64); // 64 hex chars
    let signal = FingerprintSignal::new(valid_hash, 8.0, true);
    assert!(signal.is_well_formed());
}

#[test]
fn test_fingerprint_signal_well_formed_invalid_length() {
    let short_hash = "abc".to_string();
    let signal = FingerprintSignal::new(short_hash, 8.0, true);
    assert!(!signal.is_well_formed());
}

#[test]
fn test_fingerprint_signal_well_formed_invalid_chars() {
    let invalid_hash = "g".repeat(64); // 'g' is not a hex digit
    let signal = FingerprintSignal::new(invalid_hash, 8.0, true);
    assert!(!signal.is_well_formed());
}

// ===========================================================================
// Test: DeviceFingerprint
// ===========================================================================

fn make_test_fingerprint(confidence: f64) -> DeviceFingerprint {
    DeviceFingerprint {
        user_agent: FingerprintSignal::new("a".repeat(64), 8.0, true),
        canvas_hash: Some(FingerprintSignal::new("b".repeat(64), 12.0, false)),
        screen_resolution: ScreenResolution::new(1920, 1080, 24, 100),
        collected_at: Utc::now(),
        confidence,
    }
}

#[test]
fn test_device_id_computation_produces_fixed_length() {
    let fp = make_test_fingerprint(0.85);
    let secret = b"test-secret-key-for-unit-tests-only";
    let device_id = fp.compute_device_id(secret);

    assert_eq!(device_id.len(), DEVICE_ID_HEX_LENGTH);
    assert!(device_id.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_device_id_deterministic_for_same_input() {
    let fp = make_test_fingerprint(0.85);
    let secret = b"deterministic-test-key";

    let id1 = fp.compute_device_id(secret);
    let id2 = fp.compute_device_id(secret);

    assert_eq!(id1, id2, "Same input must produce same device ID");
}

#[test]
fn test_device_id_different_for_different_secrets() {
    let fp = make_test_fingerprint(0.85);

    let id1 = fp.compute_device_id(b"secret-alpha");
    let id2 = fp.compute_device_id(b"secret-beta");

    assert_ne!(
        id1, id2,
        "Different secrets must produce different device IDs"
    );
}

#[test]
fn test_similarity_identical_fingerprints() {
    let fp = make_test_fingerprint(0.85);
    let similarity = fp.similarity(&fp);

    assert!(
        (similarity - 1.0).abs() < f64::EPSILON,
        "Identical fingerprints should have similarity 1.0"
    );
}

#[test]
fn test_similarity_different_user_agent() {
    let fp_a = make_test_fingerprint(0.85);
    let mut fp_b = fp_a.clone();
    fp_b.user_agent.value_hash = "z".repeat(64); // Different UA hash

    let similarity = fp_a.similarity(&fp_b);

    // UA has weight 0.4, so without UA match we lose that weight
    // canvas (0.3) + screen (0.3) = 0.6 out of total 1.0
    assert!(
        similarity > 0.5 && similarity < 0.7,
        "Expected partial match (~0.6), got {similarity}"
    );
}

#[test]
fn test_is_valid_good_fingerprint() {
    let fp = make_test_fingerprint(0.85);
    assert!(fp.is_valid());
}

#[test]
fn test_is_valid_low_confidence_rejected() {
    let fp = make_test_fingerprint(0.3); // Below MIN_CONFIDENCE_THRESHOLD
    assert!(!fp.is_valid());
}

#[test]
fn test_is_valid_short_ua_rejected() {
    let mut fp = make_test_fingerprint(0.85);
    fp.user_agent.value_hash = "short".to_string(); // < MIN_UA_HASH_LENGTH
    assert!(!fp.is_valid());
}

#[test]
fn test_is_valid_future_timestamp_rejected() {
    let mut fp = make_test_fingerprint(0.85);
    fp.collected_at = Utc::now() + Duration::hours(1); // Far in future
    assert!(!fp.is_valid());
}

#[test]
fn test_signal_count_with_canvas() {
    let fp = make_test_fingerprint(0.85);
    assert_eq!(fp.signal_count(), 3); // ua + canvas + screen
}

#[test]
fn test_signal_count_without_canvas() {
    let mut fp = make_test_fingerprint(0.85);
    fp.canvas_hash = None;
    assert_eq!(fp.signal_count(), 2); // ua + screen only
}

#[test]
fn test_total_entropy_calculation() {
    let fp = make_test_fingerprint(0.85);
    // UA: 8.0 + Canvas: 12.0 + Screen: 6.0 = 26.0 bits
    let entropy = fp.total_entropy();
    assert!((entropy - 26.0).abs() < 0.01);
}

#[test]
fn test_total_entropy_without_canvas() {
    let mut fp = make_test_fingerprint(0.85);
    fp.canvas_hash = None;
    // UA: 8.0 + Screen: 6.0 = 14.0 bits
    let entropy = fp.total_entropy();
    assert!((entropy - 14.0).abs() < 0.01);
}

// ===========================================================================
// Test: Constants
// ===========================================================================

#[test]
fn test_constants_are_reasonable() {
    assert!(MIN_CONFIDENCE_THRESHOLD > 0.0 && MIN_CONFIDENCE_THRESHOLD <= 1.0);
    assert!(MIN_UA_HASH_LENGTH >= 4);
    assert!(DEFAULT_ROTATION_TTL_HOURS >= 24);
    assert_eq!(DEVICE_ID_HEX_LENGTH, 64); // SHA-256 = 32 bytes = 64 hex chars
}

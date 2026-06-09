//! Comprehensive unit tests for integrity configuration types.
//!
//! Covers TOML parsing, factory methods, validation logic, serialization
//! round-trips, and file-based loading for [`IntegrityConfig`] and its
//! sub-configuration structs ([`RepairConfig`], [`ResumeConfig`],
//! [`VerificationConfig`]).

use std::path::PathBuf;

use super::*;

// ===========================================================================
// TOML Parsing Tests
// ===========================================================================

/// Parse a fully-specified integrity configuration from TOML and verify
/// all fields are correctly populated.
#[test]
fn test_parse_valid_full_toml_config() {
    let toml_str = r#"
        enabled = true
        hash_algorithm = "sha256"
        chunk_linking = true
        anti_replay_nonce = true

        [repair]
        auto_repair = true
        max_repair_attempts = 5
        repair_timeout_secs = 60
        parallel_repair = false

        [resume]
        checkpoint_interval_chunks = 25
        resume_from_checkpoint = true
        session_persistence_path = "/var/lib/misogi/sessions"

        [verification]
        post_transfer_full_verify = true
        zero_tolerance = true
    "#;

    let config = IntegrityConfig::from_toml_str(toml_str).expect("valid TOML must parse");

    assert!(config.enabled);
    assert_eq!(config.hash_algorithm, "sha256");
    assert!(config.chunk_linking);
    assert!(config.anti_replay_nonce);

    // Repair sub-config.
    assert!(config.repair.auto_repair);
    assert_eq!(config.repair.max_repair_attempts, 5);
    assert_eq!(config.repair.repair_timeout_secs, 60);
    assert!(!config.repair.parallel_repair);

    // Resume sub-config.
    assert_eq!(config.resume.checkpoint_interval_chunks, 25);
    assert!(config.resume.resume_from_checkpoint);
    assert_eq!(
        config.resume.session_persistence_path,
        "/var/lib/misogi/sessions"
    );

    // Verification sub-config.
    assert!(config.verification.post_transfer_full_verify);
    assert!(config.verification.zero_tolerance);
}

/// Parse a minimal configuration with only `enabled` set; all other fields
/// should receive their default values via serde `#[serde(default)]`.
#[test]
fn test_parse_minimal_config_defaults_fallback() {
    let toml_str = r#"
        enabled = true
    "#;

    let config = IntegrityConfig::from_toml_str(toml_str).expect("minimal TOML must parse");

    // Explicitly set field.
    assert!(config.enabled);

    // Default-fallback fields.
    assert_eq!(config.hash_algorithm, "sha256"); // DefaultImpl value
    assert!(config.chunk_linking); // DefaultImpl value
    assert!(config.anti_replay_nonce); // DefaultImpl value
    assert_eq!(config.repair.max_repair_attempts, 3); // RepairConfig default
    assert_eq!(config.resume.checkpoint_interval_chunks, 50); // ResumeConfig default
}

/// When `hash_algorithm` is omitted entirely, it must fall back to the
/// canonical default "sha256" (not cause a missing-field error).
#[test]
fn test_missing_hash_algorithm_falls_back_to_sha256() {
    let toml_str = r#"
        enabled = true
        chunk_linking = true
    "#;

    let config = IntegrityConfig::from_toml_str(toml_str).expect("missing algo => default");

    assert_eq!(config.hash_algorithm, "sha256");
}

/// An unrecognized hash algorithm string must produce a validation error
/// referencing the unsupported algorithm name.
#[test]
fn test_invalid_hash_algorithm_validation_error() {
    let toml_str = r#"
        enabled = true
        hash_algorithm = "MD5"
    "#;

    let result = IntegrityConfig::from_toml_str(toml_str);
    assert!(
        result.is_err(),
        "MD5 must be rejected as an unsupported algorithm"
    );

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unsupported hash algorithm"),
        "error message must mention 'unsupported hash algorithm': {msg}"
    );
    assert!(
        msg.contains("MD5"),
        "error message must include the rejected algorithm: {msg}"
    );
}

/// Setting `repair_timeout_secs` to zero while `auto_repair` is enabled
/// must trigger a validation failure (zero timeout makes repair impossible).
#[test]
fn test_zero_repair_timeout_with_auto_repair_enabled() {
    let toml_str = r#"
        enabled = true
        hash_algorithm = "sha256"

        [repair]
        auto_repair = true
        repair_timeout_secs = 0
    "#;

    let result = IntegrityConfig::from_toml_str(toml_str);
    assert!(result.is_err(), "zero timeout + auto_repair must fail");

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("repair_timeout_secs"),
        "error must reference repair_timeout_secs: {msg}"
    );
}

// ===========================================================================
// Factory Method Tests
// ===========================================================================

/// The `sha256_default()` factory must return a configuration identical to
/// `IntegrityConfig::default()` with SHA-256 as the hash algorithm.
#[test]
fn test_sha256_default_factory_produces_expected_values() {
    let config = IntegrityConfig::sha256_default();

    assert!(config.enabled);
    assert_eq!(config.hash_algorithm, "sha256");
    assert!(config.chunk_linking);
    assert!(config.anti_replay_nonce);
    assert!(config.repair.auto_repair);
    assert_eq!(config.repair.max_repair_attempts, 3);
    assert_eq!(config.repair.repair_timeout_secs, 30);
    assert!(!config.repair.parallel_repair);
    assert!(config.resume.resume_from_checkpoint);
    assert_eq!(config.resume.checkpoint_interval_chunks, 50);
    assert!(config.verification.post_transfer_full_verify);
    assert!(!config.verification.zero_tolerance);

    // Validation must pass for factory output.
    config.validate().expect("sha256_default must be valid");
}

/// The `high_throughput()` factory must use BLAKE3, disable chunk linking,
/// enable parallel repair, use shorter timeouts, and disable zero-tolerance.
#[test]
fn test_high_throughput_factory_has_relaxed_settings() {
    let config = IntegrityConfig::high_throughput();

    assert_eq!(config.hash_algorithm, "blake3");
    assert!(!config.chunk_linking, "chunk linking disabled for speed");
    assert!(
        config.repair.parallel_repair,
        "parallel repair for throughput"
    );
    assert_eq!(config.repair.max_repair_attempts, 2, "fewer retries");
    assert_eq!(config.repair.repair_timeout_secs, 15, "shorter timeout");
    assert_eq!(
        config.resume.checkpoint_interval_chunks, 100,
        "less frequent checkpoints"
    );
    assert!(
        !config.verification.zero_tolerance,
        "tolerate issues for speed"
    );

    // Must still be valid.
    config.validate().expect("high_throughput must be valid");
}

/// The `maximum_security()` factory must use SHA-512, enable all safety
/// features, use sequential (auditable) repair, frequent checkpoints, and
/// enforce zero-tolerance mode.
#[test]
fn test_maximum_security_factory_has_strictest_settings() {
    let config = IntegrityConfig::maximum_security();

    assert_eq!(config.hash_algorithm, "sha512");
    assert!(config.chunk_linking, "chain linking for tamper detection");
    assert!(config.anti_replay_nonce, "nonce for replay protection");
    assert!(!config.repair.parallel_repair, "sequential for audit trail");
    assert_eq!(config.repair.max_repair_attempts, 5, "more retry attempts");
    assert_eq!(config.repair.repair_timeout_secs, 60, "longer timeout");
    assert_eq!(
        config.resume.checkpoint_interval_chunks, 10,
        "frequent checkpoints"
    );
    assert!(config.verification.zero_tolerance, "any corruption = abort");

    // Must still be valid.
    config.validate().expect("maximum_security must be valid");
}

// ===========================================================================
// Serialization Round-Trip Tests
// ===========================================================================

/// Serializing to TOML then deserializing back must yield an equivalent
/// configuration (structural equality on all fields).
#[test]
fn test_serialize_deserialize_roundtrip_produces_equal_config() {
    let original = IntegrityConfig::maximum_security();

    let toml_str = toml::to_string(&original).expect("serialization must succeed");
    let restored: IntegrityConfig =
        toml::from_str(&toml_str).expect("deserialization must succeed");

    assert_eq!(restored.enabled, original.enabled);
    assert_eq!(restored.hash_algorithm, original.hash_algorithm);
    assert_eq!(restored.chunk_linking, original.chunk_linking);
    assert_eq!(restored.anti_replay_nonce, original.anti_replay_nonce);
    assert_eq!(restored.repair.auto_repair, original.repair.auto_repair);
    assert_eq!(
        restored.repair.max_repair_attempts,
        original.repair.max_repair_attempts
    );
    assert_eq!(
        restored.repair.repair_timeout_secs,
        original.repair.repair_timeout_secs
    );
    assert_eq!(
        restored.repair.parallel_repair,
        original.repair.parallel_repair
    );
    assert_eq!(
        restored.resume.checkpoint_interval_chunks,
        original.resume.checkpoint_interval_chunks
    );
    assert_eq!(
        restored.resume.resume_from_checkpoint,
        original.resume.resume_from_checkpoint
    );
    assert_eq!(
        restored.resume.session_persistence_path,
        original.resume.session_persistence_path
    );
    assert_eq!(
        restored.verification.post_transfer_full_verify,
        original.verification.post_transfer_full_verify
    );
    assert_eq!(
        restored.verification.zero_tolerance,
        original.verification.zero_tolerance
    );
}

// ===========================================================================
// File Loading Tests
// ===========================================================================

/// `load_from_file()` must successfully read and parse a valid TOML file
/// from disk, producing the expected configuration values.
#[test]
fn test_load_from_file_success() {
    let toml_content = r#"
        enabled = true
        hash_algorithm = "blake3"
        chunk_linking = false

        [repair]
        auto_repair = false
        max_repair_attempts = 1
        repair_timeout_secs = 10
        parallel_repair = true

        [resume]
        checkpoint_interval_chunks = 200
        resume_from_checkpoint = false
        session_persistence_path = "/tmp/misogi_test"

        [verification]
        post_transfer_full_verify = false
        zero_tolerance = false
    "#;

    // Write a temporary file using tempfile crate (available in workspace).
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("integrity_test.toml");
    std::fs::write(&path, toml_content).expect("write temp config file");

    let config = IntegrityConfig::load_from_file(&path).expect("loading valid file must succeed");

    assert!(config.enabled);
    assert_eq!(config.hash_algorithm, "blake3");
    assert!(!config.chunk_linking);
    assert!(!config.repair.auto_repair);
    assert_eq!(config.repair.max_repair_attempts, 1);
    assert!(!config.resume.resume_from_checkpoint);
    assert!(!config.verification.post_transfer_full_verify);
}

/// `load_from_file()` must return an `IoError` when the target file does
/// not exist on the filesystem.
#[test]
fn test_load_from_file_not_found_returns_io_error() {
    let nonexistent = PathBuf::from("/tmp/misogi_nonexistent_config_99999.toml");

    let result = IntegrityConfig::load_from_file(&nonexistent);
    assert!(result.is_err(), "nonexistent file must produce an error");

    // Verify it is specifically an IoError variant.
    match result.unwrap_err() {
        IntegrityConfigError::IoError(_) => {} // Expected.
        other => panic!("expected IoError, got: {other}"),
    }
}

// ===========================================================================
// Resume Configuration Edge Cases
// ===========================================================================

/// When `resume_from_checkpoint` is enabled but `session_persistence_path`
/// is empty, validation must fail because sessions cannot be persisted
/// without a storage location.
#[test]
fn test_resume_requires_persistence_path_when_enabled() {
    let toml_str = r#"
        enabled = true
        hash_algorithm = "sha256"

        [resume]
        resume_from_checkpoint = true
        checkpoint_interval_chunks = 20
        session_persistence_path = ""
    "#;

    let result = IntegrityConfig::from_toml_str(toml_str);
    assert!(
        result.is_err(),
        "empty persistence_path with resume enabled must fail"
    );

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("session_persistence_path"),
        "error must reference persistence path: {msg}"
    );
}

/// When `resume_from_checkpoint` is **disabled**, an empty or absent
/// `session_persistence_path` must NOT cause a validation error (the
/// path is irrelevant when resume is inactive).
#[test]
fn test_resume_disabled_allows_empty_persistence_path() {
    let toml_str = r#"
        enabled = true
        hash_algorithm = "sha256"

        [resume]
        resume_from_checkpoint = false
        checkpoint_interval_chunks = 0
        session_persistence_path = ""
    "#;

    // Should succeed: resume is off so checkpoint/path constraints are not checked.
    let config = IntegrityConfig::from_toml_str(toml_str).expect("disabled resume must pass");
    assert!(!config.resume.resume_from_checkpoint);
}

/// When auto_repair is disabled, a zero `repair_timeout_secs` must NOT
/// cause a validation error (timeout is irrelevant when repair is off).
#[test]
fn test_auto_repair_disabled_allows_zero_timeout() {
    let toml_str = r#"
        enabled = true
        hash_algorithm = "sha256"

        [repair]
        auto_repair = false
        repair_timeout_secs = 0
    "#;

    let config =
        IntegrityConfig::from_toml_str(toml_str).expect("disabled auto_repair allows zero timeout");
    assert!(!config.repair.auto_repair);
    assert_eq!(config.repair.repair_timeout_secs, 0);
}

/// Case-insensitive hash algorithm parsing: uppercase variants like
/// "Sha256", "SHA512", "Blake3" must all be accepted by validation.
/// Hyphenated forms like "SHA-256" are also normalized and accepted.
#[test]
fn test_hash_algorithm_case_insensitive() {
    for algo in &["SHA-256", "Sha256", "SHA512", "sha512", "BLAKE3", "blake3"] {
        let toml_str = format!(
            r#"enabled = true
hash_algorithm = "{algo}""#
        );
        let result = IntegrityConfig::from_toml_str(&toml_str);
        if let Err(e) = result {
            panic!("{algo} must be accepted, but got error: {e}");
        }
        let config = result.unwrap();
        assert_eq!(
            config.hash_algorithm.to_lowercase().replace('-', ""),
            algo.to_lowercase().replace('-', ""),
            "algorithm normalized to canonical form for comparison"
        );
    }
}

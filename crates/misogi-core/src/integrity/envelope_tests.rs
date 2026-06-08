//! Unit tests for integrity envelope types.
//!
//! Tests cover hash algorithm computation, envelope building, verification,
//! nonce management, chain linking, acknowledgment construction, and
//! serialization round-trip fidelity. Total: 15 tests.

use super::*;

// ===========================================================================
// HashAlgorithm Tests
// ===========================================================================

#[test]
fn test_sha256_hash_known_answer() {
    let algo = HashAlgorithm::Sha256;
    let result = algo.hash(b"hello world").unwrap();
    assert_eq!(
        result,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
    assert_eq!(result.len(), algo.output_len_hex());
}

#[test]
fn test_sha256_empty_input() {
    let algo = HashAlgorithm::Sha256;
    let result = algo.hash(b"").unwrap();
    assert_eq!(
        result,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_sha512_hash_output_length() {
    let algo = HashAlgorithm::Sha512;
    let result = algo.hash(b"test").unwrap();
    assert_eq!(result.len(), 128); // 512 bits = 128 hex chars
}

#[test]
fn test_blake3_hash_produces_output() {
    let algo = HashAlgorithm::Blake3;
    let result = algo.hash(b"blake3 test data").unwrap();
    assert_eq!(result.len(), 64); // 256 bits = 64 hex chars
    // BLAKE3 known answer for empty input
    let empty = algo.hash(b"").unwrap();
    assert_eq!(empty, "af1349b9f5f9a1a6a2024016ec9c02fd8d1b5627b6a0a4b1a21e7fc8e6b68c0c");
}

// ===========================================================================
// Envelope Builder Tests
// ===========================================================================

#[test]
fn test_build_envelope_basic() {
    let mut builder = IntegrityEnvelopeBuilder::new(HashAlgorithm::Sha256, false);
    let data = b"chunk payload data";
    let envelope = builder.build(0, data, None).unwrap();

    assert_eq!(envelope.chunk_index, 0);
    assert!(!envelope.data_hash.is_empty());
    assert!(!envelope.envelope_hash.is_empty());
    assert_eq!(envelope.sequence_nonce, 0);
    assert!(envelope.previous_chunk_hash.is_none());
    assert!(envelope.timestamp_ms > 0);
}

#[test]
fn test_verify_envelope_succeeds() {
    let mut builder = IntegrityEnvelopeBuilder::new(HashAlgorithm::Sha256, false);
    let data = b"verifiable chunk";
    let envelope = builder.build(0, data, None).unwrap();

    let result = builder.verify_envelope(&envelope, data).unwrap();
    assert!(result);
}

#[test]
fn test_verify_envelope_detects_tampered_data() {
    let mut builder = IntegrityEnvelopeBuilder::new(HashAlgorithm::Sha256, false);
    let original = b"original data";
    let envelope = builder.build(0, original, None).unwrap();

    let tampered = b"tampered data!!!!";
    let result = builder.verify_envelope(&envelope, tampered);
    assert!(result.is_err());
    match result.unwrap_err() {
        IntegrityError::HashMismatch { .. } => (),
        other => panic!("Expected HashMismatch, got: {other}"),
    }
}

#[test]
fn test_nonce_monotonic_increments() {
    let mut builder = IntegrityEnvelopeBuilder::new(HashAlgorithm::Sha256, false);

    let n0 = builder.generate_nonce();
    let n1 = builder.generate_nonce();
    let n2 = builder.generate_nonce();

    assert_eq!(n0, 0);
    assert_eq!(n1, 1);
    assert_eq!(n2, 2);
}

#[test]
fn test_reset_nonce_resets_counter() {
    let mut builder = IntegrityEnvelopeBuilder::new(HashAlgorithm::Sha256, false);
    assert_eq!(builder.generate_nonce(), 0);
    assert_eq!(builder.generate_nonce(), 1);
    builder.reset_nonce();
    assert_eq!(builder.generate_nonce(), 0);
}

#[test]
fn test_build_with_chain_linking() {
    let mut builder = IntegrityEnvelopeBuilder::new(HashAlgorithm::Sha256, true);

    // First chunk: no previous hash required.
    let env0 = builder.build(0, b"chunk_zero", None).unwrap();
    assert_eq!(env0.chunk_index, 0);

    // Second chunk: must provide previous hash.
    let env1 = builder.build(1, b"chunk_one", Some(&env0.data_hash)).unwrap();
    assert_eq!(
        env1.previous_chunk_hash.as_deref(),
        Some(env0.data_hash.as_str())
    );
}

#[test]
fn test_chain_linking_requires_prev_hash_after_first() {
    let mut builder = IntegrityEnvelopeBuilder::new(HashAlgorithm::Sha256, true);
    let _env0 = builder.build(0, b"first", None).unwrap();

    // Second chunk without prev_hash should fail.
    let result = builder.build(1, b"second", None);
    assert!(result.is_err());
    match result.unwrap_err() {
        IntegrityError::InvalidEnvelope(_) => (),
        other => panic!("Expected InvalidEnvelope, got: {other}"),
    }
}

// ===========================================================================
// IntegrityAck Tests
// ===========================================================================

#[test]
fn test_ack_ok_constructor() {
    let ack = IntegrityAck::ok(42);
    assert_eq!(ack.chunk_index, 42);
    assert!(ack.received_ok);
    assert!(ack.error.is_none());
}

#[test]
fn test_ack_fail_constructor() {
    let ack = IntegrityAck::fail(10, "hash mismatch detected");
    assert_eq!(ack.chunk_index, 10);
    assert!(!ack.received_ok);
    assert_eq!(ack.error.as_deref(), Some("hash mismatch detected"));
}

// ===========================================================================
// Serialization Round-trip Tests
// ===========================================================================

#[test]
fn test_envelope_serialization_roundtrip() {
    let mut builder = IntegrityEnvelopeBuilder::new(HashAlgorithm::Sha256, false);
    let envelope = builder.build(5, b"serialize me", None).unwrap();

    let json = serde_json::to_string(&envelope).unwrap();
    let deserialized: IntegrityEnvelope =
        serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.chunk_index, envelope.chunk_index);
    assert_eq!(deserialized.data_hash, envelope.data_hash);
    assert_eq!(deserialized.envelope_hash, envelope.envelope_hash);
    assert_eq!(deserialized.sequence_nonce, envelope.sequence_nonce);
}

#[test]
fn test_ack_serialization_roundtrip() {
    let ack = IntegrityAck::fail(3, "corruption");
    let json = serde_json::to_string(&ack).unwrap();
    let deserialized: IntegrityAck = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.chunk_index, 3);
    assert!(!deserialized.received_ok);
    assert_eq!(deserialized.error.as_deref(), Some("corruption"));
}

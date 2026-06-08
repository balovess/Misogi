//! Comprehensive test suite for IntegrityVerifier.
//!
//! Tests cover all public methods with various scenarios including:
//! - Known good/tampered/empty chunk verification
//! - Batch verification with mixed results
//! - Corruption and missing chunk detection
//! - Full file verification
//! - Zero-tolerance mode behavior
//! - Multi-chunk edge cases

#[cfg(test)]
mod tests {
    use super::super::envelope::{HashAlgorithm, IntegrityEnvelopeBuilder, IntegrityError};
    use super::super::verifier::IntegrityVerifier;

    // -----------------------------------------------------------------------
    // Helper: Build a valid envelope for test data.
    // -----------------------------------------------------------------------

    /// Helper function to create a sealed envelope for given data using SHA-256.
    fn build_test_envelope(data: &[u8]) -> (IntegrityEnvelope, String) {
        let mut builder = IntegrityEnvelopeBuilder::new(HashAlgorithm::Sha256, false);
        let envelope = builder.build(0, data, None).unwrap();
        let hash = HashAlgorithm::Sha256.hash(data).unwrap();
        (envelope, hash)
    }

    /// Helper to create a tampered version of data (flip one bit).
    fn tamper_data(data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return vec![0xFF]; // Non-empty tampered version of empty.
        }
        let mut tampered = data.to_vec();
        tampered[0] ^= 0x01; // Flip LSB of first byte.
        tampered
    }

    // -----------------------------------------------------------------------
    // verify_chunk Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_known_good_chunk() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);
        let data = b"hello world, this is a test chunk";
        let (envelope, _) = build_test_envelope(data);

        let result = verifier.verify_chunk(data, &envelope).unwrap();
        assert!(result, "Known good chunk should pass verification");
    }

    #[test]
    fn test_verify_tampered_chunk_fails() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);
        let original = b"original untampered data";
        let (envelope, _) = build_test_envelope(original);

        let tampered = tamper_data(original);
        let result = verifier.verify_chunk(&tampered, &envelope).unwrap();
        assert!(!result, "Tampered chunk should fail verification");
    }

    #[test]
    fn test_verify_empty_chunk_without_zero_tolerance() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);
        let data = b"";
        let (envelope, _) = build_test_envelope(data);

        // Empty chunk should pass when zero_tolerance is false.
        let result = verifier.verify_chunk(data, &envelope).unwrap();
        assert!(result, "Empty chunk should pass without zero tolerance");
    }

    #[test]
    fn test_verify_empty_chunk_with_zero_tolerance_rejected() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, true);
        let data = b"";
        let (envelope, _) = build_test_envelope(data);

        // Empty chunk should FAIL when zero_tolerance is true.
        let result = verifier.verify_chunk(data, &envelope).unwrap();
        assert!(
            !result,
            "Empty chunk should be rejected in zero-tolerance mode"
        );
    }

    // -----------------------------------------------------------------------
    // verify_all_chunks Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_all_chunks_all_ok() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);

        let chunks: Vec<&[u8]> = vec![b"chunk_0", b"chunk_1", b"chunk_2"];
        let envelopes: Vec<IntegrityEnvelope> = chunks
            .iter()
            .map(|c| build_test_envelope(c).0)
            .collect();

        let report = verifier.verify_all_chunks(&chunks, &envelopes);
        assert!(report.all_ok, "All-good batch should report all_ok=true");
        assert_eq!(report.issue_count(), 0, "No issues expected");
        assert!(report.missing_indices.is_empty());
        assert!(report.corrupt_indices.is_empty());
    }

    #[test]
    fn test_verify_all_chunks_with_corruption() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);

        let original_chunks: Vec<&[u8]> = vec![b"good_0", b"corrupt_me", b"good_2"];
        let envelopes: Vec<IntegrityEnvelope> = original_chunks
            .iter()
            .map(|c| build_test_envelope(c).0)
            .collect();

        // Tamper the middle chunk.
        let received: Vec<Vec<u8>> = original_chunks
            .iter()
            .enumerate()
            .map(|(i, c)| if i == 1 { tamper_data(c) } else { c.to_vec() })
            .collect();

        let received_refs: Vec<&[u8]> = received.iter().map(|v| v.as_slice()).collect();
        let report = verifier.verify_all_chunks(&received_refs, &envelopes);

        assert!(!report.all_ok, "Batch with corruption should not be all_ok");
        assert_eq!(report.corrupt_indices.len(), 1, "Exactly one corrupt chunk");
        assert_eq!(report.corrupt_indices[0], 1, "Index 1 should be corrupt");
        assert!(report.missing_indices.is_empty(), "No missing chunks here");
    }

    // -----------------------------------------------------------------------
    // detect_corruption Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_corruption_finds_bad_indices() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);

        let original: Vec<&[u8]] = vec![b"a", b"b", b"c", b"d", b"e"];
        let envelopes: Vec<IntegrityEnvelope> =
            original.iter().map(|c| build_test_envelope(c).0).collect();

        // Tamper indices 1 and 3.
        let mut received: Vec<Vec<u8>> = original.iter().map(|c| c.to_vec()).collect();
        received[1] = tamper_data(&received[1]);
        received[3] = tamper_data(&received[3]);

        let received_refs: Vec<&[u8]> = received.iter().map(|v| v.as_slice()).collect();
        let corrupt = verifier.detect_corruption(&received_refs, &envelopes);

        assert_eq!(corrupt.len(), 2, "Should detect 2 corrupt chunks");
        assert_eq!(corrupt[0], 1, "First corrupt index should be 1");
        assert_eq!(corrupt[1], 3, "Second corrupt index should be 3");
    }

    #[test]
    fn test_detect_corruption_all_clean() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);

        let chunks: Vec<&[u8]> = vec![b"x", b"y", b"z"];
        let envelopes: Vec<IntegrityEnvelope> =
            chunks.iter().map(|c| build_test_envelope(c).0).collect();

        let corrupt = verifier.detect_corruption(&chunks, &envelopes);
        assert!(corrupt.is_empty(), "No corruption in clean data");
    }

    // -----------------------------------------------------------------------
    // detect_missing Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_missing_finds_gaps() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);

        // Expecting 5 chunks, but only received 3 (indices 0, 1, 2).
        let received: Vec<IntegrityEnvelope> = vec![
            build_test_envelope(b"a").0,
            build_test_envelope(b"b").0,
            build_test_envelope(b"c").0,
        ];

        let missing = verifier.detect_missing(5, &received);
        assert_eq!(missing.len(), 2, "Should have 2 missing chunks");
        assert_eq!(missing, vec![3, 4], "Missing indices should be [3, 4]");
    }

    #[test]
    fn test_detect_missing_complete_set() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);

        let received: Vec<IntegrityEnvelope> = vec![
            build_test_envelope(b"a").0,
            build_test_envelope(b"b").0,
            build_test_envelope(b"c").0,
        ];

        let missing = verifier.detect_missing(3, &received);
        assert!(missing.is_empty(), "Complete set should have no missing");
    }

    #[test]
    fn test_detect_missing_nothing_received() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);

        let missing = verifier.detect_missing(5, &[]);
        assert_eq!(missing.len(), 5, "All 5 chunks should be missing");
        assert_eq!(missing, vec![0, 1, 2, 3, 4]);
    }

    // -----------------------------------------------------------------------
    // verify_full_file Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_file_verify_ok() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);
        let data = b"This is the complete file content for end-to-end verification.";
        let expected_hash = HashAlgorithm::Sha256.hash(data).unwrap();

        let result = verifier.verify_full_file(data, &expected_hash).unwrap();
        assert!(result, "File with matching hash should pass");
    }

    #[test]
    fn test_full_file_verify_mismatch() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);
        let original = b"Original file content here.";
        let modified = b"Modified file content here!!";

        let original_hash = HashAlgorithm::Sha256.hash(original).unwrap();
        let result = verifier.verify_full_file(modified, &original_hash).unwrap();
        assert!(!result, "Modified file should not match original hash");
    }

    // -----------------------------------------------------------------------
    // Zero Tolerance Mode Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_zero_tolerance_true_rejects_empty() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, true);
        let (envelope, _) = build_test_envelope(b"");

        let result = verifier.verify_chunk(b"", &envelope).unwrap();
        assert!(!result, "Zero tolerance must reject empty chunks");
    }

    #[test]
    fn test_zero_tolerance_false_accepts_empty() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);
        let (envelope, _) = build_test_envelope(b"");

        let result = verifier.verify_chunk(b"", &envelope).unwrap();
        assert!(result, "Non-zero tolerance accepts empty chunks");
    }

    // -----------------------------------------------------------------------
    // Multiple Chunks Mixed Scenarios
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_chunks_mixed_results() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);

        let originals: Vec<&[u8]> = vec![
            b"ok",
            b"corrupt",
            b"ok_also",
            b"corrupt_too",
            b"fine",
        ];
        let envelopes: Vec<IntegrityEnvelope> = originals
            .iter()
            .map(|c| build_test_envelope(c).0)
            .collect();

        // Corrupt indices 1 and 3.
        let mut received: Vec<Vec<u8>> = originals.iter().map(|c| c.to_vec()).collect();
        received[1] = tamper_data(&received[1]);
        received[3] = tamper_data(&received[3]);

        let refs: Vec<&[u8]> = received.iter().map(|v| v.as_slice()).collect();
        let corrupt = verifier.detect_corruption(&refs, &envelopes);

        assert_eq!(corrupt.len(), 2);
        assert_eq!(corrupt, vec![1, 3]);
    }

    // -----------------------------------------------------------------------
    // Chain Linking Verification (Basic)
    // -----------------------------------------------------------------------

    #[test]
    fn test_chain_linking_verification() {
        // Build two linked envelopes.
        let mut builder = IntegrityEnvelopeBuilder::new(HashAlgorithm::Sha256, true);
        let env0 = builder.build(0, b"first_chunk", None).unwrap();
        let prev_hash = Some(env0.data_hash.clone());
        let env1 = builder.build(1, b"second_chunk", prev_hash.as_deref()).unwrap();

        // Verify both independently.
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);
        assert!(verifier.verify_chunk(b"first_chunk", &env0).unwrap());
        assert!(verifier.verify_chunk(b"second_chunk", &env1).unwrap());

        // Verify chain integrity: env1's previous_chunk_hash should match env0's data_hash.
        assert_eq!(
            env1.previous_chunk_hash.as_deref(),
            Some(env0.data_hash.as_str()),
            "Chain link should reference previous chunk's hash"
        );
    }

    // -----------------------------------------------------------------------
    // Edge Cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_single_byte_chunk() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);
        let data = &[0x42u8];
        let (envelope, _) = build_test_envelope(data);

        assert!(verifier.verify_chunk(data, &envelope).unwrap());
    }

    #[test]
    fn test_large_chunk_1mb() {
        let verifier = IntegrityVerifier::new(HashAlgorithm::Sha256, false);
        let data = vec![0xABu8; 1024 * 1024]; // 1 MiB.
        let (envelope, _) = build_test_envelope(&data);

        assert!(verifier.verify_chunk(&data, &envelope).unwrap());
    }
}

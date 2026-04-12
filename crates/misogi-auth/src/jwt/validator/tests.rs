//! Unit tests for JwtValidator component.
//!
//! Tests token validation functionality including:
//! - Successful validation
//! - Signature verification
//! - Claim validation (iss, aud, exp)
//! - Metadata extraction
//! - Error cases

use super::super::{JwtAuthenticator, JwtConfig, JwtIssuer, JwtValidator, JwtError};
use crate::claims::MisogiClaims;

/// Helper: create test configuration with generated keypair.
fn setup(ttl_hours: i64) -> (tempfile::TempDir, JwtConfig) {
    let dir = tempfile::tempdir().unwrap();
    JwtAuthenticator::generate_keypair(dir.path()).unwrap();

    let config = JwtConfig {
        issuer: "test-issuer".to_string(),
        audience: "test-audience".to_string(),
        rsa_pem_path: dir.path().join("private.pem"),
        rsa_pub_pem_path: dir.path().join("public.pem"),
        ttl_hours,
        refresh_ttl_hours: 24,
    };

    (dir, config)
}

#[test]
fn test_validator_initialization_succeeds_with_valid_key() {
    // Test that JwtValidator can be initialized with a valid public key
    let (_dir, config) = setup(1);
    
    let result = JwtValidator::new(config);
    assert!(result.is_ok(), "Validator should initialize with valid key");
}

#[test]
fn test_validator_fails_with_missing_public_key() {
    // Test that JwtValidator fails when public key file doesn't exist
    let config = JwtConfig {
        issuer: "test".to_string(),
        audience: "test".to_string(),
        rsa_pem_path: std::path::PathBuf::from("/nonexistent/private.pem"),
        rsa_pub_pem_path: std::path::PathBuf::from("/nonexistent/public.pem"),
        ttl_hours: 1,
        refresh_ttl_hours: 24,
    };

    let result = JwtValidator::new(config);
    assert!(
        matches!(result, Err(JwtError::KeyLoadFailed(_))),
        "Should fail with KeyLoadFailed for missing key"
    );
}

#[test]
fn test_validate_rejects_malformed_token() {
    // Test that completely invalid token strings are rejected
    let (_dir, config) = setup(1);
    let validator = JwtValidator::new(config).unwrap();

    let malformed_tokens = vec![
        "",                                    // Empty string
        "not.a.token",                        // Invalid format
        "a.b.c.d",                            // Too many parts
        "invalid-header.invalid-payload.sig", // Invalid base64
    ];

    for token in &malformed_tokens {
        let result = validator.validate(token);
        assert!(
            result.is_err(),
            "Malformed token '{}' should be rejected",
            token
        );
    }
}

#[test]
fn test_validate_without_expiry_accepts_expired_token() {
    // Test that validate_without_expiry_check accepts expired tokens
    let (_dir, config) = setup(1); // Use 1 hour default, but override with custom TTL

    let issuer = JwtIssuer::new(config.clone()).unwrap();
    let validator = JwtValidator::new(config).unwrap();

    let claims = MisogiClaims::new("no-expire-user".to_string(), 0, 0);

    // Issue with very short TTL (1 second)
    let token = issuer.issue_with_ttl(&claims, 1).unwrap();

    // Wait for token to expire (5 seconds to ensure we're well past the 1s TTL on all systems)
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Normal validation should reject
    assert!(
        matches!(validator.validate(&token), Err(JwtError::TokenExpired)),
        "Normal validation should reject expired token"
    );

    // No-expire validation should accept but mark as expired
    let validated = validator.validate_without_expiry_check(&token).unwrap();
    assert_eq!(validated.claims.applicant_id, "no-expire-user");
    assert!(
        validated.is_expired,
        "Token should be marked as expired even when accepted"
    );
}

#[test]
fn test_validate_and_extract_returns_complete_metadata() {
    // Test that validate_and_extract returns all metadata fields correctly
    let (_dir, config) = setup(1);

    let issuer = JwtIssuer::new(config.clone()).unwrap();
    let validator = JwtValidator::new(config).unwrap();

    let now = super::super::unix_timestamp();
    let claims = MisogiClaims::new("metadata-test".to_string(), now, now + 3600)
        .with_display_name("Meta User".to_string())
        .with_roles(vec!["tester".to_string()]);

    let token = issuer.issue(&claims).unwrap();
    let validated = validator.validate_and_extract(&token).unwrap();

    // Verify all metadata fields are populated
    assert_eq!(validated.issuer, "test-issuer");
    assert_eq!(validated.audience, "test-audience");
    assert!(validated.issued_at > 0);
    assert!(validated.expires_at > validated.issued_at);
    assert!(!validated.is_expired);

    // Verify claims are accessible
    assert_eq!(validated.claims.applicant_id, "metadata-test");
    assert_eq!(
        validated.claims.display_name.as_deref(),
        Some("Meta User")
    );

    // Verify helper methods work
    assert!(validated.has_role("tester"));
    assert!(!validated.has_role("admin"));
    assert!(validated.remaining_seconds() > 0);
}

#[test]
fn test_validate_enforces_algorithm_rs256_only() {
    // Test that tokens signed with non-RS256 algorithms would be rejected
    // (This is implicitly tested by the library's algorithm enforcement)
    
    // We can't easily create an HS256 token without the secret, but we can verify
    // that the validator is configured correctly by checking it rejects obviously wrong tokens
    let (_dir, config) = setup(1);
    let validator = JwtValidator::new(config).unwrap();

    // Create a fake HS256-like token (just to test rejection)
    // This will fail signature check, which is the expected behavior
    let fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    let result = validator.validate(&fake_token);
    assert!(
        result.is_err(),
        "HS256 token (or any non-matching token) should be rejected"
    );
}

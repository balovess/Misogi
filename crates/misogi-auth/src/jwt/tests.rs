//! Integration tests for the modular JWT architecture.
//!
//! Tests the interaction between JwtIssuer and JwtValidator, ensuring
//! end-to-end functionality of the split architecture.

use super::{JwtAuthenticator, JwtConfig, JwtIssuer, JwtValidator};
use crate::claims::MisogiClaims;
use crate::models::User;

/// Helper: create a test configuration with generated keypair in a temp directory.
fn setup_test_config(ttl_hours: i64) -> (tempfile::TempDir, JwtConfig) {
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
fn test_issue_and_validate_roundtrip() {
    // Test complete roundtrip: issue → validate using new API
    let (_dir, config) = setup_test_config(1);

    let issuer = JwtIssuer::new(config.clone()).unwrap();
    let validator = JwtValidator::new(config).unwrap();

    let now = super::unix_timestamp();
    let claims = MisogiClaims::new("user-001".to_string(), now, now + 3600)
        .with_display_name("Test User".to_string())
        .with_roles(vec!["staff".to_string()]);

    let token = issuer.issue(&claims).unwrap();
    assert!(!token.is_empty(), "Token should not be empty");
    assert!(token.contains('.'), "Token should be JWS format (contain dots)");

    let validated_claims = validator.validate(&token).unwrap();
    assert_eq!(validated_claims.applicant_id, "user-001");
    assert_eq!(
        validated_claims.display_name.as_deref(),
        Some("Test User")
    );
    assert!(validated_claims.has_role("staff"));
}

#[test]
fn test_expired_token_rejection() {
    // Test that expired tokens are properly rejected
    let (_dir, config) = setup_test_config(1);

    let issuer = JwtIssuer::new(config.clone()).unwrap();
    let validator = JwtValidator::new(config).unwrap();

    let claims = MisogiClaims::new("expired-user".to_string(), 0, 0);

    // Issue with minimal TTL to test expiration (must be > 0)
    let token = issuer.issue_with_ttl(&claims, 1).unwrap();

    // Wait well past the token's expiration time
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Decode the token manually to verify it should be expired
    // Then validate through the validator which should reject it
    let result = validator.validate(&token);
    
    // If validation succeeded unexpectedly, check if the token is actually expired
    if let Ok(validated) = &result {
        let now = super::unix_timestamp();
        eprintln!(
            "DEBUG: Token exp={}, now={}, diff={}s",
            validated.exp,
            now,
            now.saturating_sub(validated.exp)
        );
    }
    
    assert!(
        matches!(result, Err(super::JwtError::TokenExpired)),
        "Expired token should be rejected with TokenExpired error, got: {:?}",
        result
    );
}

#[test]
fn test_tampered_token_detection() {
    // Test that tampered tokens are detected via signature verification failure
    let (_dir, config) = setup_test_config(1);

    let issuer = JwtIssuer::new(config.clone()).unwrap();
    let validator = JwtValidator::new(config).unwrap();

    let now = super::unix_timestamp();
    let claims = MisogiClaims::new("user-001".to_string(), now, now + 3600);

    let token = issuer.issue(&claims).unwrap();

    // Tamper with token by modifying a character
    let tampered = token.replacen('a', "b", 1); // Replace first 'a' with 'b'

    let result = validator.validate(&tampered);
    assert!(
        matches!(
            result,
            Err(super::JwtError::InvalidSignature | super::JwtError::MalformedToken(_))
        ),
        "Tampered token should be rejected, got: {:?}",
        result
    );
}

#[test]
fn test_invalid_signature_rejection() {
    // Test that tokens signed with a different key are rejected
    let (_dir1, config1) = setup_test_config(1);
    let (_dir2, config2) = setup_test_config(1); // Different keypair

    let issuer = JwtIssuer::new(config1).unwrap();
    let validator = JwtValidator::new(config2).unwrap(); // Different public key

    let now = super::unix_timestamp();
    let claims = MisogiClaims::new("user-001".to_string(), now, now + 3600);

    let token = issuer.issue(&claims).unwrap();

    let result = validator.validate(&token);
    assert!(
        matches!(result, Err(super::JwtError::InvalidSignature)),
        "Token signed with different key should be rejected, got: {:?}",
        result
    );
}

#[test]
fn test_custom_ttl_works_correctly() {
    // Test that custom TTL is applied correctly via issue_with_ttl()
    let (_dir, config) = setup_test_config(8); // Default 8 hours

    let issuer = JwtIssuer::new(config.clone()).unwrap();
    let validator = JwtValidator::new(config).unwrap();

    let _now = super::unix_timestamp();
    let base_claims = MisogiClaims::new("custom-ttl-user".to_string(), 0, 0);

    // Issue with custom TTL of 60 seconds
    let short_lived_token = issuer.issue_with_ttl(&base_claims, 60).unwrap();

    // Validate immediately — should succeed
    let validated = validator.validate_and_extract(&short_lived_token).unwrap();
    
    // Check that TTL was applied correctly (exp should be approximately now + 60)
    let lifetime = validated.claims.lifetime_seconds();
    assert!(
        lifetime > 50 && lifetime <= 70,
        "Custom TTL of 60s should result in ~60s lifetime, got {}s",
        lifetime
    );

    // Verify it's a different TTL than default would produce
    let default_token = issuer.issue(&base_claims).unwrap();
    let default_validated = validator.validate_and_extract(&default_token).unwrap();
    let default_lifetime = default_validated.claims.lifetime_seconds();

    assert!(
        default_lifetime > lifetime,
        "Default TTL ({}s) should be greater than custom TTL ({}s)",
        default_lifetime,
        lifetime
    );
}

#[test]
fn test_zero_ttl_rejected() {
    // Test that issuing with TTL=0 returns an error
    let (_dir, config) = setup_test_config(1);

    let issuer = JwtIssuer::new(config).unwrap();

    let claims = MisogiClaims::new("zero-ttl-user".to_string(), 0, 0);

    let result = issuer.issue_with_ttl(&claims, 0);
    assert!(
        matches!(result, Err(super::JwtError::ClaimValidationFailed(_))),
        "Zero TTL should be rejected, got: {:?}",
        result
    );
}

#[test]
fn test_backward_compatible_wrapper_functions() {
    // Test that legacy JwtAuthenticator API still works correctly
    let (_dir, config) = setup_test_config(1);

    let auth = JwtAuthenticator::new(config).unwrap();
    let user = User::staff("legacy-user", "Legacy User");

    // Legacy issue_token
    let token = auth.issue_token(&user).unwrap();
    assert!(!token.jws.is_empty());
    assert!(token.refresh_token.is_some());
    assert!(token.expires_at > chrono::Utc::now());

    // Legacy validate_token
    let claims = auth.validate_token(&token.jws).unwrap();
    assert_eq!(claims.sub, "legacy-user");
    assert_eq!(claims.name, "Legacy User");
    assert!(!claims.is_expired());

    // Legacy validate_token_no_expire (should work even if token expires)
    let _no_expire_claims = auth.validate_token_no_expire(&token.jws).unwrap();
}

#[test]
fn test_validate_with_metadata_returns_rich_info() {
    // Test that validate_and_extract returns ValidatedToken with metadata
    let (_dir, config) = setup_test_config(1);

    let issuer = JwtIssuer::new(config.clone()).unwrap();
    let validator = JwtValidator::new(config).unwrap();

    let now = super::unix_timestamp();
    let claims = MisogiClaims::new("metadata-user".to_string(), now, now + 3600)
        .with_roles(vec!["admin".to_string(), "auditor".to_string()]);

    let token = issuer.issue(&claims).unwrap();
    let validated = validator.validate_and_extract(&token).unwrap();

    // Check metadata fields
    assert_eq!(validated.issuer, "test-issuer");
    assert_eq!(validated.audience, "test-audience");
    assert_eq!(validated.issued_at, now); // Approximately
    assert!(!validated.is_expired, "Freshly issued token should not be expired");
    assert!(validated.remaining_seconds() > 0, "Should have positive remaining time");
    assert!(validated.has_role("admin"));
    assert!(validated.has_role("auditor"));
    assert!(!validated.has_role("nonexistent"));
}

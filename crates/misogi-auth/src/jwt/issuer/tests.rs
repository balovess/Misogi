//! Unit tests for JwtIssuer component.
//!
//! Tests token issuance functionality including:
//! - Successful token generation
//! - Custom TTL handling
//! - Error cases (invalid keys, zero TTL)
//! - Token format validation

use super::super::{JwtConfig, JwtIssuer, JwtError};
use base64::Engine;
use crate::claims::MisogiClaims;

/// Helper: create test configuration with generated keypair.
fn setup() -> (tempfile::TempDir, JwtConfig) {
    let dir = tempfile::tempdir().unwrap();
    
    // Use authenticator's keypair generation (shared utility)
    super::super::authenticator::JwtAuthenticator::generate_keypair(dir.path()).unwrap();

    let config = JwtConfig {
        issuer: "test-issuer".to_string(),
        audience: "test-audience".to_string(),
        rsa_pem_path: dir.path().join("private.pem"),
        rsa_pub_pem_path: dir.path().join("public.pem"), // Not used by issuer but required
        ttl_hours: 1,
        refresh_ttl_hours: 24,
    };

    (dir, config)
}

#[test]
fn test_issuer_initialization_succeeds_with_valid_key() {
    // Test that JwtIssuer can be initialized with a valid private key
    let (_dir, config) = setup();
    
    let result = JwtIssuer::new(config);
    assert!(result.is_ok(), "Issuer should initialize with valid key");
}

#[test]
fn test_issuer_fails_with_missing_private_key() {
    // Test that JwtIssuer fails when private key file doesn't exist
    let config = JwtConfig {
        issuer: "test".to_string(),
        audience: "test".to_string(),
        rsa_pem_path: std::path::PathBuf::from("/nonexistent/private.pem"),
        rsa_pub_pem_path: std::path::PathBuf::from("/nonexistent/public.pem"),
        ttl_hours: 1,
        refresh_ttl_hours: 24,
    };

    let result = JwtIssuer::new(config);
    assert!(
        matches!(result, Err(JwtError::KeyLoadFailed(_))),
        "Should fail with KeyLoadFailed for missing key"
    );
}

#[test]
fn test_issue_produces_valid_jws_format() {
    // Test that issued tokens are in valid JWS Compact Serialization format
    let (_dir, config) = setup();
    let issuer = JwtIssuer::new(config).unwrap();

    let now = super::super::unix_timestamp();
    let claims = MisogiClaims::new("user-001".to_string(), now, now + 3600);

    let token = issuer.issue(&claims).unwrap();

    // JWS Compact Serialization has 3 parts separated by dots
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWS should have 3 parts (header.payload.signature)");

    // Each part should be base64url-encoded (no padding)
    for (i, part) in parts.iter().enumerate() {
        assert!(!part.is_empty(), "JWS part {} should not be empty", i);
        // Basic check: should be valid base64url characters
        assert!(
            part.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "JWS part {} should be base64url-encoded",
            i
        );
    }
}

#[test]
fn test_issue_with_custom_ttl_applies_correct_expiration() {
    // Test that issue_with_ttl correctly sets expiration based on custom TTL
    let (_dir, config) = setup();
    let issuer = JwtIssuer::new(config).unwrap();

    let claims = MisogiClaims::new("ttl-test".to_string(), 0, 0);

    // Issue with exactly 120 second TTL
    let token = issuer.issue_with_ttl(&claims, 120).unwrap();

    // Decode without verification to inspect payload
    let parts: Vec<&str> = token.split('.').collect();
    let payload_base64 = parts[1];

    // Add padding if needed for base64 decoding
    let _payload_padded = format!(
        "{}{}",
        payload_base64,
        str::repeat("=", (4 - payload_base64.len() % 4) % 4)
    );

    let payload_json =
        String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_base64)
            .unwrap())
        .unwrap();

    let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();
    let exp = payload["exp"].as_u64().unwrap();
    let iat = payload["iat"].as_u64().unwrap();

    let lifetime = exp.saturating_sub(iat);
    assert!(
        lifetime >= 118 && lifetime <= 122,
        "Custom TTL of 120s should produce ~120s lifetime, got {}s",
        lifetime
    );
}

#[test]
fn test_issue_preserves_claims_content() {
    // Test that all claims fields are correctly serialized into the token
    let (_dir, config) = setup();
    let issuer = JwtIssuer::new(config).unwrap();

    let claims = MisogiClaims::new("preserve-test".to_string(), 0, 0)
        .with_display_name("Preserve Name".to_string())
        .with_roles(vec!["role1".to_string(), "role2".to_string()])
        .with_idp_source("test-idp".to_string())
        .with_original_subject("original-sub".to_string())
        .with_issuer_dn("cn=test".to_string())
        .with_extra("custom_field", serde_json::json!("custom_value"));

    let token = issuer.issue(&claims).unwrap();

    // Decode and verify payload contains all fields
    let parts: Vec<&str> = token.split('.').collect();
    let payload_json =
        String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap())
        .unwrap();

    let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();

    assert_eq!(payload["applicant_id"], "preserve-test");
    assert_eq!(payload["display_name"], "Preserve Name");
    assert_eq!(payload["roles"], serde_json::json!(["role1", "role2"]));
    assert_eq!(payload["idp_source"], "test-idp");
    assert_eq!(payload["original_subject"], "original-sub");
    assert_eq!(payload["issuer_dn"], "cn=test");
    assert_eq!(payload["custom_field"], "custom_value");
}

// ===========================================================================
// Integration Layer Tests — from_config / issue_identity
// ===========================================================================

/// Helper: decode JWS payload without verification for inspection.
fn decode_payload(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    let payload_json =
        String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap())
        .unwrap();
    serde_json::from_str(&payload_json).unwrap()
}

#[test]
fn test_from_config_valid_json() {
    // from_config should construct a valid JwtIssuer from complete JSON config.
    let (_dir, _config) = setup();
    // Re-use the same tempdir that has generated keys
    // We need to get the dir path, so let's use a fresh setup approach
    let dir = tempfile::tempdir().unwrap();
    super::super::authenticator::JwtAuthenticator::generate_keypair(dir.path()).unwrap();

    let config_value = serde_json::json!({
        "issuer": "config-test-issuer",
        "audience": "config-test-audience",
        "rsa_pem_path": dir.path().join("private.pem").to_str().unwrap(),
        "rsa_pub_pem_path": dir.path().join("public.pem").to_str().unwrap(),
        "ttl_hours": 4,
        "refresh_ttl_hours": 48,
    });

    let result = JwtIssuer::from_config(&config_value);
    assert!(result.is_ok(), "from_config should succeed with valid JSON");

    let issuer = result.unwrap();
    assert_eq!(issuer.config().issuer, "config-test-issuer");
    assert_eq!(issuer.config().audience, "config-test-audience");
    assert_eq!(issuer.config().ttl_hours, 4);
}

#[test]
fn test_from_config_uses_defaults_for_optional_fields() {
    // from_config should use default TTL values when optional fields are omitted.
    let dir = tempfile::tempdir().unwrap();
    super::super::authenticator::JwtAuthenticator::generate_keypair(dir.path()).unwrap();

    // Only provide required fields; omit ttl_hours and refresh_ttl_hours
    let config_value = serde_json::json!({
        "issuer": "default-ttl-issuer",
        "audience": "default-audience",
        "rsa_pem_path": dir.path().join("private.pem").to_str().unwrap(),
        "rsa_pub_pem_path": dir.path().join("public.pem").to_str().unwrap(),
    });

    let issuer = JwtIssuer::from_config(&config_value).unwrap();
    assert_eq!(issuer.config().ttl_hours, 8, "Default TTL should be 8 hours");
    assert_eq!(
        issuer.config().refresh_ttl_hours, 168,
        "Default refresh TTL should be 168 hours (7 days)"
    );
}

#[test]
fn test_from_config_missing_required_field_returns_error() {
    // from_config should return KeyLoadFailed when required fields are missing.
    let config_value = serde_json::json!({
        "issuer": "incomplete-issuer",
        // Missing: audience, rsa_pem_path, rsa_pub_pem_path
    });

    let result = JwtIssuer::from_config(&config_value);
    assert!(
        matches!(result, Err(JwtError::KeyLoadFailed(_))),
        "Missing 'audience' should cause KeyLoadFailed"
    );
}

#[test]
fn test_from_config_non_object_input_returns_error() {
    // from_config should fail when given a non-object JSON value (e.g., string).
    let config_value = serde_json::json!("this is not an object");

    let result = JwtIssuer::from_config(&config_value);
    assert!(
        matches!(result, Err(JwtError::KeyLoadFailed(_))),
        "Non-object config should cause KeyLoadFailed"
    );
}

#[test]
fn test_from_config_bad_key_path_returns_error() {
    // from_config should propagate key load failures for invalid PEM paths.
    let config_value = serde_json::json!({
        "issuer": "bad-key-issuer",
        "audience": "bad-key-audience",
        "rsa_pem_path": "/nonexistent/path/to/private.pem",
        "rsa_pub_pem_path": "/nonexistent/path/to/public.pem",
    });

    let result = JwtIssuer::from_config(&config_value);
    assert!(
        matches!(result, Err(JwtError::KeyLoadFailed(_))),
        "Invalid key path should propagate as KeyLoadFailed"
    );
}

#[test]
fn test_issue_identity_produces_valid_token() {
    // issue_identity should convert MisogiIdentity → MisogiClaims → valid JWS.
    let (_dir, config) = setup();
    let issuer = JwtIssuer::new(config).unwrap();

    let identity = crate::provider::MisogiIdentity::new("identity-user-001", "test-idp")
        .with_display_name("Identity Test User".to_string())
        .with_roles(vec!["admin".to_string(), "staff".to_string()])
        .with_original_subject("cn=Identity User,dc=example,dc=com".to_string())
        .with_extra("department", serde_json::json!("engineering"));

    let token = issuer.issue_identity(&identity).unwrap();

    // Verify it's valid JWS format
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "Token must have 3 JWS parts");

    // Verify payload contains the identity data
    let payload = decode_payload(&token);
    assert_eq!(payload["applicant_id"], "identity-user-001");
    assert_eq!(payload["display_name"], "Identity Test User");
    assert_eq!(payload["roles"], serde_json::json!(["admin", "staff"]));
    assert_eq!(payload["idp_source"], "test-idp");
    assert_eq!(payload["original_subject"], "cn=Identity User,dc=example,dc=com");
    assert_eq!(payload["department"], "engineering");
}

#[test]
fn test_issue_identity_roundtrip_preserves_all_fields() {
    // All MisogiIdentity fields should survive the full conversion chain.
    let (_dir, config) = setup();
    let issuer = JwtIssuer::new(config).unwrap();

    // Build a comprehensive identity with every field populated
    let mut extra = std::collections::HashMap::new();
    extra.insert("custom_attr".to_string(), serde_json::json!(42));
    extra.insert("location".to_string(), serde_json::json!("Tokyo"));

    let identity = crate::provider::MisogiIdentity {
        applicant_id: "comprehensive-user".to_string(),
        display_name: Some(" Comprehensive User ".trim().to_string()),
        roles: vec!["role-a".to_string(), "role-b".to_string()],
        idp_source: "oidc-keycloak".to_string(),
        original_subject: Some("sub-abc123-def456".to_string()),
        extra,
    };

    let token = issuer.issue_identity(&identity).unwrap();
    let payload = decode_payload(&token);

    assert_eq!(payload["applicant_id"], "comprehensive-user");
    assert_eq!(payload["display_name"], "Comprehensive User");
    assert_eq!(payload["idp_source"], "oidc-keycloak");
    assert_eq!(payload["original_subject"], "sub-abc123-def456");
    assert_eq!(payload["custom_attr"], 42);
    assert_eq!(payload["location"], "Tokyo");
}

#[test]
fn test_issue_with_ttl_identity_applies_custom_expiration() {
    // issue_with_ttl_identity should respect custom TTL from MisogiIdentity.
    let (_dir, config) = setup();
    let issuer = JwtIssuer::new(config).unwrap();

    let identity = crate::provider::MisogiIdentity::new("ttl-identity-user", "ldap");

    // Issue with exactly 180 second TTL
    let token = issuer.issue_with_ttl_identity(&identity, 180).unwrap();
    let payload = decode_payload(&token);

    let exp = payload["exp"].as_u64().unwrap();
    let iat = payload["iat"].as_u64().unwrap();
    let lifetime = exp.saturating_sub(iat);

    assert!(
        lifetime >= 178 && lifetime <= 182,
        "Custom TTL of 180s should produce ~180s lifetime, got {}s",
        lifetime
    );
}

#[test]
fn test_issue_with_ttl_identity_zero_ttl_rejected() {
    // issue_with_ttl_identity should reject zero TTL with ClaimValidationFailed.
    let (_dir, config) = setup();
    let issuer = JwtIssuer::new(config).unwrap();

    let identity = crate::provider::MisogiIdentity::new("zero-ttl-user", "test");

    let result = issuer.issue_with_ttl_identity(&identity, 0);
    assert!(
        matches!(result, Err(JwtError::ClaimValidationFailed(_))),
        "Zero TTL should be rejected"
    );
}

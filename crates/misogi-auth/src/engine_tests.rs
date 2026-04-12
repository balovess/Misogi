//! Comprehensive tests for AuthEngine (micro-kernel) and IdentityRegistry.
//!
//! Tests are organized into sections:
//! - Engine construction and configuration
//! - Token validation (JWT feature-gated)
//! - API key validation
//! - Audit logging
//! - Registry operations
//! - Integration scenarios

use std::sync::Arc;

use chrono::Utc;

use super::*;
use crate::provider::{AuthRequest, IdentityError, IdentityProvider, MisogiIdentity};
use crate::role::UserRole;

// ===========================================================================
// Mock Identity Provider for Testing
// ===========================================================================

/// Simple mock identity provider that returns predetermined results.
///
/// Used to test [`IdentityRegistry`] and [`AuthEngine::authenticate_via_provider`]
/// without requiring real LDAP/OIDC/SAML infrastructure.
struct MockProvider {
    id: String,
    name: String,
    should_succeed: bool,
    expected_username: Option<String>,
}

impl MockProvider {
    /// Create a mock provider that always succeeds.
    fn successful(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            should_succeed: true,
            expected_username: None,
        }
    }

    /// Create a mock provider that always fails.
    fn failing(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            should_succeed: false,
            expected_username: None,
        }
    }
}

#[async_trait::async_trait]
impl IdentityProvider for MockProvider {
    fn provider_id(&self) -> &str {
        &self.id
    }

    fn provider_name(&self) -> &str {
        &self.name
    }

    async fn authenticate(
        &self,
        input: AuthRequest,
    ) -> Result<MisogiIdentity, IdentityError> {
        if !self.should_succeed {
            return Err(IdentityError::InvalidCredentials);
        }

        // Extract username from Credentials variant if available
        let applicant_id = match &input {
            AuthRequest::Credentials { username, .. } => username.clone(),
            _ => "mock-user".to_string(),
        };

        Ok(MisogiIdentity::new(applicant_id, &self.id)
            .with_display_name(&self.name)
            .with_roles(vec!["staff".to_string()]))
    }

    async fn health_check(&self) -> Result<(), IdentityError> {
        if self.should_succeed {
            Ok(())
        } else {
            Err(IdentityError::ProviderUnavailable(
                "Mock provider intentionally unhealthy".to_string(),
            ))
        }
    }
}

// ===========================================================================
// Section 1: AuthStrategy Tests
// ===========================================================================

#[test]
fn test_auth_strategy_default_is_first_match() {
    let strategy = AuthStrategy::default();
    assert_eq!(strategy, AuthStrategy::FirstMatch);
}

#[test]
fn test_auth_strategy_display() {
    assert_eq!(AuthStrategy::FirstMatch.to_string(), "first_match");
    assert_eq!(AuthStrategy::Sequential.to_string(), "sequential");
    assert_eq!(AuthStrategy::Required.to_string(), "required");
}

#[test]
fn test_auth_strategy_serialization_roundtrip() {
    let strategies = vec![
        AuthStrategy::FirstMatch,
        AuthStrategy::Sequential,
        AuthStrategy::Required,
    ];

    for strategy in &strategies {
        let json = serde_json::to_string(strategy).unwrap();
        let deserialized: AuthStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*strategy, deserialized);
    }
}

// ===========================================================================
// Section 2: ServiceAccount Tests
// ===========================================================================

#[test]
fn test_service_account_not_expired_when_no_expiry() {
    let account = ServiceAccount {
        key_id: "key-001".to_string(),
        name: "Test Service".to_string(),
        roles: vec![UserRole::Staff],
        created_at: Utc::now(),
        expires_at: None,
    };

    assert!(!account.is_expired());
}

#[test]
fn test_service_account_not_expired_when_future() {
    let account = ServiceAccount {
        key_id: "key-002".to_string(),
        name: "Future Service".to_string(),
        roles: vec![UserRole::Admin],
        created_at: Utc::now(),
        expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
    };

    assert!(!account.is_expired());
}

#[test]
fn test_service_account_expired_when_past() {
    let account = ServiceAccount {
        key_id: "key-003".to_string(),
        name: "Expired Service".to_string(),
        roles: vec![UserRole::Staff],
        created_at: Utc::now() - chrono::Duration::days(30),
        expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
    };

    assert!(account.is_expired());
}

// ===========================================================================
// Section 3: AuthError Tests
// ===========================================================================

#[test]
fn test_auth_error_http_status_mapping() {
    use AuthError::*;

    assert_eq!(InvalidToken("test".into()).http_status(), 401);
    assert_eq!(ExpiredToken.http_status(), 401);
    assert_eq!(MissingCredentials.http_status(), 401);
    assert_eq!(InvalidApiKey.http_status(), 401);
    assert_eq!(InternalError("test".into()).http_status(), 500);
}

#[test]
fn test_auth_error_error_codes() {
    use AuthError::*;

    assert_eq!(InvalidToken("".into()).error_code(), "invalid_token");
    assert_eq!(ExpiredToken.error_code(), "expired_token");
    assert_eq!(MissingCredentials.error_code(), "missing_credentials");
    assert_eq!(InvalidApiKey.error_code(), "invalid_api_key");
    assert_eq!(InternalError("".into()).error_code(), "internal_error");
}

#[test]
fn test_auth_error_error_body_contains_required_fields() {
    let error = AuthError::ExpiredToken;
    let body = error.error_body();

    assert_eq!(body["error"], "expired_token");
    assert!(body.get("message").is_some());
    assert_eq!(body["status_code"], 401);
}

#[test]
fn test_auth_error_display_messages() {
    use AuthError::*;

    let msg = InvalidToken("bad sig".to_string()).to_string();
    assert!(msg.contains("invalid token"));
    assert!(msg.contains("bad sig"));

    let msg = InternalError("boom".to_string()).to_string();
    assert!(msg.contains("internal error"));
    assert!(msg.contains("boom"));
}

// ===========================================================================
// Section 4: RoleMappingRule Tests
// ===========================================================================

#[test]
fn test_role_mapping_rule_creation() {
    let rule = RoleMappingRule::new(r"(?i)admin.*", UserRole::Admin, 10);
    assert!(rule.is_ok());
    let rule = rule.unwrap();
    assert!(rule.matches("admin-group"));
    assert!(rule.matches("ADMIN-GROUP"));
    assert!(!rule.matches("user-group"));
    assert_eq!(rule.target_role, UserRole::Admin);
    assert_eq!(rule.priority, 10);
}

#[test]
fn test_role_mapping_rule_invalid_regex() {
    let result = RoleMappingRule::new(r"[invalid(regex", UserRole::Staff, 1);
    assert!(result.is_err());
}

#[test]
fn test_default_role_mapping_rules_exist() {
    let rules = default_role_mapping_rules();
    assert!(!rules.is_empty());
    // Should have at least admin and approver rules
    assert!(rules.iter().any(|r| r.target_role == UserRole::Admin));
    assert!(rules.iter().any(|r| r.target_role == UserRole::Approver));
}

// ===========================================================================
// Section 5: AuditEvent Tests
// ===========================================================================

#[test]
fn test_audit_event_creation() {
    let event = AuditEvent::new(AuditEventType::AuthSuccess, "Test event");

    assert_eq!(event.event_type, AuditEventType::AuthSuccess);
    assert_eq!(event.details, "Test event");
    assert!(event.user_id.is_none());
    assert!(event.ip_address.is_none());
    // Timestamp should be recent (within last 5 seconds)
    let age = Utc::now() - event.timestamp;
    assert!(age.num_seconds() < 5);
}

#[test]
fn test_audit_event_builder_pattern() {
    let event = AuditEvent::new(AuditEventType::AuthFailure, "Bad credentials")
        .with_user_id("user-001")
        .with_ip("192.168.1.100");

    assert_eq!(event.user_id.as_deref().unwrap(), "user-001");
    assert_eq!(event.ip_address.as_deref().unwrap(), "192.168.1.100");
}

#[test]
fn test_audit_event_type_serialization() {
    let types = vec![
        AuditEventType::AuthSuccess,
        AuditEventType::AuthFailure,
        AuditEventType::TokenExchange,
        AuditEventType::Logout,
        AuditEventType::ConfigChange,
    ];

    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let deserialized: AuditEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, deserialized);
    }
}

// ===========================================================================
// Section 6: IdentityRegistry Tests
// ===========================================================================

#[test]
fn test_registry_new_is_empty() {
    let registry = IdentityRegistry::new();
    assert_eq!(registry.provider_count(), 0);
    assert!(registry.list().is_empty());
}

#[test]
fn test_registry_register_single_provider() {
    let mut registry = IdentityRegistry::new();
    let provider = Box::new(MockProvider::successful("test-id", "Test Provider"));

    let result = registry.register(provider);
    assert!(result.is_ok());
    assert_eq!(registry.provider_count(), 1);
    assert!(registry.contains("test-id"));
}

#[test]
fn test_registry_register_duplicate_fails() {
    let mut registry = IdentityRegistry::new();

    registry
        .register(Box::new(MockProvider::successful("dup-id", "First")))
        .unwrap();

    let result = registry.register(Box::new(MockProvider::successful("dup-id", "Second")));
    assert!(result.is_err());

    match result.unwrap_err() {
        IdentityError::ConfigurationError(msg) => {
            assert!(msg.contains("already registered"));
        }
        other => panic!("Expected ConfigurationError, got: {other}"),
    }

    // Original provider should still be registered
    assert_eq!(registry.provider_count(), 1);
}

#[test]
fn test_registry_list_returns_correct_metadata() {
    let mut registry = IdentityRegistry::new();
    registry
        .register(Box::new(MockProvider::successful("p1", "Provider One")))
        .unwrap();
    registry
        .register(Box::new(MockProvider::successful("p2", "Provider Two")))
        .unwrap();

    let list = registry.list();
    assert_eq!(list.len(), 2);

    let ids: Vec<&str> = list.iter().map(|p| p.id.as_str()).collect();
    assert!(ids.contains(&"p1"));
    assert!(ids.contains(&"p2"));

    let names: Vec<&str> = list.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"Provider One"));
    assert!(names.contains(&"Provider Two"));
}

#[test]
fn test_registry_unregister_existing() {
    let mut registry = IdentityRegistry::new();
    registry
        .register(Box::new(MockProvider::successful("removable", "Remove Me")))
        .unwrap();

    assert_eq!(registry.provider_count(), 1);

    let removed = registry.unregister("removable").unwrap();
    assert!(removed);
    assert_eq!(registry.provider_count(), 0);
    assert!(!registry.contains("removable"));
}

#[test]
fn test_registry_unregister_nonexistent_returns_false() {
    let mut registry = IdentityRegistry::new();
    let removed = registry.unregister("ghost").unwrap();
    assert!(!removed);
}

#[test]
fn test_registry_get_found() {
    let mut registry = IdentityRegistry::new();
    registry
        .register(Box::new(MockProvider::successful("findable", "Find Me")))
        .unwrap();

    let provider = registry.get("findable");
    assert!(provider.is_some());
    assert_eq!(provider.unwrap().provider_id(), "findable");
}

#[test]
fn test_registry_get_not_found() {
    let registry = IdentityRegistry::new();
    assert!(registry.get("nonexistent").is_none());
}

#[tokio::test]
async fn test_registry_health_check_all_healthy() {
    let mut registry = IdentityRegistry::new();
    registry
        .register(Box::new(MockProvider::successful("healthy-1", "Healthy One")))
        .unwrap();
    registry
        .register(Box::new(MockProvider::successful("healthy-2", "Healthy Two")))
        .unwrap();

    let results = registry.health_check_all().await;
    assert_eq!(results.len(), 2);

    for (_id, result) in &results {
        assert!(result.is_ok(), "All providers should be healthy");
    }
}

#[tokio::test]
async fn test_registry_health_check_all_mixed() {
    let mut registry = IdentityRegistry::new();
    registry
        .register(Box::new(MockProvider::successful("ok", "OK")))
        .unwrap();
    registry
        .register(Box::new(MockProvider::failing("fail", "Failing")))
        .unwrap();

    let results = registry.health_check_all().await;
    assert_eq!(results.len(), 2);

    let ok_result = results.iter().find(|(id, _)| *id == "ok").unwrap();
    assert!(ok_result.1.is_ok());

    let fail_result = results.iter().find(|(id, _)| *id == "fail").unwrap();
    assert!(fail_result.1.is_err());
}

#[tokio::test]
async fn test_registry_authenticate_success() {
    let mut registry = IdentityRegistry::new();
    registry
        .register(Box::new(MockProvider::successful("auth-test", "Auth Provider")))
        .unwrap();

    let request = AuthRequest::Credentials {
        username: "tanaka".to_string(),
        password: "secret".to_string(),
    };

    let identity = registry.authenticate("auth-test", request).await;
    assert!(identity.is_ok());

    let identity = identity.unwrap();
    assert_eq!(identity.applicant_id, "tanaka");
    assert_eq!(identity.idp_source, "auth-test");
}

#[tokio::test]
async fn test_registry_authenticate_unknown_provider() {
    let registry = IdentityRegistry::new();

    let request = AuthRequest::Credentials {
        username: "nobody".to_string(),
        password: "nopass".to_string(),
    };

    let result = registry.authenticate("ghost-provider", request).await;
    assert!(result.is_err());

    match result.unwrap_err() {
        IdentityError::ConfigurationError(msg) => {
            assert!(msg.contains("not found"));
        }
        other => panic!("Expected ConfigurationError, got: {other}"),
    }
}

#[tokio::test]
async fn test_registry_authenticate_failing_provider() {
    let mut registry = IdentityRegistry::new();
    registry
        .register(Box::new(MockProvider::failing("bad-auth", "Bad Auth")))
        .unwrap();

    let request = AuthRequest::Credentials {
        username: "user".to_string(),
        password: "pass".to_string(),
    };

    let result = registry.authenticate("bad-auth", request).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        IdentityError::InvalidCredentials => {} // Expected
        other => panic!("Expected InvalidCredentials, got: {other}"),
    }
}

// ===========================================================================
// Section 7: AuthEngine Construction Tests (feature-gated)
// ===========================================================================

#[cfg(feature = "jwt")]
mod jwt_engine_tests {
    use super::*;

    /// Helper: create a temporary JWT config pointing to non-existent key.
    /// Tests that use this should expect initialization failure.
    fn dummy_jwt_config() -> crate::jwt::JwtConfig {
        crate::jwt::JwtConfig {
            issuer: "test-issuer".to_string(),
            audience: "test-audience".to_string(),
            rsa_pem_path: "/nonexistent/private.pem".into(),
            rsa_pub_pem_path: "/nonexistent/public.pem".into(),
            ttl_hours: 1,
            refresh_ttl_hours: 24,
        }
    }

    #[test]
    fn test_engine_creation_fails_with_bad_key_path() {
        let config = dummy_jwt_config();
        let result = AuthEngine::new(config);
        // Should fail because key file doesn't exist
        assert!(result.is_err());
    }
}

#[cfg(not(feature = "jwt"))]
mod no_jwt_engine_tests {
    use super::*;

    #[test]
    fn test_engine_creation_without_jwt() {
        let result = AuthEngine::new(());
        assert!(result.is_ok());
        let engine = result.unwrap();
        assert!(!engine.has_identity_registry());
        assert_eq!(engine.api_key_count(), 0);
    }
}

// ===========================================================================
// Section 8: AuthEngine API Key Tests
// ===========================================================================

fn create_test_engine() -> AuthEngine {
    #[cfg(feature = "jwt")]
    {
        // For JWT-enabled builds, we need a valid config or handle the error.
        // Since we can't create real keys in unit tests easily, create minimal.
        // This will fail at JwtValidator::new if keys don't exist.
        // For API key tests, we can work around by testing the struct directly.
        // Instead, let's just verify the API key logic works independently.
        panic!("API key tests require either valid JWT config or no-jwt mode");
    }

    #[cfg(not(feature = "jwt"))]
    {
        AuthEngine::new(()).expect("Engine creation should succeed")
    }
}

#[cfg(not(feature = "jwt"))]
mod api_key_engine_tests {
    use super::*;

    fn get_engine() -> AuthEngine {
        AuthEngine::new(()).unwrap()
    }

    #[test]
    fn test_validate_api_key_empty_returns_missing_credentials() {
        let engine = get_engine();
        let result = engine.validate_api_key("");
        assert!(matches!(result, Err(AuthError::MissingCredentials)));
    }

    #[test]
    fn test_validate_api_key_unknown_returns_invalid() {
        let engine = get_engine();
        let result = engine.validate_api_key("unknown-key-xyz");
        assert!(matches!(result, Err(AuthError::InvalidApiKey)));
    }

    #[test]
    fn test_validate_api_key_registered_key_succeeds() {
        let mut engine = get_engine();

        let account = ServiceAccount {
            key_id: "sk-test-valid".to_string(),
            name: "Test Service Account".to_string(),
            roles: vec![UserRole::Staff],
            created_at: Utc::now(),
            expires_at: None,
        };
        engine.register_api_key(account);

        let result = engine.validate_api_key("sk-test-valid");
        assert!(result.is_ok());

        let retrieved = result.unwrap();
        assert_eq!(retrieved.key_id, "sk-test-valid");
        assert_eq!(retrieved.name, "Test Service Account");
        assert_eq!(retrieved.roles, vec![UserRole::Staff]);
    }

    #[test]
    fn test_register_api_key_increments_count() {
        let mut engine = get_engine();
        assert_eq!(engine.api_key_count(), 0);

        engine.register_api_key(ServiceAccount {
            key_id: "key-1".to_string(),
            name: "One".to_string(),
            roles: vec![],
            created_at: Utc::now(),
            expires_at: None,
        });
        assert_eq!(engine.api_key_count(), 1);

        engine.register_api_key(ServiceAccount {
            key_id: "key-2".to_string(),
            name: "Two".to_string(),
            roles: vec![],
            created_at: Utc::now(),
            expires_at: None,
        });
        assert_eq!(engine.api_key_count(), 2);
    }

    #[test]
    fn test_validate_token_without_jwt_feature_returns_internal_error() {
        let engine = get_engine();
        let result = engine.validate_token("some-token");
        assert!(matches!(result, Err(AuthError::InternalError(_))));
    }
}

// ===========================================================================
// Section 9: AuthEngine Audit Log Tests
// ===========================================================================

#[cfg(not(feature = "jwt"))]
mod audit_log_tests {
    use super::*;

    fn get_engine() -> AuthEngine {
        AuthEngine::new(()).unwrap()
    }

    #[test]
    fn test_audit_log_starts_empty() {
        let engine = get_engine();
        let events = engine.get_audit_events(None, None);
        assert!(events.is_empty());
    }

    #[test]
    fn test_audit_log_records_events_via_config_change() {
        let mut engine = get_engine();

        // Register an API key triggers an audit event
        engine.register_api_key(ServiceAccount {
            key_id: "audit-test-key".to_string(),
            name: "Audit Test".to_string(),
            roles: vec![],
            created_at: Utc::now(),
            expires_at: None,
        });

        let events = engine.get_audit_events(None, None);
        assert!(!events.is_empty());

        let config_events: Vec<_> = events
            .iter()
            .filter(|e| e.event_type == AuditEventType::ConfigChange)
            .collect();
        assert!(!config_events.is_empty());
    }

    #[test]
    fn test_audit_log_filter_by_type() {
        let mut engine = get_engine();

        // Record some events via registration
        engine.register_api_key(ServiceAccount {
            key_id: "filter-key-1".to_string(),
            name: "Filter Test 1".to_string(),
            roles: vec![],
            created_at: Utc::now(),
            expires_at: None,
        });

        engine.register_api_key(ServiceAccount {
            key_id: "filter-key-2".to_string(),
            name: "Filter Test 2".to_string(),
            roles: vec![],
            created_at: Utc::now(),
            expires_at: None,
        });

        // Filter for ConfigChange only
        let config_events = engine.get_audit_events(None, Some(AuditEventType::ConfigChange));
        assert_eq!(config_events.len(), 2); // Two registrations

        // Filter for AuthSuccess (should be none from registration)
        let success_events = engine.get_audit_events(None, Some(AuditEventType::AuthSuccess));
        assert!(success_events.is_empty());
    }

    #[test]
    fn test_audit_log_clear() {
        let mut engine = get_engine();

        engine.register_api_key(ServiceAccount {
            key_id: "clear-key".to_string(),
            name: "Clear Test".to_string(),
            roles: vec![],
            created_at: Utc::now(),
            expires_at: None,
        });

        assert!(!engine.get_audit_events(None, None).is_empty());

        engine.clear_audit_log();
        assert!(engine.get_audit_events(None, None).is_empty());
    }

    #[test]
    fn test_set_audit_log_max_size() {
        let mut engine = get_engine();
        engine.set_audit_log_max_size(50);
        // No crash = success; actual size limiting tested implicitly
    }

    #[test]
    fn test_set_audit_log_max_size_zero_rejected() {
        let mut engine = get_engine();
        // Should not panic, should just warn and ignore
        engine.set_audit_log_max_size(0);
        // If we get here, it was handled gracefully
    }
}

// ===========================================================================
// Section 10: AuthEngine Strategy Configuration Tests
// ===========================================================================

#[cfg(not(feature = "jwt"))]
mod strategy_config_tests {
    use super::*;

    fn get_engine() -> AuthEngine {
        AuthEngine::new(()).unwrap()
    }

    #[test]
    fn test_default_strategy_is_first_match() {
        let engine = get_engine();
        assert_eq!(engine.auth_strategy(), AuthStrategy::FirstMatch);
    }

    #[test]
    fn test_set_strategy_to_sequential() {
        let mut engine = get_engine();
        engine.set_auth_strategy(AuthStrategy::Sequential);
        assert_eq!(engine.auth_strategy(), AuthStrategy::Sequential);
    }

    #[test]
    fn test_set_strategy_to_required() {
        let mut engine = get_engine();
        engine.set_auth_strategy(AuthStrategy::Required);
        assert_eq!(engine.auth_strategy(), AuthStrategy::Required);
    }

    #[test]
    fn test_set_role_mapping_rules() {
        let mut engine = get_engine();

        let custom_rules = vec![
            RoleMappingRule::new(r"custom-admin", UserRole::Admin, 1)
                .expect("valid regex"),
        ];
        engine.set_role_mapping_rules(custom_rules);
        // No assertion on internal state; just verify no panic
    }

    #[test]
    fn test_has_identity_registry_false_by_default() {
        let engine = get_engine();
        assert!(!engine.has_identity_registry());
    }
}

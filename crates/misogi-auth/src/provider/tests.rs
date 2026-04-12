//! Unit tests for [`super::IdentityProvider`] trait and related types.
//!
//! Covers: mock provider, trait object safety, AuthRequest variants,
//! IdentityError display, MisogiIdentity construction, and
//! MisogiIdentity → MisogiClaims conversion.

use std::collections::HashMap;

use super::*;

// ---- Mock Provider Implementation ----

/// Mock identity provider for testing the `IdentityProvider` trait contract.
/// NOT suitable for production use.
struct MockIdp {
    id: String,
    name: String,
    healthy: bool,
}

impl MockIdp {
    fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            healthy: true,
        }
    }

    /// Create a mock provider that will fail health checks.
    fn unhealthy(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            healthy: false,
        }
    }
}

#[async_trait]
impl IdentityProvider for MockIdp {
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
        match input {
            AuthRequest::Credentials { username, .. } => {
                if username.is_empty() {
                    return Err(IdentityError::InvalidCredentials);
                }
                let display = format!("Mock: {username}");
                Ok(MisogiIdentity::new(username, self.provider_id())
                    .with_display_name(display)
                    .with_roles(vec!["mock-role".to_string()]))
            }
            AuthRequest::AuthorizationCode { code, .. } => {
                if code.is_empty() {
                    return Err(IdentityError::TokenExchangeFailed(
                        "empty authorization code".into(),
                    ));
                }
                Ok(MisogiIdentity::new(
                    format!("user-{code}"),
                    self.provider_id(),
                ))
            }
            AuthRequest::SamlResponse { response } => {
                if response.is_empty() {
                    return Err(IdentityError::AuthenticationFailed(
                        "empty SAML response".into(),
                    ));
                }
                Ok(MisogiIdentity::new(
                    "saml-user".to_string(),
                    self.provider_id(),
                )
                .with_original_subject("urn:saml:subject".to_string()))
            }
            AuthRequest::ApiKey { key } => {
                if key == "valid-key" {
                    Ok(MisogiIdentity::new(
                        "api-user".to_string(),
                        self.provider_id(),
                    )
                    .with_roles(vec!["service-account".to_string()]))
                } else {
                    Err(IdentityError::InvalidCredentials)
                }
            }
        }
    }

    async fn health_check(&self) -> Result<(), IdentityError> {
        if self.healthy {
            Ok(())
        } else {
            Err(IdentityError::ProviderUnavailable(
                "mock provider is intentionally unhealthy".into(),
            ))
        }
    }
}

// ---- Test Cases: Provider Metadata ----

#[test]
fn test_mock_provider_returns_correct_provider_id() {
    let provider = MockIdp::new("test-idp-001", "Test Provider");
    assert_eq!(provider.provider_id(), "test-idp-001");
}

#[test]
fn test_mock_provider_returns_correct_provider_name() {
    let provider = MockIdp::new("test-idp", "Test Provider Name");
    assert_eq!(provider.provider_name(), "Test Provider Name");
}

// ---- Test Cases: Authentication Flows ----

#[tokio::test]
async fn test_authenticate_with_credentials_succeeds() {
    let provider = MockIdp::new("mock", "Mock");
    let request = AuthRequest::Credentials {
        username: "tanaka".to_string(),
        password: "secret".to_string(),
    };

    let identity = provider.authenticate(request).await.unwrap();

    assert_eq!(identity.applicant_id, "tanaka");
    assert_eq!(identity.display_name.as_deref(), Some("Mock: tanaka"));
    assert_eq!(identity.roles, vec!["mock-role"]);
    assert_eq!(identity.idp_source, "mock");
}

#[tokio::test]
async fn test_authenticate_with_empty_username_fails() {
    let provider = MockIdp::new("mock", "Mock");
    let request = AuthRequest::Credentials {
        username: String::new(),
        password: "secret".to_string(),
    };

    let result = provider.authenticate(request).await;
    assert!(matches!(result, Err(IdentityError::InvalidCredentials)));
}

#[tokio::test]
async fn test_authenticate_with_authorization_code() {
    let provider = MockIdp::new("oidc-mock", "OIDC Mock");
    let request = AuthRequest::AuthorizationCode {
        code: "abc123xyz".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        code_verifier: Some("verifier-secret".to_string()),
    };

    let identity = provider.authenticate(request).await.unwrap();

    assert_eq!(identity.applicant_id, "user-abc123xyz");
    assert_eq!(identity.idp_source, "oidc-mock");
}

#[tokio::test]
async fn test_authenticate_with_empty_code_fails() {
    let provider = MockIdp::new("oidc-mock", "OIDC Mock");
    let request = AuthRequest::AuthorizationCode {
        code: String::new(),
        redirect_uri: "https://example.com/callback".to_string(),
        code_verifier: None,
    };

    let result = provider.authenticate(request).await;
    assert!(matches!(
        result,
        Err(IdentityError::TokenExchangeFailed(_))
    ));
}

#[tokio::test]
async fn test_authenticate_with_saml_response() {
    let provider = MockIdp::new("saml-mock", "SAML Mock");
    let request = AuthRequest::SamlResponse {
        response: "base64-saml-payload".to_string(),
    };

    let identity = provider.authenticate(request).await.unwrap();

    assert_eq!(identity.applicant_id, "saml-user");
    assert_eq!(
        identity.original_subject.as_deref(),
        Some("urn:saml:subject")
    );
}

#[tokio::test]
async fn test_authenticate_with_api_key_valid() {
    let provider = MockIdp::new("key-mock", "API Key Mock");
    let request = AuthRequest::ApiKey {
        key: "valid-key".to_string(),
    };

    let identity = provider.authenticate(request).await.unwrap();

    assert_eq!(identity.applicant_id, "api-user");
    assert_eq!(identity.roles, vec!["service-account"]);
}

#[tokio::test]
async fn test_authenticate_with_api_key_invalid() {
    let provider = MockIdp::new("key-mock", "API Key Mock");
    let request = AuthRequest::ApiKey {
        key: "wrong-key".to_string(),
    };

    let result = provider.authenticate(request).await;
    assert!(matches!(result, Err(IdentityError::InvalidCredentials)));
}

// ---- Test Cases: Health Check ----

#[tokio::test]
async fn test_health_check_passes_for_healthy_provider() {
    let provider = MockIdp::new("healthy", "Healthy Provider");
    let result = provider.health_check().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_health_check_fails_for_unhealthy_provider() {
    let provider = MockIdp::unhealthy("broken", "Broken Provider");
    let result = provider.health_check().await;
    assert!(matches!(
        result,
        Err(IdentityError::ProviderUnavailable(_))
    ));
}

// ---- Test Cases: Trait Object Safety ----

#[test]
fn test_trait_is_object_safe() {
    // Verify that dyn IdentityProvider can be used as a trait object.
    // This compiles only if the trait is object-safe.
    fn _accepts_trait_object(_: &dyn IdentityProvider) {}

    let provider = MockIdp::new("obj-test", "Object Safe Test");
    _accepts_trait_object(&provider);

    // Also verify Box<dyn IdentityProvider> works
    let _: Box<dyn IdentityProvider> = Box::new(MockIdp::new("boxed", "Boxed"));
}

#[tokio::test]
async fn test_trait_object_dispatch_works() {
    // Demonstrate runtime polymorphism through dyn IdentityProvider
    let ldap = MockIdp::new("ldap", "LDAP");
    let oidc = MockIdp::new("oidc", "OIDC");
    let saml = MockIdp::new("saml", "SAML");

    let providers: Vec<&dyn IdentityProvider> = vec![&ldap, &oidc, &saml];

    for provider in &providers {
        assert!(!provider.provider_id().is_empty());
        assert!(!provider.provider_name().is_empty());
        let health = provider.health_check().await;
        assert!(
            health.is_ok(),
            "Provider {} should be healthy",
            provider.provider_id()
        );
    }
}

// ---- Test Cases: AuthRequest Variants ----

#[test]
fn test_auth_request_credentials_variant() {
    let req = AuthRequest::Credentials {
        username: "user1".to_string(),
        password: "pass1".to_string(),
    };

    match &req {
        AuthRequest::Credentials { username, password } => {
            assert_eq!(username, "user1");
            assert_eq!(password, "pass1");
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_auth_request_authorization_code_variant() {
    let req = AuthRequest::AuthorizationCode {
        code: "code-abc".to_string(),
        redirect_uri: "https://app.example/callback".to_string(),
        code_verifier: Some("pkce-verifier".to_string()),
    };

    match &req {
        AuthRequest::AuthorizationCode {
            code,
            redirect_uri,
            code_verifier,
        } => {
            assert_eq!(code, "code-abc");
            assert_eq!(redirect_uri, "https://app.example/callback");
            assert_eq!(code_verifier.as_deref(), Some("pkce-verifier"));
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_auth_request_saml_response_variant() {
    let req = AuthRequest::SamlResponse {
        response: "base64xml...".to_string(),
    };

    match &req {
        AuthRequest::SamlResponse { response } => {
            assert_eq!(response, "base64xml...");
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_auth_request_api_key_variant() {
    let req = AuthRequest::ApiKey {
        key: "sk-live-abc123".to_string(),
    };

    match &req {
        AuthRequest::ApiKey { key } => {
            assert_eq!(key, "sk-live-abc123");
        }
        _ => panic!("Wrong variant"),
    }
}

// ---- Test Cases: IdentityError Display ----

#[test]
fn test_identity_error_invalid_credentials_display() {
    let err = IdentityError::InvalidCredentials;
    let msg = format!("{err}");
    assert!(msg.contains("invalid credentials"));
}

#[test]
fn test_identity_error_user_not_found_display() {
    let err = IdentityError::UserNotFound;
    let msg = format!("{err}");
    assert!(msg.contains("user not found"));
}

#[test]
fn test_identity_error_provider_unavailable_display() {
    let err = IdentityError::ProviderUnavailable("connection timed out".into());
    let msg = format!("{err}");
    assert!(msg.contains("provider unavailable"));
    assert!(msg.contains("connection timed out"));
}

#[test]
fn test_identity_error_configuration_error_display() {
    let err = IdentityError::ConfigurationError("missing url".into());
    let msg = format!("{err}");
    assert!(msg.contains("configuration error"));
    assert!(msg.contains("missing url"));
}

#[test]
fn test_identity_error_token_exchange_failed_display() {
    let err = IdentityError::TokenExchangeFailed("invalid_grant".into());
    let msg = format!("{err}");
    assert!(msg.contains("token exchange failed"));
    assert!(msg.contains("invalid_grant"));
}

#[test]
fn test_identity_error_authentication_failed_display() {
    let err = IdentityError::AuthenticationFailed("SAML signature invalid".into());
    let msg = format!("{err}");
    assert!(msg.contains("authentication failed"));
    assert!(msg.contains("SAML signature invalid"));
}

#[test]
fn test_identity_error_internal_error_display() {
    let err = IdentityError::InternalError("unexpected null pointer".into());
    let msg = format!("{err}");
    assert!(msg.contains("internal error"));
    assert!(msg.contains("unexpected null pointer"));
}

// ---- Test Cases: MisogiIdentity Construction ----

#[test]
fn test_identity_new_with_defaults() {
    let identity = MisogiIdentity::new("user-001", "test-idp");

    assert_eq!(identity.applicant_id, "user-001");
    assert_eq!(identity.idp_source, "test-idp");
    assert!(identity.display_name.is_none());
    assert!(identity.roles.is_empty());
    assert!(identity.original_subject.is_none());
    assert!(identity.extra.is_empty());
}

#[test]
fn test_identity_builder_pattern() {
    let identity = MisogiIdentity::new("user-002", "ldap")
        .with_display_name("鈴木花子")
        .with_roles(vec!["admin".to_string(), "auditor".to_string()])
        .with_original_subject("uid=suzuki,ou=users,dc=corp")
        .with_extra("email", serde_json::json!("suzuki@corp.jp"));

    assert_eq!(identity.display_name.as_deref(), Some("鈴木花子"));
    assert_eq!(identity.roles.len(), 2);
    assert!(identity.roles.contains(&"admin".to_string()));
    assert!(
        identity.original_subject.as_deref()
            == Some("uid=suzuki,ou=users,dc=corp")
    );
    assert_eq!(
        identity.extra.get("email").unwrap(),
        &serde_json::json!("suzuki@corp.jp")
    );
}

// ---- Test Cases: Conversion MisogiIdentity → MisogiClaims ----

#[test]
fn test_identity_to_claims_conversion_maps_all_fields() {
    let identity = MisogiIdentity::new("EMP-099", "ldap-corp")
        .with_display_name("佐藤次郎".to_string())
        .with_roles(vec!["manager".to_string()])
        .with_original_subject("cn=Sato Jiro,ou=Tokyo".to_string())
        .with_extra("department", serde_json::json!("Engineering"));

    let claims: MisogiClaims = identity.into();

    assert_eq!(claims.applicant_id, "EMP-099");
    assert_eq!(claims.display_name.as_deref(), Some("佐藤次郎"));
    assert_eq!(claims.roles, vec!["manager"]);
    assert_eq!(claims.idp_source, "ldap-corp");
    assert_eq!(
        claims.original_subject.as_deref(),
        Some("cn=Sato Jiro,ou=Tokyo")
    );
    assert_eq!(
        claims.extra.get("department").unwrap(),
        &serde_json::json!("Engineering")
    );
    // Temporal fields should be set by conversion
    assert!(claims.exp > claims.iat);
}

#[test]
fn test_identity_to_claims_preserves_extra_flattened() {
    let mut extra = HashMap::new();
    extra.insert("locale".to_string(), serde_json::json!("ja-JP"));
    extra.insert("tenant".to_string(), serde_json::json!("corp-main"));

    let identity = MisogiIdentity {
        applicant_id: "u-100".to_string(),
        display_name: None,
        roles: vec![],
        idp_source: "test".to_string(),
        original_subject: None,
        extra,
    };

    let claims: MisogiClaims = identity.into();

    assert_eq!(claims.extra.get("locale").unwrap(), &serde_json::json!("ja-JP"));
    assert_eq!(claims.extra.get("tenant").unwrap(), &serde_json::json!("corp-main"));
}

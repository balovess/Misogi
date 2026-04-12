//! Unit tests for IdentityRegistry component.
//!
//! Tests cover:
//! - Provider registration and duplicate handling
//! - Provider retrieval (found / not found)
//! - Provider removal
//! - Listing providers
//! - Concurrent access safety
//! - Authentication dispatch
//! - Health check aggregation
//! - Edge cases (empty ID, empty registry)

use std::sync::Arc;

use async_trait::async_trait;

use super::IdentityRegistry;
use crate::provider::{
    AuthRequest, IdentityError, IdentityProvider, MisogiIdentity,
};

// ===========================================================================
// Test Doubles — Mock IdentityProvider Implementations
// ===========================================================================

/// A mock identity provider for testing registry operations.
///
/// Returns deterministic results based on constructor parameters.
/// Thread-safe: all fields are immutable after construction.
struct MockProvider {
    id: String,
    name: String,
    always_fail_auth: bool,
    always_fail_health: bool,
}

impl MockProvider {
    fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            always_fail_auth: false,
            always_fail_health: false,
        }
    }

    fn with_auth_failure(mut self) -> Self {
        self.always_fail_auth = true;
        self
    }

    fn with_health_failure(mut self) -> Self {
        self.always_fail_health = true;
        self
    }
}

#[async_trait]
impl IdentityProvider for MockProvider {
    fn provider_id(&self) -> &str {
        &self.id
    }

    fn provider_name(&self) -> &str {
        &self.name
    }

    async fn authenticate(
        &self,
        _input: AuthRequest,
    ) -> Result<MisogiIdentity, IdentityError> {
        if self.always_fail_auth {
            return Err(IdentityError::InvalidCredentials);
        }

        Ok(MisogiIdentity::new("mock-user", &self.id)
            .with_display_name("Mock User")
            .with_roles(vec!["staff".to_string()]))
    }

    async fn health_check(&self) -> Result<(), IdentityError> {
        if self.always_fail_health {
            return Err(IdentityError::ProviderUnavailable(
                "mock provider intentionally unhealthy".to_string(),
            ));
        }
        Ok(())
    }
}

// ===========================================================================
// Test: Registry Construction
// ===========================================================================

#[test]
fn test_registry_new_is_empty() {
    let registry = IdentityRegistry::new();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
    assert!(registry.list().is_empty());
}

#[test]
fn test_registry_default_is_empty() {
    let registry = IdentityRegistry::default();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
}

// ===========================================================================
// Test: Provider Registration
// ===========================================================================

#[test]
fn test_register_single_provider_succeeds() {
    let registry = IdentityRegistry::new();
    let provider = Arc::new(MockProvider::new("test-idp", "Test IdP"));

    let result = registry.register(provider.clone());
    assert!(result.is_ok(), "Registration should succeed");
    assert_eq!(registry.len(), 1);

    let retrieved = registry.get("test-idp");
    assert!(retrieved.is_ok(), "Registered provider should be retrievable");
    assert_eq!(retrieved.unwrap().provider_id(), "test-idp");
}

#[test]
fn test_register_duplicate_replaces_silently() {
    // Re-registering with same provider_id should replace (last-write-wins).
    let registry = IdentityRegistry::new();

    let _ = registry.register(Arc::new(MockProvider::new("my-idp", "Version 1")));
    let _ = registry.register(Arc::new(MockProvider::new("my-idp", "Version 2")));

    assert_eq!(registry.len(), 1);

    let info = &registry.list()[0];
    assert_eq!(info.provider_name, "Version 2");
}

#[test]
fn test_register_empty_id_returns_error() {
    let registry = IdentityRegistry::new();
    struct EmptyIdProvider;
    #[async_trait]
    impl IdentityProvider for EmptyIdProvider {
        fn provider_id(&self) -> &str { "" }
        fn provider_name(&self) -> &str { "Empty" }
        async fn authenticate(&self, _: AuthRequest) -> Result<MisogiIdentity, IdentityError> {
            Err(IdentityError::InternalError("n/a".to_string()))
        }
        async fn health_check(&self) -> Result<(), IdentityError> { Ok(()) }
    }

    let result = registry.register(Arc::new(EmptyIdProvider));
    assert!(
        matches!(result, Err(IdentityError::ConfigurationError(_))),
        "Empty provider_id should be rejected"
    );
    assert_eq!(registry.len(), 0);
}

// ===========================================================================
// Test: Provider Retrieval
// ===========================================================================

#[test]
fn test_get_existing_provider_returns_ok() {
    let registry = IdentityRegistry::new();
    let provider = Arc::new(MockProvider::new("ldap-01", "LDAP Corp"));
    registry.register(provider).unwrap();

    let result = registry.get("ldap-01");
    assert!(result.is_ok());
    assert_eq!(result.unwrap().provider_name(), "LDAP Corp");
}

#[test]
fn test_get_missing_provider_returns_error() {
    let registry = IdentityRegistry::new();
    registry.register(Arc::new(MockProvider::new("real-idp", "Real"))).unwrap();

    let result = registry.get("nonexistent-idp");
    assert!(
        matches!(result, Err(IdentityError::ConfigurationError(_))),
        "Missing provider should return error"
    );
}

#[test]
fn test_get_from_empty_registry_returns_error() {
    let registry = IdentityRegistry::new();
    assert!(registry.get("anything").is_err());
}

// ===========================================================================
// Test: Provider Removal
// ===========================================================================

#[test]
fn test_remove_existing_provider() {
    let registry = IdentityRegistry::new();
    registry.register(Arc::new(MockProvider::new("a", "A"))).unwrap();
    registry.register(Arc::new(MockProvider::new("b", "B"))).unwrap();
    assert_eq!(registry.len(), 2);

    let removed = registry.remove("a");
    assert!(removed);
    assert_eq!(registry.len(), 1);
    assert!(registry.get("a").is_err());
    assert!(registry.get("b").is_ok());
}

#[test]
fn test_remove_nonexistent_provider_returns_false() {
    let registry = IdentityRegistry::new();
    assert!(!registry.remove("ghost-idp"));
}

// ===========================================================================
// Test: Provider Listing
// ===========================================================================

#[test]
fn test_list_returns_all_registered_providers() {
    let registry = IdentityRegistry::new();
    registry.register(Arc::new(MockProvider::new("idp-1", "One"))).unwrap();
    registry.register(Arc::new(MockProvider::new("idp-2", "Two"))).unwrap();
    registry.register(Arc::new(MockProvider::new("idp-3", "Three"))).unwrap();

    let listed = registry.list();
    assert_eq!(listed.len(), 3);

    let ids: Vec<&str> = listed.iter().map(|p| p.provider_id.as_str()).collect();
    assert!(ids.contains(&"idp-1"));
    assert!(ids.contains(&"idp-2"));
    assert!(ids.contains(&"idp-3"));
}

#[test]
fn test_list_empty_registry() {
    assert!(IdentityRegistry::new().list().is_empty());
}

#[test]
fn test_provider_info_contains_correct_fields() {
    let registry = IdentityRegistry::new();
    registry
        .register(Arc::new(MockProvider::new(
            "special-idp",
            "Special LDAP v2",
        )))
        .unwrap();

    let info = &registry.list()[0];
    assert_eq!(info.provider_id, "special-idp");
    assert_eq!(info.provider_name, "Special LDAP v2");
}

// ===========================================================================
// Test: Len / IsEmpty
// ===========================================================================

#[test]
fn test_len_tracks_registration_and_removal() {
    let registry = IdentityRegistry::new();
    assert_eq!(registry.len(), 0);
    assert!(registry.is_empty());

    registry.register(Arc::new(MockProvider::new("x", "X"))).unwrap();
    assert_eq!(registry.len(), 1);
    assert!(!registry.is_empty());

    registry.register(Arc::new(MockProvider::new("y", "Y"))).unwrap();
    assert_eq!(registry.len(), 2);

    registry.remove("x");
    assert_eq!(registry.len(), 1);

    registry.remove("y");
    assert_eq!(registry.len(), 0);
    assert!(registry.is_empty());
}

// ===========================================================================
// Test: Authentication Dispatch
// ===========================================================================

#[tokio::test]
async fn test_authenticate_dispatches_to_correct_provider() {
    let registry = IdentityRegistry::new();
    registry
        .register(Arc::new(MockProvider::new("auth-ok", "Auth OK")))
        .unwrap();

    let request = AuthRequest::Credentials {
        username: "testuser".to_string(),
        password: "testpass".to_string(),
    };

    let result = registry.authenticate("auth-ok", &request).await;
    assert!(result.is_ok());

    let identity = result.unwrap();
    assert_eq!(identity.applicant_id, "mock-user");
    assert_eq!(identity.idp_source, "auth-ok");
}

#[tokio::test]
async fn test_authenticate_propagates_provider_error() {
    let registry = IdentityRegistry::new();
    let failing = Arc::new(MockProvider::new("fail-idp", "Failing").with_auth_failure());
    registry.register(failing).unwrap();

    let request = AuthRequest::Credentials {
        username: "anyone".to_string(),
        password: "anything".to_string(),
    };

    let result = registry.authenticate("fail-idp", &request).await;
    assert!(
        matches!(result, Err(IdentityError::InvalidCredentials)),
        "Should propagate InvalidCredentials from mock"
    );
}

#[tokio::test]
async fn test_authenticate_missing_provider_returns_error() {
    let registry = IdentityRegistry::new();
    let request = AuthRequest::ApiKey {
        key: "some-key".to_string(),
    };

    assert!(registry.authenticate("ghost", &request).await.is_err());
}

// ===========================================================================
// Test: Health Check Aggregation
// ===========================================================================

#[tokio::test]
async fn test_health_check_all_healthy() {
    let registry = IdentityRegistry::new();
    registry
        .register(Arc::new(MockProvider::new("healthy-a", "Healthy A")))
        .unwrap();
    registry
        .register(Arc::new(MockProvider::new("healthy-b", "Healthy B")))
        .unwrap();

    let results = registry.health_check_all().await;
    assert_eq!(results.len(), 2);

    for (_id, result) in &results {
        assert!(result.is_ok(), "All healthy providers should pass health check");
    }
}

#[tokio::test]
async fn test_health_check_all_mixed_results() {
    let registry = IdentityRegistry::new();
    registry.register(Arc::new(MockProvider::new("ok", "OK"))).unwrap();
    registry
        .register(Arc::new(
            MockProvider::new("unhealthy", "Unhealthy").with_health_failure(),
        ))
        .unwrap();
    registry
        .register(Arc::new(MockProvider::new("also-ok", "Also OK")))
        .unwrap();

    let results = registry.health_check_all().await;
    assert_eq!(results.len(), 3);

    let ok_result = &results.iter().find(|(id, _)| *id == "ok").unwrap().1;
    let unhealthy_result = &results
        .iter()
        .find(|(id, _)| *id == "unhealthy")
        .unwrap()
        .1;
    let also_ok_result = &results
        .iter()
        .find(|(id, _)| *id == "also-ok")
        .unwrap()
        .1;

    assert!(ok_result.is_ok(), "OK provider should be healthy");
    assert!(unhealthy_result.is_err(), "Unhealthy provider should report failure");
    assert!(also_ok_result.is_ok(), "Also OK provider should be healthy");
}

#[tokio::test]
async fn test_health_check_empty_registry() {
    assert!(IdentityRegistry::new().health_check_all().await.is_empty());
}

// ===========================================================================
// Test: Concurrent Access Safety
// ===========================================================================

#[tokio::test]
async fn test_concurrent_register_and_read() {
    use tokio::task::JoinSet;

    let registry = Arc::new(IdentityRegistry::new());
    let mut join_set = JoinSet::new();

    for i in 0..10u32 {
        let reg = Arc::clone(&registry);
        join_set.spawn(async move {
            let provider = Arc::new(MockProvider::new(
                format!("concurrent-{i}"),
                format!("Concurrent Provider {i}"),
            ));
            let _ = reg.register(provider);
        });
    }

    for _ in 0..20 {
        let reg = Arc::clone(&registry);
        join_set.spawn(async move {
            let _len = reg.len();
            let _list = reg.list();
        });
    }

    while let Some(result) = join_set.join_next().await {
        assert!(result.is_ok(), "Concurrent task should not panic");
    }

    assert_eq!(registry.len(), 10, "All 10 registrations should be present");
}

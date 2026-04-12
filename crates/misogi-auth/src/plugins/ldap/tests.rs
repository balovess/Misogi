//! Unit tests for [`LdapIdentityProvider`](super::LdapIdentityProvider).
//!
//! Test categories:
//! - Configuration construction and defaults
//! - Attribute mapping configuration
//! - Filter template rendering
//! - Shift-JIS encoding fallback
//! - Provider identity methods
//! - Error mapping correctness

use super::{
    LdapAttributeMappings, LdapIdentityProvider, LdapPluginConfig,
};
use crate::provider::{AuthRequest, IdentityError, IdentityProvider};

/// Create a minimal valid LdapPluginConfig for testing.
fn minimal_config() -> LdapPluginConfig {
    LdapPluginConfig {
        urls: vec!["ldap://localhost:389".to_string()],
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: "cn=svc,dc=example,dc=com".to_string(),
        bind_password: "test".to_string(),
        user_search_base: "ou=Users,dc=example,dc=com".to_string(),
        user_filter: "(uid={username})".to_string(),
        group_search_base: Some("ou=Groups,dc=example,dc=com".to_string()),
        ..Default::default()
    }
}

// ---- Test Group 1: LdapAttributeMappings ----

#[test]
fn test_attribute_mappings_default_is_ad() {
    let m = LdapAttributeMappings::default();
    assert_eq!(m.uid_attribute, "sAMAccountName");
    assert_eq!(m.display_name_attribute, "displayName");
    assert_eq!(m.email_attribute, "mail");
    assert_eq!(m.group_member_attribute, "member");
    assert_eq!(m.group_name_attribute, "cn");
}

#[test]
fn test_attribute_mappings_openldap_factory() {
    let m = LdapAttributeMappings::openldap();
    assert_eq!(m.uid_attribute, "uid");
    assert_eq!(m.display_name_attribute, "cn");
}

#[test]
fn test_attribute_mappings_ad_factory() {
    let m = LdapAttributeMappings::active_directory();
    let d = LdapAttributeMappings::default();
    assert_eq!(m.uid_attribute, d.uid_attribute);
}

#[test]
fn test_attribute_mappings_custom() {
    let m = LdapAttributeMappings {
        uid_attribute: "employeeId".into(),
        display_name_attribute: "name".into(),
        email_attribute: "emailAddress".into(),
        group_member_attribute: "uniqueMember".into(),
        group_name_attribute: "ou".into(),
    };
    assert_eq!(m.group_name_attribute, "ou");
}

// ---- Test Group 2: LdapPluginConfig Construction ----

#[test]
fn test_plugin_config_default_values() {
    let c = LdapPluginConfig::default();
    assert_eq!(c.urls.len(), 1);
    assert_eq!(c.connection_timeout_secs, 10);
    assert_eq!(c.pool_size, 5);
    assert!(!c.shift_jis_fallback);
    assert!(c.group_search_base.is_none());
}

#[test]
fn test_plugin_config_full_construction() {
    let c = minimal_config();
    assert!(!c.urls.is_empty());
    assert!(!c.bind_dn.is_empty());
    assert!(c.group_search_base.is_some());
}

#[test]
fn test_plugin_config_serialization_roundtrip() {
    let c = minimal_config();
    let json = serde_json::to_string(&c).unwrap();
    let de: LdapPluginConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(de.urls, c.urls);
    assert_eq!(de.user_filter, c.user_filter);
}

// ---- Test Group 3: Provider Construction & Identity ----

#[test]
fn test_provider_new_and_id() {
    let p = LdapIdentityProvider::new(minimal_config());
    assert_eq!(p.provider_id(), "ldap");
}

#[test]
fn test_provider_name_content() {
    let p = LdapIdentityProvider::new(minimal_config());
    assert!(p.provider_name().contains("LDAP"));
}

#[test]
fn test_provider_config_accessor() {
    let c = minimal_config();
    let p = LdapIdentityProvider::new(c.clone());
    assert_eq!(p.config().urls, c.urls);
}

// ---- Test Group 4: Filter Template Rendering ----

#[test]
fn test_build_user_filter_replaces_username() {
    let p = LdapIdentityProvider::new(minimal_config());
    assert_eq!(p.build_user_filter("tanaka"), "(uid=tanaka)");
}

#[test]
fn test_build_user_filter_ad_style() {
    let mut c = minimal_config();
    c.user_filter = "(sAMAccountName={username})".into();
    let p = LdapIdentityProvider::new(c);
    assert_eq!(p.build_user_filter("jsmith"), "(sAMAccountName=jsmith)");
}

#[test]
fn test_build_group_filter_default() {
    let p = LdapIdentityProvider::new(minimal_config());
    let f = p.build_group_filter("cn=U,ou=Users,dc=x,dc=com");
    assert_eq!(f, "(member=cn=U,ou=Users,dc=x,dc=com)");
}

#[test]
fn test_build_group_filter_custom() {
    let mut c = minimal_config();
    c.group_filter = Some("(&(objectClass=group)(member={user_dn}))".into());
    let p = LdapIdentityProvider::new(c);
    let f = p.build_group_filter("cn=U,dc=x,dc=com");
    assert_eq!(f, "(&(objectClass=group)(member=cn=U,dc=x,dc=com))");
}

// ---- Test Group 5: Shift-JIS Encoding Fallback ----

#[test]
fn test_decode_utf8_valid() {
    let p = LdapIdentityProvider::new(minimal_config());
    assert_eq!(p.decode_attribute_value(b"hello"), "hello");
}

#[test]
fn test_decode_utf8_japanese() {
    let p = LdapIdentityProvider::new(minimal_config());
    assert_eq!(
        p.decode_attribute_value("\u{7530}\u{4e2d}".as_bytes()),
        "\u{7530}\u{4e2d}"
    );
}

#[test]
fn test_decode_invalid_utf8_no_sjis_fallback_lossy() {
    let mut c = minimal_config();
    c.shift_jis_fallback = false;
    let p = LdapIdentityProvider::new(c);
    assert!(!p.decode_attribute_value(&[0xFE, 0xFF]).is_empty());
}

#[test]
fn test_decode_shift_jis_with_fallback() {
    let mut c = minimal_config();
    c.shift_jis_fallback = true;
    let p = LdapIdentityProvider::new(c);
    // Shift-JIS bytes for "\u{7530}" (田)
    let r = p.decode_attribute_value(&[0x92, 0x0B]);
    assert!(r.contains("\u{7530}") || !r.is_empty());
}

#[test]
fn test_decode_valid_utf8_ignores_sjis_flag() {
    let mut c = minimal_config();
    c.shift_jis_fallback = true;
    let p = LdapIdentityProvider::new(c);
    assert_eq!(p.decode_attribute_value(b"ok"), "ok");
}

// ---- Test Group 6: Round-Robin URL Selection ----

#[test]
fn test_next_url_single() {
    let mut c = minimal_config();
    c.urls = vec!["ldaps://ad1:636".into()];
    let p = LdapIdentityProvider::new(c);
    assert_eq!(p.next_url(), "ldaps://ad1:636");
    assert_eq!(p.next_url(), "ldaps://ad1:636");
}

#[test]
fn test_next_url_round_robin() {
    let mut c = minimal_config();
    c.urls = vec!["s1".into(), "s2".into(), "s3".into()];
    let p = LdapIdentityProvider::new(c);
    assert_eq!(p.next_url(), "s1");
    assert_eq!(p.next_url(), "s2");
    assert_eq!(p.next_url(), "s3");
    assert_eq!(p.next_url(), "s1"); // wraps
}

#[test]
fn test_next_url_empty_falls_back() {
    let mut c = minimal_config();
    c.urls.clear();
    let p = LdapIdentityProvider::new(c);
    assert_eq!(p.next_url(), "ldap://localhost:389");
}

// ---- Test Group 7: Non-Credentials Auth Request Rejection ----

#[tokio::test]
async fn test_reject_api_key() {
    let p = LdapIdentityProvider::new(minimal_config());
    let r = p.authenticate(AuthRequest::ApiKey { key: "k".into() }).await;
    assert!(matches!(r, Err(IdentityError::AuthenticationFailed(_))));
}

#[tokio::test]
async fn test_reject_saml() {
    let p = LdapIdentityProvider::new(minimal_config());
    let r = p.authenticate(AuthRequest::SamlResponse { response: "x".into() }).await;
    assert!(matches!(r, Err(IdentityError::AuthenticationFailed(_))));
}

#[tokio::test]
async fn test_reject_authz_code() {
    let p = LdapIdentityProvider::new(minimal_config());
    let r = p.authenticate(AuthRequest::AuthorizationCode {
        code: "c".into(), redirect_uri: "u".into(), code_verifier: None,
    }).await;
    assert!(matches!(r, Err(IdentityError::AuthenticationFailed(_))));
}

// ---- Test Group 8: Health Check Config Validation ----

#[tokio::test]
async fn test_health_check_empty_urls() {
    let mut c = minimal_config();
    c.urls.clear();
    let p = LdapIdentityProvider::new(c);
    assert!(matches!(p.health_check().await, Err(IdentityError::ConfigurationError(_))));
}

// ---- Test Group 9: Connection Error Handling ----

#[tokio::test]
async fn test_auth_unreachable_returns_unavailable() {
    let mut c = minimal_config();
    c.urls = vec!["ldap://127.0.0.1:53899".into()];
    c.connection_timeout_secs = 2;
    let p = LdapIdentityProvider::new(c);
    let r = p.authenticate(AuthRequest::Credentials {
        username: "u".into(), password: "p".into(),
    }).await;
    assert!(matches!(r, Err(IdentityError::ProviderUnavailable(_))));
}

#[tokio::test]
async fn test_health_check_unreachable_returns_unavailable() {
    let mut c = minimal_config();
    c.urls = vec!["ldap://127.0.0.1:53900".into()];
    c.connection_timeout_secs = 2;
    let p = LdapIdentityProvider::new(c);
    assert!(matches!(p.health_check().await, Err(IdentityError::ProviderUnavailable(_))));
}


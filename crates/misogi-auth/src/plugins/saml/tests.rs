//! Unit Tests for [`SamlIdentityProvider`] Plugin.
//!
//! Comprehensive test suite covering construction, configuration validation,
//! identity mapping, error mapping, health checks, and G-Cloud Japan compatibility.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;

use super::{
    build_stable_provider_id, map_saml_error, SamlAttributeMappings, SamlIdentityProvider,
    SamlPluginConfig, NameIdFormat,
};
use crate::provider::{AuthRequest, IdentityError};
use crate::saml_provider::{SamlAttributes as CoreSamlAttributes, SamlError};

// ---------------------------------------------------------------------------
// Helper: Test fixture factory
// ---------------------------------------------------------------------------

/// Create a valid minimal test configuration for [`SamlIdentityProvider`].
fn test_config() -> SamlPluginConfig {
    SamlPluginConfig {
        sp_entity_id: "https://sp.example.com/misogi".into(),
        idp_metadata_url: Some("https://idp.example.com/metadata".into()),
        idp_metadata_xml: None,
        idp_sso_url: "https://idp.example.com/sso".into(),
        idp_slo_url: Some("https://idp.example.com/slo".into()),
        certificate_path: None,
        certificate_pem: Some(
            "-----BEGIN CERTIFICATE-----\n\
             MIIBkTCB+wIJAKHBfAABAAAWMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\n\
             c3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM\n\
             BnRlc3RjYTBcMAATBgNVBAoMCVRlc3QgT3JnMFwwDQYJKoZIhvcNAQEBBQADswAw\n\
             SAJBAJ5L3SXhLqXVFKhH68Tf7lNYOZNKTrF3yFvZdNhQhRKNWHPq1hJuQ8XnUHmr\n\
             ZqK5cZjCAsIDnCAgMBAAEwDQYJKoZIhvcNAQELBQADQQBb+KMRfBGGL+7gHKqQVt\n\
             VhV2q\n-----END CERTIFICATE-----\n"
                .into(),
        ),
        private_key_path: None,
        private_key_pem: None,
        attribute_mappings: SamlAttributeMappings::default(),
        name_id_format: NameIdFormat::Transient,
        want_assertions_signed: true,
        want_responses_signed: true,
    }
}

// ===================================================================
// Test Group 1: Construction Validation
// ===================================================================

#[test]
fn test_new_rejects_empty_sp_entity_id() {
    let mut cfg = test_config();
    cfg.sp_entity_id.clear();
    assert!(matches!(
        SamlIdentityProvider::new(cfg),
        Err(IdentityError::ConfigurationError(_))
    ));
}

#[test]
fn test_new_rejects_empty_idp_sso_url() {
    let mut cfg = test_config();
    cfg.idp_sso_url.clear();
    assert!(matches!(
        SamlIdentityProvider::new(cfg),
        Err(IdentityError::ConfigurationError(_))
    ));
}

#[test]
fn test_new_accepts_valid_config() {
    let p = SamlIdentityProvider::new(test_config()).unwrap();
    assert!(p.provider_id().starts_with("saml-"));
    assert!(p.provider_name().contains("SAML"));
}

// ===================================================================
// Test Group 2: NameIdFormat Enum
// ===================================================================

#[test]
fn test_name_id_format_uris() {
    assert!(NameIdFormat::Email.uri().contains("emailAddress"));
    assert!(NameIdFormat::Persistent.uri().contains("persistent"));
    assert!(NameIdFormat::Transient.uri().contains("transient"));
    assert!(NameIdFormat::Unspecified.uri().contains("unspecified"));
}

#[test]
fn test_name_id_format_default_is_transient() {
    assert_eq!(NameIdFormat::default(), NameIdFormat::Transient);
}

// ===================================================================
// Test Group 3: SamlAttributeMappings Defaults
// ===================================================================

#[test]
fn test_attribute_mappings_defaults_use_oid_names() {
    let m = SamlAttributeMappings::default();
    assert_eq!(m.name_id_attribute, "name_id");
    assert_eq!(m.display_name_attribute, "urn:oid:2.5.4.42"); // givenName
    assert_eq!(m.email_attribute, "urn:oid:0.9.2342.19200300.100.1.3"); // mail
    assert!(m.department_attribute.is_none());
    assert!(m.organization_attribute.is_none());
}

// ===================================================================
// Test Group 4: Provider ID Generation
// ===================================================================

#[test]
fn test_provider_id_starts_with_saml_prefix() {
    let id = build_stable_provider_id("https://sp.example.com");
    assert!(id.starts_with("saml-"));
}

#[test]
fn test_provider_id_sanitizes_special_chars() {
    let id = build_stable_provider_id("https://sp.example.com:8443/path");
    // Colons, dots, slashes should become dashes/underscores
    assert!(!id.contains(':') && !id.contains('.') && !id.contains('/'));
}

// ===================================================================
// Test Group 5: G-Cloud Japan Configuration Factory
// ===================================================================

#[test]
fn test_gcloud_japan_config_uses_oid_attributes() {
    let cfg = SamlPluginConfig::gcloud_japan(
        "https://sp.gcloud.go.jp",
        "https://idp.gcloud.go.jp/sso",
        "CERT-PEM-DATA",
    );
    assert_eq!(cfg.sp_entity_id, "https://sp.gcloud.go.jp");
    assert_eq!(cfg.attribute_mappings.display_name_attribute, "urn:oid:2.5.4.42");
    assert_eq!(cfg.attribute_mappings.email_attribute, "urn:oid:0.9.2342.19200300.100.1.3");
    assert_eq!(
        cfg.attribute_mappings.department_attribute.as_deref(),
        Some("urn:oid:2.5.4.11")
    );
}

// ===================================================================
// Test Group 6: Identity Mapping (attribute → MisogiIdentity)
// ===================================================================

#[test]
fn test_map_identity_basic_fields() {
    let attrs = CoreSamlAttributes {
        name_id: "user001".into(),
        name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".into(),
        display_name: Some("Tanaka Taro".into()),
        email: Some("tanaka@example.com".into()),
        organization: Some("Ministry of Internal Affairs".into()),
        session_index: Some("_abc123".into()),
        extra: HashMap::new(),
    };
    let cfg = test_config();
    let identity = SamlIdentityProvider::map_to_identity(&attrs, &cfg);

    assert_eq!(identity.applicant_id, "user001");
    assert_eq!(identity.display_name.as_deref(), Some("Tanaka Taro"));
    assert_eq!(identity.idp_source, "saml");
    assert_eq!(identity.original_subject.as_deref(), Some("user001"));
    assert!(identity.extra.contains_key("saml_session_index"));
}

#[test]
fn test_map_identity_gcloud_oid_attributes() {
    let mut extra = HashMap::new();
    extra.insert("urn:oid:2.5.4.42".into(), vec!["Taro".into()]);
    extra.insert(
        "urn:oid:0.9.2342.19200300.100.1.3".into(),
        vec!["tanaka@gcloud.go.jp".into()],
    );
    extra.insert("urn:oid:2.5.4.11".into(), vec!["IT Department".into()]);

    let attrs = CoreSamlAttributes {
        name_id: "guser01".into(),
        name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into(),
        display_name: None,
        email: None,
        organization: None,
        session_index: None,
        extra,
    };
    let cfg = test_config();
    let identity = SamlIdentityProvider::map_to_identity(&attrs, &cfg);

    // Display name resolved from OID givenName attribute
    assert_eq!(identity.display_name.as_deref(), Some("Taro"));
    // Department mapped from OID ou attribute
    assert_eq!(
        identity.extra.get("saml_department").and_then(|v| v.as_str()),
        Some("IT Department")
    );
}

#[test]
fn test_map_identity_fallback_to_name_id_when_no_display_name() {
    let attrs = CoreSamlAttributes {
        name_id: "minimal-user".into(),
        name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".into(),
        display_name: None,
        email: None,
        organization: None,
        session_index: None,
        extra: HashMap::new(),
    };
    let cfg = test_config();
    let identity = SamlIdentityProvider::map_to_identity(&attrs, &cfg);
    assert_eq!(identity.applicant_id, "minimal-user");
    assert!(identity.display_name.is_none());
}

// ===================================================================
// Test Group 7: Error Mapping (SamlError → IdentityError)
// ===================================================================

#[test]
fn test_err_map_expired_assertion() {
    assert!(matches!(
        map_saml_error(SamlError::AssertionExpired),
        IdentityError::AuthenticationFailed(_)
    ));
}

#[test]
fn test_err_map_signature_failure() {
    assert!(matches!(
        map_saml_error(SamlError::SignatureValidationFailed("bad sig".into())),
        IdentityError::AuthenticationFailed(_)
    ));
}

#[test]
fn test_err_map_invalid_response() {
    assert!(matches!(
        map_saml_error(SamlError::InvalidResponse("malformed xml".into())),
        IdentityError::AuthenticationFailed(_)
    ));
}

#[test]
fn test_err_map_config_invalid() {
    assert!(matches!(
        map_saml_error(SamlError::ConfigInvalid("missing field".into())),
        IdentityError::ConfigurationError(_)
    ));
}

#[test]
fn test_err_map_replay_detected() {
    assert!(matches!(
        map_saml_error(SamlError::ReplayDetected),
        IdentityError::AuthenticationFailed(_)
    ));
}

// ===================================================================
// Test Group 8: Unsupported Auth Flow Rejection
// ===================================================================

#[tokio::test]
async fn test_reject_credentials_flow() {
    let p = SamlIdentityProvider::new(test_config()).unwrap();
    assert!(p
        .authenticate(AuthRequest::Credentials {
            username: "u".into(),
            password: "p".into(),
        })
        .await
        .is_err());
}

// ===================================================================
// Test Group 9: Health Check
// ===================================================================

#[tokio::test]
async fn test_health_check_passes_with_valid_config() {
    let p = SamlIdentityProvider::new(test_config()).unwrap();
    assert!(p.health_check().await.is_ok());
}

#[tokio::test]
async fn test_health_check_fails_without_certificate_when_required() {
    let mut cfg = test_config();
    cfg.certificate_pem = None;
    cfg.certificate_path = None;
    cfg.want_assertions_signed = true;
    let p = SamlIdentityProvider::new(cfg).unwrap();
    assert!(matches!(
        p.health_check().await,
        Err(IdentityError::ConfigurationError(_))
    ));
}

// ===================================================================
// Test Group 10: Base64 Decode Validation (raw SAML response handling)
// ===================================================================

#[test]
fn test_base64_decode_valid_input() {
    let xml = "<samlp:Response></samlp:Response>";
    let encoded = BASE64_STANDARD.encode(xml.as_bytes());
    let decoded = BASE64_STANDARD.decode(&encoded).unwrap();
    assert_eq!(String::from_utf8(decoded).unwrap(), xml);
}

#[test]
fn test_base64_decode_rejects_invalid_input() {
    let invalid = "!!!not-base64!!!";
    assert!(BASE64_STANDARD.decode(invalid).is_err());
}

// ===================================================================
// Test Group 11: SamlPluginConfig Default Values
// ===================================================================

#[test]
fn test_plugin_config_defaults() {
    let cfg = SamlPluginConfig::default();
    assert!(cfg.sp_entity_id.is_empty());
    assert!(cfg.idp_sso_url.is_empty());
    assert!(cfg.want_assertions_signed);
    assert!(cfg.want_responses_signed);
    assert_eq!(cfg.name_id_format, NameIdFormat::Transient);
}

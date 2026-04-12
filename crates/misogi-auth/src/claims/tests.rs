//! Unit tests for [`super::MisogiClaims`].
//!
//! Covers: construction, serialization roundtrip, field validation,
//! optional/flatten behavior, temporal checks, utility methods, derives.

use std::collections::HashMap;

use super::MisogiClaims;

// ---------------------------------------------------------------------------
// Test Constants
// ---------------------------------------------------------------------------

const TEST_ID: &str = "test-user-001";
const TEST_IAT: u64 = 1700000000;
const TEST_EXP: u64 = 1700003600;

fn full_claims() -> MisogiClaims {
    MisogiClaims::new(TEST_ID.to_string(), TEST_IAT, TEST_EXP)
        .with_display_name("Test User".to_string())
        .with_roles(vec!["admin".to_string(), "auditor".to_string()])
        .with_idp_source("oidc-keycloak".to_string())
        .with_original_subject("cn=test,dc=example,dc=com".to_string())
        .with_issuer_dn("CN=Keycloak,O=Example Inc,C=JP".to_string())
        .with_extra("tenant_id", serde_json::json!("tenant-123"))
        .with_extra("department", serde_json::json!("Engineering"))
}

// ===========================================================================
// 1. Construction
// ===========================================================================

#[test]
fn test_new_required_fields_only() {
    let c = MisogiClaims::new(TEST_ID.to_string(), TEST_IAT, TEST_EXP);
    assert_eq!(c.applicant_id, TEST_ID);
    assert_eq!(c.iat, TEST_IAT);
    assert_eq!(c.exp, TEST_EXP);
    assert!(c.display_name.is_none());
    assert!(c.roles.is_empty());
    assert_eq!(c.idp_source, "unknown");
    assert!(c.original_subject.is_none());
    assert!(c.issuer_dn.is_none());
    assert!(c.extra.is_empty());
}

#[test]
fn test_builder_chaining() {
    let c = MisogiClaims::new("x".to_string(), TEST_IAT, TEST_EXP)
        .with_display_name("N".to_string())
        .add_role("a").add_role("b")
        .with_idp_source("test".to_string());
    assert_eq!(c.display_name.as_deref(), Some("N"));
    assert_eq!(c.roles.len(), 2);
}

#[test]
fn test_full_construction() {
    let c = full_claims();
    assert_eq!(c.roles.len(), 2);
    assert_eq!(c.extra.len(), 2);
    assert!(c.original_subject.is_some());
    assert!(c.issuer_dn.is_some());
}

// ===========================================================================
// 2. Serialization Roundtrip
// ===========================================================================

#[test]
fn test_roundtrip_required_only() {
    let orig = MisogiClaims::new("rt".to_string(), TEST_IAT, TEST_EXP);
    let json = serde_json::to_string(&orig).unwrap();
    let restored: MisogiClaims = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.applicant_id, orig.applicant_id);
    assert_eq!(restored.idp_source, orig.idp_source);
}

#[test]
fn test_roundtrip_all_fields() {
    let orig = full_claims();
    let json = serde_json::to_string(&orig).unwrap();
    let r: MisogiClaims = serde_json::from_str(&json).unwrap();
    assert_eq!(r.display_name, orig.display_name);
    assert_eq!(r.roles, orig.roles);
    assert_eq!(r.original_subject, orig.original_subject);
    assert_eq!(r.extra.len(), orig.extra.len());
}

#[test]
fn test_serialization_structure() {
    let c = MisogiClaims::new("s".to_string(), TEST_IAT, TEST_EXP)
        .with_display_name("D".to_string())
        .with_extra("flag", serde_json::json!(true));
    let val = serde_json::to_value(&c).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("applicant_id"));
    assert!(obj.contains_key("flag")); // flattened extra
    assert_eq!(obj["display_name"], "D");
}

// ===========================================================================
// 3. Required Field Validation
// ===========================================================================

#[test]
fn test_required_fields_present_in_output() {
    let json = serde_json::to_string(
        &MisogiClaims::new("r".to_string(), TEST_IAT, TEST_EXP)
    ).unwrap();
    assert!(json.contains("\"applicant_id\""));
    assert!(json.contains("\"iat\""));
    assert!(json.contains("\"exp\""));
}

#[test]
fn test_missing_exp_fails_deserialize() {
    let bad = "{\"applicant_id\":\"x\",\"iat\":1000,\"idp_source\":\"l\"}";
    assert!(serde_json::from_str::<MisogiClaims>(bad).is_err());
}

#[test]
fn test_applicant_id_exact_preservation() {
    let id = "EMP-2024-0042-JP";
    let c = MisogiClaims::new(id.to_string(), TEST_IAT, TEST_EXP);
    let r: MisogiClaims =
        serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
    assert_eq!(r.applicant_id.len(), id.len());
}

// ===========================================================================
// 4. Optional Field Behavior
// ===========================================================================

#[test]
fn test_optional_skip_when_none() {
    let json = serde_json::to_string(
        &MisogiClaims::new("s".to_string(), TEST_IAT, TEST_EXP)
    ).unwrap();
    assert!(!json.contains("display_name"));
    assert!(!json.contains("original_subject"));
    assert!(json.contains("idp_source")); // String, not Option
}

#[test]
fn test_optional_present_when_some() {
    let c = MisogiClaims::new("s".to_string(), TEST_IAT, TEST_EXP)
        .with_display_name("N".to_string())
        .with_original_subject("sub".to_string())
        .with_issuer_dn("DN".to_string());
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("N") && json.contains("sub") && json.contains("DN"));
}

#[test]
fn test_roles_default_empty_vec() {
    let c = MisogiClaims::new("s".to_string(), TEST_IAT, TEST_EXP);
    assert!(c.roles.is_empty());
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"roles\":[]"));
}

// ===========================================================================
// 5. Extension Field (Flatten)
// ===========================================================================

#[test]
fn test_extra_flattens_to_top_level() {
    let c = MisogiClaims::new("f".to_string(), TEST_IAT, TEST_EXP)
        .with_extra("k1", serde_json::json!("v1"))
        .with_extra("k2", serde_json::json!(42));
    let val = serde_json::to_value(&c).unwrap();
    let obj = val.as_object().unwrap();
    assert_eq!(obj.get("k1"), Some(&serde_json::json!("v1")));
    assert_eq!(obj.get("k2"), Some(&serde_json::json!(42)));
}

#[test]
fn test_extra_roundtrip() {
    let mut ex = HashMap::new();
    ex.insert("scope".into(), serde_json::json!(["read", "write"]));
    let c = MisogiClaims { applicant_id: "e".into(), iat: TEST_IAT, exp: TEST_EXP,
        display_name: None, roles: vec![], idp_source: "t".into(),
        original_subject: None, issuer_dn: None, extra: ex.clone() };
    let r: MisogiClaims =
        serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
    assert_eq!(r.extra["scope"], serde_json::json!(["read", "write"]));
}

#[test]
fn test_extra_captures_arbitrary_keys() {
    let raw = "{\"applicant_id\":\"u\",\"iat\":1000,\"exp\":2000,\"idp_source\":\"x\",\"amr\":[\"pwd\"],\"nonce\":\"n\"}";
    let c: MisogiClaims = serde_json::from_str(raw).unwrap();
    assert_eq!(c.extra.len(), 2); // amr, nonce
    assert_eq!(c.extra["nonce"], serde_json::json!("n"));
}

#[test]
fn test_empty_extra_clean_output() {
    let c = MisogiClaims::new("c".to_string(), TEST_IAT, TEST_EXP);
    let val = serde_json::to_value(&c).unwrap();
    let obj = val.as_object().unwrap();
    for &k in &["applicant_id", "iat", "exp", "roles", "idp_source"] {
        assert!(obj.contains_key(k), "missing key {k}");
    }
}

// ===========================================================================
// 6. Temporal Validation
// ===========================================================================

#[test]
fn test_temporal_valid() {
    assert!(MisogiClaims::new("v".to_string(), TEST_IAT, TEST_EXP)
        .validate_temporal().is_ok());
}

#[test]
fn test_temporal_rejects_inverted() {
    let r = MisogiClaims::new("i".to_string(), TEST_EXP, TEST_IAT)
        .validate_temporal();
    assert!(r.is_err() && r.unwrap_err().contains("exp"));
}

#[test]
fn test_temporal_rejects_zero_lifetime() {
    assert!(MisogiClaims::new("z".to_string(), TEST_IAT, TEST_IAT)
        .validate_temporal().is_err());
}

// ===========================================================================
// 7. Utility Methods
// ===========================================================================

#[test]
fn test_has_role_case_sensitive() {
    let c = MisogiClaims::new("h".to_string(), TEST_IAT, TEST_EXP)
        .with_roles(vec!["Admin".into()]);
    assert!(c.has_role("Admin"));
    assert!(!c.has_role("admin"));
}

#[test]
fn test_has_role_empty() {
    assert!(!MisogiClaims::new("e".to_string(), TEST_IAT, TEST_EXP)
        .has_role("x"));
}

#[test]
fn test_lifetime_seconds() {
    assert_eq!(
        MisogiClaims::new("l".to_string(), 1000, 4600).lifetime_seconds(),
        3600
    );
}

#[test]
fn test_lifetime_invalid_returns_zero() {
    assert_eq!(
        MisogiClaims::new("i".to_string(), 2000, 1000).lifetime_seconds(),
        0
    );
}

// ===========================================================================
// 8. Clone / Debug Derives
// ===========================================================================

#[test]
fn test_clone_independence() {
    let orig = full_claims();
    let mut clone = orig.clone();
    clone.roles.push("new".into());
    assert_eq!(orig.roles.len(), 2); // unchanged
    assert_eq!(clone.roles.len(), 3); // modified
}

#[test]
fn test_debug_contains_key_info() {
    let c = MisogiClaims::new("d".to_string(), TEST_IAT, TEST_EXP)
        .with_display_name("Debug".to_string());
    let s = format!("{c:?}");
    assert!(s.contains("applicant_id") && s.contains("Debug"));
}

// ===========================================================================
// 9. Edge Cases
// ===========================================================================

#[test]
fn test_unicode_roundtrip() {
    let name = "\u{7530}\u{4E2D} \u{592A}\u{90CE}";
    let c = MisogiClaims::new("u".to_string(), TEST_IAT, TEST_EXP)
        .with_display_name(name.to_string());
    let r: MisogiClaims =
        serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
    assert_eq!(r.display_name.as_deref(), Some(name));
}

#[test]
fn test_large_roles_vector() {
    let roles: Vec<String> = (0..100).map(|i| format!("r-{i}")).collect();
    let c = MisogiClaims::new("m".to_string(), TEST_IAT, TEST_EXP)
        .with_roles(roles.clone());
    assert_eq!(c.roles.len(), 100);
    let r: MisogiClaims =
        serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
    assert_eq!(r.roles.len(), 100);
}

#[test]
fn test_nested_extra_data() {
    let nested = serde_json::json!({"meta": {"dept": "Eng"}, "perm": true});
    let c = MisogiClaims::new("n".to_string(), TEST_IAT, TEST_EXP)
        .with_extra("ext", nested.clone());
    let r: MisogiClaims =
        serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
    assert_eq!(r.extra["ext"], nested);
}

#[test]
fn test_idp_default_unknown() {
    assert_eq!(
        MisogiClaims::new("d".to_string(), TEST_IAT, TEST_EXP).idp_source,
        "unknown"
    );
}

#[test]
fn test_with_roles_replaces() {
    let c = MisogiClaims::new("r".to_string(), TEST_IAT, TEST_EXP)
        .add_role("old").with_roles(vec!["new-a".into(), "new-b".into()]);
    assert_eq!(c.roles.len(), 2);
    assert!(!c.has_role("old"));
}

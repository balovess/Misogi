//! Unit tests for [`super::AttributeResolver`].

use super::super::attribute::AbacValue;
use super::AttributeResolver;

// ===========================================================================
// Helper
// ===========================================================================

fn attrs(pairs: Vec<(&str, AbacValue)>) -> std::collections::HashMap<String, AbacValue> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

// ===========================================================================
// Subject Resolution Tests
// ===========================================================================

#[test]
fn test_resolve_subject_produces_core_keys() {
    let r = AttributeResolver::new(0);
    let a = r.resolve_subject_attributes("u1", "admin", "IT", attrs(vec![]));
    assert_eq!(a.get("user_id"), Some(&AbacValue::String("u1".to_string())));
    assert_eq!(a.get("role"), Some(&AbacValue::String("admin".to_string())));
    assert_eq!(
        a.get("department"),
        Some(&AbacValue::String("IT".to_string()))
    );
}

#[test]
fn test_resolve_subject_clearance_admin() {
    let r = AttributeResolver::new(0);
    let a = r.resolve_subject_attributes("u1", "administrator", "Sec", attrs(vec![]));
    assert_eq!(a.get("clearance_level"), Some(&AbacValue::Integer(5)));
}

#[test]
fn test_resolve_subject_clearance_operator() {
    let r = AttributeResolver::new(0);
    let a = r.resolve_subject_attributes("u2", "operator", "Ops", attrs(vec![]));
    assert_eq!(a.get("clearance_level"), Some(&AbacValue::Integer(2)));
}

#[test]
fn test_resolve_subject_group_membership() {
    let r = AttributeResolver::new(0);
    let a = r.resolve_subject_attributes("u3", "auditor", "Compliance", attrs(vec![]));
    match &a["group_membership"] {
        AbacValue::List(items) => assert_eq!(
            items[0],
            AbacValue::String("Compliance/auditor".to_string())
        ),
        _ => panic!("expected List"),
    }
}

#[test]
fn test_resolve_subject_extra_overrides() {
    let r = AttributeResolver::new(0);
    let mut extra = attrs(vec![]);
    extra.insert("role".to_string(), AbacValue::String("super".to_string()));
    let a = r.resolve_subject_attributes("u1", "admin", "IT", extra);
    assert_eq!(a.get("role"), Some(&AbacValue::String("super".to_string())));
}

// ===========================================================================
// Resource Resolution Tests
// ===========================================================================

#[test]
fn test_resolve_resource_all_keys_present() {
    let r = AttributeResolver::new(0);
    let a = r.resolve_resource_attributes(
        "confidential",
        "application/pdf",
        10485760,
        "dmz",
        true,
        attrs(vec![]),
    );
    assert_eq!(
        a.get("data_classification"),
        Some(&AbacValue::String("confidential".to_string()))
    );
    assert_eq!(
        a.get("file_type"),
        Some(&AbacValue::String("application/pdf".to_string()))
    );
    assert_eq!(
        a.get("file_size_bytes"),
        Some(&AbacValue::Integer(10485760))
    );
    assert_eq!(
        a.get("destination_zone"),
        Some(&AbacValue::String("dmz".to_string()))
    );
    assert_eq!(a.get("contains_pii"), Some(&AbacValue::Boolean(true)));
}

// ===========================================================================
// Environment Resolution Tests
// ===========================================================================

#[test]
fn test_resolve_environment_temporal_keys() {
    let r = AttributeResolver::new(0);
    let a = r.resolve_environment_attributes("10.0.0.1", "JP-13", true, true, attrs(vec![]));

    // time_of_day must be "HH:MM" format.
    match &a["time_of_day"] {
        AbacValue::String(s) => {
            assert_eq!(s.len(), 5);
            assert!(&s[2..3] == ":");
        }
        _ => panic!("expected String"),
    }

    // day_of_week in 1..=7.
    match &a["day_of_week"] {
        AbacValue::Integer(n) => assert!((1i64..=7i64).contains(n)),
        _ => panic!("expected Integer"),
    }

    // business_day is boolean.
    assert!(a.contains_key("business_day"));
}

#[test]
fn test_source_network_corporate_lan_10() {
    let r = AttributeResolver::new(0);
    let a = r.resolve_environment_attributes("10.100.50.23", "JP-13", true, true, attrs(vec![]));
    assert_eq!(
        a.get("source_network"),
        Some(&AbacValue::String("corporate-lan".to_string()))
    );
}

#[test]
fn test_source_network_unknown() {
    let r = AttributeResolver::new(0);
    let a = r.resolve_environment_attributes("203.0.113.42", "US-DC", false, false, attrs(vec![]));
    assert_eq!(
        a.get("source_network"),
        Some(&AbacValue::String("unknown".to_string()))
    );
}

// ===========================================================================
// Custom Attributes Tests
// ===========================================================================

#[test]
fn test_custom_passthrough() {
    let r = AttributeResolver::new(0);
    let mut input = attrs(vec![]);
    input.insert("score".to_string(), AbacValue::Float(0.95));
    let result = r.resolve_custom_attributes(input);
    assert_eq!(result.get("score"), Some(&AbacValue::Float(0.95)));
}

// ===========================================================================
// Cache Tests
// ===========================================================================

#[test]
fn test_cache_hit() {
    let r = AttributeResolver::new(60);
    r.cache_set("k", AbacValue::String("v".to_string()));
    assert_eq!(r.cache_get("k"), Some(AbacValue::String("v".to_string())));
}

#[test]
fn test_cache_miss() {
    let r = AttributeResolver::new(60);
    assert!(r.cache_get("nope").is_none());
}

#[test]
fn test_cache_expiry_zero_ttl() {
    let r = AttributeResolver::new(0); // instant expiry
    r.cache_set("x", AbacValue::Integer(42));
    assert!(r.cache_get("x").is_none());
}

#[test]
fn test_cache_valid_within_ttl() {
    let r = AttributeResolver::new(10);
    r.cache_set("y", AbacValue::Integer(99));
    assert_eq!(r.cache_get("y"), Some(AbacValue::Integer(99)));
}

#[test]
fn test_clear_cache() {
    let r = AttributeResolver::new(60);
    r.cache_set("a", AbacValue::String("1".to_string()));
    r.cache_set("b", AbacValue::String("2".to_string()));
    r.clear_cache();
    assert!(r.cache_get("a").is_none());
    assert!(r.cache_get("b").is_none());
}

#[test]
fn test_invalidate_key() {
    let r = AttributeResolver::new(60);
    r.cache_set("keep", AbacValue::String("ok".to_string()));
    r.cache_set("drop", AbacValue::String("go".to_string()));
    r.invalidate_key("drop");
    assert_eq!(
        r.cache_get("keep"),
        Some(AbacValue::String("ok".to_string()))
    );
    assert!(r.cache_get("drop").is_none());
}

#[test]
fn test_invalidate_nonexistent_noop() {
    let r = AttributeResolver::new(60);
    r.cache_set("exist", AbacValue::String("ok".to_string()));
    r.invalidate_key("ghost");
    assert!(r.cache_get("exist").is_some());
}

// ===========================================================================
// RFC 1918 Classification Tests
// ===========================================================================

#[test]
fn test_classify_10_prefix() {
    assert_eq!(
        AttributeResolver::new(0).classify_source_network("10.0.0.1"),
        "corporate-lan"
    );
}

#[test]
fn test_classify_192_168_prefix() {
    assert_eq!(
        AttributeResolver::new(0).classify_source_network("192.168.1.100"),
        "corporate-lan"
    );
}

#[test]
fn test_classify_172_16_range() {
    let r = AttributeResolver::new(0);
    assert_eq!(r.classify_source_network("172.16.0.1"), "corporate-lan");
    assert_eq!(r.classify_source_network("172.31.255.255"), "corporate-lan");
}

#[test]
fn test_classify_172_32_unknown() {
    assert_eq!(
        AttributeResolver::new(0).classify_source_network("172.32.0.1"),
        "unknown"
    );
}

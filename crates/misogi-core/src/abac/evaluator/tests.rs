//! Unit tests for [`super::ConditionEvaluator`] and [`super::EvalError`].

use super::{ConditionEvaluator, EvalError};
use super::super::attribute::{AbacAttribute, AbacValue};
use super::super::policy::{ConditionOperator, PolicyCondition};

// ===========================================================================
// Helpers
// ===========================================================================

fn cond(attr: AbacAttribute, op: ConditionOperator, val: AbacValue) -> PolicyCondition {
    PolicyCondition { attribute: attr, operator: op, value: val }
}

fn am(pairs: Vec<(&str, AbacValue)>) -> std::collections::HashMap<String, AbacValue> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

// ===========================================================================
// Eq Tests
// ===========================================================================

#[test]
fn test_eq_string_match() {
    let c = cond(AbacAttribute::Role(String::new()), ConditionOperator::Eq, AbacValue::String("admin".into()));
    assert!(ConditionEvaluator::evaluate_condition(&c, &am(vec![("Role", AbacValue::String("admin".into()))])).unwrap());
}

#[test]
fn test_eq_string_no_match() {
    let c = cond(AbacAttribute::Role(String::new()), ConditionOperator::Eq, AbacValue::String("admin".into()));
    assert!(!ConditionEvaluator::evaluate_condition(&c, &am(vec![("Role", AbacValue::String("guest".into()))])).unwrap());
}

#[test]
fn test_eq_integer() {
    let c = cond(AbacAttribute::ClearanceLevel(0), ConditionOperator::Eq, AbacValue::Integer(5));
    assert!(ConditionEvaluator::evaluate_condition(&c, &am(vec![("ClearanceLevel", AbacValue::Integer(5))])).unwrap());
}

#[test]
fn test_eq_boolean() {
    let c = cond(AbacAttribute::MfaVerified(false), ConditionOperator::Eq, AbacValue::Boolean(true));
    assert!(ConditionEvaluator::evaluate_condition(&c, &am(vec![("MfaVerified", AbacValue::Boolean(true))])).unwrap());
}

// ===========================================================================
// Neq Tests
// ===========================================================================

#[test]
fn test_neq_different() {
    let c = cond(AbacAttribute::Role(String::new()), ConditionOperator::Neq, AbacValue::String("admin".into()));
    assert!(ConditionEvaluator::evaluate_condition(&c, &am(vec![("Role", AbacValue::String("guest".into()))])).unwrap());
}

#[test]
fn test_neq_same_returns_false() {
    let c = cond(AbacAttribute::Role(String::new()), ConditionOperator::Neq, AbacValue::String("admin".into()));
    assert!(!ConditionEvaluator::evaluate_condition(&c, &am(vec![("Role", AbacValue::String("admin".into()))])).unwrap());
}

// ===========================================================================
// In / NotIn Tests
// ===========================================================================

#[test]
fn test_in_list_contains() {
    let c = cond(AbacAttribute::Role(String::new()), ConditionOperator::In,
        AbacValue::List(vec![AbacValue::String("admin".into()), AbacValue::String("operator".into())]));
    assert!(ConditionEvaluator::evaluate_condition(&c, &am(vec![("Role", AbacValue::String("operator".into()))])).unwrap());
}

#[test]
fn test_in_list_not_contains() {
    let c = cond(AbacAttribute::Role(String::new()), ConditionOperator::In,
        AbacValue::List(vec![AbacValue::String("admin".into()), AbacValue::String("operator".into())]));
    assert!(!ConditionEvaluator::evaluate_condition(&c, &am(vec![("Role", AbacValue::String("auditor".into()))])).unwrap());
}

#[test]
fn test_not_in_excluded() {
    let c = cond(AbacAttribute::Role(String::new()), ConditionOperator::NotIn,
        AbacValue::List(vec![AbacValue::String("guest".into())]));
    assert!(ConditionEvaluator::evaluate_condition(&c, &am(vec![("Role", AbacValue::String("admin".into()))])).unwrap());
}

// ===========================================================================
// Gt / Lt Tests
// ===========================================================================

#[test]
fn test_gt_integer_greater() {
    let c = cond(AbacAttribute::FileSizeBytes(0), ConditionOperator::Gt, AbacValue::Integer(1000));
    assert!(ConditionEvaluator::evaluate_condition(&c, &am(vec![("FileSizeBytes", AbacValue::Integer(5000))])).unwrap());
}

#[test]
fn test_gt_integer_not_greater() {
    let c = cond(AbacAttribute::FileSizeBytes(0), ConditionOperator::Gt, AbacValue::Integer(5000));
    assert!(!ConditionEvaluator::evaluate_condition(&c, &am(vec![("FileSizeBytes", AbacValue::Integer(1000))])).unwrap());
}

#[test]
fn test_lt_integer_less() {
    let c = cond(AbacAttribute::FileSizeBytes(0), ConditionOperator::Lt, AbacValue::Integer(10_000_000));
    assert!(ConditionEvaluator::evaluate_condition(&c, &am(vec![("FileSizeBytes", AbacValue::Integer(1024))])).unwrap());
}

#[test]
fn test_gt_type_mismatch_boolean() {
    let c = cond(AbacAttribute::MfaVerified(false), ConditionOperator::Gt, AbacValue::Integer(0));
    let r = ConditionEvaluator::evaluate_condition(&c, &am(vec![("MfaVerified", AbacValue::Boolean(true))]));
    assert!(matches!(r.unwrap_err(), EvalError::TypeMismatch { .. }));
}

// ===========================================================================
// Regex Tests
// ===========================================================================

#[test]
fn test_regex_match() {
    let c = cond(AbacAttribute::FileType(String::new()), ConditionOperator::Regex,
        AbacValue::String(r"^application/pdf$".into()));
    assert!(ConditionEvaluator::evaluate_condition(&c, &am(vec![("FileType", AbacValue::String("application/pdf".into()))])).unwrap());
}

#[test]
fn test_regex_no_match() {
    let c = cond(AbacAttribute::FileType(String::new()), ConditionOperator::Regex,
        AbacValue::String(r"^image/".into()));
    assert!(!ConditionEvaluator::evaluate_condition(&c, &am(vec![("FileType", AbacValue::String("application/pdf".into()))])).unwrap());
}

#[test]
fn test_regex_invalid_pattern_error() {
    let c = cond(AbacAttribute::FileType(String::new()), ConditionOperator::Regex,
        AbacValue::String(r"(unclosed".into()));
    let r = ConditionEvaluator::evaluate_condition(&c, &am(vec![("FileType", AbacValue::String("test".into()))]));
    assert!(matches!(r.unwrap_err(), EvalError::RegexError(_)));
}

#[test]
fn test_regex_type_mismatch_non_string_attr() {
    let c = cond(AbacAttribute::FileSizeBytes(0), ConditionOperator::Regex,
        AbacValue::String(r"\d+".into()));
    let r = ConditionEvaluator::evaluate_condition(&c, &am(vec![("FileSizeBytes", AbacValue::Integer(1234))]));
    assert!(matches!(r.unwrap_err(), EvalError::TypeMismatch { .. }));
}

// ===========================================================================
// IpInRange Tests
// ===========================================================================

#[test]
fn test_ip_in_range_cidr_match() {
    let c = cond(AbacAttribute::IpAddress(String::new()), ConditionOperator::IpInRange,
        AbacValue::String("10.0.0.0/8".into()));
    assert!(ConditionEvaluator::evaluate_condition(&c, &am(vec![("IpAddress", AbacValue::String("10.100.50.23".into()))])).unwrap());
}

#[test]
fn test_ip_in_range_cidr_no_match() {
    let c = cond(AbacAttribute::IpAddress(String::new()), ConditionOperator::IpInRange,
        AbacValue::String("192.168.0.0/16".into()));
    assert!(!ConditionEvaluator::evaluate_condition(&c, &am(vec![("IpAddress", AbacValue::String("10.0.0.1".into()))])).unwrap());
}

#[test]
fn test_ip_in_range_slash_24() {
    let c = cond(AbacAttribute::IpAddress(String::new()), ConditionOperator::IpInRange,
        AbacValue::String("192.168.1.0/24".into()));
    // Inside /24.
    assert!(ConditionEvaluator::evaluate_condition(&c, &am(vec![("IpAddress", AbacValue::String("192.168.1.100".into()))])).unwrap());
    // Outside /24.
    assert!(!ConditionEvaluator::evaluate_condition(&c, &am(vec![("IpAddress", AbacValue::String("192.168.2.1".into()))])).unwrap());
}

#[test]
fn test_ip_in_range_slash_32_exact() {
    let c = cond(AbacAttribute::IpAddress(String::new()), ConditionOperator::IpInRange,
        AbacValue::String("203.0.113.42/32".into()));
    assert!(ConditionEvaluator::evaluate_condition(&c, &am(vec![("IpAddress", AbacValue::String("203.0.113.42".into()))])).unwrap());
}

#[test]
fn test_ip_in_range_invalid_cidr_format() {
    let c = cond(AbacAttribute::IpAddress(String::new()), ConditionOperator::IpInRange,
        AbacValue::String("not-a-cidr".into()));
    // Invalid CIDR → fail-closed → false.
    assert!(!ConditionEvaluator::evaluate_condition(&c, &am(vec![("IpAddress", AbacValue::String("10.0.0.1".into()))])).unwrap());
}

// ===========================================================================
// Attribute Not Found Test
// ===========================================================================

#[test]
fn test_attribute_not_found() {
    let c = cond(AbacAttribute::UserId(String::new()), ConditionOperator::Eq, AbacValue::String("anyone".into()));
    let r = ConditionEvaluator::evaluate_condition(&c, &std::collections::HashMap::new());
    match r.unwrap_err() {
        EvalError::AttributeNotFound(k) => assert_eq!(k, "UserId"),
        other => panic!("expected AttributeNotFound, got: {other}"),
    }
}

// ===========================================================================
// Custom Attribute Key Test
// ===========================================================================

#[test]
fn test_custom_attribute_key_lookup() {
    let c = cond(
        AbacAttribute::Custom { key: "custom_score".into(), value: AbacValue::Float(0.5) },
        ConditionOperator::Gt,
        AbacValue::Float(0.9),
    );
    assert!(ConditionEvaluator::evaluate_condition(&c, &am(vec![("custom_score", AbacValue::Float(0.95))])).unwrap());
}

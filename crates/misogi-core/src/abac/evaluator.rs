//! Condition evaluation engine for ABAC policy rules.
//!
//! Provides [`ConditionEvaluator`], a stateless evaluator that applies comparison
//! operators to attribute values extracted from access request contexts.
//!
//! # Operator Coverage
//!
//! | Operator | Method | Type Requirements |
//! |----------|--------|-------------------|
//! | `Eq` / `Neq` | [`evaluate_eq`] / [`evaluate_neq`] | Any (same type) |
//! | `In` / `NotIn` | [`evaluate_in`] / [`evaluate_not_in`] | LHS any, RHS List |
//! | `Gt` / `Lt` | [`evaluate_gt`] / [`evaluate_lt`] | Integer or Float |
//! | `Regex` | [`evaluate_regex`] | LHS String, RHS String(pattern) |
//! | `IpInRange` | [`evaluate_ip_in_range`] | LHS IP string, RHS CIDR string |
//!
//! # Error Handling
//!
//! Follows **fail-closed** strategy: missing attributes → [`EvalError::AttributeNotFound`],
//! type mismatches → [`EvalError::TypeMismatch`], invalid regex → [`EvalError::RegexError`].

#[cfg(test)]
mod tests;

use std::collections::HashMap;

use thiserror::Error;

use super::attribute::{AbacAttribute, AbacValue};
use super::policy::{ConditionOperator, PolicyCondition};

// ===========================================================================
// EvalError
// ===========================================================================

/// Errors during condition evaluation. Distinct from "access denied" outcomes.
#[derive(Debug, Error)]
pub enum EvalError {
    #[error("attribute not found: {0}")]
    AttributeNotFound(String),
    #[error("type mismatch: expected {expected}, got {actual}")]
    TypeMismatch { expected: String, actual: String },
    #[error("regex error: {0}")]
    RegexError(#[from] regex::Error),
    #[error("unsupported operator for type")]
    UnsupportedOperator,
}

// ===========================================================================
// ConditionEvaluator
// ===========================================================================

/// Stateless evaluator for ABAC policy conditions.
///
/// Carries no state; all methods are `fn`. Exists as a namespace for organizing
/// evaluation logic and enabling independent unit testing per operator.
pub struct ConditionEvaluator;

impl ConditionEvaluator {
    /// Evaluates a single condition against an attribute map.
    ///
    /// Returns `Ok(true)` if satisfied, `Ok(false)` if not, `Err` on evaluation failure.
    pub fn evaluate_condition(
        condition: &PolicyCondition,
        attribute_map: &HashMap<String, AbacValue>,
    ) -> Result<bool, EvalError> {
        let attr_val = Self::extract_attribute_value(condition, attribute_map)?;
        match &condition.operator {
            ConditionOperator::Eq => Ok(Self::evaluate_eq(&attr_val, &condition.value)),
            ConditionOperator::Neq => Ok(Self::evaluate_neq(&attr_val, &condition.value)),
            ConditionOperator::In => Ok(Self::evaluate_in(&attr_val, &condition.value)),
            ConditionOperator::NotIn => Ok(Self::evaluate_not_in(&attr_val, &condition.value)),
            ConditionOperator::Gt => Self::evaluate_gt(&attr_val, &condition.value),
            ConditionOperator::Lt => Self::evaluate_lt(&attr_val, &condition.value),
            ConditionOperator::Regex => Self::evaluate_regex(&attr_val, &condition.value),
            ConditionOperator::IpInRange => {
                Ok(Self::evaluate_ip_in_range(&attr_val, &condition.value))
            }
        }
    }

    // -------------------------------------------------------------------
    // Equality Operators
    // -------------------------------------------------------------------

    fn evaluate_eq(attr_val: &AbacValue, expected: &AbacValue) -> bool {
        attr_val == expected
    }

    fn evaluate_neq(attr_val: &AbacValue, expected: &AbacValue) -> bool {
        attr_val != expected
    }

    // -------------------------------------------------------------------
    // Membership Operators
    // -------------------------------------------------------------------

    /// Checks membership in list. RHS must be `List`; non-list returns `false`.
    fn evaluate_in(attr_val: &AbacValue, expected: &AbacValue) -> bool {
        matches!(expected, AbacValue::List(items) if items.contains(attr_val))
    }

    fn evaluate_not_in(attr_val: &AbacValue, expected: &AbacValue) -> bool {
        !Self::evaluate_in(attr_val, expected)
    }

    // -------------------------------------------------------------------
    // Numeric Comparison Operators
    // -------------------------------------------------------------------

    /// Greater-than with cross-type promotion (Integer <-> Float).
    fn evaluate_gt(attr_val: &AbacValue, expected: &AbacValue) -> Result<bool, EvalError> {
        match Self::compare_numeric(attr_val, expected) {
            Some(ord) => Ok(ord.is_gt()),
            None => Err(EvalError::TypeMismatch {
                expected: "Integer or Float".to_string(),
                actual: attr_val.type_name().to_string(),
            }),
        }
    }

    fn evaluate_lt(attr_val: &AbacValue, expected: &AbacValue) -> Result<bool, EvalError> {
        match Self::compare_numeric(attr_val, expected) {
            Some(ord) => Ok(ord.is_lt()),
            None => Err(EvalError::TypeMismatch {
                expected: "Integer or Float".to_string(),
                actual: attr_val.type_name().to_string(),
            }),
        }
    }

    // -------------------------------------------------------------------
    // Pattern Matching Operator
    // -------------------------------------------------------------------

    /// Regex match. Both operands must be `String`. Invalid pattern returns error.
    fn evaluate_regex(attr_val: &AbacValue, pattern: &AbacValue) -> Result<bool, EvalError> {
        let actual = attr_val.as_str().ok_or_else(|| EvalError::TypeMismatch {
            expected: "String".to_string(),
            actual: attr_val.type_name().to_string(),
        })?;
        let pat = pattern.as_str().ok_or_else(|| EvalError::TypeMismatch {
            expected: "String".to_string(),
            actual: pattern.type_name().to_string(),
        })?;
        let re = regex::Regex::new(pat)?;
        Ok(re.is_match(actual))
    }

    // -------------------------------------------------------------------
    // IP Range Operator
    // -------------------------------------------------------------------

    /// IPv4 CIDR range membership. Parses CIDR notation (e.g., `"10.0.0.0/8"`).
    fn evaluate_ip_in_range(attr_val: &AbacValue, range: &AbacValue) -> bool {
        let ip = match attr_val.as_str() {
            Some(s) => s,
            None => return false,
        };
        let cidr = match range.as_str() {
            Some(s) => s,
            None => return false,
        };
        Self::ip_matches_cidr(ip, cidr)
    }

    // -------------------------------------------------------------------
    // Attribute Extraction
    // -------------------------------------------------------------------

    /// Extracts the value for the condition's attribute from the map.
    fn extract_attribute_value(
        condition: &PolicyCondition,
        attribute_map: &HashMap<String, AbacValue>,
    ) -> Result<AbacValue, EvalError> {
        let key = Self::attribute_key_for(&condition.attribute);
        attribute_map
            .get(&key)
            .cloned()
            .ok_or(EvalError::AttributeNotFound(key))
    }

    // -------------------------------------------------------------------
    // Private Helpers
    // -------------------------------------------------------------------

    fn attribute_key_for(attr: &AbacAttribute) -> String {
        match attr {
            AbacAttribute::UserId(_) => "UserId".into(),
            AbacAttribute::Role(_) => "Role".into(),
            AbacAttribute::Department(_) => "Department".into(),
            AbacAttribute::ClearanceLevel(_) => "ClearanceLevel".into(),
            AbacAttribute::GroupMembership(_) => "GroupMembership".into(),
            AbacAttribute::IpAddress(_) => "IpAddress".into(),
            AbacAttribute::GeographicRegion(_) => "GeographicRegion".into(),
            AbacAttribute::MfaVerified(_) => "MfaVerified".into(),
            AbacAttribute::DeviceCompliant(_) => "DeviceCompliant".into(),
            AbacAttribute::DataClassification(_) => "DataClassification".into(),
            AbacAttribute::FileType(_) => "FileType".into(),
            AbacAttribute::FileSizeBytes(_) => "FileSizeBytes".into(),
            AbacAttribute::DestinationZone(_) => "DestinationZone".into(),
            AbacAttribute::ContainsPii(_) => "ContainsPii".into(),
            AbacAttribute::TimeOfDay(_) => "TimeOfDay".into(),
            AbacAttribute::DayOfWeek(_) => "DayOfWeek".into(),
            AbacAttribute::BusinessDay(_) => "BusinessDay".into(),
            AbacAttribute::SourceNetwork(_) => "SourceNetwork".into(),
            AbacAttribute::Custom { key, .. } => key.clone(),
        }
    }

    fn compare_numeric(left: &AbacValue, right: &AbacValue) -> Option<std::cmp::Ordering> {
        match (left, right) {
            (AbacValue::Integer(l), AbacValue::Integer(r)) => Some(l.cmp(r)),
            (AbacValue::Float(l), AbacValue::Float(r)) => l.partial_cmp(r),
            (AbacValue::Integer(l), AbacValue::Float(r)) => (*l as f64).partial_cmp(r),
            (AbacValue::Float(l), AbacValue::Integer(r)) => l.partial_cmp(&(*r as f64)),
            _ => None,
        }
    }

    /// IPv4 CIDR matching via 32-bit integer masking.
    fn ip_matches_cidr(ip_str: &str, cidr: &str) -> bool {
        let Some((net_str, prefix_str)) = cidr.split_once('/') else {
            return false;
        };
        let Some(prefix) = prefix_str.parse::<u32>().ok().filter(|&p| p <= 32) else {
            return false;
        };
        let Some(ip) = Self::parse_ipv4(ip_str) else {
            return false;
        };
        let Some(net) = Self::parse_ipv4(net_str) else {
            return false;
        };
        let mask = if prefix == 0 {
            0u32
        } else {
            u32::MAX << (32 - prefix)
        };
        (ip & mask) == (net & mask)
    }

    fn parse_ipv4(addr: &str) -> Option<u32> {
        let parts: Vec<&str> = addr.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let mut result = 0u32;
        for (i, part) in parts.iter().enumerate() {
            let octet: u8 = part.parse().ok()?;
            result |= (octet as u32) << (24 - i * 8);
        }
        Some(result)
    }
}

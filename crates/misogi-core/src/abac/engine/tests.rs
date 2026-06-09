//! Unit tests for [`super::AbacEngine`].

use super::super::attribute::{AbacAttribute, AbacValue};
use super::super::policy::{
    AbacPolicyRule, ApprovalTemplate, ApproverPool, ConditionOperator, Obligation, PolicyCondition,
    PolicyEffect, PolicyTarget,
};
use super::AbacEngine;

// ===========================================================================
// Helpers
// ===========================================================================

fn am(pairs: Vec<(&str, AbacValue)>) -> std::collections::HashMap<String, AbacValue> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

fn permit_rule(id: &str, prio: i32, key: &str, val: AbacValue) -> AbacPolicyRule {
    rule(id, prio, PolicyEffect::Permit, key, val, None)
}

fn deny_rule(id: &str, prio: i32, key: &str, val: AbacValue) -> AbacPolicyRule {
    rule(id, prio, PolicyEffect::Deny, key, val, None)
}

fn rule(
    id: &str,
    prio: i32,
    effect: PolicyEffect,
    key: &str,
    val: AbacValue,
    obl: Option<Obligation>,
) -> AbacPolicyRule {
    let attr = match key {
        "role" => AbacAttribute::Role(String::new()),
        "data_classification" => AbacAttribute::DataClassification(String::new()),
        "clearance_level" => AbacAttribute::ClearanceLevel(0),
        "file_size_bytes" => AbacAttribute::FileSizeBytes(0),
        "mfa_verified" | "MfaVerified" => AbacAttribute::MfaVerified(false),
        "business_day" | "BusinessDay" => AbacAttribute::BusinessDay(false),
        "source_network" | "SourceNetwork" => AbacAttribute::SourceNetwork(String::new()),
        "destination_zone" | "DestinationZone" => AbacAttribute::DestinationZone(String::new()),
        _ => AbacAttribute::Custom {
            key: key.into(),
            value: AbacValue::Boolean(false),
        },
    };
    AbacPolicyRule {
        rule_id: id.into(),
        effect,
        conditions: vec![PolicyCondition {
            attribute: attr,
            operator: ConditionOperator::Eq,
            value: val,
        }],
        target: PolicyTarget {
            action: String::new(),
            resource_type: None,
        },
        obligation: obl,
        priority: prio,
        enabled: true,
    }
}

// ===========================================================================
// Basic Evaluation Tests
// ===========================================================================

#[tokio::test]
async fn test_single_permit_allows() {
    let e = AbacEngine::new(
        vec![permit_rule(
            "allow-admin",
            10,
            "role",
            AbacValue::String("admin".into()),
        )],
        PolicyEffect::Deny,
        0,
    );
    let d = e
        .evaluate(&am(vec![("Role", AbacValue::String("admin".into()))]))
        .await;
    assert!(d.is_permitted());
    assert_eq!(d.matched_rule_id, Some("allow-admin".into()));
}

#[tokio::test]
async fn test_single_deny_denies() {
    let e = AbacEngine::new(
        vec![deny_rule(
            "block-guest",
            10,
            "role",
            AbacValue::String("guest".into()),
        )],
        PolicyEffect::Deny,
        0,
    );
    let d = e
        .evaluate(&am(vec![("Role", AbacValue::String("guest".into()))]))
        .await;
    assert!(d.is_denied());
    assert_eq!(d.matched_rule_id, Some("block-guest".into()));
}

#[tokio::test]
async fn test_highest_priority_wins() {
    let e = AbacEngine::new(
        vec![
            permit_rule("low-p", 1, "role", AbacValue::String("admin".into())),
            deny_rule("high-d", 100, "role", AbacValue::String("admin".into())),
        ],
        PolicyEffect::Deny,
        0,
    );
    let d = e
        .evaluate(&am(vec![("Role", AbacValue::String("admin".into()))]))
        .await;
    assert!(d.is_denied());
    assert_eq!(d.matched_rule_id, Some("high-d".into()));
}

#[tokio::test]
async fn test_deny_short_circuits() {
    let e = AbacEngine::new(
        vec![
            deny_rule("first-d", 50, "role", AbacValue::String("guest".into())),
            permit_rule("second-p", 40, "role", AbacValue::String("guest".into())),
        ],
        PolicyEffect::Deny,
        0,
    );
    let d = e
        .evaluate(&am(vec![("Role", AbacValue::String("guest".into()))]))
        .await;
    assert!(d.is_denied());
    assert_eq!(d.evaluated_rules, 1); // Only 1 rule evaluated before short-circuit.
}

#[tokio::test]
async fn test_and_logic_all_must_match() {
    let mut r = permit_rule("multi", 10, "role", AbacValue::String("admin".into()));
    r.conditions.push(PolicyCondition {
        attribute: AbacAttribute::MfaVerified(false),
        operator: ConditionOperator::Eq,
        value: AbacValue::Boolean(true),
    });
    let e = AbacEngine::new(vec![r], PolicyEffect::Deny, 0);

    // Role matches but MFA missing → no match → default deny.
    assert!(
        e.evaluate(&am(vec![("Role", AbacValue::String("admin".into()))]))
            .await
            .is_denied()
    );
    // Both match → permit.
    assert!(
        e.evaluate(&am(vec![
            ("Role", AbacValue::String("admin".into())),
            ("MfaVerified", AbacValue::Boolean(true))
        ]))
        .await
        .is_permitted()
    );
}

// ===========================================================================
// Default Effect Tests
// ===========================================================================

#[tokio::test]
async fn test_no_match_default_deny() {
    let e = AbacEngine::new(
        vec![permit_rule(
            "a",
            10,
            "role",
            AbacValue::String("admin".into()),
        )],
        PolicyEffect::Deny,
        0,
    );
    let d = e
        .evaluate(&am(vec![("Role", AbacValue::String("auditor".into()))]))
        .await;
    assert!(d.is_denied());
    assert_eq!(d.matched_rule_id, None);
}

#[tokio::test]
async fn test_empty_rules_default_permit() {
    let d = AbacEngine::new(vec![], PolicyEffect::Permit, 0)
        .evaluate(&am(vec![]))
        .await;
    assert!(d.is_permitted());
}

#[tokio::test]
async fn test_empty_rules_default_deny() {
    let d = AbacEngine::new(vec![], PolicyEffect::Deny, 0)
        .evaluate(&am(vec![]))
        .await;
    assert!(d.is_denied());
}

// ===========================================================================
// Obligation Tests
// ===========================================================================

#[tokio::test]
async fn test_permit_with_obligation() {
    let mut r = permit_rule(
        "conf",
        10,
        "data_classification",
        AbacValue::String("confidential".into()),
    );
    r.obligation = Some(Obligation::RequireJustification);
    let d = AbacEngine::new(vec![r], PolicyEffect::Deny, 0)
        .evaluate(&am(vec![(
            "DataClassification",
            AbacValue::String("confidential".into()),
        )]))
        .await;
    assert!(d.is_permitted());
    assert!(matches!(
        d.obligation,
        Some(Obligation::RequireJustification)
    ));
}

// ===========================================================================
// Cache Tests
// ===========================================================================

#[tokio::test]
async fn test_cache_hit_returns_same_decision() {
    let e = AbacEngine::new(
        vec![permit_rule(
            "cached",
            10,
            "role",
            AbacValue::String("admin".into()),
        )],
        PolicyEffect::Deny,
        60,
    );
    let attrs = am(vec![("Role", AbacValue::String("admin".into()))]);
    let d1 = e.evaluate(&attrs).await;
    assert!(!d1.cache_hit);
    let d2 = e.evaluate(&attrs).await;
    assert!(d2.cache_hit);
    assert_eq!(d1.effect, d2.effect);
}

#[tokio::test]
async fn test_invalidate_cache_forces_re_eval() {
    let e = AbacEngine::new(
        vec![permit_rule(
            "c",
            10,
            "role",
            AbacValue::String("admin".into()),
        )],
        PolicyEffect::Deny,
        60,
    );
    let a = am(vec![("Role", AbacValue::String("admin".into()))]);
    let _ = e.evaluate(&a).await;
    assert!(e.evaluate(&a).await.cache_hit);
    e.invalidate_cache();
    assert!(!e.evaluate(&a).await.cache_hit);
}

// ===========================================================================
// Disabled Rules Tests
// ===========================================================================

#[tokio::test]
async fn test_disabled_rules_skipped() {
    let mut dr = deny_rule("disabled", 100, "role", AbacValue::String("admin".into()));
    dr.enabled = false;
    let pr = permit_rule("enabled", 10, "role", AbacValue::String("admin".into()));
    let d = AbacEngine::new(vec![dr, pr], PolicyEffect::Deny, 0)
        .evaluate(&am(vec![("Role", AbacValue::String("admin".into()))]))
        .await;
    assert!(d.is_permitted());
    assert_eq!(d.matched_rule_id, Some("enabled".into()));
}

// ===========================================================================
// Rule Ordering Tests
// ===========================================================================

#[tokio::test]
async fn test_rules_sorted_by_priority_desc() {
    let e = AbacEngine::new(
        vec![
            permit_rule("p1", 1, "role", AbacValue::String("any".into())),
            deny_rule("p100", 100, "role", AbacValue::String("any".into())),
            permit_rule("p50", 50, "role", AbacValue::String("any".into())),
        ],
        PolicyEffect::Deny,
        0,
    );
    let d = e
        .evaluate(&am(vec![("Role", AbacValue::String("any".into()))]))
        .await;
    assert!(d.is_denied()); // Priority 100 deny wins.
    assert_eq!(d.matched_rule_id, Some("p100".into()));
}

// ===========================================================================
// Complex Scenario Tests
// ===========================================================================

#[tokio::test]
async fn test_confidential_dual_approve_scenario() {
    let mut conf_permit = permit_rule(
        "permit-conf",
        80,
        "data_classification",
        AbacValue::String("confidential".into()),
    );
    conf_permit.obligation = Some(Obligation::RequireApproval(ApprovalTemplate {
        template_id: "dual-approve".into(),
        required_approvers: 2,
        approver_pool: ApproverPool::Role {
            roles: vec!["security_officer".into()],
        },
        timeout_hours: 24,
        escalation_on_timeout: true,
    }));
    let guest_deny = deny_rule(
        "block-guests",
        200,
        "role",
        AbacValue::String("guest".into()),
    );
    let e = AbacEngine::new(vec![conf_permit, guest_deny], PolicyEffect::Deny, 0);

    // Guest + confidential → blocked by high-priority deny.
    assert!(
        e.evaluate(&am(vec![
            ("Role", AbacValue::String("guest".into())),
            (
                "DataClassification",
                AbacValue::String("confidential".into())
            )
        ]))
        .await
        .is_denied()
    );

    // Admin + confidential → permitted with obligation.
    let da = e
        .evaluate(&am(vec![
            ("Role", AbacValue::String("admin".into())),
            (
                "DataClassification",
                AbacValue::String("confidential".into()),
            ),
        ]))
        .await;
    assert!(da.is_permitted());
    assert!(da.obligation.is_some());
}

#[tokio::test]
async fn test_cross_zone_transfer_block() {
    let mut cz_deny = deny_rule(
        "cross-zone",
        90,
        "data_classification",
        AbacValue::String("confidential".into()),
    );
    cz_deny.conditions.push(PolicyCondition {
        attribute: AbacAttribute::DestinationZone(String::new()),
        operator: ConditionOperator::Eq,
        value: AbacValue::String("external".into()),
    });
    let e = AbacEngine::new(vec![cz_deny], PolicyEffect::Permit, 0);

    // Confidential → external: denied.
    assert!(
        e.evaluate(&am(vec![
            (
                "DataClassification",
                AbacValue::String("confidential".into())
            ),
            ("DestinationZone", AbacValue::String("external".into()))
        ]))
        .await
        .is_denied()
    );
    // Confidential → internal: permitted (no blocking rule).
    assert!(
        e.evaluate(&am(vec![
            (
                "DataClassification",
                AbacValue::String("confidential".into())
            ),
            ("DestinationZone", AbacValue::String("internal".into()))
        ]))
        .await
        .is_permitted()
    );
}

#[tokio::test]
async fn test_after_hours_block() {
    let mut ah_deny = deny_rule(
        "after-hours",
        50,
        "after_hours_flag",
        AbacValue::Boolean(true),
    );
    ah_deny.conditions[0].attribute = AbacAttribute::Custom {
        key: "after_hours_flag".into(),
        value: AbacValue::Boolean(true),
    };
    let e = AbacEngine::new(vec![ah_deny], PolicyEffect::Permit, 0);

    assert!(
        e.evaluate(&am(vec![("after_hours_flag", AbacValue::Boolean(true))]))
            .await
            .is_denied()
    );
    assert!(
        e.evaluate(&am(vec![("after_hours_flag", AbacValue::Boolean(false))]))
            .await
            .is_permitted()
    );
}

#[tokio::test]
async fn test_business_hours_auto_permit() {
    let mut bp = permit_rule(
        "biz-hours",
        30,
        "source_network",
        AbacValue::String("corporate-lan".into()),
    );
    bp.conditions.push(PolicyCondition {
        attribute: AbacAttribute::BusinessDay(false),
        operator: ConditionOperator::Eq,
        value: AbacValue::Boolean(true),
    });
    let e = AbacEngine::new(vec![bp], PolicyEffect::Deny, 0);

    // Corporate LAN + business day → permit.
    assert!(
        e.evaluate(&am(vec![
            ("SourceNetwork", AbacValue::String("corporate-lan".into())),
            ("BusinessDay", AbacValue::Boolean(true))
        ]))
        .await
        .is_permitted()
    );
    // Weekend → default deny.
    assert!(
        e.evaluate(&am(vec![
            ("SourceNetwork", AbacValue::String("corporate-lan".into())),
            ("BusinessDay", AbacValue::Boolean(false))
        ]))
        .await
        .is_denied()
    );
}

// ===========================================================================
// Rule Management Tests
// ===========================================================================

#[test]
fn test_add_rule() {
    let mut e = AbacEngine::new(vec![], PolicyEffect::Deny, 0);
    e.add_rule(permit_rule("r", 10, "x", AbacValue::String("y".into())));
    assert_eq!(e.rules.len(), 1);
}

#[test]
fn test_remove_rule_existing() {
    let mut e = AbacEngine::new(
        vec![permit_rule("keep", 10, "x", AbacValue::String("y".into()))],
        PolicyEffect::Deny,
        0,
    );
    assert!(e.remove_rule("keep"));
    assert_eq!(e.rules.len(), 0);
}

#[test]
fn test_remove_rule_nonexistent() {
    let mut e = AbacEngine::new(vec![], PolicyEffect::Deny, 0);
    assert!(!e.remove_rule("ghost"));
}

#[test]
fn test_reload_rules_replaces_all() {
    let mut e = AbacEngine::new(
        vec![permit_rule("old", 10, "x", AbacValue::String("y".into()))],
        PolicyEffect::Deny,
        0,
    );
    e.reload_rules(vec![deny_rule(
        "new",
        20,
        "z",
        AbacValue::String("w".into()),
    )]);
    assert_eq!(e.rules.len(), 1);
    assert_eq!(e.rules[0].rule_id, "new");
}

// ===========================================================================
// Hash Determinism Test
// ===========================================================================

#[test]
fn test_hash_order_independent() {
    use std::collections::HashMap;
    let mut m1 = HashMap::new();
    m1.insert("a".into(), AbacValue::Integer(1));
    m1.insert("z".into(), AbacValue::Integer(2));
    let mut m2 = HashMap::new();
    m2.insert("z".into(), AbacValue::Integer(2));
    m2.insert("a".into(), AbacValue::Integer(1));
    assert_eq!(
        AbacEngine::hash_attributes(&m1),
        AbacEngine::hash_attributes(&m2)
    );
}

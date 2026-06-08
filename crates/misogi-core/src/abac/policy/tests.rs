#[cfg(test)]
mod tests {
    use crate::abac::policy::{
        AbacPolicyRule, ApprovalTemplate, ApproverPool, ConditionOperator,
        Obligation, PolicyCondition, PolicyEffect, PolicyTarget,
    };
    use crate::abac::attribute::{AbacAttribute, AbacValue};
    use std::collections::HashMap;

    // ===================================================================
    // PolicyCondition Evaluation — Eq Operator
    // ===================================================================

    #[test]
    fn condition_eq_string_matches() {
        let cond = PolicyCondition {
            attribute: AbacAttribute::Role("admin".to_string()),
            operator: ConditionOperator::Eq,
            value: AbacValue::String("admin".to_string()),
        };
        let mut map = HashMap::new();
        map.insert("Role".to_string(), AbacValue::String("admin".to_string()));
        assert!(cond.evaluate(&map));
    }

    #[test]
    fn condition_eq_string_mismatches() {
        let cond = PolicyCondition {
            attribute: AbacAttribute::Role("admin".to_string()),
            operator: ConditionOperator::Eq,
            value: AbacValue::String("admin".to_string()),
        };
        let mut map = HashMap::new();
        map.insert("Role".to_string(), AbacValue::String("guest".to_string()));
        assert!(!cond.evaluate(&map));
    }

    #[test]
    fn condition_eq_missing_key_returns_false() {
        let cond = PolicyCondition {
            attribute: AbacAttribute::Role("admin".to_string()),
            operator: ConditionOperator::Eq,
            value: AbacValue::String("admin".to_string()),
        };
        let map = HashMap::new();
        assert!(!cond.evaluate(&map));
    }

    // ===================================================================
    // Neq Operator
    // ===================================================================

    #[test]
    fn condition_neq_different_values_returns_true() {
        let cond = PolicyCondition {
            attribute: AbacAttribute::Role(String::new()),
            operator: ConditionOperator::Neq,
            value: AbacValue::String("banned_role".to_string()),
        };
        let mut map = HashMap::new();
        map.insert("Role".to_string(), AbacValue::String("normal_user".to_string()));
        assert!(cond.evaluate(&map));
    }

    #[test]
    fn condition_neq_same_value_returns_false() {
        let cond = PolicyCondition {
            attribute: AbacAttribute::Role(String::new()),
            operator: ConditionOperator::Neq,
            value: AbacValue::String("target".to_string()),
        };
        let mut map = HashMap::new();
        map.insert("Role".to_string(), AbacValue::String("target".to_string()));
        assert!(!cond.evaluate(&map));
    }

    // ===================================================================
    // In / NotIn Operators
    // ===================================================================

    #[test]
    fn condition_in_list_contains_value() {
        let cond = PolicyCondition {
            attribute: AbacAttribute::Role(String::new()),
            operator: ConditionOperator::In,
            value: AbacValue::List(vec![
                AbacValue::String("admin".to_string()),
                AbacValue::String("operator".to_string()),
            ]),
        };
        let mut map = HashMap::new();
        map.insert("Role".to_string(), AbacValue::String("operator".to_string()));
        assert!(cond.evaluate(&map));
    }

    #[test]
    fn condition_in_list_not_contains_value() {
        let cond = PolicyCondition {
            attribute: AbacAttribute::Role(String::new()),
            operator: ConditionOperator::In,
            value: AbacValue::List(vec![
                AbacValue::String("admin".to_string()),
            ]),
        };
        let mut map = HashMap::new();
        map.insert("Role".to_string(), AbacValue::String("guest".to_string()));
        assert!(!cond.evaluate(&map));
    }

    #[test]
    fn condition_not_in_excludes_denied_value() {
        let cond = PolicyCondition {
            attribute: AbacAttribute::Role(String::new()),
            operator: ConditionOperator::NotIn,
            value: AbacValue::List(vec![
                AbacValue::String("terminated".to_string()),
            ]),
        };
        let mut map = HashMap::new();
        map.insert("Role".to_string(), AbacValue::String("active".to_string()));
        assert!(cond.evaluate(&map));
    }

    // ===================================================================
    // Gt / Lt Operators
    // ===================================================================

    #[test]
    fn condition_gt_integer_greater() {
        let cond = PolicyCondition {
            attribute: AbacAttribute::FileSizeBytes(0),
            operator: ConditionOperator::Gt,
            value: AbacValue::Integer(1000),
        };
        let mut map = HashMap::new();
        map.insert("FileSizeBytes".to_string(), AbacValue::Integer(5000));
        assert!(cond.evaluate(&map));
    }

    #[test]
    fn condition_lt_integer_smaller() {
        let cond = PolicyCondition {
            attribute: AbacAttribute::FileSizeBytes(0),
            operator: ConditionOperator::Lt,
            value: AbacValue::Integer(100_000),
        };
        let mut map = HashMap::new();
        map.insert("FileSizeBytes".to_string(), AbacValue::Integer(5000));
        assert!(cond.evaluate(&map));
    }

    #[test]
    fn condition_gt_not_satisfied_when_equal() {
        let cond = PolicyCondition {
            attribute: AbacAttribute::FileSizeBytes(0),
            operator: ConditionOperator::Gt,
            value: AbacValue::Integer(100),
        };
        let mut map = HashMap::new();
        map.insert("FileSizeBytes".to_string(), AbacValue::Integer(100));
        assert!(!cond.evaluate(&map)); // 100 is not > 100
    }

    // ===================================================================
    // Regex Operator
    // ===================================================================

    #[test]
    fn condition_regex_pattern_matches() {
        let cond = PolicyCondition {
            attribute: AbacAttribute::UserId(String::new()),
            operator: ConditionOperator::Regex,
            value: AbacValue::String(r"^emp-\d{4}$".to_string()),
        };
        let mut map = HashMap::new();
        map.insert("UserId".to_string(), AbacValue::String("emp-1234".to_string()));
        assert!(cond.evaluate(&map));
    }

    #[test]
    fn condition_regex_no_match() {
        let cond = PolicyCondition {
            attribute: AbacAttribute::UserId(String::new()),
            operator: ConditionOperator::Regex,
            value: AbacValue::String(r"^emp-".to_string()),
        };
        let mut map = HashMap::new();
        map.insert("UserId".to_string(), AbacValue::String("admin-user".to_string()));
        assert!(!cond.evaluate(&map));
    }

    // ===================================================================
    // AbacPolicyRule — AND Logic (matches_conditions)
    // ===================================================================

    #[test]
    fn rule_all_conditions_match_returns_true() {
        let rule = AbacPolicyRule {
            rule_id: "test-rule-1".to_string(),
            effect: PolicyEffect::Permit,
            conditions: vec![
                PolicyCondition {
                    attribute: AbacAttribute::Role(String::new()),
                    operator: ConditionOperator::Eq,
                    value: AbacValue::String("admin".to_string()),
                },
                PolicyCondition {
                    attribute: AbacAttribute::MfaVerified(true),
                    operator: ConditionOperator::Eq,
                    value: AbacValue::Boolean(true),
                },
            ],
            target: PolicyTarget {
                action: "file_transfer".to_string(),
                resource_type: None,
            },
            obligation: None,
            priority: 100,
            enabled: true,
        };

        let mut attr_map = HashMap::new();
        attr_map.insert("Role".to_string(), AbacValue::String("admin".to_string()));
        attr_map.insert("MfaVerified".to_string(), AbacValue::Boolean(true));

        assert!(rule.matches_conditions(&attr_map));
    }

    #[test]
    fn rule_one_condition_fails_returns_false() {
        let rule = AbacPolicyRule {
            rule_id: "test-rule-2".to_string(),
            effect: PolicyEffect::Permit,
            conditions: vec![
                PolicyCondition {
                    attribute: AbacAttribute::Role(String::new()),
                    operator: ConditionOperator::Eq,
                    value: AbacValue::String("admin".to_string()),
                },
                PolicyCondition {
                    attribute: AbacAttribute::MfaVerified(false), // expects false
                    operator: ConditionOperator::Eq,
                    value: AbacValue::Boolean(false),
                },
            ],
            target: PolicyTarget {
                action: "file_transfer".to_string(),
                resource_type: None,
            },
            obligation: None,
            priority: 50,
            enabled: true,
        };

        let mut attr_map = HashMap::new();
        attr_map.insert("Role".to_string(), AbacValue::String("admin".to_string()));
        attr_map.insert("MfaVerified".to_string(), AbacValue::Boolean(true));

        // MfaVerified is true but rule requires false -> AND fails
        assert!(!rule.matches_conditions(&attr_map));
    }

    #[test]
    fn rule_empty_conditions_always_matches() {
        let rule = AbacPolicyRule {
            rule_id: "catch-all".to_string(),
            effect: PolicyEffect::Deny,
            conditions: vec![],
            target: PolicyTarget {
                action: "*".to_string(),
                resource_type: None,
            },
            obligation: None,
            priority: 0,
            enabled: true,
        };
        let empty_map = HashMap::new();
        assert!(rule.matches_conditions(&empty_map));
    }

    // ===================================================================
    // Obligation Variants
    // ===================================================================

    #[test]
    fn obligation_none_is_default_like() {
        let obl = Obligation::None;
        match &obl {
            Obligation::None => {} // Expected
            _ => panic!("Expected None variant"),
        }
    }

    #[test]
    fn obligation_require_approval_holds_template() {
        let template = ApprovalTemplate {
            template_id: "two-person-check".to_string(),
            required_approvers: 2,
            approver_pool: ApproverPool::Role {
                roles: vec!["manager".to_string()],
            },
            timeout_hours: 24,
            escalation_on_timeout: true,
        };
        let obl = Obligation::RequireApproval(template);
        match obl {
            Obligation::RequireApproval(t) => {
                assert_eq!(t.required_approvers, 2);
                assert_eq!(t.timeout_hours, 24);
            }
            _ => panic!("Expected RequireApproval variant"),
        }
    }

    #[test]
    fn obligation_notify_admins_carries_list() {
        let admins = vec!["admin-001".to_string(), "security-officer".to_string()];
        let obl = Obligation::NotifyAdmins(admins.clone());
        match obl {
            Obligation::NotifyAdmins(list) => {
                assert_eq!(list.len(), 2);
            }
            _ => panic!("Expected NotifyAdmins variant"),
        }
    }

    // ===================================================================
    // ApprovalTemplate Creation
    // ===================================================================

    #[test]
    fn approval_template_custom_list_pool() {
        let template = ApprovalTemplate {
            template_id: "sec-officer-review".to_string(),
            required_approvers: 1,
            approver_pool: ApproverPool::CustomList {
                user_ids: vec!["sec-001".to_string()],
            },
            timeout_hours: 48,
            escalation_on_timeout: false,
        };
        assert_eq!(template.template_id, "sec-officer-review");
        assert_eq!(template.required_approvers, 1);
    }

    // ===================================================================
    // PolicyEffect Default
    // ===================================================================

    #[test]
    fn policy_effect_default_is_deny() {
        assert_eq!(PolicyEffect::default(), PolicyEffect::Deny);
    }
}

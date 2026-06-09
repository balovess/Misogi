#[cfg(test)]
mod test_cases {
    use crate::abac::config::AbacConfig;
    use crate::abac::policy::{
        AbacPolicyRule, ApprovalTemplate, ApproverPool, PolicyEffect, PolicyTarget,
    };

    // ===================================================================
    // Default Configuration Values
    // ===================================================================

    #[test]
    fn default_config_is_disabled() {
        let cfg = AbacConfig::default();
        assert!(!cfg.enabled);
    }

    #[test]
    fn default_config_effect_is_deny() {
        let cfg = AbacConfig::default();
        assert_eq!(cfg.default_effect, "deny");
    }

    #[test]
    fn default_config_cache_ttl_is_300() {
        let cfg = AbacConfig::default();
        assert_eq!(cfg.decision_cache_ttl_secs, 300);
    }

    #[test]
    fn default_config_audit_log_all_decisions_is_true() {
        let cfg = AbacConfig::default();
        assert!(cfg.audit_log_all_decisions);
    }

    // ===================================================================
    // Validation — Valid Config
    // ===================================================================

    #[test]
    fn valid_minimal_config_passes_validation() {
        let cfg = AbacConfig::default();
        assert!(cfg.is_valid());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn valid_config_with_rules_and_templates_passes() {
        let cfg = AbacConfig {
            enabled: true,
            default_effect: "deny".to_string(),
            decision_cache_ttl_secs: 600,
            audit_log_all_decisions: true,
            rules: vec![AbacPolicyRule {
                rule_id: "rule-1".to_string(),
                effect: PolicyEffect::Deny,
                conditions: vec![],
                target: PolicyTarget {
                    action: "*".to_string(),
                    resource_type: None,
                },
                obligation: None,
                priority: 0,
                enabled: true,
            }],
            approval_templates: vec![ApprovalTemplate {
                template_id: "tpl-1".to_string(),
                required_approvers: 1,
                approver_pool: ApproverPool::DepartmentHead,
                timeout_hours: 24,
                escalation_on_timeout: false,
            }],
        };
        assert!(cfg.is_valid());
    }

    // ===================================================================
    // Validation — Error Cases
    // ===================================================================

    #[test]
    fn invalid_default_effect_fails_validation() {
        let cfg = AbacConfig {
            default_effect: "maybe".to_string(), // Invalid value
            ..Default::default()
        };
        let result = cfg.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.path == "default_effect"));
    }

    #[test]
    fn duplicate_rule_id_fails_validation() {
        let mut cfg = AbacConfig::default();
        let make_rule = |id: &str| AbacPolicyRule {
            rule_id: id.to_string(),
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
        cfg.rules = vec![
            make_rule("same-id"),
            make_rule("different-id"),
            make_rule("same-id"), // Duplicate!
        ];
        let result = cfg.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.path.contains("rule_id")));
    }

    #[test]
    fn duplicate_template_id_fails_validation() {
        let mut cfg = AbacConfig::default();
        let tpl = || ApprovalTemplate {
            template_id: "dup-tpl".to_string(),
            required_approvers: 1,
            approver_pool: ApproverPool::DepartmentHead,
            timeout_hours: 24,
            escalation_on_timeout: false,
        };
        cfg.approval_templates = vec![tpl(), tpl()];
        let result = cfg.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.path.contains("template_id")));
    }

    #[test]
    fn zero_required_approvers_fails_validation() {
        let cfg = AbacConfig {
            approval_templates: vec![ApprovalTemplate {
                template_id: "bad-tpl".to_string(),
                required_approvers: 0, // Invalid!
                approver_pool: ApproverPool::DepartmentHead,
                timeout_hours: 24,
                escalation_on_timeout: false,
            }],
            ..Default::default()
        };
        let result = cfg.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.path.contains("required_approvers")));
    }

    #[test]
    fn cache_ttl_exceeding_24h_fails_validation() {
        let cfg = AbacConfig {
            decision_cache_ttl_secs: 100_000, // > 86400
            ..Default::default()
        };
        let result = cfg.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.path == "decision_cache_ttl_secs"));
    }

    // ===================================================================
    // Rule Priority Ordering
    // ===================================================================

    #[test]
    fn rules_can_be_sorted_by_priority_descending() {
        let rules = vec![
            AbacPolicyRule {
                rule_id: "low".to_string(),
                priority: 10,
                ..make_dummy_rule()
            },
            AbacPolicyRule {
                rule_id: "high".to_string(),
                priority: 100,
                ..make_dummy_rule()
            },
            AbacPolicyRule {
                rule_id: "mid".to_string(),
                priority: 50,
                ..make_dummy_rule()
            },
        ];

        let mut sorted = rules.clone();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.priority));

        assert_eq!(sorted[0].rule_id, "high"); // Highest first
        assert_eq!(sorted[1].rule_id, "mid");
        assert_eq!(sorted[2].rule_id, "low"); // Lowest last
    }

    /// Helper to create a minimal dummy `AbacPolicyRule` for test cases that
    /// only need to vary specific fields (like `priority`).
    fn make_dummy_rule() -> AbacPolicyRule {
        AbacPolicyRule {
            rule_id: String::new(),
            effect: PolicyEffect::Deny,
            conditions: vec![],
            target: PolicyTarget {
                action: String::new(),
                resource_type: None,
            },
            obligation: None,
            priority: 0,
            enabled: true,
        }
    }
}

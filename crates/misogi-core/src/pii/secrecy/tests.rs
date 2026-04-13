// =============================================================================
// Secrecy Module Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // SecrecyLevelDef Tests
    // =========================================================================

    #[test]
    fn test_level_def_mandatory_controls() {
        let level = SecrecyLevelDef {
            id: "critical".to_string(),
            display_name: "Critical".to_string(),
            rank: 4,
            color: "#DC2626".to_string(),
            required_controls: vec![
                ControlRequirement {
                    id: "enc".to_string(),
                    name: "Encryption".to_string(),
                    required: true,
                    spec: "AES-256+".to_string(),
                },
                ControlRequirement {
                    id: "label".to_string(),
                    name: "Label".to_string(),
                    required: false,
                    spec: String::new(),
                },
            ],
            retention_years: 7,
        };

        assert!(level.has_mandatory_controls());
        assert_eq!(level.mandatory_controls().len(), 1);
    }

    #[test]
    fn test_level_def_no_mandatory() {
        let level = SecrecyLevelDef {
            id: "public".to_string(),
            display_name: "Public".to_string(),
            rank: 0,
            color: "#3B82F6".to_string(),
            required_controls: vec![],
            retention_years: 1,
        };
        assert!(!level.has_mandatory_controls());
    }

    // =========================================================================
    // FallbackPolicy Tests
    // =========================================================================

    #[test]
    fn test_fallback_defaults() {
        let policy = FallbackPolicy::default();
        assert_eq!(policy.unknown_default, "medium");
        assert_eq!(policy.conflict_resolution, "highest");
        assert!((policy.min_confidence - 0.3).abs() < f64::EPSILON);
    }

    // =========================================================================
    // SecrecyClassifier Tests
    // =========================================================================

    #[test]
    fn test_classifier_with_generic_tier() {
        let classifier = SecrecyClassifier::with_generic_tier().unwrap();
        let levels = classifier.level_ids();
        assert!(!levels.is_empty());
        assert!(levels.contains(&"critical".to_string()));
        assert!(levels.contains(&"high".to_string()));
        assert!(levels.contains(&"medium".to_string()));
        assert!(levels.contains(&"low".to_string()));
        assert!(levels.contains(&"public".to_string()));
    }

    #[test]
    fn test_classify_national_id_as_critical() {
        let classifier = SecrecyClassifier::with_generic_tier().unwrap();
        let result = classifier.classify(&["national_id"]).unwrap();

        assert_eq!(result.level_id, "critical");
        assert_eq!(result.level_rank, 4);
        assert!(!result.required_controls.is_empty());
    }

    #[test]
    fn test_classify_credit_card_as_critical() {
        let classifier = SecrecyClassifier::with_generic_tier().unwrap();
        let result = classifier.classify(&["credit_card"]).unwrap();

        assert_eq!(result.level_id, "critical");
        assert!(result.reason.to_lowercase().contains("payment"));
    }

    #[test]
    fn test_classify_email_only_as_medium() {
        let classifier = SecrecyClassifier::with_generic_tier().unwrap();
        let result = classifier.classify(&["email"]).unwrap();

        assert_eq!(result.level_id, "medium");
        assert!(result.reason.to_lowercase().contains("contact"));
    }

    #[test]
    fn test_classify_empty_as_public() {
        let classifier = SecrecyClassifier::with_generic_tier().unwrap();
        let result = classifier.classify(&[]).unwrap();

        assert_eq!(result.level_id, "public");
        assert_eq!(result.level_rank, 0);
    }

    #[test]
    fn test_classify_full_identity_set_as_critical() {
        let classifier = SecrecyClassifier::with_generic_tier().unwrap();
        let result = classifier
            .classify(&["full_name", "address", "phone"])
            .unwrap();

        assert_eq!(result.level_id, "critical");
        assert!(result.reason.to_lowercase().contains("complete"));
    }

    #[test]
    fn test_classify_unknown_uses_fallback() {
        let classifier = SecrecyClassifier::with_generic_tier().unwrap();
        let result = classifier
            .classify(&["unknown_custom_type_xyz"])
            .unwrap();

        assert_eq!(result.level_id, "medium");
        assert!(result.reason.to_lowercase().contains("fallback"));
    }

    #[test]
    fn test_get_level_definition() {
        let classifier = SecrecyClassifier::with_generic_tier().unwrap();
        let critical = classifier.get_level("critical");

        assert!(critical.is_some());
        let c = critical.unwrap();
        assert_eq!(c.rank, 4);
        assert_eq!(c.color, "#DC2626");
    }

    // =========================================================================
    // SecrecySchemeBuilder Tests
    // =========================================================================

    #[test]
    fn test_builder_basic() {
        let classifier = SecrecySchemeBuilder::new()
            .set_scheme("custom-2-tier")
            .add_level("secret", "Secret", 2, "#FF0000")
            .add_level("open", "Open", 1, "#00FF00")
            .add_rule(
                "rule_secret",
                Condition::RequireAnyOf {
                    pii_types: vec!["national_id".to_string()],
                },
                "secret",
                "Contains sensitive ID",
            )
            .fallback_default("open")
            .build()
            .unwrap();

        let levels = classifier.level_ids();
        assert!(levels.contains(&"secret".to_string()));
        assert!(levels.contains(&"open".to_string()));

        let result = classifier.classify(&["national_id"]).unwrap();
        assert_eq!(result.level_id, "secret");
    }

    #[test]
    fn test_builder_three_tier() {
        let classifier = SecrecySchemeBuilder::new()
            .set_scheme("org-3tier")
            .add_level("confidential", "Confidential", 3, "#DC2626")
            .add_level("internal", "Internal", 2, "#F59E0B")
            .add_level("public", "Public", 1, "#10B981")
            .fallback_default("internal")
            .build()
            .unwrap();

        let result = classifier.classify(&[]).unwrap();
        assert_eq!(result.level_id, "internal");
    }

    // =========================================================================
    // Condition Evaluation Tests
    // =========================================================================

    #[test]
    fn test_condition_require_all_of() {
        let set: HashSet<&str> =
            vec!["national_id", "email"].into_iter().collect();
        let cond = Condition::RequireAllOf {
            pii_types: vec!["national_id".to_string(), "email".to_string()],
        };
        assert!(SecrecyClassifier::evaluate_condition(&cond, &set));
    }

    #[test]
    fn test_condition_require_all_of_missing_one() {
        let set: HashSet<&str> = vec!["national_id"].into_iter().collect();
        let cond = Condition::RequireAllOf {
            pii_types: vec![
                "national_id".to_string(),
                "email".to_string(),
                "phone".to_string(),
            ],
        };
        assert!(!SecrecyClassifier::evaluate_condition(&cond, &set));
    }

    #[test]
    fn test_condition_require_any_of() {
        let set: HashSet<&str> = vec!["email"].into_iter().collect();
        let cond = Condition::RequireAnyOf {
            pii_types: vec![
                "email".to_string(),
                "phone".to_string(),
            ],
        };
        assert!(SecrecyClassifier::evaluate_condition(&cond, &set));
    }

    #[test]
    fn test_condition_exclude_all_of() {
        let set: HashSet<&str> = vec!["email"].into_iter().collect();
        let cond = Condition::ExcludeAllOf {
            pii_types: vec!["national_id".to_string()],
        };
        assert!(SecrecyClassifier::evaluate_condition(&cond, &set));
    }
}

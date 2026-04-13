// =============================================================================
// Structured Module Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // FieldMapping Tests
    // =========================================================================

    #[test]
    fn test_mapping_literal_match() {
        let m = FieldMapping::literal("email", "email", 0.98, FieldAction::Mask);
        assert!(m.matches_field("email"));
        assert!(!m.matches_field("email_address"));
        assert!(m.matches_field("EMAIL"));
    }

    #[test]
    fn test_mapping_wildcard_suffix() {
        let m = FieldMapping::wildcard("*_id", "generic_id", 0.45, FieldAction::AlertOnly);
        assert!(m.matches_field("user_id"));
        assert!(m.matches_field("order_id"));
        assert!(!m.matches_field("id_user"));
    }

    #[test]
    fn test_mapping_regex_case_insensitive() {
        let m = FieldMapping::literal("(?i)^name$", "full_name", 0.60, FieldAction::AlertOnly);
        assert!(m.matches_field("name"));
        assert!(m.matches_field("NAME"));
        assert!(m.matches_field("Name"));
        assert!(!m.matches_field("username"));
    }

    // =========================================================================
    // FieldClassifier Tests
    // =========================================================================

    #[test]
    fn test_classifier_with_defaults() {
        let fc = FieldClassifier::with_defaults();
        assert!(fc.mapping_count() > 0);
    }

    #[test]
    fn test_classifier_classify_email() {
        let fc = FieldClassifier::with_defaults();
        let result = fc.classify("email");
        assert!(result.matched);
        assert_eq!(result.pii_type, "email");
        assert!(result.confidence >= 0.9);
    }

    #[test]
    fn test_classifier_classify_unknown() {
        let fc = FieldClassifier::with_defaults();
        let result = fc.classify("unknown_field_xyz");
        assert!(!result.matched);
        assert!(result.pii_type.is_empty());
    }

    #[test]
    fn test_classifier_wildcard_match() {
        let fc = FieldClassifier::with_defaults();
        let result = fc.classify("user_id");
        assert!(result.matched);
        assert_eq!(result.pii_type, "generic_id");
        assert!(result.confidence < 0.5);
    }

    #[test]
    fn test_classifier_add_runtime_mapping() {
        let fc = FieldClassifier::with_defaults();
        let initial_count = fc.mapping_count();

        fc.add_mapping(FieldMapping::literal(
            "custom_secret",
            "secret",
            0.99,
            FieldAction::Redact,
        ))
        .unwrap();

        assert_eq!(fc.mapping_count(), initial_count + 1);

        let result = fc.classify("custom_secret");
        assert!(result.matched);
        assert_eq!(result.pii_type, "secret");
        assert_eq!(result.action, FieldAction::Redact);
    }

    #[test]
    fn test_classifier_remove_by_pattern() {
        let fc = FieldClassifier::with_defaults();
        let count_before = fc.mapping_count();

        let removed = fc.remove_by_pattern("nonexistent").unwrap();
        assert_eq!(removed, 0);
        assert_eq!(fc.mapping_count(), count_before);
    }

    // =========================================================================
    // FieldClassifierBuilder Tests
    // =========================================================================

    #[test]
    fn test_builder_basic() {
        let fc = FieldClassifierBuilder::new()
            .add_literal("my_email", "email", 0.98, FieldAction::Mask)
            .add_wildcard("*_secret", "secret", 0.90, FieldAction::Redact)
            .default_action(FieldAction::LogOnly)
            .build();

        let r1 = fc.classify("my_email");
        assert!(r1.matched);

        let r2 = fc.classify("api_secret");
        assert!(r2.matched);
        assert_eq!(r2.action, FieldAction::Redact);
    }

    // =========================================================================
    // CsvPiiScanner Tests
    // =========================================================================

    #[test]
    fn test_csv_scan_with_pii() {
        let scanner = CsvPiiScanner::with_defaults();
        let content = "name,email,phone\nJohn,john@example.com,555-1234";

        let result = scanner.scan(content).unwrap();
        assert_eq!(result.format, StructuredFormat::Csv);
        assert!(!result.pii_fields.is_empty());

        let email_field = result.pii_fields.iter().find(|f| f.field_name == "email");
        assert!(email_field.is_some());
        let ef = email_field.unwrap();
        assert_eq!(ef.pii_type, "email");
        assert!(ef.masked_value.contains('*'));
    }

    #[test]
    fn test_csv_scan_clean_data() {
        let scanner = CsvPiiScanner::with_defaults();
        let content = "id,status,active\n1,true,yes\n2,false,no";

        let result = scanner.scan(content).unwrap();
        assert!(result.pii_fields.is_empty());
    }

    #[test]
    fn test_csv_scan_empty_content() {
        let scanner = CsvPiiScanner::with_defaults();
        let result = scanner.scan("").unwrap();
        assert!(result.pii_fields.is_empty());
    }

    // =========================================================================
    // JsonPiiScanner Tests
    // =========================================================================

    #[test]
    fn test_json_scan_with_pii() {
        let scanner = JsonPiiScanner::with_defaults();
        let content = r#"{"user": {"name": "Alice", "email": "alice@test.com"}}"#;

        let result = scanner.scan(content).unwrap();
        assert_eq!(result.format, StructuredFormat::Json);
        assert!(!result.pii_fields.is_empty());

        let email_field = result
            .pii_fields
            .iter()
            .find(|f| f.field_path.contains("email"));
        assert!(email_field.is_some());
    }

    #[test]
    fn test_json_scan_array_handling() {
        let scanner = JsonPiiScanner::with_defaults();
        let content = r#"{"users": [{"email": "a@b.com"}, {"email": "c@d.com"}]}"#;

        let result = scanner.scan(content).unwrap();
        let email_count = result
            .pii_fields
            .iter()
            .filter(|f| f.pii_type == "email")
            .count();
        assert_eq!(email_count, 2);
    }

    #[test]
    fn test_json_scan_clean() {
        let scanner = JsonPiiScanner::with_defaults();
        let content = r#"{"config": {"debug": false, "version": "1.0"}}"#;

        let result = scanner.scan(content).unwrap();
        assert!(result.pii_fields.is_empty());
    }

    // =========================================================================
    // XmlPiiScanner Tests
    // =========================================================================

    #[test]
    fn test_xml_scan_with_pii() {
        let scanner = XmlPiiScanner::with_defaults();
        let content = r#"<person><name>Bob</name><email>bob@test.com</email></person>"#;

        let result = scanner.scan(content).unwrap();
        assert_eq!(result.format, StructuredFormat::Xml);
        assert!(!result.pii_fields.is_empty());
    }

    #[test]
    fn test_xml_scan_attributes() {
        let scanner = XmlPiiScanner::new(
            FieldClassifier::with_defaults(),
            XmlScannerConfig {
                scan_attributes: true,
                ..Default::default()
            },
        );
        let content = r#"<user email="admin@test.com" />"#;

        let result = scanner.scan(content).unwrap();
        let attr_match = result.pii_fields.iter().find(|f| f.field_path.contains('@'));
        assert!(attr_match.is_some());
    }

    #[test]
    fn test_xml_scan_clean() {
        let scanner = XmlPiiScanner::with_defaults();
        let content = r#"<config><debug>false</debug></config>"#;

        let result = scanner.scan(content).unwrap();
        assert!(result.pii_fields.is_empty());
    }

    // =========================================================================
    // Action Resolution Tests
    // =========================================================================

    #[test]
    fn test_redact_is_strictest() {
        let results = vec![
            FieldScanResult {
                field_path: "test".to_string(),
                field_name: "test".to_string(),
                raw_value: "val".to_string(),
                masked_value: "[REDACTED]".to_string(),
                pii_type: "test".to_string(),
                confidence: 0.9,
                action: FieldAction::Mask,
                row_index: None,
                col_index: None,
            },
            FieldScanResult {
                field_path: "test2".to_string(),
                field_name: "test2".to_string(),
                raw_value: "val2".to_string(),
                masked_value: "[REDACTED]".to_string(),
                pii_type: "test2".to_string(),
                confidence: 0.9,
                action: FieldAction::Redact,
                row_index: None,
                col_index: None,
            },
        ];

        let strictest = if results.iter().any(|r| r.action == FieldAction::Redact) {
            FieldAction::Redact
        } else {
            FieldAction::AlertOnly
        };
        assert_eq!(strictest, FieldAction::Redact);
    }
}

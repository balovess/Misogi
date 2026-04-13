// =============================================================================
// Context Module Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // ContextAnalysisRequest Tests
    // =========================================================================

    #[test]
    fn test_request_new_minimal() {
        let req = ContextAnalysisRequest::new("123456789012", "my_number", "My Number: ", " is ID");
        assert_eq!(req.candidate_text, "123456789012");
        assert_eq!(req.pii_type, "my_number");
        assert_eq!(req.prefix, "My Number: ");
        assert_eq!(req.suffix, " is ID");
        assert!(req.full_text.is_none());
    }

    #[test]
    fn test_combined_context() {
        let req = ContextAnalysisRequest::new("123", "test", "prefix_", "_suffix", "");
        assert_eq!(req.combined_context(), "prefix_123_suffix");
    }

    // =========================================================================
    // MockContextProvider Tests
    // =========================================================================

    #[tokio::test]
    async fn test_mock_always_confirm() {
        let mock = MockContextProvider::always_confirm();
        let req = ContextAnalysisRequest::new("123456789012", "my_number", "", "");

        let result = mock.analyze_context(&req).await.unwrap();
        assert!(result.is_pii);
        assert!(result.confidence_score >= 0.9);
        assert!(!result.matched_indicators.is_empty());
    }

    #[tokio::test]
    async fn test_mock_always_reject() {
        let mock = MockContextProvider::always_reject();
        let req = ContextAnalysisRequest::new("123456789012", "my_number", "", "");

        let result = mock.analyze_context(&req).await.unwrap();
        assert!(!result.is_pii);
        assert!(result.confidence_score < 0.1);
        assert!(!result.false_positive_signals.is_empty());
    }

    #[tokio::test]
    async fn test_mock_unavailable() {
        let mock = MockContextProvider::with_config("down-mock", false, true, 0.8);
        assert!(!mock.is_available().await.unwrap());

        let req = ContextAnalysisRequest::new("123", "test", "", "");
        let result = mock.analyze_context(&req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mock_provider_name() {
        let mock = MockContextProvider::with_config("custom-provider", true, false, 0.5);
        assert_eq!(mock.provider_name(), "custom-provider");
    }

    #[tokio::test]
    async fn test_mock_batch_sequential() {
        let mock = MockContextProvider::always_confirm();
        let requests = vec![
            ContextAnalysisRequest::new("111", "a", "", ""),
            ContextAnalysisRequest::new("222", "b", "", ""),
        ];

        let results = mock.analyze_batch(&requests).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_pii);
        assert!(results[1].is_pii);
    }

    // =========================================================================
    // KeywordRule / KeywordPosition Tests
    // =========================================================================

    #[test]
    fn test_keyword_matches_before() {
        let kw = KeywordRule {
            keyword: "My Number".to_string(),
            weight: 0.9,
            position: KeywordPosition::Before,
        };
        assert!(kw.matches_in("Your My Number is:", false));
        assert!(!kw.matches_in("Number is 123", false));
    }

    #[test]
    fn test_keyword_matches_after() {
        let kw = KeywordRule {
            keyword: "ID".to_string(),
            weight: 0.7,
            position: KeywordPosition::After,
        };
        assert!(kw.matches_in("is your ID now", false));
        assert!(!kw.matches_in("ID before this", false));
    }

    #[test]
    fn test_keyword_matches_either() {
        let kw = KeywordRule {
            keyword: "number".to_string(),
            weight: 0.5,
            position: KeywordPosition::Either,
        };
        assert!(kw.matches_in("phone number here", false));
        assert!(kw.matches_in("here is number", false));
        assert!(!kw.matches_in("no match text", false));
    }

    #[test]
    fn test_keyword_case_insensitive_default() {
        let kw = KeywordRule {
            keyword: "Email".to_string(),
            weight: 0.8,
            position: KeywordPosition::Before,
        };
        assert!(kw.matches_in("email address", false));
        assert!(kw.matches_in("EMAIL:", false));
    }

    #[test]
    fn test_keyword_case_sensitive() {
        let kw = KeywordRule {
            keyword: "Email".to_string(),
            weight: 0.8,
            position: KeywordPosition::Before,
        };
        assert!(kw.matches_in("Email address", true));
        assert!(!kw.matches_in("email address", true));
    }

    // =========================================================================
    // KeywordEngineConfig Tests
    // =========================================================================

    #[test]
    fn test_config_defaults() {
        let config = KeywordEngineConfig::default();
        assert_eq!(config.context_window_size, 100);
        assert!((config.positive_threshold - 0.7).abs() < f64::EPSILON);
        assert!((config.negative_threshold - 0.3).abs() < f64::EPSILON);
        assert!(!config.case_sensitive);
        assert_eq!(config.profile, "universal");
    }

    // =========================================================================
    // KeywordRuleEngine Tests
    // =========================================================================

    #[test]
    fn test_engine_with_defaults_loads() {
        let engine = KeywordRuleEngine::with_defaults();
        assert!(engine.is_ok());
    }

    #[test]
    fn test_engine_analyze_positive_context() {
        let engine = KeywordRuleEngine::with_defaults().unwrap();
        let req = ContextAnalysisRequest::new(
            "123456789012",
            "national_id",
            "Your national id number is ",
            " please keep safe",
        );

        let result = engine.analyze(&req).unwrap();
        assert!(
            result.is_pii,
            "Expected PII confirmation for 'national_id' with positive context, got: {}",
            result.reason
        );
    }

    #[test]
    fn test_engine_analyze_negative_context() {
        let engine = KeywordRuleEngine::with_defaults().unwrap();
        let req = ContextAnalysisRequest::new(
            "123456789012",
            "national_id",
            "Invoice no.",
            " reference code",
        );

        let result = engine.analyze(&req).unwrap();
        assert!(
            !result.is_pii,
            "Expected false positive rejection for invoice number, got: {}",
            result.reason
        );
    }

    #[test]
    fn test_engine_add_keyword_runtime() {
        let engine = KeywordRuleEngine::with_defaults().unwrap();

        engine
            .add_keyword(
                "national_id",
                KeywordRule {
                    keyword: "TEST_MARKER".to_string(),
                    weight: 0.99,
                    position: KeywordPosition::Before,
                },
            )
            .unwrap();

        let req = ContextAnalysisRequest::new(
            "123",
            "national_id",
            "TEST_MARKER before ",
            "",
        );

        let result = engine.analyze(&req).unwrap();
        assert!(result.is_pii);
        assert!(result.matched_indicators.contains(&"TEST_MARKER".to_string()));
    }

    #[test]
    fn test_engine_remove_keyword_runtime() {
        let engine = KeywordRuleEngine::with_defaults().unwrap();

        let removed = engine.remove_keyword("national_id", "nonexistent").unwrap();
        assert!(!removed);
    }

    // =========================================================================
    // RuleEngineBuilder Tests
    // =========================================================================

    #[test]
    fn test_builder_basic() {
        let engine = RuleEngineBuilder::new()
            .set_profile("custom")
            .set_context_window(200)
            .set_thresholds(0.8, 0.2)
            .set_case_sensitive(true)
            .add_global_anti("invoice", 0.7, KeywordPosition::Either)
            .build();

        assert!(engine.is_ok());
    }

    #[test]
    fn test_builder_with_pii_type() {
        let engine = RuleEngineBuilder::new()
            .add_pii_type("custom_type", "Custom Type")
            .add_positive("special_marker", 0.95, KeywordPosition::Before)
            .add_anti("not_special", 0.6, KeywordPosition::Either)
            .done()
            .build();

        assert!(engine.is_ok());
        let engine = engine.unwrap();
        let req = ContextAnalysisRequest::new(
            "123",
            "custom_type",
            "special_marker before ",
            "",
        );

        let result = engine.analyze(&req).unwrap();
        assert!(result.is_pii);
    }

    // =========================================================================
    // ContextAnalyzer Tests
    // =========================================================================

    #[tokio::test]
    async fn test_analyzer_keyword_only() {
        let analyzer = ContextAnalyzer::with_defaults().unwrap();
        let req = ContextAnalysisRequest::new(
            "123456789012",
            "national_id",
            "SSN: ",
            " (confidential)",
        );

        let result = analyzer.analyze(&req).await.unwrap();
        assert!(result.is_pii);
    }

    #[tokio::test]
    async fn test_analyzer_with_provider_graceful_degradation() {
        let provider = Arc::new(MockContextProvider::always_confirm());
        let fallback = KeywordRuleEngine::with_defaults().unwrap();

        let analyzer = ContextAnalyzer::with_provider(provider, fallback);

        let req = ContextAnalysisRequest::new(
            "123456789012",
            "my_number",
            "",
            "",
        );

        let result = analyzer.analyze(&req).await.unwrap();
        assert!(result.is_pii);
        assert_eq!(analyzer.provider_name(), Some("mock-always-pii"));
    }

    #[tokio::test]
    async fn test_analyzer_provider_down_fallback_to_keywords() {
        let provider = Arc::new(MockContextProvider::with_config(
            "down-provider",
            false,
            true,
            0.9,
        ));
        let fallback = KeywordRuleEngine::with_defaults().unwrap();

        let analyzer = ContextAnalyzer::with_provider(provider, fallback);

        let req = ContextAnalysisRequest::new(
            "123456789012",
            "national_id",
            "Invoice no. ",
            "",
        );

        let result = analyzer.analyze(&req).await.unwrap();
        assert!(!result.is_pii);
    }

    #[tokio::test]
    async fn test_analyzer_has_provider_flag() {
        let analyzer_no_provider = ContextAnalyzer::with_defaults().unwrap();
        assert!(!analyzer_no_provider.has_provider());
        assert!(analyzer_no_provider.provider_name().is_none());

        let provider = Arc::new(MockContextProvider::always_confirm());
        let analyzer_with = ContextAnalyzer::with_provider(
            provider,
            KeywordRuleEngine::with_defaults().unwrap(),
        );
        assert!(analyzer_with.has_provider());
        assert!(analyzer_with.provider_name().is_some());
    }

    #[tokio::test]
    async fn test_analyzer_force_keywords() {
        let provider = Arc::new(MockContextProvider::always_confirm());
        let fallback = KeywordRuleEngine::with_defaults().unwrap();

        let analyzer = ContextAnalyzer::with_provider(provider, fallback);

        let req = ContextAnalysisRequest::new(
            "123456789012",
            "national_id",
            "Invoice no. ",
            "",
        );

        let result = analyzer.analyze_with_keywords(&req).unwrap();
        assert!(!result.is_pii);
    }

    // =========================================================================
    // ContextError Tests
    // =========================================================================

    #[test]
    fn test_error_retryable_classification() {
        let comm_err = ContextError::Communication("network error".to_string());
        assert!(comm_err.is_retryable());

        let config_err = ContextError::Configuration("bad yaml".to_string());
        assert!(!config_err.is_retryable());
    }

    #[test]
    fn test_error_provider_extraction() {
        let err = ContextError::RateLimited {
            provider: "openai".to_string(),
            retry_after_secs: 30,
        };
        assert_eq!(err.provider_name(), Some("openai"));

        let err2 = ContextError::Communication("fail".to_string());
        assert_eq!(err2.provider_name(), None);
    }
}

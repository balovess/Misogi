// =============================================================================
// OCR Module Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pii::RegexPIIDetector;
    use std::sync::Arc;

    // =========================================================================
    // OcrBoundingBox Tests
    // =========================================================================

    #[test]
    fn test_bbox_new_clamps_to_range() {
        let bbox = OcrBoundingBox::new(-0.5, -0.5, 1.5, 1.5);
        assert_eq!(bbox.x_min, 0.0);
        assert_eq!(bbox.y_min, 0.0);
        assert_eq!(bbox.x_max, 1.0);
        assert_eq!(bbox.y_max, 1.0);
    }

    #[test]
    fn test_bbox_dimensions() {
        let bbox = OcrBoundingBox::new(0.1, 0.2, 0.6, 0.8);
        assert!((bbox.width() - 0.5).abs() < f64::EPSILON);
        assert!((bbox.height() - 0.6).abs() < f64::EPSILON);
        assert!((bbox.area() - 0.3).abs() < f64::EPSILON);
    }

    // =========================================================================
    // OcrExtractionResult Tests
    // =========================================================================

    #[test]
    fn test_extraction_empty() {
        let result = OcrExtractionResult::empty();
        assert!(result.full_text.is_empty());
        assert!(result.blocks.is_empty());
        assert_eq!(result.overall_confidence, 0.0);
        assert_eq!(result.block_count(), 0);
        assert_eq!(result.average_confidence(), 0.0);
    }

    #[test]
    fn test_extraction_with_blocks() {
        let result = OcrExtractionResult {
            full_text: "Hello World".to_string(),
            blocks: vec![
                OcrTextBlock {
                    text: "Hello".to_string(),
                    bbox: OcrBoundingBox::new(0.0, 0.0, 0.5, 0.5),
                    confidence: 0.95,
                },
                OcrTextBlock {
                    text: "World".to_string(),
                    bbox: OcrBoundingBox::new(0.5, 0.5, 1.0, 1.0),
                    confidence: 0.85,
                },
            ],
            metadata: OcrImageMetadata::default(),
            overall_confidence: 0.90,
        };

        assert_eq!(result.block_count(), 2);
        let avg = result.average_confidence();
        assert!((avg - 0.9).abs() < 0.01);
    }

    // =========================================================================
    // MockOcrProvider Tests
    // =========================================================================

    #[tokio::test]
    async fn test_mock_ocr_with_text() {
        let mock = MockOcrProvider::with_text("Invoice #12345 Customer: John Doe", 0.92);

        assert!(mock.is_available().await);
        assert_eq!(mock.provider_name(), "mock-ocr");

        let result = mock.extract_text(&[0; 100]).await.unwrap();
        assert_eq!(result.full_text, "Invoice #12345 Customer: John Doe");
        assert_eq!(result.block_count(), 1);
        assert!((result.overall_confidence - 0.92).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_mock_ocr_empty_result() {
        let mock = MockOcrProvider::empty_result();

        let result = mock.extract_text(&[0; 100]).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            OcrError::NoTextFound => {}
            other => panic!("Expected NoTextFound, got: {}", other),
        }
    }

    #[tokio::test]
    async fn test_mock_ocr_unavailable() {
        let mock = MockOcrProvider::unavailable();

        assert!(!mock.is_available().await);

        let result = mock.extract_text(&[0; 100]).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            OcrError::ProviderUnavailable { provider, .. } => {
                assert_eq!(provider, "mock-ocr-down");
            }
            other => panic!("Expected ProviderUnavailable, got: {}", other),
        }
    }

    // =========================================================================
    // OcrPiiDetector Integration Tests
    // =========================================================================

    #[tokio::test]
    async fn test_ocr_detector_finds_pii_in_image() {
        let mock = Arc::new(MockOcrProvider::with_text(
            "Email: admin@example.com Phone: 555-1234",
            0.95,
        )) as Arc<dyn OcrProvider>;

        let detector = Arc::new(RegexPIIDetector::with_jp_defaults());

        let ocr_detector = OcrPiiDetector::with_defaults(mock, detector);

        let result = ocr_detector.scan_image(&[0xFF; 500], "test-image.png").await.unwrap();

        assert!(result.found);
        assert!(!result.matches.is_empty());
        assert_eq!(result.total_chars_extracted, 38);
    }

    #[tokio::test]
    async fn test_ocr_detector_clean_image() {
        let mock = Arc::new(MockOcrProvider::with_text(
            "This document contains no sensitive data.",
            0.95,
        )) as Arc<dyn OcrProvider>;

        let detector = Arc::new(RegexPIIDetector::with_jp_defaults());

        let ocr_detector = OcrPiiDetector::with_defaults(mock, detector);

        let result = ocr_detector.scan_image(&[0xFF; 200], "clean.png").await.unwrap();

        assert!(!result.found);
        assert!(result.matches.is_empty());
    }

    #[tokio::test]
    async fn test_ocr_detector_spatial_annotation() {
        let mock = Arc::new(MockOcrProvider::with_text("SSN: 123-45-6789", 0.88)) as Arc<dyn OcrProvider>;
        let detector = Arc::new(RegexPIIDetector::with_jp_defaults());

        let config = OcrDetectorConfig {
            spatial_annotation: true,
            min_ocr_confidence: 0.7,
            ..Default::default()
        };
        let ocr_detector = OcrPiiDetector::new(mock, detector, config);

        let result = ocr_detector.scan_image(&[0; 100], "spatial-test.jpg").await.unwrap();

        if !result.matches.is_empty() {
            let first_match = &result.matches[0];
            assert!(first_match.bbox.is_some());
            let bbox = first_match.bbox.unwrap();
            assert!(bbox.x_min >= 0.0 && bbox.x_max <= 1.0);
        }
    }

    #[tokio::test]
    async fn test_ocr_detector_image_too_large() {
        let mock = Arc::new(MockOcrProvider::with_text("data", 0.9)) as Arc<dyn OcrProvider>;
        let detector = Arc::new(RegexPIIDetector::with_jp_defaults());

        let config = OcrDetectorConfig {
            max_size_mb: 1,
            ..Default::default()
        };
        let ocr_detector = OcrPiiDetector::new(mock, detector, config);

        let large_image = vec![0u8; 2 * 1024 * 1024];
        let result = ocr_detector.scan_image(&large_image, "huge.tiff").await;

        assert!(result.is_err());
    }

    // =========================================================================
    // OcrError Tests
    // =========================================================================

    #[test]
    fn test_error_display() {
        let err = OcrError::UnsupportedFormat { format: "gif".to_string() };
        assert!(err.to_string().contains("gif"));

        let err2 = OcrError::Timeout { timeout_ms: 5000 };
        assert!(err2.to_string().contains("5000"));
    }
}

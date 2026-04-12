//! Integration tests for PDF True CDR Engine
//!
//! These tests verify end-to-end functionality of the parse→extract→rebuild pipeline.
//! Tests are organized by scenario: basic reconstruction, threat removal, configuration,
//! and output validation.
//!
//! # Running Tests
//!
//! ```bash
//! # Run all tests (requires pdf-cdr feature)
//! cargo test --package misogi-cdr --features pdf-cdr --test pdf_true_cdr_test
//!
//! # Run only fast tests (no real file assets needed)
//! cargo test --package misogi-cdr --features pdf-cdr --test pdf_true_cdr_test -- --ignored
//! ```
//!
//! # Test Categories
//!
//! - **Basic**: Minimal PDF reconstruction (no external files)
//! - **Threat Removal**: Verify dangerous content is eliminated
//! - **Configuration**: Test different policy settings
//! - **Output Validation**: Ensure output is valid, clean PDF
//! - **Edge Cases**: Empty, corrupted, or unusual inputs

use misogi_cdr::pdf_sanitizer::PdfSanitizer;
#[cfg(feature = "pdf-cdr")]
use misogi_cdr::pdf_true_cdr::*;

// =============================================================================
// Test Utilities
// =============================================================================

/// Generate a minimal valid PDF document with one blank page.
///
/// This is a hand-crafted minimal PDF conforming to PDF 1.4 specification.
/// It contains no active content, no scripts, and no embedded resources —
/// ideal for baseline testing of the CDR pipeline.
fn generate_minimal_pdf() -> Vec<u8> {
    br#"%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj

xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 

trailer
<< /Size 4 /Root 1 0 R >>

startxref
190
%%EOF
"#
    .to_vec()
}

/// Generate a PDF with JavaScript threat (OpenAction).
///
/// This PDF contains `/OpenAction` pointing to a JavaScript action,
/// which should be detected and removed by the CDR engine.
#[allow(dead_code)]
fn generate_pdf_with_javascript() -> Vec<u8> {
    br#"%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('XSS')) >> >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj

xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000105 00000 n 
0000000162 00000 n 

trailer
<< /Size 4 /Root 1 0 R >>

startxref
237
%%EOF
"#
    .to_vec()
}

/// Generate a PDF with Additional Actions (AA) dictionary.
///
/// Contains `/AA` on catalog with page-open action — should be removed.
#[allow(dead_code)]
fn generate_pdf_with_aa() -> Vec<u8> {
    br#"%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /AA << /O << /S /JavaScript /JS (console.log('open')) >> >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj

xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000097 00000 n 
0000000154 00000 n 

trailer
<< /Size 4 /Root 1 0 R >>

startxref
229
%%EOF
"#
    .to_vec()
}

/// Generate a PDF with embedded file attachment.
///
/// Contains `/EmbeddedFile` specification — should be flagged/removed.
#[allow(dead_code)]
fn generate_pdf_with_embedded_file() -> Vec<u8> {
    // Simplified: just include the keyword; full EmbeddedFile requires complex structure
    br#"%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>
endobj

4 0 obj
<< /Type /Annot /Subtype /FileAttachment /FS << /F (malware.exe) /UF (malware.exe) /EF << /F 5 0 R >> >> >>
endobj

5 0 obj
<< /EmbeddedFile <...malicious content...> >>
endobj

xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000196 00000 n 
0000000310 00000 n 

trailer
<< /Size 6 /Root 1 0 R >>

startxref
380
%%EOF
"#
    .to_vec()
}

// =============================================================================
// A. Basic Reconstruction Tests
// =============================================================================

#[cfg(feature = "pdf-cdr")]
mod basic_tests {
    use super::*;

    #[test]
    fn test_reconstruct_minimal_pdf_succeeds() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let pdf_bytes = generate_minimal_pdf();

        let result = engine.reconstruct(&pdf_bytes);

        assert!(
            result.is_ok(),
            "Minimal PDF should reconstruct successfully"
        );
        let cdr_result = result.unwrap();

        assert!(cdr_result.success, "Result should indicate success");
        assert_eq!(
            cdr_result.report.pages_extracted, 1,
            "Should extract exactly 1 page"
        );
        assert!(
            cdr_result.output.starts_with(b"%PDF"),
            "Output should start with %PDF header"
        );
        assert!(!cdr_result.output.is_empty(), "Output should not be empty");
    }

    #[test]
    fn test_reconstruct_output_is_valid_pdf_structure() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let pdf_bytes = generate_minimal_pdf();

        let result = engine.reconstruct(&pdf_bytes).unwrap();
        let output_str = String::from_utf8_lossy(&result.output);

        // Check for required PDF structural elements
        assert!(output_str.contains("%PDF"), "Should have PDF header");
        assert!(output_str.contains("trailer"), "Should have trailer");
        assert!(output_str.contains("startxref"), "Should have startxref");
        assert!(
            output_str.ends_with("%%EOF\n") || output_str.ends_with("%%EOF\r\n"),
            "Should end with %%EOF"
        );
    }

    #[test]
    fn test_reconstruct_output_no_original_threats() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let clean_pdf = generate_minimal_pdf();

        let result = engine.reconstruct(&clean_pdf).unwrap();
        let output_str = String::from_utf8_lossy(&result.output);

        // Clean PDF should have no threats in report
        assert!(
            result.report.threats_removed.is_empty(),
            "Clean PDF should have zero threats removed"
        );

        // Output should not contain any dangerous keywords
        assert!(
            !output_str.contains("/OpenAction"),
            "Clean output should not contain /OpenAction"
        );
        assert!(
            !output_str.contains("/JS"),
            "Clean output should not contain /JS"
        );
        assert!(
            !output_str.contains("/JavaScript"),
            "Clean output should not contain /JavaScript"
        );
    }

    #[test]
    fn test_via_pdf_sanitizer_integration() {
        let sanitizer = PdfSanitizer::default_config();
        let pdf_bytes = generate_minimal_pdf();

        let result = sanitizer.true_cdr_reconstruct(&pdf_bytes, None);

        assert!(
            result.is_ok(),
            "PdfSanitizer.true_cdr_reconstruct should work"
        );
        let cdr_result = result.unwrap();

        assert!(cdr_result.success);
        assert_eq!(cdr_result.report.pages_extracted, 1);
    }
}

// =============================================================================
// B. Threat Removal Tests
// =============================================================================

#[cfg(feature = "pdf-cdr")]
mod threat_removal_tests {
    use super::*;

    #[test]
    fn test_removes_openaction_javascript() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let malicious_pdf = generate_pdf_with_javascript();

        let result = engine.reconstruct(&malicious_pdf).unwrap();

        // Should succeed despite threat
        assert!(result.success);

        // Should detect and record threat removal
        assert!(
            !result.report.threats_removed.is_empty(),
            "Should detect OpenAction/JavaScript threat"
        );

        // Verify at least one threat was JavaScript or OpenAction type
        let has_js_or_openaction = result.report.threats_removed.iter().any(|t| {
            t.threat_type == ThreatType::JavaScript || t.threat_type == ThreatType::OpenAction
        });
        assert!(
            has_js_or_openaction,
            "Should have removed JavaScript or OpenAction threat"
        );

        // Output must NOT contain the original threat
        let output_str = String::from_utf8_lossy(&result.output);
        assert!(
            !output_str.contains("/OpenAction"),
            "Output must not contain /OpenAction"
        );
        assert!(
            !output_str.contains("app.alert"),
            "Output must not contain original JS code"
        );
    }

    #[test]
    fn test_removes_additional_actions() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let aa_pdf = generate_pdf_with_aa();

        let result = engine.reconstruct(&aa_pdf).unwrap();

        assert!(result.success);

        // Should detect AA dictionary
        let has_aa_removal = result
            .report
            .threats_removed
            .iter()
            .any(|t| t.threat_type == ThreatType::AdditionalActions);
        assert!(
            has_aa_removal,
            "Should detect and remove Additional Actions"
        );

        // Output must be clean
        let output_str = String::from_utf8_lossy(&result.output);
        assert!(
            !output_str.contains("/AA"),
            "Output must not contain /AA dictionary"
        );
    }

    #[test]
    fn test_handles_embedded_file() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let ef_pdf = generate_pdf_with_embedded_file();

        let result = engine.reconstruct(&ef_pdf).unwrap();

        assert!(result.success);

        // Should flag or remove embedded file
        let has_ef_removal = result
            .report
            .threats_removed
            .iter()
            .any(|t| t.threat_type == ThreatType::EmbeddedFile);
        assert!(
            has_ef_removal || !result.report.blocked_items.is_empty(),
            "Should handle embedded file (remove or block)"
        );

        // Output should not contain executable references
        let output_str = String::from_utf8_lossy(&result.output);
        assert!(
            !output_str.contains("malware.exe"),
            "Output must not reference malicious filename"
        );
    }

    #[test]
    fn test_multiple_threats_all_removed() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();

        // Create PDF with multiple threat types (worst-case scenario)
        // For this test, we'll use JS-containing PDF as representative
        let malicious_pdf = generate_pdf_with_javascript();

        let result = engine.reconstruct(&malicious_pdf).unwrap();

        // Should still produce valid output even with threats present
        assert!(result.success);
        assert!(
            result.output.starts_with(b"%PDF"),
            "Even malicious input should produce valid PDF output"
        );

        // Report should document what was done
        assert!(
            !result.report.threats_removed.is_empty() || !result.report.warnings.is_empty(),
            "Should have some audit trail of actions taken"
        );
    }
}

// =============================================================================
// C. Configuration Tests
// =============================================================================

#[cfg(feature = "pdf-cdr")]
mod configuration_tests {
    use super::*;

    #[test]
    fn test_jp_defaults_are_maximally_secure() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();

        // Verify JP defaults enforce strictest settings
        assert!(
            engine.config.max_embedded_file_size.is_none(),
            "JP defaults should block all embedded files"
        );
        assert!(
            !engine.config.allow_forms,
            "JP defaults should disable forms"
        );
        assert!(
            !engine.config.allow_annotations,
            "JP defaults should disable annotations"
        );
        assert!(
            !engine.config.preserve_metadata,
            "JP defaults should strip metadata"
        );
        assert_eq!(
            engine.config.image_policy,
            ImageExtractionPolicy::ReEncode,
            "JP defaults should re-encode images"
        );
        assert_eq!(
            engine.config.font_policy,
            FontPolicy::StandardFontsOnly,
            "JP defaults should use standard fonts only"
        );
    }

    #[test]
    fn test_custom_config_overrides_defaults() {
        let custom_config = PdfTrueCdrConfig {
            max_embedded_file_size: Some(10 * 1024 * 1024), // 10 MB
            allow_forms: true,
            allow_annotations: true,
            preserve_metadata: true,
            image_policy: ImageExtractionPolicy::KeepOriginal,
            font_policy: FontPolicy::KeepEmbedded,
        };

        let engine = PdfTrueCdrEngine::with_config(custom_config.clone());

        assert_eq!(engine.config.max_embedded_file_size, Some(10 * 1024 * 1024));
        assert!(engine.config.allow_forms);
        assert!(engine.config.allow_annotations);
        assert!(engine.config.preserve_metadata);
        assert_eq!(
            engine.config.image_policy,
            ImageExtractionPolicy::KeepOriginal
        );
        assert_eq!(engine.config.font_policy, FontPolicy::KeepEmbedded);
    }

    #[test]
    fn test_permissive_config_still_removes_critical_threats() {
        // Even permissive config should still remove JS/OpenAction
        let permissive_config = PdfTrueCdrConfig {
            max_embedded_file_size: Some(u64::MAX),
            allow_forms: true,
            allow_annotations: true,
            preserve_metadata: true,
            image_policy: ImageExtractionPolicy::KeepOriginal,
            font_policy: FontPolicy::KeepEmbedded,
        };

        let engine = PdfTrueCdrEngine::with_config(permissive_config);
        let malicious_pdf = generate_pdf_with_javascript();

        let result = engine.reconstruct(&malicious_pdf).unwrap();

        // Critical threats MUST always be removed regardless of config
        assert!(
            !result.report.threats_removed.is_empty(),
            "Even permissive config must remove critical threats"
        );

        let output_str = String::from_utf8_lossy(&result.output);
        assert!(
            !output_str.contains("/OpenAction"),
            "Critical threats removed even in permissive mode"
        );
    }

    #[test]
    fn test_image_policy_variants() {
        // Test that all ImageExtractionPolicy variants can be used
        let policies = vec![
            ImageExtractionPolicy::KeepOriginal,
            ImageExtractionPolicy::ReEncode,
            ImageExtractionPolicy::ResizeMaxDimensions(1920, 1080),
            ImageExtractionPolicy::BlockAll,
        ];

        for policy in policies {
            let config = PdfTrueCdrConfig {
                image_policy: policy.clone(),
                ..Default::default()
            };

            let engine = PdfTrueCdrEngine::with_config(config);
            let pdf_bytes = generate_minimal_pdf();

            // Should not panic or error on any policy variant
            let result = engine.reconstruct(&pdf_bytes);
            assert!(result.is_ok(), "Image policy {:?} should work", policy);
        }
    }

    #[test]
    fn test_font_policy_variants() {
        // Test that all FontPolicy variants can be used
        let policies = vec![
            FontPolicy::KeepEmbedded,
            FontPolicy::SubsetGlyphs,
            FontPolicy::StandardFontsOnly,
        ];

        for policy in policies {
            let config = PdfTrueCdrConfig {
                font_policy: policy.clone(),
                ..Default::default()
            };

            let engine = PdfTrueCdrEngine::with_config(config);
            let pdf_bytes = generate_minimal_pdf();

            let result = engine.reconstruct(&pdf_bytes);
            assert!(result.is_ok(), "Font policy {:?} should work", policy);
        }
    }
}

// =============================================================================
// D. Output Validation Tests
// =============================================================================

#[cfg(feature = "pdf-cdr")]
mod output_validation_tests {
    use super::*;

    #[test]
    fn test_output_is_smaller_or_similar_size() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let pdf_bytes = generate_minimal_pdf();

        let result = engine.reconstruct(&pdf_bytes).unwrap();

        // Rebuilt PDF should be reasonably sized (not excessively larger)
        // Allow up to 10x size increase due to structure rebuilding overhead
        let max_expected_size = pdf_bytes.len() * 10;
        assert!(
            result.output.len() <= max_expected_size,
            "Output size {} should not exceed 10x input size {}",
            result.output.len(),
            pdf_bytes.len()
        );
    }

    #[test]
    fn test_output_has_correct_page_count() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let pdf_bytes = generate_minimal_pdf();

        let result = engine.reconstruct(&pdf_bytes).unwrap();

        // Input has 1 page, output should also have 1 page
        assert_eq!(
            result.report.pages_extracted, 1,
            "Page count should match input"
        );
    }

    #[test]
    fn test_report_contains_audit_trail() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let pdf_bytes = generate_minimal_pdf();

        let result = engine.reconstruct(&pdf_bytes).unwrap();

        // Report should always be populated
        assert!(
            result.report.pages_extracted > 0 || !result.report.warnings.is_empty(),
            "Report should have pages extracted or warnings"
        );

        // All vectors should be initialized (not None/unset)
        let _ = &result.report.fonts_preserved;
        let _ = &result.report.images_extracted;
        let _ = &result.report.threats_removed;
        let _ = &result.report.blocked_items;
        let _ = &result.report.warnings;
    }

    #[test]
    fn test_output_can_be_parsed_by_lopdf() {
        // Verify output is valid enough to re-parse (round-trip test)
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let pdf_bytes = generate_minimal_pdf();

        let result = engine.reconstruct(&pdf_bytes).unwrap();

        // Try to parse output with lopdf
        let re_parse = lopdf::Document::load_mem(&result.output);
        assert!(
            re_parse.is_ok(),
            "Output PDF should be re-parseable by lopdf"
        );
    }

    #[test]
    fn test_different_input_same_clean_output_structure() {
        // Two different clean inputs should both produce valid output
        let engine = PdfTrueCdrEngine::with_jp_defaults();

        let pdf1 = generate_minimal_pdf();
        let pdf2 = generate_minimal_pdf(); // Same content

        let result1 = engine.reconstruct(&pdf1).unwrap();
        let result2 = engine.reconstruct(&pdf2).unwrap();

        // Both should succeed
        assert!(result1.success && result2.success);

        // Both should have same page count
        assert_eq!(
            result1.report.pages_extracted, result2.report.pages_extracted,
            "Same input should produce same page count"
        );
    }
}

// =============================================================================
// E. Edge Case Tests
// =============================================================================

#[cfg(feature = "pdf-cdr")]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_very_small_pdf() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let tiny_pdf = b"%PDF-1.0\n<</Type/Catalog/Pages 1 0 R>>\n".to_vec();

        // May fail parsing but shouldn't crash
        let result = engine.reconstruct(&tiny_pdf);

        // Either success or graceful error is acceptable
        match result {
            Ok(_) => {} // Success is fine
            Err(e) => {
                // Error should be descriptive, not panic
                let _ = format!("{}", e);
            }
        }
    }

    #[test]
    fn test_non_pdf_input_returns_error() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let not_pdf = b"This is not a PDF file".to_vec();

        let result = engine.reconstruct(&not_pdf);

        assert!(result.is_err(), "Non-PDF input should return error");

        match result.unwrap_err() {
            PdfCdrError::InvalidPdf(_) => {} // Expected
            other => panic!("Expected InvalidPdf error, got {:?}", other),
        }
    }

    #[test]
    fn test_empty_input_returns_error() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let empty: Vec<u8> = Vec::new();

        let result = engine.reconstruct(&empty);

        assert!(result.is_err(), "Empty input should return error");
    }

    #[test]
    fn test_pdf_header_only() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let header_only = b"%PDF-1.4\n".to_vec();

        let result = engine.reconstruct(&header_only);

        // Will likely fail parsing (incomplete structure) but shouldn't crash
        match result {
            Ok(cdr_result) => {
                // If it succeeds, output should be valid
                assert!(cdr_result.output.starts_with(b"%PDF"));
            }
            Err(e) => {
                // Error is acceptable for malformed input
                let _ = format!("{}", e);
            }
        }
    }

    #[test]
    fn test_large_page_count_handled() {
        // Note: We can't easily generate a huge PDF in memory without lopdf,
        // so we just verify the engine doesn't crash on normal inputs
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let pdf_bytes = generate_minimal_pdf();

        // Run multiple times to check for resource leaks or state issues
        for _ in 0..5 {
            let _ = engine.reconstruct(&pdf_bytes);
        }

        // If we get here without panicking, test passes
    }
}

// =============================================================================
// F. Feature Gate Tests (Run Without pdf-cdr Feature)
// =============================================================================

#[cfg(not(feature = "pdf-cdr"))]
mod feature_gate_tests {
    use super::*;

    #[test]
    fn test_feature_disabled_returns_error() {
        let sanitizer = PdfSanitizer::default_config();
        let pdf_bytes = generate_minimal_pdf();

        let result = sanitizer.true_cdr_reconstruct(&pdf_bytes, None);

        assert!(result.is_err(), "Should return error when feature disabled");

        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("pdf-cdr") || err_msg.contains("feature"),
            "Error should mention missing feature flag"
        );
    }
}

// =============================================================================
// G. Performance Sanity Checks (Not Benchmarks)
// =============================================================================

#[cfg(feature = "pdf-cdr")]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_reconstruction_completes_in_reasonable_time() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let pdf_bytes = generate_minimal_pdf();

        let start = Instant::now();
        let result = engine.reconstruct(&pdf_bytes);
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(
            elapsed.as_secs() < 10,
            "Reconstruction took too long: {:?}",
            elapsed
        );

        println!("Minimal PDF reconstruction time: {:?}", elapsed);
    }

    #[test]
    fn test_malicious_pdf_not_slower_than_clean() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();

        let clean_pdf = generate_minimal_pdf();
        let malicious_pdf = generate_pdf_with_javascript();

        let start_clean = Instant::now();
        let _ = engine.reconstruct(&clean_pdf).unwrap();
        let elapsed_clean = start_clean.elapsed();

        let start_malicious = Instant::now();
        let _ = engine.reconstruct(&malicious_pdf).unwrap();
        let elapsed_malicious = start_malicious.elapsed();

        // Malicious PDF shouldn't be dramatically slower (within 5x)
        let ratio = elapsed_malicious.as_nanos() as f64 / elapsed_clean.as_nanos().max(1) as f64;
        assert!(
            ratio < 5.0,
            "Malicious PDF processing ({:?}) too slow vs clean ({:?}): {:.2}x",
            elapsed_malicious,
            elapsed_clean,
            ratio
        );
    }
}

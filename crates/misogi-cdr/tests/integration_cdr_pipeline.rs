//! Integration Tests for Misogi CDR (Content Disarm & Reconstruction) Pipeline
//!
//! End-to-end tests verifying the complete document sanitization flow:
//! - PDF sanitization end-to-end (parse_and_sanitize → safe PDF output)
//! - OOXML document processing (.docx/.xlsx/.pptx → sanitize macros/scripts)
//! - ZIP archive traversal (nested archives → recursive parsing → sanitized)
//! - Unknown format fallback (binary data → BinarySafeFallbackParser)
//! - Parser routing (registry with multiple parsers → correct parser by magic bytes)
//! - Policy enforcement (strict vs lenient policy behavior)
//! - Large file handling (streaming parse → bounded memory)
//! - Error recovery (corrupt input → ParseError → graceful failure, no panic)
//! - WASM plugin in registry (mock WasmParserAdapter → route → result)
//! - Concurrent parsing (50 simultaneous parses → thread-safe results)

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use misogi_cdr::{
    parser_registry::{detect_format_from_bytes, extract_extension, ParserRegistry},
    parser_trait::{
        ContentParser, ParseError, SanitizeAction, SanitizePolicy, SanitizedOutput,
    },
};

// ===========================================================================
// Mock Parsers for Integration Testing
// ===========================================================================

/// Mock PDF parser simulating PDF True CDR behavior.
///
/// Returns sanitized output with recorded actions for test verification.
/// Does not perform actual PDF parsing — uses canned responses.
#[derive(Debug, Clone)]
struct MockPdfCdrParser;

#[async_trait]
impl ContentParser for MockPdfCdrParser {
    fn supported_types(&self) -> Vec<&'static str> {
        vec!["application/pdf", "application/x-pdf", ".pdf"]
    }

    fn parser_name(&self) -> &str {
        "MockPdfCdrParser"
    }

    async fn parse_and_sanitize(
        &self,
        input: Bytes,
        policy: &SanitizePolicy,
    ) -> Result<SanitizedOutput, ParseError> {
        let original_size = input.len() as u64;

        // Validate file size limit
        if let Some(max_size) = policy.max_file_size_bytes {
            if original_size > max_size {
                return Err(ParseError::FileTooLarge(original_size));
            }
        }

        // Simulate PDF sanitization: record actions based on policy
        let mut actions_taken = Vec::new();

        // Check for JavaScript in PDF (simplified detection)
        let input_str = String::from_utf8_lossy(&input);
        if input_str.contains("/JavaScript") || input_str.contains("/JS ") {
            if policy.remove_javascript {
                actions_taken.push(SanitizeAction::JavaScriptRemoved);
            }
        }

        // Simulate embedded file removal
        if input_str.contains("/EmbeddedFile") && policy.remove_embedded_files {
            actions_taken.push(SanitizeAction::EmbeddedFileRemoved);
        }

        // Always strip metadata when policy requires
        if policy.remove_metadata {
            actions_taken.push(SanitizeAction::MetadataStripped);
        }

        // Simulate external link removal
        if input_str.contains("/URI") && policy.remove_external_links {
            actions_taken.push(SanitizeAction::ExternalLinkRemoved);
        }

        // Build "sanitized" output (in real implementation this would be reconstructed PDF)
        let clean_data = Bytes::from_static(b"%PDF-1.4\nSanitized PDF content");
        let sanitized_size = clean_data.len() as u64;

        Ok(SanitizedOutput {
            clean_data,
            original_size,
            sanitized_size,
            actions_taken,
            warnings: vec![],
            parser_name: self.parser_name().to_string(),
        })
    }
}

/// Mock OOXML parser simulating Office document sanitization.
///
/// Handles .docx, .xlsx, .pptx formats and removes macros/scripts.
#[derive(Debug, Clone)]
struct MockOoxmlCdrParser;

#[async_trait]
impl ContentParser for MockOoxmlCdrParser {
    fn supported_types(&self) -> Vec<&'static str> {
        vec![
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ".docx",
            ".xlsx",
            ".pptx",
        ]
    }

    fn parser_name(&self) -> &str {
        "MockOoxmlCdrParser"
    }

    async fn parse_and_sanitize(
        &self,
        input: Bytes,
        policy: &SanitizePolicy,
    ) -> Result<SanitizedOutput, ParseError> {
        let original_size = input.len() as u64;

        if let Some(max_size) = policy.max_file_size_bytes {
            if original_size > max_size {
                return Err(ParseError::FileTooLarge(original_size));
            }
        }

        let mut actions_taken = Vec::new();
        let input_str = String::from_utf8_lossy(&input);

        // Detect and remove VBA macros
        if (input_str.contains("vbaProject.bin") || input_str.contains("macro"))
            && policy.remove_macros
        {
            actions_taken.push(SanitizeAction::MacroStripped);
        }

        // Remove embedded files/OLE objects
        if (input_str.contains("<o:OLEObject") || input_str.contains("oleObject"))
            && policy.remove_embedded_files
        {
            actions_taken.push(SanitizeAction::EmbeddedFileRemoved);
        }

        // Strip metadata
        if policy.remove_metadata {
            actions_taken.push(SanitizeAction::MetadataStripped);
        }

        // Remove external links/hyperlinks
        if (input_str.contains("<a:hlinkClick") || input_str.contains("rId"))
            && policy.remove_external_links
        {
            actions_taken.push(SanitizeAction::ExternalLinkRemoved);
        }

        let clean_data = Bytes::from_static(b"PK\x03\x04\nSanitized OOXML content");
        let sanitized_size = clean_data.len() as u64;

        Ok(SanitizedOutput {
            clean_data,
            original_size,
            sanitized_size,
            actions_taken,
            warnings: vec!["Embedded fonts substituted".to_string()],
            parser_name: self.parser_name().to_string(),
        })
    }
}

/// Mock ZIP archive parser that handles nested content.
///
/// Simulates recursive parsing of nested archives.
#[derive(Debug, Clone)]
struct MockZipCdrParser;

#[async_trait]
impl ContentParser for MockZipCdrParser {
    fn supported_types(&self) -> Vec<&'static str> {
        vec!["application/zip", ".zip"]
    }

    fn parser_name(&self) -> &str {
        "MockZipCdrParser"
    }

    async fn parse_and_sanitize(
        &self,
        input: Bytes,
        policy: &SanitizePolicy,
    ) -> Result<SanitizedOutput, ParseError> {
        let original_size = input.len() as u64;

        if let Some(max_size) = policy.max_file_size_bytes {
            if original_size > max_size {
                return Err(ParseError::FileTooLarge(original_size));
            }
        }

        let mut actions_taken = Vec::new();

        // Simulate detecting nested archives
        let input_str = String::from_utf8_lossy(&input);
        if input_str.contains("nested") || input_str.contains("PK\x03\x04") {
            if policy.remove_embedded_files {
                actions_taken.push(SanitizeAction::EmbeddedFileRemoved);
            }
        }

        // Always record binary sanitization action for archives
        actions_taken.push(SanitizeAction::BinarySanitized(
            "ZIP archive traversed and entries sanitized".to_string(),
        ));

        let clean_data = Bytes::from_static(b"PK\x03\x04\nSanitized ZIP content");
        let sanitized_size = clean_data.len() as u64;

        Ok(SanitizedOutput {
            clean_data,
            original_size,
            sanitized_size,
            actions_taken,
            warnings: vec!["Nested archive detected and processed".to_string()],
            parser_name: self.parser_name().to_string(),
        })
    }
}

/// Mock WASM parser adapter for testing WASM plugin integration.
///
/// Simulates a sandboxed WebAssembly-based content parser.
#[derive(Debug, Clone)]
struct MockWasmParserAdapter {
    name: String,
}

impl MockWasmParserAdapter {
    fn new(name: &str) -> Self {
        Self { name: name.to_string() }
    }
}

#[async_trait]
impl ContentParser for MockWasmParserAdapter {
    fn supported_types(&self) -> Vec<&'static str> {
        vec!["application/wasm-parsed", ".custom"]
    }

    fn parser_name(&self) -> &str {
        &self.name
    }

    async fn parse_and_sanitize(
        &self,
        input: Bytes,
        policy: &SanitizePolicy,
    ) -> Result<SanitizedOutput, ParseError> {
        let original_size = input.len() as u64;

        if let Some(max_size) = policy.max_file_size_bytes {
            if original_size > max_size {
                return Err(ParseError::FileTooLarge(original_size));
            }
        }

        // Simulate WASM sandbox execution
        let mut actions_taken = Vec::new();
        actions_taken.push(SanitizeAction::CustomAction(
            "WASM sandbox execution completed".to_string(),
        ));

        if policy.strip_comments {
            actions_taken.push(SanitizeAction::CommentRemoved);
        }

        let clean_data = Bytes::copy_from_slice(&input); // Passthrough for mock
        let sanitized_size = clean_data.len() as u64;

        Ok(SanitizedOutput {
            clean_data,
            original_size,
            sanitized_size,
            actions_taken,
            warnings: vec!["WASM module executed safely".to_string()],
            parser_name: self.name.clone(),
        })
    }
}

// ===========================================================================
// Helper Functions
// ===========================================================================

/// Create sample PDF bytes containing simulated threats.
fn make_sample_pdf_with_threats() -> Bytes {
    Bytes::from_static(
        b"%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
   /Resources << /JavaScript << /JS (app.alert('XSS')) >> >>
   /Annots [<</A <</S /URI /URI (http://evil.com/)>>> /Subtype /Link>>]
   /EmbeddedFiles << /Names [(E) <</EF <</F (malware.exe) /UF (malware.exe)>>>]>>
>>
endobj

xref
...
trailer
<</Size 4 /Root 1 0 R>>
startxref
%%EOF",
    )
}

/// Create sample OOXML (.docx) bytes with macro indicators.
fn make_sample_docx_with_macros() -> Bytes {
    Bytes::from_static(
        b"PK\x03\x04
[Content_Types].xml
word/document.xml
<vbaProject.bin>
<a:hlinkClick r:id=\"rId1\" xmlns:a=\"...\"/>
<o:OLEObject ProgID=\"Excel.Sheet.1\"/>
macros here
",
    )
}

/// Create sample ZIP bytes with nested archive indicator.
fn make_sample_zip_nested() -> Bytes {
    Bytes::from_static(
        b"PK\x03\x04
entry1.txt
nested.zip
PK\x03\x04
deep_entry.exe
",
    )
}

/// Create unknown/binary format bytes for fallback testing.
fn make_unknown_binary() -> Bytes {
    Bytes::from_static(b"\x89\xAB\xCD\xEF\x01\x02\x03\x04\xFF\xFE\xFD\xFC random binary payload")
}

/// Create a fully configured registry with all mock parsers registered.
fn make_full_parser_registry() -> ParserRegistry {
    let registry = ParserRegistry::new();
    registry.register(Arc::new(MockPdfCdrParser));
    registry.register(Arc::new(MockOoxmlCdrParser));
    registry.register(Arc::new(MockZipCdrParser));
    registry
}

// ===========================================================================
// Test Group 1: PDF Sanitization End-to-End
// ===========================================================================

#[tokio::test]
async fn test_pdf_sanitization_end_to_end() {
    let registry = make_full_parser_registry();
    let policy = SanitizePolicy::default(); // Maximum security defaults

    let pdf_input = make_sample_pdf_with_threats();
    let result = registry.parse(pdf_input, &policy).await.expect("PDF parsing should succeed");

    // Verify parser identification
    assert_eq!(result.parser_name, "MockPdfCdrParser");
    assert!(result.original_size > 0);

    // Verify sanitization actions were taken
    assert!(
        result.has_actions(),
        "PDF with threats should have sanitization actions"
    );

    // Verify JavaScript was removed (default policy has remove_javascript=true)
    assert!(
        result.actions_taken.contains(&SanitizeAction::JavaScriptRemoved),
        "should detect and remove JavaScript from PDF"
    );

    // Verify metadata stripping
    assert!(
        result.actions_taken.contains(&SanitizeAction::MetadataStripped),
        "should strip PDF metadata under default policy"
    );

    // Verify external link removal
    assert!(
        result.actions_taken.contains(&SanitizeAction::ExternalLinkRemoved),
        "should remove external links from PDF"
    );

    // Verify embedded file removal
    assert!(
        result.actions_taken.contains(&SanitizeAction::EmbeddedFileRemoved),
        "should remove embedded files from PDF"
    );
}

#[tokio::test]
async fn test_pdf_sanitization_clean_document_no_actions() {
    let registry = make_full_parser_registry();
    let policy = SanitizePolicy::default();

    // Clean PDF without any threat indicators
    let clean_pdf = Bytes::from_static(
        b"%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj
...",
    );

    let result = registry.parse(clean_pdf, &policy).await.expect("clean PDF should succeed");
    assert_eq!(result.parser_name, "MockPdfCdrParser");

    // Clean PDF should still have metadata stripped (policy default)
    assert!(
        result.actions_taken.contains(&SanitizeAction::MetadataStripped),
        "metadata is always stripped by default policy"
    );

    // But should NOT have JS/macro/embedded removals
    assert!(
        !result.actions_taken.contains(&SanitizeAction::JavaScriptRemoved),
        "clean PDF should not trigger JS removal"
    );
}

// ===========================================================================
// Test Group 2: OOXML Document Processing
// ===========================================================================

#[tokio::test]
async fn test_ooxml_docx_processing_sanitizes_macros() {
    let registry = make_full_parser_registry();
    let policy = SanitizePolicy::default();

    let docx_input = make_sample_docx_with_macros();
    let result = registry.parse(docx_input, &policy).await.expect("OOXML parsing should succeed");

    assert_eq!(result.parser_name, "MockOoxmlCdrParser");
    assert!(result.has_actions());

    // Macro removal
    assert!(
        result.actions_taken.contains(&SanitizeAction::MacroStripped),
        "should strip VBA macros from OOXML document"
    );

    // OLE object removal
    assert!(
        result.actions_taken.contains(&SanitizeAction::EmbeddedFileRemoved),
        "should remove OLE objects from OOXML document"
    );

    // External link removal
    assert!(
        result.actions_taken.contains(&SanitizeAction::ExternalLinkRemoved),
        "should remove hyperlinks from OOXML document"
    );

    // Warnings about font substitution
    assert!(result.has_warnings(), "OOXML may generate warnings");
}

#[tokio::test]
async fn test_ooxlsx_pptx_routing_by_magic_bytes() {
    let registry = make_full_parser_registry();
    let policy = SanitizePolicy::default();

    // All OOXML formats start with PK\x03\x04 (ZIP magic), but we use filename hint
    let xlsx_input = Bytes::from_static(b"PK\x03\x04\nxlsx-content-with-macros vbaProject");
    let pptx_input = Bytes::from_static(b"PK\x03\x04\npptx-content-with-scripts");

    // Route .xlsx via filename
    let xlsx_result = registry
        .parse_with_filename(xlsx_input, &policy, "report.xlsx")
        .await
        .expect("xlsx parsing should succeed");
    assert_eq!(xlsx_result.parser_name, "MockOoxmlCdrParser");

    // Route .pptx via filename
    let pptx_result = registry
        .parse_with_filename(pptx_input, &policy, "presentation.pptx")
        .await
        .expect("pptx parsing should succeed");
    assert_eq!(pptx_result.parser_name, "MockOoxmlCdrParser");
}

// ===========================================================================
// Test Group 3: ZIP Archive Traversal
// ===========================================================================

#[tokio::test]
async fn test_zip_archive_traversal_nested_content() {
    let registry = make_full_parser_registry();
    let policy = SanitizePolicy::default();

    let zip_input = make_sample_zip_nested();
    let result = registry.parse(zip_input, &policy).await.expect("ZIP parsing should succeed");

    assert_eq!(result.parser_name, "MockZipCdrParser");
    assert!(result.has_actions());

    // Should detect nested content
    assert!(
        result.actions_taken.iter().any(|a| matches!(a, SanitizeAction::BinarySanitized(_))),
        "ZIP parser should report binary sanitization action"
    );

    // Should warn about nested archives
    assert!(result.has_warnings(), "nested ZIP should generate warnings");
}

#[tokio::test]
async fn test_zip_archive_by_extension_fallback() {
    let registry = make_full_parser_registry();
    let policy = SanitizePolicy::default();

    // Use extension to route to ZIP parser even without full magic match
    let zip_like = Bytes::from_static(b"some-archive-data");
    let result = registry
        .parse_with_filename(zip_like, &policy, "archive.zip")
        .await
        .expect("ZIP by extension should work");

    assert_eq!(result.parser_name, "MockZipCdrParser");
}

// ===========================================================================
// Test Group 4: Unknown Format Fallback
// ===========================================================================

#[tokio::test]
async fn test_unknown_format_fallback_binary_safe() {
    let registry = ParserRegistry::new(); // No parsers registered — pure fallback
    let policy = SanitizePolicy::default();

    let unknown = make_unknown_binary();
    let result = registry.parse(unknown, &policy).await.expect("fallback should always succeed");

    // Fallback parser should handle it
    assert_eq!(result.parser_name, "BinarySafeFallbackParser");
    assert!(!result.has_actions() || matches!(&result.actions_taken[0], SanitizeAction::BinarySanitized(_)));

    // Data should be preserved unchanged
    assert_eq!(result.sanitized_size, result.original_size);
}

#[tokio::test]
async fn test_unknown_format_with_registered_parsers_still_falls_back() {
    let registry = make_full_parser_registry(); // Has PDF/OOXML/ZIP parsers
    let policy = SanitizePolicy::default();

    let truly_unknown = Bytes::from_static(b"\xCA\xFE\xBA\xBE completely unknown format");
    let result = registry.parse(truly_unknown, &policy).await.expect("should fall back gracefully");

    // No parser matched → fallback
    assert_eq!(result.parser_name, "BinarySafeFallbackParser");
    assert!(
        matches!(&result.actions_taken[0], SanitizeAction::BinarySanitized(_)),
        "fallback should use BinarySanitized action"
    );
}

// ===========================================================================
// Test Group 5: Parser Routing by Magic Bytes
// ===========================================================================

#[tokio::test]
async fn test_parser_routing_pdf_magic_bytes() {
    let registry = make_full_parser_registry();

    // Find parser for PDF magic bytes
    let parser = registry.find_parser(b"%PDF-1.4", Some("document.pdf"));
    assert!(parser.is_some(), "should find PDF parser for PDF magic bytes");
    assert_eq!(parser.unwrap().parser_name(), "MockPdfCdrParser");
}

#[tokio::test]
async fn test_parser_routing_zip_magic_bytes() {
    let registry = make_full_parser_registry();

    // Find parser for ZIP magic bytes
    let parser = registry.find_parser(b"PK\x03\x04", Some("archive.zip"));
    assert!(parser.is_some(), "should find ZIP parser for ZIP magic bytes");
    assert_eq!(parser.unwrap().parser_name(), "MockZipCdrParser");
}

#[tokio::test]
async fn test_parser_routing_ooxml_by_extension() {
    let registry = make_full_parser_registry();

    // OOXML has same magic as ZIP but different extension
    let parser = registry.find_parser(b"PK\x03\x04", Some("document.docx"));
    assert!(parser.is_some(), "should find OOXML parser for .docx extension");
    assert_eq!(parser.unwrap().parser_name(), "MockOoxmlCdrParser");
}

#[tokio::test]
async fn test_parser_routing_priority_first_match_wins() {
    let registry = ParserRegistry::new();

    // Register two parsers both claiming ZIP — first one wins
    registry.register_at(0, Arc::new(MockZipCdrParser)); // Priority 0
    registry.register(Arc::new(MockOoxmlCdrParser));      // Lower priority

    let parser = registry.find_parser(b"PK\x03\x04", Some("file.zip")).unwrap();
    assert_eq!(parser.parser_name(), "MockZipCdrParser", "first matching parser should win");
}

// ===========================================================================
// Test Group 6: Policy Enforcement
// ===========================================================================

#[tokio::test]
async fn test_policy_strict_rejects_dangerous_content() {
    let registry = make_full_parser_registry();

    // Strict (default) policy: everything removed
    let strict_policy = SanitizePolicy::default();
    let pdf_result = registry.parse(make_sample_pdf_with_threats(), &strict_policy).await.unwrap();

    assert!(
        pdf_result.actions_taken.contains(&SanitizeAction::JavaScriptRemoved),
        "strict policy must remove JavaScript"
    );
    assert!(
        pdf_result.actions_taken.contains(&SanitizeAction::MetadataStripped),
        "strict policy must strip metadata"
    );
    assert!(
        pdf_result.actions_taken.contains(&SanitizeAction::ExternalLinkRemoved),
        "strict policy must remove external links"
    );
    assert!(
        pdf_result.actions_taken.contains(&SanitizeAction::EmbeddedFileRemoved),
        "strict policy must remove embedded files"
    );
}

#[tokio::test]
async fn test_policy_lenient_allows_more_content() {
    let registry = make_full_parser_registry();

    // Lenient policy: allow most things, only remove critical threats
    let lenient_policy = SanitizePolicy {
        remove_javascript: false,
        remove_macros: true,       // Still remove macros (critical)
        remove_embedded_files: false,
        remove_external_links: false,
        remove_metadata: false,
        strip_comments: false,
        ..Default::default()
    };

    let pdf_result = registry.parse(make_sample_pdf_with_threats(), &lenient_policy).await.unwrap();

    // JavaScript NOT removed (lenient)
    assert!(
        !pdf_result.actions_taken.contains(&SanitizeAction::JavaScriptRemoved),
        "lenient policy should preserve JavaScript"
    );

    // Metadata NOT stripped
    assert!(
        !pdf_result.actions_taken.contains(&SanitizeAction::MetadataStripped),
        "lenient policy should preserve metadata"
    );

    // For OOXML with macros — only macros should be removed
    let docx_result = registry.parse(make_sample_docx_with_macros(), &lenient_policy).await.unwrap();
    assert!(
        docx_result.actions_taken.contains(&SanitizeAction::MacroStripped),
        "even lenient policy should still remove macros"
    );
    assert!(
        !docx_result.actions_taken.contains(&SanitizeAction::EmbeddedFileRemoved),
        "lenient policy allows embedded files"
    );
}

// ===========================================================================
// Test Group 7: Large File Handling
// ===========================================================================

#[tokio::test]
async fn test_large_file_size_limit_enforcement() {
    let registry = make_full_parser_registry();

    // Set very small size limit (100 bytes)
    let strict_size_policy = SanitizePolicy {
        max_file_size_bytes: Some(100),
        ..Default::default()
    };

    // Create input exceeding 100 bytes
    let large_input = Bytes::from(vec![0xABu8; 200]);
    let result = registry.parse(large_input, &strict_size_policy).await;

    assert!(result.is_err(), "oversized input should be rejected");
    match result.unwrap_err() {
        ParseError::FileTooLarge(size) => {
            assert_eq!(size, 200, "should report actual file size");
        }
        other => panic!("expected FileTooLarge error, got: {}", other),
    }
}

#[tokio::test]
async fn test_large_file_within_limit_accepted() {
    let registry = make_full_parser_registry();

    // Generous size limit (10 MB)
    let generous_policy = SanitizePolicy {
        max_file_size_bytes: Some(10 * 1024 * 1024),
        ..Default::default()
    };

    // Create a moderately large input (50 KB)
    let medium_input = Bytes::from(vec![0x42u8; 50 * 1024]);
    let result = registry.parse(medium_input, &generous_policy).await;

    assert!(result.is_ok(), "input within limit should be accepted");
    let output = result.unwrap();
    assert_eq!(output.original_size, 50 * 1024);
}

// ===========================================================================
// Test Group 8: Error Recovery
// ===========================================================================

#[tokio::test]
async fn test_error_recovery_corrupt_input_graceful_failure() {
    let registry = make_full_parser_registry();
    let policy = SanitizePolicy::default();

    // Corrupt/truncated PDF header
    let corrupt_pdf = Bytes::from_static(b"%PD"); // Truncated PDF magic
    let result = registry.parse(corrupt_pdf, &policy).await;

    // Should not panic — either falls back or returns error
    // Since %PD doesn't match any parser's magic bytes, it goes to fallback
    assert!(result.is_ok(), "unrecognized format should use fallback, not panic");
    assert_eq!(result.unwrap().parser_name, "BinarySafeFallbackParser");
}

#[tokio::test]
async fn test_error_recovery_empty_input_no_panic() {
    let registry = make_full_parser_registry();
    let policy = SanitizePolicy::default();

    let empty = Bytes::new();
    let result = registry.parse(empty, &policy).await;

    assert!(result.is_ok(), "empty input should not cause panic");
    let output = result.unwrap();
    assert_eq!(output.original_size, 0);
    assert_eq!(output.sanitized_size, 0);
}

#[tokio::test]
async fn test_parse_error_display_human_readable() {
    let errors: Vec<(ParseError, &str)> = vec![
        (ParseError::UnsupportedFormat, "unsupported"),
        (ParseError::FileTooLarge(99999), "too large"),
        (ParseError::CorruptData("bad data".to_string()), "corrupt"),
        (ParseError::PolicyViolation("blocked".to_string()), "violation"),
        (
            ParseError::WasmRuntimeError("trap".to_string()),
            "WASM runtime",
        ),
        (
            ParseError::InternalError("bug".to_string()),
            "internal",
        ),
    ];

    for (error, expected_substr) in errors {
        let display = format!("{}", error);
        assert!(
            display.contains(expected_substr),
            "ParseError display '{}' should contain '{}'",
            display,
            expected_substr
        );
    }
}

// ===========================================================================
// Test Group 9: WASM Plugin in Registry
// ===========================================================================

#[tokio::test]
async fn test_wasm_plugin_in_registry_route_and_execute() {
    let registry = ParserRegistry::new();

    // Register mock WASM parser
    let wasm_parser = Arc::new(MockWasmParserAdapter::new("CustomWasmParser-v1"));
    registry.register(wasm_parser);

    assert_eq!(registry.parser_count(), 1);
    assert!(registry.has_parser("CustomWasmParser-v1"));

    let policy = SanitizePolicy::default();

    // Route by custom extension
    let custom_input = Bytes::from_static(b"custom format data for WASM processing");
    let result = registry
        .parse_with_filename(custom_input, &policy, "data.custom")
        .await
        .expect("WASM parser should handle custom format");

    assert_eq!(result.parser_name, "CustomWasmParser-v1");
    assert!(result.has_actions());
    assert!(
        result.actions_taken.iter().any(|a| matches!(a, SanitizeAction::CustomAction(_))),
        "WASM parser should report CustomAction"
    );
    assert!(result.has_warnings(), "WASM parser should produce warnings");
}

#[tokio::test]
async fn test_wasm_plugin_coexists_with_standard_parsers() {
    let registry = make_full_parser_registry();

    // Add WASM parser alongside standard ones
    registry.register(Arc::new(MockWasmParserAdapter::new("WasmEnhancement")));

    assert_eq!(registry.parser_count(), 4); // PDF + OOXML + ZIP + WASM

    // Standard formats still route correctly
    let pdf_parser = registry.find_parser(b"%PDF-1.4", None);
    assert!(pdf_parser.is_some());
    assert_eq!(pdf_parser.unwrap().parser_name(), "MockPdfCdrParser");

    // Custom format routes to WASM
    let wasm_parser = registry.find_parser(b"\x00\x00\x00\x00", Some("file.custom"));
    assert!(wasm_parser.is_some());
    assert_eq!(wasm_parser.unwrap().parser_name(), "WasmEnhancement");
}

// ===========================================================================
// Test Group 10: Concurrent Parsing
// ===========================================================================

#[tokio::test]
async fn test_concurrent_parsing_50_simultaneous_operations() {
    let registry = Arc::new(make_full_parser_registry());
    let policy = SanitizePolicy::default();

    let mut handles = tokio::task::JoinSet::new();

    // Spawn 50 concurrent parse operations mixing different formats
    for i in 0..50usize {
        let reg = Arc::clone(&registry);
        let pol = policy.clone();

        handles.spawn(async move {
            match i % 5 {
                0 => reg.parse(make_sample_pdf_with_threats(), &pol).await,
                1 => reg.parse(make_sample_docx_with_macros(), &pol).await,
                2 => reg.parse(make_sample_zip_nested(), &pol).await,
                3 => reg.parse(make_unknown_binary(), &pol).await,
                _ => reg.parse(Bytes::from(format!("data-{}", i)), &pol).await,
            }
        });
    }

    let mut success_count = 0;
    let mut failure_count = 0;

    while let Some(result) = handles.join_next().await {
        match result {
            Ok(parse_result) => match parse_result {
                Ok(output) => {
                    success_count += 1;
                    assert!(!output.parser_name.is_empty(), "output should have parser name");
                }
                Err(_) => {
                    failure_count += 1;
                }
            }
            Err(join_err) => {
                panic!("task panicked: {}", join_err);
            }
        }
    }

    // Most should succeed (only truly unknown might go to fallback which succeeds too)
    assert_eq!(success_count + failure_count, 50, "all 50 tasks should complete");
    assert!(
        success_count >= 45,
        "at least 45 of 50 parses should succeed (got {})",
        success_count
    );
}

#[tokio::test]
async fn test_concurrent_register_and_parse_thread_safety() {
    let registry = Arc::new(ParserRegistry::new());
    let policy = SanitizePolicy::default();
    let mut handles = tokio::task::JoinSet::new();

    // Concurrently register parsers and parse
    for i in 0..20usize {
        let reg = Arc::clone(&registry);
        let pol = policy.clone();

        if i % 2 == 0 {
            // Registration task
            handles.spawn(async move {
                let parser = Arc::new(MockWasmParserAdapter::new(&format!("ConcurrentP-{}", i)));
                reg.register(parser);
            });
        } else {
            // Parsing task
            handles.spawn(async move {
                let _ = reg.parse(Bytes::from(format!("concurrent-data-{}", i)), &pol).await;
            });
        }
    }

    while let Some(result) = handles.join_next().await {
        assert!(result.is_ok(), "concurrent operation should not panic");
    }

    // Registry should be in consistent state
    let count = registry.parser_count();
    assert!(count <= 10, "should have at most 10 registered parsers (got {count})");
}

// ===========================================================================
// Test Group 11: Registry Introspection and Management
// ===========================================================================

#[tokio::test]
async fn test_registry_introspection_list_parsers() {
    let registry = make_full_parser_registry();

    let infos = registry.list_parsers();
    assert_eq!(infos.len(), 3);

    let names: Vec<&str> = infos.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"MockPdfCdrParser"));
    assert!(names.contains(&"MockOoxmlCdrParser"));
    assert!(names.contains(&"MockZipCdrParser"));

    // Verify each parser reports its supported types
    for info in &infos {
        assert!(!info.supported_types.is_empty(), "{} should report supported types", info.name);
    }
}

#[tokio::test]
async fn test_registry_unregister_and_reroute() {
    let registry = make_full_parser_registry();
    assert_eq!(registry.parser_count(), 3);

    // Unregister PDF parser
    let removed = registry.unregister("MockPdfCdrParser");
    assert!(removed, "should successfully unregister PDF parser");
    assert_eq!(registry.parser_count(), 2);
    assert!(!registry.has_parser("MockPdfCdrParser"));

    // PDF input now falls back (no PDF parser available)
    let policy = SanitizePolicy::default();
    let pdf_result = registry.parse(make_sample_pdf_with_threats(), &policy).await.unwrap();
    assert_eq!(pdf_result.parser_name, "BinarySafeFallbackParser");

    // Re-register PDF parser
    registry.register(Arc::new(MockPdfCdrParser));
    assert_eq!(registry.parser_count(), 3);
    assert!(registry.has_parser("MockPdfCdrParser"));

    // PDF routing restored
    let pdf_restored = registry.parse(make_sample_pdf_with_threats(), &policy).await.unwrap();
    assert_eq!(pdf_restored.parser_name, "MockPdfCdrParser");
}

#[tokio::test]
async fn test_registry_clear_resets_to_fallback_only() {
    let registry = make_full_parser_registry();
    assert!(registry.parser_count() > 0);

    registry.clear();
    assert_eq!(registry.parser_count(), 0);

    // All inputs now go to fallback
    let policy = SanitizePolicy::default();
    let result = registry.parse(make_sample_pdf_with_threats(), &policy).await.unwrap();
    assert_eq!(result.parser_name, "BinarySafeFallbackParser");
}

// ===========================================================================
// Test Group 12: Magic Byte Detection Utilities
// ===========================================================================

#[test]
fn test_detect_format_pdf_high_confidence() {
    let detected = detect_format_from_bytes(b"%PDF-1.7").expect("PDF should be detected");
    assert_eq!(detected.mime_type, "application/pdf");
    assert_eq!(detected.format_name, "PDF");
    assert!((detected.confidence - 1.0).abs() < f32::EPSILON);
}

#[test]
fn test_detect_format_zip_medium_confidence() {
    let detected = detect_format_from_bytes(b"PK\x03\x04").expect("ZIP should be detected");
    assert_eq!(detected.mime_type, "application/zip");
    assert_eq!(detected.format_name, "ZIP");
    assert!(detected.confidence < 1.0 && detected.confidence > 0.5);
}

#[test]
fn test_detect_format_short_input_returns_none() {
    assert!(detect_format_from_bytes(b"%P").is_none());
    assert!(detect_format_from_bytes(b"").is_none());
    assert!(detect_format_from_bytes(b"PK").is_none());
}

#[test]
fn test_extract_extension_various_filenames() {
    assert_eq!(extract_extension("document.pdf"), Some("pdf".to_string()));
    assert_eq!(extract_extension("archive.TAR.GZ"), Some("gz".to_string()));
    assert_eq!(extract_extension("/path/to/file.DOCX"), Some("docx".to_string()));
    assert_eq!(extract_extension(r"C:\Users\test\DATA.XLSX"), Some("xlsx".to_string()));
    assert_eq!(extract_extension("noextension"), None);
    assert_eq!(extract_extension(".hidden"), None);
    assert_eq!(extract_extension(""), None);
}

// ===========================================================================
// Test Group 13: SanitizedOutput Verification
// ===========================================================================

#[test]
fn test_sanitized_output_reduction_ratio_calculation() {
    // Normal case: output smaller than input
    let output = SanitizedOutput {
        clean_data: Bytes::from_static(b"small"),
        original_size: 1000,
        sanitized_size: 5,
        actions_taken: vec![SanitizeAction::JavaScriptRemoved],
        warnings: vec![],
        parser_name: "TestParser".to_string(),
    };

    let ratio = output.reduction_ratio().expect("should have ratio");
    assert!(ratio < 1.0, "reduction ratio should be < 1.0: {}", ratio);
    assert!(ratio > 0.0, "reduction ratio should be positive: {}", ratio);

    // Expanded case: output larger than input
    let expanded = SanitizedOutput {
        clean_data: Bytes::from_static(b"this is much larger content than before"),
        original_size: 10,
        sanitized_size: 44,
        actions_taken: vec![],
        warnings: vec![],
        parser_name: "Expander".to_string(),
    };

    let expanded_ratio = expanded.reduction_ratio().unwrap();
    assert!(expanded_ratio > 1.0, "expanded output ratio > 1.0: {}", expanded_ratio);

    // Zero-size edge case
    let empty = SanitizedOutput {
        clean_data: Bytes::new(),
        original_size: 0,
        sanitized_size: 0,
        actions_taken: vec![],
        warnings: vec![],
        parser_name: "Empty".to_string(),
    };

    assert!(empty.reduction_ratio().is_none(), "zero-size should return None");
}

#[test]
fn test_sanitize_action_display_formats() {
    let actions = vec![
        (SanitizeAction::JavaScriptRemoved, "JavaScriptRemoved"),
        (SanitizeAction::MacroStripped, "MacroStripped"),
        (SanitizeAction::EmbeddedFileRemoved, "EmbeddedFileRemoved"),
        (SanitizeAction::ExternalLinkRemoved, "ExternalLinkRemoved"),
        (SanitizeAction::MetadataStripped, "MetadataStripped"),
        (SanitizeAction::CommentRemoved, "CommentRemoved"),
        (
            SanitizeAction::BinarySanitized("PDF stream rebuilt".to_string()),
            "BinarySanitized(PDF stream rebuilt)",
        ),
        (
            SanitizeAction::CustomAction("WASM cleanup".to_string()),
            "CustomAction(WASM cleanup)",
        ),
    ];

    for (action, expected) in actions {
        assert_eq!(format!("{}", action), expected);
    }
}

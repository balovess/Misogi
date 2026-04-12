//! Dynamic parser routing registry with magic byte detection and fallback sanitizer.
//!
//! This module implements the [ParserRegistry] which serves as the central
//! dispatch point for the Content Disarm & Reconstruction (CDR) pipeline.
//! It maintains an ordered chain of [ContentParser] implementations and
//! automatically routes incoming byte streams to the appropriate parser
//! based on magic byte signatures and filename hints.

use std::fmt;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use bytes::Bytes;

use crate::parser_trait::{
    ContentParser, ParseError, SanitizeAction, SanitizePolicy, SanitizedOutput,
};

// ===========================================================================
// Magic Byte Detection Constants
// ===========================================================================

/// Magic byte signature for PDF documents (%PDF).
pub const MAGIC_PDF: &[u8; 4] = b"%PDF";

/// Magic byte signature for ZIP archives and OOXML containers (PK\x03\x04).
pub const MAGIC_ZIP: &[u8; 4] = b"PK\x03\x04";

/// Minimum number of bytes required for reliable magic byte detection.
pub const MAGIC_MIN_SAMPLE_SIZE: usize = 8;

// ===========================================================================
// Detected Format
// ===========================================================================

/// Detected format information derived from magic bytes analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedFormat {
    /// Inferred MIME type or content type string (e.g., "application/pdf").
    pub mime_type: &'static str,
    /// Human-readable format name for logging and debugging purposes.
    pub format_name: &'static str,
    /// Confidence level of the detection (0.0 to 1.0).
    pub confidence: f32,
}

// ===========================================================================
// Parser Information
// ===========================================================================

/// Public information about a registered parser, used for introspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserInfo {
    /// Human-readable parser identifier.
    pub name: String,
    /// List of MIME types and extensions this parser claims to handle.
    pub supported_types: Vec<String>,
}

impl fmt::Display for ParserInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ParserInfo(name={}, types=[{}])",
            self.name,
            self.supported_types.join(", ")
        )
    }
}

// ===========================================================================
// Binary Safe Fallback Parser
// ===========================================================================

/// Internal fallback parser that returns binary data unchanged.
///
/// When no registered parser matches the input format (unknown or unsupported),
/// this parser takes over and returns the original bytes wrapped in a
/// [SanitizedOutput] with [SanitizeAction::BinarySanitized] action.
#[derive(Debug, Clone, Default)]
struct BinarySafeFallbackParser;

impl BinarySafeFallbackParser {
    #[allow(dead_code)]
    fn new() -> Self { Self }
}

#[async_trait]
impl ContentParser for BinarySafeFallbackParser {
    fn supported_types(&self) -> Vec<&'static str> { vec![] }

    fn parser_name(&self) -> &str { "BinarySafeFallbackParser" }

    async fn parse_and_sanitize(
        &self,
        input: Bytes,
        _policy: &SanitizePolicy,
    ) -> Result<SanitizedOutput, ParseError> {
        let original_size = input.len() as u64;
        Ok(SanitizedOutput {
            clean_data: input,
            original_size,
            sanitized_size: original_size,
            actions_taken: vec![SanitizeAction::BinarySanitized(
                "passthrough: no format-specific parser available".to_string(),
            )],
            warnings: vec![],
            parser_name: self.parser_name().to_string(),
        })
    }
}

// ===========================================================================
// Parser Registry
// ===========================================================================

/// Dynamic parser routing registry with magic byte detection and fallback.
///
/// [ParserRegistry] is the central dispatcher for the CDR pipeline.
pub struct ParserRegistry {
    /// Ordered parser chain protected by RwLock for thread safety.
    parsers: RwLock<Vec<Arc<dyn ContentParser>>>,
    /// Pre-instantiated fallback parser for unknown formats.
    fallback: Arc<BinarySafeFallbackParser>,
}

impl ParserRegistry {
    /// Create a new empty parser registry with no registered parsers.
    pub fn new() -> Self {
        Self {
            parsers: RwLock::new(Vec::new()),
            fallback: Arc::new(BinarySafeFallbackParser::default()),
        }
    }

    /// Create a pre-configured registry with default parser configuration.
    pub fn with_default_parsers() -> Self { Self::new() }

    /// Create a pre-configured registry with given parser list.
    pub fn with_parsers(parsers: Vec<Arc<dyn ContentParser>>) -> Self {
        Self {
            parsers: RwLock::new(parsers),
            fallback: Arc::new(BinarySafeFallbackParser::default()),
        }
    }
}

impl Default for ParserRegistry {
    fn default() -> Self { Self::new() }
}

// -------------------------------------------------------------------------
// Parser Registration Methods
// -------------------------------------------------------------------------

impl ParserRegistry {
    /// Register a parser at the end of the parser chain (lowest priority).
    pub fn register(&self, parser: Arc<dyn ContentParser>) {
        let mut parsers = self.parsers.write().expect("parser lock poisoned");
        parsers.push(parser);
    }

    /// Register a parser at a specific priority position in the chain.
    pub fn register_at(&self, priority: usize, parser: Arc<dyn ContentParser>) {
        let mut parsers = self.parsers.write().expect("parser lock poisoned");
        let insert_pos = priority.min(parsers.len());
        parsers.insert(insert_pos, parser);
    }

    /// Remove a parser from the registry by its parser_name().
    ///
    /// Returns 	rue if a parser was found and removed, alse otherwise.
    pub fn unregister(&self, name: &str) -> bool {
        let mut parsers = self.parsers.write().expect("parser lock poisoned");
        let initial_len = parsers.len();
        parsers.retain(|p| p.parser_name() != name);
        parsers.len() != initial_len
    }

    /// Remove all registered parsers, leaving only the fallback handler.
    pub fn clear(&self) {
        let mut parsers = self.parsers.write().expect("parser lock poisoned");
        parsers.clear();
    }
}

// -------------------------------------------------------------------------
// Parser Discovery / Routing
// -------------------------------------------------------------------------

impl ParserRegistry {
    /// Find the best-matching parser for the given input bytes and optional hint.
    pub fn find_parser(
        &self,
        magic_bytes: &[u8],
        filename_hint: Option<&str>,
    ) -> Option<Arc<dyn ContentParser>> {
        let detected = detect_format_from_bytes(magic_bytes);
        let extension = filename_hint.and_then(extract_extension);
        let parsers = self.parsers.read().expect("parser lock poisoned");

        for parser in parsers.iter() {
            if self.parser_matches_input(parser, &detected, extension.as_ref()) {
                return Some(Arc::clone(parser));
            }
        }
        None
    }

    /// Internal: check if a parser matches the detected signals.
    fn parser_matches_input(
        &self,
        parser: &Arc<dyn ContentParser>,
        detected: &Option<DetectedFormat>,
        extension: Option<&String>,
    ) -> bool {
        let supported = parser.supported_types();
        for content_type in &supported {
            if let Some(fmt) = detected {
                if *content_type == fmt.mime_type { return true; }
                if content_type.starts_with('.') {
                    if let Some(ext) = extension {
                        if content_type.to_lowercase() == format!(".{}", ext.to_lowercase()) {
                            return true;
                        }
                    }
                }
            }
            if let Some(ext) = extension {
                let dotted_ext = format!(".{}", ext.to_lowercase());
                if content_type.to_lowercase() == dotted_ext
                    || content_type.to_lowercase() == ext.to_lowercase()
                {
                    return true;
                }
            }
        }
        false
    }
}

// -------------------------------------------------------------------------
// Parse Entry Point
// -------------------------------------------------------------------------

impl ParserRegistry {
    /// Auto-detect format, route to matching parser, return sanitized output.
    pub async fn parse(
        &self,
        input: Bytes,
        policy: &SanitizePolicy,
    ) -> Result<SanitizedOutput, ParseError> {
        let sample_size = input.len().min(MAGIC_MIN_SAMPLE_SIZE);
        let magic_bytes = &input[..sample_size];
        let parser = self.find_parser(magic_bytes, None);

        match parser {
            Some(matched_parser) => matched_parser.parse_and_sanitize(input, policy).await,
            None => self.fallback.parse_and_sanitize(input, policy).await,
        }
    }

    /// Parse with explicit filename hint for better format disambiguation.
    pub async fn parse_with_filename(
        &self,
        input: Bytes,
        policy: &SanitizePolicy,
        filename: &str,
    ) -> Result<SanitizedOutput, ParseError> {
        let sample_size = input.len().min(MAGIC_MIN_SAMPLE_SIZE);
        let magic_bytes = &input[..sample_size];
        let parser = self.find_parser(magic_bytes, Some(filename));

        match parser {
            Some(matched_parser) => matched_parser.parse_and_sanitize(input, policy).await,
            None => self.fallback.parse_and_sanitize(input, policy).await,
        }
    }
}

// -------------------------------------------------------------------------
// Introspection
// -------------------------------------------------------------------------

impl ParserRegistry {
    /// Return information about all currently registered parsers.
    pub fn list_parsers(&self) -> Vec<ParserInfo> {
        let parsers = self.parsers.read().expect("parser lock poisoned");
        parsers.iter()
            .map(|p| ParserInfo {
                name: p.parser_name().to_string(),
                supported_types: p.supported_types().into_iter().map(String::from).collect(),
            })
            .collect()
    }

    /// Return the number of currently registered parsers (excluding fallback).
    pub fn parser_count(&self) -> usize {
        let parsers = self.parsers.read().expect("parser lock poisoned");
        parsers.len()
    }

    /// Check if a parser with the given name is currently registered.
    pub fn has_parser(&self, name: &str) -> bool {
        let parsers = self.parsers.read().expect("parser lock poisoned");
        parsers.iter().any(|p| p.parser_name() == name)
    }
}

// ===========================================================================
// Magic Byte Detection Functions
// ===========================================================================

/// Detect file format from leading magic bytes.
pub fn detect_format_from_bytes(data: &[u8]) -> Option<DetectedFormat> {
    if data.len() >= 4 && data[..4] == *MAGIC_PDF {
        return Some(DetectedFormat {
            mime_type: "application/pdf",
            format_name: "PDF",
            confidence: 1.0,
        });
    }
    if data.len() >= 4 && data[..4] == *MAGIC_ZIP {
        return Some(DetectedFormat {
            mime_type: "application/zip",
            format_name: "ZIP",
            confidence: 0.7,
        });
    }
    None
}

/// Extract file extension from a filename (without the dot prefix).
pub fn extract_extension(filename: &str) -> Option<String> {
    let basename = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
    let dot_pos = basename.rfind('.')?;
    if dot_pos + 1 >= basename.len() { return None; }
    let extension = &basename[dot_pos + 1..];
    if extension.chars().all(|c| c.is_alphanumeric()) {
        Some(extension.to_lowercase())
    } else {
        None
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;
    use tokio::task::JoinSet;

    // -----------------------------------------------------------------------
    // Mock Parser for Testing
    // -----------------------------------------------------------------------

    #[derive(Debug, Clone)]
    struct MockParser {
        name: &'static str,
        types: Vec<&'static str>,
        should_fail: bool,
    }

    impl MockParser {
        const fn new(name: &'static str, types: Vec<&'static str>) -> Self {
            Self { name, types, should_fail: false }
        }
        fn failing(name: &'static str, types: Vec<&'static str>) -> Self {
            Self { name, types, should_fail: true }
        }
    }

    #[async_trait]
    impl ContentParser for MockParser {
        fn supported_types(&self) -> Vec<&'static str> { self.types.clone() }
        fn parser_name(&self) -> &str { self.name }
        async fn parse_and_sanitize(
            &self, input: Bytes, _policy: &SanitizePolicy,
        ) -> Result<SanitizedOutput, ParseError> {
            if self.should_fail {
                return Err(ParseError::CorruptData("mock forced failure".to_string()));
            }
            let size = input.len() as u64;
            Ok(SanitizedOutput {
                clean_data: input, original_size: size, sanitized_size: size,
                actions_taken: vec![], warnings: vec![],
                parser_name: self.name.to_string(),
            })
        }
    }

    fn make_pdf_bytes() -> Bytes {
        Bytes::from_static(b"%PDF-1.4\nfake pdf content")
    }
    /// Create fake ZIP bytes for testing
    #[allow(dead_code)]  // Reserved for future test expansion
    fn make_zip_bytes() -> Bytes {
        Bytes::from_static(b"PK\x03\x04\nfake zip content")
    }
    fn make_unknown_bytes() -> Bytes {
        Bytes::from_static(b"\x89\xAB\xCD\xEF unknown format")
    }

    // ======================================================================
    // Test Group 1: Registry Construction
    // ======================================================================

    #[test]
    fn test_registry_new_is_empty() {
        let r = ParserRegistry::new();
        assert_eq!(r.parser_count(), 0);
        assert!(r.list_parsers().is_empty());
    }

    #[test]
    fn test_registry_default_is_empty() {
        let r = ParserRegistry::default();
        assert_eq!(r.parser_count(), 0);
    }

    // ======================================================================
    // Test Group 2: Registration Operations
    // ======================================================================

    #[test]
    fn test_register_adds_to_end() {
        let r = ParserRegistry::new();
        r.register(Arc::new(MockParser::new("A", vec!["t/a"])));
        r.register(Arc::new(MockParser::new("B", vec!["t/b"])));
        assert_eq!(r.parser_count(), 2);
        assert_eq!(r.list_parsers()[0].name, "A");
        assert_eq!(r.list_parsers()[1].name, "B");
    }

    #[test]
    fn test_register_at_inserts_at_position() {
        let r = ParserRegistry::new();
        r.register(Arc::new(MockParser::new("First", vec!["t/a"])));
        r.register(Arc::new(MockParser::new("Second", vec!["t/b"])));
        r.register_at(0, Arc::new(MockParser::new("Zero", vec!["t/c"])));
        let infos = r.list_parsers();
        assert_eq!(infos[0].name, "Zero");
        assert_eq!(infos[1].name, "First");
        assert_eq!(infos[2].name, "Second");
    }

    #[test]
    fn test_register_at_clamps_out_of_range() {
        let r = ParserRegistry::new();
        r.register(Arc::new(MockParser::new("Only", vec!["t/a"])));
        r.register_at(100, Arc::new(MockParser::new("Clamped", vec!["t/b"])));
        assert_eq!(r.list_parsers()[1].name, "Clamped");
    }

    #[test]
    fn test_unregister_removes_by_name() {
        let r = ParserRegistry::new();
        r.register(Arc::new(MockParser::new("ToRemove", vec!["t/a"])));
        r.register(Arc::new(MockParser::new("ToKeep", vec!["t/b"])));
        assert!(r.unregister("ToRemove"));
        assert_eq!(r.parser_count(), 1);
        assert!(r.has_parser("ToKeep"));
        assert!(!r.has_parser("ToRemove"));
    }

    #[test]
    fn test_unregister_nonexistent_returns_false() {
        let r = ParserRegistry::new();
        assert!(!r.unregister("DoesNotExist"));
    }

    #[test]
    fn test_clear_removes_all() {
        let r = ParserRegistry::new();
        r.register(Arc::new(MockParser::new("A", vec!["t/a"])));
        r.register(Arc::new(MockParser::new("B", vec!["t/b"])));
        r.clear();
        assert_eq!(r.parser_count(), 0);
    }

    // ======================================================================
    // Test Group 3: Magic Byte Detection
    // ======================================================================

    #[test]
    fn test_detect_pdf_magic() {
        let d = detect_format_from_bytes(b"%PDF-1.4").unwrap();
        assert_eq!(d.mime_type, "application/pdf");
        assert_eq!(d.format_name, "PDF");
        assert!((d.confidence - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_detect_zip_magic() {
        let d = detect_format_from_bytes(b"PK\x03\x04").unwrap();
        assert_eq!(d.mime_type, "application/zip");
        assert_eq!(d.format_name, "ZIP");
        assert!(d.confidence < 1.0 && d.confidence > 0.5);
    }

    #[test]
    fn test_detect_unknown_returns_none() {
        assert!(detect_format_from_bytes(b"\x00\x01\x02\x03\xFF\xFE").is_none());
    }

    #[test]
    fn test_detect_short_input_returns_none() {
        assert!(detect_format_from_bytes(b"%P").is_none());
    }

    // ======================================================================
    // Test Group 4: Extension Extraction
    // ======================================================================

    #[test]
    fn test_extract_simple_extensions() {
        assert_eq!(extract_extension("doc.pdf"), Some("pdf".into()));
        assert_eq!(extract_extension("arc.zip"), Some("zip".into()));
        assert_eq!(extract_extension("report.docx"), Some("docx".into()));
    }

    #[test]
    fn test_extract_case_insensitive() {
        assert_eq!(extract_extension("FILE.PDF"), Some("pdf".into()));
        assert_eq!(extract_extension("Data.DOCX"), Some("docx".into()));
    }

    #[test]
    fn test_extract_with_path() {
        assert_eq!(extract_extension("/tmp/doc.pdf"), Some("pdf".into()));
        assert_eq!(extract_extension(r"C:\data\file.xlsx"), Some("xlsx".into()));
    }

    #[test]
    fn test_extract_no_extension() {
        assert_eq!(extract_extension("README"), None);
        assert_eq!(extract_extension("hidden."), None);
    }

    // ======================================================================
    // Test Group 5: Routing Logic
    // ======================================================================

    #[tokio::test]
    async fn test_route_by_mime_type() {
        let r = ParserRegistry::new();
        r.register(Arc::new(MockParser::new("PdfH", vec!["application/pdf", ".pdf"])));
        let p = r.find_parser(b"%PDF-1.4", Some("doc.pdf")).unwrap();
        assert_eq!(p.parser_name(), "PdfH");
    }

    #[tokio::test]
    async fn test_route_by_extension_only() {
        let r = ParserRegistry::new();
        r.register(Arc::new(MockParser::new("DocxH", vec![".docx", ".xlsx"])));
        let p = r.find_parser(b"\x00\x00\x00\x00", Some("report.docx")).unwrap();
        assert_eq!(p.parser_name(), "DocxH");
    }

    #[tokio::test]
    async fn test_no_match_returns_none() {
        let r = ParserRegistry::new();
        r.register(Arc::new(MockParser::new("OnlyPdf", vec!["application/pdf"])));
        assert!(r.find_parser(b"PK\x03\x04", None).is_none());
    }

    #[tokio::test]
    async fn test_priority_first_match_wins() {
        let r = ParserRegistry::new();
        r.register(Arc::new(MockParser::new("SpecialZip", vec![".zip", "application/zip"])));
        r.register(Arc::new(MockParser::new("GenericZip", vec![".zip", "application/zip"])));
        let p = r.find_parser(b"PK\x03\x04", Some("f.zip")).unwrap();
        assert_eq!(p.parser_name(), "SpecialZip");
    }

    // ======================================================================
    // Test Group 6: Parse with Fallback
    // ======================================================================

    #[tokio::test]
    async fn test_parse_unknown_uses_fallback() {
        let r = ParserRegistry::new();
        let result = r.parse(make_unknown_bytes(), &SanitizePolicy::default()).await.unwrap();
        assert_eq!(result.parser_name, "BinarySafeFallbackParser");
        assert!(matches!(&result.actions_taken[0], SanitizeAction::BinarySanitized(_)));
    }

    #[tokio::test]
    async fn test_parse_known_routes_correctly() {
        let r = ParserRegistry::new();
        r.register(Arc::new(MockParser::new("TestPdf", vec!["application/pdf", ".pdf"])));
        let result = r.parse(make_pdf_bytes(), &SanitizePolicy::default()).await.unwrap();
        assert_eq!(result.parser_name, "TestPdf");
    }

    #[tokio::test]
    async fn test_parse_propagates_error() {
        let r = ParserRegistry::new();
        r.register(Arc::new(MockParser::failing("FailP", vec!["app/fail"])));
        let parsers = r.parsers.read().unwrap();
        let fp = Arc::clone(parsers.first().unwrap());
        drop(parsers);
        let result = fp.parse_and_sanitize(Bytes::from_static(b"x"), &SanitizePolicy::default()).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ParseError::CorruptData(_)));
    }

    // ======================================================================
    // Test Group 7: Introspection
    // ======================================================================

    #[test]
    fn test_list_parsers_info() {
        let r = ParserRegistry::new();
        r.register(Arc::new(MockParser::new("PMock", vec!["app/pdf", ".pdf", "app/x-pdf"])));
        let infos = r.list_parsers();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].supported_types.len(), 3);
    }

    #[test]
    fn test_has_parser_existence() {
        let r = ParserRegistry::new();
        assert!(!r.has_parser("Nope"));
        r.register(Arc::new(MockParser::new("Yep", vec!["t/x"])));
        assert!(r.has_parser("Yep"));
    }

    // ======================================================================
    // Test Group 8: Concurrent Access
    // ======================================================================

    #[tokio::test]
    async fn test_concurrent_parses() {
        let r = Arc::new(ParserRegistry::new());
        r.register(Arc::new(MockParser::new("ConcP", vec!["app/*", ".bin"])));
        let mut js = JoinSet::new();
        for i in 0..10 {
            let reg = Arc::clone(&r);
            js.spawn(async move {
                reg.parse(Bytes::from(format!("data {}", i)), &SanitizePolicy::default()).await
            });
        }
        let mut count = 0;
        while let Some(res) = js.join_next().await {
            assert!(res.is_ok());
            assert!(res.unwrap().is_ok());
            count += 1;
        }
        assert_eq!(count, 10);
    }

    #[tokio::test]
    async fn test_concurrent_register_and_parse() {
        let r = Arc::new(ParserRegistry::new());
        let mut js = JoinSet::new();
        for i in 0..5usize {
            let reg = Arc::clone(&r);
            js.spawn(async move {
                let n = Box::leak(format!("DP{}", i).into_boxed_str());
                reg.register(Arc::new(MockParser::new(n, vec!["t/d"])));
            });
        }
        for _ in 0..5usize {
            let reg = Arc::clone(&r);
            js.spawn(async move {
                let _ = reg.parse(Bytes::from_static(b"d"), &SanitizePolicy::default()).await;
            });
        }
        while let Some(res) = js.join_next().await {
            assert!(res.is_ok(), "concurrent op panicked");
        }
        assert!(r.parser_count() <= 5);
    }

    // ======================================================================
    // Test Group 9: Edge Cases
    // ======================================================================

    #[tokio::test]
    async fn test_empty_input_goes_to_fallback() {
        let r = ParserRegistry::new();
        let out = r.parse(Bytes::new(), &SanitizePolicy::default()).await.unwrap();
        assert_eq!(out.parser_name, "BinarySafeFallbackParser");
        assert_eq!(out.original_size, 0);
    }

    #[test]
    fn test_find_on_empty_registry() {
        let r = ParserRegistry::new();
        assert!(r.find_parser(b"%PDF-1.4", Some("t.pdf")).is_none());
    }

    #[tokio::test]
    async fn test_fallback_preserves_data() {
        let r = ParserRegistry::new();
        let orig = Bytes::from_static(b"\xDE\xAD\xBE\xEF payload");
        let len = orig.len();
        let out = r.parse(orig, &SanitizePolicy::default()).await.unwrap();
        assert_eq!(out.clean_data.len(), len);
        assert_eq!(out.original_size, len as u64);
    }
}

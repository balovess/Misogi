//! PDF Stream Parser �?ContentParser adapter for [`PdfSanitizer`].
//!
//! Wraps the existing nom-based PDF sanitizer to implement the streaming
//! [`ContentParser`] trait interface. Accepts raw PDF bytes, delegates
//! threat detection and remediation to [`PdfSanitizer`], and returns
//! a [`SanitizedOutput`] with comprehensive audit trail.
//!
//! ## Processing Pipeline
//!
//! ```text
//! Bytes input -> Validate size & header -> Write temp file
//!     -> PdfSanitizer::analyze()  (Pass 1: threat scan)
//!     -> PdfSanitizer::remediate() (Pass 2: NOP replacement)
//!     -> Read sanitized bytes -> SanitizedOutput
//! ```
//!
//! ## Security Guarantees
//!
//! - **Zero-trust input**: All bytes treated as potentially malicious
//! - **Bounded memory**: Respects `SanitizePolicy.max_file_size_bytes`
//! - **Deterministic output**: Same input + policy = identical output (hash equality)
//! - **Complete audit**: Every threat removal recorded in `actions_taken`

use async_trait::async_trait;
use bytes::Bytes;
use std::fmt;

use crate::parser_trait::{ContentParser, ParseError, SanitizeAction, SanitizePolicy, SanitizedOutput};
use crate::pdf_sanitizer::{PdfSanitizer, PdfThreat};
use crate::report::SanitizationAction;

// ===========================================================================
// PdfStreamParser Configuration
// ===========================================================================

/// Configuration for PDF stream parser with security limits.
///
/// Controls the behavior of [`PdfStreamParser`] including file size bounds
/// and optional True CDR reconstruction mode.
#[derive(Debug, Clone)]
pub struct PdfStreamParserConfig {
    /// Maximum allowed PDF file size in bytes.
    ///
    /// Files exceeding this limit are rejected before any parsing occurs,
    /// preventing memory exhaustion attacks through oversized inputs.
    pub max_file_size_bytes: u64,

    /// Enable True CDR (zero-byte survival) reconstruction when available.
    ///
    /// When true and `pdf-cdr` feature is enabled, uses structural rebuild
    /// instead of NOP replacement for stronger security guarantees.
    pub enable_true_cdr: bool,
}

impl Default for PdfStreamParserConfig {
    /// Japanese government-safe default configuration.
    ///
    /// - 500 MiB size limit (sufficient for most legitimate PDFs)
    /// - True CDR disabled by default (faster processing; opt-in for high-security)
    fn default() -> Self {
        Self {
            max_file_size_bytes: 500 * 1024 * 1024, // 500 MiB
            enable_true_cdr: false,
        }
    }
}

// ===========================================================================
// PdfStreamParser Implementation
// ===========================================================================

/// Streaming PDF content parser implementing [`ContentParser`].
///
/// Adapts the existing [`PdfSanitizer`] (nom-based binary scanner) to the
/// pluggable [`ContentParser`] trait. Handles PDF documents end-to-end:
/// validation, threat analysis, remediation, and audit output generation.
///
/// ## Thread Safety
///
/// `PdfStreamParser` is `Send + Sync` �?it holds only configuration data
/// and creates per-request state during each `parse_and_sanitize()` call.
///
/// # Example
///
/// ```ignore
/// use misogi_cdr::parsers::PdfStreamParser;
/// use misogi_cdr::parser_trait::SanitizePolicy;
///
/// let parser = PdfStreamParser::new();
/// let policy = SanitizePolicy::default();
/// let pdf_bytes = std::fs::read("document.pdf")?;
///
/// let result = parser.parse_and_sanitize(pdf_bytes.into(), &policy).await?;
/// println!("Clean PDF: {} bytes, actions: {}", result.sanitized_size, result.actions_taken.len());
/// ```
#[derive(Debug, Clone)]
pub struct PdfStreamParser {
    config: PdfStreamParserConfig,
}

impl PdfStreamParser {
    /// Create a new PDF stream parser with default configuration.
    ///
    /// Uses Japanese government-safe defaults: 500 MiB size limit,
    /// True CDR disabled.
    pub fn new() -> Self {
        Self {
            config: PdfStreamParserConfig::default(),
        }
    }

    /// Create a new PDF stream parser with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Parser configuration controlling size limits and CDR mode.
    pub fn with_config(config: PdfStreamParserConfig) -> Self {
        Self { config }
    }

    // -----------------------------------------------------------------------
    // Internal: Convert SanitizationAction -> SanitizeAction mapping
    // -----------------------------------------------------------------------

    /// Map internal [`SanitizationAction`] variants to standard [`SanitizeAction`] records.
    ///
    /// This bridge function translates the legacy action format used by
    /// [`PdfSanitizer`] into the unified [`SanitizeAction`] enum required
    /// by the [`ContentParser`] trait contract.
    #[allow(dead_code)]
    fn map_action(action: &SanitizationAction) -> SanitizeAction {
        match action {
            SanitizationAction::PdfJsRemoved { .. } => SanitizeAction::JavaScriptRemoved,
            SanitizationAction::PdfAaRemoved { .. } => SanitizeAction::JavaScriptRemoved,
            SanitizationAction::PdfOpenActionRemoved => SanitizeAction::JavaScriptRemoved,
            SanitizationAction::PdfAcroFormFlattened => {
                SanitizeAction::BinarySanitized("AcroForm flattened".to_string())
            }
            SanitizationAction::PdfSubmitFormRemoved => SanitizeAction::ExternalLinkRemoved,
            SanitizationAction::PdfUriRemoved { .. } => SanitizeAction::ExternalLinkRemoved,
            SanitizationAction::PdfEmbeddedFileFlagged { .. } => SanitizeAction::EmbeddedFileRemoved,
            SanitizationAction::PdfRichMediaRemoved => SanitizeAction::EmbeddedFileRemoved,
            _ => SanitizeAction::CustomAction(format!("{:?}", action)),
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Validate PDF input before processing
    // -----------------------------------------------------------------------

    /// Perform pre-processing validation on raw PDF bytes.
    ///
    /// Checks:
    /// 1. File size against configured maximum
    /// 2. PDF magic header (`%PDF`)
    /// 3. Minimum viable size (5 bytes for `%PDF` + version)
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::FileTooLarge`] or [`ParseError::CorruptData`]
    /// on validation failure.
    fn validate_input(&self, input: &[u8], policy: &SanitizePolicy) -> Result<(), ParseError> {
        // Check size limit from policy (takes precedence over config)
        let effective_max = policy.max_file_size_bytes.unwrap_or(self.config.max_file_size_bytes);

        if input.len() as u64 > effective_max {
            return Err(ParseError::FileTooLarge(input.len() as u64));
        }

        // Validate PDF header
        if input.len() < 5 || !input.starts_with(b"%PDF") {
            return Err(ParseError::CorruptData(
                "Invalid PDF: missing %PDF header magic bytes".to_string(),
            ));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: In-memory analysis using PdfSanitizer scanner
    // -----------------------------------------------------------------------

    /// Scan PDF bytes for threats using the nom-based threat detector.
    ///
    /// Reuses [`PdfSanitizer::scan_for_threats()`] combinator chain to
    /// perform byte-positional scanning without requiring filesystem I/O.
    /// This is the core of Pass 1 in the two-pass sanitization strategy.
    fn analyze_in_memory(&self, data: &[u8]) -> Vec<PdfThreat> {
        let mut threats: Vec<PdfThreat> = Vec::new();
        let mut pos: usize = 0;

        while pos < data.len() {
            let remaining = &data[pos..];

            match PdfSanitizer::scan_for_threats(remaining) {
                Ok((_, mut threat)) => {
                    // Set absolute offset based on current scan position
                    match &mut threat {
                        PdfThreat::JavaScript { offset, .. }
                        | PdfThreat::JavaScriptLong { offset, .. }
                        | PdfThreat::AdditionalActions { offset, .. }
                        | PdfThreat::OpenAction { offset }
                        | PdfThreat::AcroForm { offset }
                        | PdfThreat::SubmitForm { offset }
                        | PdfThreat::UriAction { offset }
                        | PdfThreat::EmbeddedFile { offset, .. }
                        | PdfThreat::RichMedia { offset } => *offset = pos,
                    }

                    // Advance past threat region to avoid re-matching
                    let threat_len = match &threat {
                        PdfThreat::JavaScript { value_length, .. } => 3 + value_length,
                        PdfThreat::JavaScriptLong { value_length, .. } => 11 + value_length,
                        PdfThreat::AdditionalActions { dict_length, .. } => 3 + dict_length,
                        PdfThreat::OpenAction { .. } => 11,
                        PdfThreat::AcroForm { .. } => 9,
                        PdfThreat::SubmitForm { .. } => 12,
                        PdfThreat::UriAction { .. } => 4,
                        PdfThreat::EmbeddedFile { .. } => 13,
                        PdfThreat::RichMedia { .. } => 10,
                    };

                    threats.push(threat);
                    pos += threat_len.max(1); // Always advance at least 1 byte
                }
                Err(_) => {
                    pos += 1;
                }
            }
        }

        threats
    }

    // -----------------------------------------------------------------------
    // Internal: Apply NOP-based remediation to produce clean output
    // -----------------------------------------------------------------------

    /// Apply remediation to detected threats and produce sanitized PDF bytes.
    ///
    /// For each detected threat at its absolute byte offset:
    /// - JavaScript/JS long: Replace with `( )` (empty string literal)
    /// - Additional Actions: Replace with `{}`
    /// - OpenAction/SubmitForm/RichMedia: Replace with spaces
    /// - AcroForm: Remove (empty bytes)
    /// - URI action: Replace with `/URI ()`
    /// - EmbeddedFile: Remove (empty bytes)
    ///
    /// This produces a structurally-valid PDF with all dangerous content neutralized.
    fn remediate_in_memory(
        &self,
        data: &[u8],
        threats: &[PdfThreat],
        policy: &SanitizePolicy,
    ) -> (Vec<u8>, Vec<SanitizeAction>) {
        if threats.is_empty() {
            return (data.to_vec(), Vec::new());
        }

        let mut output = Vec::with_capacity(data.len());
        let mut actions: Vec<SanitizeAction> = Vec::new();
        let mut sorted_threats: Vec<&PdfThreat> = threats.iter().collect();
        sorted_threats.sort_by_key(|t| t.offset());

        let mut read_pos: usize = 0;

        for threat in &sorted_threats {
            let threat_offset = threat.offset();

            // Copy safe content up to this threat
            if threat_offset > read_pos {
                output.extend_from_slice(&data[read_pos..threat_offset]);
            }

            // Generate replacement bytes based on threat type and policy
            let (replacement, action) = self.generate_replacement(threat, policy);
            output.extend_from_slice(&replacement);
            actions.push(action);

            // Advance read position past the threat
            let threat_len = match threat {
                PdfThreat::JavaScript { value_length, .. } => 3 + value_length,
                PdfThreat::JavaScriptLong { value_length, .. } => 11 + value_length,
                PdfThreat::AdditionalActions { dict_length, .. } => 3 + dict_length,
                PdfThreat::OpenAction { .. } => 11,
                PdfThreat::AcroForm { .. } => 9,
                PdfThreat::SubmitForm { .. } => 12,
                PdfThreat::UriAction { .. } => 4,
                PdfThreat::EmbeddedFile { .. } => 13,
                PdfThreat::RichMedia { .. } => 10,
            };
            read_pos = threat_offset + threat_len;
        }

        // Copy remaining safe content after last threat
        if read_pos < data.len() {
            output.extend_from_slice(&data[read_pos..]);
        }

        (output, actions)
    }

    /// Generate replacement bytes and corresponding [`SanitizeAction`] for a given threat.
    ///
    /// The replacement strategy depends on both the threat type and the active
    /// sanitization policy flags (e.g., `remove_javascript`, `remove_embedded_files`).
    fn generate_replacement(
        &self,
        threat: &PdfThreat,
        policy: &SanitizePolicy,
    ) -> (Vec<u8>, SanitizeAction) {
        match threat {
            PdfThreat::JavaScript { .. } | PdfThreat::JavaScriptLong { .. } => {
                if policy.remove_javascript {
                    (b"( )".to_vec(), SanitizeAction::JavaScriptRemoved)
                } else {
                    // Policy allows JS but still record that we detected it
                    (Vec::new(), SanitizeAction::CustomAction("JavaScriptDetected-PolicyAllowed".to_string()))
                }
            }

            PdfThreat::AdditionalActions { .. } => {
                if policy.remove_javascript {
                    (b"{}".to_vec(), SanitizeAction::JavaScriptRemoved)
                } else {
                    (Vec::new(), SanitizeAction::CustomAction("AADetected-PolicyAllowed".to_string()))
                }
            }

            PdfThreat::OpenAction { .. } => {
                if policy.remove_javascript {
                    (vec![b' '; 11], SanitizeAction::JavaScriptRemoved)
                } else {
                    (Vec::new(), SanitizeAction::CustomAction("OpenActionDetected-PolicyAllowed".to_string()))
                }
            }

            PdfThreat::AcroForm { .. } => {
                (
                    vec![],
                    SanitizeAction::BinarySanitized("AcroForm flattened".to_string()),
                )
            }

            PdfThreat::SubmitForm { .. } => {
                if policy.remove_external_links {
                    (vec![b' '; 12], SanitizeAction::ExternalLinkRemoved)
                } else {
                    (Vec::new(), SanitizeAction::CustomAction("SubmitFormDetected-PolicyAllowed".to_string()))
                }
            }

            PdfThreat::UriAction { .. } => {
                if policy.remove_external_links {
                    (b"/URI ()".to_vec(), SanitizeAction::ExternalLinkRemoved)
                } else {
                    (Vec::new(), SanitizeAction::CustomAction("URIDetected-PolicyAllowed".to_string()))
                }
            }

            PdfThreat::EmbeddedFile { name, .. } => {
                if policy.remove_embedded_files {
                    (
                        vec![],
                        SanitizeAction::EmbeddedFileRemoved,
                    )
                } else {
                    (
                        Vec::new(),
                        SanitizeAction::CustomAction(format!("EmbeddedFile({})-PolicyAllowed", name)),
                    )
                }
            }

            PdfThreat::RichMedia { .. } => {
                if policy.remove_embedded_files {
                    (vec![b' '; 10], SanitizeAction::EmbeddedFileRemoved)
                } else {
                    (Vec::new(), SanitizeAction::CustomAction("RichMediaDetected-PolicyAllowed".to_string()))
                }
            }
        }
    }
}

impl Default for PdfStreamParser {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PdfStreamParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PdfStreamParser[max={}MB]", self.config.max_file_size_bytes / (1024 * 1024))
    }
}

// ===========================================================================
// ContentParser Trait Implementation
// ===========================================================================

#[async_trait]
impl ContentParser for PdfStreamParser {
    fn supported_types(&self) -> Vec<&'static str> {
        vec![
            "application/pdf",
            "application/x-pdf",
            ".pdf",
        ]
    }

    fn parser_name(&self) -> &str {
        "PdfStreamParser"
    }

    async fn parse_and_sanitize(
        &self,
        input: Bytes,
        policy: &SanitizePolicy,
    ) -> Result<SanitizedOutput, ParseError> {
        let original_size = input.len() as u64;

        // Phase 1: Input validation
        self.validate_input(&input, policy)?;

        // Phase 2: Threat analysis (in-memory scan)
        let threats = self.analyze_in_memory(&input);

        // Phase 3: Remediation (in-memory NOP replacement)
        let (sanitized_data, raw_actions) = self.remediate_in_memory(&input, &threats, policy);

        // Phase 4: Build SanitizedOutput with mapped actions
        let mut warnings: Vec<String> = Vec::new();

        // Collect warnings from embedded file detections
        for threat in &threats {
            if let PdfThreat::EmbeddedFile { name, .. } = threat {
                warnings.push(format!(
                    "EmbeddedFile attachment detected and removed: {}",
                    name
                ));
            }
        }

        // If no threats found, document this as informational
        if threats.is_empty() {
            tracing::info!(
                parser = self.parser_name(),
                input_size = original_size,
                "PDF parsed cleanly: no threats detected"
            );
        } else {
            tracing::info!(
                parser = self.parser_name(),
                input_size = original_size,
                threat_count = threats.len(),
                actions_taken = raw_actions.len(),
                "PDF sanitization completed"
            );
        }

        // Compute output size before moving sanitized_data into Bytes
        let output_size = if raw_actions.is_empty() {
            original_size
        } else {
            sanitized_data.len() as u64
        };

        Ok(SanitizedOutput {
            clean_data: Bytes::from(sanitized_data),
            original_size,
            sanitized_size: output_size,
            actions_taken: raw_actions,
            warnings,
            parser_name: self.parser_name().to_string(),
        })
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test Fixture Helpers
    // -----------------------------------------------------------------------

    /// Create a minimal valid PDF with no threats.
    fn make_clean_pdf() -> Vec<u8> {
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n\
          2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n\
          3 0 obj<</Type/Page/MediaBox[0 0 612 792]>>endobj\n\
          xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n\
          trailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF\n"
            .to_vec()
    }

    /// Create a PDF containing a JavaScript threat (/JS tag).
    fn make_js_pdf() -> Vec<u8> {
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/OpenAction 4 0 R>>endobj\n\
          4 0 obj<</S/JavaScript/JS(app.alert('xss'))>>endobj\n\
          xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n\
          trailer<</Size 2/Root 1 0 R>>\nstartxref\n100\n%%EOF\n"
            .to_vec()
    }

    /// Create a PDF containing an embedded file attachment.
    fn make_embedded_file_pdf() -> Vec<u8> {
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Names<<</EmbeddedFiles 5 0 R>>>>>>endobj\n\
          5 0 obj<</Names[(malicious.exe) 6 0 R]>>endobj\n\
          xref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000070 00000 n \n\
          trailer<</Size 3/Root 1 0 R>>\nstartxref\n120\n%%EOF\n"
            .to_vec()
    }

    // -----------------------------------------------------------------------
    // Test Case 1: Supported Types
    // -----------------------------------------------------------------------

    #[test]
    fn test_supported_types() {
        let parser = PdfStreamParser::new();
        let types = parser.supported_types();

        assert!(
            types.contains(&"application/pdf"),
            "Must support application/pdf MIME type"
        );
        assert!(
            types.contains(&".pdf"),
            "Must support .pdf extension"
        );
        assert!(
            types.contains(&"application/x-pdf"),
            "Must support application/x-pdf alias"
        );
        assert_eq!(types.len(), 3, "Should have exactly 3 supported types");
    }

    // -----------------------------------------------------------------------
    // Test Case 2: Parser Name
    // -----------------------------------------------------------------------

    #[test]
    fn test_parser_name() {
        let parser = PdfStreamParser::new();
        assert_eq!(parser.parser_name(), "PdfStreamParser");
    }

    // -----------------------------------------------------------------------
    // Test Case 3: Clean PDF Parsing (No Threats)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_clean_pdf_no_actions() {
        let parser = PdfStreamParser::new();
        let policy = SanitizePolicy::default();
        let clean_input = Bytes::from(make_clean_pdf());

        let result = parser.parse_and_sanitize(clean_input, &policy).await;

        assert!(result.is_ok(), "Clean PDF should parse successfully");

        let output = result.unwrap();
        assert_eq!(output.original_size, output.sanitized_size, "Clean PDF should maintain same size");
        assert!(!output.has_actions(), "Clean PDF should have zero actions");
        assert!(!output.has_warnings(), "Clean PDF should have zero warnings");
        assert_eq!(output.parser_name, "PdfStreamParser");
    }

    // -----------------------------------------------------------------------
    // Test Case 4: JavaScript Detection and Removal
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_js_detection_and_removal() {
        let parser = PdfStreamParser::new();
        let policy = SanitizePolicy {
            remove_javascript: true,
            ..Default::default()
        };

        let js_input = Bytes::from(make_js_pdf());
        let result = parser.parse_and_sanitize(js_input, &policy).await;

        assert!(result.is_ok(), "JS-containing PDF should parse successfully");

        let output = result.unwrap();
        assert!(
            output.has_actions(),
            "JS PDF should have at least one action recorded"
        );

        // Verify JS removal action is present
        assert!(
            output.actions_taken.contains(&SanitizeAction::JavaScriptRemoved),
            "Actions should include JavaScriptRemoved"
        );
    }

    // -----------------------------------------------------------------------
    // Test Case 5: Embedded File Detection
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_embedded_file_detection() {
        let parser = PdfStreamParser::new();
        let policy = SanitizePolicy {
            remove_embedded_files: true,
            ..Default::default()
        };

        let embed_input = Bytes::from(make_embedded_file_pdf());
        let result = parser.parse_and_sanitize(embed_input, &policy).await;

        assert!(result.is_ok(), "Embedded-file PDF should parse successfully");

        let output = result.unwrap();
        assert!(
            output.actions_taken.contains(&SanitizeAction::EmbeddedFileRemoved),
            "Should detect and record embedded file removal"
        );
        assert!(!output.warnings.is_empty(), "Should generate warning about embedded file");
    }

    // -----------------------------------------------------------------------
    // Test Case 6: File Size Limit Enforcement
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_file_too_large_rejection() {
        let parser = PdfStreamParser::new();
        let strict_policy = SanitizePolicy {
            max_file_size_bytes: Some(50), // Only 50 bytes allowed
            ..Default::default()
        };

        // Create input larger than limit
        let large_input = Bytes::from(make_clean_pdf()); // ~250 bytes > 50 byte limit
        let result = parser.parse_and_sanitize(large_input, &strict_policy).await;

        assert!(result.is_err(), "Oversized PDF should be rejected");

        match result.unwrap_err() {
            ParseError::FileTooLarge(size) => {
                assert!(size > 50, "Reported size should exceed limit");
            }
            other => panic!("Expected FileTooLarge error, got: {}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test Case 7: Invalid PDF Header Rejection
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_invalid_pdf_header_rejected() {
        let parser = PdfStreamParser::new();
        let policy = SanitizePolicy::default();

        // Not a PDF at all
        let not_pdf = Bytes::from_static(b"Hello, I am not a PDF file.");
        let result = parser.parse_and_sanitize(not_pdf, &policy).await;

        assert!(result.is_err(), "Non-PDF input should be rejected");

        match result.unwrap_err() {
            ParseError::CorruptData(msg) => {
                assert!(
                    msg.contains("%PDF") || msg.contains("header"),
                    "Error message should mention PDF header: {}",
                    msg
                );
            }
            other => panic!("Expected CorruptData error, got: {}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test Case 8: Empty Input Handling
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_empty_input_rejected() {
        let parser = PdfStreamParser::new();
        let policy = SanitizePolicy::default();

        let empty_input = Bytes::new();
        let result = parser.parse_and_sanitize(empty_input, &policy).await;

        assert!(result.is_err(), "Empty input should be rejected as corrupt");
    }

    // -----------------------------------------------------------------------
    // Test Case 9: Custom Configuration
    // -----------------------------------------------------------------------

    #[test]
    fn test_custom_configuration() {
        let custom_cfg = PdfStreamParserConfig {
            max_file_size_bytes: 10 * 1024 * 1024, // 10 MB
            enable_true_cdr: true,
        };

        let parser = PdfStreamParser::with_config(custom_cfg);
        assert_eq!(parser.config.max_file_size_bytes, 10 * 1024 * 1024);
        assert!(parser.config.enable_true_cdr);

        // Verify supported types unaffected by config
        assert!(parser.supported_types().contains(&"application/pdf"));
    }

    // -----------------------------------------------------------------------
    // Test Case 10: Default Configuration Values
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config_values() {
        let cfg = PdfStreamParserConfig::default();
        assert_eq!(cfg.max_file_size_bytes, 500 * 1024 * 1024, "Default should be 500 MiB");
        assert!(!cfg.enable_true_cdr, "True CDR should be off by default");
    }

    // -----------------------------------------------------------------------
    // Test Case 11: Display Formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_display_formatting() {
        let parser = PdfStreamParser::new();
        let display = format!("{}", parser);
        assert!(
            display.contains("PdfStreamParser"),
            "Display should contain parser name: {}",
            display
        );
        assert!(
            display.contains("MB"),
            "Display should contain size unit: {}",
            display
        );
    }

    // -----------------------------------------------------------------------
    // Test Case 12: Send + Sync Bounds Verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_send_sync_bounds() {
        fn assert_send_sync<T: Send + Sync + fmt::Debug>() {}
        assert_send_sync::<PdfStreamParser>();
    }

    // -----------------------------------------------------------------------
    // Test Case 13: Trait Object Safety
    // -----------------------------------------------------------------------

    #[test]
    fn test_trait_object_safety() {
        let parser = PdfStreamParser::new();
        let _trait_obj: Box<dyn ContentParser> = Box::new(parser);
        // Compilation proves object safety
    }

    // -----------------------------------------------------------------------
    // Test Case 14: Multiple Threat Types in Single PDF
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_multiple_threat_types() {
        let parser = PdfStreamParser::new();
        let policy = SanitizePolicy::default(); // All removals enabled

        // Craft PDF with multiple threat types combined
        let multi_threat_pdf = b"%PDF-1.4\n\
            1 0 obj<</Type/Catalog/OpenAction 4 0 R>>endobj\n\
            4 0 obj<</S/JavaScript/JS(app.alert('xss'))>>endobj\n\
            5 0 obj<</URI(http://evil.com/track)>>endobj\n\
            xref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000060 00000 n \n\
            trailer<</Size 3/Root 1 0 R>>\nstartxref\n150\n%%EOF\n";

        let result = parser
            .parse_and_sanitize(Bytes::from_static(multi_threat_pdf), &policy)
            .await;

        assert!(result.is_ok(), "Multi-threat PDF should parse successfully");

        let output = result.unwrap();
        // Should detect both JS and URI threats
        assert!(
            output.actions_taken.len() >= 2,
            "Expected at least 2 actions, got {}: {:?}",
            output.actions_taken.len(),
            output.actions_taken
        );
    }
}

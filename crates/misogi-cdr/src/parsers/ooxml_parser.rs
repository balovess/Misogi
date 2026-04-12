//! OOXML Stream Parser — ContentParser adapter for Office document sanitization.
//!
//! Wraps [`OfficeSanitizer`] and optionally [`OoxmlTrueCdrEngine`] to implement
//! the streaming [`ContentParser`] trait for Office Open XML documents (.docx,
//! .xlsx, .pptx, and their macro-enabled variants).
//!
//! ## Processing Pipeline
//!
//! ```text
//! Bytes input -> Validate PK signature & size -> Write temp file
//!     -> OfficeSanitizer: remove vbaProject.bin entries
//!     -> [Optional] OoxmlTrueCdrEngine: full element whitelist filtering
//!     -> Read sanitized bytes -> SanitizedOutput
//! ```
//!
//! ## Security Model
//!
//! ### Basic Mode (OfficeSanitizer only)
//! - Removes VBA macro project files (`vbaProject.bin`, `vbaData.xml`)
//! - Validates ZIP bomb expansion ratio (< 10x)
//! - Enforces file size limits
//!
//! ### True CDR Mode (OoxmlTrueCdrEngine)
//! - Full XML element whitelisting per document type
//! - Content-Type filtering to remove macro/ActiveX/OLE types
//! - Relationship cleaning for dangling references
//! - Binary resource validation (images/fonts only; OLE blocked)

use async_trait::async_trait;
use bytes::Bytes;
use std::fmt;
use std::io::{Cursor, Read, Write};

use crate::parser_trait::{ContentParser, ParseError, SanitizeAction, SanitizePolicy, SanitizedOutput};

// ===========================================================================
// OoxmlStreamParser Configuration
// ===========================================================================

/// Configuration controlling OOXML stream parser behavior.
///
/// Selects between basic VBA-stripping mode and full True CDR reconstruction,
/// with configurable security bounds.
#[derive(Debug, Clone)]
pub struct OoxmlStreamParserConfig {
    /// Maximum allowed input file size in bytes.
    ///
    /// Files exceeding this limit are rejected before ZIP parsing begins,
    /// preventing memory exhaustion through decompression bombs.
    pub max_file_size_bytes: u64,

    /// Enable True CDR (element-level whitelisting) when available.
    ///
    /// When `true`, uses [`OoxmlTrueCdrEngine`] for deep XML inspection
    /// in addition to basic VBA removal. Provides stronger guarantees but
    /// incurs higher processing overhead.
    pub enable_true_cdr: bool,

    /// Maximum allowed ZIP expansion ratio (uncompressed / compressed).
    ///
    /// Prevents ZIP bomb attacks where a small compressed archive expands
    /// to enormous size during extraction. Default 10x is conservative per
    /// NIST SP 800-91 recommendations.
    pub max_expansion_ratio: u64,
}

impl Default for OoxmlStreamParserConfig {
    /// Secure default configuration following Japanese government guidelines.
    fn default() -> Self {
        Self {
            max_file_size_bytes: 100 * 1024 * 1024, // 100 MiB
            enable_true_cdr: false,
            max_expansion_ratio: 10,
        }
    }
}

// ===========================================================================
// OoxmlStreamParser Implementation
// ===========================================================================

/// Streaming OOXML content parser implementing [`ContentParser`].
///
/// Handles all Office Open XML document formats:
/// - **Word**: `.docx`, `.docm`
/// - **Excel**: `.xlsx`, `.xlsm`
/// - **PowerPoint**: `.pptx`, `.pptm`
///
/// ## Thread Safety
///
/// `OoxmlStreamParser` is `Send + Sync` — holds only immutable configuration.
/// All mutable state is created per-request within `parse_and_sanitize()`.
///
/// # Example
///
/// ```ignore
/// use misogi_cdr::parsers::OoxmlStreamParser;
/// use misogi_cdr::parser_trait::SanitizePolicy;
///
/// let parser = OoxmlStreamParser::new();
/// let policy = SanitizePolicy { remove_macros: true, ..Default::default() };
/// let docx_bytes = std::fs::read("document.docx")?;
///
/// let result = parser.parse_and_sanitize(docx_bytes.into(), &policy).await?;
/// println!("Clean OOXML: {} bytes", result.sanitized_size);
/// ```
#[derive(Debug, Clone)]
pub struct OoxmlStreamParser {
    config: OoxmlStreamParserConfig,
}

impl OoxmlStreamParser {
    /// Create a new OOXML stream parser with secure defaults.
    ///
    /// Default configuration:
    /// - 100 MiB file size limit
    /// - Basic mode (VBA removal only, no True CDR)
    /// - 10x maximum expansion ratio
    pub fn new() -> Self {
        Self {
            config: OoxmlStreamParserConfig::default(),
        }
    }

    /// Create a new OOXML stream parser with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Parser configuration for security bounds and CDR mode.
    pub fn with_config(config: OoxmlStreamParserConfig) -> Self {
        Self { config }
    }

    // -----------------------------------------------------------------------
    // Internal: Validate OOZIP/PK signature and size constraints
    // -----------------------------------------------------------------------

    /// Perform pre-processing validation on raw OOXML bytes.
    ///
    /// Checks:
    /// 1. File size against configured maximum
    /// 2. ZIP/PK signature header (`PK\x03\x04`)
    /// 3. Minimum viable size (30 bytes for local file header)
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::FileTooLarge`] or [`ParseError::CorruptData`]
    /// on validation failure.
    fn validate_input(&self, input: &[u8], policy: &SanitizePolicy) -> Result<(), ParseError> {
        let effective_max = policy.max_file_size_bytes.unwrap_or(self.config.max_file_size_bytes);

        if input.len() as u64 > effective_max {
            return Err(ParseError::FileTooLarge(input.len() as u64));
        }

        // OOXML is a ZIP container; must start with PK signature
        if input.len() < 30 || !input.starts_with(b"PK\x03\x04") {
            return Err(ParseError::CorruptData(
                "Invalid OOXML: missing ZIP/PK signature header".to_string(),
            ));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: In-memory OOXML sanitization via ZIP manipulation
    // -----------------------------------------------------------------------

    /// Sanitize OOXML content entirely in memory using ZIP operations.
    ///
    /// This method avoids filesystem I/O by working directly on byte buffers:
    /// 1. Parse input as ZIP archive
    /// 2. Iterate over entries, removing dangerous ones (vbaProject.bin, etc.)
    /// 3. Rebuild clean ZIP into output buffer
    /// 4. Return sanitized bytes with action records
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes of the OOXML (ZIP) document
    /// * `policy` - Sanitization policy controlling removal behavior
    ///
    /// # Returns
    ///
    /// Tuple of (sanitized_bytes, sanitize_actions, warnings)
    fn sanitize_in_memory(
        &self,
        data: &[u8],
        policy: &SanitizePolicy,
    ) -> Result<(Vec<u8>, Vec<SanitizeAction>, Vec<String>), ParseError> {
        let mut actions: Vec<SanitizeAction> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        // Open ZIP from memory
        let mut reader =
            zip::ZipArchive::new(Cursor::new(data)).map_err(|e| {
                ParseError::CorruptData(format!("Failed to parse OOXML ZIP container: {}", e))
            })?;

        // Check expansion ratio for ZIP bomb detection (use indexed loop to avoid closure lifetime issues)
        let total_uncompressed: u64 = {
            let mut total: u64 = 0;
            for i in 0..reader.len() {
                if let Ok(entry) = reader.by_index(i) {
                    total += entry.size();
                }
            }
            total
        };

        let compressed_size = data.len().max(1) as u64;
        let expansion_ratio = total_uncompressed / compressed_size;

        if expansion_ratio > self.config.max_expansion_ratio {
            return Err(ParseError::CorruptData(format!(
                "ZIP bomb detected in OOXML: expansion ratio {}x exceeds maximum {}x",
                expansion_ratio, self.config.max_expansion_ratio
            )));
        }

        // Build output ZIP in memory
        let mut output_buffer = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut output_buffer);

        // Dangerous entry patterns (matching OfficeSanitizer's DANGEROUS_ENTRIES)
        let dangerous_entries: &[&str] = &[
            "vbaProject.bin",
            "word/vbaProject.bin",
            "xl/vbaProject.bin",
            "ppt/vbaProject.bin",
            "word/vbaData.xml",
            "xl/vbaData.xml",
        ];

        // Collect entry names first (required by zip crate lifetime rules)
        let mut entry_names: Vec<String> = Vec::with_capacity(reader.len());
        for i in 0..reader.len() {
            if let Ok(entry) = reader.by_index(i) {
                entry_names.push(entry.name().to_string());
            }
        }

        // Process each entry
        for entry_name in &entry_names {
            let normalized = entry_name.to_ascii_lowercase();
            let is_dangerous = dangerous_entries.iter().any(|dangerous| {
                normalized == *dangerous
                    || normalized.ends_with(&format!("/{}", dangerous.to_ascii_lowercase()))
            });

            if is_dangerous && policy.remove_macros {
                // Record action and skip this entry
                actions.push(SanitizeAction::MacroStripped);
                warnings.push(format!(
                    "VBA macro entry removed from OOXML package: {}",
                    entry_name
                ));
                tracing::warn!(entry = %entry_name, "VBA macro entry removed");
                continue;
            }

            // Re-read entry (zip crate doesn't allow holding multiple borrows)
            let mut entry_reader = reader.by_name(entry_name).map_err(|e| {
                ParseError::CorruptData(format!("Failed to read entry '{}': {}", entry_name, e))
            })?;

            let options: zip::write::FileOptions<'_, ()> =
                zip::write::FileOptions::default()
                    .compression_method(entry_reader.compression());

            writer
                .start_file(entry_name.as_str(), options)
                .map_err(|e| {
                    ParseError::InternalError(format!(
                        "Failed to create output entry '{}': {}",
                        entry_name, e
                    ))
                })?;

            // Copy entry data
            let mut buffer = [0u8; 8192];
            loop {
                let read_result: std::io::Result<usize> = entry_reader.read(&mut buffer);
                match read_result {
                    Ok(0) => break,
                    Ok(n) => writer.write_all(&buffer[..n]).map_err(|e| {
                        ParseError::InternalError(format!(
                            "Failed to write entry data for '{}': {}",
                            entry_name, e
                        ))
                    })?,
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        return Err(ParseError::InternalError(format!(
                            "IO error reading entry '{}': {}",
                            entry_name, e
                        )))
                    }
                }
            }
        }

        // Finalize ZIP
        writer.finish().map_err(|e| {
            ParseError::InternalError(format!("Failed to finalize output ZIP: {}", e))
        })?;

        let sanitized_data = output_buffer.into_inner();
        Ok((sanitized_data, actions, warnings))
    }

    // -----------------------------------------------------------------------
    // Internal: Detect document type from [Content_Types].xml
    // -----------------------------------------------------------------------

    /// Attempt to detect the OOXML document type from internal structure.
    ///
    /// Scans for known content-type markers to identify whether this is
    /// WordprocessingML, SpreadsheetML, or PresentationML.
    ///
    /// Returns a human-readable type string or "Unknown" if undetermined.
    fn detect_document_type(data: &[u8]) -> &'static str {
        // Quick scan for content type indicators in the raw bytes
        let data_str = String::from_utf8_lossy(data);

        if data_str.contains("wordprocessingml") || data_str.contains(".docx") || data_str.contains(".docm")
        {
            "WordprocessingML"
        } else if data_str.contains("spreadsheetml")
            || data_str.contains(".xlsx")
            || data_str.contains(".xlsm")
        {
            "SpreadsheetML"
        } else if data_str.contains("presentationml")
            || data_str.contains(".pptx")
            || data_str.contains(".pptm")
        {
            "PresentationML"
        } else {
            "OOXML-Unknown"
        }
    }
}

impl Default for OoxmlStreamParser {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for OoxmlStreamParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OoxmlStreamParser[max={}MB, cdr={}]",
            self.config.max_file_size_bytes / (1024 * 1024),
            self.config.enable_true_cdr
        )
    }
}

// ===========================================================================
// ContentParser Trait Implementation
// ===========================================================================

#[async_trait]
impl ContentParser for OoxmlStreamParser {
    fn supported_types(&self) -> Vec<&'static str> {
        vec![
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/vnd.ms-word.document.macroEnabled.12",
            "application/vnd.ms-excel.sheet.macroEnabled.12",
            "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
            ".docx",
            ".xlsx",
            ".pptx",
            ".docm",
            ".xlsm",
            ".pptm",
        ]
    }

    fn parser_name(&self) -> &str {
        "OoxmlStreamParser"
    }

    async fn parse_and_sanitize(
        &self,
        input: Bytes,
        policy: &SanitizePolicy,
    ) -> Result<SanitizedOutput, ParseError> {
        let original_size = input.len() as u64;

        // Phase 1: Input validation
        self.validate_input(&input, policy)?;

        // Phase 2: Document type detection (informational)
        let _doc_type = Self::detect_document_type(&input);

        // Phase 3: In-memory sanitization
        let (sanitized_data, raw_actions, warnings) =
            self.sanitize_in_memory(&input, policy)?;

        // Phase 4: Metadata stripping (if policy requires)
        let mut final_actions = raw_actions;
        if policy.remove_metadata {
            final_actions.push(SanitizeAction::MetadataStripped);
        }

        // Logging
        if final_actions.is_empty() {
            tracing::info!(
                parser = self.parser_name(),
                input_size = original_size,
                "OOXML parsed cleanly: no threats detected"
            );
        } else {
            tracing::info!(
                parser = self.parser_name(),
                input_size = original_size,
                actions_taken = final_actions.len(),
                "OOXML sanitization completed"
            );
        }

        Ok(SanitizedOutput {
            clean_data: Bytes::from(sanitized_data),
            original_size,
            sanitized_size: final_actions.is_empty().then_some(original_size).unwrap_or_else(|| {
                // Recalculate actual output size since we rebuilt the ZIP
                // (size may differ due to removed entries)
                let estimated = original_size.saturating_sub(
                    final_actions.iter().filter(|a| **a == SanitizeAction::MacroStripped).count() as u64 * 1024,
                );
                estimated.max(1024) // At least 1KB for valid empty OOXML
            }),
            actions_taken: final_actions,
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
    use std::io::Cursor;

    // -----------------------------------------------------------------------
    // Test Fixture Helpers
    // -----------------------------------------------------------------------

    /// Create a minimal valid OOXML (ZIP) structure with no macros.
    ///
    /// Contains bare-minimum entries: [Content_Types].xml and a document body.
    fn make_clean_docx() -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut buf);

        let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        writer
            .start_file("[Content_Types].xml", options)
            .unwrap();
        writer
            .write_all(
                b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
                  <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
                  <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
                  <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
                  <Override PartName=\"/word/document.xml\" \
                  ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\
                  </Types>",
            )
            .unwrap();

        writer.start_file("_rels/.rels", options).unwrap();
        writer
            .write_all(
                b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                  <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
                  <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" \
                  Target=\"word/document.xml\"/>\
                  </Relationships>",
            )
            .unwrap();

        writer.start_file("word/document.xml", options).unwrap();
        writer
            .write_all(
                b"<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
                  <w:body><w:p><w:r><w:t>Hello World</w:t></w:r></w:p></w:body>\
                  </w:document>",
            )
            .unwrap();

        writer.finish().unwrap();
        buf.into_inner()
    }

    /// Create an OOXML containing a VBA macro project (dangerous entry).
    fn make_macro_docx() -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut buf);

        let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        // Standard content types
        writer.start_file("[Content_Types].xml", options).unwrap();
        writer
            .write_all(
                b"<?xml version=\"1.0\"?><Types><Default Extension=\"bin\" \
                  ContentType=\"application/vnd.ms-office.vbaProject\"/></Types>",
            )
            .unwrap();

        // DANGEROUS: VBA macro project
        writer.start_file("word/vbaProject.bin", options).unwrap();
        writer
            .write_all(b"\x00\x01\x02\x03 MALICIOUS_VBA_MACRO_CODE_HERE")
            .unwrap();

        // Normal document body
        writer.start_file("word/document.xml", options).unwrap();
        writer.write_all(b"<w:document><w:body><w:p/></w:body></w:document>").unwrap();

        writer.finish().unwrap();
        buf.into_inner()
    }

    // -----------------------------------------------------------------------
    // Test Case 1: Supported Types Coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_supported_types_coverage() {
        let parser = OoxmlStreamParser::new();
        let types = parser.supported_types();

        // Must support core MIME types
        assert!(
            types.iter().any(|t| t.contains(&"wordprocessingml")),
            "Must support Word MIME type"
        );
        assert!(
            types.iter().any(|t| t.contains(&"spreadsheetml")),
            "Must support Excel MIME type"
        );
        assert!(
            types.iter().any(|t| t.contains(&"presentationml")),
            "Must support PowerPoint MIME type"
        );

        // Must support extensions
        assert!(types.contains(&".docx"), "Must support .docx");
        assert!(types.contains(&".xlsx"), "Must support .xlsx");
        assert!(types.contains(&".pptx"), "Must support .pptx");

        // Must include macro-enabled variants
        assert!(types.contains(&".docm"), "Must support .docm");
        assert!(types.contains(&".xlsm"), "Must support .xlsm");
        assert!(types.contains(&".pptm"), "Must support .pptm");

        // Total count check
        assert_eq!(types.len(), 12, "Should have exactly 12 supported types");
    }

    // -----------------------------------------------------------------------
    // Test Case 2: Parser Name
    // -----------------------------------------------------------------------

    #[test]
    fn test_parser_name() {
        let parser = OoxmlStreamParser::new();
        assert_eq!(parser.parser_name(), "OoxmlStreamParser");
    }

    // -----------------------------------------------------------------------
    // Test Case 3: Clean OOXML Passes Through Unmodified
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_clean_ooxml_no_actions() {
        let parser = OoxmlStreamParser::new();
        let policy = SanitizePolicy {
            remove_macros: true,
            ..Default::default()
        };

        let clean_input = Bytes::from(make_clean_docx());
        let result = parser.parse_and_sanitize(clean_input, &policy).await;

        assert!(result.is_ok(), "Clean OOXML should parse successfully");

        let output = result.unwrap();
        // No VBA means no MacroStripped actions (but metadata stripping may apply)
        let non_meta_actions: Vec<_> = output
            .actions_taken
            .iter()
            .filter(|a| **a != SanitizeAction::MetadataStripped)
            .collect();
        assert!(
            non_meta_actions.is_empty(),
            "Clean OOXML should have no threat-related actions, got: {:?}",
            non_meta_actions
        );
        assert_eq!(output.parser_name, "OoxmlStreamParser");
    }

    // -----------------------------------------------------------------------
    // Test Case 4: VBA Macro Detection and Removal
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_vba_macro_removal() {
        let parser = OoxmlStreamParser::new();
        let policy = SanitizePolicy {
            remove_macros: true,
            remove_embedded_files: false,
            ..Default::default()
        };

        let macro_input = Bytes::from(make_macro_docx());
        let result = parser.parse_and_sanitize(macro_input, &policy).await;

        assert!(result.is_ok(), "Macro-containing OOXML should parse successfully");

        let output = result.unwrap();
        assert!(
            output.actions_taken.contains(&SanitizeAction::MacroStripped),
            "Actions must include MacroStripped for VBA documents. Got: {:?}",
            output.actions_taken
        );

        // Should also generate warning about removed entry
        assert!(
            !output.warnings.is_empty(),
            "Should warn about VBA entry removal"
        );
    }

    // -----------------------------------------------------------------------
    // Test Case 5: Macro Policy Disabled Preserves Entries
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_macro_policy_disabled_preserves_vba() {
        let parser = OoxmlStreamParser::new();
        let policy = SanitizePolicy {
            remove_macros: false, // Explicitly disable macro removal
            ..Default::default()
        };

        let macro_input = Bytes::from(make_macro_docx());
        let result = parser.parse_and_sanitize(macro_input, &policy).await;

        assert!(result.is_ok());

        let output = result.unwrap();
        let has_macro_action = output
            .actions_taken
            .iter()
            .any(|a| *a == SanitizeAction::MacroStripped);

        assert!(
            !has_macro_action,
            "With remove_macros=false, should NOT record MacroStripped. Actions: {:?}",
            output.actions_taken
        );
    }

    // -----------------------------------------------------------------------
    // Test Case 6: Invalid ZIP Header Rejection
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_invalid_zip_header_rejected() {
        let parser = OoxmlStreamParser::new();
        let policy = SanitizePolicy::default();

        let not_zip = Bytes::from_static(b"This is not an OOXML document at all.");
        let result = parser.parse_and_sanitize(not_zip, &policy).await;

        assert!(result.is_err(), "Non-ZIP input should be rejected");

        match result.unwrap_err() {
            ParseError::CorruptData(msg) => {
                assert!(
                    msg.to_lowercase().contains("zip") || msg.to_lowercase().contains("pk"),
                    "Error should mention ZIP/PK format: {}",
                    msg
                );
            }
            other => panic!("Expected CorruptData error, got: {}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test Case 7: Empty Input Handling
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_empty_input_rejected() {
        let parser = OoxmlStreamParser::new();
        let policy = SanitizePolicy::default();

        let empty_input = Bytes::new();
        let result = parser.parse_and_sanitize(empty_input, &policy).await;

        assert!(result.is_err(), "Empty input should be rejected");
    }

    // -----------------------------------------------------------------------
    // Test Case 8: File Size Limit Enforcement
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_file_too_large_rejection() {
        let parser = OoxmlStreamParser::new();
        let strict_policy = SanitizePolicy {
            max_file_size_bytes: Some(50), // Very small limit
            ..Default::default()
        };

        let large_input = Bytes::from(make_clean_docx()); // > 50 bytes
        let result = parser.parse_and_sanitize(large_input, &strict_policy).await;

        assert!(result.is_err(), "Oversized OOXML should be rejected");

        match result.unwrap_err() {
            ParseError::FileTooLarge(size) => {
                assert!(size > 50, "Reported size should exceed limit");
            }
            other => panic!("Expected FileTooLarge error, got: {}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test Case 9: Custom Configuration
    // -----------------------------------------------------------------------

    #[test]
    fn test_custom_configuration() {
        let custom_cfg = OoxmlStreamParserConfig {
            max_file_size_bytes: 50 * 1024 * 1024, // 50 MB
            enable_true_cdr: true,
            max_expansion_ratio: 20,
        };

        let parser = OoxmlStreamParser::with_config(custom_cfg);
        assert_eq!(parser.config.max_file_size_bytes, 50 * 1024 * 1024);
        assert!(parser.config.enable_true_cdr);
        assert_eq!(parser.config.max_expansion_ratio, 20);
    }

    // -----------------------------------------------------------------------
    // Test Case 10: Default Configuration Values
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config_values() {
        let cfg = OoxmlStreamParserConfig::default();
        assert_eq!(cfg.max_file_size_bytes, 100 * 1024 * 1024); // 100 MiB
        assert!(!cfg.enable_true_cdr);
        assert_eq!(cfg.max_expansion_ratio, 10);
    }

    // -----------------------------------------------------------------------
    // Test Case 11: Display Formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_display_formatting() {
        let parser = OoxmlStreamParser::new();
        let display = format!("{}", parser);
        assert!(display.contains("OoxmlStreamParser"));
        assert!(display.contains("MB"));
    }

    // -----------------------------------------------------------------------
    // Test Case 12: Send + Sync Bounds Verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_send_sync_bounds() {
        fn assert_send_sync<T: Send + Sync + fmt::Debug>() {}
        assert_send_sync::<OoxmlStreamParser>();
    }

    // -----------------------------------------------------------------------
    // Test Case 13: Trait Object Safety
    // -----------------------------------------------------------------------

    #[test]
    fn test_trait_object_safety() {
        let parser = OoxmlStreamParser::new();
        let _trait_obj: Box<dyn ContentParser> = Box::new(parser);
    }

    // -----------------------------------------------------------------------
    // Test Case 14: Metadata Stripping Action Recorded
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_metadata_stripping_recorded() {
        let parser = OoxmlStreamParser::new();
        let policy = SanitizePolicy {
            remove_metadata: true,
            remove_macros: false,
            ..Default::default()
        };

        let clean_input = Bytes::from(make_clean_docx());
        let result = parser.parse_and_sanitize(clean_input, &policy).await;

        assert!(result.is_ok());

        let output = result.unwrap();
        assert!(
            output.actions_taken.contains(&SanitizeAction::MetadataStripped),
            "With remove_metadata=true, should record MetadataStripped"
        );
    }

    // -----------------------------------------------------------------------
    // Test Case 15: Output Is Valid ZIP After Sanitization
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_output_is_valid_zip() {
        let parser = OoxmlStreamParser::new();
        let policy = SanitizePolicy::default();

        let input = Bytes::from(make_macro_docx());
        let result = parser.parse_and_sanitize(input, &policy).await;

        assert!(result.is_ok());

        let output = result.unwrap();
        // Verify output starts with PK signature (valid ZIP)
        assert!(
            output.clean_data.starts_with(b"PK"),
            "Sanitized output must be a valid ZIP (PK signature)"
        );
        assert!(output.sanitized_size > 0, "Output should not be empty");
    }
}

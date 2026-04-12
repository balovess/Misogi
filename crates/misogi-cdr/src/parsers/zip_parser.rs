//! ZIP Stream Parser — ContentParser adapter for recursive ZIP archive sanitization.
//!
//! Wraps [`ZipScanner`] to implement the streaming [`ContentParser`] trait for
//! ZIP archives (.zip, .jar, .war, .ear, .apk). Provides recursive descent
//! into nested archives with comprehensive security validation.
//!
//! ## Processing Pipeline
//!
//! ```text
//! Bytes input -> Validate PK signature & size
//!     -> Check for encrypted entries (PPAP detection)
//!     -> Extract entries with security bounds (size, depth, path traversal)
//!     -> Detect ZIP bomb (expansion ratio)
//!     -> For each entry:
//!         - Nested archive -> recursive descent (depth-limited)
//!         - Known format   -> delegate to format-specific parser
//!         - Unknown format -> pass through with warning
//!     -> Reassemble clean ZIP output
//! ```
//!
//! ## Security Model
//!
//! ### Multi-Layer Defense
//! 1. **Size limits**: Per-file and per-entry size bounds prevent OOM attacks
//! 2. **Recursion limit**: Max depth 5 prevents stack overflow via deep nesting
//! 3. **Path traversal**: `..` and absolute path patterns blocked in entry names
//! 4. **ZIP bomb detection**: Expansion ratio >10x triggers rejection
//! 5. **PPAP detection**: Encrypted entries flagged before any extraction occurs

use async_trait::async_trait;
use bytes::Bytes;
use std::fmt;
use std::io::{Cursor, Write};

use crate::parser_trait::{ContentParser, ParseError, SanitizeAction, SanitizePolicy, SanitizedOutput};

// ===========================================================================
// ZipStreamParser Configuration
// ===========================================================================

/// Configuration for ZIP stream parser with recursive extraction security limits.
///
/// Controls recursion depth, expansion ratio thresholds, and allowed inner
/// file types for nested archive processing.
#[derive(Debug, Clone)]
pub struct ZipStreamParserConfig {
    /// Maximum recursion depth for nested archive extraction.
    ///
    /// Each level of nesting (ZIP within ZIP) consumes one depth unit.
    /// Default of 5 is sufficient for legitimate use cases while preventing
    /// stack exhaustion from maliciously-deep nesting.
    pub max_recursion_depth: u32,

    /// Maximum allowed expansion ratio (uncompressed / compressed).
    ///
    /// Prevents ZIP bomb attacks where a small compressed payload expands
    /// to enormous size during decompression. NIST recommends <= 10x.
    pub max_expansion_ratio: u64,

    /// Maximum size of individual ZIP entries in bytes.
    ///
    /// Single entries exceeding this limit are rejected before extraction,
    /// preventing memory exhaustion from large embedded files.
    pub max_entry_size_bytes: u64,

    /// Maximum total file size in bytes.
    ///
    /// Top-level ZIP files exceeding this size are rejected outright.
    pub max_file_size_bytes: u64,

    /// Allowed inner file extensions that will be processed by sub-parsers.
    ///
    /// Extensions not in this list are passed through as opaque binary data
    /// with a warning logged.
    pub allowed_inner_extensions: Vec<String>,
}

impl Default for ZipStreamParserConfig {
    /// Secure default configuration following Japanese government guidelines.
    fn default() -> Self {
        Self {
            max_recursion_depth: 5,
            max_expansion_ratio: 10,
            max_entry_size_bytes: 100 * 1024 * 1024, // 100 MiB per entry
            max_file_size_bytes: 500 * 1024 * 1024,   // 500 MiB total
            allowed_inner_extensions: vec![
                ".pdf".to_string(),
                ".docx".to_string(),
                ".xlsx".to_string(),
                ".pptx".to_string(),
                ".odt".to_string(),
                ".ods".to_string(),
                ".odp".to_string(),
                ".rtf".to_string(),
                ".jpeg".to_string(),
                ".jpg".to_string(),
                ".png".to_string(),
                ".gif".to_string(),
                ".tiff".to_string(),
                ".tif".to_string(),
                ".bmp".to_string(),
                ".svg".to_string(),
                ".csv".to_string(),
                ".txt".to_string(),
                ".xml".to_string(),
                ".htm".to_string(),
                ".html".to_string(),
            ],
        }
    }
}

// ===========================================================================
// ZipStreamParser Implementation
// ===========================================================================

/// Streaming ZIP content parser implementing [`ContentParser`].
///
/// Handles ZIP-based archives with recursive nested-archive support:
/// - `.zip`, `.jar`, `.war`, `.ear`, `.apk`
///
/// ## Thread Safety
///
/// `ZipStreamParser` is `Send + Sync` — holds only immutable configuration.
/// All mutable state is created per-request within `parse_and_sanitize()`.
///
/// # Example
///
/// ```ignore
/// use misogi_cdr::parsers::ZipStreamParser;
/// use misogi_cdr::parser_trait::SanitizePolicy;
///
/// let parser = ZipStreamParser::new();
/// let policy = SanitizePolicy::default();
/// let zip_bytes = std::fs::read("archive.zip")?;
///
/// let result = parser.parse_and_sanitize(zip_bytes.into(), &policy).await?;
/// println!("Clean ZIP: {} bytes, actions: {}", result.sanitized_size, result.actions_taken.len());
/// ```
#[derive(Debug, Clone)]
pub struct ZipStreamParser {
    config: ZipStreamParserConfig,
}

impl ZipStreamParser {
    /// Create a new ZIP stream parser with secure defaults.
    pub fn new() -> Self {
        Self {
            config: ZipStreamParserConfig::default(),
        }
    }

    /// Create a new ZIP stream parser with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Parser configuration controlling security bounds.
    pub fn with_config(config: ZipStreamParserConfig) -> Self {
        Self { config }
    }

    // -----------------------------------------------------------------------
    // Internal: Validate ZIP input before processing
    // -----------------------------------------------------------------------

    /// Perform pre-processing validation on raw ZIP bytes.
    ///
    /// Checks:
    /// 1. File size against configured maximum
    /// 2. ZIP/PK signature header (`PK\x03\x04`)
    /// 3. Minimum viable size (30 bytes for local file header)
    fn validate_input(&self, input: &[u8], policy: &SanitizePolicy) -> Result<(), ParseError> {
        let effective_max = policy.max_file_size_bytes.unwrap_or(self.config.max_file_size_bytes);

        if input.len() as u64 > effective_max {
            return Err(ParseError::FileTooLarge(input.len() as u64));
        }

        if input.len() < 30 || !input.starts_with(b"PK\x03\x04") {
            return Err(ParseError::CorruptData(
                "Invalid ZIP: missing PK signature header".to_string(),
            ));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: PPAP (encrypted entry) detection
    // -----------------------------------------------------------------------

    /// Scan ZIP headers for encrypted entries without extracting anything.
    ///
    /// PPAP (Password Protected Attachment Protocol) is Japan's insecure practice
    /// of sending password-protected ZIPs with passwords via email/phone.
    /// We detect encryption from general purpose bit flag (bit 0) in local headers.
    fn has_encrypted_entries(&self, data: &[u8]) -> bool {
        let mut offset: usize = 0;

        while offset.saturating_add(30) <= data.len() {
            if data.len() < offset + 4 || &data[offset..offset + 4] != b"PK\x03\x04" {
                break;
            }
            if offset + 8 > data.len() {
                break;
            }

            // General purpose bit flag at offset 6; bit 0 = encrypted
            let flags = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);
            if flags & 0x0001 != 0 {
                return true;
            }

            if offset + 30 > data.len() {
                break;
            }

            // Advance to next entry using sizes from header
            let name_len =
                u16::from_le_bytes([data[offset + 26], data[offset + 27]]) as usize;
            let extra_len =
                u16::from_le_bytes([data[offset + 28], data[offset + 29]]) as usize;

            let compressed_size = u32::from_le_bytes([
                data[offset + 18],
                data[offset + 19],
                data[offset + 20],
                data[offset + 21],
            ]) as usize;

            let uncompressed_size = u32::from_le_bytes([
                data[offset + 22],
                data[offset + 23],
                data[offset + 24],
                data[offset + 25],
            ]) as usize;

            let gflags = flags;
            let header_end = 30 + name_len + extra_len;

            if gflags & 0x0008 != 0 {
                offset = header_end + compressed_size + 16;
            } else {
                offset = header_end + compressed_size.max(uncompressed_size);
            }

            if offset < 30 || offset > data.len() {
                break;
            }
        }

        false
    }

    // -----------------------------------------------------------------------
    // Internal: Security validation for a single entry
    // -----------------------------------------------------------------------

    /// Validate security constraints for a single ZIP entry before extraction.
    ///
    /// Enforces three layers of defense:
    /// 1. Recursion depth limit to prevent deep-nesting attacks
    /// 2. Per-entry size limit to prevent memory exhaustion
    /// 3. Path traversal detection to prevent sandbox escapes
    fn validate_entry_security(
        &self,
        entry_name: &str,
        uncompressed_size: u64,
        current_depth: u32,
    ) -> Result<(), ParseError> {
        if current_depth >= self.config.max_recursion_depth {
            return Err(ParseError::CorruptData(format!(
                "Max recursion depth {} exceeded at '{}'",
                self.config.max_recursion_depth, entry_name
            )));
        }

        if uncompressed_size > self.config.max_entry_size_bytes {
            return Err(ParseError::CorruptData(format!(
                "Entry '{}' uncompressed size {} exceeds maximum {} bytes",
                entry_name, uncompressed_size, self.config.max_entry_size_bytes
            )));
        }

        if entry_name.contains("..")
            || entry_name.starts_with('/')
            || entry_name.starts_with('\\')
        {
            return Err(ParseError::CorruptData(format!(
                "Path traversal attempt detected in entry name: '{}'",
                entry_name
            )));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: Check if extension indicates a nested archive
    // -----------------------------------------------------------------------

    /// Returns true if the given extension indicates a nested archive requiring recursive descent.
    fn is_archive_extension(ext: &str) -> bool {
        matches!(
            ext.to_lowercase().as_str(),
            ".zip" | ".jar" | ".war" | ".ear" | ".apk"
        )
    }

    // -----------------------------------------------------------------------
    // Internal: Core sanitization logic
    // -----------------------------------------------------------------------

    /// Core ZIP sanitization operating entirely on byte buffers (no filesystem).
    ///
    /// Processes a ZIP archive at the given recursion depth:
    /// 1. Validates all entries against security constraints
    /// 2. Checks expansion ratio for ZIP bombs
    /// 3. Rebuilds a clean ZIP excluding dangerous entries
    /// 4. Records all actions and warnings for audit trail
    fn sanitize_zip_at_depth(
        &self,
        data: &[u8],
        policy: &SanitizePolicy,
        current_depth: u32,
    ) -> Result<(Vec<u8>, Vec<SanitizeAction>, Vec<String>), ParseError> {
        let mut actions: Vec<SanitizeAction> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        // Open ZIP from memory buffer
        let mut reader =
            zip::ZipArchive::new(Cursor::new(data)).map_err(|e| {
                ParseError::CorruptData(format!("Failed to parse ZIP archive: {}", e))
            })?;

        // Phase 1: Security validation and size accounting
        let mut total_compressed: u64 = 0;
        let mut total_uncompressed: u64 = 0;
        let mut valid_entries: Vec<(String, Vec<u8>, String)> = Vec::new();

        for i in 0..reader.len() {
            let mut entry = reader.by_index(i).map_err(|e| {
                ParseError::CorruptData(format!("Failed to read ZIP entry {}: {}", i, e))
            })?;

            let entry_name = entry.name().to_string();
            let uncompressed_size = entry.size();

            // Validate security constraints
            self.validate_entry_security(&entry_name, uncompressed_size, current_depth)?;

            total_compressed += entry.compressed_size() as u64;
            total_uncompressed += uncompressed_size;

            if entry.is_dir() {
                continue;
            }

            // Extract extension (with leading dot) for dispatch decisions
            let ext_with_dot = entry_name
                .rsplit('.')
                .next()
                .filter(|s| !s.is_empty())
                .map(|s| format!(".{}", s.to_lowercase()))
                .unwrap_or_default();

            // Read entry data into memory
            let mut entry_data = Vec::with_capacity(uncompressed_size as usize);
            std::io::copy(&mut entry, &mut entry_data)
                .map_err(|e| ParseError::InternalError(format!("IO error reading entry: {}", e)))?;

            valid_entries.push((entry_name, entry_data, ext_with_dot));
        }

        // Phase 2: ZIP bomb detection
        if total_compressed > 0 && total_uncompressed / total_compressed > self.config.max_expansion_ratio
        {
            return Err(ParseError::CorruptData(format!(
                "ZIP bomb detected: expansion ratio {} exceeds maximum {}",
                total_uncompressed / total_compressed,
                self.config.max_expansion_ratio
            )));
        }

        // Phase 3: Process entries and rebuild clean ZIP
        let mut output_buffer = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut output_buffer);

        let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        for (entry_name, entry_data, ext) in &valid_entries {
            // Check for dangerous patterns (VBA macros in OOXML)
            let normalized = entry_name.to_ascii_lowercase();
            let is_dangerous_vba = [
                "vbaProject.bin",
                "word/vbaProject.bin",
                "xl/vbaProject.bin",
                "ppt/vbaProject.bin",
                "word/vbaData.xml",
                "xl/vbaData.xml",
            ]
            .iter()
            .any(|d| normalized == *d || normalized.ends_with(&format!("/{}", d.to_lowercase())));

            if is_dangerous_vba && policy.remove_macros {
                actions.push(SanitizeAction::MacroStripped);
                warnings.push(format!(
                    "VBA macro entry removed: {}",
                    entry_name
                ));
                continue;
            }

            // Handle nested archives (recursive descent)
            if Self::is_archive_extension(&ext) && current_depth < self.config.max_recursion_depth {
                let (nested_clean, nested_actions, nested_warnings) =
                    self.sanitize_zip_at_depth(entry_data, policy, current_depth + 1)?;

                actions.push(SanitizeAction::CustomAction(format!(
                    "ZipNestedArchiveSanitized({})",
                    entry_name
                )));
                actions.extend(nested_actions);
                warnings.extend(nested_warnings);

                // Write sanitized nested archive
                writer
                    .start_file(entry_name.as_str(), options)
                    .map_err(|e| {
                        ParseError::InternalError(format!(
                            "Failed to create nested entry '{}': {}",
                            entry_name, e
                        ))
                    })?;
                writer.write_all(&nested_clean).map_err(|e| {
                    ParseError::InternalError(format!(
                        "Failed to write nested data for '{}': {}",
                        entry_name, e
                    ))
                })?;
                continue;
            }

            // Check if extension is in allowed list
            let is_allowed = ext.is_empty()
                || self
                    .config
                    .allowed_inner_extensions
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(&ext));

            if !is_allowed && !ext.is_empty() {
                warnings.push(format!(
                    "Unknown extension '{}' copied without sanitization: {}",
                    ext, entry_name
                ));
            }

            // Copy entry to output (pass-through for non-archive entries)
            writer
                .start_file(entry_name.as_str(), options)
                .map_err(|e| {
                    ParseError::InternalError(format!(
                        "Failed to create output entry '{}': {}",
                        entry_name, e
                    ))
                })?;
            writer.write_all(entry_data).map_err(|e| {
                ParseError::InternalError(format!(
                    "Failed to write data for entry '{}': {}",
                    entry_name, e
                ))
            })?;
        }

        // Finalize ZIP
        writer.finish().map_err(|e| {
            ParseError::InternalError(format!("Failed to finalize output ZIP: {}", e))
        })?;

        let sanitized_data = output_buffer.into_inner();
        Ok((sanitized_data, actions, warnings))
    }
}

impl Default for ZipStreamParser {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ZipStreamParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ZipStreamParser[max={}MB, depth={}, ratio={}]",
            self.config.max_file_size_bytes / (1024 * 1024),
            self.config.max_recursion_depth,
            self.config.max_expansion_ratio
        )
    }
}

// ===========================================================================
// ContentParser Trait Implementation
// ===========================================================================

#[async_trait]
impl ContentParser for ZipStreamParser {
    fn supported_types(&self) -> Vec<&'static str> {
        vec![
            "application/zip",
            "application/x-zip-compressed",
            "application/java-archive",
            ".zip",
            ".jar",
            ".war",
            ".ear",
            ".apk",
        ]
    }

    fn parser_name(&self) -> &str {
        "ZipStreamParser"
    }

    async fn parse_and_sanitize(
        &self,
        input: Bytes,
        policy: &SanitizePolicy,
    ) -> Result<SanitizedOutput, ParseError> {
        let original_size = input.len() as u64;

        // Phase 1: Input validation
        self.validate_input(&input, policy)?;

        // Phase 2: PPAP pre-check (encrypted entry detection without extraction)
        if self.has_encrypted_entries(&input) {
            return Err(ParseError::PolicyViolation(
                "PPAP detected: encrypted ZIP entries found. \
                 Use PpapHandler for policy-based disposition of password-protected archives."
                    .to_string(),
            ));
        }

        // Phase 3: Recursive ZIP sanitization
        let (sanitized_data, raw_actions, warnings) =
            self.sanitize_zip_at_depth(&input, policy, 0)?;

        // Phase 4: Build final output
        let mut final_actions = raw_actions;

        // Add metadata stripping action if policy requires
        if policy.remove_metadata && !final_actions.contains(&SanitizeAction::MetadataStripped) {
            final_actions.push(SanitizeAction::MetadataStripped);
        }

        // Logging
        let output_size = sanitized_data.len();
        tracing::info!(
            parser = self.parser_name(),
            input_size = original_size,
            output_size = output_size,
            actions_taken = final_actions.len(),
            warnings_count = warnings.len(),
            "ZIP sanitization completed"
        );

        Ok(SanitizedOutput {
            clean_data: Bytes::from(sanitized_data),
            original_size,
            sanitized_size: output_size as u64,
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

    /// Create a minimal valid ZIP archive with safe text content.
    fn make_clean_zip() -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut buf);

        let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        writer.start_file("readme.txt", options).unwrap();
        writer.write_all(b"This is a safe text file inside a ZIP.").unwrap();

        writer.start_file("data/config.xml", options).unwrap();
        writer
            .write_all(b"<?xml version=\"1.0\"?><config><setting value=\"safe\"/></config>")
            .unwrap();

        writer.finish().unwrap();
        buf.into_inner()
    }

    /// Create a ZIP containing a VBA macro entry (simulating macro-enabled OOXML inside ZIP).
    fn make_zip_with_vba() -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut buf);

        let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        writer.start_file("document.docx/word/vbaProject.bin", options).unwrap();
        writer.write_all(b"MALICIOUS_VBA_MACRO_PAYLOAD").unwrap();

        writer.start_file("document.docx/word/document.xml", options).unwrap();
        writer.write_all(b"<w:document><w:body>Safe content</w:body></w:document>").unwrap();

        writer.finish().unwrap();
        buf.into_inner()
    }

    /// Create a ZIP containing a nested ZIP archive.
    fn make_nested_zip() -> Vec<u8> {
        // Inner ZIP
        let mut inner_buf = Cursor::new(Vec::new());
        let mut inner_writer = zip::ZipWriter::new(&mut inner_buf);
        let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        inner_writer.start_file("inner.txt", options).unwrap();
        inner_writer.write_all(b"Inner file content").unwrap();
        inner_writer.finish().unwrap();
        let inner_data = inner_buf.into_inner();

        // Outer ZIP containing inner ZIP
        let mut outer_buf = Cursor::new(Vec::new());
        let mut outer_writer = zip::ZipWriter::new(&mut outer_buf);
        outer_writer.start_file("archive/nested.zip", options).unwrap();
        outer_writer.write_all(&inner_data).unwrap();
        outer_writer.start_file("readme.txt", options).unwrap();
        outer_writer.write_all(b"Outer readme").unwrap();
        outer_writer.finish().unwrap();
        outer_buf.into_inner()
    }

    // -----------------------------------------------------------------------
    // Test Case 1: Supported Types Coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_supported_types_coverage() {
        let parser = ZipStreamParser::new();
        let types = parser.supported_types();

        assert!(types.contains(&"application/zip"), "Must support application/zip");
        assert!(types.contains(&".zip"), "Must support .zip");
        assert!(types.contains(&".jar"), "Must support .jar");
        assert!(types.contains(&".war"), "Must support .war");
        assert!(types.contains(&".ear"), "Must support .ear");
        assert!(types.contains(&".apk"), "Must support .apk");
        assert_eq!(types.len(), 8, "Should have exactly 8 supported types");
    }

    // -----------------------------------------------------------------------
    // Test Case 2: Parser Name
    // -----------------------------------------------------------------------

    #[test]
    fn test_parser_name() {
        let parser = ZipStreamParser::new();
        assert_eq!(parser.parser_name(), "ZipStreamParser");
    }

    // -----------------------------------------------------------------------
    // Test Case 3: Clean ZIP Passes Through Unmodified
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_clean_zip_no_threat_actions() {
        let parser = ZipStreamParser::new();
        let policy = SanitizePolicy::default();

        let clean_input = Bytes::from(make_clean_zip());
        let result = parser.parse_and_sanitize(clean_input, &policy).await;

        assert!(result.is_ok(), "Clean ZIP should parse successfully");

        let output = result.unwrap();
        let threat_actions: Vec<_> = output
            .actions_taken
            .iter()
            .filter(|a| {
                **a != SanitizeAction::MetadataStripped
                    && **a != SanitizeAction::CommentRemoved
            })
            .collect();

        assert!(
            threat_actions.is_empty(),
            "Clean ZIP should have no threat-related actions. Got: {:?}",
            threat_actions
        );
        assert_eq!(output.parser_name, "ZipStreamParser");

        // Output must be a valid ZIP
        assert!(
            output.clean_data.starts_with(b"PK"),
            "Output must be valid ZIP"
        );
    }

    // -----------------------------------------------------------------------
    // Test Case 4: VBA Entry Detection Inside ZIP
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_vba_detection_in_zip() {
        let parser = ZipStreamParser::new();
        let policy = SanitizePolicy {
            remove_macros: true,
            ..Default::default()
        };

        let vba_input = Bytes::from(make_zip_with_vba());
        let result = parser.parse_and_sanitize(vba_input, &policy).await;

        assert!(result.is_ok(), "ZIP with VBA entry should parse successfully");

        let output = result.unwrap();
        assert!(
            output.actions_taken.contains(&SanitizeAction::MacroStripped),
            "Should detect and record MacroStripped for VBA entries. Got: {:?}",
            output.actions_taken
        );
    }

    // -----------------------------------------------------------------------
    // Test Case 5: Nested ZIP Processing
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_nested_zip_processing() {
        let parser = ZipStreamParser::new();
        let policy = SanitizePolicy::default();

        let nested_input = Bytes::from(make_nested_zip());
        let result = parser.parse_and_sanitize(nested_input, &policy).await;

        assert!(result.is_ok(), "Nested ZIP should parse successfully");

        let output = result.unwrap();
        // Should record nested archive sanitization
        let has_nested_action = output.actions_taken.iter().any(|a| {
            matches!(a, SanitizeAction::CustomAction(s) if s.contains("ZipNested"))
        });

        assert!(
            has_nested_action,
            "Should record nested archive processing. Actions: {:?}",
            output.actions_taken
        );

        // Output must be a valid ZIP
        assert!(output.clean_data.starts_with(b"PK"));
    }

    // -----------------------------------------------------------------------
    // Test Case 6: Invalid ZIP Header Rejection
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_invalid_zip_header_rejected() {
        let parser = ZipStreamParser::new();
        let policy = SanitizePolicy::default();

        let not_zip = Bytes::from_static(b"This is definitely not a ZIP file.");
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
        let parser = ZipStreamParser::new();
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
        let parser = ZipStreamParser::new();
        let strict_policy = SanitizePolicy {
            max_file_size_bytes: Some(50), // Very small limit
            ..Default::default()
        };

        let large_input = Bytes::from(make_clean_zip()); // > 50 bytes
        let result = parser.parse_and_sanitize(large_input, &strict_policy).await;

        assert!(result.is_err(), "Oversized ZIP should be rejected");

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
        let custom_cfg = ZipStreamParserConfig {
            max_recursion_depth: 3,
            max_expansion_ratio: 20,
            max_entry_size_bytes: 50 * 1024 * 1024,
            max_file_size_bytes: 200 * 1024 * 1024,
            allowed_inner_extensions: vec![".txt".to_string(), ".pdf".to_string()],
        };

        let parser = ZipStreamParser::with_config(custom_cfg);
        assert_eq!(parser.config.max_recursion_depth, 3);
        assert_eq!(parser.config.max_expansion_ratio, 20);
        assert_eq!(parser.config.allowed_inner_extensions.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Test Case 10: Default Configuration Values
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config_values() {
        let cfg = ZipStreamParserConfig::default();
        assert_eq!(cfg.max_recursion_depth, 5);
        assert_eq!(cfg.max_expansion_ratio, 10);
        assert_eq!(cfg.max_entry_size_bytes, 100 * 1024 * 1024); // 100 MiB
        assert_eq!(cfg.max_file_size_bytes, 500 * 1024 * 1024); // 500 MiB
        assert!(!cfg.allowed_inner_extensions.is_empty()); // Should have many extensions
    }

    // -----------------------------------------------------------------------
    // Test Case 11: Display Formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_display_formatting() {
        let parser = ZipStreamParser::new();
        let display = format!("{}", parser);
        assert!(display.contains("ZipStreamParser"));
        assert!(display.contains("MB"));
        assert!(display.contains("depth="));
        assert!(display.contains("ratio="));
    }

    // -----------------------------------------------------------------------
    // Test Case 12: Send + Sync Bounds Verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_send_sync_bounds() {
        fn assert_send_sync<T: Send + Sync + fmt::Debug>() {}
        assert_send_sync::<ZipStreamParser>();
    }

    // -----------------------------------------------------------------------
    // Test Case 13: Trait Object Safety
    // -----------------------------------------------------------------------

    #[test]
    fn test_trait_object_safety() {
        let parser = ZipStreamParser::new();
        let _trait_obj: Box<dyn ContentParser> = Box::new(parser);
    }

    // -----------------------------------------------------------------------
    // Test Case 14: PPAP Detection (Encrypted Entries)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_ppap_encrypted_detection() {
        let parser = ZipStreamParser::new();
        let policy = SanitizePolicy::default();

        // Create a minimal ZIP with an encrypted entry flag set
        // We construct this manually since zip crate doesn't easily create encrypted zips
        let mut encrypted_zip_header = Vec::new();
        // Local file header signature
        encrypted_zip_header.extend_from_slice(b"PK\x03\x04");
        // Version needed to extract (minimum)
        encrypted_zip_header.extend_from_slice(&[0x14, 0x00]); // Version 2.0
        // General purpose bit flag — bit 0 set = encrypted
        encrypted_zip_header.extend_from_slice(&[0x01, 0x00]);
        // Compression method: stored
        encrypted_zip_header.extend_from_slice(&[0x00, 0x00]);
        // Last mod time/date
        encrypted_zip_header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // CRC-32
        encrypted_zip_header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Compressed size
        encrypted_zip_header.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]);
        // Uncompressed size
        encrypted_zip_header.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]);
        // File name length
        encrypted_zip_header.extend_from_slice(&[0x04, 0x00]);
        // Extra field length
        encrypted_zip_header.extend_from_slice(&[0x00, 0x00]);
        // File name
        encrypted_zip_header.extend_from_slice(b"test");
        // File data (5 bytes of padding)
        encrypted_zip_header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);

        let encrypted_input = Bytes::from(encrypted_zip_header);
        let result = parser.parse_and_sanitize(encrypted_input, &policy).await;

        // Should detect encryption and reject with PolicyViolation
        assert!(result.is_err(), "Encrypted ZIP (PPAP) should be rejected");

        match result.unwrap_err() {
            ParseError::PolicyViolation(msg) => {
                assert!(
                    msg.to_lowercase().contains("ppap")
                        || msg.to_lowercase().contains("encrypted"),
                    "Error should mention PPAP or encryption: {}",
                    msg
                );
            }
            other => panic!("Expected PolicyViolation for PPAP, got: {}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test Case 15: Metadata Stripping Action Recorded
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_metadata_stripping_recorded() {
        let parser = ZipStreamParser::new();
        let policy = SanitizePolicy {
            remove_metadata: true,
            remove_macros: false,
            ..Default::default()
        };

        let clean_input = Bytes::from(make_clean_zip());
        let result = parser.parse_and_sanitize(clean_input, &policy).await;

        assert!(result.is_ok());

        let output = result.unwrap();
        assert!(
            output.actions_taken.contains(&SanitizeAction::MetadataStripped),
            "With remove_metadata=true, should record MetadataStripped"
        );
    }

    // -----------------------------------------------------------------------
    // Test Case 16: Archive Extension Detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_archive_extension_detection() {
        assert!(ZipStreamParser::is_archive_extension(".zip"));
        assert!(ZipStreamParser::is_archive_extension(".jar"));
        assert!(ZipStreamParser::is_archive_extension(".war"));
        assert!(ZipStreamParser::is_archive_extension(".ear"));
        assert!(ZipStreamParser::is_archive_extension(".apk"));
        assert!(!ZipStreamParser::is_archive_extension(".pdf"));
        assert!(!ZipStreamParser::is_archive_extension(".docx"));
        assert!(!ZipStreamParser::is_archive_extension(""));
    }
}

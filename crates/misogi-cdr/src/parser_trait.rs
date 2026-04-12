//! Pluggable content parser trait for the Misogi CDR engine.
//!
//! This module defines the core abstraction for extensible file parsing
//! and sanitization within the Content Disarm & Reconstruction (CDR) pipeline.
//!
//! ## Architecture Overview
//!
//! The `ContentParser` trait enables a **plugin-based architecture** where:
//! - Each parser handles specific MIME types or file formats
//! - Parsers can be dynamically registered and composed
//! - All parsers share a common sanitization policy interface
//!
//! ## Security Model
//!
//! Every parser implementation MUST guarantee:
//! 1. **Zero-trust input handling**: No assumption about input safety
//! 2. **Bounded memory usage**: O(1) or O(n) with configurable limits
//! 3. **Deterministic output**: Same input always produces same sanitized output
//! 4. **Complete audit trail**: All actions must be recorded in `SanitizedOutput`
//!
//! # Example
//!
//! ```ignore
//! use misogi_cdr::parser_trait::{ContentParser, SanitizePolicy};
//! use bytes::Bytes;
//!
//! let parser = MyCustomParser::new();
//! let policy = SanitizePolicy::default();
//! let input = Bytes::from_static(b"<script>alert('xss')</script>");
//!
//! let result = parser.parse_and_sanitize(input, &policy).await?;
//! println!("Actions taken: {:?}", result.actions_taken);
//! ```

use async_trait::async_trait;
use bytes::Bytes;
use std::fmt;
use thiserror::Error;

// ===========================================================================
// Sanitization Policy Configuration
// ===========================================================================

/// Granular sanitization policy controlling which threat categories to remove.
///
/// This struct provides fine-grained control over the CDR (Content Disarm &
/// Reconstruction) process, allowing security administrators to tailor the
/// sanitization behavior based on their organization's risk tolerance and
/// compliance requirements.
///
/// ## Security Defaults
///
/// The `Default` implementation provides **maximum security** configuration
/// where all potentially dangerous content is removed. This aligns with
/// Japanese government (MIC) guidelines for handling untrusted documents.
///
/// ## Memory Safety
///
/// `max_file_size_bytes` acts as a hard limit to prevent OOM attacks through
/// decompression bombs or maliciously crafted files that expand during parsing.
///
/// # Example
///
/// ```
/// use misogi_cdr::parser_trait::SanitizePolicy;
///
/// // Maximum security defaults (all removals enabled)
/// let strict_policy = SanitizePolicy::default();
/// assert!(strict_policy.remove_javascript);
/// assert!(strict_policy.remove_macros);
///
/// // Custom policy allowing embedded images but removing scripts
/// let permissive = SanitizePolicy {
///     remove_javascript: true,
///     remove_macros: true,
///     remove_embedded_files: false,  // Allow embedded images
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizePolicy {
    /// Remove JavaScript/ECMAScript from HTML, PDF, and Office documents.
    ///
    /// When enabled, all `<script>` tags, JS event handlers, and embedded
    /// JavaScript code will be stripped from the output.
    pub remove_javascript: bool,

    /// Remove VBA macros, Excel 4.0 macros, and other automation code.
    ///
    /// This is critical for Office document sanitization as macros are the
    /// primary vector for document-based malware (e.g., Emotet, TrickBot).
    pub remove_macros: bool,

    /// Remove embedded files (OLE objects, attachments, packaged payloads).
    ///
    /// Embedded files can contain malware hidden inside legitimate-looking
    /// documents. This includes OLE embeddings, PDF attachments, and ZIP archives.
    pub remove_embedded_files: bool,

    /// Remove or sanitize external hyperlinks and references.
    ///
    /// External links can be used for tracking, phishing, or command-and-control
    /// communication. When enabled, links are either removed or converted to
    /// non-functional text representations.
    pub remove_external_links: bool,

    /// Strip document metadata (author, revision history, comments).
    ///
    /// Metadata can leak sensitive information about the document's origin,
    /// editing history, and authorship. This is required for GDPR/DPA compliance
    /// when processing third-party documents.
    pub remove_metadata: bool,

    /// Remove code comments that may hide malicious instructions.
    ///
    /// Comments in scripts and markup languages can be used to obfuscate
    /// attack payload or provide covert channels for data exfiltration.
    pub strip_comments: bool,

    /// Maximum allowed input size in bytes before rejection.
    ///
    /// This prevents memory exhaustion attacks through:
    /// - Zip bombs (high compression ratio archives)
    /// - XML bomb expansion (entity expansion attacks)
    /// - PDF stream inflation
    ///
    /// Set to `None` to disable size checking (not recommended for production).
    pub max_file_size_bytes: Option<u64>,

    /// Whitelist of allowed MIME types for content validation.
    ///
    /// If non-empty, only files matching these MIME types will be processed.
    /// Files with mismatched content-type declarations will be rejected as
    /// potential content-sniffing attacks.
    pub allowed_mime_types: Vec<String>,
}

impl Default for SanitizePolicy {
    /// Creates a maximum-security policy with all removal options enabled.
    ///
    /// This default configuration follows the principle of **secure by default**,
    /// requiring explicit opt-in for any potentially risky content preservation.
    fn default() -> Self {
        Self {
            remove_javascript: true,
            remove_macros: true,
            remove_embedded_files: true,
            remove_external_links: true,
            remove_metadata: true,
            strip_comments: true,
            max_file_size_bytes: Some(100 * 1024 * 1024), // 100 MB default limit
            allowed_mime_types: Vec::new(),               // Empty = allow all
        }
    }
}

// ===========================================================================
// Sanitization Action Enumeration
// ===========================================================================

/// Individual action taken during the sanitization process.
///
/// Each variant represents a specific transformation applied to the input
/// content. These actions are recorded in [`SanitizedOutput`] to provide
/// a complete audit trail of what was modified during CDR processing.
///
/// ## Audit Compliance
///
/// For government and enterprise deployments, every `SanitizeAction` recorded
/// contributes to the compliance evidence chain. Actions should be logged
/// with timestamps and correlated to the original document hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanitizeAction {
    /// JavaScript code was detected and removed from the document.
    ///
    /// Includes removal of `<script>` blocks, inline event handlers (`onclick`,
    /// `onload`, etc.), and `javascript:` URIs.
    JavaScriptRemoved,

    /// Macro code (VBA, Excel 4.0, WordBasic) was stripped from the document.
    ///
    /// Macro stripping is the most critical defense against office-document
    /// malware, which accounts for >70% of email-borne threats.
    MacroStripped,

    /// An embedded file or OLE object was removed.
    ///
    /// Embedded files are a common vector for multi-stage attacks where the
    /// initial document serves as a dropper for secondary payloads.
    EmbeddedFileRemoved,

    /// An external hyperlink or reference was removed or neutralized.
    ///
    /// External links can facilitate tracking pixels, beaconing, and
    /// callback-to-attacker infrastructure.
    ExternalLinkRemoved,

    /// Document metadata fields were stripped.
    ///
    /// Metadata includes: author, title, subject, keywords, creation date,
    /// modification history, last saved by, revision number, etc.
    MetadataStripped,

    /// Code comments were removed from script/markup content.
    ///
    /// Comments may contain hidden data, obfuscated payloads, or
    /// operational security (OPSEC) indicators.
    CommentRemoved,

    /// Binary content was sanitized using format-specific logic.
    ///
    /// The `String` parameter describes the specific binary sanitization
    /// performed (e.g., "PDF stream re-encoded", "OLE object flattened").
    BinarySanitized(String),

    /// Custom parser-specific action not covered by standard variants.
    ///
    /// Allows parser implementations to report domain-specific actions while
    /// maintaining type safety in the standard enum.
    CustomAction(String),
}

impl fmt::Display for SanitizeAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JavaScriptRemoved => write!(f, "JavaScriptRemoved"),
            Self::MacroStripped => write!(f, "MacroStripped"),
            Self::EmbeddedFileRemoved => write!(f, "EmbeddedFileRemoved"),
            Self::ExternalLinkRemoved => write!(f, "ExternalLinkRemoved"),
            Self::MetadataStripped => write!(f, "MetadataStripped"),
            Self::CommentRemoved => write!(f, "CommentRemoved"),
            Self::BinarySanitized(desc) => write!(f, "BinarySanitized({})", desc),
            Self::CustomAction(action) => write!(f, "CustomAction({})", action),
        }
    }
}

// ===========================================================================
// Sanitized Output Result
// ===========================================================================

/// Result of the parse-and-sanitize operation containing clean data and audit trail.
///
/// This struct is the primary output of the CDR pipeline, providing both the
/// sanitized content and comprehensive metadata about what transformations
/// were applied during processing.
///
/// ## Size Tracking
///
/// Both `original_size` and `sanitized_size` are tracked to enable:
/// - Compression ratio analysis (detecting zip bombs)
/// - Storage quota management
/// - Bandwidth estimation for downstream systems
///
/// ## Audit Trail Integrity
///
/// The `actions_taken` and `warnings` vectors form an immutable record of
/// the CDR operation. This data should be persisted alongside the sanitized
/// output for forensic analysis and compliance auditing.
///
/// # Example
///
/// ```
/// use misogi_cdr::parser_trait::{SanitizedOutput, SanitizeAction};
/// use bytes::Bytes;
///
/// let output = SanitizedOutput {
///     clean_data: Bytes::from_static(b"<p>Safe content</p>"),
///     original_size: 1024,
///     sanitized_size: 24,
///     actions_taken: vec![SanitizeAction::JavaScriptRemoved],
///     warnings: vec!["Embedded image lost during sanitization".to_string()],
///     parser_name: "HtmlParser".to_string(),
/// };
///
/// assert_eq!(output.actions_taken.len(), 1);
/// assert!(output.sanitized_size < output.original_size);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SanitizedOutput {
    /// The sanitized content safe for downstream consumption.
    ///
    /// This `Bytes` buffer contains the reconstructed document with all
    /// threats neutralized according to the provided `SanitizePolicy`.
    pub clean_data: Bytes,

    /// Original input size in bytes (before any processing).
    ///
    /// Used for size reduction metrics and anomaly detection.
    pub original_size: u64,

    /// Output size in bytes after sanitization.
    ///
    /// May be larger than `original_size` if content was expanded during
    /// safe reconstruction (e.g., XML re-serialization).
    pub sanitized_size: u64,

    /// Ordered list of sanitization actions performed on this document.
    ///
    /// Each action corresponds to a specific threat category that was
    /// addressed during processing.
    pub actions_taken: Vec<SanitizeAction>,

    /// Non-fatal warnings generated during processing.
    ///
    /// Warnings indicate issues that didn't prevent sanitization but may
    /// affect output quality (e.g., "Font substitution applied").
    pub warnings: Vec<String>,

    /// Identifier of the parser that produced this output.
    ///
    /// Used for routing, logging, and debugging purposes.
    pub parser_name: String,
}

impl SanitizedOutput {
    /// Calculate the size reduction ratio (0.0 to 1.0+).
    ///
    /// Values > 1.0 indicate the output is larger than input (possible with
    /// certain reconstruction strategies like XML pretty-printing).
    ///
    /// # Returns
    ///
    /// * `Some(f64)` - Reduction ratio when original_size > 0
    /// * `None` - When original_size is 0 (division by zero protection)
    #[inline]
    pub fn reduction_ratio(&self) -> Option<f64> {
        if self.original_size == 0 {
            None
        } else {
            Some(self.sanitized_size as f64 / self.original_size as f64)
        }
    }

    /// Check if any sanitization actions were actually taken.
    ///
    /// A clean output with no actions suggests the input was already safe
    /// or the policy was too permissive for the content type.
    #[inline]
    pub fn has_actions(&self) -> bool {
        !self.actions_taken.is_empty()
    }

    /// Check if any warnings were generated during processing.
    #[inline]
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}

// ===========================================================================
// Parse Error Types
// ===========================================================================

/// Comprehensive error type for content parsing operations.
///
/// This enum covers all failure modes in the CDR pipeline, from unsupported
/// formats to runtime errors in WASM-based parsers. Each variant carries
/// sufficient context for debugging without leaking sensitive information.
///
/// ## Error Handling Strategy
///
/// Errors should be handled at the API boundary with appropriate HTTP status
/// mapping:
/// - `UnsupportedFormat` → 415 Unsupported Media Type
/// - `FileTooLarge` → 413 Payload Too Large
/// - `CorruptData` / `PolicyViolation` → 422 Unprocessable Entity
/// - `IoError` / `InternalError` → 500 Internal Server Error
/// - `WasmRuntimeError` → 502 Bad Gateway (if using external WASM runtime)
#[derive(Debug, Error)]
pub enum ParseError {
    /// Input format is not supported by any registered parser.
    ///
    /// This error indicates that no parser claimed responsibility for the
    /// given MIME type or file extension. The system administrator should
    /// verify that the appropriate parser plugin is installed and enabled.
    #[error("unsupported content format: cannot find parser for input")]
    UnsupportedFormat,

    /// Input exceeds the configured maximum file size limit.
    ///
    /// The contained value is the actual file size in bytes, which can be
    /// used to inform the user how much they need to reduce the file.
    #[error("file too large: {0} bytes exceeds configured maximum")]
    FileTooLarge(u64),

    /// Input data is corrupted or malformed and cannot be parsed.
    ///
    /// The `String` parameter contains a human-readable description of
    /// what specifically was wrong with the input (without revealing
    /// internal implementation details that could aid attackers).
    #[error("corrupt or malformed input data: {0}")]
    CorruptData(String),

    /// Input violates the sanitization policy constraints.
    ///
    /// This error is returned when pre-check validation fails (e.g.,
    /// MIME type not in whitelist, mandatory metadata missing).
    #[error("policy violation: {0}")]
    PolicyViolation(String),

    /// I/O error during file reading or writing operations.
    ///
    /// Wraps `std::io::Error` to preserve the original error context
    /// including OS-level error codes.
    #[error("I/O error during parsing: {0}")]
    IoError(#[from] std::io::Error),

    /// Runtime error from WASM-based parser execution.
    ///
    /// When using sandboxed WASM parsers, this error indicates a trap,
    /// out-of-memory condition, or other runtime failure within the
    /// WebAssembly execution environment.
    #[error("WASM runtime error: {0}")]
    WasmRuntimeError(String),

    /// Internal error indicating a bug or unexpected state.
    ///
    /// These errors should never occur in production and indicate a
    /// programming error or resource exhaustion condition. All instances
    /// should be logged with full stack traces for developer review.
    #[error("internal parser error: {0}")]
    InternalError(String),
}

// ===========================================================================
// Content Parser Trait Definition
// ===========================================================================

/// Core trait for pluggable content parsing and sanitization.
///
/// This trait defines the interface that all CDR parsers must implement to
/// participate in the Misogi pluggable architecture. Implementations handle
/// specific file formats (PDF, OOXML, HTML, images, etc.) and produce
/// sanitized output according to the provided security policy.
///
/// ## Trait Object Safety
///
/// `ContentParser` is designed to be used as a trait object (`dyn ContentParser`)
/// enabling dynamic parser registration and runtime dispatch. All methods
/// return concrete types (no generics in method signatures) to maintain
/// object safety.
///
/// ## Implementation Requirements
///
/// Parsers MUST satisfy these contractual obligations:
///
/// 1. **Thread Safety**: Implementations must be `Send + Sync` for concurrent use
/// 2. **Memory Bounds**: Must respect `SanitizePolicy.max_file_size_bytes`
/// 3. **Determinism**: Same input + same policy → identical output (hash equality)
/// 4. **Audit Completeness**: Record ALL modifications in `actions_taken`
/// 5. **No Panics**: Return `ParseError::InternalError` instead of panicking
///
/// ## Lifecycle
///
/// ```text
/// Registration → Format Detection → Parse & Sanitize → Output Validation
///      │              │                   │                │
///      ▼              ▼                   ▼                ▼
///   ParserRegistry  supported_types()  parse_and_sanitize()  SanitizedOutput
/// ```
///
/// # Example Implementation
///
/// ```ignore
/// use async_trait::async_trait;
/// use misogi_cdr::parser_trait::*;
/// use bytes::Bytes;
///
/// #[derive(Debug)]
/// struct MarkdownParser;
///
/// #[async_trait]
/// impl ContentParser for MarkdownParser {
///     fn supported_types(&self) -> Vec<&'static str> {
///         vec!["text/markdown", "text/x-markdown"]
///     }
///
///     fn parser_name(&self) -> &str {
///         "MarkdownParser"
///     }
///
///     async fn parse_and_sanitize(
///         &self,
///         input: Bytes,
///         policy: &SanitizePolicy,
///     ) -> Result<SanitizedOutput, ParseError> {
///         // Implementation: parse markdown, sanitize HTML blocks, rebuild
///         todo!()
///     }
/// }
/// ```
#[async_trait]
pub trait ContentParser: Send + Sync + fmt::Debug {
    /// Returns the list of MIME types / content types this parser can handle.
    ///
    /// The returned strings are used by the parser registry to route incoming
    /// files to the correct parser implementation. Multiple entries allow
    /// a single parser to handle related MIME types (e.g., both
    /// `"application/pdf"` and `"application/x-pdf"`).
    ///
    /// # Returns
    ///
    /// Vector of static string slices representing supported content types.
    /// Empty vector indicates a catch-all parser (use with caution).
    fn supported_types(&self) -> Vec<&'static str>;

    /// Returns the human-readable name of this parser implementation.
    ///
    /// Used for logging, debugging, and populating the `parser_name` field
    /// in [`SanitizedOutput`]. Should be unique across all registered parsers.
    ///
    /// # Returns
    ///
    /// Static string slice identifying this parser (e.g., "PdfCdrParser",
    /// "OoxmlTrueCdr", "HtmlSanitizer").
    fn parser_name(&self) -> &str;

    /// Parse input content and sanitize it according to the given policy.
    ///
    /// This is the primary entry point for the CDR pipeline. Implementations
    /// must:
    ///
    /// 1. Validate input size against `policy.max_file_size_bytes`
    /// 2. Parse the input format completely (fail fast on corrupt data)
    /// 3. Apply sanitization rules based on policy flags
    /// 4. Reconstruct safe output preserving benign content
    /// 5. Build comprehensive `SanitizedOutput` with audit trail
    ///
    /// # Arguments
    ///
    /// * `input` - Raw bytes of the input file/document
    /// * `policy` - Sanitization configuration controlling what to remove
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when:
    /// - Input format is unsupported or corrupt
    /// - File exceeds size limits
    /// - Policy constraints are violated
    /// - I/O or runtime failures occur
    ///
    /// # Example
    ///
    /// ```ignore
    /// let result = parser.parse_and_sanitize(raw_bytes, &policy).await?;
    /// println!("Clean output: {} bytes", result.sanitized_size);
    /// for action in &result.actions_taken {
    ///     println!("Action: {}", action);
    /// }
    /// ```
    async fn parse_and_sanitize(
        &self,
        input: Bytes,
        policy: &SanitizePolicy,
    ) -> Result<SanitizedOutput, ParseError>;
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test Infrastructure: Mock Parser Implementation
    // -----------------------------------------------------------------------

    /// Mock parser for testing trait contract and integration scenarios.
    ///
    /// This minimal implementation allows verification of the trait bounds,
    /// default policy behavior, and error handling patterns without requiring
    /// a real format-specific parser.
    #[derive(Debug, Clone)]
    struct MockTextParser {
        name: String,
        types: Vec<&'static str>,
    }

    impl MockTextParser {
        /// Create a new mock parser with specified capabilities.
        fn new(name: &str, types: Vec<&'static str>) -> Self {
            Self {
                name: name.to_string(),
                types,
            }
        }
    }

    #[async_trait]
    impl ContentParser for MockTextParser {
        fn supported_types(&self) -> Vec<&'static str> {
            self.types.clone()
        }

        fn parser_name(&self) -> &str {
            &self.name
        }

        async fn parse_and_sanitize(
            &self,
            input: Bytes,
            policy: &SanitizePolicy,
        ) -> Result<SanitizedOutput, ParseError> {
            // Validate file size constraint
            if let Some(max_size) = policy.max_file_size_bytes {
                if input.len() as u64 > max_size {
                    return Err(ParseError::FileTooLarge(input.len() as u64));
                }
            }

            // Validate MIME type whitelist
            if !policy.allowed_mime_types.is_empty() {
                // For mock, we assume text/plain is always acceptable
                if !policy.allowed_mime_types.contains(&"text/plain".to_string()) {
                    return Err(ParseError::PolicyViolation(
                        "MIME type not in allowed list".to_string(),
                    ));
                }
            }

            // Simulate sanitization: convert to uppercase as "sanitization"
            let sanitized = String::from_utf8_lossy(&input).to_uppercase();
            let clean_data = Bytes::from(sanitized.into_bytes());
            let output_size = clean_data.len() as u64;

            let mut actions = Vec::new();
            if policy.remove_metadata {
                actions.push(SanitizeAction::MetadataStripped);
            }
            if policy.strip_comments {
                actions.push(SanitizeAction::CommentRemoved);
            }

            Ok(SanitizedOutput {
                clean_data,
                original_size: input.len() as u64,
                sanitized_size: output_size,
                actions_taken: actions,
                warnings: Vec::new(),
                parser_name: self.parser_name().to_string(),
            })
        }
    }

    // -----------------------------------------------------------------------
    // Test Case 1: SanitizePolicy Secure Defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_sanitize_policy_secure_defaults() {
        // Verify that Default implementation provides maximum security
        let policy = SanitizePolicy::default();

        // All removal flags MUST be true for secure-by-default behavior
        assert!(
            policy.remove_javascript,
            "Default policy must enable JavaScript removal"
        );
        assert!(
            policy.remove_macros,
            "Default policy must enable macro removal"
        );
        assert!(
            policy.remove_embedded_files,
            "Default policy must enable embedded file removal"
        );
        assert!(
            policy.remove_external_links,
            "Default policy must enable external link removal"
        );
        assert!(
            policy.remove_metadata,
            "Default policy must enable metadata removal"
        );
        assert!(
            policy.strip_comments,
            "Default policy must enable comment stripping"
        );

        // Default size limit must be set (not None)
        assert!(
            policy.max_file_size_bytes.is_some(),
            "Default policy must have a size limit configured"
        );
        assert_eq!(
            policy.max_file_size_bytes,
            Some(100 * 1024 * 1024),
            "Default size limit should be 100 MB"
        );

        // MIME whitelist should be empty (allow-all by default)
        assert!(
            policy.allowed_mime_types.is_empty(),
            "Default policy should have empty MIME whitelist (allow all)"
        );
    }

    // -----------------------------------------------------------------------
    // Test Case 2: Custom Policy Construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_custom_policy_construction() {
        // Test partial override using struct update syntax
        let custom_policy = SanitizePolicy {
            remove_javascript: false,
            remove_embedded_files: false,
            max_file_size_bytes: Some(50 * 1024 * 1024), // 50 MB
            allowed_mime_types: vec![
                "application/pdf".to_string(),
                "application/msword".to_string(),
            ],
            ..Default::default()
        };

        assert!(!custom_policy.remove_javascript, "JS removal disabled");
        assert!(!custom_policy.remove_embedded_files, "Embed removal disabled");
        assert!(custom_policy.remove_macros, "Macro removal still enabled");
        assert!(custom_policy.remove_metadata, "Metadata removal still enabled");
        assert_eq!(
            custom_policy.max_file_size_bytes,
            Some(50 * 1024 * 1024)
        );
        assert_eq!(custom_policy.allowed_mime_types.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Test Case 3: Mock Parser Basic Operations
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_mock_parser_basic_parsing() {
        let parser = MockTextParser::new(
            "TestTextParser",
            vec!["text/plain", "text/csv"],
        );
        let policy = SanitizePolicy::default();
        let input = Bytes::from_static(b"hello world");

        let result = parser.parse_and_sanitize(input, &policy).await;

        assert!(result.is_ok(), "Parsing should succeed for valid input");

        let output = result.unwrap();
        assert_eq!(output.parser_name, "TestTextParser");
        assert!(output.has_actions(), "Default policy should trigger actions");
        assert!(!output.has_warnings(), "Mock should not generate warnings");
        assert_eq!(
            output.clean_data,
            Bytes::from_static(b"HELLO WORLD"),
            "Mock converts to uppercase"
        );
    }

    // -----------------------------------------------------------------------
    // Test Case 4: File Size Limit Enforcement
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_file_too_large_error() {
        let parser = MockTextParser::new("SizeLimitParser", vec!["text/plain"]);

        // Create policy with very small size limit
        let strict_policy = SanitizePolicy {
            max_file_size_bytes: Some(10), // Only 10 bytes allowed
            ..Default::default()
        };

        // Generate input exceeding the limit
        let large_input = Bytes::from_static(b"this input is way too large for the limit");

        let result = parser.parse_and_sanitize(large_input, &strict_policy).await;

        assert!(result.is_err(), "Should reject oversized input");

        match result.unwrap_err() {
            ParseError::FileTooLarge(size) => {
                assert_eq!(size, 41, "Error should report actual file size");
            }
            other => panic!("Expected FileTooLarge error, got: {}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test Case 5: ParseError Display Formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_error_display() {
        // Test each error variant produces human-readable message
        let errors: Vec<(ParseError, &str)> = vec![
            (ParseError::UnsupportedFormat, "unsupported content format"),
            (ParseError::FileTooLarge(99999), "file too large: 99999"),
            (
                ParseError::CorruptData("invalid header".to_string()),
                "corrupt or malformed",
            ),
            (
                ParseError::PolicyViolation("mime blocked".to_string()),
                "policy violation",
            ),
            (
                ParseError::WasmRuntimeError("stack overflow".to_string()),
                "WASM runtime error",
            ),
            (
                ParseError::InternalError("null pointer".to_string()),
                "internal parser error",
            ),
        ];

        for (error, expected_substr) in errors {
            let display = format!("{}", error);
            assert!(
                display.contains(expected_substr),
                "Error display '{}' should contain '{}'",
                display,
                expected_substr
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test Case 6: SanitizedOutput Construction and Methods
    // -----------------------------------------------------------------------

    #[test]
    fn test_sanitized_output_construction() {
        let output = SanitizedOutput {
            clean_data: Bytes::from_static(b"clean content"),
            original_size: 2048,
            sanitized_size: 14,
            actions_taken: vec![
                SanitizeAction::JavaScriptRemoved,
                SanitizeAction::MetadataStripped,
            ],
            warnings: vec!["font substituted".to_string()],
            parser_name: "TestParser".to_string(),
        };

        // Verify field values
        assert_eq!(output.original_size, 2048);
        assert_eq!(output.sanitized_size, 14);
        assert_eq!(output.actions_taken.len(), 2);
        assert_eq!(output.warnings.len(), 1);
        assert_eq!(output.parser_name, "TestParser");

        // Test helper methods
        assert!(output.has_actions());
        assert!(output.has_warnings());

        // Test reduction ratio calculation
        let ratio = output.reduction_ratio();
        assert!(ratio.is_some());
        let ratio_val = ratio.unwrap();
        assert!(ratio_val < 1.0, "Should show size reduction: {}", ratio_val);
        assert!(
            ratio_val > 0.0,
            "Ratio should be positive: {}",
            ratio_val
        );
    }

    // -----------------------------------------------------------------------
    // Test Case 7: SanitizedOutput Edge Cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_sanitized_output_edge_cases() {
        // Zero-size input edge case
        let empty_output = SanitizedOutput {
            clean_data: Bytes::new(),
            original_size: 0,
            sanitized_size: 0,
            actions_taken: vec![],
            warnings: vec![],
            parser_name: "EmptyParser".to_string(),
        };

        assert!(!empty_output.has_actions());
        assert!(!empty_output.has_warnings());
        assert!(
            empty_output.reduction_ratio().is_none(),
            "Zero-size input should return None for ratio"
        );

        // Output larger than input (possible with XML pretty-printing)
        let expanded_output = SanitizedOutput {
            clean_data: Bytes::from_static(b"expanded content here"),
            original_size: 10,
            sanitized_size: 21,
            actions_taken: vec![SanitizeAction::CommentRemoved],
            warnings: vec![],
            parser_name: "Expander".to_string(),
        };

        let ratio = expanded_output.reduction_ratio().unwrap();
        assert!(
            ratio > 1.0,
            "Expanded output should have ratio > 1.0: {}",
            ratio
        );
    }

    // -----------------------------------------------------------------------
    // Test Case 8: SanitizeAction Display Formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_sanitize_action_display() {
        let actions: Vec<(SanitizeAction, &str)> = vec![
            (SanitizeAction::JavaScriptRemoved, "JavaScriptRemoved"),
            (SanitizeAction::MacroStripped, "MacroStripped"),
            (SanitizeAction::EmbeddedFileRemoved, "EmbeddedFileRemoved"),
            (SanitizeAction::ExternalLinkRemoved, "ExternalLinkRemoved"),
            (SanitizeAction::MetadataStripped, "MetadataStripped"),
            (SanitizeAction::CommentRemoved, "CommentRemoved"),
            (
                SanitizeAction::BinarySanitized("stream re-encoded".to_string()),
                "BinarySanitized(stream re-encoded)",
            ),
            (
                SanitizeAction::CustomAction("XMP cleanup".to_string()),
                "CustomAction(XMP cleanup)",
            ),
        ];

        for (action, expected) in actions {
            let display = format!("{}", action);
            assert_eq!(
                display, expected,
                "SanitizeAction display mismatch for {:?}",
                action
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test Case 9: Trait Object Safety Verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_trait_object_safety() {
        // Verify that ContentParser can be used as a trait object
        // This is essential for dynamic parser registration in the registry
        let parser: MockTextParser =
            MockTextParser::new("ObjectSafeParser", vec!["text/plain"]);

        // Create trait object (this compilation proves object safety)
        let trait_object: Box<dyn ContentParser> = Box::new(parser);

        // Verify trait object methods work correctly
        assert_eq!(trait_object.parser_name(), "ObjectSafeParser");
        let types = trait_object.supported_types();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0], "text/plain");

        // Verify Send + Sync bounds (required for async concurrency)
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn ContentParser>>();
    }

    // -----------------------------------------------------------------------
    // Test Case 10: Policy Violation Error Path
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_policy_violation_error() {
        let parser = MockTextParser::new("StrictParser", vec!["text/plain"]);

        // Create policy with restrictive MIME whitelist
        let restricted_policy = SanitizePolicy {
            allowed_mime_types: vec!["application/pdf".to_string()], // Only PDF allowed
            ..Default::default()
        };

        let input = Bytes::from_static(b"test content");
        let result = parser.parse_and_sanitize(input, &restricted_policy).await;

        assert!(result.is_err(), "Should reject non-whitelisted MIME type");

        match result.unwrap_err() {
            ParseError::PolicyViolation(msg) => {
                assert!(
                    msg.to_lowercase().contains("mime") || msg.to_lowercase().contains("allowed"),
                    "Policy violation message should mention MIME/type: {}",
                    msg
                );
            }
            other => panic!("Expected PolicyViolation, got: {}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test Case 11: IoError Conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_io_error_conversion() {
        // Verify that std::io::Error automatically converts via From trait
        let io_err = std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "configuration file missing",
        );

        let parse_error: ParseError = io_err.into();

        match parse_error {
            ParseError::IoError(ref inner) => {
                assert_eq!(
                    inner.kind(),
                    std::io::ErrorKind::NotFound,
                    "Preserved IO error kind"
                );
            }
            other => panic!("Expected IoError variant, got: {}", other),
        }

        // Also test Display formatting
        let display = format!("{}", parse_error);
        assert!(
            display.contains("I/O error"),
            "IoError display should mention I/O: {}",
            display
        );
    }
}

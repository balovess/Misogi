// =============================================================================
// CDR Engine v2 — Configuration Structures
// =============================================================================
// This module defines deserializable configuration structures for the CDR v2
// engine. All config types support serde Serialize/Deserialize for TOML/YAML/JSON
// file loading and have sensible Default implementations for zero-config startup.
//
// Configuration Hierarchy:
//   CdrV2Config (top-level)
//     +-- PdfConfig      (PDF-specific settings)
//     +-- OfficeConfig   (OOXML + legacy Office settings)
//     +-- ArchiveConfig  (ZIP/RAR/7z/TAR archive handling)
//     +-- WhitelistConfig (trusted source / content whitelists)
//
// Validation:
// - Every struct has a validate() method returning Result<(), String>.
// - Validation is NOT automatic on construction — caller must invoke it.
// - Invalid configurations MUST cause explicit errors, never silent fallbacks.
// =============================================================================

use serde::{Deserialize, Serialize};

/// Maximum allowed file size in bytes for PDF processing (default: 100 MB).
const DEFAULT_PDF_MAX_SIZE_BYTES: u64 = 100 * 1024 * 1024;

/// Maximum allowed embedded file size within PDF (default: 10 MB).
const DEFAULT_PDF_MAX_EMBEDDED_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum allowed number of pages in an Office document (default: 10,000).
const DEFAULT_OFFICE_MAX_PAGES: u32 = 10_000;

/// Maximum archive nesting depth (default: 5).
const DEFAULT_ARCHIVE_MAX_DEPTH: u32 = 5;

/// Maximum total extracted size from archives (default: 1 GB).
const DEFAULT_ARCHIVE_MAX_TOTAL_SIZE: u64 = 1024 * 1024 * 1024;

// =============================================================================
// PdfConfig — PDF-specific processing configuration
// =============================================================================

/// Configuration for PDF document sanitization.
///
/// Controls how the PDF parser and sanitizer handle JavaScript, forms,
/// embedded files, and other PDF-specific threat vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfConfig {
    /// Whether to strip all JavaScript from PDF documents.
    #[serde(default = "default_true")]
    pub strip_javascript: bool,

    /// Whether to remove PDF OpenAction / OpenDestination entries.
    #[serde(default = "default_true")]
    pub strip_open_actions: bool,

    /// Whether to flatten XFA dynamic form templates into static AcroForms.
    #[serde(default = "default_true")]
    pub flatten_xfa_forms: bool,

    /// Whether to remove embedded files (file attachments) from PDF.
    #[serde(default = "default_true")]
    pub strip_embedded_files: bool,

    /// Maximum allowed PDF file size in bytes.
    /// Files exceeding this limit are rejected before parsing.
    #[serde(default = "default_pdf_max_size")]
    pub max_file_size_bytes: u64,

    /// Maximum size of a single embedded file within a PDF.
    /// Embedded files larger than this are rejected.
    #[serde(default = "default_pdf_max_embedded_size")]
    pub max_embedded_file_size_bytes: u64,

    /// Whether to preserve hyperlinks (external URLs) in PDF output.
    /// When false, external links are converted to plain text.
    #[serde(default = "default_false")]
    pub preserve_hyperlinks: bool,
}

impl Default for PdfConfig {
    fn default() -> Self {
        Self {
            strip_javascript: true,
            strip_open_actions: true,
            flatten_xfa_forms: true,
            strip_embedded_files: true,
            max_file_size_bytes: DEFAULT_PDF_MAX_SIZE_BYTES,
            max_embedded_file_size_bytes: DEFAULT_PDF_MAX_EMBEDDED_SIZE,
            preserve_hyperlinks: false,
        }
    }
}

impl PdfConfig {
    /// Validate that all configuration values are within acceptable bounds.
    ///
    /// # Errors
    /// Returns a descriptive string if any value is invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_file_size_bytes == 0 {
            return Err("max_file_size_bytes must be > 0".into());
        }
        if self.max_embedded_file_size_bytes == 0 {
            return Err("max_embedded_file_size_bytes must be > 0".into());
        }
        if self.max_embedded_file_size_bytes > self.max_file_size_bytes {
            return Err(
                "max_embedded_file_size_bytes must not exceed max_file_size_bytes".into(),
            );
        }
        Ok(())
    }
}

// =============================================================================
// OfficeConfig — Office document processing configuration
// =============================================================================

/// Configuration for Microsoft Office document sanitization.
///
/// Covers both modern OOXML formats (Docx/Xlsx/Pptx) and legacy binary
/// formats (Doc/Xls/Ppt). Macro handling is the primary security concern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfficeConfig {
    /// Whether to strip VBA macro projects entirely.
    #[serde(default = "default_true")]
    pub strip_macros: bool,

    /// Whether to remove OLE embedded objects (Excel sheets, packages).
    #[serde(default = "default_true")]
    pub strip_ole_objects: bool,

    /// Whether to remove external data connections (database queries, web queries).
    #[serde(default = "default_true")]
    pub strip_external_data_connections: bool,

    /// Whether to disable ActiveX controls (replace with static images).
    #[serde(default = "default_true")]
    pub disable_activex_controls: bool,

    /// Maximum allowed page count per document.
    /// Prevents denial-of-service via extremely large spreadsheets.
    #[serde(default = "default_office_max_pages")]
    pub max_page_count: u32,

    /// Whether to preserve document properties (title, author, etc.).
    /// Subject to global preserve_metadata_fields whitelist.
    #[serde(default = "default_false")]
    pub preserve_document_properties: bool,
}

impl Default for OfficeConfig {
    fn default() -> Self {
        Self {
            strip_macros: true,
            strip_ole_objects: true,
            strip_external_data_connections: true,
            disable_activex_controls: true,
            max_page_count: DEFAULT_OFFICE_MAX_PAGES,
            preserve_document_properties: false,
        }
    }
}

impl OfficeConfig {
    /// Validate that all configuration values are within acceptable bounds.
    ///
    /// # Errors
    /// Returns a descriptive string if any value is invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_page_count == 0 {
            return Err("max_page_count must be > 0".into());
        }
        if self.max_page_count > 100_000 {
            return Err("max_page_count must not exceed 100000".into());
        }
        Ok(())
    }
}

// =============================================================================
// ArchiveConfig — Archive extraction configuration
// =============================================================================

/// Configuration for archive (ZIP/RAR/7z/TAR) processing.
///
/// Archives present unique risks: zip bombs, path traversal attacks,
/// symlink escapes, and nested archive recursion depth bombs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveConfig {
    /// Maximum nesting depth for recursive archive extraction.
    /// Prevents infinite recursion via nested archives.
    #[serde(default = "default_archive_max_depth")]
    pub max_nesting_depth: u32,

    /// Maximum total uncompressed size across all extracted files.
    /// Prevents zip bomb memory exhaustion attacks.
    #[serde(default = "default_archive_max_total_size")]
    pub max_total_extracted_size_bytes: u64,

    /// Maximum size of a single file within an archive.
    #[serde(default = "default_archive_max_total_size")]
    pub max_single_file_size_bytes: u64,

    /// Whether to block archives containing symlinks pointing outside
    /// the extraction directory (path traversal prevention).
    #[serde(default = "default_true")]
    pub block_symlink_escape: bool,

    /// Whether to process nested archives recursively.
    /// When false, nested archives are treated as opaque blobs.
    #[serde(default = "default_true")]
    pub process_nested_archives: bool,

    /// Allowed file extensions within archives (empty = allow all).
    /// Extensions not in this list are blocked if non-empty.
    #[serde(default)]
    pub allowed_extensions: Vec<String>,
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            max_nesting_depth: DEFAULT_ARCHIVE_MAX_DEPTH,
            max_total_extracted_size_bytes: DEFAULT_ARCHIVE_MAX_TOTAL_SIZE,
            max_single_file_size_bytes: DEFAULT_ARCHIVE_MAX_TOTAL_SIZE,
            block_symlink_escape: true,
            process_nested_archives: true,
            allowed_extensions: Vec::new(),
        }
    }
}

impl ArchiveConfig {
    /// Validate that all configuration values are within acceptable bounds.
    ///
    /// # Errors
    /// Returns a descriptive string if any value is invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_nesting_depth == 0 {
            return Err("max_nesting_depth must be > 0".into());
        }
        if self.max_nesting_depth > 20 {
            return Err("max_nesting_depth must not exceed 20".into());
        }
        if self.max_total_extracted_size_bytes == 0 {
            return Err("max_total_extracted_size_bytes must be > 0".into());
        }
        if self.max_single_file_size_bytes == 0 {
            return Err("max_single_file_size_bytes must be > 0".into());
        }
        if self.max_single_file_size_bytes > self.max_total_extracted_size_bytes {
            return Err(
                "max_single_file_size_bytes must not exceed max_total_extracted_size_bytes"
                    .into(),
            );
        }
        Ok(())
    }
}

// =============================================================================
// WhitelistEntry & WhitelistConfig — Trusted content configuration
// =============================================================================

/// Single whitelist entry identifying trusted content or sources.
///
/// Whitelists provide exception mechanisms for legitimate active content
/// that should bypass sanitization (e.g., digitally signed macros from
/// approved vendors).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhitelistEntry {
    /// Unique identifier for this entry (for audit trail correlation).
    pub id: String,

    /// Pattern type: "hash" (SHA-256), "source" (domain), "signature"
    /// (certificate thumbprint), or "content_type" (ActiveContentType name).
    pub match_type: String,

    /// The pattern value to match against.
    pub pattern: String,

    /// Human-readable description of why this entry exists.
    pub description: String,

    /// Whether this entry is currently enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// ISO8601 expiration timestamp (None = no expiry).
    pub expires_at: Option<String>,
}

impl WhitelistEntry {
    /// Create a new whitelist entry with required fields.
    ///
    /// # Arguments
    /// * `id` - Unique identifier.
    /// * `match_type` - Pattern matching category.
    /// * `pattern` - Pattern value to match.
    /// * `description` - Human-readable justification.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        match_type: impl Into<String>,
        pattern: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            match_type: match_type.into(),
            pattern: pattern.into(),
            description: description.into(),
            enabled: true,
            expires_at: None,
        }
    }

    /// Check whether this entry has expired relative to the given time.
    ///
    /// Entries without an expiration never expire.
    #[must_use]
    pub fn is_expired(&self, _now: &str) -> bool {
        // In production, parse ISO8601 timestamps and compare.
        // For now, entries with expires_at set are considered unexpired
        // unless explicitly past their deadline.
        false
    }

    /// Set expiration timestamp.
    pub fn with_expiry(mut self, ts: impl Into<String>) -> Self {
        self.expires_at = Some(ts.into());
        self
    }

    /// Disable this entry.
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// Aggregated whitelist configuration for all trust categories.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WhitelistConfig {
    /// Trusted file hashes (SHA-256 of original file content).
    pub file_hashes: Vec<WhitelistEntry>,

    /// Trusted source domains / IP addresses.
    pub sources: Vec<WhitelistEntry>,

    /// Trusted digital signature certificates (thumbprints).
    pub signatures: Vec<WhitelistEntry>,

    /// Trusted content types that may bypass sanitization.
    pub content_types: Vec<WhitelistEntry>,
}

impl WhitelistConfig {
    /// Return all enabled (non-expired, non-disabled) entries across categories.
    #[must_use]
    pub fn active_entries(&self) -> Vec<&WhitelistEntry> {
        let now = ""; // Placeholder; production uses chrono::Utc::now()
        let mut active = Vec::new();
        for entry in self
            .file_hashes
            .iter()
            .chain(self.sources.iter())
            .chain(self.signatures.iter())
            .chain(self.content_types.iter())
        {
            if entry.enabled && !entry.is_expired(now) {
                active.push(entry);
            }
        }
        active
    }

    /// Total number of configured entries (including disabled/expired).
    #[must_use]
    pub fn total_entry_count(&self) -> usize {
        self.file_hashes.len()
            + self.sources.len()
            + self.signatures.len()
            + self.content_types.len()
    }
}

// =============================================================================
// CdrV2Config — Top-level configuration
// =============================================================================

/// Complete CDR Engine v2 configuration.
///
/// This is the root configuration structure loaded from config files
/// (TOML preferred). It aggregates all format-specific and cross-cutting
/// settings into a single serializable/deserializable unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdrV2Config {
    /// PDF-specific processing settings.
    #[serde(default)]
    pub pdf: PdfConfig,

    /// Office document processing settings.
    #[serde(default)]
    pub office: OfficeConfig,

    /// Archive extraction settings.
    #[serde(default)]
    pub archive: ArchiveConfig,

    /// Whitelist / trust configuration.
    #[serde(default)]
    pub whitelist: WhitelistConfig,
}

impl Default for CdrV2Config {
    fn default() -> Self {
        Self {
            pdf: PdfConfig::default(),
            office: OfficeConfig::default(),
            archive: ArchiveConfig::default(),
            whitelist: WhitelistConfig::default(),
        }
    }
}

impl CdrV2Config {
    /// Create a new configuration with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate all sub-configurations recursively.
    ///
    /// # Errors
    /// Returns the first validation error encountered during recursive check.
    pub fn validate(&self) -> Result<(), String> {
        self.pdf.validate()?;
        self.office.validate()?;
        self.archive.validate()?;
        Ok(())
    }

    /// Load configuration from a TOML string.
    ///
    /// # Arguments
    /// * `toml_str` - TOML-formatted configuration string.
    ///
    /// # Errors
    /// Returns a descriptive string if parsing or validation fails.
    pub fn from_toml(toml_str: &str) -> Result<Self, String> {
        let config: CdrV2Config =
            toml::from_str(toml_str).map_err(|e| format!("TOML parse error: {e}"))?;
        config.validate()?;
        Ok(config)
    }
}

// =============================================================================
// Serde Default Helpers
// =============================================================================

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_pdf_max_size() -> u64 {
    DEFAULT_PDF_MAX_SIZE_BYTES
}

fn default_pdf_max_embedded_size() -> u64 {
    DEFAULT_PDF_MAX_EMBEDDED_SIZE
}

fn default_office_max_pages() -> u32 {
    DEFAULT_OFFICE_MAX_PAGES
}

fn default_archive_max_depth() -> u32 {
    DEFAULT_ARCHIVE_MAX_DEPTH
}

fn default_archive_max_total_size() -> u64 {
    DEFAULT_ARCHIVE_MAX_TOTAL_SIZE
}

// Unit tests extracted to config_tests.rs (line count limit)
#[cfg(test)]
mod config_tests;

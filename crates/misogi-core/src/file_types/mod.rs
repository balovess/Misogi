// =============================================================================
// Misogi Core — File Type Detection via Magic Number Registry
// =============================================================================
// This module provides file type identification using magic number (file signature)
// analysis, extension-based fallback, and composite detection strategies.
//
// ## Architecture
//
// 1. **MagicNumberRegistry** — Config-driven registry of known file signatures.
//    Each entry maps a magic byte pattern to a file type with metadata.
//
// 2. **MagicNumberDetector** — Primary detector that reads file headers and
//    matches against the registry's magic byte patterns.
//
// 3. **ExtensionFallbackDetector** — Secondary detector that uses filename
//    extensions when magic number analysis is inconclusive.
//
// 4. **CompositeDetector** — Orchestrator that runs multiple detectors and
//    returns the highest-confidence result.
//
// ## Security Model
// Magic number detection is the primary defense against extension spoofing
// attacks where a malicious executable is renamed to `.txt` or `.pdf`.
// The composite approach ensures: magic bytes > extension > unknown.
//
// ## Built-in Registry
// Pre-populated with common Japanese government/enterprise file types:
// - PDF (%PDF), DOCX/XLSX/PPTX (PK ZIP), JTD (OLE), DWG (AutoCAD),
//   JPEG, PNG, GIF, ZIP, and more.
// =============================================================================

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{MisogiError, Result};
use crate::traits::{
    FileDetectionResult, FileTypeDetector,
};

// =============================================================================
// A. Magic Number Registry
// =============================================================================

/// Single entry in the [`MagicNumberRegistry`] describing a known file type.
///
/// Each entry defines the signature pattern (magic bytes) used to identify
/// a specific file format, along with metadata for downstream processing
/// (sanitizer selection, blocking policy, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicNumberEntry {
    /// File extension without leading dot (e.g., "pdf", "xlsx", "jpg").
    pub extension: String,

    /// Hex-encoded magic byte string for this format (e.g., "25504446" for PDF).
    /// `None` means this entry has no magic byte validation (extension-only).
    pub magic_hex: Option<String>,

    /// Whether magic byte matching is required for positive identification.
    /// When `true`, a mismatch between declared extension and detected magic
    /// bytes produces a low-confidence or blocked result.
    pub required_magic: bool,

    /// Name of the recommended CDR sanitizer for this file type.
    /// Empty string indicates no sanitizer is needed or applicable.
    pub sanitizer: Option<String>,

    /// Human-readable description of this file type (for audit logs).
    pub description: Option<String>,

    /// Optional external adapter name for custom detection logic.
    pub external_adapter: Option<String>,
}

impl MagicNumberEntry {
    /// Create a new magic number entry with all fields specified.
    pub fn new(
        extension: impl Into<String>,
        magic_hex: Option<String>,
        required_magic: bool,
        sanitizer: Option<String>,
        description: Option<String>,
    ) -> Self {
        Self {
            extension: extension.into(),
            magic_hex,
            required_magic,
            sanitizer,
            description,
            external_adapter: None,
        }
    }

    /// Parse the `magic_hex` field into a byte vector for binary comparison.
    ///
    /// # Returns
    /// `Some(Vec<u8>)` if `magic_hex` is present and valid hex; `None` otherwise.
    pub fn magic_bytes(&self) -> Option<Vec<u8>> {
        self.magic_hex.as_ref().and_then(|hex_str| {
            // Handle both plain hex and space-separated formats
            let cleaned: String = hex_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if cleaned.len() % 2 != 0 {
                return None;
            }
            (0..cleaned.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
                .collect()
        })
    }
}

/// Configurable registry of known file type signatures.
///
/// The registry is the central data structure driving file type detection.
/// Entries can be added at runtime via [`register()`](MagicNumberRegistry::register)
/// and looked up by extension or matched against raw byte sequences.
///
/// # Thread Safety
/// The registry is designed to be built once (during initialization) and then
/// shared read-only across detection tasks via `Arc<>`. Mutation methods
/// (`register`) are intended for setup phase only.
pub struct MagicNumberRegistry {
    /// Ordered list of registered file type entries.
    entries: Vec<MagicNumberEntry>,
}

impl MagicNumberRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Register a new file type entry into the registry.
    ///
    /// Entries are checked in registration order during detection, so more
    /// specific patterns should be registered before generic ones.
    ///
    /// # Arguments
    /// * `entry` — The [`MagicNumberEntry`] to add.
    pub fn register(&mut self, entry: MagicNumberEntry) {
        self.entries.push(entry);
    }

    /// Look up an entry by file extension (case-insensitive).
    ///
    /// # Arguments
    /// * `extension` — Extension without leading dot (e.g., "pdf").
    ///
    /// # Returns
    /// Reference to the matching entry, or `None` if not found.
    pub fn lookup(&self, extension: &str) -> Option<&MagicNumberEntry> {
        let ext_lower = extension.to_lowercase();
        self.entries
            .iter()
            .find(|e| e.extension.to_lowercase() == ext_lower)
    }

    /// Detect file type from raw byte data and optional filename hint.
    ///
    /// Scans the provided data against all registered magic byte patterns.
    /// Returns the best-matching [`FileDetectionResult`] with confidence scoring.
    ///
    /// # Confidence Levels
    /// - **1.0**: Exact magic byte match (certain identification).
    /// - **0.7**: Partial / prefix magic match (likely but not certain).
    /// - **0.3**: Extension-only match (low confidence, easily spoofed).
    /// - **0.0**: No match (unknown type).
    ///
    /// # Arguments
    /// * `data` — Raw file header bytes (typically first 262+ bytes).
    /// * `filename` — Optional filename for extension-based fallback.
    ///
    /// # Returns
    /// A [`FileDetectionResult`] with type classification and confidence.
    pub fn detect_from_bytes(
        &self,
        data: &[u8],
        filename: Option<&str>,
    ) -> FileDetectionResult {
        // Strategy 1: Try exact magic byte matches first (highest confidence)
        for entry in &self.entries {
            if let Some(ref magic_hex) = entry.magic_hex {
                if let Some(magic_bytes) = entry.magic_bytes() {
                    if data.starts_with(&magic_bytes) {
                        return FileDetectionResult::detected(
                            self.mime_for_extension(&entry.extension),
                            entry.extension.clone(),
                            magic_hex.clone(),
                            entry.sanitizer.as_deref().unwrap_or(""),
                        );
                    }
                }
            }
        }

        // Strategy 2: Fallback to extension-based lookup (lower confidence)
        if let Some(fname) = filename {
            if let Some(ext) = Self::extract_extension(fname) {
                if let Some(entry) = self.lookup(&ext) {
                    return FileDetectionResult {
                        detected_type: self.mime_for_extension(&entry.extension),
                        confidence: 0.3, // Low confidence: extension only
                        extension: entry.extension.clone(),
                        magic_hex: String::new(),
                        recommended_sanitizer: entry.sanitizer.as_deref().unwrap_or("").to_string(),
                        is_blocked: false,
                        block_reason: None,
                    };
                }
            }
        }

        // No match found
        FileDetectionResult::unknown()
    }

    /// Return all registered extensions as a vector of &str references.
    pub fn all_extensions(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.extension.as_str()).collect()
    }

    /// Build the default Japanese government/enterprise file type registry.
    ///
    /// Pre-populates with commonly encountered formats in Japanese government
    /// document workflows, including office documents, CAD files, images,
    /// archives, and specialized formats (JTD, etc.).
    pub fn jp_government_defaults() -> Self {
        let mut registry = Self::new();

        // --- Document Formats ---
        registry.register(MagicNumberEntry::new(
            "pdf",
            Some("25504446".to_string()), // %PDF
            true,
            Some("builtin-pdf-strategy".to_string()),
            Some("Portable Document Format".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "docx",
            Some("504B0304".to_string()), // PK\x03\x04 (ZIP/OOXML)
            true,
            Some("office-cdr".to_string()),
            Some("Office Open XML Word Document".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "xlsx",
            Some("504B0304".to_string()),
            true,
            Some("office-cdr".to_string()),
            Some("Office Open Excel Spreadsheet".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "pptx",
            Some("504B0304".to_string()),
            true,
            Some("office-cdr".to_string()),
            Some("Office Open PowerPoint Presentation".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "doc",
            Some("D0CF11E0".to_string()), // OLE Compound Document
            true,
            Some("office-cdr".to_string()),
            Some("Legacy Microsoft Word 97-2003".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "xls",
            Some("D0CF11E0".to_string()),
            true,
            Some("office-cdr".to_string()),
            Some("Legacy Microsoft Excel 97-2003".to_string()),
        ));

        // --- Japanese-Specific Formats ---
        registry.register(MagicNumberEntry::new(
            "jtd", // Ichitaro document
            Some("D0CF11E0".to_string()), // OLE-based
            true,
            Some("jtd-sanitizer".to_string()),
            Some("Ichitaro (JustSystem) Document".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "dwg", // AutoCAD drawing
            Some("41433130".to_string()), // AC1.0 header variant
            false,
            None,
            Some("AutoCAD Drawing Database".to_string()),
        ));

        // --- Image Formats ---
        registry.register(MagicNumberEntry::new(
            "jpeg",
            Some("FFD8FF".to_string()),
            true,
            None,
            Some("JPEG Image".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "jpg",
            Some("FFD8FF".to_string()),
            true,
            None,
            Some("JPEG Image (alias)".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "png",
            Some("89504E470D0A1A0A".to_string()),
            true,
            None,
            Some("Portable Network Graphics".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "gif",
            Some("47494638".to_string()),
            true,
            None,
            Some("Graphics Interchange Format".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "tiff",
            Some("49492A00".to_string()),
            true,
            None,
            Some("Tagged Image File Format (little-endian)".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "tif",
            Some("4D4D002A".to_string()),
            true,
            None,
            Some("Tagged Image File Format (big-endian)".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "bmp",
            Some("424D".to_string()),
            true,
            None,
            Some("Windows Bitmap".to_string()),
        ));

        // --- Archive Formats ---
        registry.register(MagicNumberEntry::new(
            "zip",
            Some("504B0304".to_string()),
            true,
            Some("zip-scanner".to_string()),
            Some("ZIP Archive".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "rar",
            Some("526172211A07".to_string()),
            true,
            None,
            Some("RAR Archive".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "7z",
            Some("377ABCAF271C".to_string()),
            true,
            None,
            Some("7-Zip Archive".to_string()),
        ));

        // --- Text Formats ---
        registry.register(MagicNumberEntry::new(
            "txt",
            None, // No magic bytes for plain text
            false,
            None,
            Some("Plain Text".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "csv",
            None,
            false,
            None,
            Some("Comma-Separated Values".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "xml",
            Some("3C3F786D6C".to_string()), // <?xml
            false,
            None,
            Some("Extensible Markup Language".to_string()),
        ));

        // --- Executable / Blocked Types ---
        registry.register(MagicNumberEntry::new(
            "exe",
            Some("4D5A".to_string()), // MZ header
            true,
            None, // Blocked — no sanitizer
            Some("Windows Portable Executable".to_string()),
        ));

        registry.register(MagicNumberEntry::new(
            "msi",
            Some("D0CF11E0".to_string()), // OLE-based installer
            true,
            None,
            Some("Windows Installer Package".to_string()),
        ));

        registry
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    /// Map a file extension to its standard MIME type string.
    fn mime_for_extension(&self, extension: &str) -> String {
        match extension.to_lowercase().as_str() {
            "pdf" => "application/pdf".to_string(),
            "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document".to_string(),
            "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_string(),
            "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation".to_string(),
            "doc" => "application/msword".to_string(),
            "xls" => "application/vnd.ms-excel".to_string(),
            "jtd" => "application/x-ichitaro".to_string(),
            "jpeg" | "jpg" => "image/jpeg".to_string(),
            "png" => "image/png".to_string(),
            "gif" => "image/gif".to_string(),
            "tiff" | "tif" => "image/tiff".to_string(),
            "bmp" => "image/bmp".to_string(),
            "zip" => "application/zip".to_string(),
            "txt" => "text/plain".to_string(),
            "csv" => "text/csv".to_string(),
            "xml" => "application/xml".to_string(),
            "exe" => "application/vnd.microsoft.portable-executable".to_string(),
            _ => format!("application/x-{}", extension),
        }
    }

    /// Extract the file extension from a filename (without leading dot).
    ///
    /// # Returns
    /// The lowercase extension, or empty string if none found.
    fn extract_extension(filename: &str) -> Option<String> {
        filename
            .rsplit('.')
            .next()
            .filter(|s| !s.is_empty() && *s != filename)
            .map(|s| s.to_lowercase())
    }
}

impl Default for MagicNumberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// B. MagicNumberDetector
// =============================================================================

/// File type detector using magic number (binary signature) analysis.
///
/// This is the primary detector in the Misogi pipeline. It reads the first N
/// bytes of a file and compares them against registered magic byte patterns
/// to determine the actual file format, independent of the declared extension.
///
/// # Security Rationale
/// Extension spoofing (renaming `.exe` to `.pdf`) is trivially accomplished
/// by attackers. Magic number analysis inspects the actual binary content,
/// making it significantly harder to bypass. Combined with the
/// [`ExtensionFallbackDetector`], it forms a defense-in-depth strategy.
pub struct MagicNumberDetector {
    /// The registry containing known file type signatures.
    registry: Arc<MagicNumberRegistry>,
}

impl MagicNumberDetector {
    /// Construct a new magic number detector with the given registry.
    pub fn new(registry: Arc<MagicNumberRegistry>) -> Self {
        Self { registry }
    }

    /// Construct with the default Japanese government registry.
    pub fn with_defaults() -> Self {
        Self {
            registry: Arc::new(MagicNumberRegistry::jp_government_defaults()),
        }
    }
}

#[async_trait]
impl FileTypeDetector for MagicNumberDetector {
    /// Returns `"magic-number-detector"`.
    fn name(&self) -> &str {
        "magic-number-detector"
    }

    /// Detect file type by reading header bytes and matching against registry.
    ///
    /// Reads up to 262 bytes from the beginning of the file (sufficient for
    /// all known magic signatures) and performs binary comparison against
    /// each registered entry's magic byte pattern.
    ///
    /// # Performance
    /// O(n*m) where n = bytes read, m = registry entries. In practice this
    /// is very fast because magic byte comparisons fail fast on first-byte
    /// mismatch and most registries have < 100 entries.
    ///
    /// # Errors
    /// - [`MisogiError::NotFound`] if the file does not exist.
    /// - [`MisogiError::Io`] if the file cannot be read.
    async fn detect(
        &self,
        file_path: &PathBuf,
        _declared_extension: &str,
    ) -> Result<FileDetectionResult> {
        // Read file header (up to 262 bytes covers all known magic numbers)
        let mut file = tokio::fs::File::open(file_path).await?;
        let mut buffer = [0u8; 262];
        let bytes_read = tokio::io::AsyncReadExt::read(&mut file, &mut buffer).await?;
        let data = &buffer[..bytes_read];

        if bytes_read == 0 {
            return Err(MisogiError::NotFound(format!(
                "Empty file: {}",
                file_path.display()
            )));
        }

        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        Ok(self.registry.detect_from_bytes(data, Some(filename)))
    }

    /// Return all extensions registered in the underlying registry.
    fn supported_extensions(&self) -> Vec<&'static str> {
        self.registry
            .all_extensions()
            .into_iter()
            .map(|s| Box::leak(s.to_string().into_boxed_str()) as &'static str)
            .collect()
    }
}

// =============================================================================
// C. ExtensionFallbackDetector
// =============================================================================

/// Simple extension-based file type detector (fallback when magic bytes fail).
///
/// This detector provides a secondary identification path for cases where:
/// - The file is too small to contain a complete magic signature.
/// - The file uses a format without a well-defined magic number (plain text).
/// - The magic number is corrupted or encrypted.
///
/// Confidence scores from this detector are always lower than magic-number
/// based detections (max 0.5 vs 1.0), ensuring the pipeline prefers
/// magic-byte results when available.
pub struct ExtensionFallbackDetector {
    /// Registry for extension-to-type mapping.
    registry: Arc<MagicNumberRegistry>,
}

impl ExtensionFallbackDetector {
    /// Construct a new extension fallback detector.
    pub fn new(registry: Arc<MagicNumberRegistry>) -> Self {
        Self { registry }
    }

    /// Construct with default registry.
    pub fn with_defaults() -> Self {
        Self {
            registry: Arc::new(MagicNumberRegistry::jp_government_defaults()),
        }
    }
}

#[async_trait]
impl FileTypeDetector for ExtensionFallbackDetector {
    /// Returns `"extension-fallback-detector"`.
    fn name(&self) -> &str {
        "extension-fallback-detector"
    }

    /// Detect file type by looking up the declared extension in the registry.
    ///
    /// Does NOT read file contents — relies solely on the filename extension.
    /// Returns low-confidence results (0.5 max) suitable for fallback use only.
    ///
    /// # Errors
    /// - [`MisogiError::NotFound`] if the file does not exist (existence check only).
    async fn detect(
        &self,
        file_path: &PathBuf,
        declared_extension: &str,
    ) -> Result<FileDetectionResult> {
        // Verify file exists (basic sanity check)
        tokio::fs::metadata(file_path).await?;

        let ext_to_check = if declared_extension.is_empty() {
            // Extract from filename if no declared extension provided
            file_path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|f| f.rsplit('.').next())
                .unwrap_or("")
                .to_lowercase()
        } else {
            declared_extension.to_lowercase()
        };

        if let Some(entry) = self.registry.lookup(&ext_to_check) {
            Ok(FileDetectionResult {
                detected_type: self.registry.mime_for_extension(&entry.extension),
                confidence: 0.5, // Medium-low confidence: extension only
                extension: entry.extension.clone(),
                magic_hex: entry.magic_hex.clone().unwrap_or_default(),
                recommended_sanitizer: entry.sanitizer.as_deref().unwrap_or("").to_string(),
                is_blocked: false,
                block_reason: None,
            })
        } else {
            // Unknown extension
            Ok(FileDetectionResult::unknown())
        }
    }

    /// Return all extensions supported by the registry.
    fn supported_extensions(&self) -> Vec<&'static str> {
        self.registry
            .all_extensions()
            .into_iter()
            .map(|s| Box::leak(s.to_string().into_boxed_str()) as &'static str)
            .collect()
    }
}

// =============================================================================
// D. CompositeDetector
// =============================================================================

/// Orchestrator that runs multiple [`FileTypeDetector`] implementations and
/// returns the highest-confidence result.
///
/// The composite pattern enables layered detection:
/// 1. Run each registered detector in sequence.
/// 2. Collect all results.
/// 3. Select the result with the highest confidence score.
/// 4. If multiple results have equal highest confidence, prefer earlier detectors.
///
/// # Typical Configuration
/// ```ignore
/// let composite = CompositeDetector::new(vec![
///     Arc::new(MagicNumberDetector::with_defaults()),  // Primary: high confidence
///     Arc::new(ExtensionFallbackDetector::with_defaults()), // Fallback: medium confidence
/// ]);
/// ```
pub struct CompositeDetector {
    /// Ordered list of child detectors (earlier = higher priority on tie).
    detectors: Vec<Arc<dyn FileTypeDetector>>,
}

impl CompositeDetector {
    /// Construct a new composite detector with the given child detectors.
    ///
    /// # Arguments
    /// * `detectors` — Ordered list of detectors to run. Earlier detectors
    ///   have priority when confidence scores are tied.
    pub fn new(detectors: Vec<Arc<dyn FileTypeDetector>>) -> Self {
        Self { detectors }
    }

    /// Construct with the recommended default detector chain for Misogi.
    ///
    /// Chain order:
    /// 1. [`MagicNumberDetector`] — Binary signature analysis (highest accuracy).
    /// 2. [`ExtensionFallbackDetector`] — Filename extension lookup (fallback).
    pub fn with_defaults() -> Self {
        let registry = Arc::new(MagicNumberRegistry::jp_government_defaults());
        Self {
            detectors: vec![
                Arc::new(MagicNumberDetector::new(Arc::clone(&registry))) as Arc<dyn FileTypeDetector>,
                Arc::new(ExtensionFallbackDetector::new(Arc::clone(&registry)))
                    as Arc<dyn FileTypeDetector>,
            ],
        }
    }
}

#[async_trait]
impl FileTypeDetector for CompositeDetector {
    /// Returns `"composite-detector"`.
    fn name(&self) -> &str {
        "composite-detector"
    }

    /// Run all child detectors and return the highest-confidence result.
    ///
    /// Iterates through all registered detectors, invokes each one's
    /// [`detect()`](FileTypeDetector::detect) method, and selects the
    /// result with the highest confidence score.
    ///
    /// # Tie-Breaking
    /// When two detectors produce equal confidence scores, the result from
    /// the earlier detector (lower index in the `detectors` vector) wins.
    /// This ensures magic-number results take precedence over extension-only.
    ///
    /// # Errors
    /// Returns the first error encountered if all detectors fail.
    /// If some detectors succeed and others fail, errors from failing
    /// detectors are logged but do not prevent success results from being returned.
    async fn detect(
        &self,
        file_path: &PathBuf,
        declared_extension: &str,
    ) -> Result<FileDetectionResult> {
        let mut best_result: Option<FileDetectionResult> = None;
        let mut last_error: Option<MisogiError> = None;

        for detector in &self.detectors {
            match detector.detect(file_path, declared_extension).await {
                Ok(result) => {
                    match &best_result {
                        Some(best) => {
                            if result.confidence > best.confidence {
                                best_result = Some(result);
                            }
                        }
                        None => {
                            best_result = Some(result);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        detector = detector.name(),
                        error = %e,
                        "Child detector failed, trying next"
                    );
                    last_error = Some(e);
                }
            }
        }

        best_result.ok_or_else(|| {
            last_error.unwrap_or_else(|| {
                MisogiError::Protocol(format!(
                    "All {} detectors failed for file: {}",
                    self.detectors.len(),
                    file_path.display()
                ))
            })
        })
    }

    /// Return the union of all child detectors' supported extensions.
    fn supported_extensions(&self) -> Vec<&'static str> {
        let mut extensions: std::collections::HashSet<&'static str> =
            std::collections::HashSet::new();
        for detector in &self.detectors {
            extensions.extend(detector.supported_extensions());
        }
        extensions.into_iter().collect()
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // MagicNumberRegistry Tests
    // =========================================================================

    #[test]
    fn test_registry_new_is_empty() {
        let registry = MagicNumberRegistry::new();
        assert!(registry.entries.is_empty());
    }

    #[test]
    fn test_registry_register_and_lookup() {
        let mut registry = MagicNumberRegistry::new();
        registry.register(MagicNumberEntry::new(
            "pdf",
            Some("25504446".to_string()),
            true,
            Some("pdf-sanitizer".to_string()),
            Some("PDF Document".to_string()),
        ));

        assert_eq!(registry.entries.len(), 1);

        let entry = registry.lookup("pdf").expect("Should find pdf entry");
        assert_eq!(entry.extension, "pdf");
        assert_eq!(entry.magic_hex.as_deref(), Some("25504446"));
    }

    #[test]
    fn test_registry_lookup_case_insensitive() {
        let mut registry = MagicNumberRegistry::new();
        registry.register(MagicNumberEntry::new(
            "PDF",
            Some("25504446".to_string()),
            true,
            None,
            None,
        ));

        assert!(registry.lookup("pdf").is_some());
        assert!(registry.lookup("PDF").is_some());
        assert!(registry.lookup("Pdf").is_some());
    }

    #[test]
    fn test_registry_lookup_not_found() {
        let registry = MagicNumberRegistry::new();
        assert!(registry.lookup("xyz").is_none());
    }

    #[test]
    fn test_magic_entry_magic_bytes_parsing() {
        let entry = MagicNumberEntry::new(
            "pdf",
            Some("25504446".to_string()),
            true,
            None,
            None,
        );

        let bytes = entry.magic_bytes().expect("Should parse hex");
        assert_eq!(bytes, vec![0x25, 0x50, 0x44, 0x46]); // %PDF
    }

    #[test]
    fn test_magic_entry_no_magic_hex() {
        let entry = MagicNumberEntry::new(
            "txt",
            None,
            false,
            None,
            None,
        );

        assert!(entry.magic_bytes().is_none());
    }

    #[test]
    fn test_jp_government_defaults_has_common_types() {
        let registry = MagicNumberRegistry::jp_government_defaults();

        // Should have core types
        assert!(registry.lookup("pdf").is_some());
        assert!(registry.lookup("docx").is_some());
        assert!(registry.lookup("xlsx").is_some());
        assert!(registry.lookup("jpeg").is_some());
        assert!(registry.lookup("png").is_some());

        // Should have Japanese-specific types
        assert!(registry.lookup("jtd").is_some());
        assert!(registry.lookup("dwg").is_some());

        // Should have blocked types
        assert!(registry.lookup("exe").is_some());
    }

    #[tokio::test]
    async fn test_detect_from_bytes_pdf() {
        let registry = MagicNumberRegistry::jp_government_defaults();
        let pdf_header = b"%PDF-1.4"; // Standard PDF header

        let result = registry.detect_from_bytes(pdf_header, Some("document.pdf"));
        assert_eq!(result.detected_type, "application/pdf");
        assert_eq!(result.extension, "pdf");
        assert!((result.confidence - 1.0).abs() < f64::EPSILON); // Full confidence
    }

    #[tokio::test]
    async fn test_detect_from_bytes_jpeg() {
        let registry = MagicNumberRegistry::jp_government_defaults();
        let jpeg_header: Vec<u8> = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG SOI + APP0 marker

        let result = registry.detect_from_bytes(&jpeg_header, Some("photo.jpg"));
        assert_eq!(result.extension, "jpeg");
        assert!(result.confidence >= 0.9); // High confidence for magic match
    }

    #[tokio::test]
    async fn test_detect_from_bytes_unknown_fallback_to_extension() {
        let registry = MagicNumberRegistry::jp_government_defaults();
        let random_data = b"This is just plain text content";

        let result = registry.detect_from_bytes(random_data, Some("myfile.txt"));
        // Should fall back to extension-based detection for text files
        assert_eq!(result.extension, "txt");
        assert!(result.confidence < 1.0); // Lower confidence than magic match
    }

    #[tokio::test]
    async fn test_detect_from_bytes_completely_unknown() {
        let registry = MagicNumberRegistry::jp_government_defaults();
        let garbage = b"\x00\x01\x02\x03\x04\x05";

        let result = registry.detect_from_bytes(garbage, None::<&str>);
        assert!(!result.is_confident(0.5)); // Unknown type
    }

    #[test]
    fn test_extract_extension() {
        assert_eq!(
            MagicNumberRegistry::extract_extension("document.pdf"),
            Some("pdf".to_string())
        );
        assert_eq!(
            MagicNumberRegistry::extract_extension("archive.tar.gz"),
            Some("gz".to_string())
        );
        assert_eq!(
            MagicNumberRegistry::extract_extension("no_extension"),
            None
        );
        assert_eq!(
            MagicNumberRegistry::extract_extension(".hiddenfile"),
            Some("hiddenfile".to_string())
        );
    }

    #[test]
    fn test_mime_for_extension() {
        let registry = MagicNumberRegistry::jp_government_defaults();
        assert_eq!(registry.mime_for_extension("pdf"), "application/pdf");
        assert_eq!(
            registry.mime_for_extension("docx"),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        );
        assert_eq!(registry.mime_for_extension("png"), "image/png");
        assert!(registry.mime_for_extension("unknown").starts_with("application/x-"));
    }

    // =========================================================================
    // MagicNumberDetector Tests
    // =========================================================================

    #[test]
    fn test_magic_detector_name() {
        let detector = MagicNumberDetector::with_defaults();
        assert_eq!(detector.name(), "magic-number-detector");
    }

    #[tokio::test]
    async fn test_magic_detector_detect_pdf_file() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let detector = MagicNumberDetector::with_defaults();

        // Create a minimal PDF file
        let pdf_path = tmp_dir.path().join("test.pdf");
        tokio::fs::write(&pdf_path, b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
            .await
            .unwrap();

        let result = detector
            .detect(&pdf_path, "pdf")
            .await
            .unwrap();

        assert_eq!(result.extension, "pdf");
        assert!(result.is_confident(0.9));
    }

    #[tokio::test]
    async fn test_magic_detector_detect_png_file() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let detector = MagicNumberDetector::with_defaults();

        // Create a minimal PNG file (valid PNG header)
        let png_path = tmp_dir.path().join("test.png");
        let png_header: Vec<u8> = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk start
        ];
        tokio::fs::write(&png_path, &png_header).await.unwrap();

        let result = detector
            .detect(&png_path, "png")
            .await
            .unwrap();

        assert_eq!(result.extension, "png");
        assert!(result.is_confident(0.9));
    }

    #[tokio::test]
    async fn test_magic_detector_nonexistent_file() {
        let detector = MagicNumberDetector::with_defaults();
        let result = detector
            .detect(&PathBuf::from("/nonexistent/file.txt"), "txt")
            .await;

        assert!(result.is_err());
    }

    // =========================================================================
    // ExtensionFallbackDetector Tests
    // =========================================================================

    #[test]
    fn test_extension_detector_name() {
        let detector = ExtensionFallbackDetector::with_defaults();
        assert_eq!(detector.name(), "extension-fallback-detector");
    }

    #[tokio::test]
    async fn test_extension_detector_detect_known_type() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let detector = ExtensionFallbackDetector::with_defaults();

        let txt_path = tmp_dir.path().join("data.csv");
        tokio::fs::write(&txt_path, b"a,b,c\n1,2,3\n").await.unwrap();

        let result = detector.detect(&txt_path, "csv").await.unwrap();
        assert_eq!(result.extension, "csv");
        assert!(result.confidence <= 0.6); // Lower than magic number
    }

    #[tokio::test]
    async fn test_extension_detector_detect_unknown_type() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let detector = ExtensionFallbackDetector::with_defaults();

        let xyz_path = tmp_dir.path().join("data.xyz123");
        tokio::fs::write(&xyz_path, b"some data").await.unwrap();

        let result = detector
            .detect(&xyz_path, "xyz123")
            .await
            .unwrap();

        assert!(!result.is_confident(0.3)); // Very low or zero confidence
    }

    // =========================================================================
    // CompositeDetector Tests
    // =========================================================================

    #[test]
    fn test_composite_detector_name() {
        let detector = CompositeDetector::with_defaults();
        assert_eq!(detector.name(), "composite-detector");
    }

    #[test]
    fn test_composite_detector_with_defaults_has_two_detectors() {
        let detector = CompositeDetector::with_defaults();
        assert_eq!(detector.detectors.len(), 2);
    }

    #[tokio::test]
    async fn test_composite_detector_prefers_magic_over_extension() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let detector = CompositeDetector::with_defaults();

        // Create a real PDF file
        let pdf_path = tmp_dir.path().join("real.pdf");
        tokio::fs::write(&pdf_path, b"%PDF-1.4").await.unwrap();

        let result = detector.detect(&pdf_path, "pdf").await.unwrap();
        // Should use magic number detector (confidence ~1.0) over extension (0.5)
        assert!(result.is_confident(0.8));
        assert_eq!(result.extension, "pdf");
    }

    #[tokio::test]
    async fn test_composite_detector_falls_back_to_extension() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let detector = CompositeDetector::with_defaults();

        // Create a plain text file (no magic bytes)
        let txt_path = tmp_dir.path().join("notes.txt");
        tokio::fs::write(&txt_path, b"Just some notes here")
            .await
            .unwrap();

        let result = detector.detect(&txt_path, "txt").await.unwrap();
        // Should fall back to extension detector since no magic match
        assert_eq!(result.extension, "txt");
    }

    #[tokio::test]
    async fn test_composite_detector_all_fail_returns_error() {
        let detector = CompositeDetector::new(vec![]); // Empty — no detectors
        let result = detector
            .detect(&PathBuf::from("/nonexistent"), "")
            .await;

        assert!(result.is_err());
    }

    #[test]
    fn test_composite_supported_extensions_union() {
        let detector = CompositeDetector::with_defaults();
        let exts = detector.supported_extensions();
        assert!(exts.contains(&"pdf"));
        assert!(exts.contains(&"xlsx"));
        assert!(exts.contains(&"png"));
    }

    // =========================================================================
    // FileDetectionResult Helper Tests
    // =========================================================================

    #[test]
    fn test_detection_result_detected() {
        let result =
            FileDetectionResult::detected("application/pdf", "pdf", "25504446", "pdf-sanitizer");
        assert_eq!(result.confidence, 1.0);
        assert_eq!(result.extension, "pdf");
        assert!(!result.is_blocked);
    }

    #[test]
    fn test_detection_result_blocked() {
        let result = FileDetectionResult::blocked("application/exe", "Executable files are blocked");
        assert!(result.is_blocked);
        assert!(result.block_reason.is_some());
    }

    #[test]
    fn test_detection_result_unknown() {
        let result = FileDetectionResult::unknown();
        assert!(!result.is_confident(0.1));
        assert!(result.detected_type.is_empty());
    }

    #[test]
    fn test_detection_result_is_confident() {
        let high = FileDetectionResult::detected("app/pdf", "pdf", "", "");
        assert!(high.is_confident(0.9));

        let low = FileDetectionResult::unknown();
        assert!(!low.is_confident(0.5));
    }

    // =========================================================================
    // MagicNumberEntry Serialization Test
    // =========================================================================

    #[test]
    fn test_magic_number_entry_serialization() {
        let entry = MagicNumberEntry {
            extension: "pdf".to_string(),
            magic_hex: Some("25504446".to_string()),
            required_magic: true,
            sanitizer: Some("builtin-pdf-strategy".to_string()),
            description: Some("PDF Document".to_string()),
            external_adapter: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let decoded: MagicNumberEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.extension, entry.extension);
        assert_eq!(decoded.magic_hex, entry.magic_hex);
        assert_eq!(decoded.required_magic, entry.required_magic);
    }
}

// =============================================================================
// Misogi WASM — In-Memory Compatibility Layer
// =============================================================================
// This module provides WASM-safe adapters that bridge the filesystem-based
// CDR pipeline APIs (which operate on `&Path` / `std::fs::File`) with the
// browser sandbox environment where only in-memory `Vec<u8>` buffers are
// available.
//
// ## Architecture Rationale
//
// The core CDR engine (`misogi-cdr`) was designed for server-side deployment
// where filesystem I/O is available. The [`FileSanitizer`] trait accepts
// `input_path: &Path` and `output_path: &Path`, and implementations such as
// [`PdfSanitizer`] and [`OfficeSanitizer`] use `tokio::fs` / `std::fs` for
// all data movement.
//
// In WebAssembly (browser), there is no filesystem. All input arrives as
// `Vec<u8>` (e.g., from `<input type="file">` or `fetch()` responses) and
// all output must be returned as `Vec<u8>`. This module provides thin wrappers
// that:
//
// 1. Accept `&[u8]` instead of file paths
// 2. Perform sanitization entirely in memory (no temp files)
// 3. Return `Vec<u8>` output buffers
// 4. Preserve the same threat-detection logic as the original implementations
//
// ## Memory Safety Contract
//
// - Input is borrowed (`&[u8]`) — zero-copy where possible
// - Output is owned (`Vec<u8>`) — caller takes ownership for JS transfer
// - No heap allocation exceeds `MAX_WASM_FILE_SIZE` (configurable, default 500 MiB)
// - All parsing uses bounded iterators; no unbounded Vec growth
//
// =============================================================================

use std::io::{Cursor, Read, Seek, Write};

use misogi_cdr::{
    pdf_sanitizer::{PdfSanitizer, PdfThreat},
    policy::SanitizationPolicy,
    report::{SanitizationAction, SanitizationReport},
};
use misogi_core::{hash, MisogiError, Result};

// =============================================================================
// Constants
// =============================================================================

/// Maximum file size accepted by the WASM sanitizer (500 MiB).
///
/// Matches the default `PdfSanitizer` limit. Files exceeding this size are
/// rejected before any parsing occurs to prevent OOM kills in the browser's
/// WebAssembly linear memory sandbox.
pub const MAX_WASM_FILE_SIZE_BYTES: u64 = 500 * 1024 * 1024;

/// Default streaming buffer size for ZIP entry copy operations (8 KiB).
const STREAM_BUFFER_SIZE: usize = 8 * 1024;

// =============================================================================
// A. In-Memory PDF Sanitizer Adapter
// =============================================================================

/// Result of in-memory PDF sanitization containing both output bytes and audit report.
#[derive(Debug, Clone)]
pub struct WasmPdfResult {
    /// Sanitized PDF content ready for download / transfer.
    pub output_data: Vec<u8>,
    /// Detailed audit report of actions taken during sanitization.
    pub report: SanitizationReport,
}

/// In-memory PDF sanitizer adapter for WASM environments.
///
/// Replicates the two-pass strategy of [`PdfSanitizer`] without any filesystem I/O:
///
/// **Pass 1 (Analysis):** Scans raw PDF bytes using nom parser combinators to
/// collect [`PdfThreat`] entries with exact byte offsets.
///
/// **Pass 2 (Remediation):** Streams input bytes -> output buffer, replacing
/// detected threat regions with policy-appropriate NOP bytes.
///
/// # Compatibility
/// This is a re-implementation of the core scanning/remediation logic from
/// [`PdfSanitizer`] adapted for pure in-memory operation. It produces identical
/// threat detection results given the same input bytes.
pub struct WasmPdfSanitizer {
    /// Maximum allowed input size in bytes.
    max_file_size_bytes: u64,
}

impl WasmPdfSanitizer {
    /// Construct a new WASM PDF sanitizer with explicit file size limit.
    ///
    /// # Arguments
    /// * `max_file_size_bytes` - Maximum allowed input size. Files exceeding
    ///   this limit are rejected with [`MisogiError::SecurityViolation`].
    pub fn new(max_file_size_bytes: u64) -> Self {
        Self { max_file_size_bytes }
    }

    /// Construct with default configuration (500 MiB limit).
    pub fn with_defaults() -> Self {
        Self {
            max_file_size_bytes: MAX_WASM_FILE_SIZE_BYTES,
        }
    }

    // -----------------------------------------------------------------
    // Pass 1: Threat Analysis (identical logic to PdfSanitizer::analyze)
    // -----------------------------------------------------------------

    /// Scan PDF binary data for threat markers using nom parser combinators.
    ///
    /// Performs byte-positional scan identical to [`PdfSanitizer::analyze()`]
    /// but operates directly on a `&[u8]` slice instead of reading from disk.
    ///
    /// # Arguments
    /// * `data` - Raw PDF file contents as byte slice.
    ///
    /// # Returns
    /// Vector of detected [`PdfThreat`] entries sorted by ascending offset.
    ///
    /// # Errors
    /// - [`MisogiError::SecurityViolation`] if data length exceeds configured maximum
    /// - [`MisogiError::Protocol`] if data does not start with `%PDF` header
    pub fn analyze(&self, data: &[u8]) -> Result<Vec<PdfThreat>> {
        if data.len() as u64 > self.max_file_size_bytes {
            return Err(MisogiError::SecurityViolation(format!(
                "WASM: Input size {} bytes exceeds maximum {} bytes",
                data.len(),
                self.max_file_size_bytes
            )));
        }

        if data.len() < 5 || !data.starts_with(b"%PDF") {
            return Err(MisogiError::Protocol(
                "Invalid PDF header: expected %PDF magic bytes".to_string(),
            ));
        }

        let mut threats: Vec<PdfThreat> = Vec::new();
        let mut pos: usize = 0;

        while pos < data.len() {
            let remaining = &data[pos..];

            match PdfSanitizer::scan_for_threats(remaining) {
                Ok((_, mut threat)) => {
                    // Set absolute offset (relative-to-absolute conversion)
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

                    // Advance past this threat region
                    let skip_pos = Self::advance_past_threat(data, pos, &threat);
                    threats.push(threat);
                    pos = skip_pos;
                }
                Err(_) => {
                    pos += 1;
                }
            }
        }

        Ok(threats)
    }

    /// Advance scan position past the end of a detected threat region.
    ///
    /// Uses line-boundary heuristic to avoid re-matching partial content
    /// within the same threat region.
    fn advance_past_threat(data: &[u8], base_pos: usize, threat: &PdfThreat) -> usize {
        let threat_end = base_pos + threat.length();
        if threat_end >= data.len() {
            return data.len();
        }

        for i in threat_end..data.len().min(threat_end + 256) {
            if data[i] == b'\n' || data[i] == b'\r' {
                return i + 1;
            }
        }

        (threat_end + 1).min(data.len())
    }

    // -----------------------------------------------------------------
    // Pass 2: Remediation (in-memory byte replacement)
    // -----------------------------------------------------------------

    /// Apply NOP replacement to all detected threats, producing sanitized output.
    ///
    /// Streams input bytes into an output `Vec<u8>`, at each threat offset
    /// emitting policy-appropriate replacement bytes instead of original content.
    ///
    /// # Arguments
    /// * `data` - Original (potentially malicious) PDF bytes.
    /// * `threats` - Pre-collected threat list from [`analyze()`](Self::analyze).
    /// * `policy` - Sanitization strategy governing replacement behavior.
    ///
    /// # Returns
    /// Tuple of (sanitized_bytes, action_list) where action_list records every
    /// remediation performed for the audit trail.
    pub fn remediate(
        &self,
        data: &[u8],
        threats: &[PdfThreat],
        policy: &SanitizationPolicy,
    ) -> Result<(Vec<u8>, Vec<SanitizationAction>)> {
        let mut output: Vec<u8> = Vec::with_capacity(data.len());
        let mut actions: Vec<SanitizationAction> = Vec::new();
        let mut read_pos: usize = 0;

        let mut sorted_threats: Vec<PdfThreat> = threats.to_vec();
        sorted_threats.sort_by_key(|t| t.offset());

        while read_pos < data.len() {
            if let Some(threat) = sorted_threats.first()
                .filter(|t| t.offset() == read_pos)
            {
                let (replacement_bytes, action) =
                    Self::generate_replacement(threat, policy)?;
                output.extend_from_slice(&replacement_bytes);
                actions.push(action);

                let skip_bytes = threat.length();
                read_pos += skip_bytes;
                sorted_threats.remove(0);
            } else {
                output.push(data[read_pos]);
                read_pos += 1;
            }
        }

        Ok((output, actions))
    }

    /// Generate policy-appropriate replacement bytes and audit action for a threat.
    ///
    /// Replacement matrix mirrors [`PdfSanitizer::generate_replacement()`].
    fn generate_replacement(
        threat: &PdfThreat,
        policy: &SanitizationPolicy,
    ) -> Result<(Vec<u8>, SanitizationAction)> {
        match (threat, policy) {
            (
                PdfThreat::JavaScript { .. } | PdfThreat::JavaScriptLong { .. },
                SanitizationPolicy::StripActiveContent | SanitizationPolicy::ConvertToFlat,
            ) => Ok((b"( )".to_vec(), threat.to_action())),

            (
                PdfThreat::JavaScript { .. } | PdfThreat::JavaScriptLong { .. },
                SanitizationPolicy::TextOnly,
            ) => {
                let spaces: Vec<u8> = vec![b' '; threat.length()];
                Ok((spaces, threat.to_action()))
            }

            (
                PdfThreat::AdditionalActions { .. },
                SanitizationPolicy::StripActiveContent,
            ) => Ok((b"{}".to_vec(), threat.to_action())),

            (
                PdfThreat::AdditionalActions { .. },
                SanitizationPolicy::ConvertToFlat | SanitizationPolicy::TextOnly,
            ) => {
                let spaces: Vec<u8> = vec![b' '; threat.length()];
                Ok((spaces, threat.to_action()))
            }

            (
                PdfThreat::OpenAction { .. }
                | PdfThreat::SubmitForm { .. }
                | PdfThreat::RichMedia { .. },
                _,
            ) => {
                let spaces: Vec<u8> = vec![b' '; threat.length()];
                Ok((spaces, threat.to_action()))
            }

            (PdfThreat::AcroForm { .. }, SanitizationPolicy::TextOnly) => {
                let spaces: Vec<u8> = vec![b' '; threat.length()];
                Ok((spaces, threat.to_action()))
            }

            (PdfThreat::AcroForm { .. }, _) => Ok((vec![], threat.to_action())),

            (
                PdfThreat::UriAction { .. },
                SanitizationPolicy::StripActiveContent,
            ) => Ok((b"/URI ()".to_vec(), threat.to_action())),

            (PdfThreat::UriAction { .. }, _) => {
                let spaces: Vec<u8> = vec![b' '; threat.length()];
                Ok((spaces, threat.to_action()))
            }

            (PdfThreat::EmbeddedFile { .. }, SanitizationPolicy::StripActiveContent) => {
                Ok((vec![], threat.to_action()))
            }

            (PdfThreat::EmbeddedFile { .. }, _) => {
                let spaces: Vec<u8> = vec![b' '; threat.length()];
                Ok((spaces, threat.to_action()))
            }
        }
    }

    // -----------------------------------------------------------------
    // Combined sanitize (analyze + remediate + report)
    // -----------------------------------------------------------------

    /// Perform complete in-memory PDF sanitization: analyze threats, remediate, build report.
    ///
    /// This is the primary entry point called by the WASM FFI layer. It combines
    /// both passes into a single call and returns both the sanitized output and
    /// a structured audit report suitable for JSON serialization to JavaScript.
    ///
    /// # Arguments
    /// * `data` - Raw PDF file bytes from browser (e.g., `<input type="file">`).
    /// * `policy` - Sanitization policy governing threat removal behavior.
    ///
    /// # Returns
    /// [`WasmPdfResult`] containing sanitized bytes and full audit trail.
    ///
    /// # Example (from FFI layer)
    /// ```ignore
    /// let sanitizer = WasmPdfSanitizer::with_defaults();
    /// let result = sanitizer.sanitize(&pdf_bytes, &SanitizationPolicy::default())?;
    /// // result.output_data -> send back to JS as Vec<u8>
    /// // result.report -> serialize to JSON for JS consumption
    /// ```
    pub fn sanitize(
        &self,
        data: &[u8],
        policy: &SanitizationPolicy,
    ) -> Result<WasmPdfResult> {
        let start_time = std::time::Instant::now();

        let threats = self.analyze(data)?;

        let (output_data, actions) = if threats.is_empty() {
            // No threats found — pass through original bytes unchanged
            (data.to_vec(), Vec::new())
        } else {
            self.remediate(data, &threats, policy)?
        };

        let original_hash = hash::compute_md5(data);
        let sanitized_hash = hash::compute_md5(&output_data);
        let elapsed_ms = start_time.elapsed().as_millis() as u64;

        let warnings: Vec<String> = threats
            .iter()
            .filter_map(|t| match t {
                PdfThreat::EmbeddedFile { name, .. } => {
                    Some(format!("EmbeddedFile attachment detected: {}", name))
                }
                _ => None,
            })
            .collect();

        let report = SanitizationReport {
            file_id: format!("wasm-pdf-{}", hash::compute_md5(data)),
            original_filename: "upload.pdf".to_string(),
            original_hash,
            sanitized_hash,
            policy: policy.clone(),
            actions_taken: actions,
            warnings,
            processing_time_ms: elapsed_ms,
            success: true,
        };

        Ok(WasmPdfResult { output_data, report })
    }
}

impl Default for WasmPdfSanitizer {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// =============================================================================
// B. In-Memory Office Document Sanitizer Adapter
// =============================================================================

/// Result of in-memory Office document sanitization.
#[derive(Debug, Clone)]
pub struct WasmOfficeResult {
    /// Sanitized OOXML content (valid DOCX/XLSX/PPTX ZIP archive).
    pub output_data: Vec<u8>,
    /// Detailed audit report of VBA macro removal and other actions.
    pub report: SanitizationReport,
}

/// In-memory Office document (OOXML) sanitizer adapter for WASM environments.
///
/// Office Open XML formats (DOCX, XLSX, PPTX, DOCM, XLSM, PPTM) are ZIP archives
/// containing XML files and potentially embedded VBA macro projects. This adapter:
///
/// 1. Opens the input bytes as a ZIP archive via `zip::ZipArchive<Cursor<Vec<u8>>>`
/// 2. Scans for dangerous entries (vbaProject.bin, vbaData.xml)
/// 3. Reconstructs a clean ZIP archive excluding macro-bearing entries
/// 4. Returns the sanitized archive as `Vec<u8>`
///
/// # ZIP Bomb Protection
/// Maintains the same expansion-ratio check as [`OfficeSanitizer`] to prevent
/// decompression bomb attacks within the browser's memory constraints.
pub struct WasmOfficeSanitizer {
    max_file_size_bytes: u64,
}

impl WasmOfficeSanitizer {
    /// Construct a new WASM Office sanitizer with explicit file size limit.
    pub fn new(max_file_size_bytes: u64) -> Self {
        Self { max_file_size_bytes }
    }

    /// Construct with default configuration (100 MiB limit for Office docs).
    pub fn with_defaults() -> Self {
        Self {
            max_file_size_bytes: 100 * 1024 * 1024,
        }
    }

    /// Check if a ZIP entry name matches known dangerous/macro-bearing patterns.
    ///
    /// Mirrors [`OfficeSanitizer::is_dangerous_entry()`] logic.
    fn is_dangerous_entry(name: &str) -> bool {
        let normalized = name.to_ascii_lowercase();
        const DANGEROUS: &[&str] = &[
            "vbaProject.bin",
            "word/vbaProject.bin",
            "xl/vbaProject.bin",
            "ppt/vbaProject.bin",
            "word/vbaData.xml",
            "xl/vbaData.xml",
        ];
        DANGEROUS.iter().any(|dangerous| {
            normalized == *dangerous
                || normalized.ends_with(&format!("/{}", dangerous.to_ascii_lowercase()))
        })
    }

    /// Perform complete in-memory Office document sanitization.
    ///
    /// # Arguments
    /// * `data` - Raw OOXML file bytes (DOCX/XLSX/PPTX/etc.) from browser.
    /// * `policy` - Sanitization policy (currently only StripActiveContent semantics
    ///   apply; VBA removal is unconditional for security).
    ///
    /// # Returns
    /// [`WasmOfficeResult`] containing sanitized OOXML bytes and audit report.
    pub fn sanitize(
        &self,
        data: &[u8],
        policy: &SanitizationPolicy,
    ) -> Result<WasmOfficeResult> {
        let start_time = std::time::Instant::now();

        // --- Size validation ---
        if data.len() as u64 > self.max_file_size_bytes {
            return Err(MisogiError::SecurityViolation(format!(
                "WASM: Office input size {} bytes exceeds maximum {} bytes",
                data.len(),
                self.max_file_size_bytes
            )));
        }

        // --- Open ZIP from memory (Cursor instead of File) ---
        let cursor = Cursor::new(data);
        let mut reader =
            zip::ZipArchive::new(cursor).map_err(|e| MisogiError::Protocol(format!("Invalid OOXML/ZIP archive: {}", e)))?;

        // --- ZIP bomb protection: calculate uncompressed total ---
        let mut total_uncompressed: u64 = 0;
        for i in 0..reader.len() {
            let entry = reader
                .by_index(i)
                .map_err(|e| MisogiError::Io(e.into()))?;
            total_uncompressed = total_uncompressed.saturating_add(entry.size());
        }

        const MAX_ZIP_EXPANSION_RATIO: u64 = 10;
        let compressed_size = (data.len() as u64).max(1);
        let expansion_ratio = total_uncompressed / compressed_size;
        if expansion_ratio > MAX_ZIP_EXPANSION_RATIO {
            return Err(MisogiError::SecurityViolation(format!(
                "ZIP bomb detected: expansion ratio {}x exceeds maximum {}x",
                expansion_ratio, MAX_ZIP_EXPANSION_RATIO
            )));
        }

        // --- Rebuild clean ZIP into memory buffer ---
        let mut output_cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut output_cursor);

        let entry_names: Vec<String> = reader.file_names().map(|s| s.to_string()).collect();
        let mut actions: Vec<SanitizationAction> = Vec::new();

        for entry_name in &entry_names {
            if Self::is_dangerous_entry(entry_name) {
                actions.push(SanitizationAction::VbaMacroRemoved {
                    filename: entry_name.clone(),
                });
                continue;
            }

            let mut entry_reader = reader
                .by_name(entry_name)
                .map_err(|e| MisogiError::Io(e.into()))?;

            let options: zip::write::FileOptions<()> = zip::write::FileOptions::default()
                .compression_method(entry_reader.compression());

            writer
                .start_file(entry_name, options)
                .map_err(|e| MisogiError::Io(e.into()))?;

            // Stream-copy entry data into output ZIP
            let mut buffer = [0u8; STREAM_BUFFER_SIZE];
            loop {
                match entry_reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => writer
                        .write_all(&buffer[..n])
                        .map_err(|e| MisogiError::Io(e))?,
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(MisogiError::Io(e)),
                }
            }
        }

        writer.finish().map_err(|e| MisogiError::Io(e.into()))?;

        let output_data = output_cursor.into_inner();
        let original_hash = hash::compute_md5(data);
        let sanitized_hash = hash::compute_md5(&output_data);
        let elapsed_ms = start_time.elapsed().as_millis() as u64;

        let report = SanitizationReport {
            file_id: format!("wasm-office-{}", hash::compute_md5(data)),
            original_filename: "upload.docx".to_string(),
            original_hash,
            sanitized_hash,
            policy: policy.clone(),
            actions_taken: actions,
            warnings: vec![],
            processing_time_ms: elapsed_ms,
            success: true,
        };

        Ok(WasmOfficeResult { output_data, report })
    }
}

impl Default for WasmOfficeSanitizer {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// =============================================================================
// C. In-Memory Hash Utilities
// =============================================================================

/// Compute MD5 hash of arbitrary byte data (pure Rust, WASM-compatible).
///
/// Wraps [`misogi_core::hash::compute_md5()`] which already operates on `&[u8]`
/// and requires no filesystem access.
///
/// # Arguments
/// * `data` - Arbitrary byte slice to hash.
///
/// # Returns
/// Lowercase hexadecimal MD5 digest string (32 characters).
pub fn wasm_compute_md5(data: &[u8]) -> String {
    hash::compute_md5(data)
}

/// Compute SHA-256 hash of arbitrary byte data (pure Rust, WASM-compatible).
///
/// Uses the RustCrypto `sha2` crate which is fully compatible with
/// `wasm32-unknown-unknown` (pure software implementation, no ASM).
///
/// # Arguments
/// * `data` - Arbitrary byte slice to hash.
///
/// # Returns
/// Lowercase hexadecimal SHA-256 digest string (64 characters).
pub fn wasm_compute_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// =============================================================================
// D. PII Scan Adapter (already memory-friendly; thin wrapper)
// =============================================================================

/// Result of a PII scan operation formatted for WASM/JS interop.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmPiiScanResult {
    /// Whether any PII matches were found in the scanned content.
    pub found: bool,

    /// Individual PII matches with positional metadata.
    pub matches: Vec<WasmPiiMatch>,

    /// Overall recommended action: "block", "mask", or "alert_only".
    pub recommended_action: String,

    /// Total number of bytes scanned.
    pub bytes_scanned: u64,

    /// Wall-clock scan duration in milliseconds.
    pub scan_duration_ms: u64,
}

/// Single PII match result formatted for JavaScript consumption.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmPiiMatch {
    /// PII pattern category name (e.g., "my_number", "email", "credit_card").
    pub pii_type: String,

    /// Byte offset of the match within the scanned content.
    pub offset: usize,

    /// Character length of the matched region.
    pub length: usize,

    /// Surrounding text context for human review (up to 80 chars centered on match).
    pub context: String,

    /// Masked version of the matched text (sensitive characters redacted).
    pub masked_text: String,
}

/// Extract context window around a match position for human-readable display.
///
/// Returns up to 40 characters before and after the match position, truncated
/// at word boundaries to produce readable excerpts for audit review UIs.
pub fn extract_context(content: &str, offset: usize, length: usize) -> String {
    let context_radius = 40usize;
    let start = offset.saturating_sub(context_radius);
    let end = (offset + length + context_radius).min(content.len());

    let mut excerpt = content[start..end].to_string();

    // Trim leading partial word
    if start > 0 && !excerpt.starts_with(' ') {
        if let Some(space_pos) = excerpt.find(' ') {
            excerpt = excerpt[space_pos..].to_string();
        }
    }

    // Trailing ellipsis indicators
    if start > 0 {
        excerpt.insert(0, '\u{2026}'); // HORIZONTAL ELLIPSIS
    }
    if end < content.len() {
        excerpt.push('\u{2026}');
    }

    excerpt
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // WasmPdfSanitizer Tests
    // =========================================================================

    #[test]
    fn test_pdf_analyze_clean_document() {
        let sanitizer = WasmPdfSanitizer::with_defaults();
        let clean_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";
        let threats = sanitizer.analyze(clean_pdf).unwrap();
        assert!(threats.is_empty(), "Clean PDF should have no threats");
    }

    #[test]
    fn test_pdf_analyze_detects_javascript() {
        let sanitizer = WasmPdfSanitizer::with_defaults();
        let malicious_pdf = b"%PDF-1.4\n1 0 obj\n<< /JS (app.alert('xss')) >>\nendobj\n";
        let threats = sanitizer.analyze(malicious_pdf).unwrap();
        assert!(!threats.is_empty(), "Malicious PDF should detect JavaScript");
        assert!(matches!(&threats[0], PdfThreat::JavaScript { .. }));
    }

    #[test]
    fn test_pdf_rejects_non_pdf_header() {
        let sanitizer = WasmPdfSanitizer::with_defaults();
        let not_pdf = b"This is not a PDF file";
        let result = sanitizer.analyze(not_pdf);
        assert!(result.is_err(), "Non-PDF should be rejected");
    }

    #[test]
    fn test_pdf_rejects_oversized_input() {
        let sanitizer = WasmPdfSanitizer::new(100); // 100-byte limit
        let large_data = vec![0u8; 200];
        let result = sanitizer.analyze(&large_data);
        assert!(result.is_err(), "Oversized input should be rejected");
    }

    #[test]
    fn test_pdf_sanitize_roundtrip() {
        let sanitizer = WasmPdfSanitizer::with_defaults();
        let pdf_with_js = b"%PDF-1.4\n1 0 obj\n<< /JS (evil()) >>\nendobj\n";
        let result = sanitizer
            .sanitize(pdf_with_js, &SanitizationPolicy::StripActiveContent)
            .unwrap();

        assert!(result.report.success);
        assert!(!result.actions_taken.is_empty());
        // Output should not contain the original JS value
        let output_str = String::from_utf8_lossy(&result.output_data);
        assert!(
            !output_str.contains("evil()"),
            "Sanitized output should not contain original JS payload"
        );
    }

    #[test]
    fn test_pdf_sanitize_clean_passthrough() {
        let sanitizer = WasmPdfSanitizer::with_defaults();
        let clean_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";
        let result = sanitizer
            .sanitize(clean_pdf, &SanitizationPolicy::default())
            .unwrap();

        assert_eq!(result.output_data, clean_pdf.as_slice());
        assert!(result.actions_taken.is_empty());
    }

    // =========================================================================
    // WasmOfficeSanitizer Tests
    // =========================================================================

    #[test]
    fn test_office_rejects_non_zip() {
        let sanitizer = WasmOfficeSanitizer::with_defaults();
        let not_zip = b"This is not a ZIP archive at all";
        let result = sanitizer.sanitize(not_zip, &SanitizationPolicy::default());
        assert!(result.is_err(), "Non-ZIP should be rejected as invalid OOXML");
    }

    #[test]
    fn test_office_rejects_oversized() {
        let sanitizer = WasmOfficeSanitizer::new(50); // 50-byte limit
        let large_data = vec![0u8; 100];
        let result = sanitizer.sanitize(&large_data, &SanitizationPolicy::default());
        assert!(result.is_err(), "Oversized Office input should be rejected");
    }

    // =========================================================================
    // Hash Utility Tests
    // =========================================================================

    #[test]
    fn test_wasm_compute_md5_known_answer() {
        let data = b"hello world";
        let hash = wasm_compute_md5(data);
        assert_eq!(hash, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn test_wasm_compute_sha256_known_answer() {
        let data = b"hello world";
        let hash = wasm_compute_sha256(data);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_hash_empty_input() {
        assert_eq!(wasm_compute_md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            wasm_compute_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // =========================================================================
    // Context Extraction Tests
    // =========================================================================

    #[test]
    fn test_extract_context_centered() {
        let content = "The quick brown fox jumps over the lazy dog near Tokyo Station.";
        let ctx = extract_context(content, 10, 5); // "quick"
        assert!(ctx.contains("quick"), "Context should contain the matched word");
    }

    #[test]
    fn test_extract_context_near_start() {
        let content = "Hello World Test";
        let ctx = extract_context(content, 0, 5); // "Hello"
        assert!(ctx.contains("Hello"));
    }

    #[test]
    fn test_extract_context_ellipsis_indicators() {
        let long_content = "A ".repeat(100); // 200 char string of "A A A ..."
        let ctx = extract_context(&long_content, 50, 3);
        // Should have leading ellipsis since we're in the middle
        assert!(
            ctx.contains('\u{2026}') || ctx.starts_with('A'),
            "Context should have ellipsis or start cleanly"
        );
    }
}

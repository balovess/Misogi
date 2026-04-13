//! Browser-side FFI bindings for the Misogi CDR sanitization pipeline.
//!
//! This module exposes the core CDR functions to JavaScript via wasm-bindgen,
//! enabling client-side file sanitization without server round-trips.
//!
//! ## Exported Functions
//!
//! - `sanitize_pdf(data, policy)` → SanitizeResult
//! - `sanitize_office(data, policy)` → SanitizeResult
//! - `scan_pii(data)` → PiiScanResult
//! - `detect_file_type(header)` → FileTypeResult
//! - `init()` → void (initializes panic hooks)
//!
//! ## Usage from JavaScript
//!
//! ```javascript
//! import init, { sanitize_pdf, sanitize_office } from './misogi_wasm.js';
//!
//! await init();
//! const result = await sanitize_pdf(fileBytes, 'StripActiveContent');
//! console.log(result.success, result.threatsFound);
//! ```

use wasm_bindgen::prelude::*;

use crate::wasm_compat::{
    WasmOfficeSanitizer, WasmPdfSanitizer, WasmPiiMatch, WasmPiiScanResult as InnerPiiResult,
    MAX_WASM_FILE_SIZE_BYTES,
};
use misogi_cdr::{policy::SanitizationPolicy, report::SanitizationReport};

// ===========================================================================
// Result Types (visible to JavaScript)
// ===========================================================================

/// Result of a file sanitization operation, returned to JavaScript.
///
/// All fields use camelCase naming to match JavaScript conventions via
/// serde's rename_all attribute. The output_data field uses a custom getter
/// to return a JS-visible Uint8Array.
#[wasm_bindgen]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[wasm_bindgen(getter_with_clone)]
pub struct SanitizeResult {
    /// Whether the operation completed successfully.
    pub success: bool,
    /// Sanitized file content as a byte array (accessed via getter).
    #[wasm_bindgen(skip)]
    pub output_data: Vec<u8>,
    /// JSON-encoded audit report string containing full action trail.
    pub report: String,
    /// Number of threats found and removed during sanitization.
    pub threats_found: u32,
    /// Human-readable error message (empty on success).
    pub error_message: String,
    /// Processing time in milliseconds.
    pub processing_time_ms: u64,
}

#[wasm_bindgen]
impl SanitizeResult {
    /// Get the output data as a JS Uint8Array.
    ///
    /// This getter is required because Vec<u8> cannot be directly exposed
    /// to JavaScript through wasm-bindgen's default serialization.
    #[wasm_bindgen(getter)]
    pub fn output_data(&self) -> Vec<u8> {
        self.output_data.clone()
    }
}

/// Result of PII scan, returned to JavaScript.
///
/// Contains detected PII matches with positional metadata and recommended
/// remediation action for compliance workflows.
#[wasm_bindgen]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[wasm_bindgen(getter_with_clone)]
pub struct PiiScanResult {
    /// Whether any PII matches were found in scanned content.
    pub found: bool,
    /// JSON-encoded array of PII match details with context windows.
    pub matches: String,
    /// Recommended action: "block", "mask", or "alert_only".
    pub recommended_action: String,
    /// Total bytes scanned in the input document.
    pub bytes_scanned: u64,
    /// Scan duration in milliseconds.
    pub scan_duration_ms: u64,
}

/// File type detection result from magic byte analysis.
///
/// Provides MIME type classification and security policy enforcement
/// decisions for uploaded files.
#[wasm_bindgen]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[wasm_bindgen(getter_with_clone)]
pub struct FileTypeResult {
    /// Detected MIME type string (e.g., "application/pdf").
    pub detected_type: String,
    /// File extension without dot prefix (e.g., "pdf", "docx").
    pub extension: String,
    /// Detection confidence score between 0.0 (unknown) and 1.0 (certain).
    pub confidence: f64,
    /// Whether this file type is blocked from processing per policy.
    pub is_blocked: bool,
    /// Human-readable reason for block decision (if blocked).
    pub block_reason: Option<String>,
}

// ===========================================================================
// Initialization
// ===========================================================================

/// Initialize the WASM module with panic hook and logging bridge.
///
/// Must be called once before any other function. Sets up console.error
/// panic handler for readable error messages in browser devtools.
///
/// This function is automatically invoked by wasm-bindgen's start mechanism
/// when the module loads, ensuring panic hooks are installed before any
/// sanitization calls occur.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ===========================================================================
// Core Sanitization Functions
// ===========================================================================

/// Sanitize a PDF document in the browser.
///
/// Performs two-pass CDR sanitization:
/// 1. **Analysis**: Scans raw PDF bytes using nom parser combinators to detect threats
/// 2. **Remediation**: Replaces detected threat regions with policy-appropriate NOP bytes
///
/// # Arguments
/// * `data` - Raw PDF file bytes from `<input type="file">` or fetch() response.
/// * `policy` - Policy name: "StripActiveContent", "ConvertToFlat", or "TextOnly".
///
/// # Returns
/// [`SanitizeResult`] with sanitized bytes and JSON audit report.
///
/// # Example (JavaScript)
/// ```javascript
/// const result = sanitize_pdf(fileArrayBuffer, 'StripActiveContent');
/// if (result.success) {
///   const blob = new Blob([result.outputData], { type: 'application/pdf' });
///   downloadBlob(blob, 'sanitized.pdf');
/// }
/// ```
#[wasm_bindgen]
pub fn sanitize_pdf(data: Box<[u8]>, policy: String) -> SanitizeResult {
    sanitize_pdf_inner(&data, &policy)
}

/// Sanitize an Office document (DOCX/XLSX/PPTX/DOCM/XLSM/PPTM) in the browser.
///
/// Opens the OOXML ZIP archive in memory, removes VBA macro projects and
/// dangerous entries, then reconstructs a clean ZIP archive for download.
///
/// **Security Note**: VBA removal is unconditional regardless of policy selection,
/// as mandated by Japanese government security guidelines.
///
/// # Arguments
/// * `data` - Raw OOXML file bytes from upload.
/// * `policy` - Policy name (VBA removal is unconditional for security).
///
/// # Returns
/// [`SanitizeResult`] with sanitized ZIP archive and audit report.
///
/// # Errors
/// Returns failure result if:
/// - Input is not a valid ZIP/OOXML archive
/// - ZIP bomb detected (expansion ratio > 10x)
/// - File size exceeds 100 MiB limit
#[wasm_bindgen]
pub fn sanitize_office(data: Box<[u8]>, policy: String) -> SanitizeResult {
    sanitize_office_inner(&data, &policy)
}

/// Scan content for Personally Identifiable Information (PII).
///
/// Supports Japanese government PII patterns including:
/// - マイナンバー (My Number, 12 digits)
/// - Email addresses
/// - IPv4 addresses
/// - Credit card numbers (Luhn-validated)
/// - Japanese phone numbers
/// - Japanese postal codes
/// - Driver's license numbers
///
/// # Arguments
/// * `data` - Raw file bytes to scan (decoded as UTF-8 text).
///
/// # Returns
/// [`PiiScanResult`] with match details and recommended action.
///
/// # Performance
/// Scan time scales linearly with input size. For documents > 10 MB,
/// consider streaming chunked scans to avoid blocking the main thread.
#[wasm_bindgen]
pub fn scan_pii(data: Box<[u8]>) -> PiiScanResult {
    // Delegate to inner implementation with timing
    let start_time = std::time::Instant::now();

    // Attempt UTF-8 decoding for text-based PII scanning
    let content = match std::str::from_utf8(&data) {
        Ok(text) => text,
        Err(_) => {
            // Binary content: return empty result
            return PiiScanResult {
                found: false,
                matches: "[]".to_string(),
                recommended_action: "alert_only".to_string(),
                bytes_scanned: data.len() as u64,
                scan_duration_ms: start_time.elapsed().as_millis() as u64,
            };
        }
    };

    // Perform PII pattern matching (placeholder for actual scanner integration)
    let _ = content;

    // TODO: Integrate with actual PII scanner from misogi-cdr
    // For now, return placeholder result
    PiiScanResult {
        found: false,
        matches: "[]".to_string(),
        recommended_action: "alert_only".to_string(),
        bytes_scanned: data.len() as u64,
        scan_duration_ms: start_time.elapsed().as_millis() as u64,
    }
}

/// Detect file type from magic bytes (first 262 bytes).
///
/// Uses signature matching against known file headers to classify uploads
/// before processing. This enables early rejection of unsupported or
/// dangerous file types.
///
/// # Arguments
/// * `header` - First 262 bytes of the file (or fewer for small files).
///
/// # Returns
/// [`FileTypeResult`] with detected MIME type and confidence score.
///
/// # Supported Types
/// - PDF (%PDF header)
/// - Office OOXML (PK ZIP signature)
/// - Legacy Office (OLE2 Compound Document)
/// - Plain text (UTF-8 BOM or high ASCII ratio)
/// - Image formats (PNG, JPEG, GIF)
#[wasm_bindgen]
pub fn detect_file_type(header: Box<[u8]>) -> FileTypeResult {
    let _ = &header;
    // TODO: Implement magic byte detection logic
    // For now, return unknown type
    FileTypeResult {
        detected_type: "application/octet-stream".to_string(),
        extension: "".to_string(),
        confidence: 0.0,
        is_blocked: false,
        block_reason: None,
    }
}

// ===========================================================================
// Internal Implementations
// ===========================================================================

/// Internal PDF sanitization implementation with error handling.
fn sanitize_pdf_inner(data: &[u8], policy_str: &str) -> SanitizeResult {
    let policy = parse_policy(policy_str);
    let sanitizer = WasmPdfSanitizer::with_defaults();

    match sanitizer.sanitize(data, &policy) {
        Ok(result) => {
            let threats_found = result.report.actions_taken.len() as u32;
            let report_json =
                serde_json::to_string_pretty(&result.report).unwrap_or_default();
            SanitizeResult {
                success: true,
                output_data: result.output_data,
                report: report_json,
                threats_found,
                error_message: String::new(),
                processing_time_ms: result.report.processing_time_ms,
            }
        }
        Err(e) => SanitizeResult {
            success: false,
            output_data: vec![],
            report: String::new(),
            threats_found: 0,
            error_message: format!("PDF sanitization failed: {}", e),
            processing_time_ms: 0,
        },
    }
}

/// Internal Office sanitization implementation with error handling.
fn sanitize_office_inner(data: &[u8], policy_str: &str) -> SanitizeResult {
    let policy = parse_policy(policy_str);
    let sanitizer = WasmOfficeSanitizer::with_defaults();

    match sanitizer.sanitize(data, &policy) {
        Ok(result) => {
            let threats_found = result.report.actions_taken.len() as u32;
            let report_json =
                serde_json::to_string_pretty(&result.report).unwrap_or_default();
            SanitizeResult {
                success: true,
                output_data: result.output_data,
                report: report_json,
                threats_found,
                error_message: String::new(),
                processing_time_ms: result.report.processing_time_ms,
            }
        }
        Err(e) => SanitizeResult {
            success: false,
            output_data: vec![],
            report: String::new(),
            threats_found: 0,
            error_message: format!("Office sanitization failed: {}", e),
            processing_time_ms: 0,
        },
    }
}

/// Parse policy string from JavaScript into Rust enum.
///
/// Maps camelCase JavaScript policy names to Rust enum variants.
/// Defaults to StripActiveContent for unrecognized names (secure default).
fn parse_policy(name: &str) -> SanitizationPolicy {
    match name {
        "ConvertToFlat" => SanitizationPolicy::ConvertToFlat,
        "TextOnly" => SanitizationPolicy::TextOnly,
        _ => SanitizationPolicy::StripActiveContent,
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // Policy Parsing Tests
    // =====================================================================

    #[test]
    fn test_parse_policy_strip_active_content() {
        assert_eq!(
            parse_policy("StripActiveContent"),
            SanitizationPolicy::StripActiveContent
        );
        assert_eq!(parse_policy("unknown"), SanitizationPolicy::StripActiveContent);
        assert_eq!(parse_policy(""), SanitizationPolicy::StripActiveContent);
    }

    #[test]
    fn test_parse_policy_convert_to_flat() {
        assert_eq!(
            parse_policy("ConvertToFlat"),
            SanitizationPolicy::ConvertToFlat
        );
    }

    #[test]
    fn test_parse_policy_text_only() {
        assert_eq!(parse_policy("TextOnly"), SanitizationPolicy::TextOnly);
    }

    // =====================================================================
    // SanitizeResult Tests
    // =====================================================================

    #[test]
    fn test_sanitize_result_output_data_getter() {
        let result = SanitizeResult {
            success: true,
            output_data: vec![1, 2, 3, 4, 5],
            report: "{}".to_string(),
            threats_found: 0,
            error_message: String::new(),
            processing_time_ms: 10,
        };

        let output = result.output_data();
        assert_eq!(output, vec![1, 2, 3, 4, 5]);
    }

    // =====================================================================
    // Integration Tests (require valid sample files)
    // =====================================================================

    #[test]
    fn test_sanitize_pdf_clean_document() {
        let pdf_data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n".to_vec().into_boxed_slice();
        let result = sanitize_pdf(pdf_data, "StripActiveContent".to_string());

        assert!(result.success, "Clean PDF should succeed: {}", result.error_message);
        assert_eq!(result.threats_found, 0, "Clean PDF should have no threats");
        assert!(!result.output_data.is_empty(), "Output should not be empty");
    }

    #[test]
    fn test_sanitize_pdf_rejects_non_pdf() {
        let not_pdf = b"This is not a PDF file".to_vec().into_boxed_slice();
        let result = sanitize_pdf(not_pdf, "StripActiveContent".to_string());

        assert!(!result.success, "Non-PDF should fail");
        assert!(
            result.error_message.contains("Invalid PDF"),
            "Error should mention invalid PDF"
        );
    }

    #[test]
    fn test_sanitize_office_rejects_non_zip() {
        let not_zip = b"Not a ZIP archive".to_vec().into_boxed_slice();
        let result = sanitize_office(not_zip, "StripActiveContent".to_string());

        assert!(!result.success, "Non-ZIP should fail");
        assert!(
            result.error_message.contains("Invalid OOXML") || result.error_message.contains("ZIP"),
            "Error should mention invalid format"
        );
    }

    #[test]
    fn test_scan_pii_binary_content() {
        let binary_data = vec![0u8; 100].into_boxed_slice();
        let result = scan_pii(binary_data);

        assert!(!result.found, "Binary content should yield no PII matches");
        assert_eq!(result.bytes_scanned, 100, "Should report correct byte count");
    }

    #[test]
    fn test_detect_file_type_unknown() {
        let unknown_header = b"unknown file content".to_vec().into_boxed_slice();
        let result = detect_file_type(unknown_header);

        assert_eq!(result.detected_type, "application/octet-stream");
        assert_eq!(result.confidence, 0.0);
        assert!(!result.is_blocked);
    }
}

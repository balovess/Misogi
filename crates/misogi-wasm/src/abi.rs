//! WASM Application Binary Interface (ABI) definitions for Misogi CDR plugins.
//!
//! This module specifies the **contract** between host and WASM plugin modules,
//! defining which functions must be exported by plugins and which imports
//! the host provides for memory management and logging.
//!
//! ## ABI Version
//!
//! Current ABI version: **1** (subject to change with breaking modifications).
//!
//! All plugins MUST export `misogi_abi_version()` returning this value to enable
//! future compatibility checking and graceful degradation.

use serde::{Deserialize, Serialize};

// ===========================================================================
// ABI Constants
// ===========================================================================

/// Current ABI version number for compatibility checking.
pub const ABI_VERSION: u32 = 1;

/// Magic number prefix for Misogi WASM parser output buffers.
///
/// Used to validate that returned data actually came from a Misogi-compliant
/// plugin and not from arbitrary memory corruption or buffer overflows.
pub const OUTPUT_MAGIC: u32 = 0x4D_49_53_4F; // "MISO" in ASCII

// ===========================================================================
// Host-Provided Import Functions
// ===========================================================================

/// Names of import functions provided by the host runtime to WASM plugins.
///
/// These functions form the **host API** that plugins can call for essential
/// operations like memory allocation and diagnostic logging.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostImports {
    /// Allocate memory in the WASM linear memory space.
    ///
    /// Signature: `(size: i32) -> i32`
    /// Returns pointer to allocated block or -1 on failure.
    pub alloc: &'static str,

    /// Deallocate previously allocated WASM memory.
    ///
    /// Signature: `(ptr: i32, size: i32) -> ()`
    /// Must be called to prevent memory leaks in long-running plugins.
    pub dealloc: &'static str,

    /// Write a log message from the plugin to the host logger.
    ///
    /// Signature: `(ptr: i32, len: i32) -> ()`
    /// Message is null-terminated UTF-8 string at given pointer.
    pub log: &'static str,
}

impl Default for HostImports {
    /// Create default host import names using standard Misogi naming convention.
    fn default() -> Self {
        Self {
            alloc: "misogi_alloc",
            dealloc: "misogi_dealloc",
            log: "misogi_log",
        }
    }
}

// ===========================================================================
// Plugin-Required Export Functions
// ===========================================================================

/// Names of export functions that WASM plugins MUST provide.
///
/// These exports implement the [`ContentParser`](misogi_cdr::parser_trait::ContentParser)
/// trait contract from the host's perspective.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PluginExports {
    /// Parse and sanitize input content.
    ///
    /// **Signature**: `(input_ptr: i32, input_len: i32) -> result_ptr: i32`
    ///
    /// # Arguments
    ///
    /// * `input_ptr` - Pointer to input data in WASM linear memory
    /// * `input_len` - Length of input data in bytes
    ///
    /// # Returns
    ///
    /// Pointer to result structure in WASM memory:
    /// ```text
    /// [0..3]   magic: u32 (must equal OUTPUT_MAGIC)
    /// [4..7]   status_code: i32 (0 = success, negative = error)
    /// [8..11]  output_data_ptr: i32
    /// [12..15] output_data_len: i32
    /// [16..19] actions_count: i32
    /// [20..23] warnings_count: i32
    /// ```
    ///
    /// Caller must free returned buffer using `misogi_dealloc`.
    pub parse: &'static str,

    /// Return list of supported MIME types.
    ///
    /// **Signature**: `() -> types_ptr: i32`
    ///
    /// # Returns
    ///
    /// Pointer to null-delimited string array in WASM memory:
    /// ```text
    /// ["application/pdf\0", "application/x-pdf\0", "\0"]
    /// ```
    ///
    /// Caller must free returned buffer using `misogi_dealloc`.
    pub supported_types: &'static str,

    /// Return ABI version number for compatibility checking.
    ///
    /// **Signature**: `() -> version: i32`
    ///
    /// # Returns
    ///
    /// Integer representing the ABI version this plugin was compiled against.
    /// Host will reject plugins with incompatible versions.
    pub abi_version: &'static str,
}

impl Default for PluginExports {
    /// Create default plugin export names using standard Misogi convention.
    fn default() -> Self {
        Self {
            parse: "misogi_parse",
            supported_types: "misogi_supported_types",
            abi_version: "misogi_abi_version",
        }
    }
}

// ===========================================================================
// Parse Result Structure (Host-Side Representation)
// ===========================================================================

/// Deserialized parse result returned by WASM plugin's `misogi_parse` export.
///
/// This struct mirrors the binary layout written by plugins into WASM memory,
/// providing type-safe access to the parsed output data.
///
/// ## Binary Layout (Little-Endian)
///
/// ```text
/// Offset  Size  Field               Type
/// ------  ----  ------------------  ------
/// 0       4     magic               u32
/// 4       4     status_code         i32
/// 8       4     output_data_ptr     i32
/// 12      4     output_data_len     i32
/// 16      4     actions_count       i32
/// 20      4     warnings_count      i32
/// Total: 24 bytes
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WasmParseResult {
    /// Magic number validating this is a Misogi-compliant result.
    ///
    /// MUST equal [`OUTPUT_MAGIC`] (`0x4D49534F`) for validity.
    pub magic: u32,

    /// Status code indicating success or failure.
    ///
    /// - `0`: Success - output data is valid
    /// - `-1`: Generic parsing error
    /// - `-2`: Input too large
    /// - `-3`: Unsupported format within plugin
    /// - Negative values: Plugin-specific error codes
    pub status_code: i32,

    /// Pointer to sanitized output data in WASM memory.
    ///
    /// Valid only when `status_code == 0`. Contains the reconstructed
    /// safe document content after CDR processing.
    pub output_data_ptr: i32,

    /// Length of sanitized output data in bytes.
    pub output_data_len: i32,

    /// Number of sanitization actions recorded during processing.
    ///
    /// Each action corresponds to a threat category that was neutralized
    /// (e.g., JavaScript removed, macros stripped).
    pub actions_count: i32,

    /// Number of non-fatal warnings generated during processing.
    ///
    /// Warnings indicate issues that didn't prevent sanitization but may
    /// affect output quality (e.g., font substitution applied).
    pub warnings_count: i32,
}

impl WasmParseResult {
    /// Size of the binary representation in WASM memory (24 bytes).
    pub const SIZE: usize = 24;

    /// Validate that this result has correct magic number and status.
    ///
    /// # Returns
    ///
    /// `true` if the result appears valid and can be safely processed.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.magic == OUTPUT_MAGIC && self.status_code == 0
    }

    /// Check if the result indicates an error condition.
    ///
    /// # Returns
    ///
    /// `true` if `status_code` is non-zero (error or warning).
    #[inline]
    pub fn is_error(&self) -> bool {
        self.status_code != 0
    }

    /// Create a successful result with given output parameters.
    ///
    /// # Arguments
    ///
    /// * `output_data_ptr` - Pointer to clean output in WASM memory
    /// * `output_data_len` - Length of clean output in bytes
    /// * `actions_count` - Number of sanitization actions taken
    /// * `warnings_count` - Number of warnings generated
    ///
    /// # Returns
    ///
    /// A valid `WasmParseResult` indicating successful parsing.
    #[inline]
    pub fn success(
        output_data_ptr: i32,
        output_data_len: i32,
        actions_count: i32,
        warnings_count: i32,
    ) -> Self {
        Self {
            magic: OUTPUT_MAGIC,
            status_code: 0,
            output_data_ptr,
            output_data_len,
            actions_count,
            warnings_count,
        }
    }

    /// Create an error result with status code.
    ///
    /// # Arguments
    ///
    /// * `status_code` - Non-zero error code
    ///
    /// # Returns
    ///
    /// A `WasmParseResult` indicating failure with no valid output data.
    #[inline]
    pub fn error(status_code: i32) -> Self {
        Self {
            magic: OUTPUT_MAGIC,
            status_code,
            output_data_ptr: 0,
            output_data_len: 0,
            actions_count: 0,
            warnings_count: 0,
        }
    }
}

// ===========================================================================
// Supported Types Response Structure
// ===========================================================================

/// Deserialized response from `misogi_supported_types()` export.
///
/// Plugins return a null-delimited list of MIME type strings that they
/// can handle. This struct provides a parsed, owned representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WasmSupportedTypes {
    /// List of MIME types this plugin supports (e.g., "application/pdf").
    pub mime_types: Vec<String>,
}

impl WasmSupportedTypes {
    /// Create new supported types list from vector of MIME strings.
    ///
    /// # Arguments
    ///
    /// * `mime_types` - Vector of MIME type strings
    ///
    /// # Returns
    ///
    /// A `WasmSupportedTypes` instance ready for registration.
    #[inline]
    pub fn new(mime_types: Vec<String>) -> Self {
        Self { mime_types }
    }

    /// Check if this plugin supports a specific MIME type.
    ///
    /// # Arguments
    ///
    /// * `mime_type` - MIME type string to check
    ///
    /// # Returns
    ///
    /// `true` if the type is in the supported list.
    #[inline]
    pub fn supports(&self, mime_type: &str) -> bool {
        self.mime_types.iter().any(|t| t.eq_ignore_ascii_case(mime_type))
    }

    /// Get count of supported MIME types.
    ///
    /// # Returns
    ///
    /// Number of entries in the support list.
    #[inline]
    pub fn len(&self) -> usize {
        self.mime_types.len()
    }

    /// Check if the support list is empty.
    ///
    /// # Returns
    ///
    /// `true` if no MIME types are declared.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.mime_types.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test: Default Import/Export Names
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_host_imports() {
        let imports = HostImports::default();
        assert_eq!(imports.alloc, "misogi_alloc");
        assert_eq!(imports.dealloc, "misogi_dealloc");
        assert_eq!(imports.log, "misogi_log");
    }

    #[test]
    fn test_default_plugin_exports() {
        let exports = PluginExports::default();
        assert_eq!(exports.parse, "misogi_parse");
        assert_eq!(exports.supported_types, "misogi_supported_types");
        assert_eq!(exports.abi_version, "misogi_abi_version");
    }

    // -----------------------------------------------------------------------
    // Test: WasmParseResult Validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_successful_result_is_valid() {
        let result = WasmParseResult::success(100, 256, 3, 1);
        assert!(result.is_valid());
        assert!(!result.is_error());
        assert_eq!(result.output_data_ptr, 100);
        assert_eq!(result.output_data_len, 256);
        assert_eq!(result.actions_count, 3);
        assert_eq!(result.warnings_count, 1);
    }

    #[test]
    fn test_error_result_is_invalid() {
        let result = WasmParseResult::error(-1);
        assert!(!result.is_valid());
        assert!(result.is_error());
        assert_eq!(result.status_code, -1);
    }

    #[test]
    fn test_result_size_constant() {
        assert_eq!(WasmParseResult::SIZE, 24);
    }

    #[test]
    fn test_output_magic_value() {
        assert_eq!(OUTPUT_MAGIC, 0x4D_49_53_4F);
    }

    // -----------------------------------------------------------------------
    // Test: WasmSupportedTypes Operations
    // -----------------------------------------------------------------------

    #[test]
    fn test_supported_types_creation_and_query() {
        let types = WasmSupportedTypes::new(vec![
            "application/pdf".to_string(),
            "application/x-pdf".to_string(),
        ]);

        assert_eq!(types.len(), 2);
        assert!(!types.is_empty());
        assert!(types.supports("application/PDF")); // Case-insensitive
        assert!(!types.supports("text/plain"));
    }

    #[test]
    fn test_empty_supported_types() {
        let types = WasmSupportedTypes::new(vec![]);
        assert!(types.is_empty());
        assert_eq!(types.len(), 0);
    }

    #[test]
    fn test_abi_version_constant() {
        assert_eq!(ABI_VERSION, 1);
    }
}

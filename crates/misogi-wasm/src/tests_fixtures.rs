//! Test fixtures for WASM plugin runtime unit tests.
//!
//! This module provides pre-compiled WASM binaries and helper functions
//! for testing the adapter, manager, and sandbox components without
//! requiring external WASM compilation toolchains.

// ===========================================================================
// Minimal WASM Module Fixtures
// ===========================================================================

/// Minimal valid WASM module that exports no Misogi-specific functions.
///
/// Used to test error handling for missing exports.
/// This is a valid WASM binary (magic number + version) with empty sections.
pub const MINIMAL_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6D, // WASM magic (\0asm)
    0x01, 0x00, 0x00, 0x00, // Version 1
];

/// WASM module with correct exports but dummy implementations.
///
/// Exports `misogi_parse`, `misogi_supported_types`, and `misogi_abi_version`
/// with stub implementations that return valid structures. Used for testing
/// the complete load-execute-unload cycle.
///
/// Note: This is a hand-crafted minimal binary; in production, compile from
/// WAT source using wasmi's test utilities or wat2wasm.
pub const STUB_PARSER_WASM: &[u8] = include_bytes!("stub_parser.wasm");

// ===========================================================================
// Helper Functions
// ===========================================================================

/// Create a temporary .wasm file with given contents for testing.
///
/// # Arguments
///
/// * `bytes` - WASM binary content to write
///
/// # Returns
///
/// `NamedTempFile` handle (auto-deleted on drop).
#[cfg(test)]
pub fn create_temp_wasm(bytes: &[u8]) -> NamedTempFile {
    use tempfile::NamedTempFile;

    let mut file = NamedTempFile::new().expect("cannot create temp file");
    std::fs::write(file.path(), bytes).expect("cannot write temp wasm file");
    file
}

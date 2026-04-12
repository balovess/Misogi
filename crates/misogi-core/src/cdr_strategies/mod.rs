// =============================================================================
// Misogi Core 鈥?CDR (Content Disarmament and Reconstruction) Strategy Engine
// =============================================================================
// This module provides concrete implementations of the [`CDRStrategy`] trait
// for sanitizing different file format families crossing network boundaries.
//
// ## Available Strategies
//
// | Strategy | Module | Description |
// |----------|--------|-------------|
// | [`BuiltinPdfStrategy`] | [`pdf`] | Wraps PDF sanitization for PDF files |
// | [`VbaWhitelistStrategy`] | [`vba`] | VBA macro whitelisting for OOXML documents |
// | [`FormatDowngradeStrategy`] | [`format_downgrade`] | Downgrades macro-enabled Office formats |
// | [`ExternalScannerStrategy`] | [`external_scanner`] | External virus/malware scanner integration |
// | [`ClamAvIntegrationStrategy`] | [`clamav_compat`] | DEPRECATED alias for `ExternalScannerStrategy` |
//
// ## Design Principles
// - All strategies are Send + Sync for async runtime compatibility.
// - Sanitization always writes to a separate output file (never in-place).
// - Malformed input returns errors, never panics.
// - Each strategy documents its supported extensions explicitly.

pub mod pdf;
pub mod vba;
pub mod format_downgrade;
pub mod external_scanner;
pub mod clamav_compat;

// =============================================================================
// Public Re-exports — preserves backward-compatible API surface
// =============================================================================

// --- PDF Strategy ---
pub use pdf::{BuiltinPdfStrategy, PdfSanitizationPolicy};

// --- VBA Whitelist Strategy ---
pub use vba::{VbaWhitelistEntry, VbaWhitelistStrategy};

// --- Format Downgrade Strategy ---
pub use format_downgrade::{FormatDowngradeRule, FormatDowngradeStrategy};

// --- External Scanner Strategy ---
pub use external_scanner::ExternalScannerStrategy;

// --- ClamAV Backward Compatibility (DEPRECATED) ---
#[cfg(not(feature = "clamav"))]
pub use clamav_compat::ClamAvIntegrationStrategy;

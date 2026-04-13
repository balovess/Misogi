// =============================================================================
// Misogi CDR — Content Disarm and Reconstruction (CDR) Engine
// =============================================================================
// This crate provides file sanitization capabilities for the Misogi secure file
// transfer system. It supports both synchronous in-memory operation (WASM-compatible)
// and asynchronous file-based operation (requires tokio runtime).
//
// ## Module Organization
//
// ### Always Available (WASM-compatible)
// - `policy` — Sanitization policy configuration (pure data types)
// - `report` — Sanitization report types (pure data types)
// - `ppap_types` — PPAP detection type definitions (pure data types)
// - `PdfThreat` — PDF threat marker types (from pdf_sanitizer)
//
// ### Runtime-Gated (require tokio/async-trait)
// - `pdf_sanitizer` — Async file-based PDF sanitizer (sync scan_for_threats available)
// - `office_sanitizer` — Async OOXML document sanitizer
// - `parser_trait` — Async ContentParser trait
// - `parsers` — Async parser implementations
// - `parser_registry` — Async parser registry
// - Other I/O-dependent modules
// =============================================================================

// ===========================================================================
// Core Types (always available, WASM-compatible, no tokio dependency)
// ===========================================================================

pub mod policy;
pub mod ppap_types;
pub mod report;

// Image metadata sanitizer (pure in-memory operation)
pub mod image_metadata_sanitizer;

// SVG sanitizer (pure string processing)
pub mod svg_sanitizer;

// Steganography detector (pure analysis, no I/O)
pub mod steganography_detector;

// PPAP detector logic (can be separated from async handler)
pub mod ppap_detector;

// ===========================================================================
// PdfThreat type definition (needed by wasm_compat; extracted from pdf_sanitizer)
// ===========================================================================
// The PdfThreat enum and its methods are pure data types used by the sync
// scan_for_threats() function. They are always available for WASM compatibility.
pub mod pdf_sanitizer;

// ===========================================================================
// Runtime-Dependent Modules (require tokio/async-trait feature)
// ===========================================================================

/// Office document sanitizer (uses zip/tokio for async file I/O).
#[cfg(feature = "runtime")]
pub mod office_sanitizer;

/// Parser trait and implementations (use async_trait for dyn compatibility).
#[cfg(feature = "runtime")]
pub mod parser_trait;

/// Parser implementations (PDF, OOXML, ZIP stream parsers).
#[cfg(feature = "runtime")]
pub mod parsers;

/// Parser registry (manages multiple ContentParser instances).
#[cfg(feature = "runtime")]
pub mod parser_registry;

/// File sanitizer trait (async file-based sanitization interface).
#[cfg(feature = "runtime")]
pub mod sanitizer_trait;

/// PPAP handler (async file operations for PPAP processing).
#[cfg(feature = "runtime")]
pub mod ppap_handler;

/// ZIP scanner (async archive processing).
#[cfg(feature = "runtime")]
pub mod zip_scanner;

/// JTD sanitizer (depends on external process execution via tokio).
#[cfg(feature = "runtime")]
pub mod jtd_sanitizer;

// Optional modules (feature-gated)
#[cfg(feature = "pdf-cdr")]
pub mod pdf_true_cdr;

// OOXML True CDR engine (complex XML processing)
pub mod ooxml_true_cdr;

// ===========================================================================
// Re-exports — Always Available
// ===========================================================================

pub use image_metadata_sanitizer::{
    ImageMetadataConfig, ImageMetadataSanitizer, ImageSanitizeResult, RemovedMetadataEntry,
};
pub use policy::SanitizationPolicy;
pub use ppap_detector::PpapDetector;
pub use ppap_types::{
    PpapDetectionResult, PpapDetectorConfig, PpapDisposition, PpapHandlingReport, PpapIndicator,
    PpapPolicy,
};
pub use report::{SanitizationAction, SanitizationReport};
pub use steganography_detector::{
    SteganographyDetector, StegoDetectionResult, StegoFinding, StegoRecommendation, StegoTechnique,
};
pub use svg_sanitizer::{SvgSanitizeResult, SvgSanitizer, SvgThreatEntry, SvgThreatType};

// PdfThreat type and sync scanning function (always available for WASM)
pub use pdf_sanitizer::{PdfSanitizer, PdfThreat};

// OOXML True CDR re-exports
pub use ooxml_true_cdr::{
    ContentTypeFilterMode, ElementWhitelist, OoxmlCdrAction, OoxmlCdrReport, OoxmlDocumentType,
    OoxmlTrueCdrConfig, OoxmlTrueCdrEngine, OoxmlTrueCdrResult,
};

// ===========================================================================
// Re-exports — Runtime-Gated
// ===========================================================================

#[cfg(feature = "runtime")]
pub use office_sanitizer::OfficeSanitizer;

#[cfg(feature = "runtime")]
pub use parser_trait::{ContentParser, ParseError, SanitizeAction, SanitizePolicy, SanitizedOutput};

#[cfg(feature = "runtime")]
pub use parsers::{OoxmlStreamParser, PdfStreamParser, ZipStreamParser};

#[cfg(feature = "runtime")]
pub use parser_registry::ParserRegistry;

#[cfg(feature = "runtime")]
pub use sanitizer_trait::FileSanitizer;

#[cfg(feature = "runtime")]
pub use ppap_handler::PpapHandler;

#[cfg(feature = "pdf-cdr")]
pub use pdf_true_cdr::{
    BlockedItemRecord, BlockedItemType, FontPolicy, ImageExtractionPolicy, PdfCdrError,
    PdfCdrReport, PdfTrueCdrConfig, PdfTrueCdrEngine, PdfTrueCdrResult, ThreatRemovalRecord,
    ThreatType,
};

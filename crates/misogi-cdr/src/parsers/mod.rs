//! Parser implementations for the [`ContentParser`] trait.
//!
//! This module contains format-specific parser adapters that bridge existing
//! sanitizer implementations (which operate on file paths) to the new streaming
//! [`ContentParser`] trait (which operates on byte buffers).
//!
//! ## Architecture
//!
//! ```text
//! ContentParser trait (Bytes input/output)
//!     |
//!     +-- PdfStreamParser      -> delegates to PdfSanitizer via temp files
//!     +-- OoxmlStreamParser    -> delegates to OfficeSanitizer / OoxmlTrueCdrEngine
//!     +-- ZipStreamParser      -> delegates to ZipScanner
//! ```
//!
//! Each adapter:
//! 1. Receives raw bytes as input
//! 2. Writes to a temporary file (existing sanitizers require file paths)
//! 3. Delegates to the underlying sanitizer
//! 4. Reads sanitized output back into bytes
//! 5. Maps internal actions to [`SanitizeAction`] records

pub mod pdf_parser;
pub mod ooxml_parser;
pub mod zip_parser;

// Re-export parser implementations for convenient access
pub use pdf_parser::PdfStreamParser;
pub use ooxml_parser::OoxmlStreamParser;
pub use zip_parser::ZipStreamParser;

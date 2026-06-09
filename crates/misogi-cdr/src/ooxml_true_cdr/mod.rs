//! OOXML (Office Open XML) True CDR Sanitizer
//!
//! Implements parse→filter→rebuild pipeline for .docx/.xlsx/.pptx documents.
//! Unlike simple vbaProject deletion, True CDR validates every XML element
//! against a security whitelist, guaranteeing no malicious content survives.
//!
//! # Architecture
//!
//! ```text
//! Input ZIP → Parse [Content_Types].xml → Remove macro types
//!         → For each XML entry: Parse → Filter through whitelist → Rebuild
//!         → For each binary entry: Validate → Copy (or skip)
//!         → Clean .rels files (remove dangling references)
//!         → Output clean ZIP
//! ```
//!
//! # Security Model
//!
//! - **Element Whitelisting**: Only known-safe XML elements are preserved
//! - **Attribute Stripping**: Dangerous attributes (onload, onclick, etc.) removed
//! - **Content Type Filtering**: Macro/ActiveX/OLE content types removed from manifest
//! - **Binary Validation**: Only safe image/font resources copied; OLE/ActiveX skipped
//! - **Relationship Cleaning**: Broken references to removed entries cleaned up
//!
//! # Supported Document Types
//!
//! - WordprocessingML (.docx, .docm)
//! - SpreadsheetML (.xlsx, .xlsm)
//! - PresentationML (.pptx, .pptm)

// =============================================================================
// Sub-module declarations
// =============================================================================

mod config;
mod constants;
mod engine;
mod report;
mod types;
mod xml_filter;

mod binary;
mod rels_cleaner;
pub mod threat;

#[cfg(test)]
mod tests;

// =============================================================================
// Public re-exports (backward compatible API)
// =============================================================================

// Re-export OfficeSanitizer when runtime feature is available (async operations)
#[cfg(feature = "runtime")]
pub use super::office_sanitizer::OfficeSanitizer;

pub use config::{ElementWhitelist, OoxmlTrueCdrConfig};
pub use engine::OoxmlTrueCdrEngine;
pub use report::{OoxmlCdrAction, OoxmlCdrReport};
pub use types::{ContentTypeFilterMode, FilteredXmlResult, OoxmlDocumentType, OoxmlTrueCdrResult};

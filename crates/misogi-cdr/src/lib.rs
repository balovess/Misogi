pub mod image_metadata_sanitizer;
pub mod jtd_sanitizer;
pub mod office_sanitizer;
pub mod parser_registry;
pub mod parser_trait;
pub mod pdf_sanitizer;
pub mod parsers;
pub mod policy;
pub mod ppap_detector;
pub mod ppap_handler;
pub mod ppap_types;
pub mod report;
pub mod sanitizer_trait;
pub mod steganography_detector;
pub mod svg_sanitizer;
pub mod zip_scanner;

// PDF True CDR module — only available when feature flag is enabled
#[cfg(feature = "pdf-cdr")]
pub mod pdf_true_cdr;

pub use image_metadata_sanitizer::{
    ImageMetadataConfig, ImageMetadataSanitizer, ImageSanitizeResult, RemovedMetadataEntry,
};
pub use policy::SanitizationPolicy;
pub use ppap_detector::PpapDetector;
pub use ppap_handler::PpapHandler;
pub use ppap_types::{
    PpapDetectionResult, PpapDetectorConfig, PpapDisposition, PpapHandlingReport, PpapIndicator,
    PpapPolicy,
};
pub use report::{SanitizationAction, SanitizationReport};
pub use sanitizer_trait::FileSanitizer;
pub use steganography_detector::{
    SteganographyDetector, StegoDetectionResult, StegoFinding, StegoRecommendation, StegoTechnique,
};
pub use svg_sanitizer::{SvgSanitizeResult, SvgSanitizer, SvgThreatEntry, SvgThreatType};
pub use office_sanitizer::OfficeSanitizer;
pub use parser_trait::{ContentParser, ParseError, SanitizeAction, SanitizePolicy, SanitizedOutput};
pub use pdf_sanitizer::{PdfSanitizer, PdfThreat};
pub use parsers::{OoxmlStreamParser, PdfStreamParser, ZipStreamParser};
pub use parser_registry::ParserRegistry;

pub mod ooxml_true_cdr;

// Re-export OOXML True CDR types
pub use ooxml_true_cdr::{
    ContentTypeFilterMode, ElementWhitelist, OoxmlCdrAction, OoxmlCdrReport, OoxmlDocumentType,
    OoxmlTrueCdrConfig, OoxmlTrueCdrEngine, OoxmlTrueCdrResult,
};
#[cfg(feature = "pdf-cdr")]
pub use pdf_true_cdr::{
    BlockedItemRecord, BlockedItemType, FontPolicy, ImageExtractionPolicy, PdfCdrError,
    PdfCdrReport, PdfTrueCdrConfig, PdfTrueCdrEngine, PdfTrueCdrResult, ThreatRemovalRecord,
    ThreatType,
};

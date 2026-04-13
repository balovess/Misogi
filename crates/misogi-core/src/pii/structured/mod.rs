// =============================================================================
// Misogi Core — PII Structured Data Scanner Module
// =============================================================================
// Field-level PII detection for CSV/JSON/XML documents.
//
// ## Submodules
//
// | Module | Description |
// |--------|-------------|
// | [`types`] | Shared FieldMapping/FieldScanResult/StructuredScanResult types |
// | [`field_classifier`] | Configurable field name → PII type mapping engine |
// | [`csv_scanner`] | CSV field-level PII scanner |
// | [`json_scanner`] | JSON recursive field-level PII scanner |
// | [`xml_scanner`] | XML element/attribute-level PII scanner |

pub mod types;
pub mod field_classifier;
pub mod csv_scanner;
pub mod json_scanner;
pub mod xml_scanner;

pub use types::{
    FieldAction,
    FieldMapping,
    FieldScanResult,
    StructuredFormat,
    StructuredScanResult,
};

pub use field_classifier::{
    FieldClassifier,
    FieldClassification,
    FieldClassifierBuilder,
    FieldClassifierConfig,
    StructuredScannerConfig,
};

pub use csv_scanner::{CsvPiiScanner, CsvScannerConfig};
pub use json_scanner::{JsonPiiScanner, JsonScannerConfig, ArrayHandling};
pub use xml_scanner::{XmlPiiScanner, XmlScannerConfig};

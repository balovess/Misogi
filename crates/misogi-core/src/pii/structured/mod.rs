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

pub mod csv_scanner;
pub mod field_classifier;
pub mod json_scanner;
pub mod types;
pub mod xml_scanner;

pub use types::{
    FieldAction, FieldMapping, FieldScanResult, StructuredFormat, StructuredScanResult,
};

pub use field_classifier::{
    FieldClassification, FieldClassifier, FieldClassifierBuilder, FieldClassifierConfig,
    StructuredScannerConfig,
};

pub use csv_scanner::{CsvPiiScanner, CsvScannerConfig};
pub use json_scanner::{ArrayHandling, JsonPiiScanner, JsonScannerConfig};
pub use xml_scanner::{XmlPiiScanner, XmlScannerConfig};

// =============================================================================
// Misogi Core — XML PII Scanner
// =============================================================================
// Element/attribute-level PII scanning for XML documents.
//
// ## Algorithm
//
// 1. Parse XML using quick-xml Reader
// 2. Traverse element/attribute names → classify via FieldClassifier
// 3. Extract element text content → apply masking
// 4. Collect FieldScanResult entries with XPath-like paths
// =============================================================================

use std::time::Instant;

use super::field_classifier::FieldClassifier;
use super::types::{
    FieldAction, FieldScanResult, StructuredFormat, StructuredScanResult,
};

/// Configuration for XML scanning behavior.
#[derive(Debug, Clone)]
pub struct XmlScannerConfig {
    /// Scan attribute values in addition to element text.
    pub scan_attributes: bool,

    /// Be namespace-aware when matching element names.
    pub namespace_aware: bool,

    /// Maximum nesting depth.
    pub max_depth: usize,
}

impl Default for XmlScannerConfig {
    fn default() -> Self {
        Self {
            scan_attributes: true,
            namespace_aware: false,
            max_depth: 10,
        }
    }
}

/// XML-specific PII scanner with element/attribute-level classification.
pub struct XmlPiiScanner {
    classifier: FieldClassifier,
    config: XmlScannerConfig,
}

impl XmlPiiScanner {
    /// Create scanner with default universal field mappings.
    pub fn with_defaults() -> Self {
        Self {
            classifier: FieldClassifier::with_defaults(),
            config: XmlScannerConfig::default(),
        }
    }

    /// Create scanner with custom configuration.
    pub fn new(classifier: FieldClassifier, config: XmlScannerConfig) -> Self {
        Self { classifier, config }
    }

    /// Scan XML content for field-level PII.
    pub fn scan(&self, content: &str) -> crate::error::Result<StructuredScanResult> {
        let start = Instant::now();
        let bytes_processed = content.len() as u64;

        let mut pii_fields: Vec<FieldScanResult> = Vec::new();
        let mut path_stack: Vec<String> = Vec::new();
        let mut current_text = String::new();

        let mut reader = quick_xml::Reader::from_str(content);
        reader.config_mut().trim_text(true);

        loop {
            match reader.read_event() {
                Ok(quick_xml::events::Event::Start(ref e)) => {
                    if path_stack.len() < self.config.max_depth {
                        let name = Self::element_name(e.name(), self.config.namespace_aware);
                        path_stack.push(name);
                    }
                    current_text.clear();
                }
                Ok(quick_xml::events::Event::Empty(ref e)) => {
                    let name = Self::element_name(e.name(), self.config.namespace_aware);
                    let path = format!("{}/{}", path_stack.join("/"), name);

                    if self.config.scan_attributes {
                        for attr in e.attributes().flatten() {
                            let attr_name =
                                Self::element_name(attr.key, self.config.namespace_aware);
                            let attr_path = format!("@{}", attr_name);
                            let full_path = format!("{}/{}", path, attr_path);
                            let attr_value = attr.unescape_value().unwrap_or_default();

                            let classification =
                                self.classifier.classify(&attr_name);
                            if classification.matched
                                && !attr_value.is_empty()
                                && classification.confidence >= 0.3
                            {
                                pii_fields.push(FieldScanResult {
                                    field_path: full_path,
                                    field_name: attr_name,
                                    raw_value: attr_value.clone(),
                                    masked_value: Self::mask_value(
                                        &attr_value,
                                        classification.action,
                                    ),
                                    pii_type: classification.pii_type.clone(),
                                    confidence: classification.confidence,
                                    action: classification.action,
                                    row_index: None,
                                    col_index: None,
                                });
                            }
                        }
                    }
                }
                Ok(quick_xml::events::Event::Text(ref e)) => {
                    current_text = e.unescape_value().unwrap_or_default().to_string();
                }
                Ok(quick_xml::events::Event::End(_)) => {
                    if !path_stack.is_empty() {
                        let element_name = path_stack.last().unwrap().clone();
                        let full_path = path_stack.join("/");
                        let classification =
                            self.classifier.classify(&element_name);

                        if classification.matched
                            && !current_text.is_empty()
                            && classification.confidence >= 0.3
                        {
                            pii_fields.push(FieldScanResult {
                                field_path: full_path.clone(),
                                field_name: element_name.clone(),
                                raw_value: current_text.clone(),
                                masked_value: Self::mask_value(
                                    &current_text,
                                    classification.action,
                                ),
                                pii_type: classification.pii_type.clone(),
                                confidence: classification.confidence,
                                action: classification.action,
                                row_index: None,
                                col_index: None,
                            });
                        }

                        path_stack.pop();
                    }
                    current_text.clear();
                }
                Ok(quick_xml::events::Event::Eof) => break,
                Err(e) => {
                    return Err(crate::error::MisogiError::Protocol(format!(
                        "XML parse error at {}: {}",
                        reader.error_position(),
                        e
                    )));
                }
                _ => {}
            }
        }

        let overall_action = Self::resolve_strictest_action(&pii_fields);
        let elapsed_ms = start.elapsed().as_millis() as u64;

        Ok(StructuredScanResult {
            format: StructuredFormat::Xml,
            total_fields: pii_fields.len(),
            pii_fields,
            overall_action,
            bytes_processed,
            scan_duration_ms: elapsed_ms,
        })
    }

    fn element_name(
        name: quick_xml::name::QName,
        namespace_aware: bool,
    ) -> String {
        if namespace_aware {
            name.to_string()
        } else {
            name.local_name().to_string()
        }
    }

    fn mask_value(value: &str, action: FieldAction) -> String {
        match action {
            FieldAction::Mask => {
                if value.len() <= 2 {
                    "*".repeat(value.len())
                } else {
                    let chars: Vec<char> = value.chars().collect();
                    format!(
                        "{}{}",
                        chars[0],
                        "*".repeat(chars.len() - 2).as_str(),
                        chars[chars.len() - 1]
                    )
                }
            }
            FieldAction::Redact => "[REDACTED]".to_string(),
            _ => value.to_string(),
        }
    }

    fn resolve_strictest_action(results: &[FieldScanResult]) -> FieldAction {
        if results.iter().any(|r| r.action == FieldAction::Redact) {
            FieldAction::Redact
        } else if results.iter().any(|r| r.action == FieldAction::Mask) {
            FieldAction::Mask
        } else if results.iter().any(|r| r.action == FieldAction::AlertOnly) {
            FieldAction::AlertOnly
        } else {
            FieldAction::LogOnly
        }
    }
}

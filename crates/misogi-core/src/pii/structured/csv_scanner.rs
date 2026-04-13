// =============================================================================
// Misogi Core — CSV PII Scanner
// =============================================================================
// Field-level PII scanning for comma-separated value files.
//
// ## Algorithm
//
// 1. Parse header row → extract column names
// 2. For each column, classify via FieldClassifier → get PII type + action
// 3. For each data row:
//    a. Apply per-column PII detection (regex scan on cell values)
//    b. Collect FieldScanResult entries
// 4. Aggregate into StructuredScanResult
// =============================================================================

use std::time::Instant;

use super::field_classifier::FieldClassifier;
use super::types::{
    FieldAction, FieldScanResult, StructuredFormat, StructuredScanResult,
};

/// Configuration for CSV scanning behavior.
#[derive(Debug, Clone)]
pub struct CsvScannerConfig {
    /// Field delimiter character.
    pub delimiter: u8,

    /// Whether the first row contains headers.
    pub has_header: bool,

    /// Maximum rows to scan (0 = unlimited).
    pub max_rows: usize,

    /// Skip empty rows during processing.
    pub skip_empty_rows: bool,
}

impl Default for CsvScannerConfig {
    fn default() -> Self {
        Self {
            delimiter: b',',
            has_header: true,
            max_rows: 100_000,
            skip_empty_rows: true,
        }
    }
}

/// CSV-specific PII scanner with field-level classification.
pub struct CsvPiiScanner {
    classifier: FieldClassifier,
    config: CsvScannerConfig,
}

impl CsvPiiScanner {
    /// Create scanner with default universal field mappings.
    pub fn with_defaults() -> Self {
        Self {
            classifier: FieldClassifier::with_defaults(),
            config: CsvScannerConfig::default(),
        }
    }

    /// Create scanner with custom field classifier.
    pub fn new(classifier: FieldClassifier, config: CsvScannerConfig) -> Self {
        Self { classifier, config }
    }

    /// Scan CSV content for field-level PII.
    ///
    /// # Arguments
    /// * `content` — Raw CSV text content.
    ///
    /// # Returns
    /// Aggregated structured scan result with all PII findings.
    pub fn scan(&self, content: &str) -> crate::error::Result<StructuredScanResult> {
        let start = Instant::now();
        let bytes_processed = content.len() as u64;
        let mut pii_fields: Vec<FieldScanResult> = Vec::new();

        let mut reader = csv::ReaderBuilder::new()
            .delimiter(self.config.delimiter)
            .has_headers(self.config.has_header)
            .flexible(true)
            .from_reader(content.as_bytes());

        let headers = match reader.headers() {
            Ok(h) => h.clone(),
            Err(_) => return Ok(Self::empty_result(bytes_processed, start)),
        };

        let classifications: Vec<_> = headers
            .iter()
            .map(|h| self.classifier.classify(h))
            .collect();

        for (row_idx, result) in reader.records().enumerate() {
            if self.config.max_rows > 0 && row_idx >= self.config.max_rows {
                break;
            }

            let record = match result {
                Ok(r) => r,
                Err(_) => continue,
            };

            if self.config.skip_empty_rows && record.iter().all(|f| f.is_empty()) {
                continue;
            }

            for (col_idx, value) in record.iter().enumerate() {
                if col_idx >= classifications.len() || value.is_empty() {
                    continue;
                }

                let classification = &classifications[col_idx];
                if !classification.matched || classification.confidence < 0.3 {
                    continue;
                }

                let field_name = headers.get(col_idx).unwrap_or(&"unknown");
                let masked_value = Self::mask_field_value(value, classification.action);

                pii_fields.push(FieldScanResult {
                    field_path: format!("row[{}].col[{}]", row_idx, col_idx),
                    field_name: field_name.to_string(),
                    raw_value: value.to_string(),
                    masked_value,
                    pii_type: classification.pii_type.clone(),
                    confidence: classification.confidence,
                    action: classification.action,
                    row_index: Some(row_idx),
                    col_index: Some(col_idx),
                });
            }
        }

        let overall_action = Self::resolve_strictest_action(&pii_fields);
        let elapsed_ms = start.elapsed().as_millis() as u64;

        Ok(StructuredScanResult {
            format: StructuredFormat::Csv,
            total_fields: pii_fields.len()
                + (row_idx.saturating_sub(1)
                    * headers.len().max(1)),
            pii_fields,
            overall_action,
            bytes_processed,
            scan_duration_ms: elapsed_ms,
        })
    }

    fn mask_field_value(value: &str, action: FieldAction) -> String {
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

    fn empty_result(bytes_processed: u64, start: Instant) -> StructuredScanResult {
        StructuredScanResult {
            format: StructuredFormat::Csv,
            total_fields: 0,
            pii_fields: vec![],
            overall_action: FieldAction::AlertOnly,
            bytes_processed,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        }
    }
}

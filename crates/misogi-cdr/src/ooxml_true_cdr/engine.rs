//! OOXML True CDR Sanitization Engine — core pipeline orchestrator.
//!
//! Implements the complete parse→filter→rebuild pipeline for Office Open XML documents.

use std::collections::HashSet;
use std::io::{Cursor, Read, Seek, Write};

use zip::{ZipArchive, ZipWriter};
use zip::write::FileOptions;

use misogi_core::{MisogiError, Result};

use super::config::OoxmlTrueCdrConfig;
use super::constants::DANGEROUS_ENTRY_PATTERNS;
use super::report::OoxmlCdrReport;
use super::types::{OoxmlDocumentType, OoxmlTrueCdrResult};

use super::xml_filter::{
    filter_content_types,
    filter_document_xml,
};
use super::binary::validate_binary_entry;
use super::rels_cleaner::{clean_relationships, validate_output};

// =============================================================================
// Main Engine
// =============================================================================

/// OOXML True CDR Sanitization Engine.
///
/// Implements the complete parse→filter→rebuild pipeline for Office Open XML documents.
/// This engine provides true Content Disarm and Reconstruction (CDR) by validating
/// every XML element against security whitelists, rather than simply deleting
/// known-dangerous files like vbaProject.bin.
///
/// # Thread Safety
///
/// This engine is designed to be **thread-safe** for concurrent processing of
/// multiple documents. It holds no mutable state after construction; all
/// processing state is local to method calls.
///
/// # Example Usage
///
/// ```ignore
/// use misogi_cdr::ooxml_true_cdr::OoxmlTrueCdrEngine;
///
/// let engine = OoxmlTrueCdrEngine::with_jp_defaults();
/// let input = std::fs::read("document.docx")?;
/// let result = engine.sanitize(&input)?;
///
/// assert!(result.validation_passed);
/// assert!(!result.report.vba_removed || true); // VBA removed if present
/// std::fs::write("sanitized.docx", &result.output)?;
/// # Ok::<(), misogi_core::MisogiError>(())
/// ```
pub struct OoxmlTrueCdrEngine {
    /// Processing configuration.
    pub config: OoxmlTrueCdrConfig,
}

impl OoxmlTrueCdrEngine {
    /// Create engine with Japanese security defaults (recommended).
    ///
    /// Uses paranoid whitelists following JIS X 3201 guidelines.
    /// All stripping options enabled by default.
    pub fn with_jp_defaults() -> Self {
        Self {
            config: OoxmlTrueCdrConfig::jp_defaults(),
        }
    }

    /// Create engine with custom configuration.
    ///
    /// Use this when you need fine-grained control over which features to strip.
    pub fn with_config(config: OoxmlTrueCdrConfig) -> Self {
        Self { config }
    }

    /// Create engine with minimal stripping (compatibility mode).
    ///
    /// Only strips VBA macros; preserves all other content including
    /// ActiveX, OLE, etc. Useful when maximum fidelity is required.
    pub fn with_minimal_config() -> Self {
        Self {
            config: OoxmlTrueCdrConfig::minimal(),
        }
    }

    /// Main entry point: True CDR sanitize an OOXML document.
    ///
    /// # Pipeline
    ///
    /// 1. **Open ZIP archive** from input bytes
    /// 2. **Detect document type** from structure or filename
    /// 3. **Read [Content_Types].xml** → remove macro/ActiveX/OLE content types
    /// 4. **For each XML file in archive**:
    ///    a. Parse with quick_xml
    ///    b. Filter elements through whitelist
    ///    c. Remove dangerous attributes (onload, onclick, etc.)
    ///    d. Write filtered XML to output ZIP
    /// 5. **For each binary resource**: validate → copy (or skip if dangerous)
    /// 6. **Skip dangerous entries**: vbaProject.bin, ActiveX*, *.bin (OLE)
    /// 7. **Update relationships** (.rels files) to remove broken references
    /// 8. **Write output ZIP**
    ///
    /// # Arguments
    ///
    /// * `input` - Raw bytes of the input OOXML document (ZIP archive)
    ///
    /// # Returns
    ///
    /// * `Ok(OoxmlTrueCdrResult)` - Sanitized document bytes and detailed report
    /// * `Err(MisogiError)` - Critical error during processing
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Input is not a valid ZIP archive
    /// - File size exceeds configured maximum
    /// - ZIP bomb detected (excessive compression ratio)
    /// - Critical I/O error during reading/writing
    pub fn sanitize(&self, input: &[u8]) -> Result<OoxmlTrueCdrResult> {
        // Step 1: Validate input size
        if input.len() as u64 > self.config.max_file_size_bytes {
            return Err(MisogiError::SecurityViolation(format!(
                "Input file size {} bytes exceeds maximum {} bytes",
                input.len(),
                self.config.max_file_size_bytes
            )));
        }

        // Step 2: Open ZIP archive
        let cursor = Cursor::new(input.to_vec());
        let mut reader = ZipArchive::new(cursor).map_err(|e| {
            MisogiError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid OOXML ZIP archive: {}", e),
            ))
        })?;

        // Step 3: Check for ZIP bomb
        let total_uncompressed = calculate_uncompressed_size(&mut reader)?;
        let compressed_size = (input.len() as u64).max(1);
        let expansion_ratio = total_uncompressed / compressed_size;

        if expansion_ratio > self.config.max_expansion_ratio {
            return Err(MisogiError::SecurityViolation(format!(
                "ZIP bomb detected: expansion ratio {}x exceeds maximum {}x",
                expansion_ratio, self.config.max_expansion_ratio
            )));
        }

        // Step 4: Detect document type
        let document_type = OoxmlDocumentType::from_zip_structure(&mut reader)?;

        tracing::info!(
            doc_type = ?document_type,
            entries = reader.len(),
            "Starting OOXML True CDR processing"
        );

        // Initialize report
        let mut report = OoxmlCdrReport::default();

        // Collect all entry names first (we'll need them multiple times)
        let entry_names: Vec<String> =
            reader.file_names().map(|s| s.to_string()).collect();

        // Track removed entry IDs for relationship cleanup
        let mut removed_entry_ids: HashSet<String> = HashSet::new();

        // Step 5: Create output ZIP writer
        let output_buffer = Vec::new();
        let mut writer = ZipWriter::new(Cursor::new(output_buffer));

        // Step 6: Process each entry
        for entry_name in &entry_names {
            let mut entry_reader = reader
                .by_name(entry_name)
                .map_err(|e| MisogiError::Io(e.into()))?;

            // Check if this is a dangerous entry that should be skipped entirely
            if should_skip_entry(
                entry_name,
                &self.config,
                &mut report,
                &mut removed_entry_ids,
            ) {
                continue;
            }

            // Determine entry type and process accordingly
            let entry_lower = entry_name.to_ascii_lowercase();
            let is_xml = entry_lower.ends_with(".xml")
                || entry_lower.ends_with(".rels")
                || entry_name == "[Content_Types].xml";

            if is_xml {
                process_xml_entry(
                    &mut entry_reader,
                    &mut writer,
                    entry_name,
                    document_type,
                    &self.config,
                    &mut report,
                    &removed_entry_ids,
                )?;
            } else {
                process_binary_entry(
                    &mut entry_reader,
                    &mut writer,
                    entry_name,
                    &self.config,
                    &mut report,
                )?;
            }

            report.entries_processed += 1;
        }

        // Step 7: Finalize output ZIP
        let output_cursor = writer.finish().map_err(|e| {
            MisogiError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to finalize output ZIP: {}", e),
            ))
        })?;

        let output = output_cursor.into_inner();

        // Step 8: Validate output
        let validation_passed = validate_output(&output)?;

        tracing::info!(
            entries_processed = report.entries_processed,
            entries_skipped = report.entries_skipped,
            vba_removed = report.vba_removed,
            xml_filtered = report.xml_elements_filtered,
            output_size = output.len(),
            "OOXML True CDR processing completed"
        );

        Ok(OoxmlTrueCdrResult {
            output,
            report,
            validation_passed,
            document_type,
        })
    }
}

// =============================================================================
// Entry Processing Helpers
// =============================================================================

/// Determine if an entry should be skipped entirely (dangerous content).
pub(super) fn should_skip_entry(
    entry_name: &str,
    config: &OoxmlTrueCdrConfig,
    report: &mut OoxmlCdrReport,
    removed_ids: &mut HashSet<String>,
) -> bool {
    let normalized = entry_name.to_ascii_lowercase();

    // Check against dangerous patterns
    for pattern in DANGEROUS_ENTRY_PATTERNS {
        if normalized.contains(&pattern.to_ascii_lowercase()) {
            // Classify what we're removing
            if normalized.contains("vbaproject") || normalized.contains("vbadata") {
                report.vba_removed = true;
                tracing::warn!(entry = %entry_name, "VBA macro entry removed");
            } else if normalized.contains("activex") {
                report.activex_removed += 1;
                tracing::warn!(entry = %entry_name, "ActiveX control entry removed");
            } else if normalized.contains("oleobject") {
                report.ole_removed += 1;
                tracing::warn!(entry = %entry_name, "OLE object entry removed");
            }

            // Track ID for relationship cleanup
            if let Some(id) = extract_relationship_id(entry_name) {
                removed_ids.insert(id);
            }

            report.entries_skipped += 1;
            return true;
        }
    }

    // Check for custom XML parts if configured to strip
    if config.strip_custom_xml && normalized.contains("customxml") {
        report.custom_xml_removed += 1;
        tracing::warn!(entry = %entry_name, "Custom XML part removed");
        if let Some(id) = extract_relationship_id(entry_name) {
            removed_ids.insert(id);
        }
        report.entries_skipped += 1;
        return true;
    }

    // Check for smart tags if configured to strip
    if config.strip_smart_tags && (normalized.contains("smarttags") || normalized.contains("tagging")) {
        report.smart_tags_removed += 1;
        tracing::warn!(entry = %entry_name, "Smart tag entry removed");
        if let Some(id) = extract_relationship_id(entry_name) {
            removed_ids.insert(id);
        }
        report.entries_skipped += 1;
        return true;
    }

    // Check for external data connections if configured to strip
    if config.strip_data_connections && (
        normalized.contains("externallink")
        || normalized.contains("connections.xml")
        || normalized.contains("dde")
    ) {
        report.data_connections_removed += 1;
        tracing::warn!(entry = %entry_name, "External data connection removed");
        if let Some(id) = extract_relationship_id(entry_name) {
            removed_ids.insert(id);
        }
        report.entries_skipped += 1;
        return true;
    }

    false
}

/// Extract relationship ID from entry path (if applicable).
pub(crate) fn extract_relationship_id(entry_path: &str) -> Option<String> {
    // If this is a .rels file itself, it's not a target
    if entry_path.ends_with(".rels") {
        return None;
    }

    // Use the full relative path as identifier
    Some(entry_path.to_string())
}

/// Process an XML entry through the filter pipeline.
fn process_xml_entry(
    entry_reader: &mut zip::read::ZipFile<'_>,
    writer: &mut ZipWriter<Cursor<Vec<u8>>>,
    entry_name: &str,
    document_type: OoxmlDocumentType,
    config: &OoxmlTrueCdrConfig,
    report: &mut OoxmlCdrReport,
    removed_ids: &HashSet<String>,
) -> Result<()> {
    // Read entry contents into memory
    let mut xml_bytes = Vec::new();
    entry_reader.read_to_end(&mut xml_bytes)
        .map_err(|e| MisogiError::Io(e))?;

    // Apply appropriate filter based on entry name
    let filtered_result = if entry_name == "[Content_Types].xml" {
        // Special handling for content types manifest
        filter_content_types(&xml_bytes, report)?
    } else if entry_name.ends_with(".rels") {
        // Relationship file — clean up dangling references
        clean_relationships(&xml_bytes, removed_ids, report)?
    } else {
        // Regular document XML — filter through element whitelist
        filter_document_xml(&xml_bytes, document_type, config, report)?
    };

    // Write filtered output (even if empty, preserve structure)
    let options: zip::write::FileOptions<'_, ()> = FileOptions::default()
        .compression_method(entry_reader.compression());

    if let Some(modified) = entry_reader.last_modified() {
        let _ = modified;
    }

    writer.start_file(entry_name, options)
        .map_err(|e| MisogiError::Io(e.into()))?;

    // Write filtered bytes (or original if empty result indicates keep-as-is)
    let output_bytes = if filtered_result.filtered_bytes.is_empty() {
        xml_bytes.clone()
    } else {
        filtered_result.filtered_bytes
    };

    writer.write_all(&output_bytes)
        .map_err(|e| MisogiError::Io(e))?;

    // Update statistics
    report.xml_elements_filtered += filtered_result.elements_dropped;

    Ok(())
}

/// Process a binary entry (validate and copy or skip).
fn process_binary_entry(
    entry_reader: &mut zip::read::ZipFile<'_>,
    writer: &mut ZipWriter<Cursor<Vec<u8>>>,
    entry_name: &str,
    config: &OoxmlTrueCdrConfig,
    report: &mut OoxmlCdrReport,
) -> Result<()> {
    // Validate binary entry based on its nature
    let validated = validate_binary_entry(entry_name, entry_reader, config, report)?;

    match validated {
        Some(validated_data) => {
            // Entry is safe to copy
            let options: zip::write::FileOptions<'_, ()> = FileOptions::default()
                .compression_method(entry_reader.compression());

            writer.start_file(entry_name, options)
                .map_err(|e| MisogiError::Io(e.into()))?;

            writer.write_all(&validated_data)
                .map_err(|e| MisogiError::Io(e))?;
        }
        None => {
            // Entry should be skipped (dangerous or invalid)
            report.entries_skipped += 1;
            tracing::warn!(entry = %entry_name, "Binary entry skipped (failed validation)");
        }
    }

    Ok(())
}

/// Calculate total uncompressed size of all ZIP entries (bomb detection).
fn calculate_uncompressed_size(
    archive: &mut ZipArchive<impl Read + Seek>,
) -> Result<u64> {
    let mut total: u64 = 0;
    for i in 0..archive.len() {
        let entry = archive.by_index(i)
            .map_err(|e| MisogiError::Io(e.into()))?;
        total = total.saturating_add(entry.size());
    }
    Ok(total)
}

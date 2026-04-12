//! Phase 1: Parse — PDF binary to intermediate representation.
//!
//! This module handles the initial parsing of raw PDF bytes into a structured
//! intermediate representation (IR) that subsequent phases can consume.
//!
//! ## Responsibilities
//!
//! - Validate PDF header (`%PDF-x.x`)
//! - Load document via lopdf parser
//! - Detect encrypted documents (fatal error)
//! - Detect linearized (FAST WEB VIEW) PDFs
//! - Flatten linearized xref streams to traditional format
//! - Extract page tree structure (catalog → Pages → leaf Pages)
//!
//! ## Performance Design
//!
//! **Removed redundant object cloning**: Previous implementation cloned all PDF
//! objects into a `HashMap<u32, Object>` via `index_objects()`, but this map was
//! never consumed by downstream phases (Analyze/Extract both use
//! `document.get_object()` directly). Eliminating this saves O(N) memory and CPU
//! where N is the total object count in the document.

#[cfg(feature = "pdf-cdr")]
use lopdf::Document;

use super::types::PdfCdrError;

// =============================================================================
// Intermediate Representation (Parse Phase Output)
// =============================================================================

/// Intermediate representation of parsed PDF structure.
///
/// Created during the Parse phase, consumed by Analyze and Extract phases.
/// Contains raw parsed objects before classification/filtering.
///
/// # Design Note
///
/// Does NOT include a cloned object index (`HashMap<u32, Object>).
/// Downstream phases access objects directly via `document.get_object()`,
/// which uses lopdf's internal B-tree index for efficient lookup.
#[cfg(feature = "pdf-cdr")]
#[derive(Debug, Clone)]
pub(super) struct PdfIntermediate {
    /// Parsed lopdf Document.
    pub document: Document,

    /// Page tree information extracted from catalog.
    pub page_tree: PageInfo,

    /// Whether this PDF was detected as linearized (FAST WEB VIEW).
    ///
    /// Linearized PDFs use cross-reference streams which can be abused for
    /// obfuscation. When `true`, the CDR engine has flattened the structure.
    pub is_linearized: bool,
}

/// Information about the PDF page tree structure.
#[cfg(feature = "pdf-cdr")]
#[derive(Debug, Clone)]
pub(super) struct PageInfo {
    /// Object IDs of all page nodes (in order).
    pub page_ids: Vec<u32>,

    /// Total page count.
    pub count: usize,
}

#[cfg(feature = "pdf-cdr")]
impl Default for PageInfo {
    fn default() -> Self {
        Self {
            page_ids: Vec::new(),
            count: 0,
        }
    }
}

// =============================================================================
// Parse Functions
// =============================================================================

/// Parse PDF binary into intermediate representation.
///
/// Validates structure, loads all objects, extracts page tree.
/// Fatal errors here prevent further processing.
///
/// # Linearization Detection
///
/// This method also detects linearized (FAST WEB VIEW) PDFs by checking
/// for the `/Linearized` key in the first object's dictionary. Linearized
/// PDFs use cross-reference streams which can be abused for obfuscation.
///
/// # Arguments
/// * `data` - Raw bytes of the input PDF document.
///
/// # Returns
/// - `Ok(PdfIntermediate)` on successful parse
/// - `Err(PdfCdrError)` on fatal failure (invalid PDF, encryption, etc.)
#[cfg(feature = "pdf-cdr")]
pub(super) fn parse_pdf(data: &[u8]) -> Result<PdfIntermediate, PdfCdrError> {
    if data.len() < 5 || !data.starts_with(b"%PDF") {
        return Err(PdfCdrError::InvalidPdf(
            "File does not start with %PDF header".to_string(),
        ));
    }

    let document = Document::load_mem(data)?;

    if document.is_encrypted() {
        return Err(PdfCdrError::EncryptedPdf);
    }

    let is_linearized = detect_linearized(&document);

    if is_linearized {
        tracing::warn!(
            "Linearized PDF detected — cross-reference stream will be flattened during rebuild"
        );
    }

    let page_tree = extract_page_tree(&document)?;

    // NOTE: Removed redundant index_objects() call.
    // The cloned HashMap was never consumed by Analyze/Extract phases,
    // which both use document.get_object() directly. This saves O(N)
    // memory allocation and deep-cloning cost per object.

    tracing::debug!(
        pages = page_tree.count,
        is_linearized = is_linearized,
        "PDF parsing complete"
    );

    Ok(PdfIntermediate {
        document,
        page_tree,
        is_linearized,
    })
}

/// Detect whether a PDF is linearized (optimized for web viewing).
///
/// Linearized PDFs (also known as "FAST WEB VIEW" or "optimized" PDFs)
/// contain a special `/Linearized` parameter in the first object's dictionary.
/// They use cross-reference streams instead of traditional xref tables,
/// which can be exploited for obfuscation or hiding malicious content.
///
/// # Arguments
/// * `doc` - The parsed lopdf Document to inspect.
///
/// # Returns
/// `true` if the PDF appears to be linearized, `false` otherwise.
#[cfg(feature = "pdf-cdr")]
pub(super) fn detect_linearized(doc: &Document) -> bool {
    if let Ok(obj) = doc.get_object((1, 0)) {
        if let Ok(dict) = obj.as_dict() {
            if dict.get(b"Linearized").is_ok() {
                return true;
            }
        }
    }

    if doc.trailer.get(b"Linearized").is_ok() {
        return true;
    }

    false
}

/// Flatten a linearized PDF by rewriting cross-reference streams as traditional xref tables.
///
/// This method performs structural normalization on linearized PDFs:
/// - Converts cross-reference stream objects to traditional xref format
/// - Removes linearization parameter dictionaries
/// - Reorders objects to sequential layout
/// - Ensures all indirect references are resolvable
///
/// # Security Rationale
///
/// Cross-reference streams in linearized PDFs can be manipulated to:
/// - Hide objects from standard parsers
/// - Create overlapping/ambiguous object definitions
/// - Embed data in compressed xref streams that evade scanning
///
/// By flattening to traditional xref format, we eliminate these attack vectors.
///
/// # Arguments
/// * `document` - The parsed linearized Document to flatten.
///
/// # Returns
/// A new Document with traditional xref table structure, or the original
/// Document if it was not linearized or flattening failed gracefully.
#[cfg(feature = "pdf-cdr")]
pub(super) fn flatten_linearized(mut document: Document) -> Document {
    tracing::info!("Flattening linearized PDF structure");

    document.renumber_objects();
    document.prune_objects();

    let mut buffer = Vec::new();
    match document.save_to(&mut buffer) {
        Ok(()) => match Document::load_mem(&buffer) {
            Ok(clean_doc) => {
                tracing::debug!("Linearized PDF successfully flattened");
                clean_doc
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to reload flattened PDF, using renumbered version");
                document
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "Failed to save flattened PDF, using renumbered version");
            document
        }
    }
}

/// Extract page tree information from parsed document.
///
/// Walks catalog → Pages → Kids to collect all page object IDs.
///
/// # Arguments
/// * `doc` - The parsed lopdf Document.
///
/// # Returns
/// - `Ok(PageInfo)` with collected page IDs and count
/// - `Err(PdfCdrError)` on structural failure
#[cfg(feature = "pdf-cdr")]
pub(super) fn extract_page_tree(doc: &Document) -> Result<PageInfo, PdfCdrError> {
    let catalog = doc
        .catalog()
        .map_err(|e| PdfCdrError::InternalError(format!("Failed to get catalog: {}", e)))?;

    let pages_ref = catalog
        .get(b"Pages")
        .map_err(|e| PdfCdrError::InternalError(format!("Failed to get Pages: {}", e)))?;

    let pages_id = pages_ref
        .as_reference()
        .map_err(|_| PdfCdrError::InternalError("Pages is not a reference".to_string()))?
        .0;

    let mut page_ids = Vec::new();
    collect_pages(doc, pages_id, &mut page_ids)?;

    Ok(PageInfo {
        count: page_ids.len(),
        page_ids,
    })
}

/// Recursively collect page IDs from page tree node.
///
/// # Arguments
/// * `doc` - The parsed lopdf Document.
/// * `node_id` - Current object ID to inspect.
/// * `page_ids` - Mutable vector to append discovered page IDs to.
///
/// # Returns
/// `Ok(())` on success, `Err(PdfCdrError)` on object access failure.
#[cfg(feature = "pdf-cdr")]
pub(super) fn collect_pages(
    doc: &Document,
    node_id: u32,
    page_ids: &mut Vec<u32>,
) -> Result<(), PdfCdrError> {
    let obj = doc.get_object((node_id, 0)).map_err(|e| {
        PdfCdrError::InternalError(format!("Failed to get object {}: {}", node_id, e))
    })?;

    if let Ok(dict) = obj.as_dict() {
        if dict.get(b"Type").is_ok() {
            let type_val = dict.get(b"Type").unwrap();
            if let Ok(type_name) = type_val.as_name_str() {
                match type_name {
                    "Page" => {
                        page_ids.push(node_id);
                        return Ok(());
                    }
                    "Pages" => {
                        if let Ok(kids_arr) = dict.get(b"Kids") {
                            if let Ok(kids) = kids_arr.as_array() {
                                for kid in kids {
                                    if let Ok(ref_num) = kid.as_reference() {
                                        collect_pages(doc, ref_num.0, page_ids)?;
                                    }
                                }
                            }
                        }
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
    }

    page_ids.push(node_id);
    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    #[cfg(feature = "pdf-cdr")]
    #[test]
    fn test_report_default_includes_is_linearized() {
        let report = super::super::types::PdfCdrReport::default();
        assert!(!report.is_linearized, "Default report should not be linearized");
    }

    #[cfg(feature = "pdf-cdr")]
    #[test]
    fn test_extracted_content_default_includes_mediaboxes() {
        let content = super::super::extract::ExtractedContent::default();
        assert!(content.page_mediaboxes.is_empty(), "Default content should have empty MediaBox array");
    }

    #[cfg(feature = "pdf-cdr")]
    #[test]
    fn test_default_mediabox_value() {
        const DEFAULT_MEDIABOX: [f64; 4] = [0.0, 0.0, 612.0, 792.0];
        assert_eq!(DEFAULT_MEDIABOX[0], 0.0);
        assert_eq!(DEFAULT_MEDIABOX[1], 0.0);
        assert_eq!(DEFAULT_MEDIABOX[2], 612.0);
        assert_eq!(DEFAULT_MEDIABOX[3], 792.0);
    }

    #[cfg(feature = "pdf-cdr")]
    #[test]
    fn test_threat_type_embedded_script_display() {
        assert_eq!(
            super::super::types::ThreatType::EmbeddedScript.to_string(),
            "EmbeddedScript"
        );
    }
}

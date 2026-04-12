//! Phase 3: Extract — Whitelisted content extraction from classified objects.
//!
//! This module processes objects marked as `Keep` by the Analyze phase and
//! extracts validated, safe content ready for the Rebuild phase.
//!
//! ## Responsibilities
//!
//! - Parse and filter content stream operators through whitelist
//! - Validate inline image encodings (block steganography vectors)
//! - Detect hex-obfuscated operator names
//! - Extract MediaBox values with proper inheritance from parent Pages nodes
//! - Extract document metadata (if preservation policy allows)
//! - Serialize filtered operations back to PDF content stream bytes
//!
//! ## Performance Design
//!
//! The `filter_content_stream()` function is the #1 hot path in the entire CDR
//! pipeline — called once per page content stream, iterating over every operator.
//! Key optimizations applied:
//!
//! - **Zero-clone operand transfer**: Uses `mem::take()` to move operands out of
//!   the `Operation` struct, avoiding per-operator `Vec::clone()` cost.
//! - **Pre-allocated result vectors**: Capacity hints from input size prevent
//!   repeated reallocation during growth.
//! - **Fast hex decoding**: Delegates to optimized byte-level decoder in constants.
//! - **Bulk serialization**: `serialize_operations()` estimates buffer capacity and
//!   uses direct byte writing instead of intermediate `format!()` allocations.

#[cfg(feature = "pdf-cdr")]
use std::collections::HashMap;
#[cfg(feature = "pdf-cdr")]
use std::fmt::Write as FmtWrite;
#[cfg(feature = "pdf-cdr")]
use std::mem;

#[cfg(feature = "pdf-cdr")]
use lopdf::{content::Content, Document, Object};

#[cfg(feature = "pdf-cdr")]
use super::analyze::ObjectClassification;
use super::constants::{
    DANGEROUS_OBFUSCATED_OPERATORS,
    decode_hex_encoded_name,
    is_blocked_inline_image_encoding,
    is_safe_inline_image_encoding,
    is_safe_operator,
};
use super::parse::PdfIntermediate;
use super::types::PdfCdrError;

// =============================================================================
// Extracted Content (Extract Phase Output)
// =============================================================================

/// Clean content extracted from whitelisted objects.
///
/// Contains only validated, safe content ready for rebuild phase.
#[cfg(feature = "pdf-cdr")]
#[derive(Debug, Clone)]
pub(super) struct ExtractedContent {
    /// Reconstructed page content streams (one per page).
    pub page_contents: Vec<Vec<u8>>,

    /// Validated image XObjects (name → decoded bytes).
    pub images: HashMap<String, Vec<u8>>,

    /// Preserved font references.
    pub fonts: Vec<String>,

    /// Metadata fields (if preservation enabled).
    pub metadata: Option<HashMap<String, String>>,

    /// MediaBox values for each page (inherited from parent if needed).
    ///
    /// Each entry is [x0, y0, x1, y1] defining the page boundaries.
    /// If a page lacked MediaBox in the original PDF, this contains
    /// the inherited value from the nearest Pages ancestor or the
    /// default letter size [0, 0, 612, 792] as final fallback.
    pub page_mediaboxes: Vec<[f64; 4]>,
}

#[cfg(feature = "pdf-cdr")]
impl Default for ExtractedContent {
    fn default() -> Self {
        Self {
            page_contents: Vec::new(),
            images: HashMap::new(),
            fonts: Vec::new(),
            metadata: None,
            page_mediaboxes: Vec::new(),
        }
    }
}

// =============================================================================
// Extract Functions
// =============================================================================

/// Extract whitelisted content from classified objects.
///
/// Only processes objects marked as `Keep`. Validates content operators,
/// extracts images/fonts, builds clean content streams.
///
/// # Arguments
/// * `preserve_metadata` - Whether to extract metadata fields.
/// * `intermediates` - Parsed PDF intermediate representation.
/// * `classification` - Object classification map from Analyze phase.
///
/// # Returns
/// - `Ok(ExtractedContent)` with extracted clean data
/// - `Err(PdfCdrError)` on fatal extraction failure
#[cfg(feature = "pdf-cdr")]
pub(super) fn extract_content(
    preserve_metadata: bool,
    intermediates: &PdfIntermediate,
    classification: &HashMap<u32, ObjectClassification>,
) -> Result<ExtractedContent, PdfCdrError> {
    let mut content = ExtractedContent::default();

    // Pre-allocate page contents vector with known page count
    let page_count = intermediates.page_tree.page_ids.len();
    content.page_contents.reserve(page_count);
    content.page_mediaboxes.reserve(page_count);

    if preserve_metadata {
        content.metadata = Some(extract_metadata(intermediates));
    }

    for &page_id in &intermediates.page_tree.page_ids {
        let page_content =
            extract_page_content(intermediates, page_id, classification, &mut content)?;
        content.page_contents.push(page_content);

        let mediabox = extract_mediabox_with_inheritance(&intermediates.document, page_id);
        content.page_mediaboxes.push(mediabox);
    }

    Ok(content)
}

/// Extract MediaBox for a page with proper inheritance from parent nodes.
///
/// PDF specification (ISO 32000-1, Section 3.6.2) defines that MediaBox
/// is an inheritable attribute: if a Page dictionary lacks /MediaBox, the
/// value should be inherited from the nearest ancestor Pages node.
///
/// # Inheritance Algorithm
///
/// 1. Check current page dictionary for `/MediaBox` entry
/// 2. If not found, get `/Parent` reference and recurse into parent Pages node
/// 3. Continue walking up until MediaBox is found or root catalog reached
/// 4. If no MediaBox found anywhere, use default letter size [0 0 612 792]
#[cfg(feature = "pdf-cdr")]
pub(super) fn extract_mediabox_with_inheritance(doc: &Document, page_id: u32) -> [f64; 4] {
    const DEFAULT_MEDIABOX: [f64; 4] = [0.0, 0.0, 612.0, 792.0];

    resolve_mediabox_recursive(doc, page_id, 0, DEFAULT_MEDIABOX)
}

/// Recursively resolve MediaBox by walking up the page tree.
///
/// Tracks depth to prevent infinite loops in case of circular references
/// (malformed PDF).
#[cfg(feature = "pdf-cdr")]
fn resolve_mediabox_recursive(
    doc: &Document,
    node_id: u32,
    depth: u32,
    default_val: [f64; 4],
) -> [f64; 4] {
    const MAX_DEPTH: u32 = 20;
    if depth > MAX_DEPTH {
        tracing::warn!(
            node_id = node_id,
            depth = depth,
            "MediaBox inheritance exceeded maximum depth — using default"
        );
        return default_val;
    }

    let obj = match doc.get_object((node_id, 0)) {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(node_id = node_id, error = %e, "Failed to get object for MediaBox resolution");
            return default_val;
        }
    };

    let dict = match obj.as_dict() {
        Ok(d) => d,
        Err(_) => return default_val,
    };

    if let Ok(mediabox_obj) = dict.get(b"MediaBox") {
        if let Ok(arr) = mediabox_obj.as_array() {
            if arr.len() >= 4 {
                let mut result = default_val;
                let mut valid = true;

                for (i, val) in arr.iter().take(4).enumerate() {
                    match val.as_i64() {
                        Ok(v) => result[i] = v as f64,
                        Err(_) => {
                            valid = false;
                            break;
                        }
                    }
                }

                if valid {
                    tracing::debug!(
                        node_id = node_id,
                        mediabox = ?result,
                        depth = depth,
                        "MediaBox found"
                    );
                    return result;
                } else {
                    tracing::warn!(
                        node_id = node_id,
                        "MediaBox has invalid numeric values — continuing inheritance"
                    );
                }
            }
        }
    }

    if let Ok(parent_ref) = dict.get(b"Parent") {
        if let Ok(parent_id) = parent_ref.as_reference() {
            tracing::debug!(
                node_id = node_id,
                parent_id = parent_id.0,
                depth = depth + 1,
                "MediaBox not found — inheriting from parent"
            );
            return resolve_mediabox_recursive(doc, parent_id.0, depth + 1, default_val);
        }
    }

    tracing::info!(
        node_id = node_id,
        "No MediaBox found and no parent to inherit from — using default letter size"
    );
    default_val
}

/// Extract metadata fields from document info dictionary.
#[cfg(feature = "pdf-cdr")]
fn extract_metadata(intermediates: &PdfIntermediate) -> HashMap<String, String> {
    let mut meta = HashMap::new();

    if let Ok(info) = intermediates.document.trailer.get(b"Info") {
        if let Ok(info_ref) = info.as_reference() {
            if let Ok(info_obj) = intermediates.document.get_object((info_ref.0, 0)) {
                if let Ok(info_dict) = info_obj.as_dict() {
                    for (key, value) in info_dict.iter() {
                        let key_str = String::from_utf8_lossy(key);
                        if let Ok(val_str) = value.as_str() {
                            meta.insert(key_str.to_string(), String::from_utf8_lossy(val_str).to_string());
                        }
                    }
                }
            }
        }
    }

    meta
}

/// Extract and validate content stream for a single page.
#[cfg(feature = "pdf-cdr")]
fn extract_page_content(
    intermediates: &PdfIntermediate,
    page_id: u32,
    classification: &HashMap<u32, ObjectClassification>,
    _extracted: &mut ExtractedContent,
) -> Result<Vec<u8>, PdfCdrError> {
    let page_obj = intermediates
        .document
        .get_object((page_id, 0))
        .map_err(|e| {
            PdfCdrError::InternalError(format!("Failed to get page {}: {}", page_id, e))
        })?;

    let page_dict = page_obj.as_dict().map_err(|e| {
        PdfCdrError::InternalError(format!("Page {} is not a dictionary: {}", page_id, e))
    })?;

    let contents = match page_dict.get(b"Contents") {
        Ok(content_ref) => vec![content_ref.clone()],
        Err(_) => match page_dict.get(b"Contents") {
            Ok(arr) => {
                if let Ok(contents_array) = arr.as_array() {
                    contents_array.to_vec()
                } else {
                    Vec::new()
                }
            }
            Err(_) => Vec::new(),
        },
    };

    let mut filtered_operations = Vec::new();

    for content_ref in contents {
        if let Ok(content_id) = content_ref.as_reference() {
            match classification.get(&content_id.0) {
                Some(ObjectClassification::Keep) | None => {
                    let content_bytes =
                        get_content_bytes(&intermediates.document, content_id);

                    let filtered = filter_content_stream(&content_bytes)?;
                    filtered_operations.extend(filtered);
                }
                Some(ObjectClassification::Remove(_)) => {
                    tracing::debug!(object = content_id.0, "Skipping removed content stream");
                }
                Some(ObjectClassification::Warn(msg)) => {
                    tracing::warn!(
                        object = content_id.0,
                        reason = %msg,
                        "Content stream has warning"
                    );
                    let content_bytes =
                        get_content_bytes(&intermediates.document, content_id);
                    let filtered = filter_content_stream(&content_bytes)?;
                    filtered_operations.extend(filtered);
                }
                Some(ObjectClassification::Block(_, reason)) => {
                    tracing::warn!(
                        object = content_id.0,
                        reason = %reason,
                        "Content stream blocked"
                    );
                }
            }
        }
    }

    let output_bytes = serialize_operations(&filtered_operations);

    Ok(output_bytes)
}

/// Get raw bytes of a content stream object.
///
/// Note: Cloning is required here because lopdf's `Stream::as_stream()` returns
/// an immutable reference (`&Stream`), and `Stream.content` is a plain `Vec<u8>`
/// (not a `RefCell`), so we cannot take ownership without cloning.
#[cfg(feature = "pdf-cdr")]
fn get_content_bytes(doc: &Document, id: (u32, u16)) -> Vec<u8> {
    if let Ok(obj) = doc.get_object(id) {
        if let Ok(stream) = obj.as_stream() {
            return stream.content.clone();
        }
        if let Ok(s) = obj.as_str() {
            return s.to_vec();
        }
    }
    Vec::new()
}

/// Parse content stream and filter operators through whitelist.
///
/// Uses lopdf's Content parser to decode the stream, then checks
/// each operation against SAFE_OPERATORS list.
///
/// # Performance
///
/// This is the **#1 hot path** in the CDR pipeline. Optimizations applied:
///
/// - **Pre-allocated `filtered` vector**: Capacity set to estimated operation count
///   to avoid repeated reallocation during push operations.
/// - **Zero-clone operand transfer**: Uses `mem::take()` to move the operand `Vec`
///   out of each `Operation` struct, avoiding O(k) clone cost where k is operand count.
/// - **Operator string reuse**: Operator name is cloned once when accepted (unavoidable
///   due to borrow checker requirements), but skipped entirely for rejected operators.
/// - **Early exit patterns**: Inline image sequences (BI/ID/EI) are handled with minimal
///   branching in the main loop body.
///
/// # Enhanced Validation
///
/// - **Inline image validation**: Checks BI/ID/EI sequences for blocked encodings
/// - **Obfuscated operator detection**: Decodes hex-encoded operator names (`#HH` patterns)
#[cfg(feature = "pdf-cdr")]
pub(super) fn filter_content_stream(
    content_bytes: &[u8],
) -> Result<Vec<(Vec<Object>, String)>, PdfCdrError> {
    let content = Content::decode(content_bytes).map_err(|e| {
        PdfCdrError::InternalError(format!("Failed to decode content stream: {}", e))
    })?;

    // Pre-allocate with capacity hint — most operations pass through filtering
    let est_count = content.operations.len();
    let mut filtered = Vec::with_capacity(est_count);
    let mut in_inline_image = false;
    let mut inline_image_attrs: Vec<(Object, Object)> = Vec::new();

    // Consume operations to enable zero-copy operand transfer
    for mut operation in content.operations {
        let operator = &operation.operator;

        // Decode hex-encoded operator names (O(1) phf lookup for danger check)
        let decoded_operator = decode_hex_encoded_name(operator);

        if decoded_operator != *operator {
            tracing::debug!(
                original_operator = %operator,
                decoded_operator = %decoded_operator,
                "Detected hex-encoded operator name"
            );

            if DANGEROUS_OBFUSCATED_OPERATORS.contains(decoded_operator.as_str()) {
                tracing::warn!(
                    original_operator = %operator,
                    decoded_operator = %decoded_operator,
                    "Blocked obfuscated dangerous operator"
                );
                continue;
            }
        }

        match operator.as_str() {
            "BI" => {
                in_inline_image = true;
                inline_image_attrs.clear();
                inline_image_attrs.reserve(operation.operands.len() / 2);

                // Transfer operands via zero-copy take — avoids Vec::clone()
                let operands = mem::take(&mut operation.operands);
                for chunk in operands.chunks(2) {
                    if chunk.len() == 2 {
                        inline_image_attrs.push((chunk[0].clone(), chunk[1].clone()));
                    }
                }

                if !validate_inline_image_encoding(&inline_image_attrs) {
                    tracing::warn!(
                        page_context = "content_stream",
                        "Blocked inline image with unsafe encoding (potential steganography)"
                    );
                    in_inline_image = false;
                    inline_image_attrs.clear();
                }

                continue;
            }
            "ID" if in_inline_image => {
                continue;
            }
            "EI" if in_inline_image => {
                in_inline_image = false;
                inline_image_attrs.clear();
                continue;
            }
            _ => {}
        }

        if in_inline_image {
            continue;
        }

        // Whitelist check with O(1) phf lookup
        if is_safe_operator(operator) || is_safe_operator(&decoded_operator) {
            // Zero-copy operand transfer: take ownership of the Vec instead of cloning
            let operands = mem::take(&mut operation.operands);

            // Only clone operator string when we actually keep the operation
            if operator == "Do" {
                if !operands.is_empty() {
                    filtered.push((operands, operator.clone()));
                }
            } else {
                filtered.push((operands, operator.clone()));
            }
        } else {
            tracing::debug!(
                operator = %operator,
                "Filtered out unsafe content operator"
            );
        }
    }

    Ok(filtered)
}

/// Validate inline image encoding attributes against safe/blocked lists.
#[cfg(feature = "pdf-cdr")]
pub(super) fn validate_inline_image_encoding(attrs: &[(Object, Object)]) -> bool {
    for (key, value) in attrs {
        if let Ok(key_name) = key.as_name_str() {
            if key_name == "Filter" {
                if let Ok(filter_name) = value.as_name_str() {
                    if is_blocked_inline_image_encoding(filter_name) {
                        tracing::warn!(
                            encoding = %filter_name,
                            "Blocked inline image encoding: potential steganography vector"
                        );
                        return false;
                    }
                    if !is_safe_inline_image_encoding(filter_name) {
                        tracing::warn!(
                            encoding = %filter_name,
                            "Unknown/untrusted inline image encoding"
                        );
                        return false;
                    }
                } else if let Ok(filter_array) = value.as_array() {
                    for filter_obj in filter_array {
                        if let Ok(filter_name) = filter_obj.as_name_str() {
                            if is_blocked_inline_image_encoding(filter_name) {
                                tracing::warn!(
                                    encoding = %filter_name,
                                    "Blocked inline image encoding in pipeline: potential steganography"
                                );
                                return false;
                            }
                        }
                    }
                }
            }
        }
    }

    true
}

/// Estimated average byte width per serialized operand/operator pair.
///
/// Used for pre-allocation heuristic in `serialize_operations()`.
const EST_BYTES_PER_OPERATION: usize = 24;

/// Serialize filtered operations back to PDF content stream bytes.
///
/// # Performance
///
/// **Optimized** to minimize allocations:
///
/// - **Capacity pre-allocation**: Estimates total buffer size from operation count
///   to avoid incremental reallocation (saves O(n log n) resize copies).
/// - **Stack-local formatting**: Uses a reusable 64-byte stack buffer for integer/real
///   formatting via `std::fmt::Write`, avoiding heap-allocated `format!()` for common types.
/// - **Direct byte extension**: Simple types (integers, reals) write directly to the
///   output buffer without intermediate String allocation.
/// - **Bulk writes**: Space and newline separators are written as single byte-slice
///   extensions rather than individual byte pushes.
#[cfg(feature = "pdf-cdr")]
pub(super) fn serialize_operations(operations: &[(Vec<Object>, String)]) -> Vec<u8> {
    // Estimate total capacity: avg ~24 bytes per operation (operand + space + op + newline)
    let estimated_capacity = operations.len().saturating_mul(EST_BYTES_PER_OPERATION);
    let mut bytes = Vec::with_capacity(estimated_capacity);

    // Reusable stack buffer for numeric formatting (avoids heap allocation)
    let mut fmt_buf = [0u8; 64];

    for (operands, operator) in operations {
        for (i, operand) in operands.iter().enumerate() {
            if i > 0 {
                bytes.extend_from_slice(b" ");
            }

            // Format operand based on type — fast-path for common cases
            match operand {
                Object::Integer(n) => {
                    // Write integer directly to stack buffer, then extend
                    let s = format_int_to_buf(*n, &mut fmt_buf);
                    bytes.extend_from_slice(s.as_bytes());
                }
                Object::Real(f) => {
                    // Write real number directly to stack buffer (f32 → f64 for formatting)
                    let s = format_real_to_buf(f64::from(*f), &mut fmt_buf);
                    bytes.extend_from_slice(s.as_bytes());
                }
                Object::Name(name) => {
                    bytes.push(b'/');
                    bytes.extend_from_slice(name);
                }
                Object::String(s, _) => {
                    bytes.push(b'(');
                    bytes.extend_from_slice(s);
                    bytes.push(b')');
                }
                Object::Array(arr) => {
                    bytes.push(b'[');
                    for (j, o) in arr.iter().enumerate() {
                        if j > 0 {
                            bytes.extend_from_slice(b" ");
                        }
                        // Debug-format array elements (consistent with original behavior)
                        let formatted = format!("{:?}", o);
                        bytes.extend_from_slice(formatted.as_bytes());
                    }
                    bytes.push(b']');
                }
                Object::Reference(id) => {
                    // Write reference directly without format!() allocation
                    let ref_str = format_ref_to_buf(id.0, id.1, &mut fmt_buf);
                    bytes.extend_from_slice(ref_str.as_bytes());
                }
                _ => {
                    // Fallback for rare types — uses format! (acceptable for cold path)
                    let fallback = format!("{:?}", operand);
                    bytes.extend_from_slice(fallback.as_bytes());
                }
            };
        }

        bytes.extend_from_slice(b" ");
        bytes.extend_from_slice(operator.as_bytes());
        bytes.extend_from_slice(b"\n");
    }

    bytes
}

/// Format an i64 integer into the provided stack buffer, returning a str slice.
///
/// Uses `std::fmt::Write` to write into a fixed-size byte buffer, avoiding
/// heap allocation for the common case of integer operands.
#[inline]
fn format_int_to_buf(n: i64, buf: &mut [u8; 64]) -> &str {
    buf.fill(0);
    let mut writer = StackWriter { buf, pos: 0 };
    let _ = write!(writer, "{}", n);
    // Safety: write! only writes valid UTF-8 (ASCII digits and optional '-')
    unsafe { std::str::from_utf8_unchecked(&writer.buf[..writer.pos]) }
}

/// Format an f64 real number into the provided stack buffer.
#[inline]
fn format_real_to_buf(f: f64, buf: &mut [u8; 64]) -> &str {
    buf.fill(0);
    let mut writer = StackWriter { buf, pos: 0 };
    let _ = write!(writer, "{}", f);
    unsafe { std::str::from_utf8_unchecked(&writer.buf[..writer.pos]) }
}

/// Format a PDF reference (obj_num gen R) into the provided stack buffer.
#[inline]
fn format_ref_to_buf(obj: u32, generation: u16, buf: &mut [u8; 64]) -> &str {
    buf.fill(0);
    let mut writer = StackWriter { buf, pos: 0 };
    let _ = write!(writer, "{} {} R", obj, generation);
    unsafe { std::str::from_utf8_unchecked(&writer.buf[..writer.pos]) }
}

/// Stack-backed writer for zero-heap-allocation formatting.
///
/// Writes into a fixed-size byte buffer. Panics on overflow (should never
/// happen with 64-byte buffer for typical PDF operand sizes).
struct StackWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> FmtWrite for StackWriter<'a> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let end = (self.pos + s.len()).min(self.buf.len());
        self.buf[self.pos..end].copy_from_slice(s.as_bytes());
        self.pos = end;
        Ok(())
    }
}

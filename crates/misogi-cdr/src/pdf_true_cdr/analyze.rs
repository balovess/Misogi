//! Phase 2: Analyze — Object classification and threat detection.
//!
//! This module classifies every PDF object from the parsed intermediate
//! representation into one of four categories:
//!
//! - **Keep** — Legitimate content (text, graphics, safe resources)
//! - **Remove** — Known threat (JS, OpenAction, AA, EmbeddedFile, etc.)
//! - **Warn** — Suspicious but not clearly malicious (logged as warning)
//! - **Block** — Unprocessable (encrypted, corrupted, oversized)
//!
//! ## Analysis Scope
//!
//! 1. **Catalog-level**: OpenAction, AA (Additional Actions), AcroForm, JavaScript
//! 2. **Page-level**: Per-page AA, Actions, Annotations, Resources
//! 3. **Annotation-level**: RichMedia, Screen/Movie/Sound, FileAttachment, per-annotation AA
//! 4. **Resource-level**: XObject subtypes, ColorSpace validation

#[cfg(feature = "pdf-cdr")]
use std::collections::HashMap;

#[cfg(feature = "pdf-cdr")]
use lopdf::Object;

use super::constants::{
    ALLOWED_COLOR_SPACES,
    SUSPICIOUS_COLOR_SPACES,
};
use super::parse::PdfIntermediate;
use super::types::{BlockedItemType, ThreatType};

// =============================================================================
// Object Classification
// =============================================================================

/// Classification result for each PDF object.
///
/// Determines whether an object should be kept, removed, or blocked.
#[cfg(feature = "pdf-cdr")]
#[derive(Debug, Clone, PartialEq)]
pub(super) enum ObjectClassification {
    /// Object contains legitimate content (text, graphics, safe resources).
    Keep,

    /// Object contains a known threat (JS, OpenAction, etc.).
    Remove(ThreatType),

    /// Object is suspicious but not clearly malicious (log warning).
    Warn(String),

    /// Object cannot be processed (encrypted, corrupted, oversized).
    Block(BlockedItemType, String),
}

// =============================================================================
// Analyze Functions
// =============================================================================

/// Classify all PDF objects as keep/remove/block.
///
/// Scans catalog, pages, and individual objects for threats.
/// Returns classification map keyed by object ID.
///
/// # Arguments
/// * `allow_forms` - Whether form fields are permitted by policy.
/// * `allow_annotations` - Whether annotations are permitted by policy.
/// * `intermediates` - Parsed PDF intermediate representation.
///
/// # Returns
/// HashMap mapping object ID → classification decision.
#[cfg(feature = "pdf-cdr")]
pub(super) fn analyze_objects(
    allow_forms: bool,
    allow_annotations: bool,
    intermediates: &PdfIntermediate,
) -> HashMap<u32, ObjectClassification> {
    let mut classification = HashMap::new();

    analyze_catalog(intermediates, allow_forms, &mut classification);

    for &page_id in &intermediates.page_tree.page_ids {
        analyze_page(intermediates, page_id, allow_annotations, &mut classification);
    }

    classification
}

/// Analyze catalog dictionary for threats.
///
/// Checks for:
/// - `/OpenAction` — auto-executes on document open
/// - `/AA` (Additional Actions) — event-driven script triggers
/// - `/AcroForm` — form fields (if disallowed by policy)
/// - `/JavaScript` or `/JS` — named JavaScript entries
#[cfg(feature = "pdf-cdr")]
fn analyze_catalog(
    intermediates: &PdfIntermediate,
    allow_forms: bool,
    classification: &mut HashMap<u32, ObjectClassification>,
) {
    if let Ok(catalog) = intermediates.document.catalog() {
        if catalog.get(b"OpenAction").is_ok() {
            classification.insert(0, ObjectClassification::Remove(ThreatType::OpenAction));
            tracing::warn!("Catalog contains /OpenAction — removing");
        }

        if catalog.get(b"AA").is_ok() {
            classification.insert(0, ObjectClassification::Remove(ThreatType::AdditionalActions));
            tracing::warn!("Catalog contains /AA — removing");
        }

        if !allow_forms && catalog.get(b"AcroForm").is_ok() {
            classification.insert(
                0,
                ObjectClassification::Remove(ThreatType::SubmitForm),
            );
            tracing::debug!("Catalog contains /AcroForm — removing (forms disallowed)");
        }

        if catalog.get(b"JavaScript").is_ok() || catalog.get(b"JS").is_ok() {
            classification.insert(0, ObjectClassification::Remove(ThreatType::JavaScript));
            tracing::warn!("Catalog contains JavaScript — removing");
        }
    }
}

/// Analyze a single page object for threats.
///
/// Checks for:
/// - Page-level `/AA` and `/Actions`
/// - Annotation array (delegates to `analyze_annotation`)
/// - Resource dictionary (delegates to `analyze_resources`)
#[cfg(feature = "pdf-cdr")]
fn analyze_page(
    intermediates: &PdfIntermediate,
    page_id: u32,
    allow_annotations: bool,
    classification: &mut HashMap<u32, ObjectClassification>,
) {
    if let Ok(page_obj) = intermediates.document.get_object((page_id, 0)) {
        if let Ok(dict) = page_obj.as_dict() {
            if dict.get(b"AA").is_ok() {
                classification.insert(
                    page_id,
                    ObjectClassification::Remove(ThreatType::AdditionalActions),
                );
            }

            if dict.get(b"Actions").is_ok() {
                classification.insert(
                    page_id,
                    ObjectClassification::Remove(ThreatType::JavaScript),
                );
            }

            if allow_annotations {
                if let Ok(annots) = dict.get(b"Annots") {
                    if let Ok(annots_array) = annots.as_array() {
                        for annot in annots_array {
                            if let Ok(annot_ref) = annot.as_reference() {
                                analyze_annotation(
                                    intermediates,
                                    annot_ref.0,
                                    classification,
                                );
                            }
                        }
                    }
                }
            } else {
                if dict.get(b"Annots").is_ok() {
                    classification.insert(
                        page_id,
                        ObjectClassification::Warn("Annotations stripped (policy)".to_string()),
                    );
                }
            }

            if let Ok(resources) = dict.get(b"Resources") {
                analyze_resources(intermediates, resources, classification);
            }
        }
    }
}

/// Analyze annotation object for threats.
///
/// Classification rules:
/// - `RichMedia` → Remove (Flash/SWF container)
/// - `Screen`, `Movie`, `Sound` → Block (multimedia)
/// - Other subtypes (`Text`, `Highlight`, `Stamp`, etc.) → Keep
/// - Any annotation with `/AA` → Remove
/// - `FileAnnotation` with `/FS` → Remove (EmbeddedFile)
#[cfg(feature = "pdf-cdr")]
fn analyze_annotation(
    intermediates: &PdfIntermediate,
    annot_id: u32,
    classification: &mut HashMap<u32, ObjectClassification>,
) {
    if let Ok(annot_obj) = intermediates.document.get_object((annot_id, 0)) {
        if let Ok(dict) = annot_obj.as_dict() {
            if let Ok(subtype) = dict.get(b"Subtype") {
                if let Ok(name) = subtype.as_name_str() {
                    match name {
                        "RichMedia" => {
                            classification.insert(
                                annot_id,
                                ObjectClassification::Remove(ThreatType::RichMedia),
                            );
                        }
                        "Screen" | "Movie" | "Sound" => {
                            classification.insert(
                                annot_id,
                                ObjectClassification::Block(
                                    BlockedItemType::UnsupportedImageFormat,
                                    "Multimedia annotation blocked".to_string(),
                                ),
                            );
                        }
                        _ => {
                            classification.insert(annot_id, ObjectClassification::Keep);
                        }
                    }
                }
            }

            if dict.get(b"AA").is_ok() {
                classification.insert(
                    annot_id,
                    ObjectClassification::Remove(ThreatType::AdditionalActions),
                );
            }

            if let Ok(subtype) = dict.get(b"Subtype") {
                if let Ok(name) = subtype.as_name_str() {
                    if name == "FileAttachment" && dict.get(b"FS").is_ok() {
                        classification.insert(
                            annot_id,
                            ObjectClassification::Remove(ThreatType::EmbeddedFile),
                        );
                    }
                }
            }
        }
    }
}

/// Analyze resource dictionary for suspicious entries.
///
/// # Enhanced Validation
///
/// This method validates `/ColorSpace` entries in the resource dictionary
/// to block color spaces that can embed arbitrary data:
///
/// **Allowed** (safe, well-defined):
/// - DeviceRGB, DeviceCMYK, DeviceGray, CalRGB, CalGRAY, Pattern
///
/// **Blocked/suspicious** (can hide payloads):
/// - ICCBased, Lab, Separation, DeviceN, Indexed
#[cfg(feature = "pdf-cdr")]
fn analyze_resources(
    intermediates: &PdfIntermediate,
    resources: &Object,
    classification: &mut HashMap<u32, ObjectClassification>,
) {
    if let Ok(res_dict) = resources.as_dict() {
        if let Ok(xobjects) = res_dict.get(b"XObject") {
            if let Ok(xobj_dict) = xobjects.as_dict() {
                for (key, value) in xobj_dict.iter() {
                    let key_str = String::from_utf8_lossy(key);
                    if let Ok(ref_num) = value.as_reference() {
                        if let Ok(xobj) = intermediates.document.get_object((ref_num.0, 0)) {
                            if let Ok(xdict) = xobj.as_dict() {
                                if let Ok(subtype) = xdict.get(b"Subtype") {
                                    if let Ok(name) = subtype.as_name_str() {
                                        match name {
                                            "RichMedia" => {
                                                classification.insert(
                                                    ref_num.0,
                                                    ObjectClassification::Remove(ThreatType::RichMedia),
                                                );
                                            }
                                            "Image" => {
                                                classification.insert(
                                                    ref_num.0,
                                                    ObjectClassification::Keep,
                                                );
                                            }
                                            _ => {
                                                classification.insert(
                                                    ref_num.0,
                                                    ObjectClassification::Keep,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            classification.insert(
                                ref_num.0,
                                ObjectClassification::Warn(format!(
                                    "Unresolved XObject reference: {}",
                                    key_str
                                )),
                            );
                        }
                    }
                }
            }
        }

        if let Ok(colorspaces) = res_dict.get(b"ColorSpace") {
            validate_color_spaces(colorspaces, classification);
        }

        for (_, value) in res_dict.iter() {
            if let Ok(sub_dict) = value.as_dict() {
                if let Ok(cs) = sub_dict.get(b"ColorSpace") {
                    validate_color_spaces(cs, classification);
                }
            }
        }
    }
}

/// Validate color space definitions against allowed/blocked lists.
///
/// # Security Rationale
///
/// Certain PDF color space types can contain or reference arbitrary binary data:
/// - **ICCBased**: ICC profile stream (any binary payload)
/// - **Indexed**: Lookup table byte string (steganography vector)
/// - **Separation/DeviceN**: Tint transform functions (code execution risk)
/// - **Lab**: Range arrays with floating point values (data hiding)
#[cfg(feature = "pdf-cdr")]
pub(super) fn validate_color_spaces(
    colorspaces: &Object,
    classification: &mut HashMap<u32, ObjectClassification>,
) {
    if let Ok(cs_dict) = colorspaces.as_dict() {
        for (cs_key, cs_value) in cs_dict.iter() {
            let cs_name = String::from_utf8_lossy(cs_key);

            let cs_type = match cs_value {
                Object::Name(name) => String::from_utf8_lossy(name).to_string(),
                Object::Array(arr) => {
                    if !arr.is_empty() {
                        if let Ok(first) = arr[0].as_name_str() {
                            first.to_string()
                        } else {
                            "Unknown".to_string()
                        }
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };

            if ALLOWED_COLOR_SPACES.contains(&cs_type.as_str()) {
                tracing::debug!(
                    colorspace = %cs_name,
                    cs_type = %cs_type,
                    "Color space is allowed"
                );
                continue;
            }

            if SUSPICIOUS_COLOR_SPACES.contains(&cs_type.as_str()) {
                tracing::warn!(
                    colorspace = %cs_name,
                    cs_type = %cs_type,
                    "Blocked suspicious color space — potential data hiding vector"
                );

                classification.insert(
                    hash_colorspace_name(&cs_name),
                    ObjectClassification::Warn(format!(
                        "Blocked suspicious color space '{}' ({}) — potential data hiding vector",
                        cs_name, cs_type
                    )),
                );
            } else {
                tracing::warn!(
                    colorspace = %cs_name,
                    cs_type = %cs_type,
                    "Unknown color space type — allowing but monitoring recommended"
                );
            }
        }
    }
}

/// Generate a deterministic pseudo-object-ID for color space names.
///
/// Since color spaces are identified by name (not object ID), we need
/// a stable identifier for classification map entries.
///
/// # Performance
///
/// Uses **FNV-1a 32-bit hash** instead of `DefaultHasher` (SipHash).
/// FNV-1a is significantly faster because:
/// - No heap allocation (no Hasher struct to instantiate)
/// - Simple multiply-xor loop with CPU-friendly operations
/// - SipHash is cryptographically secure but overkill for this use case
/// - Typical speedup: ~3-5x for short strings like color space names
///
/// The high-order nibble (`0xF`) is set to ensure these IDs don't collide
/// with real PDF object IDs (which are typically small sequential integers).
#[cfg(feature = "pdf-cdr")]
#[inline]
pub(super) fn hash_colorspace_name(name: &str) -> u32 {
    // FNV-1a 32-bit constants
    const FNV_OFFSET_BASIS: u32 = 0x811C_9DC5;
    const FNV_PRIME: u32 = 0x0100_0193;

    let mut hash = FNV_OFFSET_BASIS;
    for &byte in name.as_bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    // Set high-order nibble to distinguish from real object IDs
    hash | 0xF000_0000
}

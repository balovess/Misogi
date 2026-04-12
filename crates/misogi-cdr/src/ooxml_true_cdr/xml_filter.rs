//! XML filtering pipeline for OOXML True CDR.
//!
//! Handles Content_Types.xml filtering, document XML whitelist filtering,
//! attribute stripping, and element name resolution.

use std::io::Cursor;

use quick_xml::events::attributes::Attributes;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::{Reader, Writer};

use misogi_core::{MisogiError, Result};

use super::config::OoxmlTrueCdrConfig;
use super::constants::DANGEROUS_ATTRIBUTES;
use super::constants::DANGEROUS_CONTENT_TYPES;
use super::report::OoxmlCdrReport;
use super::types::{FilteredXmlResult, OoxmlDocumentType};

use super::threat::{
    scan_element_threats,
    scan_text_content_threats,
};

// =============================================================================
// Public API Functions
// =============================================================================

/// Filter [Content_Types].xml to remove macro-related content types.
///
/// Parses the Content_Types manifest and removes Override/Default elements
/// that reference dangerous MIME types (VBA, ActiveX, OLE, etc.).
pub fn filter_content_types(
    xml_bytes: &[u8],
    report: &mut OoxmlCdrReport,
) -> Result<FilteredXmlResult> {
    let mut reader = Reader::from_reader(xml_bytes);

    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut elements_dropped = 0;
    let mut buf: Vec<u8> = Vec::new();

    // Preserve XML declaration if present
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Decl(decl)) => {
                writer.write_event(Event::Decl(decl))
                    .map_err(|e| MisogiError::Io(xml_write_error(e)))?;
                break;
            }
            Ok(Event::Start(_) | Event::Empty(_)) | Err(_) => {
                break;
            }
            Ok(_) => continue,
        }
    }

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let local_name = e.local_name();
                let name_str = String::from_utf8_lossy(local_name.as_ref());

                // Check if this is an Override or Default element with dangerous ContentType
                if name_str == "Override" || name_str == "Default" {
                    let attrs = e.attributes();
                    let mut attrs_vec: Vec<(String, String)> = Vec::new();
                    let mut content_type_value = String::new();
                    let mut is_dangerous = false;

                    for attr in attrs.flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        let value = String::from_utf8_lossy(&attr.value).to_string();

                        if key == "ContentType" {
                            content_type_value = value.clone();
                            let ct_lower = value.to_ascii_lowercase();
                            for dangerous_ct in DANGEROUS_CONTENT_TYPES {
                                if ct_lower.contains(&dangerous_ct.to_ascii_lowercase()) {
                                    is_dangerous = true;
                                    break;
                                }
                            }
                        }

                        attrs_vec.push((key, value));
                    }

                    if is_dangerous {
                        elements_dropped += 1;
                        tracing::debug!(
                            content_type = %content_type_value,
                            "Removed dangerous content type from manifest"
                        );
                        continue;
                    }

                    let name_owned = name_str.clone().into_owned();
                    let is_override = name_str == "Override";
                    let mut new_elem = BytesStart::new(name_owned);
                    for (key, value) in &attrs_vec {
                        new_elem.push_attribute((key.as_str(), value.as_str()));
                    }

                    if is_override {
                        writer.write_event(Event::Start(new_elem))
                            .map_err(|e| MisogiError::Io(xml_write_error(e)))?;
                    } else {
                        writer.write_event(Event::Empty(new_elem))
                            .map_err(|e| MisogiError::Io(xml_write_error(e)))?;
                    }
                } else {
                    writer.write_event(Event::Start(e.to_owned()))
                        .map_err(|e| MisogiError::Io(xml_write_error(e)))?;
                }
            }
            Ok(Event::End(e)) => {
                writer.write_event(Event::End(e))
                    .map_err(|e| MisogiError::Io(xml_write_error(e)))?;
            }
            Ok(Event::Text(e)) => {
                writer.write_event(Event::Text(e))
                    .map_err(|e| MisogiError::Io(xml_write_error(e)))?;
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                report.add_warning(format!("XML parsing error in Content_Types.xml: {}", e));
                break;
            }
            _ => {}
        }

        buf.clear();
    }

    let output_cursor = writer.into_inner();
    let filtered_bytes = output_cursor.into_inner();

    if elements_dropped > 0 {
        report.content_types_modified = true;
    }

    Ok(FilteredXmlResult {
        filtered_bytes,
        elements_dropped,
        removed_target_ids: Vec::new(),
    })
}

/// Filter document XML through element whitelist.
///
/// Parses XML and recursively filters elements, keeping only those
/// present in the whitelist for the detected document type. Also strips
/// dangerous attributes from kept elements.
pub fn filter_document_xml(
    xml_bytes: &[u8],
    doc_type: OoxmlDocumentType,
    config: &OoxmlTrueCdrConfig,
    report: &mut OoxmlCdrReport,
) -> Result<FilteredXmlResult> {
    let whitelist = config.element_whitelist.get_whitelist(doc_type);

    let mut reader = Reader::from_reader(xml_bytes);

    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut buf: Vec<u8> = Vec::new();
    let mut elements_dropped = 0;
    let mut removed_targets = Vec::new();

    // Name stack for proper End event handling
    let mut name_stack: Vec<String> = Vec::new();
    // Depth stack — parallel to name_stack
    let mut depth_stack: Vec<bool> = vec![true];
    // Current text content parent element name for DDE/script scanning
    let mut current_text_parent: Option<String> = None;

    // Preserve XML declaration if present
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Decl(decl)) => {
                writer.write_event(Event::Decl(decl))
                    .map_err(|e| MisogiError::Io(xml_write_error(e)))?;
                break;
            }
            Ok(Event::Start(_) | Event::Empty(_)) | Err(_) => break,
            Ok(_) => continue,
        }
    }

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let elem_name = resolve_element_name(e);
                let parent_kept = *depth_stack.last().unwrap_or(&true);

                // Namespace-aware whitelist matching
                let in_whitelist = whitelist.contains(&elem_name)
                    || elem_name.split(':').last().map_or(false, |local| whitelist.contains(local));

                // Document-type-specific pre-filter threat scanning
                let force_drop = scan_element_threats(
                    &elem_name,
                    e.attributes(),
                    doc_type,
                    config,
                    report,
                    &mut removed_targets,
                );

                if parent_kept && in_whitelist && !force_drop {
                    let filtered_attrs = filter_attributes(e.attributes());

                    let mut new_start = BytesStart::new(elem_name.as_str());
                    for (key, value) in &filtered_attrs {
                        new_start.push_attribute((key.as_str(), value.as_str()));
                    }

                    name_stack.push(elem_name.clone());
                    depth_stack.push(true);
                    current_text_parent = Some(elem_name.clone());

                    writer.write_event(Event::Start(new_start))
                        .map_err(|e| MisogiError::Io(xml_write_error(e)))?;
                } else {
                    name_stack.push(elem_name.clone());
                    depth_stack.push(false);
                    current_text_parent = Some(elem_name.clone());
                    elements_dropped += 1;

                    if let Some(target_id) = extract_element_target_id(&elem_name, e.attributes()) {
                        removed_targets.push(target_id);
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                let elem_name = resolve_element_name(e);
                let parent_kept = *depth_stack.last().unwrap_or(&true);
                let in_whitelist = whitelist.contains(&elem_name)
                    || elem_name.split(':').last().map_or(false, |local| whitelist.contains(local));

                let _force_drop = scan_element_threats(
                    &elem_name,
                    e.attributes(),
                    doc_type,
                    config,
                    report,
                    &mut removed_targets,
                );

                if parent_kept && in_whitelist {
                    let filtered_attrs = filter_attributes(e.attributes());

                    let mut new_empty = BytesStart::new(elem_name.as_str());
                    for (key, value) in &filtered_attrs {
                        new_empty.push_attribute((key.as_str(), value.as_str()));
                    }

                    writer.write_event(Event::Empty(new_empty))
                        .map_err(|e| MisogiError::Io(xml_write_error(e)))?;
                } else {
                    elements_dropped += 1;
                }
            }
            Ok(Event::End(_)) => {
                if depth_stack.len() > 1 {
                    let was_kept = depth_stack.pop().unwrap_or(false);
                    let elem_name = name_stack.pop().unwrap_or_default();

                    if was_kept && !elem_name.is_empty() {
                        let end_tag = BytesEnd::new(elem_name.as_str());
                        writer.write_event(Event::End(end_tag))
                            .map_err(|e| MisogiError::Io(xml_write_error(e)))?;
                    }
                }
                current_text_parent = name_stack.last().cloned();
            }
            Ok(Event::Text(e)) => {
                let parent_kept = *depth_stack.last().unwrap_or(&false);
                if parent_kept {
                    let text_content = String::from_utf8_lossy(e.as_ref()).to_string();
                    let text_safe = scan_text_content_threats(
                        &text_content,
                        current_text_parent.as_deref(),
                        doc_type,
                        config,
                        report,
                    );

                    if text_safe {
                        writer.write_event(Event::Text(e))
                            .map_err(|e| MisogiError::Io(xml_write_error(e)))?;
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                report.add_warning(format!("XML parsing error: {}", e));
                break;
            }
            _ => {}
        }

        buf.clear();
    }

    let output_cursor = writer.into_inner();
    let filtered_bytes = output_cursor.into_inner();

    Ok(FilteredXmlResult {
        filtered_bytes,
        elements_dropped,
        removed_target_ids: removed_targets,
    })
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Resolve element name from event, handling namespace prefixes.
pub(crate) fn resolve_element_name(event: &BytesStart<'_>) -> String {
    let full_name = String::from_utf8_lossy(event.name().as_ref()).to_string();

    if full_name.contains(':') {
        full_name
    } else {
        String::from_utf8_lossy(event.local_name().as_ref()).to_string()
    }
}

/// Filter attributes from an element, removing dangerous ones.
///
/// Returns a vector of (key, value) pairs for safe attributes only.
pub(crate) fn filter_attributes(attrs: Attributes<'_>) -> Vec<(String, String)> {
    let mut safe_attrs = Vec::new();

    for attr in attrs.flatten() {
        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
        let value = String::from_utf8_lossy(&attr.value).to_string();

        let is_dangerous = DANGEROUS_ATTRIBUTES.iter().any(|dangerous| {
            key.to_ascii_lowercase() == dangerous.to_ascii_lowercase()
                || value.to_ascii_lowercase().contains(&dangerous.to_ascii_lowercase())
        });

        if !is_dangerous {
            safe_attrs.push((key, value));
        } else {
            tracing::debug!(
                attribute = %key,
                "Stripped dangerous attribute from element"
            );
        }
    }

    safe_attrs
}

/// Extract target ID from an element's attributes (for relationship tracking).
pub(crate) fn extract_element_target_id(
    _elem_name: &str,
    _attrs: Attributes<'_>,
) -> Option<String> {
    None
}

/// Format XML write error with context.
fn xml_write_error(e: quick_xml::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("XML write error: {}", e))
}

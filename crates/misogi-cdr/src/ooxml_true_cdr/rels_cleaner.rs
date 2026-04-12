//! Relationship cleaning and output validation for OOXML True CDR.

use std::collections::HashSet;
use std::io::Cursor;

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, Writer};
use zip::ZipArchive;

use misogi_core::{MisogiError, Result};

use super::report::OoxmlCdrReport;
use super::types::FilteredXmlResult;

// =============================================================================
// Relationship Cleaning
// =============================================================================

/// Clean relationships file to remove dangling references.
///
/// When entries are removed (VBA, ActiveX, OLE, etc.), their corresponding
/// relationship entries in .rels files become dangling. This method removes
/// those dangling references to maintain OOXML validity.
pub fn clean_relationships(
    rels_xml: &[u8],
    removed_ids: &HashSet<String>,
    report: &mut OoxmlCdrReport,
) -> Result<FilteredXmlResult> {
    if removed_ids.is_empty() {
        return Ok(FilteredXmlResult {
            filtered_bytes: Vec::new(),
            elements_dropped: 0,
            removed_target_ids: Vec::new(),
        });
    }

    let mut reader = Reader::from_reader(rels_xml);

    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut elements_dropped = 0;
    let mut buf = Vec::new();

    // Preserve XML declaration
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
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let local_name = e.local_name();
                let name_str = String::from_utf8_lossy(local_name.as_ref());

                if name_str == "Relationship" {
                    let attrs = e.attributes();
                    let mut rel_id = String::new();
                    #[allow(unused_assignments)]
                    let mut target = String::new();
                    let mut attrs_to_keep: Vec<(String, String)> = Vec::new();
                    let mut should_remove = false;

                    for attr in attrs.flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        let value = String::from_utf8_lossy(&attr.value).to_string();

                        if key == "Id" {
                            rel_id = value.clone();
                        } else if key == "Target" {
                            target = value.clone();
                            let normalized_target = target.replace('\\', "/");
                            if removed_ids.contains(&normalized_target)
                                || removed_ids.iter().any(|id| normalized_target.contains(id))
                            {
                                should_remove = true;
                                tracing::debug!(
                                    rel_id = %rel_id,
                                    target = %target,
                                    "Removing dangling relationship"
                                );
                            }
                        }

                        attrs_to_keep.push((key, value));
                    }

                    if should_remove {
                        elements_dropped += 1;
                        continue;
                    }

                    let rel_name: &str = "Relationship";
                    let mut new_rel = BytesStart::new(rel_name);
                    for (key, value) in &attrs_to_keep {
                        new_rel.push_attribute((key.as_str(), value.as_str()));
                    }

                    writer.write_event(Event::Empty(new_rel))
                        .map_err(|e| MisogiError::Io(xml_write_error(e)))?;
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
                report.add_warning(format!("XML parsing error in .rels file: {}", e));
                break;
            }
            _ => {}
        }

        buf.clear();
    }

    let output_cursor = writer.into_inner();
    let filtered_bytes = output_cursor.into_inner();

    if elements_dropped > 0 {
        report.relationships_modified = true;
    }

    Ok(FilteredXmlResult {
        filtered_bytes,
        elements_dropped,
        removed_target_ids: Vec::new(),
    })
}

// =============================================================================
// Output Validation
// =============================================================================

/// Validate the output ZIP archive for structural integrity.
pub fn validate_output(output: &[u8]) -> Result<bool> {
    let cursor = Cursor::new(output.to_vec());
    match ZipArchive::new(cursor) {
        Ok(mut archive) => {
            let has_content_types = (0..archive.len()).any(|i| {
                archive.by_index(i)
                    .map(|e| e.name() == "[Content_Types].xml")
                    .unwrap_or(false)
            });

            if !has_content_types {
                tracing::warn!("Output ZIP missing [Content_Types].xml — invalid OOXML");
                return Ok(false);
            }

            Ok(true)
        }
        Err(e) => {
            tracing::error!(error = %e, "Output is not a valid ZIP archive");
            Ok(false)
        }
    }
}

// =============================================================================
// Internal Helpers
// =============================================================================

fn xml_write_error(e: quick_xml::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("XML write error: {}", e))
}

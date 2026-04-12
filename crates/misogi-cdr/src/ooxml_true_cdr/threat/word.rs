//! Word-specific threat scanning for OOXML True CDR.

use quick_xml::events::attributes::Attributes;

use super::super::report::{OoxmlCdrAction, OoxmlCdrReport};
use super::{has_blocked_url_protocol, identify_blocked_protocol};

/// Scan a Word element for document-specific threats.
///
/// # Word Threat Model
///
/// 1. **instrText** — Field instruction text can contain macro-like commands.
///    (Text content scanning handled in `scan_text_content_threats`)
///
/// 2. **altChunk** — External content embedding via `r:id` target.
///    Major attack vector for HTML smuggling and content spoofing.
///
/// 3. **hyperlink** with `r:id` or `Target` — Validate target against blocklist.
///
/// 4. **permStart/permEnd** — IRM permission elements that can hide content
///    from CDR scanners via permission-based visibility.
pub fn scan_word_element_threats(
    elem_name: &str,
    attrs: Attributes<'_>,
    report: &mut OoxmlCdrReport,
    removed_targets: &mut Vec<String>,
) -> bool {
    let mut force_drop = false;

    let attr_vec: Vec<(String, String)> = attrs.flatten()
        .map(|a| (
            String::from_utf8_lossy(a.key.as_ref()).to_string(),
            String::from_utf8_lossy(&a.value).to_string(),
        ))
        .collect();

    match elem_name {
        "altChunk" => {
            let chunk_id = attr_vec.iter()
                .find(|(k, _)| k == "r:id" || k == "id")
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| "unknown".to_string());

            report.word_threats_neutralized += 1;
            report.actions_taken.push(OoxmlCdrAction::AltChunkRemoved {
                chunk_id: chunk_id.clone(),
            });
            removed_targets.push(chunk_id);

            tracing::warn!(
                "altChunk (external content embedding) detected — major attack vector, removed entirely"
            );
            force_drop = true;
        }

        "hyperlink" => {
            let target = attr_vec.iter()
                .find(|(k, _)| k == "Target" || k == "r:id")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();

            if !target.is_empty() && has_blocked_url_protocol(&target) {
                let proto = identify_blocked_protocol(&target)
                    .unwrap_or_else(|| "unknown".to_string());

                report.word_threats_neutralized += 1;
                report.actions_taken.push(OoxmlCdrAction::HyperlinkBlocked {
                    target: target.clone(),
                    reason: format!("blocked protocol: {}", proto),
                });

                tracing::warn!(
                    target = %target,
                    protocol = %proto,
                    "Word hyperlink with blocked protocol — neutralized"
                );
                force_drop = true;
            }
        }

        "permStart" | "permEnd" => {
            let perm_id = attr_vec.iter()
                .find(|(k, _)| k == "id")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();

            report.word_threats_neutralized += 1;
            report.actions_taken.push(OoxmlCdrAction::IrmPermissionStripped {
                location: format!("{}[{}]", elem_name, perm_id),
            });

            tracing::warn!(
                element = %elem_name,
                perm_id = %perm_id,
                "IRM permission element (permStart/permEnd) detected — can hide content from CDR, stripped"
            );
            force_drop = true;
        }

        _ => {}
    }

    force_drop
}

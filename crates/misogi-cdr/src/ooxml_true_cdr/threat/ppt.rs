//! PowerPoint-specific threat scanning for OOXML True CDR.

use quick_xml::events::attributes::Attributes;

use super::super::report::{OoxmlCdrAction, OoxmlCdrReport};
use super::{contains_script_injection, has_blocked_url_protocol};

/// Scan a PowerPoint element for presentation-specific threats.
///
/// # PowerPoint Threat Model
///
/// 1. **oleObj within graphicFrame** — OLE object embeddings disguised as pictures.
///    Can execute code on open via OLE activation.
///
/// 2. **snd (transition sound)** — Sound effect references that may point to
///    external URLs instead of internal package resources.
///
/// 3. **extLst (extension list)** — Non-standard extension elements used by
///    zero-day exploits and undocumented features.
///
/// 4. **cmd (animation action verb)** — Animation commands that can contain
///    javascript:, vbscript:, powershell: URLs for script execution.
pub fn scan_powerpoint_element_threats(
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
        "oleObj" => {
            let obj_id = attr_vec.iter()
                .find(|(k, _)| k == "r:id" || k == "id")
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| "unknown".to_string());

            report.powerpoint_threats_neutralized += 1;
            report.actions_taken.push(OoxmlCdrAction::OleObjectDetected {
                object_id: obj_id.clone(),
            });
            removed_targets.push(obj_id);

            tracing::warn!(
                "OLE object embedding (oleObj) inside graphicFrame detected — potential code execution vector"
            );
            force_drop = true;
        }

        "snd" => {
            let sound_name = attr_vec.iter()
                .find(|(k, _)| k == "name")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();

            let is_external = !sound_name.is_empty()
                && (sound_name.contains("://")
                    || sound_name.starts_with("http")
                    || sound_name.starts_with("ftp")
                    || has_blocked_url_protocol(&sound_name));

            if is_external {
                report.powerpoint_threats_neutralized += 1;
                report.actions_taken.push(OoxmlCdrAction::ExternalSoundStripped {
                    sound_ref: sound_name.clone(),
                });

                tracing::warn!(
                    sound_ref = %sound_name,
                    "Transition sound with external reference detected — stripped"
                );
                force_drop = true;
            }
        }

        "extLst" => {
            let location = attr_vec.iter()
                .find(|(k, _)| k == "id" || k == "uri")
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| "slide".to_string());

            report.powerpoint_threats_neutralized += 1;
            report.actions_taken.push(OoxmlCdrAction::ExtLstRemoved {
                location: location.clone(),
            });

            tracing::warn!(
                location = %location,
                "extLst (extension list) detected — common zero-day attack vector, removed entirely"
            );
            force_drop = true;
        }

        "cBhvr" => {
            let has_malicious_action = attr_vec.iter().any(|(k, v)| {
                (k == "action" || k == "verb") && (
                    has_blocked_url_protocol(v)
                        || contains_script_injection(v)
                )
            });

            if has_malicious_action {
                report.powerpoint_threats_neutralized += 1;
                tracing::warn!(
                    "Animation behavior with malicious action verb detected — stripped"
                );
                force_drop = true;
            }
        }

        _ => {}
    }

    force_drop
}

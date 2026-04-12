//! Excel-specific threat scanning for OOXML True CDR.

use quick_xml::events::attributes::Attributes;

use super::super::report::{OoxmlCdrAction, OoxmlCdrReport};
use super::{contains_script_injection, has_blocked_url_protocol};

/// Scan an Excel element for spreadsheet-specific threats.
///
/// # Excel Threat Model
///
/// 1. **sheetProtection** with `password` attribute — hashed password enables
///    offline brute-force attacks. Action: Strip the entire element.
///
/// 2. **pivotCacheDefinition** with external data source references — can exfiltrate
///    data or pull malicious content. Action: Strip cacheSource children.
///
/// 3. **Map** (custom XML mapping) with script-injectable attributes — XSS vector.
///    Action: Validate Map element ID and schema references.
///
/// 4. **dataValidation** → `<formula1>` containing blocked URL protocols.
///    Action: Detect and flag for removal.
pub fn scan_excel_element_threats(
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
        "sheetProtection" => {
            let has_password = attr_vec.iter().any(|(k, v)| {
                k == "password" && !v.is_empty()
            });

            if has_password {
                report.excel_threats_neutralized += 1;
                report.actions_taken.push(OoxmlCdrAction::SheetProtectionStripped {
                    location: "worksheet".to_string(),
                });

                tracing::warn!(
                    "sheetProtection with password hash detected — potential brute-force vector, stripping element"
                );
                force_drop = true;
            }
        }

        "pivotCacheDefinition" => {
            let has_external_ref = attr_vec.iter().any(|(k, v)| {
                (k == "id" || k == "cacheId")
                    && (v.to_ascii_lowercase().contains("external")
                        || v.to_ascii_lowercase().contains("connection"))
            });

            if has_external_ref {
                let cache_id = attr_vec.iter()
                    .find(|(k, _)| k == "id" || k == "cacheId")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();

                report.excel_threats_neutralized += 1;
                report.actions_taken.push(OoxmlCdrAction::PivotCacheExternalRefStripped {
                    cache_id: cache_id.clone(),
                });
                removed_targets.push(cache_id.clone());

                tracing::warn!(
                    cache_id = %cache_id,
                    "PivotCache with external data source reference detected — stripped"
                );
                force_drop = true;
            }
        }

        "Map" => {
            let map_id = attr_vec.iter()
                .find(|(k, _)| k == "id")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();

            let has_injection = attr_vec.iter().any(|(_, v)| {
                contains_script_injection(v) || has_blocked_url_protocol(v)
            });

            if has_injection {
                report.excel_threats_neutralized += 1;
                report.actions_taken.push(OoxmlCdrAction::CustomXmlMappingStripped {
                    map_id: map_id.clone(),
                    reason: "script injection pattern detected in mapping attributes".to_string(),
                });

                tracing::warn!(
                    map_id = %map_id,
                    "Custom XML mapping with script injection detected — stripped"
                );
                force_drop = true;
            }
        }

        "dataValidation" => {
            let has_malicious_url = attr_vec.iter().any(|(k, v)| {
                (k == "formula1" || k == "formula2") && has_blocked_url_protocol(v)
            });

            if has_malicious_url {
                let url = attr_vec.iter()
                    .find(|(k, _)| k == "formula1" || k == "formula2")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();

                report.excel_threats_neutralized += 1;
                report.actions_taken.push(OoxmlCdrAction::MaliciousDataValidationStripped {
                    location: "dataValidation".to_string(),
                    url: url.clone(),
                });

                tracing::warn!(
                    url = %url,
                    "Malicious URL in data validation dropdown — stripped"
                );
                force_drop = true;
            }
        }

        "externalReference" => {
            let _ = &attr_vec;
        }

        _ => {}
    }

    force_drop
}

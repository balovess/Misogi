//! Threat detection module for OOXML True CDR.
//!
//! Provides document-type-specific threat scanning for Excel, Word, and PowerPoint,
//! plus common detection utilities (DDE, URL protocols, script injection).

mod excel;
mod word;
mod ppt;

pub use excel::scan_excel_element_threats;
pub use word::scan_word_element_threats;
pub use ppt::scan_powerpoint_element_threats;

use quick_xml::events::attributes::Attributes;
use regex::Regex;

use super::config::OoxmlTrueCdrConfig;
use super::constants::{DDE_PATTERNS, BLOCKED_URL_PROTOCOLS, SCRIPT_INJECTION_PATTERNS};
use super::report::{OoxmlCdrAction, OoxmlCdrReport};
use super::types::OoxmlDocumentType;

// =============================================================================
// Common Threat Detection Utilities
// =============================================================================

/// Scan an element for document-type-specific threats before whitelist filtering.
///
/// Called for every Start/Empty event during XML filtering.
/// Performs deep security analysis based on the detected document type.
///
/// # Returns
///
/// `true` if the element should be force-dropped regardless of whitelist status.
pub fn scan_element_threats(
    elem_name: &str,
    attrs: Attributes<'_>,
    doc_type: OoxmlDocumentType,
    _config: &OoxmlTrueCdrConfig,
    report: &mut OoxmlCdrReport,
    removed_targets: &mut Vec<String>,
) -> bool {
    let local_name = elem_name.split(':').last().unwrap_or(elem_name);

    match doc_type {
        OoxmlDocumentType::Excel => scan_excel_element_threats(local_name, attrs, report, removed_targets),
        OoxmlDocumentType::Word => scan_word_element_threats(local_name, attrs, report, removed_targets),
        OoxmlDocumentType::PowerPoint => scan_powerpoint_element_threats(local_name, attrs, report, removed_targets),
        OoxmlDocumentType::Unknown => false,
    }
}

/// Scan text content for DDE attack payloads and script injection patterns.
///
/// Called during Text event processing to inspect textual content of
/// elements like `<v>` (cell values), `<f>` (formulas), `<definedName>`,
/// `<instrText>`, and `<p:cmd>` for known attack signatures.
///
/// # Returns
///
/// `true` if text content is safe and should be preserved.
/// `false` if malicious content was detected and text should be dropped.
pub fn scan_text_content_threats(
    text_content: &str,
    parent_elem_name: Option<&str>,
    doc_type: OoxmlDocumentType,
    _config: &OoxmlTrueCdrConfig,
    report: &mut OoxmlCdrReport,
) -> bool {
    let parent = parent_elem_name
        .and_then(|n| n.split(':').last())
        .unwrap_or("");

    // DDE Attack Detection — scan cell values (<v>) and formulas (<f>)
    if parent == "v" || parent == "f" || parent == "definedName" {
        if contains_dde_payload(text_content) {
            report.dde_attacks_detected += 1;
            let matched_pattern = matched_dde_pattern(text_content)
                .unwrap_or("unknown".to_string());

            report.actions_taken.push(OoxmlCdrAction::DdeAttackDetected {
                location: format!("{} element", parent),
                pattern_matched: matched_pattern,
            });

            tracing::warn!(
                parent_element = %parent,
                content = %text_content,
                "DDE attack payload detected and neutralized"
            );
            return false;
        }
    }

    // Word instrText deep-scan for script injection
    if parent == "instrText" && doc_type == OoxmlDocumentType::Word {
        if contains_script_injection(text_content) {
            report.word_threats_neutralized += 1;
            report.actions_taken.push(OoxmlCdrAction::InstrTextScriptNeutralized {
                field_content: text_content.chars().take(100).collect(),
            });

            tracing::warn!(
                content = %text_content,
                "Script injection detected in Word instrText field — neutralized"
            );
            return false;
        }
    }

    // PowerPoint animation command filtering
    if parent == "cmd" && doc_type == OoxmlDocumentType::PowerPoint {
        if contains_script_injection(text_content)
            || has_blocked_url_protocol(text_content)
        {
            report.powerpoint_threats_neutralized += 1;
            report.actions_taken.push(OoxmlCdrAction::AnimationCmdStripped {
                cmd_content: text_content.chars().take(100).collect(),
            });

            tracing::warn!(
                content = %text_content,
                "Script injection in PowerPoint animation cmd — stripped"
            );
            return false;
        }
    }

    true
}

// =============================================================================
// DDE Detection Methods
// =============================================================================

/// Check if text content contains a DDE attack payload.
pub fn contains_dde_payload(content: &str) -> bool {
    DDE_PATTERNS.iter().any(|pattern| {
        Regex::new(pattern).map_or(false, |re| re.is_match(content))
    })
}

/// Return the first matching DDE pattern string (for reporting).
pub fn matched_dde_pattern(content: &str) -> Option<String> {
    DDE_PATTERNS.iter().find(|pattern| {
        Regex::new(pattern).map_or(false, |re| re.is_match(content))
    }).map(|s| s.to_string())
}

// =============================================================================
// URL Protocol Detection Methods
// =============================================================================

/// Check if a URL/reference uses a blocked protocol scheme.
pub fn has_blocked_url_protocol(url: &str) -> bool {
    let url_lower = url.to_ascii_lowercase();
    BLOCKED_URL_PROTOCOLS.iter().any(|proto| {
        url_lower.starts_with(proto) || url_lower.contains(proto)
    })
}

/// Identify which blocked protocol triggered the detection (for reporting).
pub fn identify_blocked_protocol(url: &str) -> Option<String> {
    let url_lower = url.to_ascii_lowercase();
    BLOCKED_URL_PROTOCOLS.iter().find(|proto| {
        url_lower.starts_with(*proto) || url_lower.contains(*proto)
    }).map(|s| s.to_string())
}

// =============================================================================
// Script Injection Detection
// =============================================================================

/// Check if text content contains script injection patterns.
pub fn contains_script_injection(content: &str) -> bool {
    SCRIPT_INJECTION_PATTERNS.iter().any(|pattern| {
        Regex::new(pattern).map_or(false, |re| re.is_match(content))
    })
}

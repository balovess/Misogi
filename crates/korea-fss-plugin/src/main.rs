//! Korea FSS (Financial Supervisory Service) compliance plugin for Misogi.
//!
//! Demonstrates the production-grade Misogi Macro SDK by implementing a
//! region-specific compliance rule with zero boilerplate trait implementations.
//!
//! # Capabilities
//!
//! | Hook                  | Trait               | Purpose                          |
//! |-----------------------|---------------------|----------------------------------|
//! | `#[on_metadata]`      | `FileTypeDetector`  | Korean document format classification |
//! | `#[on_file_stream]`   | `CDRStrategy`       | RRN (주민등록번호) pattern detection  |
//! | `#[on_scan_content]`  | `PIIDetector`       | Structured PII match reporting    |
//! | `#[misogi_plugin]`    | `PluginMetadata`    | Auto-registration + metadata     |

use misogi_macros::{misogi_plugin, on_metadata, on_file_stream, on_scan_content};
use misogi_core::traits::PIIMatch;

/// Korea Financial Supervisory Service compliance plugin.
///
/// Enforces Korean financial sector document handling regulations including
/// RRN detection, HWP/HWPX format classification, and FSS-mandated audit trails.
#[misogi_plugin(
    name = "korea_fss_compliance",
    version = "1.0.0",
    description = "Korea FSS compliance: RRN detection, Korean format \
                   classification, and structured PII scanning"
)]
pub struct KoreaFssCompliancePlugin;

// =============================================================================
// Hook: File Type Classification → FileTypeDetector
// =============================================================================

/// Classify incoming files by Korean-specific document format extensions.
///
/// # Supported Formats
///
/// | Extension | Format          | Description                        |
/// |-----------|-----------------|------------------------------------|
/// | `.hwp`    | Hancom Word     | Legacy Korean word processor       |
/// | `.hwpx`   | Hancom Word XML | Modern XML-based HWP variant      |
/// | `.gul`    | Hangul Document | Old-style Korean word processing   |
/// | `.cel`    | CEL Template    | Hancom template format            |
#[on_metadata(impl_for = KoreaFssCompliancePlugin)]
fn classify_korean_format(filename: &str) -> &'static str {
    let filename_lower = filename.to_lowercase();

    if filename_lower.ends_with(".hwp") || filename_lower.ends_with(".hwpx") {
        "Document::KoreanHwp"
    } else if filename_lower.ends_with(".gul") || filename_lower.ends_with(".cel") {
        "Document::KoreanLegacy"
    } else if filename_lower.ends_with(".pdf") {
        "Document::Pdf"
    } else {
        "Unknown"
    }
}

// =============================================================================
// Hook: Raw Stream Content Scanning → CDRStrategy
// =============================================================================

/// Scan raw byte stream for Korean Resident Registration Number (RRN) patterns.
///
/// # RRN Format
///
/// The Korean RRN is a 13-digit number in `YYMMDD-GNNNNNN` format:
///
/// ```text
/// YY    - Birth year (2 digits)
/// MM    - Birth month (2 digits)
/// DD    - Birth day (2 digits)
/// G     - Gender/century digit (1-4: 1900s, 5-8: 2000s)
/// NNNNNN - Serial number + check digit
/// ```
///
/// Detection uses `\d{6}-?\d{7}` pattern with official check-digit validation.
#[on_file_stream(
    impl_for = KoreaFssCompliancePlugin,
    extensions = ["hwp", "hwpx", "gul", "cel", "pdf", "txt"]
)]
async fn scan_korean_rrn(chunk: &mut [u8]) -> Result<(), std::io::Error> {
    let data_str: &str = match std::str::from_utf8(chunk) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    let rrn_pattern =
        regex::Regex::new(r"\d{6}[-]?\d{7}").expect("RRN regex is valid");

    for mat in rrn_pattern.find_iter(data_str) {
        let candidate: String = mat.as_str().replace('-', "");
        if validate_rrn_check_digit(&candidate) {
            eprintln!(
                "[WARN] Korean RRN pattern detected in content stream: {}",
                mat.as_str()
            );
        }
    }

    Ok(())
}

// =============================================================================
// Hook: PII Content Scanning → PIIDetector
// =============================================================================

/// Scan content bytes for structured PII matches with action recommendations.
///
/// Returns typed [`PIIMatch`] entries for each detected sensitive pattern,
/// enabling downstream policy enforcement (block/alert/redact).
#[on_scan_content(impl_for = KoreaFssCompliancePlugin)]
async fn scan_pii_matches(content: &[u8]) -> Result<Vec<PIIMatch>, std::io::Error> {
    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return Ok(Vec::new()),
    };

    let rrn_pattern =
        regex::Regex::new(r"\d{6}[-]?\d{7}").expect("RRN regex is valid");
    let mut matches = Vec::new();

    for mat in rrn_pattern.find_iter(text) {
        let candidate: String = mat.as_str().replace('-', "");
        if validate_rrn_check_digit(&candidate) {
            matches.push(PIIMatch {
                pattern_name: "Korean_RRN".into(),
                matched_text: mat.as_str().to_string(),
                masked_text: mask_rrn(mat.as_str()),
                offset: mat.start(),
                length: mat.len(),
                pattern_regex: r"\d{6}[-]?\d{7}".into(),
            });
        }
    }

    Ok(matches)
}

// =============================================================================
// RRN Check Digit Validation
// =============================================================================

/// Validate the Korean RRN check digit using the official government algorithm.
///
/// ```text
/// sum     = Σ(digit[i] * weight[i])  for i in 0..12
/// weights = [2,3,4,5,6,7,8,9,2,3,4,5]
/// check   = (11 - (sum % 11)) % 10
/// ```
fn validate_rrn_check_digit(rrn: &str) -> bool {
    if rrn.len() != 13 {
        return false;
    }

    let digits: Vec<u32> = rrn
        .chars()
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 13 {
        return false;
    }

    let weights: [u32; 12] = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    let sum: u32 = digits[..12]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();

    let check = (11 - (sum % 11)) % 10;
    check == digits[12]
}

/// Mask a Korean RRN for safe logging: preserve first 6 and last 1 digit.
///
/// `900101-1234567` → `900101-******7`
fn mask_rrn(rrn: &str) -> String {
    if rrn.len() <= 7 {
        return "*".repeat(rrn.len());
    }
    format!("{}****{}", &rrn[..6], &rrn[rrn.len() - 1..])
}

// =============================================================================
// Entry Point — Plugin Verification
// =============================================================================

fn main() {
    use misogi_core::traits::PluginMetadata;

    let plugin = KoreaFssCompliancePlugin;

    println!("=== Korea FSS Compliance Plugin ===");
    println!("Name:           {}", plugin.name());
    println!("Version:        {}", plugin.version());
    println!("Description:    {:?}", plugin.description());
    println!("Interfaces:     {:?}", plugin.implemented_interfaces());

    assert_eq!(plugin.name(), "korea_fss_compliance");
    assert_eq!(plugin.version(), "1.0.0");

    let category = classify_korean_format("report.hwp");
    assert_eq!(category, "Document::KoreanHwp");
    println!("Classification: report.hwp → {}", category);

    let category_pdf = classify_korean_format("document.pdf");
    assert_eq!(category_pdf, "Document::Pdf");
    println!("Classification: document.pdf → {}", category_pdf);

    let unknown = classify_korean_format("data.xyz");
    assert_eq!(unknown, "Unknown");
    println!("Classification: data.xyz → {}", unknown);

    assert!(validate_rrn_check_digit("9001011234567"));
    assert!(!validate_rrn_check_digit("0000000000000"));
    println!("RRN validation:  OK");

    println!("\n[OK] All plugin verifications passed.");
}

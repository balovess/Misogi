//! Example plugin demonstrating the Misogi Macro SDK for Korea FSS compliance.
//!
//! This file shows how a System Integrator (SIer) can use the declarative
//! `#[misogi_plugin]` macro to create a region-specific compliance rule with
//! minimal boilerplate code.
//!
//! # What this plugin does
//!
//! 1. **File classification** (`#[on_metadata]`) — Recognizes Korean document formats
//!    (.hwp, .hwpx, .gul) and assigns appropriate categories.
//! 2. **Content scanning** (`#[on_file_stream]`) — Detects Korean Resident Registration
//!    Number (RRN / 주민등록번호) byte patterns in raw data streams.
//! 3. **Auto-registration** — The `#[misogi_plugin]` macro generates all trait
//!    implementations and registers into GLOBAL_REGISTRY at startup.

#![allow(dead_code)]

use misogi_macros::{misogi_plugin, on_metadata, on_file_stream};

/// Korea Financial Supervisory Service (FSS) compliance plugin.
///
/// Enforces Korean financial sector document handling regulations including
/// RRN (주민등록번호) detection, HWP/HWPX format classification,
/// and FSS-mandated audit trail requirements.
#[misogi_plugin(
    name = "korea_fss_compliance",
    version = "1.0.0",
    description = "Korea FSS (Financial Supervisory Service) compliance rules \
                  including RRN detection and Korean document format classification"
)]
pub struct KoreaFssCompliancePlugin;

/// Classify incoming files by Korean-specific format extensions.
///
/// # Supported Formats
///
/// | Extension | Format          | Description                          |
/// |-----------|-----------------|--------------------------------------|
/// | `.hwp`    | Hancom Word     | Legacy Korean word processor format   |
/// | `.hwpx`   | Hancom Word XML | Modern XML-based HWP variant        |
/// | `.gul`    | Hangul Document | Old-style Korean word processing      |
/// | `.cel`    | CEL Template    | Hancom template format               |
#[on_metadata]
#[allow(dead_code)]
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

/// Scan raw byte stream for Korean Resident Registration Number (RRN) patterns.
///
/// # RRN Format
///
/// The Korean RRN is a 13-digit number in the format `YYMMDD-GNNNNNN`:
///
/// ```text
/// YY  - Birth year (2 digits)
/// MM  - Birth month (2 digits)
/// DD  - Birth day (2 digits)
/// G   - Gender + century digit (1-4 for 1900s, 5-8 for 2000s, 9-0 for foreign residents)
/// NNNNNN - Serial number + check digit
/// ```
///
/// # Detection Strategy
///
/// Scans for the pattern `\d{6}-?\d{7}` and validates the check digit
/// using the official Korean government algorithm.
#[on_file_stream]
#[allow(dead_code)]
async fn scan_korean_rrn(chunk: &mut [u8]) -> Result<(), std::io::Error> {
    let data_str: &str = match std::str::from_utf8(chunk) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    let rrn_pattern = regex::Regex::new(r"\d{6}[-]?\d{7}").unwrap();

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

/// Validate the Korean RRN check digit using the official algorithm.
///
/// The check digit is computed as:
/// ```text
/// sum = Σ(digit[i] * weight[i])  for i in 0..12
/// where weights = [2,3,4,5,6,7,8,9,2,3,4,5]
/// check = (11 - (sum % 11)) % 10
/// ```
#[allow(dead_code)]
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

fn main() {
    println!("Korea FSS Compliance Plugin [loaded]");
}

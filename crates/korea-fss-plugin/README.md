# korea-fss-plugin

**Korea FSS (Financial Supervisory Service) Compliance Plugin for Misogi**

![Rust 2024](https://img.shields.io/badge/Rust-2024-orange) ![License](https://img.shields.io/badge/License-Apache--2.0-blue)

## Overview

This plugin demonstrates the production-grade Misogi Macro SDK by implementing a region-specific compliance rule with zero boilerplate trait implementations. It enforces Korean financial sector document handling regulations including RRN (Resident Registration Number) detection, HWP/HWPX format classification, and FSS-mandated audit trails.

## Capabilities

| Hook | Trait | Purpose |
|------|-------|---------|
| `#[on_metadata]` | `FileTypeDetector` | Korean document format classification |
| `#[on_file_stream]` | `CDRStrategy` | RRN (주민등록번호) pattern detection |
| `#[on_scan_content]` | `PIIDetector` | Structured PII match reporting |
| `#[misogi_plugin]` | `PluginMetadata` | Auto-registration + metadata |

## Supported Korean Document Formats

| Extension | Format | Description |
|-----------|--------|-------------|
| `.hwp` | Hancom Word | Legacy Korean word processor |
| `.hwpx` | Hancom Word XML | Modern XML-based HWP variant |
| `.gul` | Hangul Document | Old-style Korean word processing |
| `.cel` | CEL Template | Hancom template format |

## Korean RRN (Resident Registration Number)

The Korean RRN is a 13-digit number in `YYMMDD-GNNNNNN` format:

```
YY    - Birth year (2 digits)
MM    - Birth month (2 digits)
DD    - Birth day (2 digits)
G     - Gender/century digit (1-4: 1900s, 5-8: 2000s)
NNNNNN - Serial number + check digit
```

Detection uses `\d{6}-?\d{7}` pattern with official check-digit validation.

### Check Digit Algorithm

```
sum     = Σ(digit[i] * weight[i])  for i in 0..12
weights = [2,3,4,5,6,7,8,9,2,3,4,5]
check   = (11 - (sum % 11)) % 10
```

## Key Dependencies

- `misogi-macros`: Procedural macro SDK for trait code generation
- `misogi-core`: Core traits (`FileTypeDetector`, `CDRStrategy`, `PIIDetector`)
- `regex`: Pattern matching for RRN detection

## Quick Example

```rust
use korea_fss_plugin::KoreaFssCompliancePlugin;
use misogi_core::traits::PluginMetadata;

let plugin = KoreaFssCompliancePlugin;

// Plugin metadata
println!("Name: {}", plugin.name());        // "korea_fss_compliance"
println!("Version: {}", plugin.version());  // "1.0.0"

// File classification
let category = classify_korean_format("report.hwp");
assert_eq!(category, "Document::KoreanHwp");

// RRN validation
assert!(validate_rrn_check_digit("9001011234567"));
assert!(!validate_rrn_check_digit("0000000000000"));

// RRN masking for safe logging
let masked = mask_rrn("900101-1234567");
assert_eq!(masked, "900101-****7");
```

## PII Detection Output

When RRN patterns are detected, the plugin returns structured `PIIMatch` entries:

```rust
PIIMatch {
    pattern_name: "Korean_RRN",
    matched_text: "900101-1234567",
    masked_text: "900101-****7",
    offset: 42,
    length: 13,
    pattern_regex: r"\d{6}[-]?\d{7}",
}
```

## Integration with Misogi

This plugin is automatically registered with the Misogi plugin registry when the `korea-fss-plugin` crate is included in the workspace. The procedural macros generate all necessary trait implementations:

1. **`#[misogi_plugin]`** — Generates `PluginMetadata` trait implementation
2. **`#[on_metadata]`** — Generates `FileTypeDetector` trait implementation
3. **`#[on_file_stream]`** — Generates `CDRStrategy` trait implementation
4. **`#[on_scan_content]`** — Generates `PIIDetector` trait implementation

## Regulatory Compliance

This plugin assists with compliance to:

- **Korea Personal Information Protection Act (PIPA)**
- **Korea Financial Supervisory Service (FSS) guidelines**
- **Korea Data Protection Regulations**

## Full Documentation

For complete plugin development guide, macro SDK reference, and regulatory compliance details, see the [root README](../../README.md).

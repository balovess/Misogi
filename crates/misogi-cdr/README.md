# misogi-cdr

**Content Disarm and Reconstruction (CDR) Engine for Misogi**

Enterprise-grade CDR capabilities with security-first approach. Proactively removes malicious content while preserving document integrity and usability. Supports streaming-safe processing with bounded memory usage.

## Key Public API

- **`FileSanitizer` trait** — Core trait for format-specific sanitizers
- **`PdfSanitizer`**, **`DocxSanitizer`, etc.** — Format-specific implementations
- **`PpapDetector`** — PPAP (Password Protected Archive Protocol) detection
- **`PpapHandler`** — PPAP handling with configurable policies
- **`SanitizationPolicy` enum** — StripActiveContent, ConvertToFlat, TextOnly
- **`SanitizationReport` struct** — Detailed sanitization action report

## Key Dependencies

- `tokio`: Async runtime
- `serde`: Serialization
- `thiserror`: Error handling
- `nom`: Parser combinators
- `zip`: ZIP archive handling

## Supported Formats

PDF, DOCX, XLSX, PPTX, images (with re-encoding), JTD (Japanese word processor), and PPAP detection/handling.

## Quick Example

```rust
use misogi_cdr::{PdfSanitizer, SanitizationPolicy};

let sanitizer = PdfSanitizer::new();
let report = sanitizer.sanitize(
    Path::new("input.pdf"),
    Path::new("output.pdf"),
    &SanitizationPolicy::StripActiveContent,
).await?;
```

## Full Documentation

For complete file type support details, PPAP handling policies, security considerations, performance benchmarks, and architecture overview, see the [root README](../../README.md).

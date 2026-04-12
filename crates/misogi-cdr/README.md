# misogi-cdr

Content Disarm and Reconstruction (CDR) Engine for Misogi

## Overview

`misogi-cdr` provides enterprise-grade Content Disarm and Reconstruction capabilities for the Misogi file transfer system. It implements a security-first approach to file handling by proactively removing potentially malicious content while preserving the integrity and usability of the original document.

## Features

### Core CDR Capabilities

- **Streaming-Safe Processing**: Guaranteed bounded memory usage regardless of file size
- **Multi-Format Support**: Comprehensive coverage for common business document types
- **Policy-Driven Sanitization**: Configurable security policies for different threat levels
- **Detailed Audit Logging**: Complete trail of all sanitization actions for compliance

### Supported File Types

#### PDF Documents
- Strips JavaScript and active content
- Removes embedded files and attachments
- Sanitizes form fields and annotations
- Preserves document structure and readability

#### Microsoft Office Files
- **Word (.docx)**: Removes macros, active content, external data connections
- **Excel (.xlsx)**: Strips VBA macros, external links, dynamic formulas
- **PowerPoint (.pptx)**: Removes embedded scripts, activeX controls, media

#### Image Files
- Re-encoding to remove steganographic content
- Metadata stripping (EXIF, IPTC, XMP)
- Format validation and normalization

#### JTD Files (Justsystems Text Document)
- Japanese word processor format support
- Active content removal
- Structure preservation

### PPAP Detection and Handling

Implements comprehensive detection and handling of PPAP (Password Protected Archive Protocol) files:

#### Detection Capabilities
- **Encryption Detection**: Identifies encrypted ZIP entries
- **Heuristic Analysis**: Filename patterns (password, 暗号，etc.)
- **Confidence Scoring**: Quantified detection confidence levels
- **Method Identification**: Distinguishes between ZipCrypto, AES-256, etc.

#### Handling Policies

1. **Block**: Complete rejection with compliance event generation
2. **WarnAndSanitize**: Strip weak encryption, apply CDR, log warnings
3. **Quarantine**: Move to secure quarantine area for admin review
4. **ConvertToSecure**: Full PPAP replacement workflow with secure tunnel transfer

## Architecture

```
┌─────────────────┐
│  Input File     │
│  (Potentially   │
│   Malicious)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  File Type      │
│  Detector       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  PPAP Detector  │◄── Optional pre-scan
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Policy Engine  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Sanitizer      │
│  (Format-       │
│   Specific)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Output File    │
│  (Sanitized)    │
└─────────────────┘
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
misogi-cdr = { path = "../misogi-cdr" }
```

## Usage

### Basic Sanitization

```rust
use misogi_cdr::{FileSanitizer, PdfSanitizer, SanitizationPolicy};
use std::path::Path;

// Create sanitizer instance
let sanitizer = PdfSanitizer::new();

// Define sanitization policy
let policy = SanitizationPolicy::StripActiveContent;

// Sanitize file
let report = sanitizer
    .sanitize(
        Path::new("/input/suspicious.pdf"),
        Path::new("/output/safe.pdf"),
        &policy,
    )
    .await?;

// Review report
println!("Actions taken: {:?}", report.actions);
println!("Threats neutralized: {}", report.threats_detected);
```

### PPAP Detection and Handling

```rust
use misogi_cdr::{PpapDetector, PpapHandler, PpapPolicy};
use std::sync::Arc;

// Create detector
let detector = Arc::new(PpapDetector::new());

// Detect PPAP
let detection = detector.detect(Path::new("archive.zip")).await?;

if detection.is_ppap {
    // Create handler with policy
    let handler = PpapHandler::new(
        PpapPolicy::ConvertToSecure,
        detector,
    );
    
    // Handle according to policy
    let report = handler
        .handle(
            Path::new("archive.zip"),
            Path::new("/output/safe.zip"),
            &SanitizationPolicy::StripActiveContent,
        )
        .await?;
    
    println!("PPAP handled: {:?}", report.disposition);
}
```

### Policy Configuration

```rust
use misogi_cdr::SanitizationPolicy;

// Strip all active content (recommended for most cases)
let policy = SanitizationPolicy::StripActiveContent;

// Convert to flat format (maximum security)
let policy = SanitizationPolicy::ConvertToFlat;

// Extract text only (nuclear option)
let policy = SanitizationPolicy::TextOnly;
```

## Sanitization Policies

### StripActiveContent
**Security Level**: Medium-High  
**Use Case**: General business documents

Removes:
- JavaScript and scripting
- Embedded executables
- ActiveX controls
- Macros and VBA code
- External data connections

Preserves:
- Document formatting
- Images and graphics
- Text content
- Basic structure

### ConvertToFlat
**Security Level**: High  
**Use Case**: High-security environments

Converts document to flattened format:
- PDF/A for documents
- PNG/TIFF for images
- Removes all interactive elements
- Preserves visual appearance only

### TextOnly
**Security Level**: Maximum  
**Use Case**: Maximum security, threat intelligence

Extracts plain text only:
- Removes all formatting
- Removes all embedded content
- Returns raw text content
- Maximum threat removal

## API Reference

### FileSanitizer Trait

Core trait implemented by all format-specific sanitizers:

```rust
#[async_trait]
pub trait FileSanitizer: Send + Sync {
    fn supported_extensions(&self) -> &[&str];
    
    async fn sanitize(
        &self,
        input_path: &Path,
        output_path: &Path,
        policy: &SanitizationPolicy,
    ) -> Result<SanitizationReport>;
}
```

### SanitizationReport

Detailed report of sanitization actions:

```rust
pub struct SanitizationReport {
    pub input_file: String,
    pub output_file: String,
    pub actions: Vec<SanitizationAction>,
    pub threats_detected: usize,
    pub processing_time_ms: u64,
    pub success: bool,
}
```

### PpapDetectionResult

PPAP detection results:

```rust
pub struct PpapDetectionResult {
    pub is_ppap: bool,
    pub confidence: f64,
    pub indicators: Vec<String>,
    pub encryption_method: Option<String>,
}
```

## Security Considerations

### Memory Safety

All CDR operations are designed with streaming architecture:
- **No full file loading**: Files are processed in chunks
- **Bounded memory**: Memory usage independent of file size
- **DoS protection**: Prevents memory exhaustion attacks

### Threat Model

CDR protects against:
- **Embedded malware**: Executables, scripts, macros
- **Exploit code**: Buffer overflow payloads, ROP chains
- **Data exfiltration**: Hidden data channels, steganography
- **Social engineering**: Deceptive content, phishing elements

### Limitations

CDR is not a silver bullet:
- **Zero-day exploits**: Unknown attack vectors may persist
- **Content-level attacks**: Legitimate-looking malicious content
- **OCR evasion**: Text embedded in images
- **Logical vulnerabilities**: Business logic attacks

Complementary security measures recommended:
- Antivirus scanning
- Sandboxing
- User training
- Access controls

## Performance

### Benchmarks

Typical processing times (M.2 NVMe SSD, Intel i7):

| File Type | Size | Processing Time |
|-----------|------|-----------------|
| PDF | 1 MB | ~50-100 ms |
| DOCX | 500 KB | ~30-60 ms |
| XLSX | 1 MB | ~40-80 ms |
| PPTX | 5 MB | ~200-400 ms |
| ZIP | 10 MB | ~100-200 ms |

### Optimization Tips

1. **Use appropriate policy**: StripActiveContent is fastest
2. **Batch processing**: Process multiple files in parallel
3. **Async I/O**: Leverage Tokio's async runtime
4. **Memory mapping**: Use for very large files

## Error Handling

Comprehensive error types via `thiserror`:

```rust
pub enum CdrError {
    #[error("Unsupported file format: {0}")]
    UnsupportedFormat(String),
    
    #[error("File corrupted or unreadable: {0}")]
    CorruptedFile(String),
    
    #[error("Sanitization failed: {0}")]
    SanitizationFailed(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("PPAP detection error: {0}")]
    PpapDetection(String),
}
```

## Testing

Run the test suite:

```bash
cargo test -p misogi-cdr
```

### Test Coverage

- Unit tests for each sanitizer
- Integration tests for full pipeline
- PPAP detection accuracy tests
- Performance regression tests
- Fuzzing tests for robustness

## Dependencies

- `tokio`: Async runtime
- `serde`: Serialization
- `thiserror`: Error handling
- `nom`: Parser combinators
- `zip`: ZIP archive handling
- `md-5`: Hash verification
- `regex`: Pattern matching
- `tempfile`: Temporary file handling

## Contributing

Contributions welcome! Please note:
- All code must compile with Rust 2024 Edition
- Comprehensive documentation required
- Tests mandatory for new features
- Security review for CDR logic changes

## License

Licensed under Apache 2.0 License. See [LICENSE](../../LICENSE) for details.

---

**Security Notice**: CDR is a security control, not a complete security solution. Deploy as part of a defense-in-depth strategy.

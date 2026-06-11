# CDR v2 Configuration Guide

## Overview

The CDR (Content Disarm and Reconstruction) v2 Engine provides secure file processing by removing potentially malicious content while preserving the functional parts of files. This follows the CDR approach recommended by security frameworks like NIST.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Input     │────▶│   Detect    │────▶│   Process   │────▶│  Reconstruct│
│   File      │     │   Type      │     │   Content   │     │   Output    │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

---

## Configuration Structure

### CdrV2Config

| Field | Type | Description |
|-------|------|-------------|
| `pdf` | `PdfConfig` | PDF processing options |
| `office` | `OfficeConfig` | Office document options |
| `archive` | `ArchiveConfig` | Archive handling options |
| `whitelist` | `WhitelistConfig` | Allowed file types |

---

## PDF Configuration

### PdfConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_javascript_removal` | `bool` | `true` | Remove embedded JavaScript |
| `enable_embedded_file_extraction` | `bool` | `true` | Extract and sanitize embedded files |
| `enable_metadata_sanitization` | `bool` | `true` | Remove sensitive metadata |

### TOML Example

```toml
[cdr_v2.pdf]
enable_javascript_removal = true
enable_embedded_file_extraction = true
enable_metadata_sanitization = true
```

### Processing Details

**JavaScript Removal**:
- Removes all JavaScript actions from PDF
- Eliminates `OpenAction`, `AA` (Additional Actions)
- Removes form field JavaScript

**Embedded File Extraction**:
- Extracts all file attachments
- Processes each embedded file through CDR
- Re-embeds sanitized versions

**Metadata Sanitization**:
- Removes author, creator, producer info
- Clears custom metadata fields
- Preserves structural metadata (page count, dimensions)

---

## Office Configuration

### OfficeConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_macro_removal` | `bool` | `true` | Remove VBA macros |
| `enable_ole_sanitization` | `bool` | `true` | Sanitize OLE objects |
| `enable_external_link_removal` | `bool` | `true` | Remove external links |

### TOML Example

```toml
[cdr_v2.office]
enable_macro_removal = true
enable_ole_sanitization = true
enable_external_link_removal = true
```

### Supported Formats

| Format | Extension | Processing |
|--------|-----------|------------|
| Word | `.doc`, `.docx` | Full processing |
| Excel | `.xls`, `.xlsx` | Full processing |
| PowerPoint | `.ppt`, `.pptx` | Full processing |
| Legacy | `.doc`, `.xls`, `.ppt` | OLE-based processing |

### Processing Details

**Macro Removal**:
- Removes all VBA modules
- Clears macro-related streams
- Preserves document content

**OLE Sanitization**:
- Removes embedded OLE objects
- Sanitizes linked objects
- Clears ActiveX controls

**External Link Removal**:
- Removes hyperlinks to external URLs
- Clears DDE connections
- Removes external data connections

---

## Archive Configuration

### ArchiveConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_extraction_depth` | `u32` | `5` | Maximum nested archive depth |
| `max_file_count` | `u32` | `1000` | Maximum files per archive |
| `enable_bomb_detection` | `bool` | `true` | Detect zip bombs |

### TOML Example

```toml
[cdr_v2.archive]
max_extraction_depth = 5
max_file_count = 1000
enable_bomb_detection = true
```

### Supported Formats

| Format | Extension | Notes |
|--------|-----------|-------|
| ZIP | `.zip` | Standard processing |
| RAR | `.rar` | Limited support |
| 7-Zip | `.7z` | Full support |
| TAR | `.tar`, `.tar.gz` | Unix archives |
| CAB | `.cab` | Windows cabinets |

### Bomb Detection

The engine detects potential zip bombs by checking:

1. **Compression Ratio**: Reject if ratio > 100:1
2. **Nested Depth**: Reject if depth > `max_extraction_depth`
3. **File Count**: Reject if count > `max_file_count`

```
┌─────────────┐
│   Archive   │
│   Input     │
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌─────────────┐
│   Check     │────▶│   Ratio     │──▶ Reject if > 100:1
│   Ratio     │     │   OK?       │
└─────────────┘     └─────────────┘
       │ Yes
       ▼
┌─────────────┐     ┌─────────────┐
│   Check     │────▶│   Depth     │──▶ Reject if > max
│   Depth     │     │   OK?       │
└─────────────┘     └─────────────┘
       │ Yes
       ▼
┌─────────────┐
│   Extract   │
│   & Process │
└─────────────┘
```

---

## Whitelist Configuration

### WhitelistConfig

| Field | Type | Description |
|-------|------|-------------|
| `allowed_extensions` | `Vec<String>` | Allowed file extensions |
| `allowed_mime_types` | `Vec<String>` | Allowed MIME types |
| `file_hashes` | `Vec<WhitelistEntry>` | Trusted file hashes (SHA-256) |
| `sources` | `Vec<WhitelistEntry>` | Trusted source domains |
| `signatures` | `Vec<WhitelistEntry>` | Trusted code signatures |

### WhitelistEntry

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | `String` | - | Unique identifier |
| `match_type` | `String` | - | Pattern type: "hash", "source", "signature" |
| `pattern` | `String` | - | Pattern value to match |
| `description` | `String` | - | Human-readable justification |
| `enabled` | `bool` | `true` | Whether entry is active |
| `expires_at` | `Option<String>` | `None` | ISO8601 expiration timestamp |

### Expiration Handling

Whitelist entries support automatic expiration via the `expires_at` field:

```toml
[[cdr_v2.whitelist.file_hashes]]
id = "trusted-vendor-cert"
match_type = "hash"
pattern = "sha256:abc123..."
description = "Trusted vendor certificate"
enabled = true
expires_at = "2025-12-31T23:59:59Z"  # ISO8601 format
```

**Expiration Behavior**:
- Entries without `expires_at` never expire
- Expired entries are automatically excluded from whitelist checks
- Invalid timestamp formats are treated as expired (fail-safe)

### TOML Example

```toml
[cdr_v2.whitelist]
allowed_extensions = [
    ".pdf",
    ".doc", ".docx",
    ".xls", ".xlsx",
    ".ppt", ".pptx",
    ".txt", ".csv",
    ".jpg", ".png"
]

allowed_mime_types = [
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/plain",
    "image/jpeg",
    "image/png"
]

# Trusted file hashes with expiration
[[cdr_v2.whitelist.file_hashes]]
id = "internal-form-v1"
match_type = "hash"
pattern = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
description = "Internal HR form template"
expires_at = "2025-06-30T00:00:00Z"

# Trusted source domains
[[cdr_v2.whitelist.sources]]
id = "partner-domain"
match_type = "source"
pattern = "*.trusted-partner.com"
description = "Files from trusted partner domain"
```

### Whitelist Behavior

| Scenario | Action |
|----------|--------|
| Extension matches, MIME matches | Process file |
| Extension matches, MIME mismatch | Reject (potential spoofing) |
| Extension not in list | Reject |
| MIME not in list | Reject |

---

## Complete TOML Configuration

```toml
[cdr_v2]
# PDF processing
[cdr_v2.pdf]
enable_javascript_removal = true
enable_embedded_file_extraction = true
enable_metadata_sanitization = true

# Office document processing
[cdr_v2.office]
enable_macro_removal = true
enable_ole_sanitization = true
enable_external_link_removal = true

# Archive processing
[cdr_v2.archive]
max_extraction_depth = 5
max_file_count = 1000
enable_bomb_detection = true

# Whitelist
[cdr_v2.whitelist]
allowed_extensions = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv"]
allowed_mime_types = [
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/plain"
]
```

---

## Pipeline Stages

### Execution Mode

The pipeline supports two execution modes controlled by `execution_mode`:

| Mode | Description | Use Case |
|------|-------------|----------|
| `Sequential` | Stages run one after another | Default, safe, deterministic |
| `Parallel` | Independent stages run concurrently | Performance optimization |

```toml
[cdr_v2.policy]
# Sequential mode (default)
execution_mode = "Sequential"

# Parallel mode with max 4 concurrent stages
execution_mode = { Parallel = { max_concurrency = 4 } }
```

### Output Integrity

Each processed document generates a SHA-256 hash stored in the `CdrReport`:

```rust
pub struct CdrReport {
    pub success: bool,
    pub stages_executed: Vec<SanitizationReport>,
    pub total_active_contents_found: u32,
    pub total_actions_taken: u32,
    pub output_hash: Option<String>,  // SHA-256 of sanitized AST
}
```

**Hash Computation**:
- Deterministic serialization of AST structure
- Includes document format, metadata, active contents
- Sorted by path for consistent ordering
- Enables audit integrity verification

### AST Copy-on-Write

The `AstHandle` wrapper provides zero-copy read access with CoW semantics:

```rust
// Read without cloning
let ast_ref = handle.read();

// Write triggers clone only if shared
let mut ast_mut = handle.write();
```

**Performance Benefits**:
- Read-only stages: O(1) with no allocation
- Write stages: O(n) clone only when shared
- Reduces memory pressure for large documents

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CDR v2 Processing Pipeline                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Stage 1: File Type Detection                                               │
│  ┌─────────────┐                                                            │
│  │   Input     │──▶ Magic bytes check ──▶ MIME detection ──▶ Extension check│
│  │   File      │                                                            │
│  └─────────────┘                                                            │
│                                      │                                       │
│                                      ▼                                       │
│  Stage 2: Whitelist Validation                                              │
│  ┌─────────────┐                                                            │
│  │  Validate   │──▶ Extension in list? ──▶ MIME in list? ──▶ Continue       │
│  │  Whitelist  │                                                            │
│  └─────────────┘                                                            │
│                                      │                                       │
│                                      ▼                                       │
│  Stage 3: Format-Specific Processing                                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                         │
│  │    PDF      │  │   Office    │  │   Archive   │                         │
│  │  Handler    │  │   Handler   │  │   Handler   │                         │
│  └─────────────┘  └─────────────┘  └─────────────┘                         │
│                                      │                                       │
│                                      ▼                                       │
│  Stage 4: Content Reconstruction                                            │
│  ┌─────────────┐                                                            │
│  │ Reconstruct │──▶ Build sanitized file ──▶ Preserve structure             │
│  │   Output    │                                                            │
│  └─────────────┘                                                            │
│                                      │                                       │
│                                      ▼                                       │
│  Stage 5: Integrity Verification                                            │
│  ┌─────────────┐                                                            │
│  │   Verify    │──▶ Check output validity ──▶ Generate SHA-256 hash         │
│  │  Output     │                                                            │
│  └─────────────┘                                                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Best Practices

### Security

- Enable all sanitization options by default
- Use restrictive whitelists
- Set `max_extraction_depth <= 5`
- Enable bomb detection

### Performance

- Process files in parallel when possible
- Cache file type detection results
- Use streaming for large files

### Compliance

- Log all CDR operations
- Maintain audit trail of removed content
- Document whitelist decisions

---

## Related Documentation

- [architecture-overview.md](architecture-overview.md) - System architecture
- [integrity-config.md](integrity-config.md) - Integrity verification
- [abac-config.md](abac-config.md) - Access control

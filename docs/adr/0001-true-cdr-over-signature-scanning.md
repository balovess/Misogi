# ADR-0001: True CDR over Signature-Based Scanning

## Status

Accepted

## Context

Misogi must protect against malicious content in transferred files. Two fundamental approaches exist:

1. **Signature-Based Scanning**: Match known threat patterns (AV-style)
2. **True CDR (Content Disarm and Reconstruction)**: Parse, analyze, rebuild from safe components only

### Problem

Signature-based scanning has critical limitations:
- **Zero-day vulnerability**: Cannot detect unknown threats
- **Reactive nature**: Requires signature updates after new threats emerge
- **False negatives**: Sophisticated polymorphic malware evades detection
- **Compliance gap**: Japanese government guidelines (デジタル庁標準) require proactive threat elimination

### Decision Drivers

| Driver | Signature-Based | True CDR |
|--------|-----------------|----------|
| Zero-day protection | ❌ None | ✅ Proactive |
| Update dependency | ❌ Continuous | ✅ None |
| False negative rate | ⚠️ Variable | ✅ Near-zero |
| Processing overhead | ✅ Lower | ⚠️ Higher |
| Compliance (LGWAN) | ❌ Insufficient | ✅ Compliant |

## Decision

**We adopt True CDR as the core threat elimination strategy.**

Every file is parsed into its structural components, analyzed for active content, and rebuilt using only safe components. No signature matching is performed.

### Implementation

```
Raw File → Parse → Analyze → Extract Safe Components → Rebuild → Sanitized Artifact
           │         │              │                    │
           │         │              │                    └── New structure, no threats
           │         │              └── Only passive content preserved
           │         └── Identify active content (JS, macros, embedded files)
           └── Format-specific parser (PDF, OOXML, ZIP, SVG)
```

### Supported Formats

| Format | Parser | Threat Model |
|--------|--------|--------------|
| PDF | `PdfStreamParser` | JavaScript, AA dicts, AcroForms, OpenAction, EmbeddedFiles, RichMedia |
| DOCX/XLSX/PPTX | `OoxmlStreamParser` | VBA macros, ActiveX, embedded objects, external links |
| ZIP | `ZipSanitizer` | Nested bombs, path traversal, encrypted entries (PPAP) |
| SVG | `SvgSanitizer` | Script elements, event handlers, foreignObject |
| Images | `ImageMetadataSanitizer` | EXIF/GPS metadata, ICC profiles (steganography detected) |
| JTD | `JtdSanitizer` | Japanese word processor macros, embedded objects |

## Consequences

### Positive

- **Zero-day immunity**: Unknown threats are eliminated by design
- **No signature updates**: System never becomes outdated
- **Compliance**: Meets Japanese government CDR requirements (デジタル庁標準ガイドライン)
- **Audit trail**: Every action recorded in `SanitizationReport`
- **Memory safety**: Rust 2024 guarantees eliminate implementation vulnerabilities

### Negative

- **Processing overhead**: Parsing + rebuilding is slower than signature matching
- **Format coverage**: Only supported formats can be processed
- **False positives**: Some legitimate active content (forms, calculations) is removed

### Mitigations

- **Performance**: Streaming parsers with bounded memory; chunked processing
- **Coverage**: Extensible parser registry; community contributions welcome
- **False positives**: Configurable `SanitizationPolicy` (StripActiveContent / ConvertToFlat / TextOnly)

## Alternatives Considered

### Alternative 1: Signature-Based Only

Rejected. Cannot protect against zero-day threats. Fails LGWAN compliance requirements.

### Alternative 2: Hybrid (Signature + CDR)

Considered but rejected:
- Adds complexity without significant benefit
- Signature scanning provides false sense of security
- True CDR already eliminates known and unknown threats

### Alternative 3: External CDR Service

Rejected:
- Introduces network dependency
- Latency unacceptable for real-time transfers
- Data leaves organizational boundary

## References

- ISO 32000 (PDF specification)
- ECMA-376 (OOXML specification)
- APPNOTE (ZIP specification)
- W3C SVG specification
- デジタル庁標準ガイドライン (Japanese Digital Agency Standard Guidelines)

---

## History

| Date | Change |
|------|--------|
| 2026-06-08 | Initial ADR creation |

[English](README.md) | [日本語](README_ja.md)

# Misogi (禊ぎ)

**High-performance secure file transfer with built-in CDR sanitization**

![Rust 2024](https://img.shields.io/badge/Rust-2024-orange) ![Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue) ![WASM Edge](https://img.shields.io/badge/WASM-Edge-green)

## Value Proposition

Misogi is a secure file transfer platform that combines **Content Disarm and Reconstruction (CDR)** sanitization with high-performance gRPC-based file transfer. Built entirely in **Rust 2024 Edition**, it eliminates entire classes of memory-safety vulnerabilities at compile time — no garbage collector, no runtime bounds checks, no buffer overflows. Every file passing through Misogi is parsed, analyzed for threats, and rebuilt from safe components only (True CDR), ensuring that malicious payloads cannot survive the sanitization pipeline regardless of unknown zero-day exploits.

## Core Features

- **CDR Engine**: PDF True CDR (`PdfStreamParser`), OOXML True CDR for Word/Excel/PPT (`OoxmlStreamParser`), ZIP recursive nested scanning (`ZipSanitizer`), SVG script-element removal (`SvgSanitizer`), image EXIF/GPS metadata stripping (`ImageMetadataSanitizer`), steganography detection, and JTD Japanese word processor format support (`JtdSanitizer`)
- **WASM Edge**: Browser-side CDR via WebAssembly — sub-200ms latency, zero server dependency, files never leave the client
- **Authentication**: JWT RS256 (asymmetric keys only — HS256 symmetric rejected), LDAP/Active Directory, OIDC, SAML 2.0, RBAC with 9 granular permission actions
- **Transfer Protocol**: gRPC chunked streaming with resume support, Forward Error Correction (FEC), and multiple driver types: `direct_tcp`, `storage_relay`, `blind_send`, `pull`, `external_command`
- **Audit Trail**: Immutable JSON/Syslog/CEF logs with SHA-256 event hashing and configurable retention policies
- **PII Detection**: Configurable rules engine for automatic identification of sensitive/personal data in transferred files

## Architecture

```
> Clean Room Design: All CDR algorithms are developed from publicly available
> specifications only — ISO 32000 (PDF), APPNOTE (.ZIP), ECMA-376 (OOXML),
> W3C (SVG), and Rust/nom documentation.
> No reverse engineering of any third-party product has been performed.

                         Misogi Architecture
  ┌──────────────────────────────────────────────────────────────┐
  │                                                              │
  │   ┌─────────────┐         gRPC / TLS          ┌────────────┐ │
  │   │    Sender    │ ◄═════════════════════════► │  Receiver  │ │
  │   │             │   Chunked Streaming + FEC   │            │ │
  │   └──────┬──────┘                              └─────┬──────┘ │
  │          │                                           │        │
  │          ▼                                           ▼        │
  │   ┌──────────────┐                           ┌────────────┐  │
  │   │  CDR Engine   │◄── Sanitize All Files ──►│  CDR Engine │  │
  │   │              │                            │            │  │
  │   │ · PDF TrueCDR│                            │ · PDF True │  │
  │   │ · OOXML True │                            │ · OOXML    │  │
  │   │ · ZIP Recurse│                            │ · ZIP      │  │
  │   │ · SVG Strip  │                            │ · SVG      │  │
  │   │ · Image Meta │                            │ · Image    │  │
  │   │ · SteganoDet │                            │ · Stegano  │  │
  │   │ · JTD Support│                            │ · JTD      │  │
  │   └──────────────┘                            └────────────┘  │
  │          │                                           │        │
  │          ▼                                           ▼        │
  │   ┌──────────────┐   ┌──────────────┐   ┌─────────────────┐  │
  │   │ Auth Service │   │ Audit Logger  │   │ PII Detector    │  │
  │   │              │   │              │   │                 │  │
  │   │ JWT RS256    │   │ Immutable     │   │ Rule Engine     │  │
  │   │ LDAP / AD    │   │ JSON/Syslog   │   │ Configurable    │  │
  │   │ OIDC / SAML  │   │ SHA-256 Hash  │   │ Pattern Match   │  │
  │   │ RBAC (9 acts)│   │ CEF Format    │   │ Auto-flagging   │  │
  │   └──────────────┘   └──────────────┘   └─────────────────┘  │
  │                                                              │
  └──────────────────────────────────────────────────────────────┘

  WASM Edge (Browser Embed):
  ┌──────────────────────────────────────────┐
  │  Browser (Zero Server Dependency)        │
  │  [File Input] → [WASM Module] → [Clean]  │
  │  sanitize_pdf() · sanitize_office()       │
  │  scan_pii() · detect_file_type()          │
  └──────────────────────────────────────────┘
```

## Quick Start

### Docker Compose (Primary)

```bash
git clone https://github.com/balovess/Misogi.git && cd Misogi
docker compose up -d --build
curl http://localhost:3001/api/v1/health
```

### Source Build (Alternative)

```bash
git clone https://github.com/balovess/Misogi.git && cd Misogi
cargo build --release --bins
# Generate RSA keypair (first time only):
cargo run --package misogi-auth --example generate-keys -- ./keys
./target/release/misogi-sender --config config.toml &
./target/release/misogi-receiver --config config.toml &
```

## Supported Formats

| Format | Parser | Sanitization Approach |
|--------|--------|----------------------|
| PDF | `PdfStreamParser` | True CDR: parse → analyze → extract → rebuild into clean container |
| DOCX/XLSX/PPTX | `OoxmlStreamParser` | True CDR per format with Word/Excel/PPT-specific threat models |
| ZIP | `ZipSanitizer` | Recursive nested archive scanning with bomb detection |
| SVG | `SvgSanitizer` | Script element, event handler, and foreignObject removal |
| Images (JPEG/PNG/TIFF) | `ImageMetadataSanitizer` | EXIF/GPS/ICC metadata stripping; pixel-integrity preserved |
| JTD | `JtdSanitizer` | Japanese word processor format conversion to safe OOXML |

## Deployment Options

| Environment | Method | Use Case |
|------------|--------|----------|
| Docker | Docker Compose | Development, staging, and evaluation |
| Kubernetes | Helm Chart | Production / cloud-native / auto-scaling |
| WASM Edge | Browser embed | Client-side CDR, offline-capable, zero server trust |
| Bare Metal | `cargo build --release` | On-premises / air-gapped environments |

## Security Highlights

| Feature | Implementation |
|---------|---------------|
| Memory Safety | Rust 2024 Edition — compile-time guarantees, no GC, no UB |
| Transport Encryption | TLS 1.2+ with configurable cipher suites |
| Authentication | JWT RS256 asymmetric + multi-IdP (LDAP/OIDC/SAML) |
| Authorization | Role-Based Access Control with 9 granular actions |
| Audit Trail | Write-only immutable logs (JSON/Syslog/CEF) with SHA-256 event hashing |
| Input Validation | All files sanitized through True CDR pipeline before storage |
| Clean Room Design | Algorithms from public specs only — ISO 32000, APPNOTE, ECMA-376, W3C |

## CVE Comparison

| Product | Language | Memory Safety | Historical CVEs |
|---------|----------|---------------|-----------------|
| **Misogi** | **Rust** | ✅ Compile-time guarantees | **0** |
| Typical CDR (C/C++) | C/C++ | ❌ Runtime-dependent | 10+ (buffer overflow, UAF, heap corruption) |
| Typical CDR (Managed) | C#/Java | ⚠️ GC-dependent | 3+ (deserialization, injection) |

> Misogi's Rust foundation eliminates memory-correction vulnerability classes entirely. No buffer overflows. No use-after-free. No double-free. No integer overflow on allocations.

## SDK & Integrations

Misogi provides SDKs and examples for major platforms:

| Platform | Technology | Location |
|----------|-----------|----------|
| Java | Spring Boot 3.x + gRPC-Java | [`examples/java-spring-boot/`](examples/java-spring-boot/) |
| Python | asyncio + grpcio | [`examples/python-client/`](examples/python-client/) |
| Web Frontend | React + TypeScript + gRPC-Web | [`examples/web-react/`](examples/web-react/) |
| Browser WASM | wasm-pack + wasm32 | [`examples/wasm-browser/`](examples/wasm-browser/) |
| Native gRPC | Tonic / Protobuf | [`crates/misogi-core/proto/`](crates/misogi-core/proto/) |

Proto stubs are generated via Buf toolchain from [`proto-dist/`](proto-dist/):

```bash
cd proto-dist
buf generate    # Generate all language stubs
buf lint        # Lint proto definitions
buf breaking --against '.git/#branch=main'  # Backward-compat check
```

## Regional Documentation

```
Region-Specific Documentation
  Japan (SIer/Government):   README_ja.md -> docs/ja/
  EU (GDPR/NIS2):            docs/eu/gdpr-nis2-compliance.md
  US (FedRAMP/CMMC):         docs/us/fedramp-cmmc-compliance.md
  SEA (PDPA/Bank Indonesia): docs/sea/pdpa-bi-compliance.md
```

## Project Structure

```
Misogi/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── misogi-core/            # Core library: protocol, types, hash, error
│   ├── misogi-sender/          # Sender node: upload, gRPC stream, file monitor
│   ├── misogi-receiver/        # Receiver node: download, reassemble, storage
│   ├── misogi-auth/            # Auth: JWT RS256, LDAP/OIDC/SAML, RBAC
│   ├── misogi-audit/           # Audit: immutable logs, SHA-256, CEF/Syslog
│   ├── misogi-cdr/             # CDR engine: PDF, OOXML, ZIP, SVG, Image, JTD
│   ├── misogi-wasm/            # WASM Edge: browser-side sanitization
│   └── misogi-smtp/            # SMTP notification service
├── proto-dist/                 # Protobuf definitions & generated stubs
├── docker/                     # Docker Compose configurations
├── helm/                       # Kubernetes Helm charts
├── examples/                   # SDK examples (Java, Python, React, WASM)
└── docs/                       # Regional & compliance documentation
```

## Contributing

Contributions are welcome! Please follow this workflow:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add some amazing-feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

**Requirements:**
- All code must compile under **Rust 2024 Edition**
- `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` must pass cleanly
- Follow existing code conventions and document public APIs

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

See also [PATENTS](PATENTS) for patent grant information.

---

## Disclaimer

This software is provided **"AS IS"** without warranty of any kind, express or implied. The authors assume **NO LIABILITY** for damages including but not limited to: data breaches, information leakage, business interruption, financial loss, or security incidents resulting from misconfiguration or unknown vulnerabilities (including zero-day exploits).

**This software does NOT guarantee 100% detection of all malicious content.** Before deploying in production environments — especially government systems, financial institutions, or critical infrastructure — you **MUST** conduct thorough internal security assessments and compliance reviews at your own responsibility.

Copyright 2026 Misogi Contributors

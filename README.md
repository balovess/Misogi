[English](README.md) | [日本語](README_ja.md)

# Misogi (禊ぎ)

**High-performance secure file transfer with built-in CDR sanitization**

![Rust 2024](https://img.shields.io/badge/Rust-2024-orange) ![Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue) ![WASM Edge](https://img.shields.io/badge/WASM-Edge-green)

## Value Proposition

Misogi is a secure file transfer platform that combines **Content Disarm and Reconstruction (CDR)** sanitization with high-performance gRPC-based file transfer. Built entirely in **Rust 2024 Edition**, it eliminates entire classes of memory-safety vulnerabilities at compile time — no garbage collector, no runtime bounds checks, no buffer overflows. Every file passing through Misogi is parsed, analyzed for threats, and rebuilt from safe components only (True CDR), ensuring that malicious payloads cannot survive the sanitization pipeline regardless of unknown zero-day exploits.

## Core Features

- **CDR Engine**: PDF True CDR (`PdfStreamParser`), OOXML True CDR for Word/Excel/PPT (`OoxmlStreamParser`), ZIP recursive nested scanning (`ZipSanitizer`), SVG script-element removal (`SvgSanitizer`), image EXIF/GPS metadata stripping (`ImageMetadataSanitizer`), steganography detection, and JTD Japanese word processor format support (`JtdSanitizer`)
- **CDR v2 Engine**: Enhanced pipeline with PDF/Office/Archive processing, whitelist enforcement, and bomb detection
- **WASM Edge**: Browser-side CDR via WebAssembly — sub-200ms latency, zero server dependency, files never leave the client
- **Authentication**: JWT RS256 (asymmetric keys only — HS256 symmetric rejected), LDAP/Active Directory, OIDC, SAML 2.0, RBAC with 9 granular permission actions
- **ABAC Engine**: Attribute-Based Access Control following NIST SP 800-162 with policy rules, approval workflows, and hot reload
- **Transfer Protocol**: gRPC chunked streaming with resume support, Forward Error Correction (FEC), and multiple driver types: `direct_tcp`, `storage_relay`, `blind_send`, `pull`, `external_command`
- **Relay Mesh**: Multi-tier relay for secure file transfer across network boundaries with circuit breaker and heartbeat monitoring
- **Integrity Layer**: Self-healing integrity verification with automatic repair, session management, and multi-algorithm checksums (BLAKE3, SHA-256, SHA-512)
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
 ┌──────────────────────────────────────────────────────────────┐
 │  Browser (Zero Server Dependency)                            │
 │  [File Input] → [WASM Module 271KB] → [Clean Output]        │
 │  sanitize_pdf() · sanitize_office()                          │
 │  scan_pii() · detect_file_type()                             │
 │                                                              │
 │  Performance: ~200 MiB/s PDF analyze | ~75 KB gzip           │
 │  Tested: Chrome / Firefox / Safari / Edge (Playwright)      │
 │  CI: .github/workflows/wasm-ci.yml                           │
 └──────────────────────────────────────────────────────────────┘
```

## Quick Start

### One-Command Setup (Recommended)

**Linux/macOS:**
```bash
git clone https://github.com/balovess/Misogi.git && cd Misogi
./scripts/quickstart.sh
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/balovess/Misogi.git; cd Misogi
.\scripts\quickstart.ps1
```

The quickstart script will:
1. Check all dependencies (Docker, OpenSSL, etc.)
2. Create default configuration files
3. Generate RSA keypair for authentication
4. Start services with Docker Compose
5. Verify service health

### Docker Compose (Manual)

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
./target/release/misogi-sender --config config/misogi.toml.default &
./target/release/misogi-receiver --config config/misogi.toml.default &
```

### Interactive Configuration

For guided setup with compliance presets:

```bash
# Run configuration wizard
misogi-sender --init

# Check system dependencies
misogi-sender --check-deps

# List available presets
misogi-sender --list-presets

# Validate configuration
misogi-sender --validate-config misogi.toml
```

### Available Presets

| Preset | Description | Use Case |
|--------|-------------|----------|
| `minimal` | Minimum configuration | Development, testing |
| `lgwan` | LGWAN government compliance | Japanese local government |
| `medical` | HIPAA-Japan aligned | Healthcare providers |
| `enterprise` | Balanced security | General enterprise |

Use presets with:
```bash
./scripts/quickstart.sh --preset lgwan
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

## Technical Documentation

| Document | Description |
|----------|-------------|
| [architecture-overview.md](docs/architecture-overview.md) | System architecture overview |
| [relay-mesh-config.md](docs/relay-mesh-config.md) | Multi-tier relay mesh configuration |
| [cdr-v2-config.md](docs/cdr-v2-config.md) | CDR v2 engine configuration |
| [integrity-config.md](docs/integrity-config.md) | Self-healing integrity layer configuration |
| [abac-config.md](docs/abac-config.md) | ABAC engine configuration |
| [enterprise-deployment.md](docs/enterprise-deployment.md) | Enterprise deployment guide |

## Project Structure

```
Misogi/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── misogi-core/            # Core library: protocol, types, hash, error, audit log
│   ├── misogi-cdr/             # CDR engine: PDF, OOXML, ZIP, SVG, Image, JTD
│   ├── misogi-auth/            # Auth: JWT RS256, LDAP/OIDC/SAML, RBAC
│   ├── misogi-macros/          # Procedural macros: plugin trait code generation
│   ├── misogi-sender/          # Sender node: upload, gRPC stream, file monitor
│   ├── misogi-receiver/        # Receiver node: download, reassemble, storage
│   ├── misogi-wasm/            # WASM Edge: browser-side sanitization
│   ├── misogi-smtp/            # SMTP notification service
│   ├── misogi-rest-api/        # RESTful admin API for system management
│   ├── misogi-nocode/          # No-code integration: YAML declarative configuration
│   ├── misogi-bootstrap/       # Application bootstrap: config loading, service init
│   ├── misogi-config/          # Configuration management: TOML parsing, validation
│   ├── misogi-health/          # Health check: service status monitoring
│   └── korea-fss-plugin/       # Korea FSS regulatory compliance plugin
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

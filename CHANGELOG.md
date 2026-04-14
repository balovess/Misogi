# Changelog

All notable changes to Misogi will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### misogi-macros — Production-Grade Procedural Macro SDK
- **5 Hook attribute macros upgraded from pass-through to full trait code generation**:
  - `#[on_metadata(impl_for = S)]` → generates `FileTypeDetector` trait impl
  - `#[on_file_stream(impl_for = S, extensions = [...])]` → generates `CDRStrategy` trait impl
  - `#[on_scan_content(impl_for = S)]` → generates `PIIDetector` trait impl
  - `#[on_format_log(impl_for = S)]` → generates `LogFormatter` trait impl
  - `#[on_approval_event(impl_for = S)]` → generates `ApprovalTrigger<S>` trait impl
- **Compile-time signature validation framework** ([`src/sig_check.rs`](crates/misogi-macros/src/sig_check.rs)):
  - Async/sync correctness enforcement with span-aware error messages
  - Parameter count bounds checking (min/max range support)
  - Structural return type prefix matching (`Result<T,E>` matches `"Result"` pattern)
  - Disallowed qualifier rejection (`unsafe`, `const`, `extern`, generics)
  - Visibility constraint enforcement (no `pub(crate)` on hook functions)
  - Plugin name kebab-case format validation (`[a-z][a-z0-9_-]*`)
- **`#[misogi_plugin]` enhanced** with optional `interfaces = ["..."]` parameter for
  explicit interface list override in `implemented_interfaces()`
- **`async_trait` integration**: All generated async trait methods correctly use
  `#[async_trait::async_trait]` to match core trait definitions
- **Unit test suite**: 3 tests covering plugin name validation, invalid name rejection,
  and structural return type matching — run via `cargo test -p misogi-macros`
- **Zero clippy warnings** across both `misogi-macros` and consumer `korea-fss-plugin`

#### korea-fss-plugin — Integration Test Consumer (Upgraded)
- Migrated from example-level dead-code to production-grade plugin exercising all 3 hooks:
  - `#[on_metadata]` → Korean document format classifier (HWP/HWPX/GUL/CEL/PDF)
  - `#[on_file_stream]` → RRN (주민등록번호) stream scanner with check-digit validation
  - `#[on_scan_content]` → Structured PIIMatch reporter with masking utility
- Added `mask_rrn()` helper for safe log output: `900101-1234567` → `900101-******7`

#### misogi-wasm — Production-Grade WASM Module
- **Dual-target architecture**: `misogi-wasm` now supports both native (wasmi plugin runtime)
  and browser (wasm-bindgen FFI) compilation targets via feature flags (`native` / `browser`)
- **FFI binding layer** ([`src/ffi.rs`](crates/misogi-wasm/src/ffi.rs)): Exposes `sanitize_pdf()`,
  `sanitize_office()`, `scan_pii()`, `detect_file_type()` to JavaScript via wasm-bindgen with
  `SanitizeResult`, `PiiScanResult`, `FileTypeResult` return types
- **JS interop module** ([`src/js_glue.rs`](crates/misogi-wasm/src/js_glue.rs)): Japanese error localization
  (`localize_error()`), WASM linear memory management (`allocate_buffer()` / `deallocate_buffer()`),
  browser console bridge (`console_log()`), WebAssembly feature detection (`detect_wasm_features()`)
- **Performance benchmark suite** ([`benches/`](crates/misogi-wasm/benches/)): 8 criterion groups with
  26 benchmarks covering PDF analysis throughput (~200 MiB/s), Office ZIP rebuild, PII scanning,
  and hash computation baselines — run via `cargo bench -p misogi-wasm --bench wasm_perf`
- **Playwright browser compatibility tests** ([`tests/browser_compat/`](crates/misogi-wasm/tests/browser_compat/)):
  16 automated test cases across Chromium/Firefox/Safari validating WASM loading, sanitization E2E
  flows, PII display, download functionality, Japanese error messages, large file handling (~10MB),
  and COOP/COEP fallback — run via `npm test` in the test directory
- **WASM binary optimization pipeline** ([`scripts/optimize-wasm.sh`](scripts/optimize-wasm.sh)):
  `wasm-opt -Oz` post-processing with debug info stripping and size budget enforcement
  (raw < 8 MB, gzip < 3 MB)
- **CI/CD pipeline** ([`.github/workflows/wasm-ci.yml`](.github/workflows/wasm-ci.yml)): 4-stage pipeline
  (native-check → wasm-build → benchmarks → browser-compat) with artifact retention

#### misogi-wasm — Browser Demo Enhancements
- **COOP/COEP meta tags**: Cross-Origin isolation headers for SharedArrayBuffer support in demo page
- **Feature detection system** ([`feature-detection.js`](examples/wasm-browser/feature-detection.js)):
  `detectWasmSupport()`, `detectSharedArrayBuffer()`, `detectCoopCoep()` with graceful degradation
- **Japanese error localization**: All error messages translated to user-friendly Japanese
- **Progressive UI loading**: Page renders immediately; WASM loads in background with 30-second timeout
  protection ([`wasm-loader.js`](examples/wasm-browser/wasm-loader.js))
- **Modular architecture**: Monolithic app.js split into ES6 modules (app.js + feature-detection.js + wasm-loader.js)

#### misogi-core / misogi-cdr — WASM Compatibility
- **Runtime feature gate**: Async/networking dependencies (tokio, tonic, axum, reqwest)
  moved behind optional `runtime` feature, enabling clean `wasm32-unknown-unknown` compilation
- **ZIP configuration**: Disabled xz/lzma C dependency (requires C stdlib, incompatible with WASM)
- **Conditional compilation**: Platform-specific code gated behind `#[cfg(feature = "runtime")]`

### Changed

#### Build & Deployment
- **WASM binary size**: 271.2 KB raw (was unbounded before), well under 8 MB budget (3.4% utilization)
- **Gzip compressed size**: ~75 KB, well under 3 MB budget (2.5% utilization)
- **Build command**: Now requires `--no-default-features --features browser` for WASM target
- **Cargo.toml structure**: `misogi-wasm`, `misogi-core`, `misogi-cdr` all refactored with
  feature-gated dependencies for dual-target support (native + browser)

### Planned Features
- Web-based monitoring dashboard
- Enhanced logging and observability features
- Improved file transfer performance with parallel chunking

### Changed (v0.2.0 Development)

#### Fixed
- **Resolved all 26 compilation errors** in `misogi-wasm` crate — WASM FFI layer now compiles cleanly
- Fixed `misogi-wasm` dependencies: added direct `misogi-core`, `zip`, `tokio` dependencies; enabled `serde-serialize` feature on `wasm-bindgen`
- Fixed Copy trait bound issues on `String`/`Vec<u8>` fields in WASM-exported structs via `#[wasm_bindgen(getter_with_clone)]`
- Fixed private visibility for `PIIAction`, `PIIDetector` traits re-exported through `misogi_core::pii`
- Fixed `RegexPIIDetector` iterator ambiguity using UFCS syntax (`PIIDetector::scan()`)
- Fixed `FileOptions` type annotation in Office sanitizer WASM adapter
- Cleaned up ~22 warnings in `misogi-core` (unused imports, unused variables, dead code)

#### misogi-cdr — PDF True CDR Engine Enhancements
- **Linearized PDF detection**: Detect `/Linearized` PDFs and flatten cross-reference streams to traditional xref tables
- **Inline image validation**: BI/ID/EI sequence scanning; block FlateDecode/LZWDecode inline images (steganography vector); allow only ASCIIHex/ASCII85/DCT/CCITTFax encodings
- **Obfuscated operator name detection**: Hex-encoded `#HH` operator decoding; detect dangerous obfuscated commands (`#4A#53` = JS)
- **Color space validation**: Allowlist DeviceRGB/CMYK/Gray/CalRGB/CalGRAY; block suspicious ICCBased/Lab/Separation/DeviceN spaces
- **MediaBox inheritance validation**: Recursive page tree walk for MediaBox resolution; default to letter size [0 0 612 792]
- **Multiple content streams handling**: Proper concatenation of `/Contents` arrays with per-stream SAFE_OPERATORS filtering

#### misogi-cdr — Office CDR Deepening
- **XML End event name tracking**: Fixed balanced tag output with name stack mechanism (was TODO/stub)
- **DDE attack prevention`: Cell value/formula scanning for `=CMD|`, `=EXEC(`, `=MSQUERY` patterns; external link protocol blocking (`file://`, `javascript:`, `vbscript:`)
- **Excel-specific threats**: sheetProtection password stripping, PivotCache external reference detection, custom XML mapping injection scan, data validation URL filtering
- **Word-specific threats**: altChunk removal (external content embedding), dangerous hyperlink protocol blocking, IRM permission stripping, instrText script injection neutralization
- **PowerPoint-specific threats**: OLE object disguised-as-picture detection, external sound reference validation, extLst (zero-day vector) removal, animation command script injection filtering
- **16 new OoxmlCdrAction variants** for fine-grained audit trail

#### misogi-auth — OIDC Production Hardening
- **JWKS key rotation**: Auto-refresh when unknown `kid` encountered; configurable TTL (default 3600s); G-Cloud extended to 7200s
- **Token refresh flow**: `refresh_access_token()` with grant_type=refresh_token support
- **RP-initiated logout**: `initiate_logout()` with id_token_hint + post_logout_redirect_uri
- **Nonce binding verification**: Nonce store with TTL (default 300s); auto-cleanup of expired entries
- **IdP-specific adapters**: Keycloak, Azure AD, Okta, Japan G-Cloud pre-configured factory functions
- **Middleware integration**: `OidcExtractor` (Axum FromRequestParts), `OidcGrpcInterceptor` (tonic gRPC), secure session cookie config

#### misogi-auth — SAML 2.0 Full Implementation
- **Core protocol**: AuthnRequest generation (deflate+base64), Response parsing (base64+inflate+XML), XML Signature validation via ring, Conditions validation (NotBefore/NotOnOrAfter/Audience/Destination), Replay attack LRU cache
- **Japan IdP compatibility**: G-Cloud attribute mapping (urn:oid:... patterns), Prefectural flexible mapping, NameID Format handling (persistent/transient/email)
- **Metadata exchange**: SP metadata XML generation, IdP metadata parsing with auto-refresh
- **Route handler templates**: /saml/login, /saml/acs, /saml/logout, /saml/metadata endpoints

#### misogi-auth — Auth Engine Unification
- **Multi-backend auth strategy**: Sequential / FirstMatch / Required modes; configurable backend order (JWT → OIDC → LDAP → SAML → API Key)
- **Unified User identity resolution**: Cross-backend user mapping to `UnifiedUser` struct with roles, groups, attributes
- **Role mapping from external IdP**: Regex-based rules with priority; built-in enterprise mappings (Admin/Approver/Staff); Japanese group name support
- **Audit log integration**: Ring buffer (10K events); SIEM-ready JSON export; per-event timestamp/backend/IP/details
- **Token exchange service**: External IdP auth → internal Misogi JWT (RS256 signed); downstream services validate against Misogi public key only

## [0.1.0] - 2026-04-11

### Added

#### Core Features
- **Initial release** of Misogi file transfer system
- **Chunked file transfer** with configurable chunk sizes
- **Real-time monitoring** of file transfers with detailed progress tracking
- **gRPC-based communication** for reliable streaming
- **Dual mode operation** (server and daemon modes)
- **Type-safe implementation** using Rust 2024 Edition

#### misogi-core
- Protocol Buffer definitions for gRPC services
- Hash utilities for file integrity verification (MD5)
- Comprehensive error handling with `thiserror`
- Core type definitions and data structures
- Async/await support with Tokio

#### misogi-sender
- HTTP API for file upload (Axum-based)
- gRPC streaming client for receiver communication
- File system monitoring with `notify`
- Configurable chunk sizes for efficient transfer
- Progress tracking and status reporting
- CLI interface with `clap`
- TOML-based configuration

#### misogi-receiver
- gRPC server for receiving chunked file streams (Tonic-based)
- HTTP download endpoints for file retrieval
- File reassembly from received chunks
- Organized file storage with metadata
- Tunnel mode support for direct sender-receiver communication
- Real-time receive status monitoring
- CLI interface with `clap`
- TOML-based configuration

#### misogi-cdr
- Content Disarm and Reconstruction (CDR) engine
- PPAP (Penetration Test as a Service) detection and handling
- Support for multiple file types:
  - PDF documents
  - Microsoft Office files (Word, Excel, PowerPoint)
  - Image files
- Configurable sanitization policies
- Security-focused file transformation

#### misogi-auth
- Authentication and authorization framework
- Role-based access control (RBAC)
- JWT token support
- Secure credential storage
- Permission management system

#### Documentation
- Bilingual README (English and Japanese)
- CONTRIBUTING guide with code style guidelines
- SECURITY policy with vulnerability reporting process
- GitHub issue templates (bug reports and feature requests)
- Pull request template
- Crate-specific README files

#### Development Tools
- Comprehensive test suite
- Code formatting with `rustfmt`
- Linting with `clippy`
- API documentation generation with `cargo doc`

### Security

- TLS support for gRPC connections
- File integrity verification with MD5 hashing
- Input validation on all endpoints
- Secure storage permissions
- Structured JSON logging for audit trails
- No hardcoded credentials or secrets

### Technical Details

#### Dependencies
- `tokio` - Async runtime
- `axum` - Web framework
- `tonic` - gRPC framework
- `prost` - Protocol Buffers implementation
- `serde` - Serialization framework
- `thiserror` - Error handling
- `clap` - CLI parsing
- `notify` - File system monitoring
- `uuid` - Unique identifiers
- `chrono` - Date and time handling

#### Architecture
- Sender-Receiver architecture
- Chunked file transfer protocol
- Streaming support for large files
- Modular crate structure
- Pluggable design for future extensions

### Known Issues

- Initial release - no known issues at this time

### Deprecated

- Nothing deprecated in initial release

### Removed

- Nothing removed in initial release

---

## Version History

| Version | Release Date | Description |
|---------|-------------|-------------|
| 0.1.0   | 2026-04-11  | Initial Release |

---

## License

This project is licensed under the Apache 2.0 License.
See [LICENSE](LICENSE) for details.

---

**Note**: For detailed information about each release, please refer to the GitHub releases page.

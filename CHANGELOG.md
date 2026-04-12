# Changelog

All notable changes to Misogi will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

# GDPR & NIS2 Compliance Mapping for Misogi

**EU Regulatory Compliance Documentation — Misogi (禊) CDR Secure File Transfer System**

This document provides a structured mapping between the European Union's data protection and cybersecurity regulatory frameworks and the technical capabilities of the Misogi system. It is intended for use in GDPR compliance assessments, NIS2 readiness evaluations, and vendor security questionnaires within the EU/EEA market.

---

## Document Information

| Field | Value |
|-------|-------|
| Document Name | GDPR & NIS2 Compliance Mapping for Misogi |
| Target System | Misogi (禊) CDR Secure File Transfer System |
| Created | 2026-04-13 |
| Scope | EU/EEA Regulatory Compliance |
| Classification | Government Procurement / Vendor Assessment Material |

---

## 1. Overview

The European Union maintains a dual-layered regulatory framework governing data protection and cybersecurity: the **General Data Protection Regulation (GDPR, Regulation (EU) 2016/679)** establishes binding requirements for personal data processing, while **NIS2 Directive (Directive (EU) 2022/2555)** mandates cybersecurity risk management and incident reporting obligations for essential and important entities.

Misogi addresses both frameworks through its core architecture:

- **CDR (Content Disarm & Reconstruction)** engine in `misogi-cdr` strips unnecessary data, removes embedded threats, and reconstructs clean files — directly supporting data minimization (GDPR Art. 5) and supply chain security (NIS2 Art. 21).
- **PII Detection** via `RegexPIIDetector` in `misogi-core::pii` enables privacy-by-design processing (GDPR Art. 25) with configurable Block/Mask/Alert actions.
- **RBAC + JWT Authentication** from `misogi-auth` enforces least-privilege access control across 9 permission actions (UPLOAD, DOWNLOAD, SCAN, APPROVE, ADMIN, etc.), supporting GDPR Art. 32 and NIS2 Art. 21.
- **Audit Log Engine** (`LogEngine`) produces structured JSON/Syslog/CEF output with SHA-256 integrity hashes, enabling breach notification readiness (GDPR Art. 33) and incident reporting (NIS2 Art. 23).
- **TLS 1.3** transport encryption via `rustls` / `tonic` (gRPC-RS) ensures confidentiality and integrity of data in transit (GDPR Art. 32, NIS2 Art. 21).
- **Rust memory safety** eliminates entire classes of vulnerabilities (buffer overflows, use-after-free), contributing to system integrity under NIS2 Art. 21.

---

## 2. GDPR Article Mapping Table

| GDPR Article | Requirement Summary | Misogi Capability | Module / Component | Status |
|-------------|-------------------|------------------|-------------------|--------|
| **Art. 5(1)(c)** — Data Minimization | Personal data shall be adequate, relevant and limited to what is necessary | CDR sanitization strips embedded metadata, scripts, macros, and unnecessary objects from PDF/OOXML/ZIP/SVG files during transfer. `SanitizationPolicy` enum controls the level of data reduction. | `misogi-cdr` (`PdfStreamParser`, `OoxmlStreamParser`, `ZipSanitizer`, `SvgSanitizer`) | ✅ Supported |
| **Art. 25** — Privacy by Design & by Default | Implement appropriate technical measures to ensure privacy principles are embedded into processing | PII detection engine scans file content in-stream for personal identifiers (My Number, credit cards, email, phone). Configurable `PIIAction` (Block / Mask / AlertOnly) enforces privacy defaults at the policy level. | `misogi-core::pii::RegexPIIDetector`, `PIIRule`, `PIIAction` enum | ✅ Supported |
| **Art. 32** — Security of Processing | Implement appropriate technical and organizational measures to ensure a level of security appropriate to the risk | Multi-layered security: TLS 1.3 end-to-end encryption (`rustls` + `tonic` gRPC); RBAC with 9 granular permission actions (`misogi-auth`); audit logging with SHA-256 integrity hashing (`LogEngine` + `JsonLogFormatter`); StateMachine-based approval workflow with role separation. | `misogi-auth` (RBAC, JWT, LDAP/OIDC/SAML), `misogi-core::engine::StateMachine`, `misogi-core::LogEngine`, TLS config | ✅ Supported |
| **Art. 33** — Notification of Personal Data Breach | Notify supervisory authority without undue delay (and where feasible, not later than 72 hours) | Audit log engine records all file operations with UUID, ISO 8601 timestamp, user identifier, file SHA-256 hash, and processing result. Real-time alerting via `ApprovalTrigger` callbacks enables rapid breach detection. Structured log output (JSON/Syslog/CEF) supports automated SIEM correlation for timely notification. | `misogi-core::LogEngine`, `JsonLogFormatter`, `SyslogFormatter`, `CefFormatter`, `misogi-sender::approval_routes` | ✅ Supported |
| **Art. 35** — Data Protection Impact Assessment (DPIA) | Carry out an assessment of the impact of the envisaged processing operations on personal data | PII classification engine identifies sensitive data categories; `SanitizationPolicy` graduated levels (Strip / Mask / ConvertToFlat / Preserve) provide documented, auditable data handling choices. Audit trail captures all policy decisions and their outcomes for DPIA evidence gathering. | `misogi-core::pii::RegexPIIDetector`, `SanitizationPolicy` enum, `misogi-core::audit_log` | ✅ Supported |

### GDPR Cross-Article Capability Matrix

| Capability Domain | Relevant Articles | Misogi Implementation | Evidence Available |
|------------------|------------------|----------------------|-------------------|
| Data Minimization | Art. 5(1)(c) | CDR stream parsing removes non-essential objects | `cdr_result.threats_removed` in audit log |
| Privacy by Design | Art. 25 | PII detection + SanitizationPolicy at pipeline entry | Policy configuration in TOML |
| Access Control | Art. 25, Art. 32 | RBAC 9-action model + AD/LDAP/OIDC/SAML | Role-permission matrix in config |
| Encryption in Transit | Art. 32 | TLS 1.3 via rustls + certificate pinning | TLS handshake logs |
| Audit Trail | Art. 32, Art. 33 | LogEngine with JSON/Syslog/CEF + SHA-256 | Per-event hash chain |
| Breach Detection | Art. 33 | Real-time alerts + SIEM-formatted output | Alert callback configuration |
| DPIA Support | Art. 35 | PII classification + policy-level documentation | SanitizationPolicy audit log |

---

## 3. NIS2 Directive Mapping Table

| NIS2 Requirement | Article / Provision | Misogi Capability | Module / Component | Status |
|-----------------|-------------------|------------------|-------------------|--------|
| **Incident Reporting** (Art. 23) | Report significant incidents to CSIRTs / competent authorities without undue delay | `LogEngine` generates structured events (`FILE_PROCESSED`, `AUTH_SUCCESS`, `APPROVAL_GRANTED`, etc.) with full context. Syslog/CEF formatters produce output consumable by SIEM platforms for automated incident detection and reporting pipelines. | `misogi-core::LogEngine`, `SyslogFormatter`, `CefFormatter` | ✅ Supported |
| **Supply Chain Security** (Art. 21(2)(d)) | Address security of supply chain relationships, including security-related aspects concerning the relationship between each entity and its direct suppliers or service providers | Clean-room CDR implementation in `misogi-cdr` has zero third-party runtime dependencies for file parsing (PDF, OOXML, ZIP, SVG are parsed using pure Rust implementations). Rust memory safety eliminates vulnerability classes common in C/C++ parser libraries. `cargo-audit` integration scans dependency tree for known CVEs. | `misogi-cdr` (all sanitizers), build system, `cargo-audit` | ✅ Supported |
| **Risk Management Measures** (Art. 21(2)) | Take appropriate and proportionate technical and organizational measures to manage risks posed to network and information systems | `SanitizationPolicy` enum defines graduated levels of threat mitigation: `Strip` (remove dangerous content), `Mask` (redact detected PII), `ConvertToFlat` (flatten complex formats), `Preserve` (pass-through with logging). Risk-based policy selection is enforced via TOML configuration. Combined with RBAC access control and approval workflow (`StateMachine`), this forms a defense-in-depth risk management posture. | `SanitizationPolicy` enum, `misogi-core::engine::StateMachine`, `misogi-auth::role` | ✅ Supported |
| **Crypto Agility** (Art. 21(2)(a)) | Ensure systems use state-of-the-art cryptography and cryptographic protocols | TLS 1.3 as default transport protocol via `rustls`. Configurable cipher suite selection through TOML `[tls]` section. Support for TLS 1.2 fallback where required. Certificate pinning capability for mutual TLS (mTLS) scenarios. Future-proof design allows cipher suite updates without code changes. | TLS configuration module, `rustls`, `tonic` (gRPC-RS) | ✅ Supported |
| **Business Continuity** (Art. 21(2)(f)) | Have backup procedures and a disaster recovery plan | Multiple `TransferDriver` implementations support diverse network topologies: `DirectTcpDriver` (standard), `PullDriver` (receiver-initiated), `BlindSendDriver` (air-gapped / diode), `StorageRelayDriver` (cloud relay). `StorageBackend` trait abstracts storage (local FS, S3-compatible, Azure Blob). Helm Chart deployment ensures Kubernetes-native resilience with pod restart policies. | `misogi-core::drivers`, `misogi-core::traits::storage`, Helm Chart manifests | ✅ Supported |
| **Access Control** (Art. 21(2)(b)) | Ensure appropriate access control policies based on business needs | RBAC model with 9 permission actions mapped to roles. Integration with enterprise IdPs: Active Directory / LDAP (`LdapAuthProvider`), OIDC (Keycloak / Azure AD), SAML 2.0. JWT-based session tokens with RS256 signing. gRPC interceptors enforce authentication on every request. | `misogi-auth` (full provider suite), `misogi-auth::role`, `misogi-auth::extractors` | ✅ Supported |
| **System Security** (Art. 21(2)(c)) | Secure network and information systems, including secure configuration | Rust language guarantees eliminate memory safety vulnerabilities (no buffer overflows, no use-after-free, no double-free). All file parsing performed via stream-based sanitizers that reconstruct clean output rather than mutating input. No shell command execution, no dynamic code loading. Container deployment with read-only root filesystem and non-root user execution. | Entire project (Rust 2024 edition), `misogi-cdr` stream parsers, container security profile | ✅ Supported |

---

## 4. References

All references below point exclusively to official EU government or agency domains.

| # | Source | URL | Relevance |
|---|--------|-----|-----------|
| 1 | **GDPR — Regulation (EU) 2016/679** (Official text, EUR-Lex) | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679 | Primary legal reference for Articles 5, 25, 32, 33, 35 mapping |
| 2 | **NIS2 Directive — Directive (EU) 2022/2555** (Official text, EUR-Lex) | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555 | Primary legal reference for Articles 21, 23 mapping |
| 3 | **ENISA — European Union Agency for Cybersecurity** | https://www.enisa.europa.eu/ | EU cybersecurity agency; publishes NIS2 implementation guidance, threat landscape reports, and good practice recommendations |
| 4 | **European Data Protection Board (EDPB)** | https://edpb.europa.eu/ | Supervisory authority coordination body; issues GDPR guidelines and opinions |
| 5 | **European Commission — Digital Strategy** | https://digital-strategy.ec.europa.eu/en/policies/cybersecurity-policy | Overview of EU cybersecurity policy framework including NIS2 |

---

*This document was produced by the Misogi project.*
*Content is based on official EU legislative texts published on EUR-Lex.*
*Last updated: 2026-04-13 | Version: 1.0*
*License: Apache 2.0*

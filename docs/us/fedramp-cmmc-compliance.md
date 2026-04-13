# FedRAMP & CMMC Compliance Mapping for Misogi

**US Federal Cybersecurity Framework Alignment — Misogi (禊) CDR Secure File Transfer System**

This document provides a structured mapping between United States federal cybersecurity frameworks and the technical capabilities of the Misogi system. It is intended for use in FedRAMP authorization packages, CMMC 2.0 self-assessments, and vendor security questionnaires within the US federal supply chain.

---

## Document Information

| Field | Value |
|-------|-------|
| Document Name | FedRAMP & CMMC Compliance Mapping for Misogi |
| Target System | Misogi (禊) CDR Secure File Transfer System |
| Created | 2026-04-13 |
| Scope | US Federal / DoD Supply Chain Compliance |
| Classification | Government Procurement / Vendor Assessment Material |

---

## 1. Overview

The United States federal government operates a tiered cybersecurity authorization framework centered on **FedRAMP** (Federal Risk and Authorization Management Program) for cloud systems and **CMMC 2.0** (Cybersecurity Maturity Model Certification) for Defense Industrial Base (DIB) contractors. Both frameworks are grounded in **NIST SP 800-53** control baselines and the **NIST Cybersecurity Framework (CSF)**.

Misogi addresses these frameworks through its security-first architecture:

- **RBAC + Multi-Protocol Authentication** in `misogi-auth` provides granular access control across 9 permission actions with enterprise IdP integration (AD/LDAP, OIDC, SAML 2.0), directly supporting FedRAMP AC (Access Control) and CMMC AC.2 families.
- **Audit Log Engine** (`LogEngine`) produces tamper-evident structured logs in JSON/Syslog/CEF formats with per-event SHA-256 integrity hashing, satisfying FedRAMP AU (Audit and Accountability) and CMMC AU.2 requirements.
- **TLS 1.3 Transport Security** via `rustls` and gRPC (`tonic`) ensures encrypted system communications, addressing FedRAMP SC (System and Communications Protection) and CMMC SC.2.
- **Rust Memory Safety** eliminates entire vulnerability classes inherent in C/C++ implementations, providing strong foundational assurance for FedRAMP SI (System and Information Integrity) and contributing to overall CMMC maturity.
- **CDR Sanitization Engine** (`misogi-cdr`) performs content disarm and reconstruction on PDF/OOXML/ZIP/SVG files, removing embedded threats before processing — a unique capability that strengthens media protection posture under CMMC MP.2.

---

## 2. FedRAMP Baseline Mapping Table

### 2.1 FedRAMP Low/Moderate Control Family Mapping

| Control Family | Control ID | Control Summary | Misogi Capability | Module / Component | Status |
|---------------|-----------|----------------|------------------|-------------------|--------|
| **AC — Access Control** | AC-1, AC-2, AC-3 | Access control policy; account management; least privilege | RBAC model with 9 granular permission actions: UPLOAD, DOWNLOAD, SCAN, APPROVE, ADMIN, CONFIGURE, VIEW_LOGS, MANAGE_USERS, MANAGE_VENDORS. Role-permission matrix enforced via JWT claims on every request. Account lifecycle managed through AD/LDAP synchronization or local user store. | `misogi-auth::role`, `misogi-auth::extractors`, `LdapAuthProvider`, `JwtAuthenticator` | ✅ Supported |
| **AC — Access Control** | AC-6 | Principle of least privilege | Each permission action is independently assignable to roles. StateMachine enforces separation of duties: operators can submit requests but cannot approve them; approvers cannot modify system configuration. `VendorIsolationManager` provides dedicated access boundary for third-party vendors. | `misogi-auth::role` (9-action enum), `misogi-core::engine::StateMachine`, `VendorIsolationManager` | ✅ Supported |
| **AU — Audit and Accountability** | AU-2, AU-3, AU-6 | Audit events; audit record content; audit review, analysis, and reporting | `LogEngine` captures all security-relevant events: FILE_PROCESSED, AUTH_SUCCESS, AUTH_FAILURE, APPROVAL_GRANTED, APPROVAL_DENIED, CONFIG_CHANGE. Each event includes UUID, ISO 8601 timestamp (millisecond precision, UTC), actor identity, resource identifier (file SHA-256 hash), action taken, and outcome. Multiple output formatters enable downstream analysis. | `misogi-core::LogEngine`, event enum definitions | ✅ Supported |
| **AU — Audit and Accountability** | AU-9 | Protection of audit information | Per-event SHA-256 integrity hashing via `audit_log` module. Write-only log file policy (append-only). Structured output formats (JSON, Syslog, CEF) support external SIEM ingestion with chain-of-custody preservation. Log rotation by size and time with configurable retention policies. | `misogi-core::audit_log`, `JsonLogFormatter`, `SyslogFormatter`, `CefFormatter` | ✅ Supported |
| **AU — Audit and Accountability** | AU-12 | Audit trail generation | Every file transfer operation generates an immutable audit record from submission through approval, CDR processing, PII detection, and delivery. The complete lifecycle is traceable via event UUID correlation. No administrative bypass of audit logging is possible. | `misogi-core::LogEngine`, `misogi-core::engine::StateMachine` (state transition logging) | ✅ Supported |
| **SC — System and Communications Protection** | SC-7, SC-8, SC-12, SC-23 | Boundary protection; transmission confidentiality/integrity; cryptographic key management; Session authentication | TLS 1.3 as default transport protocol via `rustls`. Configurable cipher suite selection through `[tls]` TOML section. Certificate pinning for mutual TLS (mTLS). RS256 JWT signing for session tokens. All gRPC and HTTP communications encrypted end-to-end. | TLS config module, `rustls`, `tonic` (gRPC-RS), `misogi-auth::JwtAuthenticator` | ✅ Supported |
| **SC — System and Communications Protection** | SC-8 | Transmission confidentiality and integrity | End-to-end encryption for all data in transit using TLS 1.3. File content at rest protected by storage backend encryption (S3 server-side encryption, Azure Blob encryption). In-memory file buffers use scoped lifetimes with zeroization on drop (Rust ownership model). | TLS layer, `StorageBackend` trait implementations, Rust memory model | ✅ Supported |
| **SI — System and Information Integrity** | SI-7, SI-10 | Malicious code protection; information input validation | CDR engine performs True Content Disarm and Reconstruction: PDF parsed via `PdfStreamParser` (binary stream analysis, cross-reference table rebuild), OOXML via `OoxmlStreamParser` (ZIP container extraction, XML sanitization, vbaProject/ddeLink/oleObject removal), ZIP via `ZipSanitizer` (recursive extraction, per-entry routing), SVG via `SvgSanitizer` (script/handler/external reference removal). Rust memory safety prevents exploitation of parser-level vulnerabilities. | `misogi-cdr` (all sanitizers), Rust language guarantees | ✅ Supported |
| **CM — Configuration Management** | CM-2, CM-3, CM-6, CM-7 | Baseline configuration; change control; least functionality; least privileges | TOML-based declarative configuration with schema validation. All security-relevant parameters (CDR policy, PII rules, RBAC roles, TLS settings) version-controlled. Feature flags enable/disable individual sanitizers and detectors. Container deployment uses read-only root filesystem with minimal installed packages. | `misogi-config`, `[cdr]`, `[pii]`, `[auth]`, `[tls]` TOML sections, container manifests | ✅ Supported |
| **IA — Identification and Authentication** | IA-2, IA-5 | Identification and authentication (organizational users); Authenticator management | Multi-provider authentication: LDAP/AD Bind (`LdapAuthProvider`) with group-based authorization; OIDC (Keycloak, Azure AD) with consent integration; SAML 2.0; API Key authentication. Password policy enforcement configurable. MFA extension points available via `AuthEngine` microkernel architecture. | `misogi-auth` (full provider suite), `AuthEngine`, `LdapAuthProvider`, `OidcProvider` | ✅ Supported |

### 2.2 FedRAMP Control Coverage Summary

| Control Family | Controls Addressed | Total Applicable | Coverage |
|--------------|-------------------|-----------------|----------|
| AC (Access Control) | AC-1, AC-2, AC-3, AC-6 | 4+ | ✅ High |
| AU (Audit) | AU-2, AU-3, AU-6, AU-9, AU-12 | 5 | ✅ Complete |
| SC (System Comms) | SC-7, SC-8, SC-12, SC-23 | 4 | ✅ High |
| SI (System Integrity) | SI-7, SI-10 | 2 | ✅ Strong (CDR core) |
| CM (Config Mgmt) | CM-2, CM-3, CM-6, CM-7 | 4 | ✅ High |
| IA (Identification) | IA-2, IA-5 | 2+ | ✅ High |

---

## 3. CMMC 2.0 Level 2 (Maturity) Mapping Table

CMMC 2.0 Level 2 requires demonstrated maturity across 14 practice areas. The following table maps Level 2 practices relevant to a secure file transfer system to Misogi capabilities.

| Practice Area | Practice ID | Practice Requirement | Misogi Capability | Module / Component | Maturity Evidence |
|-------------|------------|---------------------|------------------|-------------------|------------------|
| **AC — Access Control** | AC.L2-082 | Limit data system access to authorized users; enforce least privilege | RBAC with 9 permission actions mapped to organizational roles. JWT-based session enforcement on every API call. Role assignment through AD/LDAP group membership or manual configuration. Separation of duties enforced via StateMachine (operators vs. approvers). | `misogi-auth::role`, `misogi-auth::extractors`, `misogi-core::engine::StateMachine` | Policy definition in TOML; role matrix documented; test evidence of permission enforcement |
| **AC — Access Control** | AC.L2-083 | Control internal system access | All access mediated through authenticated sessions. No direct database or filesystem access bypassing the application layer. Vendor isolation via `VendorIsolationManager` restricts third-party accounts to designated operations only. | `misogi-auth` (all interceptors), `VendorIsolationManager` | Access control matrix; vendor isolation policy configuration |
| **AU — Audit Logging** | AU.L2-092 | Create, protect, and retain system audit records | `LogEngine` generates structured audit events for all security-relevant operations. SHA-256 integrity hashes per event prevent tampering. JSON/Syslog/CEF output formats support long-term retention in external storage (S3, NAS, Elasticsearch). Configurable retention periods align with organizational policy. | `misogi-core::LogEngine`, `JsonLogFormatter`, `SyslogFormatter`, `CefFormatter`, `misogi-core::audit_log` | Sample audit log output; retention policy configuration; integrity verification procedure |
| **MP — Media Protection** | MP.L2-112 | Protect media containing CUI during transport and at rest | CDR engine sanitizes all incoming files before storage or forwarding. Threat removal includes: JavaScript from PDF, VBA macros/DDE links from Office documents, scripts from SVG, recursive nested archive contents. Clean-room implementation avoids third-party parser vulnerabilities. Output files are newly reconstructed (not mutated originals). | `misogi-cdr::PdfStreamParser`, `misogi-cdr::OoxmlStreamParser`, `misogi-cdr::ZipSanitizer`, `misogi-cdr::SvgSanitizer` | CDR processing log showing threats removed; sanitized output verification; threat library coverage list |
| **SC — System Communications** | SC.L2-128 | Protect CUI transmitted on external systems | TLS 1.3 mandatory for all inter-system communication (Sender ↔ Receiver, Client ↔ Server). Configurable cipher suites. Certificate pinning support. gRPC binary protocol with built-in framing integrity. Optional tunnel mode for air-gapped environments (`BlindSendDriver`). | TLS config, `rustls`, `tonic` (gRPC-RS), `BlindSendDriver` | TLS handshake validation; cipher suite configuration; certificate pinning setup guide |
| **SC — System Communications** | SC.L2-129 | Monitor, control, and protect external communications | All outbound connections defined in configuration. No arbitrary network access. Storage backends (S3, Azure Blob, Local FS) accessed through abstracted trait interface with credential isolation. Network policy enforcement via Kubernetes NetworkPolicy (default deny) when deployed in K8s. | `misogi-core::traits::storage`, `TransferDriver` trait, K8s NetworkPolicy manifests | Network topology diagram; allowed endpoint list; K8s network policy YAML |
| **SI — System Integrity** | SI.L2-136 | Identify, report, and correct flaws | Rust compiler-enforced memory safety eliminates buffer overflows, use-after-free, double-free, null pointer dereference, and integer overflow classes. `cargo-audit` scans dependency tree for known CVEs. CDR sanitization provides defense-in-depth against file-based attack vectors. | Rust 2024 edition toolchain, `cargo-audit`, `misogi-cdr` sanitizers | Compiler safety guarantees documentation; dependency audit report; CDR threat coverage matrix |

### CMMC 2.0 Level 2 Practice Coverage Summary

| Domain | Practices Covered | Total Relevant | Assessment Objective |
|--------|------------------|----------------|---------------------|
| Access Control (AC) | AC.L2-082, AC.L2-083 | 2/2 | Demonstrate role-based access with least privilege |
| Audit Logging (AU) | AU.L2-092 | 1/1 | Demonstrate audit record creation and protection |
| Media Protection (MP) | MP.L2-112 | 1/1 | Demonstrate CUI protection during file handling |
| System Comms (SC) | SC.L2-128, SC.L2-129 | 2/2 | Demonstrate encrypted and controlled communications |
| System Integrity (SI) | SI.L2-136 | 1/1 | Demonstrate vulnerability identification and mitigation |

---

## 4. NIST CSF Alignment

Misogi capabilities map to NIST CSF Core Functions as follows:

| CSF Function | Category | Misogi Implementation |
|-------------|----------|----------------------|
| **Identify** | ID.AM (Asset Management) | Asset inventory via configuration management; file metadata tracking in audit log |
| **Protect** | PR.AC (Access Control) | RBAC 9-action model; IdP integration; least privilege enforcement |
| **Protect** | PR.DS (Data Security) | CDR sanitization; PII detection; TLS encryption; SHA-256 integrity |
| **Detect** | DE.CM (Security Monitoring) | Real-time alert callbacks; structured log output for SIEM |
| **Respond** | RS.AN (Analysis) | Event correlation via UUID; state machine audit trail |
| **Recover** | RC.RP (Recovery Plan) | Multiple transfer drivers; storage backend abstraction; Helm Chart resilience |

---

## 5. References

All references below point exclusively to official US government domains.

| # | Source | URL | Relevance |
|---|--------|-----|-----------|
| 1 | **FedRAMP — Baselines** | https://www.fedramp.gov/baselines/ | Primary source for FedRAMP Low/Moderate control baseline requirements |
| 2 | **NIST SP 800-53 Rev. 5** (Security and Privacy Controls) | https://csrc.nist.gov/pubs/sp/800/53/final/ | Foundational control catalog underlying FedRAMP and CMMC |
| 3 | **CMMC 2.0 Program** (Department of Defense) | https://www.dssa.mil/cmmc/ | Official DoD CMMC program guidance and model specifications |
| 4 | **NIST Cybersecurity Framework (CSF)** | https://www.nist.gov/cyberframework | Risk management framework referenced by both FedRAMP and CMMC |
| 5 | **FedRAMP Marketplace** | https://marketplace.fedramp.gov/ | Authorized cloud product listings and security packages |

---

*This document was produced by the Misogi project.*
*Content is based on official US government publications.*
*Last updated: 2026-04-13 | Version: 1.0*
*License: Apache 2.0*

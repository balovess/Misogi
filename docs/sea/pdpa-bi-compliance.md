# Southeast Asia Data Protection Compliance Mapping for Misogi

**SEA Regional Regulatory Compliance Documentation — Misogi (禊) CDR Secure File Transfer System**

This document provides a structured mapping between Southeast Asian data protection regulations and the technical capabilities of the Misogi system. It is intended for use in compliance assessments across major SEA markets: Singapore, Indonesia, Malaysia, Thailand, Philippines, and financial sector regulations (Bank Indonesia).

---

## Document Information

| Field | Value |
|-------|-------|
| Document Name | Southeast Asia Data Protection Compliance Mapping for Misogi |
| Target System | Misogi (禊) CDR Secure File Transfer System |
| Created | 2026-04-13 |
| Scope | Singapore PDPA, Indonesia PDP Law, Malaysia PDPA, Thailand PDPA, Philippines DIPA, Bank Indonesia Regulations |
| Classification | Government Procurement / Vendor Assessment Material |

---

## 1. Overview

Southeast Asia presents a diverse regulatory landscape for data protection and cybersecurity. Major jurisdictions have enacted comprehensive data protection laws modeled on GDPR, while financial sector regulators impose additional security requirements. Key frameworks include:

- **Singapore PDPA** (Personal Data Protection Act 2012) — Established framework with Protection, Access, and Correction obligations.
- **Indonesia PDP Law** (UU No. 27/2022) — Comprehensive data protection law with consent management, cross-border transfer safeguards, and data minimization requirements.
- **Malaysia PDPA** (Personal Data Protection Act 2010) — Protection obligation with data retention and security requirements.
- **Thailand PDPA** (Personal Data Protection Act B.E. 2562) — GDPR-inspired framework with consent, access rights, and cross-border transfer provisions.
- **Philippines DIPA** (Data Privacy Act of 2012) — Comprehensive privacy law with security of personal information and data breach notification requirements.
- **Bank Indonesia Regulations** — Information security requirements for financial institutions, including data residency considerations.

Misogi addresses these frameworks through:

- **CDR Sanitization** (`misogi-cdr`) removes embedded threats and unnecessary metadata from files, supporting protection obligations and data minimization.
- **PII Detection** (`RegexPIIDetector`) enables automated identification of personal data with configurable Block/Mask/Alert actions.
- **Audit Log Engine** (`LogEngine`) provides comprehensive audit trails for access/correction requests and data breach investigations.
- **Storage Backend Abstraction** (`StorageBackend` trait) supports local deployment options for data residency compliance.
- **OIDC Consent Integration** enables consent management workflows required by Indonesia PDP and other frameworks.

---

## 2. Singapore PDPA Mapping Table

| PDPA Provision | Requirement | Misogi Capability | Module / Component | Status |
|--------------|-------------|------------------|-------------------|--------|
| **Protection Obligation** (Section 24) | Make reasonable security arrangements to prevent unauthorized access, collection, use, disclosure, copying, modification, disposal, or similar risks | CDR sanitization removes embedded threats (JavaScript, macros, scripts, external references) from PDF/OOXML/ZIP/SVG files during transfer. TLS 1.3 encryption protects data in transit. RBAC enforces access control. PII detection identifies sensitive content for additional protection. | `misogi-cdr` (all sanitizers), TLS config, `misogi-auth::role`, `misogi-core::pii::RegexPIIDetector` | ✅ Supported |
| **Access/Correction Obligation** (Sections 21-22) | Provide data subjects with access to their personal data and correction upon request | Audit log engine records all file operations with full context: UUID, ISO 8601 timestamp, actor identity, file SHA-256 hash, processing result. Structured JSON output enables efficient search and retrieval for access requests. PII detection logs identify which files contain personal data. | `misogi-core::LogEngine`, `JsonLogFormatter`, `misogi-core::pii::RegexPIIDetector` | ✅ Supported |
| **Data Portability** (Section 26) | Provide personal data in commonly used machine-readable format upon request | `StorageBackend` trait abstracts storage access. Multiple backend implementations (Local FS, S3-compatible, Azure Blob) enable data export in various formats. JSON-formatted audit logs provide machine-readable records of data transfers. | `misogi-core::traits::storage`, `JsonLogFormatter` | ✅ Supported |
| **Notification Obligation** (Section 26) | Notify data subjects and PDPC of data breaches where significant harm is likely | Real-time alerting via `ApprovalTrigger` callbacks enables rapid breach detection. Audit log captures all events with SHA-256 integrity hashing for forensic analysis. Syslog/CEF output formats support SIEM integration for automated breach notification workflows. | `misogi-sender::approval_routes`, `misogi-core::LogEngine`, `SyslogFormatter`, `CefFormatter` | ✅ Supported |
| **Retention Limitation** (Section 25) | Retain personal data only as long as necessary for purpose | Configurable log retention policies via rotation settings. Storage backend abstraction enables integration with archival systems that enforce retention schedules. Audit log provides evidence of data lifecycle management. | `misogi-core::LogEngine` (rotation config), `misogi-core::traits::storage` | ✅ Supported |

---

## 3. Indonesia PDP Law (UU No. 27/2022) Mapping Table

| PDP Law Provision | Requirement | Misogi Capability | Module / Component | Status |
|------------------|-------------|------------------|-------------------|--------|
| **Consent Management** (Article 13) | Obtain explicit consent before processing personal data; consent must be freely given, specific, informed, and unambiguous | OIDC provider integration (`OidcProvider`) supports consent workflows. Authorization code flow with consent prompt ensures explicit user consent before data access. Consent decisions recorded in audit log for accountability. | `misogi-auth::OidcProvider`, `misogi-core::LogEngine` (AUTH_SUCCESS events) | ✅ Supported |
| **Cross-Border Transfer** (Article 52) | Implement technical safeguards for international data transfer; ensure adequate protection level | CDR sanitization provides technical safeguard by removing embedded threats before cross-border transfer. TLS 1.3 encryption protects data in transit. Data residency compliance supported via local deployment options (Docker/K8s on-premises). | `misogi-cdr` (all sanitizers), TLS config, Helm Chart manifests | ✅ Supported |
| **Data Minimization** (Article 11) | Process only personal data that is adequate, relevant, and limited to purpose | CDR sanitization strips unnecessary metadata and embedded objects from files. `SanitizationPolicy::ConvertToFlat` option reduces complex formats to simplified representations. PII detection identifies personal data for targeted processing. | `misogi-cdr` (all sanitizers), `SanitizationPolicy` enum, `misogi-core::pii::RegexPIIDetector` | ✅ Supported |
| **Data Subject Rights** (Articles 23-30) | Right to access, correct, delete, withdraw consent, object to processing | Audit log engine provides comprehensive record of all data processing operations. JSON output format enables efficient search for access requests. Role-based access control supports data subject access workflows. Consent withdrawal supported via OIDC session revocation. | `misogi-core::LogEngine`, `JsonLogFormatter`, `misogi-auth::role`, `misogi-auth::OidcProvider` | ✅ Supported |
| **Data Breach Notification** (Article 45) | Notify data subjects and data protection authority within 72 hours of breach discovery | Real-time alerting via callback triggers enables rapid breach detection. Audit log with per-event SHA-256 integrity hashes provides forensic evidence. Structured log output supports automated breach notification workflows. | `misogi-sender::approval_routes`, `misogi-core::LogEngine`, `audit_log` module | ✅ Supported |

---

## 4. Bank Indonesia (BI) Regulations for Financial Institutions

Bank Indonesia imposes specific information security requirements on financial institutions operating in Indonesia.

| BI Regulation | Requirement | Misogi Capability | Module / Component | Status |
|--------------|-------------|------------------|-------------------|--------|
| **Information Security Management** (POJK No. 38/POJK.03/2016) | Implement comprehensive information security management system including access control, encryption, and monitoring | RBAC with 9 granular permission actions enforces least privilege access control. TLS 1.3 encryption protects all communications. Audit log engine provides continuous monitoring. Multi-factor authentication extension points available via `AuthEngine`. | `misogi-auth::role`, TLS config, `misogi-core::LogEngine`, `AuthEngine` | ✅ Supported |
| **Data Residency** (BI Circular Letters) | Store and process data within Indonesian territory where required by law | Local deployment options via Docker and Kubernetes Helm Chart. `StorageBackend` trait supports local filesystem storage. On-premises deployment avoids cross-border data transfer for regulated data. | Helm Chart manifests, `misogi-core::traits::storage` (LocalFsBackend), container deployment guides | ✅ Supported |
| **Audit Trail** (BI Guidelines) | Maintain comprehensive audit trail of all system access and data processing | `LogEngine` captures all security-relevant events: authentication, file transfers, CDR processing, PII detection, approval workflows. Each event includes UUID, timestamp, actor, resource, action, and outcome. SHA-256 integrity hashing prevents tampering. | `misogi-core::LogEngine`, event definitions, `audit_log` module | ✅ Supported |
| **Incident Response** (BI Guidelines) | Establish incident response procedures with rapid detection and notification | Real-time alerting via `ApprovalTrigger` callbacks. Structured log output (JSON/Syslog/CEF) for SIEM integration. State machine tracks file transfer lifecycle for incident reconstruction. | `misogi-sender::approval_routes`, `misogi-core::LogEngine`, `misogi-core::engine::StateMachine` | ✅ Supported |
| **Third-Party Risk Management** (BI Guidelines) | Assess and manage risks from third-party service providers | Vendor isolation via `VendorIsolationManager` restricts third-party account privileges. Clean-room CDR implementation eliminates third-party runtime dependencies. `cargo-audit` scans dependency tree for known vulnerabilities. | `VendorIsolationManager`, `misogi-cdr` (zero third-party deps), `cargo-audit` | ✅ Supported |

---

## 5. Other SEA Jurisdictions Summary

### 5.1 Malaysia PDPA (2010)

| Provision | Requirement | Misogi Support |
|-----------|-------------|-----------------|
| Protection Obligation (Section 9) | Reasonable security arrangements | CDR sanitization + TLS + RBAC + PII detection |
| Access/Correction (Section 10) | Provide access and correction | Audit log + JSON output for efficient search |
| Retention (Section 11) | Retain only as long as necessary | Configurable retention policies |
| Data Integrity (Section 12) | Ensure accuracy and completeness | SHA-256 integrity hashing + audit trail |

### 5.2 Thailand PDPA (B.E. 2562)

| Provision | Requirement | Misogi Support |
|-----------|-------------|-----------------|
| Consent (Section 19) | Explicit consent before processing | OIDC consent integration + audit logging |
| Data Subject Rights (Sections 24-30) | Access, correction, deletion, portability | Audit log + storage backend abstraction |
| Cross-Border Transfer (Section 33) | Adequate protection level | CDR sanitization + TLS + local deployment |
| Security Measures (Section 37) | Appropriate security measures | CDR + TLS + RBAC + audit logging |

### 5.3 Philippines DIPA (Republic Act No. 10173)

| Provision | Requirement | Misogi Support |
|-----------|-------------|-----------------|
| Security of Personal Information (Section 20) | Reasonable security measures | CDR + TLS + RBAC + PII detection |
| Access Rights (Section 18) | Data subject access to personal data | Audit log + JSON output |
| Data Breach Notification (Section 20) | Notify affected parties | Real-time alerts + structured logging |
| Accountability (Section 21) | Demonstrate compliance | Comprehensive audit trail + policy documentation |

---

## 6. Cross-Jurisdictional Capability Matrix

| Capability | Singapore PDPA | Indonesia PDP | Malaysia PDPA | Thailand PDPA | Philippines DIPA | Bank Indonesia |
|-----------|---------------|--------------|---------------|---------------|------------------|----------------|
| **Data Minimization** | ✅ (CDR) | ✅ (CDR + SanitizationPolicy) | ✅ (CDR) | ✅ (CDR) | ✅ (CDR) | ✅ (CDR) |
| **Access Control** | ✅ (RBAC) | ✅ (RBAC) | ✅ (RBAC) | ✅ (RBAC) | ✅ (RBAC) | ✅ (RBAC) |
| **Audit Trail** | ✅ (LogEngine) | ✅ (LogEngine) | ✅ (LogEngine) | ✅ (LogEngine) | ✅ (LogEngine) | ✅ (LogEngine) |
| **Consent Management** | — | ✅ (OIDC) | — | ✅ (OIDC) | — | — |
| **Cross-Border Safeguards** | — | ✅ (CDR + Local Deploy) | — | ✅ (CDR + Local Deploy) | — | ✅ (Local Deploy) |
| **Data Residency** | — | — | — | — | — | ✅ (Local Deploy) |
| **Breach Notification** | ✅ (Alerts) | ✅ (Alerts) | ✅ (Alerts) | ✅ (Alerts) | ✅ (Alerts) | ✅ (Alerts) |
| **PII Detection** | ✅ (RegexPIIDetector) | ✅ (RegexPIIDetector) | ✅ (RegexPIIDetector) | ✅ (RegexPIIDetector) | ✅ (RegexPIIDetector) | ✅ (RegexPIIDetector) |

---

## 7. References

All references below point exclusively to official government or regulatory body domains.

| # | Country | Source | URL | Relevance |
|---|---------|--------|-----|-----------|
| 1 | Singapore | **PDPC — Personal Data Protection Commission** | https://www.pdpc.gov.sg/ | Singapore PDPA official guidance and advisory publications |
| 2 | Indonesia | **Kominfo — Ministry of Communication and Informatics** | https://kominfo.go.id/ | Indonesia PDP Law (UU No. 27/2022) and related regulations |
| 3 | Indonesia | **OJK — Financial Services Authority** | https://ojk.go.id/ | Financial sector data protection and cybersecurity regulations |
| 4 | Indonesia | **Bank Indonesia** | https://www.bi.go.id/ | Information security requirements for financial institutions |
| 5 | Malaysia | **KPKT — Ministry of Communications and Multimedia** | https://www.kpkt.gov.my/ | Malaysia PDPA official resources and guidelines |
| 6 | Thailand | **PDPC — Personal Data Protection Committee** | https://pdpc.or.th/ | Thailand PDPA official guidance and compliance resources |
| 7 | Philippines | **NPC — National Privacy Commission** | https://privacy.gov.ph/ | Philippines DIPA (Data Privacy Act) official publications |

---

*This document was produced by the Misogi project.*
*Content is based on official SEA government and regulatory body publications.*
*Last updated: 2026-04-13 | Version: 1.0*
*License: Apache 2.0*

# Misogi Domain Context

> **禊ぎ (Misogi)** — Shinto purification ritual. Every file is impure until proven clean.

---

## Core Domain

Misogi is a **Zero-Trust Content Gateway**. The domain is defined by the principle that **no file is trusted until it has been purified**. Transfer is merely the delivery mechanism; purification is the essential value.

### Domain Statement

```
For any file F entering the system:
  F is assumed malicious until CDR(F) produces a sanitized artifact S
  S is the only artifact permitted to exit the system
```

---

## Glossary

### Core Concepts

| Term | Definition | Japanese | Code Reference |
|------|------------|----------|----------------|
| **Purification** | The act of transforming an untrusted file into a safe artifact through CDR processing. | 浄化 | `FileSanitizer::sanitize()` |
| **Artifact** | A file that has been processed by Misogi. May be "raw" (untrusted input) or "sanitized" (purified output). | 成果物 | `FileInfo`, `FileManifest` |
| **Threat** | Any active content capable of executing code or exfiltrating data: JavaScript, VBA macros, embedded executables, steganographic payloads. | 脅威 | `PdfThreat`, `SanitizationAction` |
| **Active Content** | Document elements that can execute code or trigger external requests: scripts, macros, forms, annotations, embedded files. | 能動的コンテンツ | — |
| **True CDR** | Content Disarm and Reconstruction that parses, analyzes, and rebuilds files from safe components only. No signature matching; proactive threat elimination. | 真のCDR | `PdfTrueCdrEngine`, `OoxmlTrueCdrEngine` |

### CDR Domain

| Term | Definition | Japanese | Code Reference |
|------|------------|----------|----------------|
| **Sanitization Policy** | Strategy governing how aggressively to strip content. Three tiers: `StripActiveContent`, `ConvertToFlat`, `TextOnly`. | サニタイズポリシー | `SanitizationPolicy` |
| **Sanitization Report** | Immutable audit record of every action taken during purification. Serves as legal evidence chain. | サニタイズレポート | `SanitizationReport` |
| **Sanitization Action** | Individual remediation performed on a file: e.g., `PdfJsRemoved`, `VbaMacroRemoved`, `ZipEntrySanitized`. | サニタイズアクション | `SanitizationAction` |
| **PPAP** | Password Protected Attachment Protocol — a social engineering attack vector using encrypted ZIP attachments. | PPAP | `PpapDetector`, `PpapHandler` |
| **Steganography** | Hidden data embedded within image pixels or audio samples. Detected but not removed by Misogi. | ステガノグラフィ | `SteganographyDetector` |

### Transfer Domain

| Term | Definition | Japanese | Code Reference |
|------|------------|----------|----------------|
| **Sender** | Node that initiates file transfers. Uploads files, applies CDR, streams chunks to Receiver. | 送信者 | `misogi-sender` crate |
| **Receiver** | Node that accepts file transfers. Receives chunks, reassembles files, stores to backend. | 受信者 | `misogi-receiver` crate |
| **Chunk** | Fixed-size block of file data (default 1MB). Unit of streaming transfer. | チャンク | `ChunkMeta`, `ChunkData` |
| **Manifest** | Complete metadata for a file transfer: ID, size, hash, chunk list, status. | マニフェスト | `FileManifest` |
| **Transfer** | The act of moving an artifact from Sender to Receiver. Always preceded by purification. | 転送 | `FileTransferRequest` |
| **FEC** | Forward Error Correction — Reed-Solomon encoding for chunk loss recovery. | 誤り訂正 | `fec::ReedSolomon` |

### Authentication Domain

| Term | Definition | Japanese | Code Reference |
|------|------------|----------|----------------|
| **User** | Human or service account with assigned role and permissions. | ユーザ | `User` |
| **Role** | Authorization tier: `Staff` (upload only), `Approver` (can approve), `Admin` (full access). | 役割 | `UserRole` |
| **Permission** | Fine-grained capability: 9 discrete actions (upload, download, approve, manage users, etc.). | 権限 | `PermissionAction`, `Permissions` |
| **Session Token** | Lightweight bearer token for authentication. Bound to user and device fingerprint. | セッショントークン | `SessionToken` |
| **Identity Provider** | External authentication source: LDAP/AD, OIDC, SAML. | IDプロバイダ | `IdentityProvider` trait |
| **Device Fingerprint** | Stable identifier derived from User-Agent, Canvas hash, screen resolution. | デバイス指紋 | `DeviceFingerprint` |
| **Device Posture** | Security assessment of client device: OS version, AV status, patch compliance. | デバイス姿勢 | `DevicePosture`, `PostureChecker` |

### Audit Domain

| Term | Definition | Japanese | Code Reference |
|------|------------|----------|----------------|
| **Audit Entry** | Immutable record of a security-relevant event. Hash-chained for tamper detection. | 監査記録 | `AuditLogEntry` |
| **Event Hash** | SHA-256 hash of audit entry, linked to previous entry hash for chain integrity. | イベントハッシュ | `hash::sha256()` |
| **CEF** | Common Event Format — syslog standard for security events. | CEF形式 | `LogFormatter` trait |

### PII Domain

| Term | Definition | Japanese | Code Reference |
|------|------------|----------|----------------|
| **PII** | Personally Identifiable Information: names, addresses, phone numbers, etc. | 個人情報 | `PIIDetector` trait |
| **PII Match** | Detected instance of PII with type, location, and confidence score. | PII一致 | `PIIMatch` |
| **Context Analysis** | Surrounding text analysis to reduce false positives in PII detection. | 文脈分析 | `ContextAnalyzer` |
| **Secrecy Classification** | Sensitivity level assignment per Japanese secrecy scheme (秘, 秘密, 極秘). | 秘密度分類 | `SecrecyClassifier` |

---

## Bounded Contexts

### CDR Context

**Responsibility**: Transform untrusted files into safe artifacts.

```
Input:  Raw file bytes (untrusted)
Output: Sanitized file bytes + SanitizationReport (trusted)
Invariant: No active content survives the transformation
```

**Key Invariants**:
- Memory bounded: Never load entire file into memory
- Streaming safe: Process in fixed-size chunks
- Audit complete: Every action logged to SanitizationReport

### Transfer Context

**Responsibility**: Move artifacts between Sender and Receiver nodes.

```
Input:  Sanitized artifact + FileManifest
Output: Stored artifact at destination
Invariant: Artifact integrity verified via hash chain
```

**Key Invariants**:
- Chunk integrity: Each chunk has MD5 hash
- File integrity: Reassembled file matches manifest hash
- Resume capability: Partial transfers can resume from last acknowledged chunk

### Auth Context

**Responsibility**: Authenticate users and authorize actions.

```
Input:  Credentials (JWT, LDAP, OIDC, SAML)
Output: User + Permissions
Invariant: Every action requires explicit permission check
```

**Key Invariants**:
- Token validity: RS256 signature verified, expiration checked
- Role hierarchy: Staff < Approver < Admin
- Device binding: Session token bound to device fingerprint (optional)

### Audit Context

**Responsibility**: Record security-relevant events immutably.

```
Input:  Event (transfer, sanitization, auth, etc.)
Output: AuditLogEntry with hash chain
Invariant: Entries are append-only, hash-chained, tamper-evident
```

**Key Invariants**:
- Write-only: No modification or deletion of entries
- Hash-chained: Each entry includes hash of previous entry
- Retention: Configurable retention policy per compliance requirements

---

## Domain Relationships

```
┌─────────────────────────────────────────────────────────────────┐
│                        Misogi Domain                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   User ──┬── authenticates via ──► IdentityProvider             │
│          │                                                      │
│          └── has role ──► UserRole ──► Permissions              │
│                                                                 │
│   Artifact ──┬── raw (untrusted)                                │
│               │                                                 │
│               └── sanitized (trusted) ◄── purified by ── CDR    │
│                                                                 │
│   Transfer ──┬── initiated by ──► Sender                        │
│               │                                                 │
│               └── received by ──► Receiver                      │
│                                                                 │
│   SanitizationReport ──► AuditEntry ──► AuditLog               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Anti-Corruption Patterns

### Term Conflicts to Avoid

| ❌ Avoid | ✅ Use Instead | Reason |
|----------|----------------|--------|
| "Clean file" | "Sanitized artifact" | "Clean" is ambiguous; "sanitized artifact" is precise |
| "Scan" | "Purify" or "Sanitize" | Misogi does not scan for signatures; it proactively removes threats |
| "Upload" | "Transfer (initiated by Sender)" | Upload is implementation detail; Transfer is domain concept |
| "User" (in CDR context) | — | CDR context has no User concept; keep contexts separate |
| "File" (ambiguous) | "Artifact" or "Raw file" | Distinguish between untrusted input and processed output |

### Boundary Rules

1. **CDR Context** does not know about Users or Transfers
2. **Auth Context** does not know about Artifacts or Chunks
3. **Transfer Context** does not know about Sanitization internals
4. **Audit Context** observes all but modifies none

---

## Compliance Mapping

| Domain Concept | GDPR | NIS2 | LGWAN | PDPA |
|----------------|------|------|-------|------|
| PII Detection | Art. 32 (Security) | Art. 21 (Risk Mgmt) | 個人情報保護 | Section 9 |
| Audit Trail | Art. 30 (Records) | Art. 23 (Logging) | 監査記録 | Section 13 |
| Device Posture | — | Art. 20 (Supply Chain) | 端末セキュリティ | — |
| Sanitization Report | Art. 5 (Accountability) | Art. 24 (Evidence) | 証跡 | Section 14 |

---

## Version History

| Date | Change | Author |
|------|--------|--------|
| 2026-06-08 | Initial domain context creation | grill-with-docs |

---

*"Every file is impure until proven clean." — Misogi Principle*

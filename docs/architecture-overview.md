# Misogi Architecture Overview

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Misogi Secure File Transfer                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         API Layer (CLI/REST)                         │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                       │
│                                      ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      Authorization Layer                             │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │              ABAC Engine (NIST SP 800-162)                   │    │    │
│  │  │  • Policy evaluation  • Approval workflows  • Hot reload     │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                       │
│                                      ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                       Processing Layer                               │    │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐            │    │
│  │  │   CDR v2      │  │   Scanner     │  │   Reporter    │            │    │
│  │  │   Engine      │  │               │  │               │            │    │
│  │  └───────────────┘  └───────────────┘  └───────────────┘            │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                       │
│                                      ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                       Transport Layer                                │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │              Self-Healing Integrity Layer                    │    │    │
│  │  │  • Session management  • Verification  • Auto-repair         │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │              Multi-Tier Relay Mesh                           │    │    │
│  │  │  • Circuit breaker  • Heartbeat  • Strategy selection        │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                       │
│                                      ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                       Storage Layer                                  │    │
│  │  • File system  • Database (PostgreSQL)  • Audit logs               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Multi-Tier Relay Mesh

**Purpose**: Secure multi-hop file transfer across network boundaries.

**Key Features**:
- **Circuit Breaker**: Automatic failure detection and recovery
- **Heartbeat**: Connection health monitoring
- **Strategy Selection**: Adaptive routing based on network conditions
- **Max Hops Control**: Prevent infinite relay loops

**Configuration**: See [relay-mesh-config.md](relay-mesh-config.md)

**Source**: [relay/config.rs](../crates/misogi-core/src/relay/config.rs)

---

### 2. CDR v2 Engine

**Purpose**: Content Disarm and Reconstruction for secure file processing.

**Key Features**:
- **PDF Processing**: JavaScript removal, embedded file extraction, metadata sanitization
- **Office Processing**: Macro removal, OLE sanitization, external link removal
- **Archive Processing**: Depth control, file count limits, bomb detection
- **Whitelist**: Extension and MIME type filtering

**Configuration**: See [cdr-v2-config.md](cdr-v2-config.md)

**Source**: [cdr_v2/config.rs](../crates/misogi-core/src/cdr_v2/config.rs)

---

### 3. Self-Healing Integrity Layer

**Purpose**: End-to-end data integrity verification with automatic repair.

**Key Features**:
- **SessionManager**: Transfer session lifecycle management
- **IntegrityVerifier**: Multi-algorithm verification (SHA-256, SHA-512, BLAKE3)
- **RepairEngine**: Automatic corruption detection and block-level repair
- **HealingTransport**: Transparent integrity layer with auto-retry

**Configuration**: See [integrity-config.md](integrity-config.md)

**Source**: [integrity/mod.rs](../crates/misogi-core/src/integrity/mod.rs)

---

### 4. ABAC Engine

**Purpose**: Attribute-Based Access Control following NIST SP 800-162.

**Key Features**:
- **Policy Rules**: Priority-based evaluation with deny precedence
- **Condition Operators**: Eq, Neq, In, NotIn, Gt, Lt, Regex, IpInRange
- **Approval Workflows**: Multi-approver support with timeout handling
- **Hot Reload**: Runtime policy updates without restart
- **Decision Caching**: TTL-based cache for performance

**Configuration**: See [abac-config.md](abac-config.md)

**Source**: [abac/config.rs](../crates/misogi-core/src/abac/config.rs)

---

## Data Flow

```
┌─────────────┐
│   Client    │
│  Request    │
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌─────────────┐
│   ABAC      │────▶│   Deny?     │──Yes──▶ ┌─────────────┐
│   Engine    │     │   Check     │         │   Reject    │
└──────┬──────┘     └─────────────┘         └─────────────┘
       │ No
       ▼
┌─────────────┐
│   CDR v2    │
│   Process   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Integrity  │
│  Envelope   │
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌─────────────┐
│   Relay     │────▶│  Multi-hop  │
│   Mesh      │     │  Transfer   │
└──────┬──────┘     └─────────────┘
       │
       ▼
┌─────────────┐
│  Integrity  │
│  Verify     │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Storage   │
└─────────────┘
```

---

## Security Model

### Defense in Depth

1. **Network Layer**: TLS encryption, certificate validation
2. **Transport Layer**: Integrity verification, self-healing
3. **Processing Layer**: CDR sanitization, whitelist enforcement
4. **Authorization Layer**: ABAC policy evaluation
5. **Storage Layer**: Audit logging, access control

### Fail-Closed Defaults

- ABAC: `default_effect = "deny"` - deny when no rule matches
- Integrity: Reject on verification failure
- CDR: Reject unknown file types
- Relay: Disable by default (`enabled = false`)

### Zero-Trust Principles

- Every request is authenticated and authorized
- No implicit trust based on network location
- All operations are logged for audit
- Secrets are never stored in plaintext

---

## Related Documentation

| Document | Description |
|----------|-------------|
| [relay-mesh-config.md](relay-mesh-config.md) | Relay Mesh configuration guide |
| [cdr-v2-config.md](cdr-v2-config.md) | CDR v2 configuration guide |
| [integrity-config.md](integrity-config.md) | Integrity layer configuration guide |
| [abac-config.md](abac-config.md) | ABAC configuration guide |
| [enterprise-deployment.md](enterprise-deployment.md) | Enterprise deployment guide |

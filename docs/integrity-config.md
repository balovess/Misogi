# Self-Healing Integrity Configuration Guide

## Overview

The Self-Healing Integrity Layer provides end-to-end data integrity verification with automatic repair capabilities. It ensures that files remain intact throughout the transfer process, detecting and recovering from corruption automatically.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Source    │────▶│  Integrity  │────▶│   Transfer  │────▶│  Integrity  │
│   File      │     │  Envelope   │     │   Channel   │     │  Verify     │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                           │                                         │
                           │         Checksum                        │
                           └─────────────────────────────────────────┘
```

---

## Core Components

### IntegrityConfig

Top-level configuration for the integrity subsystem.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable integrity verification |
| `algorithm` | `String` | `"blake3"` | Hash algorithm |
| `session_timeout_secs` | `u64` | `3600` | Session timeout |
| `auto_repair` | `bool` | `true` | Enable automatic repair |
| `max_repair_attempts` | `u32` | `3` | Maximum repair attempts |

---

### IntegrityEnvelope

Wraps file data with integrity metadata for transfer.

```
┌─────────────────────────────────────────────────────────────┐
│                    IntegrityEnvelope                        │
├─────────────────────────────────────────────────────────────┤
│  checksum: String           # BLAKE3/SHA-256/SHA-512 hash   │
│  algorithm: String          # Algorithm identifier          │
│  size: u64                  # Original file size            │
│  block_size: u32            # Block size for chunking       │
│  block_checksums: Vec<String>  # Per-block checksums        │
│  metadata: HashMap<String, String>  # Custom metadata       │
│  version: u32               # Envelope format version       │
│  timestamp: DateTime        # Creation timestamp            │
└─────────────────────────────────────────────────────────────┘
```

---

### SessionManager

Manages transfer session lifecycle and state persistence.

```
┌─────────────────────────────────────────────────────────────┐
│                     SessionManager                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐    │
│  │   Create    │────▶│   Active    │────▶│  Complete   │    │
│  │   Session   │     │   Session   │     │   Session   │    │
│  └─────────────┘     └─────────────┘     └─────────────┘    │
│         │                   │                   │            │
│         │                   │                   │            │
│         ▼                   ▼                   ▼            │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐    │
│  │  Persist    │     │   Update    │     │   Archive   │    │
│  │   State     │     │   Progress  │     │   Session   │    │
│  └─────────────┘     └─────────────┘     └─────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Session States**:

| State | Description |
|-------|-------------|
| `Created` | Session initialized, awaiting transfer |
| `Active` | Transfer in progress |
| `Paused` | Transfer paused, can resume |
| `Complete` | Transfer finished, verified |
| `Failed` | Transfer failed, may retry |
| `Expired` | Session timed out |

---

### IntegrityVerifier

Performs multi-algorithm integrity verification.

**Supported Algorithms**:

| Algorithm | Identifier | Use Case |
|-----------|------------|----------|
| BLAKE3 | `blake3` | Default, high performance |
| SHA-256 | `sha256` | FIPS 140-2 compliance |
| SHA-512 | `sha512` | High security requirements |

**Verification Modes**:

1. **Full Verification**: Hash entire file
2. **Incremental Verification**: Hash blocks as received
3. **Parallel Verification**: Multi-threaded block verification

```
┌─────────────┐
│   Input     │
│   File      │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│                    IntegrityVerifier                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   Block 1   │  │   Block 2   │  │   Block N   │          │
│  │   Hash      │  │   Hash      │  │   Hash      │          │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │
│         │                │                │                  │
│         └────────────────┴────────────────┘                  │
│                          │                                    │
│                          ▼                                    │
│                   ┌─────────────┐                            │
│                   │   Compare   │                            │
│                   │   Hashes    │                            │
│                   └──────┬──────┘                            │
│                          │                                    │
│              ┌───────────┴───────────┐                       │
│              ▼                       ▼                       │
│       ┌─────────────┐         ┌─────────────┐               │
│       │    PASS     │         │    FAIL     │               │
│       └─────────────┘         └─────────────┘               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

### RepairEngine

Automatically detects and repairs corrupted data.

**Repair Strategies**:

| Strategy | Description | Use Case |
|----------|-------------|----------|
| `retransfer` | Re-transfer corrupted blocks | Network corruption |
| `redundancy` | Use redundant copies | High availability |
| `parity` | Use parity data | Forward error correction |

**Repair Flow**:

```
┌─────────────┐
│  Corrupted  │
│   Block     │
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌─────────────┐
│   Detect    │────▶│   Identify  │
│   Failure   │     │   Blocks    │
└─────────────┘     └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │   Select    │
                    │   Strategy  │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
       ┌───────────┐ ┌───────────┐ ┌───────────┐
       │Retransfer │ │ Redundancy│ │  Parity   │
       └─────┬─────┘ └─────┬─────┘ └─────┬─────┘
             │             │             │
             └─────────────┴─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │   Verify    │
                    │   Repair    │
                    └─────────────┘
```

---

### HealingTransport

Transparent integrity layer that wraps the transport channel.

```
┌─────────────────────────────────────────────────────────────┐
│                     HealingTransport                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                   Transport Layer                    │    │
│  └─────────────────────────────────────────────────────┘    │
│                          │                                   │
│                          ▼                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Integrity Envelope Wrap                 │    │
│  └─────────────────────────────────────────────────────┘    │
│                          │                                   │
│                          ▼                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Auto-Retry on Failure                   │    │
│  └─────────────────────────────────────────────────────┘    │
│                          │                                   │
│                          ▼                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Progress Tracking                       │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Configuration Example

```toml
[integrity]
enabled = true
algorithm = "blake3"
session_timeout_secs = 3600
auto_repair = true
max_repair_attempts = 3

[integrity.block]
size = 65536          # 64KB blocks
parallel_verification = true
max_parallel_jobs = 4

[integrity.session]
persistence = "database"  # "memory" or "database"
cleanup_interval_secs = 300
max_active_sessions = 1000

[integrity.repair]
strategy = "retransfer"
timeout_secs = 60
backoff_multiplier = 2.0
```

---

## Recovery Scenarios

### Network Interruption

```
┌─────────────┐                    ┌─────────────┐
│   Source    │ ──── X ─────────── │   Target    │
│             │      Network       │             │
└─────────────┘      Down          └─────────────┘
       │
       ▼
┌─────────────┐
│   Session   │ ──▶ State persisted
│   Paused    │
└─────────────┘
       │
       │ Network restored
       ▼
┌─────────────┐
│   Resume    │ ──▶ Continue from last verified block
│   Transfer  │
└─────────────┘
```

### Partial Corruption

```
┌─────────────┐
│   Block 5   │ ──▶ Checksum mismatch
│   Corrupted │
└─────────────┘
       │
       ▼
┌─────────────┐
│   Repair    │ ──▶ Re-transfer block 5
│   Engine    │
└─────────────┘
       │
       ▼
┌─────────────┐
│   Verify    │ ──▶ Confirm repair
│   Success   │
└─────────────┘
```

### Checksum Mismatch

```
┌─────────────┐                    ┌─────────────┐
│   Source    │ ──▶ Hash: abc123   │   Target    │
│             │                    │   Hash: xyz789
└─────────────┘                    └─────────────┘
                                           │
                                           ▼
                                    ┌─────────────┐
                                    │   Detect    │
                                    │   Mismatch  │
                                    └──────┬──────┘
                                           │
                                           ▼
                                    ┌─────────────┐
                                    │   Full      │
                                    │   Retransfer│
                                    └─────────────┘
```

---

## Best Practices

### Performance

- Use BLAKE3 for best performance
- Enable parallel verification for large files
- Set block size to 64KB-1MB for optimal throughput

### Reliability

- Enable auto-repair for production
- Set max_repair_attempts >= 3
- Use database persistence for session state

### Security

- Use SHA-256 for FIPS compliance
- Verify both file hash and block hashes
- Log all verification failures

---

## Related Documentation

- [architecture-overview.md](architecture-overview.md) - System architecture
- [relay-mesh-config.md](relay-mesh-config.md) - Relay mesh configuration
- [enterprise-deployment.md](enterprise-deployment.md) - Deployment guide

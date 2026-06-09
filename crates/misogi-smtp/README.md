# misogi-smtp

**SMTP Email Sanitization Gateway — intercepts emails, extracts attachments, routes through CDR pipeline, reassembles clean emails**

![Rust 2024](https://img.shields.io/badge/Rust-2024-orange) ![License](https://img.shields.io/badge/License-Apache--2.0-blue)

## Architecture Overview

```
┌─────────────┐    SMTP     ┌──────────────────┐   Parse    ┌─────────────┐
│  Mail Client │ ──────────> │  Misogi SMTP GW  │ ─────────> │ MIME Handler│
└─────────────┘             └──────────────────┘            └──────┬──────┘
                                                                   │
                                                                   v
                                                            ┌─────────────┐
                            Extract Attachments             │ CDR Pipeline │
                            <────────────────────────────── │ (misogi-cdr) │
                                                                   │
                                                                   v
                                                            ┌─────────────┐
                            Reassemble Clean Email          │ Delivery Q  │
                            <────────────────────────────── │ (lettre)    │
                                                                   │
                                                                   v
                                                            ┌─────────────┐
                            Relay Sanitized Email            │ Destination │
                            ──────────────────────────────> │ Mail Server │
                                                            └─────────────┘
```

## Operational Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **TransparentProxy** | Listens on SMTP ports (25/587), processes messages, relays to downstream | MTA replacement or inline gateway |
| **Pickup** | Watches directory for `.eml` files, processes each as it appears | Integration with Postfix `pickup` daemon |

## Zone-Based Policy Enforcement

The gateway classifies each email into one of four zone categories:

| Classification | Policy Behavior |
|----------------|-----------------|
| Internal → Internal | Standard sanitization policy |
| Internal → External | Stricter policy override (outbound enforcement) |
| External → Internal | Standard + PII scan (inbound threat focus) |
| External → External | Standard policy (transit only) |

## Key Public API

- **`SmtpServer`** — Async SMTP server with configurable listeners
- **`MimeHandler`** — MIME parsing and attachment extraction
- **`SanitizePipeline`** — CDR processing orchestration
- **`DeliveryQueue`** — Outbound email delivery via lettre

## Key Dependencies

- `lettre`: SMTP client for outbound delivery
- `mailparse`: MIME message parsing
- `misogi-cdr`: Content Disarm and Reconstruction engine
- `tokio`: Async runtime

## Security Guarantees

- ✅ All attachments processed through CDR pipeline before delivery
- ✅ Executable attachments blocked by default
- ✅ Password-protected archives blocked (cannot inspect interior)
- ✅ S/MIME encrypted content detected and flagged for quarantine
- ✅ Full audit trail via `SanitizationReport` per attachment

> **Note**: DKIM signatures are invalidated after sanitization (expected behavior)

## Quick Example

```rust
use misogi_smtp::server::SmtpServer;
use misogi_smtp::sanitize_pipeline::SanitizePipeline;

// Start SMTP gateway
let server = SmtpServer::bind("0.0.0.0:25").await?;
server.run().await?;
```

## Full Documentation

For complete configuration options, zone policy details, and deployment patterns, see the [root README](../../README.md).

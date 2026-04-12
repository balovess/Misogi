//! Misogi SMTP Gateway — Email Sanitization via CDR Pipeline.
//!
//! This crate provides an SMTP server that intercepts incoming email messages,
//! extracts attachments, routes them through the Misogi Content Disarm and
//! Reconstruction (CDR) pipeline, and reassembles sanitized emails for delivery.
//!
//! # Architecture Overview
//!
//! ```text
//! ┌─────────────┐    SMTP     ┌──────────────────┐   Parse    ┌─────────────┐
//! │  Mail Client │ ──────────> │  Misogi SMTP GW  │ ─────────> │ MIME Handler│
//! └─────────────┘             └──────────────────┘            └──────┬──────┘
//!                                                                    │
//!                                                                    v
//!                                                             ┌─────────────┐
//!                             Extract Attachments             │ CDR Pipeline │
//!                             <────────────────────────────── │ (misogi-cdr) │
//!                                                                    │
//!                                                                    v
//!                                                             ┌─────────────┐
//!                             Reassemble Clean Email          │ Delivery Q  │
//!                             <────────────────────────────── │ (lettre)    │
//!                                                                    │
//!                                                                    v
//!                                                             ┌─────────────┐
//!                             Relay Sanitized Email            │ Destination │
//!                             ──────────────────────────────> │ Mail Server │
//!                                                             └─────────────┘
//! ```
//!
//! # Operational Modes
//!
//! - **TransparentProxy**: Listens on standard SMTP ports (25/587), accepts
//!   connections from mail clients or upstream MTAs, processes each message,
//!   and relays sanitized output to the configured downstream SMTP host.
//! - **Pickup**: Watches a configurable directory for `.eml` files (maildrop
//!   directory pattern), processing each file as it appears. Suitable for
//!   integration with MTA queue injection (e.g., Postfix `pickup` daemon).
//!
//! # Zone-Based Policy Enforcement
//!
//! The gateway classifies each email into one of four zone categories based on
//! sender and recipient domains relative to a configured set of internal domains:
//!
//! | Classification        | Policy Behavior                              |
//! |-----------------------|-----------------------------------------------|
//! | Internal → Internal   | Standard sanitization policy                  |
//! | Internal → External   | Stricter policy override (outbound enforcement)|
//! | External → Internal   | Standard + PII scan (inbound threat focus)    |
//! | External → External   | Standard policy (transit only)               |
//!
//! # Security Guarantees
//!
//! - All attachments are processed through the CDR pipeline before delivery
//! - Executable attachments are blocked by default regardless of content scan
//! - Password-protected archives are blocked (cannot inspect interior contents)
//! - S/MIME encrypted content is detected and flagged for quarantine review
//! - DKIM signatures are invalidated after sanitization (expected behavior)
//! - Full audit trail via `SanitizationReport` per attachment

pub mod delivery;
pub mod error;
pub mod mime_handler;
pub mod sanitize_pipeline;
pub mod server;

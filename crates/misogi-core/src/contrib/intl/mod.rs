//! International / region-agnostic compliance rule pack.
//!
//! This module provides universal CDR policies and detection rules applicable
//! across all regions, independent of any single country's regulatory framework:
//!
//! - **Common Malicious PDF Signatures** — Known exploit vectors in PDF files
//! - **Universal PII Patterns** — Credit cards, IBAN, email addresses (global scope)
//! - **NIST/ISO Baseline Policies** — Security controls aligned with international standards
//!
//! # When to Use This Module
//!
//! Use `contrib/intl` when deploying Misogi in environments that:
//! - Do NOT require country-specific calendar/encoding support
//! - Need baseline CDR protection against common threats
//! - Operate under international frameworks (NIST, ISO 27001, CIS Controls)
//! - Serve multi-national organizations with mixed compliance requirements

pub mod common_pii;
pub mod universal_cdr;

pub use common_pii::{InternationalPiiPatterns, PiiRulePack};
pub use universal_cdr::{MaliciousPdfSignature, UniversalCdrPolicy};

//! Contributed modules for regional compliance and locale-specific extensions.
//!
//! This module tree contains optional, region-specific functionality that
//! extends the core Misogi system with localized requirements per country
//! or regulatory domain:
//!
//! # Module Structure
//!
//! ## Current Modules
//!
//! - [`jp`] — Japanese (日本) compliance modules:
//!   - [`calendar`](jp::calendar) — Imperial era (Wareki/和暦) calendar, national holidays
//!   - [`vendor`](jp::vendor) — Multi-tenant vendor (取引先) access control
//!   - [`encoding`](jp::encoding) — Legacy text encodings (Shift-JIS, EUC-JP, JIS)
//!   - [`external_adapter`](jp::external_adapter) — External sanitizer adapters (一太郎, CAD)
//!
//! ## Planned Modules (Future Work)
//!
//! - `kr` — Korean (한국) compliance under FSS (Financial Supervisory Service):
//!   - EUC-KR / CP949 encoding support
//!   - Korean financial document handling (HWP format)
//!   - FSS network separation audit trail requirements
//!
//! - `intl` — International / region-agnostic compliance packs:
//!   - NIST Zero Trust Architecture (ZTA) CDR policies
//!   - GDPR data subject identification patterns
//!   - ACSC (Australian Cyber Security Centre) CDS guidelines
//!   - Common malicious PDF variant signatures (universal threat patterns)
//!
//! # Design Philosophy
//!
//! These modules are **contributed** (not core) because:
//! 1. They implement region-specific regulations that do not apply globally.
//! 2. They introduce additional dependencies beyond the minimal core set.
//! 3. They can be conditionally compiled via Cargo features for each target region.
//! 4. SIer (System Integrators) can mix-and-match contrib packages for their market.
//!
//! # Feature Flags
//!
//! ```toml
//! [features]
//! default = []
//! jp_contrib = []          # Enable Japanese compliance modules
//! kr_contrib = []          # Enable Korean compliance modules (planned)
//! intl_contrib = []        # Enable international compliance pack (planned)
//! ```
//!
//! All modules in this tree follow rigorous documentation standards with
//! comprehensive English comments suitable for international code review.

#[cfg(feature = "jp_contrib")]
pub mod jp;

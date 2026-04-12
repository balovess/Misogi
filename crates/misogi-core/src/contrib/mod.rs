//! Contributed modules for regional compliance and locale-specific extensions.
//!
//! This module tree contains **opt-in**, region-specific functionality that
//! extends the core Misogi system with localized requirements per country
//! or regulatory domain. **No contrib module is included by default.**
//!
//! # Architecture: Core-First, Region-Opt-In
//!
//! ```text
//! ┌─────────────────────────┐
//! │     misogi-core         │
//! │  (zero regional deps)   │
//! └──────┬──────────┬────────┘
//!        │          │
//! ┌──────▼──┐  ┌────▼────────────┐
//! │ jp_contrib│  │ intl_contrib  │
//! │ (opt-in) │  │ (opt-in)       │
//! └──────────┘  └────────────────┘
//! ```
//!
//! The core crate compiles cleanly with zero regional dependencies. Each region
//! must be explicitly enabled via Cargo feature flag at build time.
//!
//! # Module Structure
//!
//! ## Japanese — [`jp`] (feature: `jp_contrib`)
//!
//! Enabled with: `cargo build --features jp_contrib`
//!
//! - [`calendar`](jp::calendar) — Imperial era (Wareki/和暦) calendar, national holidays per 祝日法
//! - [`vendor`](jp::vendor) — Multi-tenant vendor (取引先) access control per ベンダー管理規定
//! - [`encoding`](jp::encoding) — Legacy text encodings (Shift-JIS, EUC-JP, JIS)
//! - [`external_adapter`](jp::external_adapter) — External sanitizer adapters (一太郎, CAD)
//!
//! ## International — [`intl`](intl) (feature: `intl_contrib`)
//!
//! Enabled with: `cargo build --features intl_contrib`
//!
//! - [`common_pii`](intl::common_pii) — Universal PII patterns (SSN, credit card, etc.)
//! - [`universal_cdr`](intl::universal_cdr) — Region-agnostic CDR policies (NIST, ACSC, GDPR)
//!
//! ## Planned Modules (Future Work)
//!
//! - `kr` — Korean (한국) compliance under FSS (Financial Supervisory Service):
//!   - EUC-KR / CP949 encoding support
//!   - Korean financial document handling (HWP format)
//!   - FSS network separation (네트워크 분리) audit trail requirements
//!
//! # Design Principles
//!
//! These modules are **contributed** (not core) because:
//!
//! 1. **Regional specificity** — They implement country-specific regulations that do not apply globally.
//! 2. **Dependency isolation** — They introduce additional crate dependencies beyond the minimal core set.
//! 3. **Compile-time selection** — Conditionally compiled via Cargo features; dead code elimination for unused regions.
//! 4. **Market flexibility** — SIer (System Integrators) mix-and-match contrib packages for their target market.
//!
//! # Feature Flags
//!
//! ```toml
//! [features]
//! default = []               # ← No regional modules included by design
//! jp_contrib = []            # Japanese compliance (calendar, vendor, encoding, external tools)
//! intl_contrib = []          # International compliance pack (common PII, universal CDR)
//! kr_contrib = []            # Korean compliance (planned)
//! ```
//!
//! # Plugin vs Feature Gate
//!
//! | Mechanism | Scope | When to Use |
//! |-----------|-------|-------------|
//! | **Feature gate** (`[features]`) | Compile-time inclusion of entire module tree | Regional compliance packs |
//! | **Plugin registry** ([`plugin_registry`]) | Runtime dynamic loading | Third-party strategy implementations |
//!
//! Feature gates are for "baked-in" regional support that must exist at compile time
//! (e.g., Japanese encoding handlers that call into `encoding_rs`). The plugin registry
//! is for runtime-extensible behavior (e.g., custom CDR strategies loaded from shared libraries).
//!
//! All modules in this tree follow rigorous documentation standards with
//! comprehensive English comments suitable for international code review.

#[cfg(feature = "jp_contrib")]
pub mod jp;

#[cfg(feature = "intl_contrib")]
pub mod intl;

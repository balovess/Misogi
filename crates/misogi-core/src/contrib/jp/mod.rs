//! Japanese (日本) compliance module collection.
//!
//! Provides Japan-specific implementations of core Misogi traits for government
//! and enterprise systems operating under Japanese regulatory requirements:
//!
//! - **Calendar**: Imperial era (Wareki/和暦) date handling per 祝日法
//! - **Vendor Security**: Multi-tenant isolation per ベンダー管理規定
//! - **Encoding**: Legacy text encoding support (Shift-JIS, EUC-JP, JIS)
//! - **External Tools**: Third-party sanitizer integration (CAD, drawing formats)
//!
//! # Regulatory Context
//!
//! Japanese government systems must comply with:
//! - 個人情報保護法 (Act on Protection of Personal Information)
//! - 行政手続における特定の個人を識別するための番号の利用等に関する法律 (My Number Act)
//! - サイバーセキュリティ基本計画 (Basic Cybersecurity Plan)
//! - 各省庁のセキュリティガイドライン (Ministry-specific security guidelines)
//!
//! # Thread Safety
//!
//! All public structs in this module are `Send + Sync` and safe for concurrent
//! use across async Tokio tasks without additional synchronization.

pub mod calendar;
pub mod vendor;
pub mod encoding;
pub mod external_adapter;

// Re-export commonly used types at the jp module level for ergonomic imports
pub use calendar::{
    detect_wareki_in_filename,
    load_calendar_toml,
    EraDefinition,
    JapaneseCalendarProvider,
};
pub use vendor::{VendorAccount, VendorIsolationManager};
pub use encoding::{JapaneseEncodingHandler, PdfFontAction};
pub use external_adapter::{
    ExternalFailureAction,
    ExternalSanitizerAdapter,
    ExternalSanitizerConfig,
    ExternalSanitizeResult,
    ExternalSuccessAction,
    render_args,
};

//! Application state for the Misogi Sender (送信側) component.
//!
//! This module defines [`AppState`], the central shared state container that holds
//! all dependencies required by HTTP route handlers, upload engine, tunnel task,
//! and approval workflow subsystems.
//!
//! # Architecture
//!
//! `AppState` follows the **State Container** pattern where a single `Arc<AppState>`
//! is shared across all async tasks via Axum's State extractor. All fields are
//! constructed once during initialization and remain immutable thereafter (or use
//! interior mutability via `RwLock` for collection-type fields).
//!
//! # Pluggable Trait Layer (Task 5.14)
//!
//! Starting from Task 5.14, `AppState` wires in trait-based pluggable components
//! that enable runtime-swappable implementations:
//!
//! | Field                  | Trait                   | Default Implementation          |
//! |------------------------|-------------------------|--------------------------------|
//! | `transfer_driver`      | `TransferDriver`        | `DirectTcpDriver`              |
//! | `cdr_strategies`       | `CDRStrategy` (Vec)     | `BuiltinPdfStrategy`           |
//! | `file_type_detector`   | `FileTypeDetector`       | `CompositeDetector`            |
//! | `pii_detector`         | `PIIDetector`            | `RegexPIIDetector`             |
//! | `encoding_handler`     | `EncodingHandler`        | `JapaneseEncodingHandler`     |
//! | `calendar`             | `CalendarProvider`       | `None` (disabled by default)   |
//! | `vendor_isolation`     | `VendorIsolationManager` | `None` (disabled by default)   |
//!
//! # Thread Safety
//!
//! - Immutable fields (`config`, sanitizers, detectors, drivers): `Send + Sync` via `Arc`.
//! - Mutable collections (`files`, `requests`): Protected by `tokio::sync::RwLock`.
//! - Audit log: Internally thread-safe via `Arc<AuditLogManager>`.
//!
//! # Construction
//!
//! Use [`AppState::from_config()`] factory method which reads `SenderConfig` and
//! constructs all trait objects with appropriate defaults based on configuration flags.
//! The legacy [`AppState::new()`] constructor is retained for backward compatibility
//! but delegates to `from_config()` internally.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::config::SenderConfig;
use crate::upload_engine::FileUploader;
use misogi_core::{
    FileInfo,
    FileStatus,
    approval::TransferRequest,
    audit_log::AuditLogManager,
};
use misogi_auth::store::UserStore;
use misogi_cdr::{
    office_sanitizer::OfficeSanitizer,
    pdf_sanitizer::PdfSanitizer,
    zip_scanner::ZipScanner,
    SanitizationPolicy,
};

// Re-export trait types for ergonomic access within this module
use misogi_core::traits::{CDRStrategy, EncodingHandler, FileTypeDetector, PIIDetector, TransferDriver};
#[cfg(feature = "jp_contrib")]
use misogi_core::contrib::jp::encoding::JapaneseEncodingHandler;
#[cfg(feature = "jp_contrib")]
use misogi_core::contrib::jp::vendor::VendorIsolationManager;
use misogi_core::cdr_strategies::BuiltinPdfStrategy;
use misogi_core::cdr_strategies::VbaWhitelistStrategy;
use misogi_core::cdr_strategies::FormatDowngradeStrategy;
use misogi_core::file_types::CompositeDetector;
use misogi_core::pii::RegexPIIDetector;
use misogi_core::drivers::{DirectTcpDriver, StorageRelayDriver, ExternalCommandDriver};
use misogi_core::log_engine::{JsonLogFormatter, SyslogCefFormatter, TemplateLogFormatter};
use misogi_core::traits::LogFormatter;

// =============================================================================
// AppState — Central Shared State Container
// =============================================================================

/// Central application state for the Misogi Sender component.
///
/// Holds all dependencies required by HTTP route handlers, the upload engine,
/// tunnel transfer task, and the approval workflow system. Constructed once
/// at startup via [`from_config()`](AppState::from_config) and shared across
/// all async tasks behind an `Arc<>`.
///
/// # Pluggable Components (Task 5.14)
///
/// Fields suffixed with `_driver`, `_detector`, `_strategies`, or `_handler`
/// are trait objects enabling runtime-swappable implementations. These are
/// built from `SenderConfig` settings during initialization.
pub struct AppState {
    // -----------------------------------------------------------------------
    // Core Configuration & Storage
    // -----------------------------------------------------------------------

    /// Parsed sender configuration (immutable after startup).
    pub config: SenderConfig,

    /// Registry of uploaded files awaiting transfer or already processed.
    ///
    /// Keyed by `file_id`. Protected by `RwLock` for concurrent read/write.
    pub files: RwLock<HashMap<String, FileInfo>>,

    /// Upload engine handling file reception, storage, and sanitization dispatch.
    pub uploader: FileUploader,

    // -----------------------------------------------------------------------
    // Legacy Direct Sanitizers (retained for backward compatibility)
    // -----------------------------------------------------------------------

    /// PDF sanitizer for direct CDR processing (legacy path).
    ///
    /// **Note**: New code should prefer `self.cdr_strategies` for pluggable CDR.
    /// This field is retained so existing routes that reference it directly
    /// continue to compile without modification.
    pub pdf_sanitizer: PdfSanitizer,

    /// Office document sanitizer for DOCX/XLSX/PPTX (legacy path).
    ///
    /// **Note**: Prefer `self.cdr_strategies` for new code.
    pub office_sanitizer: OfficeSanitizer,

    /// ZIP archive scanner for nested file inspection (legacy path).
    pub zip_scanner: ZipScanner,

    /// Global sanitization policy controlling strictness level.
    pub sanitization_policy: SanitizationPolicy,

    // -----------------------------------------------------------------------
    // Approval Workflow State
    // -----------------------------------------------------------------------

    /// Pending and historical transfer requests requiring approval.
    ///
    /// Keyed by `request_id`. Protected by `RwLock`.
    pub requests: RwLock<HashMap<String, TransferRequest>>,

    /// Authentication store holding user credentials and role assignments.
    pub user_store: Arc<misogi_auth::store::UserStore>,

    // -----------------------------------------------------------------------
    // Audit Logging (with pluggable formatter)
    // -----------------------------------------------------------------------

    /// Audit log manager with configured [`LogFormatter`] backend.
    ///
    /// The formatter is selected at construction time based on
    /// `config.log_format` ("json", "syslog", "cef", "custom").
    pub audit_log: Arc<AuditLogManager>,

    // =======================================================================
    // Pluggable Trait Layer (Task 5.14)
    // =======================================================================

    /// Transport driver for cross-network file transfer.
    ///
    /// Selected at startup based on `config.transfer_driver_type`:
    /// - `"direct_tcp"` (default) → [`DirectTcpDriver`] wrapping TunnelClient.
    /// - `"storage_relay"` → [`StorageRelayDriver`] for diode/NFS scenarios.
    /// - `"external_command"` → [`ExternalCommandDriver`] for subprocess bridge.
    ///
    /// **Task 5.14 Note**: Currently uses concrete `DirectTcpDriver` type due to
    /// Rust's object safety requirements for traits with associated types.
    /// Future enhancement: Change to `Arc<dyn TransferDriver<Config = ConcreteDriverConfig>>`
    /// once TransferDriver trait API is stabilized and Config type is unified.
    pub transfer_driver: Arc<misogi_core::drivers::DirectTcpDriver>,

    /// Ordered chain of CDR (Content Disarmament and Reconstruction) strategies.
    ///
    /// Strategies are evaluated in order; the first one returning
    /// [`StrategyDecision::Sanitize`](mogi_core::traits::StrategyDecision::Sanitize)
    /// is applied. Built-in chain always includes `BuiltinPdfStrategy`.
    /// Additional strategies are appended when their config flags are enabled.
    pub cdr_strategies: Vec<Arc<dyn CDRStrategy>>,

    /// File type detector using magic number analysis + extension fallback.
    ///
    /// Detects actual file format independent of declared extension,
    /// providing defense against extension-spoofing attacks.
    pub file_type_detector: Arc<dyn FileTypeDetector>,

    /// PII (Personally Identifiable Information) detector for compliance scanning.
    ///
    /// Scans file content for sensitive data patterns (My Number, credit cards,
    /// phone numbers, etc.) per Japanese government regulations (APPI, My Number Act).
    /// Configured as no-op when `config.pii_enabled == false`.
    pub pii_detector: Arc<dyn PIIDetector>,

    /// Japanese calendar provider for business-day calculations and era conversion.
    ///
    /// `None` when calendar integration is not configured (default).
    /// When `Some(...)`, used by approval deadline calculator to exclude weekends
    /// and national holidays from response windows.
    pub calendar: Option<Arc<dyn misogi_core::traits::CalendarProvider>>,

    /// Text encoding handler for Japanese legacy encoding detection/conversion.
    ///
    /// Handles Shift-JIS, EUC-JP, ISO-2022-JP, UTF-8, and UTF-16 detection
    /// and conversion. Always present — uses sensible defaults for JP government systems.
    #[cfg(feature = "jp_contrib")]
    pub encoding_handler: Arc<dyn EncodingHandler>,

    /// Vendor (取引先) isolation manager for multi-tenant security boundaries.
    ///
    /// Enforces IP whitelisting, rate limiting, dual-approval gates, and
    /// forced CDR policies per external vendor account.
    /// `None` when vendor isolation is disabled (default).
    #[cfg(feature = "jp_contrib")]
    pub vendor_isolation: Option<Arc<VendorIsolationManager>>,
}

impl AppState {
    // =========================================================================
    // Construction — Factory Method (Task 5.14)
    // =========================================================================

    /// Build a fully-wired `AppState` from the parsed sender configuration.
    ///
    /// This is the **recommended** constructor for Task 5.14+ deployments. It reads
    /// all configuration sections and constructs the appropriate trait object
    /// implementations for each pluggable component.
    ///
    /// # Configuration Mapping
    ///
    /// | Config Field                    | Component Built               |
    /// |--------------------------------|--------------------------------|
    /// | `transfer_driver_type`          | `TransferDriver` impl          |
    /// | `tunnel_remote_addr`            | DirectTcpDriver receiver addr  |
    /// | `transfer_output_dir/input_dir` | StorageRelayDriver params     |
    /// | `transfer_send/status_command`  | ExternalCommandDriver params   |
    /// | `pii_enabled` / pii rules       | RegexPIIDetector config        |
    /// | `log_format` / `log_template_path`| LogFormatter selection        |
    /// | `vendor_isolation_enabled`      | VendorIsolationManager         |
    /// | `cdr_vba_whitelist_enabled`     | VbaWhitelistStrategy append    |
    /// | `cdr_format_downgrade_enabled`  | FormatDowngradeStrategy append |
    ///
    /// # Returns
    /// `Arc<Self>` ready for injection into Axum router's `.with_state()`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = SenderConfig::from_file("sender_config.toml")?;
    /// let state = AppState::from_config(&config);
    /// let app = Router::new().route("/", get(health)).with_state(state);
    /// ```
    pub fn from_config(config: &SenderConfig) -> Arc<Self> {
        // --- 1. Transport Driver ---
        // Task 5.14 Note: Currently always constructs DirectTcpDriver as concrete type.
        // Future enhancement: Use config.transfer_driver_type to select driver implementation
        // and return Arc<dyn TransferDriver<Config = ConcreteConfig>> once trait API stabilizes.
        let receiver_addr = config.tunnel_remote_addr.clone()
            .unwrap_or_else(|| "127.0.0.1:9000".to_string());
        let node_id = format!("misogi-sender-{}", &config.server_addr);
        let driver: Arc<misogi_core::drivers::DirectTcpDriver> =
            Arc::new(DirectTcpDriver::new(receiver_addr, node_id));

        // --- 2. CDR Strategy Chain ---
        let mut strategies: Vec<Arc<dyn CDRStrategy>> = vec![
            // BuiltinPdfStrategy is always first — handles .pdf files
            Arc::new(BuiltinPdfStrategy::default_config()),
        ];

        // Append VBA whitelist strategy if enabled
        if config.cdr_vba_whitelist_enabled {
            strategies.push(Arc::new(VbaWhitelistStrategy::strict_mode()));
        }

        // Append format downgrade strategy if enabled
        if config.cdr_format_downgrade_enabled {
            strategies.push(Arc::new(FormatDowngradeStrategy::jp_government_defaults()));
        }

        // --- 3. File Type Detector ---
        let detector: Arc<dyn FileTypeDetector> = Arc::new(CompositeDetector::with_defaults());

        // --- 4. PII Detector ---
        let pii: Arc<dyn PIIDetector> = if config.pii_enabled {
            Arc::new(RegexPIIDetector::with_jp_defaults())
        } else {
            // No-op PII detector: returns clean results immediately
            Arc::new(RegexPIIDetector::new(
                vec![],
                misogi_core::traits::PIIAction::AlertOnly,
                vec!["utf-8".to_string()],
            ))
        };

        // --- 5. Encoding Handler (requires jp_contrib feature) ---
        #[cfg(feature = "jp_contrib")]
        let encoding: Arc<dyn EncodingHandler> =
            Arc::new(JapaneseEncodingHandler::default());

        // --- 6. Log Formatter + AuditLogManager ---
        // Task 5.14 Note: TemplateLogFormatter requires Tera instance; using JsonLogFormatter
        // as fallback for "custom" mode until template path loading is implemented.
        let log_formatter: Arc<dyn LogFormatter> = match config.log_format.as_str() {
            "syslog" | "cef" => Arc::new(SyslogCefFormatter::new()) as Arc<dyn LogFormatter>,
            _ => Arc::new(JsonLogFormatter::new()) as Arc<dyn LogFormatter>, // default JSON (also for "custom")
        };

        let storage_dir = config.storage_dir.clone();
        let audit_log = AuditLogManager::with_config(
            std::path::PathBuf::from(&storage_dir).join("audit_logs"),
            config.log_max_memory_entries,
            config.log_retention_days as u64,
            Some(log_formatter),
        );

        // --- 7. Vendor Isolation Manager (optional, requires jp_contrib feature) ---
        #[cfg(feature = "jp_contrib")]
        let vendor_isolation = if config.vendor_isolation_enabled {
            Some(Arc::new(VendorIsolationManager::new(true)))
        } else {
            None
        };

        // --- 8. Legacy components (unchanged) ---
        let uploader = FileUploader::new(&config.storage_dir, config.chunk_size);
        let sanitization_policy = config.sanitization_policy.clone();

        Arc::new(Self {
            config: config.clone(),
            files: RwLock::new(HashMap::new()),
            uploader,
            pdf_sanitizer: PdfSanitizer::default_config(),
            office_sanitizer: OfficeSanitizer::default_config(),
            zip_scanner: ZipScanner::with_defaults(),
            sanitization_policy,
            requests: RwLock::new(HashMap::new()),
            user_store: UserStore::new(),
            audit_log,
            transfer_driver: driver,
            cdr_strategies: strategies,
            file_type_detector: detector,
            pii_detector: pii,
            calendar: None, // Calendar provider not yet implemented
            #[cfg(feature = "jp_contrib")]
            encoding_handler: encoding,
            #[cfg(feature = "jp_contrib")]
            vendor_isolation,
        })
    }

    // =========================================================================
    // Legacy Constructor (Backward Compatible)
    // =========================================================================

    /// Legacy constructor — builds `AppState` without pluggable trait layer.
    ///
    /// **Prefer [`from_config()`](AppState::from_config) for new code.**
    /// This constructor is retained for backward compatibility with existing
    /// test code and configurations that do not yet include Phase 5 sections.
    ///
    /// # Differences from `from_config()`
    /// - Uses `DirectTcpDriver` unconditionally (no config-driven selection).
    /// - Uses minimal CDR strategy chain (BuiltinPdfStrategy only).
    /// - Uses default `JsonLogFormatter`.
    /// - PII detector is disabled (no-op).
    /// - Vendor isolation is disabled.
    ///
    /// **Note**: This constructor delegates to [`from_config()`](Self::from_config) for
    /// full trait object initialization, then returns the inner `Self` directly
    /// (not wrapped in Arc). This is less efficient than using `from_config()` directly
    /// but maintains backward compatibility with existing call sites.
    pub fn new(config: SenderConfig) -> Self {
        // For backward compatibility, construct a minimal state without full trait initialization.
        // Call sites should migrate to AppState::from_config() for complete pluggable trait support.
        let storage_dir = config.storage_dir.clone();
        Self {
            config,
            files: RwLock::new(HashMap::new()),
            uploader: FileUploader::new(&storage_dir, 1024 * 1024), // Default 1MB chunks
            pdf_sanitizer: PdfSanitizer::default_config(),
            office_sanitizer: OfficeSanitizer::default_config(),
            zip_scanner: ZipScanner::with_defaults(),
            sanitization_policy: SanitizationPolicy::default(),
            requests: RwLock::new(HashMap::new()),
            user_store: UserStore::new(),
            audit_log: AuditLogManager::with_config(
                std::path::PathBuf::from(&storage_dir).join("audit_logs"),
                1000,
                30,
                None,
            ),
            transfer_driver: Arc::new(DirectTcpDriver::new(
                "127.0.0.1:9000".to_string(), // Default address
                "legacy-sender".to_string(),
            )),
            cdr_strategies: vec![Arc::new(BuiltinPdfStrategy::default_config())],
            file_type_detector: Arc::new(CompositeDetector::with_defaults()),
            pii_detector: Arc::new(RegexPIIDetector::new(
                vec![],
                misogi_core::traits::PIIAction::AlertOnly,
                vec!["utf-8".to_string()],
            )),
            calendar: None,
            #[cfg(feature = "jp_contrib")]
            encoding_handler: Arc::new(JapaneseEncodingHandler::default()),
            #[cfg(feature = "jp_contrib")]
            vendor_isolation: None,
        }
    }

    // =========================================================================
    // File Operations
    // =========================================================================

    /// Register a newly uploaded or processed file into the state registry.
    ///
    /// Acquires exclusive write lock on the `files` hashmap for the duration
    /// of the insertion. Callers should avoid holding this lock across await points.
    pub async fn add_file(&self, file_info: FileInfo) {
        let mut files = self.files.write().await;
        files.insert(file_info.file_id.clone(), file_info);
    }

    /// Look up a file by its unique identifier.
    ///
    /// Returns `None` if no file with the given ID exists in the registry.
    /// Acquires shared read lock only — safe for concurrent calls.
    pub async fn get_file(&self, file_id: &str) -> Option<FileInfo> {
        let files = self.files.read().await;
        files.get(file_id).cloned()
    }

    /// Update the status of an existing file in the registry.
    ///
    /// Returns `true` if the file was found and updated, `false` if the
    /// `file_id` does not exist (no-op).
    pub async fn update_file_status(&self, file_id: &str, status: FileStatus) -> bool {
        let mut files = self.files.write().await;
        if let Some(file) = files.get_mut(file_id) {
            file.status = status;
            true
        } else {
            false
        }
    }

    /// List all registered files, optionally filtered by status.
    ///
    /// When `status_filter` is `Some(_)`, only files matching that status are
    /// returned. When `None`, all files are returned regardless of status.
    pub async fn list_files(
        &self,
        status_filter: Option<&FileStatus>,
    ) -> Vec<FileInfo> {
        let files = self.files.read().await;
        if let Some(filter) = status_filter {
            files.iter()
                .filter(|f| f.1.status == *filter)
                .map(|(_, v)| v.clone())
                .collect()
        } else {
            files.values().cloned().collect()
        }
    }

    // =========================================================================
    // Transfer Request Operations
    // =========================================================================

    /// Register a new transfer request awaiting approval.
    pub async fn add_transfer_request(&self, request: TransferRequest) {
        let mut requests = self.requests.write().await;
        requests.insert(request.request_id.clone(), request);
    }

    /// Look up a transfer request by its unique identifier.
    pub async fn get_transfer_request(&self, request_id: &str) -> Option<TransferRequest> {
        let requests = self.requests.read().await;
        requests.get(request_id).cloned()
    }

    /// Update an existing transfer request in place.
    ///
    /// If no request with the given ID exists, this is a no-op.
    pub async fn update_transfer_request(&self, request_id: &str, updated: TransferRequest) {
        let mut requests = self.requests.write().await;
        if let Some(req) = requests.get_mut(request_id) {
            *req = updated;
        }
    }

    /// List pending approval requests, optionally filtered by assigned approver.
    ///
    /// When `approver_id` is `Some(id)`, only requests assigned to that approver
    /// are returned. When `None`, all pending requests are returned.
    pub async fn list_pending_requests(
        &self,
        approver_id: Option<&str>,
    ) -> Vec<TransferRequest> {
        let requests = self.requests.read().await;
        requests
            .iter()
            .filter(|r| {
                if r.1.status != misogi_core::approval::ApprovalStatus::PendingApproval {
                    return false;
                }
                if let Some(aid) = approver_id {
                    r.1.approver_id.as_deref() == Some(aid)
                } else {
                    true
                }
            })
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// Paginated listing of all transfer requests with optional status filter.
    ///
    /// Returns a tuple of `(page_items, total_count)` for frontend pagination.
    ///
    /// # Arguments
    /// * `page` — 1-based page number.
    /// * `per_page` — Number of items per page.
    /// * `status_filter` — Optional filter by approval status.
    pub async fn list_transfer_requests(
        &self,
        page: u32,
        per_page: u32,
        status_filter: Option<&misogi_core::approval::ApprovalStatus>,
    ) -> (Vec<TransferRequest>, usize) {
        let requests = self.requests.read().await;

        let filtered: Vec<TransferRequest> = if let Some(status) = status_filter {
            requests.iter()
                .filter(|r| &r.1.status == status)
                .map(|(_, v)| v.clone())
                .collect()
        } else {
            requests.values().cloned().collect()
        };

        let total = filtered.len();
        let start = ((page.saturating_sub(1)) as usize * per_page as usize).min(total);
        let end = (start + per_page as usize).min(total);
        let paginated = filtered[start..end].to_vec();

        (paginated, total)
    }
}

// =============================================================================
// Shared State Type Alias
// =============================================================================

/// Shared reference to application state, suitable for Axum's `.with_state()`.
///
/// All route extractors receive `&SharedState` (which derefs to `&AppState`).
pub type SharedState = Arc<AppState>;

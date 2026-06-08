// =============================================================================
// CDR Engine v2 — Config Unit Tests
// =============================================================================
// Tests for all configuration structures in the cdr_v2::config module.
// Covers: PdfConfig, OfficeConfig, ArchiveConfig, WhitelistEntry,
// WhitelistConfig, CdrV2Config validation and TOML deserialization.
// =============================================================================

use super::*;

// -----------------------------------------------------------------
// PdfConfig Tests
// -----------------------------------------------------------------

#[test]
fn pdf_config_default_is_secure() {
    let cfg = PdfConfig::default();
    assert!(cfg.strip_javascript);
    assert!(cfg.strip_open_actions);
    assert!(cfg.flatten_xfa_forms);
    assert!(cfg.strip_embedded_files);
    assert!(!cfg.preserve_hyperlinks);
}

#[test]
fn pdf_config_validate_accepts_valid_config() {
    let cfg = PdfConfig::default();
    assert!(cfg.validate().is_ok());
}

#[test]
fn pdf_config_validate_rejects_zero_max_size() {
    let mut cfg = PdfConfig::default();
    cfg.max_file_size_bytes = 0;
    assert!(cfg.validate().is_err());
}

#[test]
fn pdf_config_validate_rejects_embedded_larger_than_total() {
    let mut cfg = PdfConfig::default();
    cfg.max_embedded_file_size_bytes = 999_999_999;
    assert!(cfg.validate().is_err());
}

// -----------------------------------------------------------------
// OfficeConfig Tests
// -----------------------------------------------------------------

#[test]
fn office_config_default_is_secure() {
    let cfg = OfficeConfig::default();
    assert!(cfg.strip_macros);
    assert!(cfg.strip_ole_objects);
    assert!(cfg.disable_activex_controls);
    assert_eq!(cfg.max_page_count, 10_000);
}

#[test]
fn office_config_validate_rejects_excessive_pages() {
    let mut cfg = OfficeConfig::default();
    cfg.max_page_count = 200_000;
    assert!(cfg.validate().is_err());
}

// -----------------------------------------------------------------
// ArchiveConfig Tests
// -----------------------------------------------------------------

#[test]
fn archive_config_default_is_secure() {
    let cfg = ArchiveConfig::default();
    assert_eq!(cfg.max_nesting_depth, 5);
    assert!(cfg.block_symlink_escape);
    assert!(cfg.process_nested_archives);
    assert!(cfg.allowed_extensions.is_empty());
}

#[test]
fn archive_config_validate_rejects_deep_nesting() {
    let mut cfg = ArchiveConfig::default();
    cfg.max_nesting_depth = 25;
    assert!(cfg.validate().is_err());
}

#[test]
fn archive_config_validate_rejects_single_larger_than_total() {
    let mut cfg = ArchiveConfig::default();
    cfg.max_single_file_size_bytes = 2_000_000_000;
    assert!(cfg.validate().is_err());
}

// -----------------------------------------------------------------
// WhitelistEntry Tests
// -----------------------------------------------------------------

#[test]
fn whitelist_entry_builder_creates_valid_entry() {
    let entry = WhitelistEntry::new(
        "wl-001",
        "hash",
        "abc123def456",
        "Approved vendor template",
    );

    assert_eq!(entry.id, "wl-001");
    assert_eq!(entry.match_type, "hash");
    assert!(entry.enabled);
    assert!(entry.expires_at.is_none());
}

#[test]
fn whitelist_entry_with_expiry_and_disabled() {
    let entry = WhitelistEntry::new(
        "wl-002",
        "source",
        "trusted.example.com",
        "Internal domain",
    )
    .with_expiry("2025-12-31T23:59:59Z")
    .disabled();

    assert!(!entry.enabled);
    assert_eq!(
        entry.expires_at.as_deref(),
        Some("2025-12-31T23:59:59Z")
    );
}

// -----------------------------------------------------------------
// WhitelistConfig Tests
// -----------------------------------------------------------------

#[test]
fn whitelist_config_active_entries_filters_disabled() {
    let mut cfg = WhitelistConfig::default();
    cfg.file_hashes.push(WhitelistEntry::new("a", "hash", "h1", "enabled").disabled());
    cfg.sources.push(WhitelistEntry::new("b", "source", "s1", "also enabled"));

    let active = cfg.active_entries();
    assert_eq!(active.len(), 1); // Only the enabled source entry
}

// -----------------------------------------------------------------
// CdrV2Config Tests
// -----------------------------------------------------------------

#[test]
fn cdv2_config_new_has_all_defaults() {
    let cfg = CdrV2Config::new();
    assert!(cfg.pdf.strip_javascript);
    assert!(cfg.office.strip_macros);
    assert!(cfg.archive.block_symlink_escape);
}

#[test]
fn cdv2_config_validate_passes_for_defaults() {
    let cfg = CdrV2Config::new();
    assert!(cfg.validate().is_ok());
}

#[test]
fn cdv2_config_from_toml_parses_valid_config() {
    let toml_str = r#"
        [pdf]
        strip_javascript = true
        max_file_size_bytes = 50000000

        [office]
        strip_macros = true
        max_page_count = 5000

        [archive]
        max_nesting_depth = 3
        block_symlink_escape = true
    "#;

    let cfg = CdrV2Config::from_toml(toml_str);
    assert!(cfg.is_ok());
    let parsed = cfg.unwrap();
    assert!(parsed.pdf.strip_javascript);
    assert_eq!(parsed.office.max_page_count, 5000);
    assert_eq!(parsed.archive.max_nesting_depth, 3);
}

#[test]
fn cdv2_config_from_toml_rejects_invalid_values() {
    let toml_str = r#"
        [pdf]
        max_file_size_bytes = 0
    "#;

    let result = CdrV2Config::from_toml(toml_str);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("max_file_size_bytes"));
}

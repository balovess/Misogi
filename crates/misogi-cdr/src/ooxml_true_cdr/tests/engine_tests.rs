//! Engine core and entry processing tests.

use std::collections::HashSet;

use super::super::{
    engine::*,
    report::*,
};

#[test]
fn test_dangerous_entry_detection() {
    let engine = OoxmlTrueCdrEngine::with_jp_defaults();
    let mut report = OoxmlCdrReport::default();
    let mut removed_ids = HashSet::new();

    // Test VBA detection
    assert!(should_skip_entry(
        "word/vbaProject.bin",
        &engine.config,
        &mut report,
        &mut removed_ids,
    ));
    assert!(report.vba_removed);

    // Reset for next test
    report = OoxmlCdrReport::default();
    removed_ids.clear();

    // Test ActiveX detection
    assert!(should_skip_entry(
        "word/activeX/activeX1.xml",
        &engine.config,
        &mut report,
        &mut removed_ids,
    ));
    assert_eq!(report.activex_removed, 1);
}

#[test]
fn test_cdr_report_tracking() {
    let mut report = OoxmlCdrReport::default();

    assert!(!report.has_modifications());

    report.vba_removed = true;
    assert!(report.has_modifications());

    report = OoxmlCdrReport::default();
    report.xml_elements_filtered = 10;
    assert!(report.has_modifications());

    report.add_warning("Test warning");
    assert_eq!(report.warnings.len(), 1);
}

#[test]
fn test_extract_relationship_id() {
    // Normal entry returns Some
    assert!(extract_relationship_id("word/document.xml").is_some());
    assert!(extract_relationship_id("word/media/image1.png").is_some());

    // .rels file itself returns None
    assert!(extract_relationship_id("word/_rels/document.xml.rels").is_none());
}

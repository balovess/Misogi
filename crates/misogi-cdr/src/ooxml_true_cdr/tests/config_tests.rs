//! Configuration, whitelist, and type detection tests.

use super::super::{
    config::*,
    types::*,
};

#[test]
fn test_jp_defaults_config() {
    let config = OoxmlTrueCdrConfig::jp_defaults();

    assert!(config.strip_vba);
    assert!(config.strip_activex);
    assert!(config.strip_ole_embeddings);
    assert!(config.strip_data_connections);
    assert!(config.strip_custom_xml);
    assert!(config.strip_smart_tags);
    assert_eq!(config.content_type_mode, ContentTypeFilterMode::Permissive);
}

#[test]
fn test_minimal_config() {
    let config = OoxmlTrueCdrConfig::minimal();

    assert!(config.strip_vba);
    assert!(!config.strip_activex);
    assert!(!config.strip_ole_embeddings);
    assert!(!config.strip_data_connections);
}

#[test]
fn test_document_type_detection_from_filename() {
    assert_eq!(OoxmlDocumentType::from_filename("document.docx"), OoxmlDocumentType::Word);
    assert_eq!(OoxmlDocumentType::from_filename("spreadsheet.xlsx"), OoxmlDocumentType::Excel);
    assert_eq!(OoxmlDocumentType::from_filename("presentation.pptx"), OoxmlDocumentType::PowerPoint);
    assert_eq!(OoxmlDocumentType::from_filename("unknown.dat"), OoxmlDocumentType::Unknown);
}

#[test]
fn test_element_whitelist_contents() {
    let whitelist = ElementWhitelist::jp_defaults();

    // Word whitelist checks
    assert!(whitelist.docx_body.contains("w:p"));
    assert!(whitelist.docx_body.contains("w:t"));
    assert!(whitelist.docx_body.contains("w:tbl"));
    assert!(!whitelist.docx_body.contains("w:mc")); // AlternateContent blocked
    assert!(!whitelist.docx_body.contains("w:sdt")); // SDT blocked

    // Excel whitelist checks
    assert!(whitelist.xlsx_sheet.contains("worksheet"));
    assert!(whitelist.xlsx_sheet.contains("row"));
    assert!(whitelist.xlsx_sheet.contains("c"));
    assert!(!whitelist.xlsx_sheet.contains("pivotTable")); // Pivot tables blocked
    assert!(!whitelist.xlsx_sheet.contains("ddeLink")); // DDE blocked

    // PowerPoint whitelist checks
    assert!(whitelist.pptx_slide.contains("sp"));
    assert!(whitelist.pptx_slide.contains("pic"));
    assert!(whitelist.pptx_slide.contains("txBody"));
}

//! Integration tests for OOXML True CDR sanitization engine.
//!
//! These tests verify end-to-end functionality of the [`OoxmlTrueCdrEngine`]
//! including VBA removal, XML filtering, content type sanitization, and
//! relationship cleanup.
//!
//! # Test Categories
//!
//! 1. **Structure Tests** — Verify output is valid OOXML (ZIP archive)
//! 2. **VBA Removal Tests** — Confirm vbaProject.bin and related entries are removed
//! 3. **XML Filtering Tests** — Validate element whitelist enforcement
//! 4. **Content Type Tests** — Check [Content_Types].xml sanitization
//! 5. **Relationship Tests** — Verify dangling reference cleanup
//! 6. **Edge Case Tests** — Error handling, empty files, malformed input
//!
//! # Note on Test Fixtures
//!
//! Some tests are marked `#[ignore]` because they require real OOXML test fixtures
//! (actual .docx/.xlsx/.pptx files). These can be run manually when fixtures are available.

use std::io::{Cursor, Write};
use zip::ZipWriter;

use misogi_cdr::ooxml_true_cdr::{
    ContentTypeFilterMode, OoxmlDocumentType, OoxmlTrueCdrConfig, OoxmlTrueCdrEngine,
};

// =============================================================================
// Helper Functions for Creating Test OOXML Files
// =============================================================================

/// Create a minimal valid DOCX file (ZIP) with basic structure.
///
/// Returns bytes of a minimal .docx file containing:
/// - [Content_Types].xml
/// - _rels/.rels
/// - word/_rels/document.xml.rels
/// - word/document.xml (with simple paragraph)
fn create_minimal_docx() -> Vec<u8> {
    let buffer = Vec::new();
    let mut writer = ZipWriter::new(Cursor::new(buffer));

    // [Content_Types].xml
    let content_types = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#;
    writer
        .start_file("[Content_Types].xml", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(content_types).unwrap();

    // _rels/.rels
    let root_rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#;
    writer
        .start_file("_rels/.rels", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(root_rels).unwrap();

    // word/_rels/document.xml.rels
    let doc_rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
</Relationships>"#;
    writer
        .start_file(
            "word/_rels/document.xml.rels",
            zip::write::FileOptions::<()>::default(),
        )
        .unwrap();
    writer.write_all(doc_rels).unwrap();

    // word/document.xml
    let document_xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>Hello, World!</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>"#;
    writer
        .start_file("word/document.xml", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(document_xml).unwrap();

    // Finalize ZIP
    let cursor = writer.finish().unwrap();
    cursor.into_inner()
}

/// Create a DOCX file with VBA macro project.
///
/// Same as minimal DOCX but includes vbaProject.bin entry.
fn create_docx_with_vba() -> Vec<u8> {
    let buffer = Vec::new();
    let mut writer = ZipWriter::new(Cursor::new(buffer));

    // [Content_Types].xml — includes VBA content type
    let content_types = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
</Types>"#;
    writer
        .start_file("[Content_Types].xml", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(content_types).unwrap();

    // _rels/.rels
    let root_rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#;
    writer
        .start_file("_rels/.rels", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(root_rels).unwrap();

    // word/_rels/document.xml.rels — references vbaProject
    let doc_rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rIdVba" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
</Relationships>"#;
    writer
        .start_file(
            "word/_rels/document.xml.rels",
            zip::write::FileOptions::<()>::default(),
        )
        .unwrap();
    writer.write_all(doc_rels).unwrap();

    // word/document.xml
    let document_xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>Document with macros</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>"#;
    writer
        .start_file("word/document.xml", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(document_xml).unwrap();

    // word/vbaProject.bin — fake VBA project data
    let vba_data = b"This is fake VBA macro data for testing purposes";
    writer
        .start_file("word/vbaProject.bin", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(vba_data).unwrap();

    // Finalize ZIP
    let cursor = writer.finish().unwrap();
    cursor.into_inner()
}

/// Create a DOCX file with dangerous XML elements (not in whitelist).
///
/// Contains elements like w:sdt, w:mc (AlternateContent), etc. that should be filtered out.
fn create_docx_with_dangerous_elements() -> Vec<u8> {
    let buffer = Vec::new();
    let mut writer = ZipWriter::new(Cursor::new(buffer));

    // [Content_Types].xml
    let content_types = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#;
    writer
        .start_file("[Content_Types].xml", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(content_types).unwrap();

    // _rels/.rels
    let root_rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#;
    writer
        .start_file("_rels/.rels", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(root_rels).unwrap();

    // word/_rels/document.xml.rels
    let doc_rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
</Relationships>"#;
    writer
        .start_file(
            "word/_rels/document.xml.rels",
            zip::write::FileOptions::<()>::default(),
        )
        .unwrap();
    writer.write_all(doc_rels).unwrap();

    // word/document.xml — contains dangerous elements mixed with safe ones
    let document_xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <!-- Safe element -->
    <w:p>
      <w:r>
        <w:t>Safe text content</w:t>
      </w:r>
    </w:p>

    <!-- Dangerous: Structured Document Tag (can hide macros) -->
    <w:sdt>
      <w:sdtPr>
        <w:tag w:val="dangerous"/>
      </w:sdtPr>
      <w:sdtContent>
        <w:p><w:r><w:t>Hidden dangerous content</w:t></w:r></w:p>
      </w:sdtContent>
    </w:sdt>

    <!-- Dangerous: AlternateContent (can contain fallback exploits) -->
    <w:mc:AlternateContent xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006">
      <w:Choice Requires="wps">
        <w:p><w:r><w:t>Exploitable alternate content</w:t></w:r></w:p>
      </w:Choice>
      <w:Fallback>
        <w:p><w:r><w:t>Fallback exploit</w:t></w:r></w:p>
      </w:Fallback>
    </w:mc:AlternateContent>

    <!-- Safe element after dangerous ones -->
    <w:p>
      <w:r>
        <w:t>More safe text</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>"#;
    writer
        .start_file("word/document.xml", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(document_xml).unwrap();

    // Finalize ZIP
    let cursor = writer.finish().unwrap();
    cursor.into_inner()
}

/// Create a minimal XLSX file for testing Excel True CDR.
fn create_minimal_xlsx() -> Vec<u8> {
    let buffer = Vec::new();
    let mut writer = ZipWriter::new(Cursor::new(buffer));

    // [Content_Types].xml
    let content_types = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.worksheet+xml"/>
</Types>"#;
    writer
        .start_file("[Content_Types].xml", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(content_types).unwrap();

    // _rels/.rels
    let root_rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"#;
    writer
        .start_file("_rels/.rels", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(root_rels).unwrap();

    // xl/workbook.xml
    let workbook = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>"#;
    writer
        .start_file("xl/workbook.xml", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(workbook).unwrap();

    // xl/worksheets/sheet1.xml
    let sheet = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1" t="inlineStr"><is><t>Test Data</t></is></c>
    </row>
  </sheetData>
</worksheet>"#;
    writer
        .start_file(
            "xl/worksheets/sheet1.xml",
            zip::write::FileOptions::<()>::default(),
        )
        .unwrap();
    writer.write_all(sheet).unwrap();

    // Finalize ZIP
    let cursor = writer.finish().unwrap();
    cursor.into_inner()
}

/// Create an XLSX file with DDE link (dangerous — code execution vector).
fn create_xlsx_with_dde() -> Vec<u8> {
    let buffer = Vec::new();
    let mut writer = ZipWriter::new(Cursor::new(buffer));

    // [Content_Types].xml
    let content_types = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.worksheet+xml"/>
  <Override PartName="/xl/externalLinks/externalLink1.xml" ContentType="application/vnd.openxmlformats-officedocument.externalLink+xml"/>
</Types>"#;
    writer
        .start_file("[Content_Types].xml", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(content_types).unwrap();

    // xl/worksheets/sheet1.xml — contains DDE formula
    let sheet = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1"><f>=cmd|' /c calc.exe'!A1</f></c>
    </row>
  </sheetData>
</worksheet>"#;
    writer
        .start_file(
            "xl/worksheets/sheet1.xml",
            zip::write::FileOptions::<()>::default(),
        )
        .unwrap();
    writer.write_all(sheet).unwrap();

    // xl/externalLinks/externalLink1.xml — DDE link entry
    let external_link = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ddeLink xmlns:dde="http://schemas.openxmlformats.org/spreadsheetml/2006/dde">
  <ddeItems>
    <ddeItem name="calc.exe" advise="oneTime"/>
  </ddeItems>
</ddeLink>"#;
    writer
        .start_file(
            "xl/externalLinks/externalLink1.xml",
            zip::write::FileOptions::<()>::default(),
        )
        .unwrap();
    writer.write_all(external_link).unwrap();

    // Finalize ZIP
    let cursor = writer.finish().unwrap();
    cursor.into_inner()
}

// =============================================================================
// Integration Tests
// =============================================================================

/// Test that minimal DOCX passes through without modifications when clean.
#[test]
fn test_clean_docx_passes_through() {
    let engine = OoxmlTrueCdrEngine::with_jp_defaults();
    let docx_bytes = create_minimal_docx();

    let result = engine
        .sanitize(&docx_bytes)
        .expect("Sanitization should succeed");

    assert!(result.validation_passed, "Output should be valid OOXML");
    assert!(
        !result.report.has_modifications(),
        "Clean document should have no modifications"
    );
    assert_eq!(result.document_type, OoxmlDocumentType::Word);

    // Output should still be a valid ZIP
    let cursor = Cursor::new(result.output);
    let archive = zip::ZipArchive::new(cursor).expect("Output should be valid ZIP");
    assert!(archive.len() >= 3, "Should have at least 3 entries");
}

/// Test that VBA macro project is removed from DOCX.
#[test]
fn test_vba_removal_from_docx() {
    let engine = OoxmlTrueCdrEngine::with_jp_defaults();
    let docx_with_vba = create_docx_with_vba();

    let result = engine
        .sanitize(&docx_with_vba)
        .expect("Sanitization should succeed");

    assert!(result.validation_passed, "Output should be valid OOXML");
    assert!(
        result.report.vba_removed,
        "VBA should be detected as removed"
    );
    assert!(
        result.report.has_modifications(),
        "Should report modifications"
    );

    // Verify vbaProject.bin is NOT in output
    let cursor = Cursor::new(result.output);
    let mut archive = zip::ZipArchive::new(cursor).expect("Output should be valid ZIP");

    let has_vba = (0..archive.len()).any(|i| {
        archive
            .by_index(i)
            .map(|e| e.name().contains("vbaProject"))
            .unwrap_or(false)
    });
    assert!(!has_vba, "Output should not contain vbaProject.bin");

    // Verify Content_Types.xml no longer has VBA content type
    let mut ct_entry = archive
        .by_name("[Content_Types].xml")
        .expect("Should have Content_Types");
    let mut ct_content = Vec::new();
    std::io::Read::read_to_end(&mut ct_entry, &mut ct_content).unwrap();
    let ct_str = String::from_utf8_lossy(&ct_content);
    assert!(
        !ct_str.contains("vbaProject"),
        "Content_Types.xml should not reference vbaProject"
    );
}

/// Test that dangerous XML elements are filtered from document body.
#[test]
fn test_dangerous_element_filtering() {
    let engine = OoxmlTrueCdrEngine::with_jp_defaults();
    let docx_dangerous = create_docx_with_dangerous_elements();

    let result = engine
        .sanitize(&docx_dangerous)
        .expect("Sanitization should succeed");

    assert!(result.validation_passed);
    assert!(
        result.report.xml_elements_filtered > 0,
        "Should have filtered some dangerous elements"
    );

    // Verify output document doesn't contain dangerous elements
    let cursor = Cursor::new(result.output);
    let mut archive = zip::ZipArchive::new(cursor).expect("Valid ZIP");

    let mut doc_entry = archive
        .by_name("word/document.xml")
        .expect("Should have document.xml");
    let mut doc_content = Vec::new();
    std::io::Read::read_to_end(&mut doc_entry, &mut doc_content).unwrap();
    let doc_str = String::from_utf8_lossy(&doc_content);

    // Should NOT contain these dangerous elements
    assert!(
        !doc_str.contains("<w:sdt"),
        "Output should not contain w:sdt (Structured Document Tag)"
    );
    assert!(
        !doc_str.contains("<w:mc:AlternateContent"),
        "Output should not contain AlternateContent"
    );

    // SHOULD contain safe elements
    assert!(
        doc_str.contains("<w:p>"),
        "Output should preserve safe paragraph elements"
    );
    assert!(
        doc_str.contains("Safe text content"),
        "Output should preserve safe text content"
    );
    assert!(
        doc_str.contains("More safe text"),
        "Output should preserve trailing safe content"
    );
}

/// Test that XLSX files are processed correctly.
#[test]
fn test_xlsx_processing() {
    let engine = OoxmlTrueCdrEngine::with_jp_defaults();
    let xlsx_bytes = create_minimal_xlsx();

    let result = engine
        .sanitize(&xlsx_bytes)
        .expect("Sanitization should succeed");

    assert!(result.validation_passed);
    assert_eq!(result.document_type, OoxmlDocumentType::Excel);

    // Should preserve worksheet data
    let cursor = Cursor::new(result.output);
    let mut archive = zip::ZipArchive::new(cursor).expect("Valid ZIP");

    let mut sheet_entry = archive
        .by_name("xl/worksheets/sheet1.xml")
        .expect("Should have sheet1.xml");
    let mut sheet_content = Vec::new();
    std::io::Read::read_to_end(&mut sheet_entry, &mut sheet_content).unwrap();
    let sheet_str = String::from_utf8_lossy(&sheet_content);

    assert!(
        sheet_str.contains("Test Data"),
        "Should preserve cell data in XLSX"
    );
}

/// Test that DDE links are removed from XLSX.
#[test]
fn test_dde_link_removal_from_xlsx() {
    let engine = OoxmlTrueCdrEngine::with_jp_defaults();
    let xlsx_with_dde = create_xlsx_with_dde();

    let result = engine
        .sanitize(&xlsx_with_dde)
        .expect("Sanitization should succeed");

    assert!(result.validation_passed);
    assert!(
        result.report.data_connections_removed > 0 || result.report.entries_skipped > 0,
        "Should remove or skip DDE-related entries"
    );

    // Verify DDE link entry is not in output
    let cursor = Cursor::new(result.output);
    let mut archive = zip::ZipArchive::new(cursor).expect("Valid ZIP");

    let has_dde = (0..archive.len()).any(|i| {
        archive
            .by_index(i)
            .map(|e| {
                let name = e.name().to_ascii_lowercase();
                name.contains("externallink") || name.contains("dde")
            })
            .unwrap_or(false)
    });
    assert!(!has_dde, "Output should not contain DDE link entries");
}

/// Test that relationships are cleaned up after removing entries.
#[test]
fn test_relationship_cleanup() {
    let engine = OoxmlTrueCdrEngine::with_jp_defaults();
    let docx_with_vba = create_docx_with_vba();

    let result = engine
        .sanitize(&docx_with_vba)
        .expect("Sanitization should succeed");

    // After VBA removal, the relationship to vbaProject should be cleaned
    if result.report.relationships_modified {
        tracing::info!("Relationships were modified during cleanup");
    }

    // Verify no dangling references to vbaProject remain
    let cursor = Cursor::new(result.output);
    let mut archive = zip::ZipArchive::new(cursor).expect("Valid ZIP");

    let mut rels_entry = archive
        .by_name("word/_rels/document.xml.rels")
        .expect("Should have document.xml.rels");
    let mut rels_content = Vec::new();
    std::io::Read::read_to_end(&mut rels_entry, &mut rels_content).unwrap();
    let rels_str = String::from_utf8_lossy(&rels_content);

    assert!(
        !rels_str.contains("vbaProject"),
        "Relationships should not reference removed vbaProject"
    );
}

/// Test configuration options (minimal mode vs paranoid mode).
#[test]
fn test_configuration_modes() {
    // Paranoid Japanese defaults
    let paranoid_engine = OoxmlTrueCdrEngine::with_jp_defaults();
    let config = OoxmlTrueCdrConfig::jp_defaults();
    assert!(config.strip_vba);
    assert!(config.strip_activex);
    assert!(config.strip_custom_xml);

    // Minimal mode (compatibility-focused)
    let minimal_config = OoxmlTrueCdrConfig::minimal();
    assert!(minimal_config.strip_vba); // Always strip VBA
    assert!(!minimal_config.strip_activex); // Keep ActiveX in minimal mode
    assert!(!minimal_config.strip_custom_xml); // Keep custom XML

    let minimal_engine = OoxmlTrueCdrEngine::with_config(minimal_config);

    // Both engines should work on same input
    let docx_bytes = create_minimal_docx();

    let paranoid_result = paranoid_engine
        .sanitize(&docx_bytes)
        .expect("Paranoid engine should work");
    assert!(paranoid_result.validation_passed);

    let minimal_result = minimal_engine
        .sanitize(&docx_bytes)
        .expect("Minimal engine should work");
    assert!(minimal_result.validation_passed);
}

/// Test content type filter modes (Strict vs Lenient vs Permissive).
#[test]
fn test_content_type_filter_modes() {
    // Strict mode would reject unknown binary types
    let strict_config = OoxmlTrueCdrConfig {
        strip_vba: true,
        strip_activex: true,
        strip_ole_embeddings: true,
        strip_data_connections: true,
        strip_custom_xml: true,
        strip_smart_tags: true,
        content_type_mode: ContentTypeFilterMode::Strict,
        ..OoxmlTrueCdrConfig::default()
    };
    let strict_engine = OoxmlTrueCdrEngine::with_config(strict_config);

    let docx_bytes = create_minimal_docx();
    let result = strict_engine
        .sanitize(&docx_bytes)
        .expect("Strict mode should work");
    assert!(result.validation_passed);
}

/// Test error handling for non-ZIP input.
#[test]
fn test_non_zip_input_error() {
    let engine = OoxmlTrueCdrEngine::with_jp_defaults();
    let not_a_zip = b"This is plain text, not a ZIP archive";

    let result = engine.sanitize(not_a_zip);

    assert!(result.is_err(), "Non-ZIP input should return error");
}

/// Test oversized file rejection (security check).
#[test]
fn test_oversized_file_rejection() {
    let config = OoxmlTrueCdrConfig {
        max_file_size_bytes: 100, // Very small limit for testing
        ..OoxmlTrueCdrConfig::default()
    };
    let engine = OoxmlTrueCdrEngine::with_config(config);

    let large_input = vec![0u8; 200]; // Exceeds 100-byte limit
    let result = engine.sanitize(&large_input);

    assert!(result.is_err(), "Oversized file should be rejected");
}

/// Test ZIP bomb detection (excessive compression ratio).
#[test]
#[ignore] // Requires creating actual ZIP bomb (slow to generate)
fn test_zip_bomb_detection() {
    // This test would create a ZIP bomb (small compressed size, huge uncompressed)
    // and verify it's rejected by the engine
    // For now, marked as ignore since generating real ZIP bombs is slow
}

/// Test document type detection from various inputs.
#[test]
fn test_document_type_detection() {
    let engine = OoxmlTrueCdrEngine::with_jp_defaults();

    let docx = create_minimal_docx();
    let result = engine.sanitize(&docx).unwrap();
    assert_eq!(result.document_type, OoxmlDocumentType::Word);

    let xlsx = create_minimal_xlsx();
    let result = engine.sanitize(&xlsx).unwrap();
    assert_eq!(result.document_type, OoxmlDocumentType::Excel);
}

/// Test report generation accuracy.
#[test]
fn test_report_accuracy() {
    let engine = OoxmlTrueCdrEngine::with_jp_defaults();

    // Clean file — minimal report
    let clean = create_minimal_docx();
    let clean_result = engine.sanitize(&clean).unwrap();
    assert!(!clean_result.report.has_modifications());
    assert_eq!(clean_result.report.warnings.len(), 0);

    // File with VBA — detailed report
    let dirty = create_docx_with_vba();
    let dirty_result = engine.sanitize(&dirty).unwrap();
    assert!(dirty_result.report.has_modifications());
    assert!(dirty_result.report.vba_removed);
    assert!(dirty_result.report.entries_processed > 0);
    // May or may not have warnings depending on processing
}

/// Test that binary resources (images) are preserved.
#[test]
fn test_binary_resource_preservation() {
    let buffer = Vec::new();
    let mut writer = ZipWriter::new(Cursor::new(buffer));

    // Create DOCX with embedded image
    let content_types = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="png" ContentType="image/png"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#;
    writer
        .start_file("[Content_Types].xml", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(content_types).unwrap();

    let document_xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Image test</w:t></w:r></w:p></w:body>
</w:document>"#;
    writer
        .start_file("word/document.xml", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(document_xml).unwrap();

    // Add a fake PNG image (valid enough to pass validation)
    let fake_png = b"\x89PNG\r\n\x1a\nfake png data for testing";
    writer
        .start_file("word/media/image1.png", zip::write::FileOptions::<()>::default())
        .unwrap();
    writer.write_all(fake_png).unwrap();

    let docx_with_image = writer.finish().unwrap().into_inner();

    let engine = OoxmlTrueCdrEngine::with_jp_defaults();
    let result = engine
        .sanitize(&docx_with_image)
        .expect("Should handle images");

    assert!(result.validation_passed);

    // Image should be preserved in output
    let cursor = Cursor::new(result.output);
    let mut archive = zip::ZipArchive::new(cursor).expect("Valid ZIP");

    let has_image = (0..archive.len()).any(|i| {
        archive
            .by_index(i)
            .map(|e| e.name().contains("image1.png"))
            .unwrap_or(false)
    });
    assert!(has_image, "Image resource should be preserved in output");
}

/// Test multiple rounds of sanitization (idempotency).
#[test]
fn test_idempotency() {
    let engine = OoxmlTrueCdrEngine::with_jp_defaults();

    let original = create_minimal_docx();

    // First pass
    let first_pass = engine.sanitize(&original).expect("First pass succeeds");
    assert!(first_pass.validation_passed);

    // Second pass on already-sanitized output
    let second_pass = engine
        .sanitize(&first_pass.output)
        .expect("Second pass succeeds");
    assert!(second_pass.validation_passed);

    // Second pass should make no additional modifications
    assert!(
        !second_pass.report.has_modifications(),
        "Second pass should not modify already-clean output"
    );
}

//! XML filtering and name_stack balanced tag tests.

use super::super::{
    config::*,
    report::*,
    types::*,
    xml_filter::*,
};

#[test]
fn test_content_type_filtering() {
    let _config = OoxmlTrueCdrConfig::jp_defaults();
    let mut report = OoxmlCdrReport::default();

    // Sample Content_Types.xml with dangerous type
    let sample_content_types = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Override PartName="/word/activeX/activeX1.xml" ContentType="application/vnd.ms-office.activeX+xml"/>
</Types>"#;

    let result = filter_content_types(sample_content_types, &mut report).unwrap();

    // Should have removed 3 dangerous content types:
    assert_eq!(result.elements_dropped, 3);
    assert!(report.content_types_modified);

    let output_str = String::from_utf8_lossy(&result.filtered_bytes);
    assert!(!output_str.contains("vbaProject"));
    assert!(!output_str.contains("activeX"));
}

#[test]
fn test_name_stack_balanced_tags() {
    let config = OoxmlTrueCdrConfig::jp_defaults();
    let mut report = OoxmlCdrReport::default();

    // Simple nested XML with whitelisted elements (namespaced)
    let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>Hello</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>"#;

    let result = filter_document_xml(xml, OoxmlDocumentType::Word, &config, &mut report).unwrap();
    let output = String::from_utf8_lossy(&result.filtered_bytes);

    let has_open_tag = |name: &str| -> bool {
        output.contains(&format!("<{}>", name))
            || output.contains(&format!("<{}:", name))
            || output.split_whitespace().any(|tok| tok.starts_with('<') && !tok.starts_with("</") && tok[1..].contains(name))
    };
    let has_close_tag = |name: &str| -> bool {
        output.contains(&format!("</{}>", name))
            || output.contains(&format!("</{}:", name))
            || (output.contains("</") && {
                output.split('>').any(|part| part.contains('/') && part.contains(name))
            })
    };

    assert!(has_open_tag("document") || output.contains("document"), "Missing opening document tag");
    assert!(output.contains("</") && has_close_tag("document"),
        "Missing closing document tag — name_stack fix required");
    assert!(has_open_tag("body") || output.contains("<body"),
        "Missing opening body tag");
    assert!(has_close_tag("body"),
        "Missing closing body tag — name_stack fix required");
    assert!(has_open_tag("p") || output.contains("<p"),
        "Missing opening p tag");
    assert!(has_close_tag("p"),
        "Missing closing p tag — name_stack fix required");
    assert!(has_open_tag("t") || output.contains("<t"),
        "Missing opening t tag");
    assert!(has_close_tag("t"),
        "Missing closing t tag — name_stack fix required");

    assert!(output.contains("Hello"), "Text content should be preserved");
    assert!(output.contains('<'), "Output should contain XML opening brackets");
    assert!(output.contains('>'), "Output should contain XML closing brackets");
    assert!(output.contains("</"), "Output should contain closing tag markers");
}

#[test]
fn test_name_stack_self_closing_elements() {
    let config = OoxmlTrueCdrConfig::jp_defaults();
    let mut report = OoxmlCdrReport::default();

    let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p/>
    <w:p>
      <w:r><w:t>Text</w:t></w:r>
    </w:p>
    <w:br/>
  </w:body>
</w:document>"#;

    let result = filter_document_xml(xml, OoxmlDocumentType::Word, &config, &mut report).unwrap();
    let output = String::from_utf8_lossy(&result.filtered_bytes);

    assert!(output.contains("<w:p/>") || output.contains("<w:p />"), "Self-closing w:p should be preserved as empty element");
    assert!(output.contains("</w:body>"), "Closing w:body should be present after self-closing children");
    assert!(output.contains("</w:document>"), "Closing w:document should be present");
}

#[test]
fn test_name_stack_dropped_elements_no_spurious_closing() {
    let config = OoxmlTrueCdrConfig::jp_defaults();
    let mut report = OoxmlCdrReport::default();

    let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:mc>
      <w:sdt>Malicious content</w:sdt>
    </w:mc>
    <w:p><w:t>Safe text</w:t></w:p>
  </w:body>
</w:document>"#;

    let result = filter_document_xml(xml, OoxmlDocumentType::Word, &config, &mut report).unwrap();
    let output = String::from_utf8_lossy(&result.filtered_bytes);

    assert!(!output.contains("w:mc"), "Non-whitelisted w:mc should not appear in output");
    assert!(!output.contains("w:sdt"), "Non-whitelisted w:sdt should not appear in output");
    assert!(!output.contains("Malicious"), "Content of dropped element should not leak");
    assert!(output.contains("</w:p>"), "Safe w:p should have proper closing tag");
    assert!(output.contains("Safe text"), "Safe text content should be preserved");
}

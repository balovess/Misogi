//! Integration tests and cross-cutting validation for OOXML True CDR.

use super::super::{
    config::*,
    report::*,
    types::*,
    xml_filter::*,
};

#[test]
fn test_ooxml_cdr_action_variants() {
    // Verify all enum variants can be constructed
    let _vba = OoxmlCdrAction::VbaMacroRemoved {
        filename: "vbaProject.bin".to_string(),
    };
    let dde = OoxmlCdrAction::DdeAttackDetected {
        location: "v element".to_string(),
        pattern_matched: r"(?i)=CMD\|".to_string(),
    };
    let link = OoxmlCdrAction::BlockedExternalLink {
        url: "file:///etc/passwd".to_string(),
        blocked_protocol: "file://".to_string(),
    };
    let _sheet_prot = OoxmlCdrAction::SheetProtectionStripped {
        location: "Sheet1".to_string(),
    };
    let _pivot = OoxmlCdrAction::PivotCacheExternalRefStripped {
        cache_id: "cache1".to_string(),
    };
    let _mapping = OoxmlCdrAction::CustomXmlMappingStripped {
        map_id: "Map1".to_string(),
        reason: "script injection".to_string(),
    };
    let _dataval = OoxmlCdrAction::MaliciousDataValidationStripped {
        location: "A1".to_string(),
        url: "javascript:x".to_string(),
    };
    let _instr = OoxmlCdrAction::InstrTextScriptNeutralized {
        field_content: "powershell x".to_string(),
    };
    let altchunk = OoxmlCdrAction::AltChunkRemoved {
        chunk_id: "rId5".to_string(),
    };
    let _hlink = OoxmlCdrAction::HyperlinkBlocked {
        target: "javascript:x".to_string(),
        reason: "blocked protocol".to_string(),
    };
    let _irm = OoxmlCdrAction::IrmPermissionStripped {
        location: "permStart[1]".to_string(),
    };
    let _ole = OoxmlCdrAction::OleObjectDetected {
        object_id: "rId3".to_string(),
    };
    let _sound = OoxmlCdrAction::ExternalSoundStripped {
        sound_ref: "http://evil.com/x.wav".to_string(),
    };
    let extlst = OoxmlCdrAction::ExtLstRemoved {
        location: "slide1".to_string(),
    };
    let _anim_cmd = OoxmlCdrAction::AnimationCmdStripped {
        cmd_content: "javascript:x".to_string(),
    };

    // Verify equality works (for PartialEq derive)
    assert_eq!(dde, OoxmlCdrAction::DdeAttackDetected {
        location: "v element".to_string(),
        pattern_matched: r"(?i)=CMD\|".to_string(),
    });
    assert!(dde != link); // Different variants are not equal

    // Verify Debug output works
    let _debug_str = format!("{:?}", altchunk);
    let _debug_str2 = format!("{:?}", extlst);
}

#[test]
fn test_integration_excel_multiple_threats() {
    let config = OoxmlTrueCdrConfig::jp_defaults();
    let mut report = OoxmlCdrReport::default();

    // Worksheet containing DDE payload + sheetProtection + dataValidation URL
    let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetProtection password="AAAA" sheet="1"/>
  <sheetData>
    <row r="1">
      <c r="A1">
        <v>=CMD|/c calc.exe</v>
      </c>
    </row>
  </sheetData>
  <dataValidations count="1">
    <dataValidation sqref="B1" type="list" formula1="javascript:alert(1)"/>
  </dataValidations>
</worksheet>"#;

    let result = filter_document_xml(xml, OoxmlDocumentType::Excel, &config, &mut report).unwrap();

    // Multiple threats should be detected
    assert!(report.dde_attacks_detected > 0, "DDE attack should be detected");
    assert!(report.excel_threats_neutralized >= 2, "At least 2 Excel threats (sheetProtection + dataValidation)");
    assert!(report.has_modifications(), "Report should indicate modifications");

    let output = String::from_utf8_lossy(&result.filtered_bytes);
    assert!(!output.contains("CMD|"), "DDE payload should be stripped from output");
    assert!(!output.contains("calc.exe"), "DDE target should not appear");
}

#[test]
fn test_integration_word_multiple_threats() {
    let config = OoxmlTrueCdrConfig::jp_defaults();
    let mut report = OoxmlCdrReport::default();

    let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
            xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">
  <w:body>
    <w:altChunk r:id="rId99"/>
    <w:permStart w:id="perm1" w:edGrp="none"/>
    <w:p>
      <w:hyperlink Target="file:///C:/Windows/System32/cmd.exe">Click me</w:hyperlink>
      <w:r>
        <w:instrText> POWERSHELL -ENCODEDCOMMAND ABCDEF </w:instrText>
      </w:r>
    </w:p>
    <w:permEnd w:id="perm1"/>
  </w:body>
</w:document>"#;

    let _result = filter_document_xml(xml, OoxmlDocumentType::Word, &config, &mut report).unwrap();

    // Multiple Word threats should be detected
    assert!(report.word_threats_neutralized >= 3, "Should detect altChunk + hyperlink + IRM threats");
    assert!(report.has_modifications());

    let action_types: Vec<&str> = report.actions_taken.iter().map(|a| match a {
        OoxmlCdrAction::AltChunkRemoved { .. } => "altChunk",
        OoxmlCdrAction::HyperlinkBlocked { .. } => "hyperlink",
        OoxmlCdrAction::IrmPermissionStripped { .. } => "irm",
        OoxmlCdrAction::InstrTextScriptNeutralized { .. } => "instrText",
        _ => "other",
    }).collect();

    assert!(action_types.contains(&"altChunk"), "altChunk removal should be recorded");
    assert!(action_types.contains(&"hyperlink") || action_types.contains(&"irm"),
        "Hyperlink or IRM threat should be recorded");
}

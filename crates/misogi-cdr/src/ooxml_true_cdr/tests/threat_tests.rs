//! Threat detection tests: DDE, URL protocols, script injection, Excel/Word/PPT specific.

use quick_xml::{Reader, events::Event};
use super::super::{
    config::*,
    report::*,
    threat::*,
    types::*,
    constants::*,
};

// =========================================================================
// DDE Attack Prevention Tests
// =========================================================================

#[test]
fn test_dde_detection_in_cell_value() {
    // Test =CMD| pattern
    assert!(contains_dde_payload("=CMD|/c calc.exe"));
    assert!(contains_dde_payload("=cmd|/c powershell"));

    // Test =EXEC( pattern
    assert!(contains_dde_payload("=EXEC(\"cmd.exe /c calc\")"));
    assert!(contains_dde_payload("=exec('powershell')"));

    // Test =MSQUERY pattern
    assert!(contains_dde_payload("=MSQUERY;external_source"));

    // Safe values should NOT trigger detection
    assert!(!contains_dde_payload("12345"));
    assert!(!contains_dde_payload("Normal text"));
    assert!(!contains_dde_payload("=SUM(A1:A10)"));
    assert!(!contains_dde_payload("=IF(A1>0,\"yes\",\"no\")"));
}

#[test]
fn test_dde_detection_case_insensitive() {
    assert!(contains_dde_payload("=cmd|/c test"));       // lowercase
    assert!(contains_dde_payload("=Cmd|/c test"));        // mixed case
    assert!(contains_dde_payload("=CMD|/c test"));        // uppercase
    assert!(contains_dde_payload("=exec("));              // lowercase
    assert!(contains_dde_payload("=EXEC("));              // uppercase
    assert!(contains_dde_payload("=msquery"));            // lowercase
    assert!(contains_dde_payload("=MSQUERY"));            // uppercase
}

#[test]
fn test_dde_text_content_neutralized_in_filtering() {
    let config = OoxmlTrueCdrConfig::jp_defaults();
    let mut report = OoxmlCdrReport::default();

    let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="B2" t="s">
        <f>=CMD|/c calc.exe</f>
        <v>malicious</v>
      </c>
    </row>
  </sheetData>
</worksheet>"#;

    let result = super::super::xml_filter::filter_document_xml(
        xml, OoxmlDocumentType::Excel, &config, &mut report,
    ).unwrap();
    let output = String::from_utf8_lossy(&result.filtered_bytes);

    assert!(report.dde_attacks_detected > 0, "DDE attacks should be detected");
    assert!(report.has_modifications(), "Report should show modifications");

    let dde_actions: Vec<_> = report.actions_taken.iter()
        .filter(|a| matches!(a, OoxmlCdrAction::DdeAttackDetected { .. }))
        .collect();
    assert!(!dde_actions.is_empty(), "DdeAttackDetected action should be recorded");

    assert!(!output.contains("CMD|"), "DDE command string should be stripped from output");
    assert!(!output.contains("calc.exe"), "DDE target should not appear in output");
}

// =========================================================================
// URL Protocol Detection Tests
// =========================================================================

#[test]
fn test_blocked_url_protocol_detection() {
    // Blocked protocols
    assert!(has_blocked_url_protocol("file:///C:/Windows/System32/cmd.exe"));
    assert!(has_blocked_url_protocol("javascript:alert(1)"));
    assert!(has_blocked_url_protocol_static("vbscript:MsgBox"));
    assert!(has_blocked_url_protocol_static("data:text/html,<script>alert(1)</script>"));
    assert!(has_blocked_url_protocol("FILE://server/payload"));

    // Safe URLs should pass
    assert!(!has_blocked_url_protocol("https://example.com"));
    assert!(!has_blocked_url_protocol("http://example.com"));
    assert!(!has_blocked_url_protocol("mailto:user@example.com"));
    assert!(!has_blocked_url_protocol("#bookmark"));
    assert!(!has_blocked_url_protocol("../relative/path"));
}

/// Helper to test blocked URL protocol with static method access.
fn has_blocked_url_protocol_static(url: &str) -> bool {
    let url_lower = url.to_ascii_lowercase();
    BLOCKED_URL_PROTOCOLS.iter().any(|proto| {
        url_lower.starts_with(*proto) || url_lower.contains(*proto)
    })
}

#[test]
fn test_identify_blocked_protocol() {
    assert_eq!(
        identify_blocked_protocol("javascript:alert(1)"),
        Some("javascript:".to_string())
    );
    assert_eq!(
        identify_blocked_protocol("file:///etc/passwd"),
        Some("file://".to_string())
    );
    assert_eq!(
        identify_blocked_protocol("https://safe.com"),
        None
    );
}

// =========================================================================
// Excel-Specific Threat Tests
// =========================================================================

#[test]
fn test_excel_sheet_protection_password_detected() {
    let mut report = OoxmlCdrReport::default();
    let mut removed_targets = Vec::new();

    let attrs_str = br#"password="ABCD" sheet="1" objects="1" scenarios="1""#;
    let mut reader = Reader::from_reader(attrs_str.as_slice());
    let mut buf = Vec::new();
    let event = reader.read_event_into(&mut buf).unwrap();

    if let Event::Empty(ref e) | Event::Start(ref e) = event {
        let force_drop = scan_excel_element_threats(
            "sheetProtection",
            e.attributes(),
            &mut report,
            &mut removed_targets,
        );

        assert!(force_drop, "sheetProtection with password should be force-dropped");
        assert_eq!(report.excel_threats_neutralized, 1);
        assert!(matches!(
            report.actions_taken.last(),
            Some(OoxmlCdrAction::SheetProtectionStripped { .. })
        ));
    }
}

#[test]
fn test_excel_sheet_protection_without_password_kept() {
    let mut report = OoxmlCdrReport::default();
    let mut removed_targets = Vec::new();

    let attrs_str = br#"sheet="1" objects="1" scenarios="1""#;
    let mut reader = Reader::from_reader(attrs_str.as_slice());
    let mut buf = Vec::new();
    let event = reader.read_event_into(&mut buf).unwrap();

    if let Event::Empty(ref e) | Event::Start(ref e) = event {
        let force_drop = scan_excel_element_threats(
            "sheetProtection",
            e.attributes(),
            &mut report,
            &mut removed_targets,
        );

        assert!(!force_drop, "sheetProtection without password should NOT be dropped");
        assert_eq!(report.excel_threats_neutralized, 0);
    }
}

#[test]
fn test_excel_data_validation_malicious_url() {
    let mut report = OoxmlCdrReport::default();
    let mut removed_targets = Vec::new();

    let attrs_str = br#"sqref="A1" type="list" formula1="javascript:alert(1)""#;
    let mut reader = Reader::from_reader(attrs_str.as_slice());
    let mut buf = Vec::new();
    let event = reader.read_event_into(&mut buf).unwrap();

    if let Event::Empty(ref e) | Event::Start(ref e) = event {
        let force_drop = scan_excel_element_threats(
            "dataValidation",
            e.attributes(),
            &mut report,
            &mut removed_targets,
        );

        assert!(force_drop, "dataValidation with malicious URL should be force-dropped");
        assert_eq!(report.excel_threats_neutralized, 1);
        assert!(matches!(
            report.actions_taken.last(),
            Some(OoxmlCdrAction::MaliciousDataValidationStripped { .. })
        ));
    }
}

#[test]
fn test_excel_custom_xml_mapping_script_injection() {
    let mut report = OoxmlCdrReport::default();
    let mut removed_targets = Vec::new();

    let attrs_str = r#"id="Map1" RootElement="xss"><script>powershell</script>"#;
    let mut reader = Reader::from_reader(attrs_str.as_bytes());
    let mut buf = Vec::new();
    let event = reader.read_event_into(&mut buf).unwrap();

    if let Event::Start(ref e) = event {
        let force_drop = scan_excel_element_threats(
            "Map",
            e.attributes(),
            &mut report,
            &mut removed_targets,
        );

        assert!(force_drop, "Map with script injection should be force-dropped");
        assert!(matches!(
            report.actions_taken.last(),
            Some(OoxmlCdrAction::CustomXmlMappingStripped { .. })
        ));
    }
}

#[test]
fn test_excel_pivotcache_external_reference() {
    let mut report = OoxmlCdrReport::default();
    let mut removed_targets = Vec::new();

    let attrs_str = br#"id="pivotCacheDef1" cacheId="externalConnection1""#;
    let mut reader = Reader::from_reader(attrs_str.as_slice());
    let mut buf = Vec::new();
    let event = reader.read_event_into(&mut buf).unwrap();

    if let Event::Empty(ref e) | Event::Start(ref e) = event {
        let force_drop = scan_excel_element_threats(
            "pivotCacheDefinition",
            e.attributes(),
            &mut report,
            &mut removed_targets,
        );

        assert!(force_drop, "PivotCache with external ref should be force-dropped");
        assert!(matches!(
            report.actions_taken.last(),
            Some(OoxmlCdrAction::PivotCacheExternalRefStripped { .. })
        ));
    }
}

// =========================================================================
// Word-Specific Threat Tests
// =========================================================================

#[test]
fn test_word_altchunk_removal() {
    let mut report = OoxmlCdrReport::default();
    let mut removed_targets = Vec::new();

    let attrs_str = br#"r:id="rId10""#;
    let mut reader = Reader::from_reader(attrs_str.as_slice());
    let mut buf = Vec::new();
    let event = reader.read_event_into(&mut buf).unwrap();

    if let Event::Empty(ref e) | Event::Start(ref e) = event {
        let force_drop = scan_word_element_threats(
            "altChunk",
            e.attributes(),
            &mut report,
            &mut removed_targets,
        );

        assert!(force_drop, "altChunk should always be force-dropped (major attack vector)");
        assert_eq!(report.word_threats_neutralized, 1);
        assert!(matches!(
            report.actions_taken.last(),
            Some(OoxmlCdrAction::AltChunkRemoved { chunk_id }) if !chunk_id.is_empty()
        ));
        assert!(!removed_targets.is_empty(), "altChunk ID should be added to removed targets");
    }
}

#[test]
fn test_word_hyperlink_dangerous_protocol_blocked() {
    let mut report = OoxmlCdrReport::default();
    let mut removed_targets = Vec::new();

    let attrs_str = br#"Target="javascript:alert(document.cookie)""#;
    let mut reader = Reader::from_reader(attrs_str.as_slice());
    let mut buf = Vec::new();
    let event = reader.read_event_into(&mut buf).unwrap();

    if let Event::Empty(ref e) | Event::Start(ref e) = event {
        let force_drop = scan_word_element_threats(
            "hyperlink",
            e.attributes(),
            &mut report,
            &mut removed_targets,
        );

        assert!(force_drop, "hyperlink with javascript: should be blocked");
        assert!(matches!(
            report.actions_taken.last(),
            Some(OoxmlCdrAction::HyperlinkBlocked { reason, .. })
                if reason.contains("blocked protocol")
        ));
    }
}

#[test]
fn test_word_hyperlink_safe_target_allowed() {
    let mut report = OoxmlCdrReport::default();
    let mut removed_targets = Vec::new();

    let attrs_str = br#"Target="https://example.com/page""#;
    let mut reader = Reader::from_reader(attrs_str.as_slice());
    let mut buf = Vec::new();
    let event = reader.read_event_into(&mut buf).unwrap();

    if let Event::Empty(ref e) | Event::Start(ref e) = event {
        let force_drop = scan_word_element_threats(
            "hyperlink",
            e.attributes(),
            &mut report,
            &mut removed_targets,
        );

        assert!(!force_drop, "hyperlink with https target should be allowed");
        assert_eq!(report.word_threats_neutralized, 0);
    }
}

#[test]
fn test_word_irm_permission_stripping() {
    let mut report = OoxmlCdrReport::default();
    let mut removed_targets = Vec::new();

    let attrs_str = br#"id="perm1" edGrp="none""#;
    let mut reader = Reader::from_reader(attrs_str.as_slice());
    let mut buf = Vec::new();
    let event = reader.read_event_into(&mut buf).unwrap();

    if let Event::Empty(ref e) | Event::Start(ref e) = event {
        let force_drop_start = scan_word_element_threats(
            "permStart",
            e.attributes(),
            &mut report,
            &mut removed_targets,
        );
        assert!(force_drop_start, "permStart should be force-dropped");

        let mut report2 = OoxmlCdrReport::default();
        let mut targets2 = Vec::new();
        let force_drop_end = scan_word_element_threats(
            "permEnd",
            e.attributes(),
            &mut report2,
            &mut targets2,
        );
        assert!(force_drop_end, "permEnd should be force-dropped");

        assert!(matches!(
            report.actions_taken.last(),
            Some(OoxmlCdrAction::IrmPermissionStripped { location })
                if location.contains("permStart")
        ));
    }
}

#[test]
fn test_word_instrtext_script_injection() {
    let config = OoxmlTrueCdrConfig::jp_defaults();
    let mut report = OoxmlCdrReport::default();

    // Safe instrText content should return true (kept)
    let safe_result = scan_text_content_threats(
        "normal field instruction", Some("instrText"),
        OoxmlDocumentType::Word, &config, &mut report,
    );
    assert!(safe_result, "Safe instrText should return true (keep)");
    assert_eq!(report.word_threats_neutralized, 0);

    // PowerShell pattern — should return false (dropped)
    let ps_result = scan_text_content_threats(
        "powershell -encodedcommand XYZ", Some("instrText"),
        OoxmlDocumentType::Word, &config, &mut report,
    );
    assert!(!ps_result, "PowerShell in instrText should be dropped");
    assert!(report.word_threats_neutralized >= 1);

    // cmd.exe pattern — should return false (dropped)
    let cmd_result = scan_text_content_threats(
        "cmd.exe /c whoami", Some("instrText"),
        OoxmlDocumentType::Word, &config, &mut report,
    );
    assert!(!cmd_result, "cmd.exe in instrText should be dropped");

    // VBScript pattern — should return false (dropped)
    let vbs_result = scan_text_content_threats(
        "vbscript:MsgBox \"XSS\"", Some("instrText"),
        OoxmlDocumentType::Word, &config, &mut report,
    );
    assert!(!vbs_result, "VBScript in instrText should be dropped");
}

// =========================================================================
// PowerPoint-Specific Threat Tests
// =========================================================================

#[test]
fn test_powerpoint_ole_object_detection() {
    let mut report = OoxmlCdrReport::default();
    let mut removed_targets = Vec::new();

    let attrs_str = br#"r:id="rId5" progId="Excel.Sheet.12" ShapeId="1""#;
    let mut reader = Reader::from_reader(attrs_str.as_slice());
    let mut buf = Vec::new();
    let event = reader.read_event_into(&mut buf).unwrap();

    if let Event::Empty(ref e) | Event::Start(ref e) = event {
        let force_drop = scan_powerpoint_element_threats(
            "oleObj",
            e.attributes(),
            &mut report,
            &mut removed_targets,
        );

        assert!(force_drop, "oleObj should be detected and force-dropped");
        assert_eq!(report.powerpoint_threats_neutralized, 1);
        assert!(matches!(
            report.actions_taken.last(),
            Some(OoxmlCdrAction::OleObjectDetected { object_id })
                if !object_id.is_empty()
        ));
    }
}

#[test]
fn test_powerpoint_external_sound_stripped() {
    let mut report = OoxmlCdrReport::default();
    let mut removed_targets = Vec::new();

    // External URL sound
    let attrs_str = br#"name="http://evil.com/tracking.wav""#;
    let mut reader = Reader::from_reader(attrs_str.as_slice());
    let mut buf = Vec::new();
    let event = reader.read_event_into(&mut buf).unwrap();

    if let Event::Empty(ref e) | Event::Start(ref e) = event {
        let force_drop = scan_powerpoint_element_threats(
            "snd",
            e.attributes(),
            &mut report,
            &mut removed_targets,
        );

        assert!(force_drop, "External sound reference should be stripped");
        assert!(matches!(
            report.actions_taken.last(),
            Some(OoxmlCdrAction::ExternalSoundStripped { sound_ref })
                if sound_ref.contains("evil.com")
        ));
    }

    // Internal package sound should be allowed
    let mut report2 = OoxmlCdrReport::default();
    let mut targets2 = Vec::new();
    let internal_snd = br#"name="click.wav""#;
    let mut reader2 = Reader::from_reader(internal_snd.as_slice());
    let mut buf2 = Vec::new();
    let event2 = reader2.read_event_into(&mut buf2).unwrap();

    if let Event::Empty(ref e) | Event::Start(ref e) = event2 {
        let force_drop_internal = scan_powerpoint_element_threats(
            "snd",
            e.attributes(),
            &mut report2,
            &mut targets2,
        );
        assert!(!force_drop_internal, "Internal sound name should be allowed");
    }
}

#[test]
fn test_powerpoint_extlst_removal() {
    let mut report = OoxmlCdrReport::default();
    let mut removed_targets = Vec::new();

    let attrs_str = br#"uri="{some-vendor-extension}""#;
    let mut reader = Reader::from_reader(attrs_str.as_slice());
    let mut buf = Vec::new();
    let event = reader.read_event_into(&mut buf).unwrap();

    if let Event::Empty(ref e) | Event::Start(ref e) = event {
        let force_drop = scan_powerpoint_element_threats(
            "extLst",
            e.attributes(),
            &mut report,
            &mut removed_targets,
        );

        assert!(force_drop, "extLst should always be removed (zero-day attack vector)");
        assert_eq!(report.powerpoint_threats_neutralized, 1);
        assert!(matches!(
            report.actions_taken.last(),
            Some(OoxmlCdrAction::ExtLstRemoved { location })
                if !location.is_empty()
        ));
    }
}

#[test]
fn test_powerpoint_animation_cmd_filtering() {
    let config = OoxmlTrueCdrConfig::jp_defaults();
    let mut report = OoxmlCdrReport::default();

    // Safe animation command
    let safe = scan_text_content_threats(
        "ppaction://hlinksldjump",
        Some("cmd"),
        OoxmlDocumentType::PowerPoint,
        &config,
        &mut report,
    );
    assert!(safe, "Safe PowerPoint cmd should be kept");
    assert_eq!(report.powerpoint_threats_neutralized, 0);

    // JavaScript in animation command
    let js_attack = scan_text_content_threats(
        "javascript:alert(1)",
        Some("cmd"),
        OoxmlDocumentType::PowerPoint,
        &config,
        &mut report,
    );
    assert!(!js_attack, "JavaScript in PPT cmd should be stripped");
    assert!(report.powerpoint_threats_neutralized >= 1);

    // VBScript in animation command
    let vbs_attack = scan_text_content_threats(
        "vbscript:ExecuteGlobal",
        Some("cmd"),
        OoxmlDocumentType::PowerPoint,
        &config,
        &mut report,
    );
    assert!(!vbs_attack, "VBScript in PPT cmd should be stripped");
}

#[test]
fn test_powerpoint_cbhvr_malicious_action() {
    let mut report = OoxmlCdrReport::default();
    let mut removed_targets = Vec::new();

    let attrs_str = br#"action="javascript:alert(1)" verb="onload""#;
    let mut reader = Reader::from_reader(attrs_str.as_slice());
    let mut buf = Vec::new();
    let event = reader.read_event_into(&mut buf).unwrap();

    if let Event::Empty(ref e) | Event::Start(ref e) = event {
        let force_drop = scan_powerpoint_element_threats(
            "cBhvr",
            e.attributes(),
            &mut report,
            &mut removed_targets,
        );

        assert!(force_drop, "cBhvr with javascript action should be force-dropped");
        assert!(report.powerpoint_threats_neutralized >= 1);
    }
}

// =========================================================================
// Cross-Cutting Tests
// =========================================================================

#[test]
fn test_script_injection_pattern_coverage() {
    // All defined patterns should be detected
    assert!(contains_script_injection("run powershell script"));
    assert!(contains_script_injection("execute cmd.exe"));
    assert!(contains_script_injection("cmd /c dir"));
    assert!(contains_script_injection("cmd /k ping"));
    assert!(contains_script_injection("vbscript:code"));
    assert!(contains_script_injection("jscript:x"));
    assert!(contains_script_injection("create WScript.Shell"));
    assert!(contains_script_injection("shell.execute"));
    assert!(contains_script_injection("eval(malicious)"));
    assert!(contains_script_injection("document.write(xss)"));

    // Normal text should not trigger
    assert!(!contains_script_injection("The document describes shell companies."));
    assert!(!contains_script_injection("Evaluation of the product."));
    assert!(!contains_script_injection("Command line interface tutorial."));
}

#[test]
fn test_enhanced_report_tracking() {
    let mut report = OoxmlCdrReport::default();

    assert!(!report.has_modifications());

    report.dde_attacks_detected = 1;
    assert!(report.has_modifications());

    report = OoxmlCdrReport::default();
    report.excel_threats_neutralized = 3;
    assert!(report.has_modifications());

    report = OoxmlCdrReport::default();
    report.word_threats_neutralized = 2;
    assert!(report.has_modifications());

    report = OoxmlCdrReport::default();
    report.powerpoint_threats_neutralized = 4;
    assert!(report.has_modifications());

    report = OoxmlCdrReport::default();
    report.actions_taken.push(OoxmlCdrAction::VbaMacroRemoved {
        filename: "test".to_string(),
    });
    assert!(report.has_modifications());
}

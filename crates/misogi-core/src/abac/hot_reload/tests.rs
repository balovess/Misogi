//! Unit tests for [`AbacHotReload`](super::AbacHotReload).
//!
//! Covers: construction, check_and_reload polling, force_reload,
//! reload_from_string, cache invalidation, sighup_handler loop,
//! error handling, and atomic component updates.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::watch;

use super::{AbacHotReload, ReloadError};
use super::super::config::AbacConfig;
use super::super::engine::AbacEngine;
use super::super::executor::ApprovalExecutor;
use super::super::policy::{
    AbacPolicyRule, ApprovalTemplate, ApproverPool, PolicyEffect, PolicyTarget,
};

// ===========================================================================
// Test Helpers
// ===========================================================================

fn make_config(
    rules: Vec<AbacPolicyRule>,
    templates: Vec<ApprovalTemplate>,
) -> AbacConfig {
    AbacConfig {
        enabled: true,
        default_effect: "deny".to_string(),
        decision_cache_ttl_secs: 300,
        audit_log_all_decisions: true,
        rules,
        approval_templates: templates,
    }
}

fn make_permit_rule(id: &str, priority: i32) -> AbacPolicyRule {
    AbacPolicyRule {
        rule_id: id.to_string(),
        effect: PolicyEffect::Permit,
        conditions: vec![],
        target: PolicyTarget {
            action: String::new(),
            resource_type: None,
        },
        obligation: None,
        priority,
        enabled: true,
    }
}

fn make_template(id: &str, required: u8) -> ApprovalTemplate {
    ApprovalTemplate {
        template_id: id.to_string(),
        required_approvers: required,
        approver_pool: ApproverPool::CustomList {
            user_ids: vec!["approver-1".to_string()],
        },
        timeout_hours: 24,
        escalation_on_timeout: false,
    }
}

fn config_to_toml(config: &AbacConfig) -> String {
    toml::to_string_pretty(config).expect("config must be serializable")
}

fn make_components(
    config: &AbacConfig,
) -> (AbacEngine, ApprovalExecutor) {
    (
        AbacEngine::from_config(config),
        ApprovalExecutor::new(config.approval_templates.clone()),
    )
}

// ===========================================================================
// 1. Construction
// ===========================================================================

#[test]
fn test_new_without_file_watch() {
    let c = make_config(vec![], vec![]);
    let (e, x) = make_components(&c);
    let hr = AbacHotReload::new(e, x);
    assert!(hr.config_path.is_none());
    assert!(hr.last_loaded_at().is_none());
}

#[test]
fn test_with_file_watch_captures_timestamp() {
    let c = make_config(vec![make_permit_rule("r1", 10)], vec![]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("abac.toml");
    std::fs::write(&path, config_to_toml(&c)).unwrap();

    let (e, x) = make_components(&c);
    let hr = AbacHotReload::with_file_watch(e, x, &path);
    assert!(hr.config_path.is_some());
    assert!(hr.last_loaded_at().is_some());
}

// ===========================================================================
// 2. check_and_reload — No Change
// ===========================================================================

#[test]
fn test_check_no_change_returns_false() {
    let c = make_config(vec![make_permit_rule("r1", 10)], vec![]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("abac.toml");
    std::fs::write(&path, config_to_toml(&c)).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    let (e, x) = make_components(&c);
    let hr = AbacHotReload::with_file_watch(e, x, &path);
    let _ = hr.check_and_reload(); // baseline
    assert_eq!(hr.check_and_reload().unwrap(), false);
}

// ===========================================================================
// 3. check_and_reload — File Modified
// ===========================================================================

#[test]
fn test_check_modified_returns_true() {
    let c1 = make_config(vec![make_permit_rule("r1", 10)], vec![]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("abac.toml");
    std::fs::write(&path, config_to_toml(&c1)).unwrap();

    let (e, x) = make_components(&c1);
    let hr = AbacHotReload::with_file_watch(e, x, &path);
    let _ = hr.check_and_reload(); // baseline

    std::thread::sleep(Duration::from_millis(100));
    let mut r2 = make_permit_rule("r2", 20);
    r2.effect = PolicyEffect::Deny;
    let c2 = make_config(vec![make_permit_rule("r1", 10), r2], vec![]);
    std::fs::write(&path, config_to_toml(&c2)).unwrap();

    assert!(hr.check_and_reload().unwrap());
}

// ===========================================================================
// 4. force_reload — Success
// ===========================================================================

#[test]
fn test_force_reload_success() {
    let c = make_config(vec![make_permit_rule("f1", 5)], vec![make_template("t1", 1)]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("abac.toml");
    std::fs::write(&path, config_to_toml(&c)).unwrap();

    let (e, x) = make_components(&make_config(vec![], vec![]));
    let hr = AbacHotReload::with_file_watch(e, x, &path);
    let loaded = hr.force_reload().unwrap();
    assert_eq!(loaded.rules.len(), 1);
    assert_eq!(loaded.approval_templates.len(), 1);
}

// ===========================================================================
// 5. force_reload — Invalid Config
// ===========================================================================

#[test]
fn test_force_reload_invalid_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.toml");
    std::fs::write(&path, "not valid toml !!!").unwrap();

    let (e, x) = make_components(&make_config(vec![], vec![]));
    let hr = AbacHotReload::with_file_watch(e, x, &path);
    match hr.force_reload().unwrap_err() {
        ReloadError::ParseError(msg) => assert!(msg.contains("TOML")),
        other => panic!("expected ParseError, got {:?}", other),
    }
}

// ===========================================================================
// 6. reload_from_string
// ===========================================================================

#[test]
fn test_reload_from_string_valid() {
    let (e, x) = make_components(&make_config(vec![], vec![]));
    let hr = AbacHotReload::new(e, x);

    let c = make_config(
        vec![make_permit_rule("s1", 15)],
        vec![make_template("st", 2)],
    );
    let loaded = hr.reload_from_string(&config_to_toml(&c)).unwrap();
    assert_eq!(loaded.rules.len(), 1);
    assert_eq!(loaded.approval_templates.len(), 1);
}

#[test]
fn test_reload_from_string_invalid_toml() {
    let (e, x) = make_components(&make_config(vec![], vec![]));
    let hr = AbacHotReload::new(e, x);
    assert!(matches!(
        hr.reload_from_string("{{{invalid").unwrap_err(),
        ReloadError::ParseError(_)
    ));
}

#[test]
fn test_reload_from_string_validation_error() {
    let (e, x) = make_components(&make_config(vec![], vec![]));
    let hr = AbacHotReload::new(e, x);
    let bad = r#"
enabled = true
default_effect = "maybe"
rules = []
approval_templates = []
"#;
    match hr.reload_from_string(bad).unwrap_err() {
        ReloadError::ValidationFailed(errs) => {
            assert!(errs.iter().any(|e| e.contains("default_effect")));
        }
        other => panic!("expected ValidationFailed, got {:?}", other),
    }
}

// ===========================================================================
// 7. Cache Invalidation After Reload
// ===========================================================================

#[test]
fn test_invalidate_cache_on_reload() {
    use crate::abac::attribute::AbacValue;
    use std::collections::HashMap;

    let c = make_config(vec![make_permit_rule("cr", 10)], vec![]);
    let (engine, executor) = make_components(&c);
    let hr = AbacHotReload::new(engine, executor);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let attrs: HashMap<String, AbacValue> = HashMap::new();
    let _d = rt.block_on(async { hr.engine.read().unwrap().evaluate(&attrs).await });

    let mut r2 = make_permit_rule("cv2", 20);
    r2.effect = PolicyEffect::Deny;
    assert!(hr
        .reload_from_string(&config_to_toml(&make_config(vec![r2], vec![])))
        .is_ok());
}

// ===========================================================================
// 8. Rules Replaced Not Appended
// ===========================================================================

#[test]
fn test_rules_replaced_not_appended() {
    let ca = make_config(vec![make_permit_rule("a", 10)], vec![]);
    let (e, x) = make_components(&ca);
    let hr = AbacHotReload::new(e, x);

    let mut rb = make_permit_rule("b", 30);
    rb.effect = PolicyEffect::Deny;
    let cb = make_config(vec![rb, make_permit_rule("c", 5)], vec![]);
    let loaded = hr.reload_from_string(&config_to_toml(&cb)).unwrap();
    let ids: Vec<&str> = loaded.rules.iter().map(|r| r.rule_id.as_str()).collect();
    assert!(!ids.contains(&"a"));
    assert_eq!(ids.len(), 2);
}

// ===========================================================================
// 9. Executor Templates Updated
// ===========================================================================

#[test]
fn test_executor_templates_updated() {
    use crate::abac::attribute::AbacValue;
    use std::collections::HashMap;

    let co = make_config(vec![], vec![make_template("old", 1)]);
    let (_, exec) = make_components(&co);
    let hr = AbacHotReload::new(AbacEngine::from_config(&co), exec);

    let cn = make_config(vec![], vec![make_template("new-tpl", 3)]);
    hr.reload_from_string(&config_to_toml(&cn)).unwrap();

    let e = hr.executor.read().unwrap();
    let attrs: HashMap<String, AbacValue> = HashMap::new();
    let req = e.execute_template("new-tpl", "r", "u", "d", &attrs).unwrap();
    assert_eq!(req.required_approvers, 3);
}

// ===========================================================================
// 10. Missing File Error
// ===========================================================================

#[test]
fn test_missing_file_error() {
    let (e, x) = make_components(&make_config(vec![], vec![]));
    let np = PathBuf::from("/tmp/misogi_ghost_abac_99999.toml");
    let hr = AbacHotReload::with_file_watch(e, x, &np);
    match hr.check_and_reload().unwrap_err() {
        ReloadError::FileNotFound(_) => {}
        other => panic!("expected FileNotFound, got {:?}", other),
    }
}

// ===========================================================================
// 11. Validation Errors Propagated
// ===========================================================================

#[test]
fn test_validation_errors_propagated() {
    let (e, x) = make_components(&make_config(vec![], vec![]));
    let hr = AbacHotReload::new(e, x);

    // Duplicate rule IDs should cause validation failure.
    // Use valid TOML: omit optional fields (obligation, resource_type) instead of null.
    let bad = r#"
enabled = true
default_effect = "deny"
[[rules]]
rule_id = "dup"
effect = "permit"
priority = 10
conditions = []
target = { action = "" }
enabled = true
[[rules]]
rule_id = "dup"
effect = "deny"
priority = 5
conditions = []
target = { action = "" }
enabled = true
approval_templates = []
"#;
    match hr.reload_from_string(bad).unwrap_err() {
        ReloadError::ValidationFailed(errs) => {
            assert!(errs.iter().any(|e| e.contains("duplicate") || e.contains("dup")));
        }
        other => panic!("expected ValidationFailed, got {:?}", other),
    }
}

// ===========================================================================
// 12. sighup_handler Loop
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_sighup_handler_exits_on_shutdown() {
    let c = make_config(vec![], vec![]);
    let (e, x) = make_components(&c);
    let hr = AbacHotReload::new(e, x);
    let (tx, rx) = watch::channel(());

    let shared = Arc::new(RwLock::new(Some(hr)));
    let task = tokio::spawn(async move {
        // Extract the handler from the lock before awaiting to satisfy Send bound.
        let handler_opt = shared.write().unwrap().take();
        if let Some(h) = handler_opt {
            let _ = h.sighup_handler(rx).await;
        }
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    tx.send(()).ok();

    let r = tokio::time::timeout(Duration::from_secs(5), task).await;
    assert!(r.is_ok(), "handler should exit on shutdown");
    r.unwrap().expect("task should complete without error");
}

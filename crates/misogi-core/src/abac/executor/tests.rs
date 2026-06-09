//! Unit tests for [`ApprovalExecutor`](super::ApprovalExecutor).
//!
//! Covers: template execution, approver selection strategies, approval
//! recording with auto-completion, timeout handling, cancellation, query
//! operations, and error paths.

use std::collections::HashMap;

use chrono::Utc;

use super::super::attribute::AbacValue;
use super::super::policy::{ApprovalTemplate, ApproverPool};
use super::types::AbacApprovalStatus;
use super::{ApprovalExecutor, ExecutorError};

// ===========================================================================
// Test Helpers
// ===========================================================================

/// Creates a minimal valid `ApprovalTemplate` for testing.
fn make_template(
    id: &str,
    required: u8,
    pool: ApproverPool,
    timeout_hours: u32,
    escalate: bool,
) -> ApprovalTemplate {
    ApprovalTemplate {
        template_id: id.to_string(),
        required_approvers: required,
        approver_pool: pool,
        timeout_hours,
        escalation_on_timeout: escalate,
    }
}

/// Creates a basic attribute map for testing.
fn make_attr_map(pairs: Vec<(&str, AbacValue)>) -> HashMap<String, AbacValue> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

/// Creates a role-based pool with the given role names.
fn role_pool(roles: &[&str]) -> ApproverPool {
    ApproverPool::Role {
        roles: roles.iter().map(|r| r.to_string()).collect(),
    }
}

/// Creates a custom-list pool with the given user IDs.
fn custom_pool(user_ids: &[&str]) -> ApproverPool {
    ApproverPool::CustomList {
        user_ids: user_ids.iter().map(|u| u.to_string()).collect(),
    }
}

// ===========================================================================
// 1. Execute Template — Basic Success
// ===========================================================================

#[test]
fn test_execute_template_creates_pending_request() {
    let tpl = make_template("tpl-1", 1, custom_pool(&["approver-1"]), 24, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);

    let req = exec
        .execute_template("tpl-1", "rule-001", "user-alice", "transfer file X", &attrs)
        .expect("execution should succeed");

    assert_eq!(req.status, AbacApprovalStatus::Pending);
    assert_eq!(req.template_id, "tpl-1");
    assert_eq!(req.triggered_by_rule, "rule-001");
    assert_eq!(req.subject_user_id, "user-alice");
    assert_eq!(req.resource_description, "transfer file X");
    assert_eq!(req.required_approvers, 1);
    assert_eq!(req.selected_approvers, vec!["approver-1"]);
    assert_eq!(req.timeout_hours, 24);
    assert!(!req.escalation_on_timeout);
    assert!(!req.request_id.is_empty());
}

#[test]
fn test_execute_template_generates_unique_request_ids() {
    let tpl = make_template("tpl", 1, custom_pool(&["a"]), 1, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);

    let req1 = exec.execute_template("tpl", "r", "u", "d", &attrs).unwrap();
    let req2 = exec.execute_template("tpl", "r", "u", "d", &attrs).unwrap();

    assert_ne!(req1.request_id, req2.request_id);
}

#[test]
fn test_execute_template_sets_created_timestamp() {
    let tpl = make_template("tpl", 1, custom_pool(&["a"]), 1, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);
    let before = Utc::now();

    let req = exec.execute_template("tpl", "r", "u", "d", &attrs).unwrap();
    let after = Utc::now();

    assert!(req.created_at >= before && req.created_at <= after);
}

// ===========================================================================
// 2. Role-Based Approver Selection
// ===========================================================================

#[test]
fn test_role_based_approver_selection_finds_matching_users() {
    let tpl = make_template("tpl-role", 1, role_pool(&["manager"]), 24, false);
    let exec = ApprovalExecutor::new(vec![tpl]);

    // Simulate attribute map containing role membership info
    let attrs = make_attr_map(vec![(
        "role_members_manager",
        AbacValue::List(vec![
            AbacValue::String("mgr-bob".to_string()),
            AbacValue::String("mgr-carol".to_string()),
        ]),
    )]);

    let req = exec
        .execute_template("tpl-role", "r", "u", "d", &attrs)
        .expect("should find approvers");

    assert_eq!(req.selected_approvers.len(), 2);
    assert!(req.selected_approvers.contains(&"mgr-bob".to_string()));
    assert!(req.selected_approvers.contains(&"mgr-carol".to_string()));
}

#[test]
fn test_role_based_multiple_roles_union() {
    let tpl = make_template(
        "tpl-multi",
        1,
        role_pool(&["manager", "security_officer"]),
        24,
        false,
    );
    let exec = ApprovalExecutor::new(vec![tpl]);

    let attrs = make_attr_map(vec![
        (
            "role_members_manager",
            AbacValue::List(vec![AbacValue::String("mgr-a".to_string())]),
        ),
        (
            "role_members_security_officer",
            AbacValue::List(vec![AbacValue::String("sec-b".to_string())]),
        ),
    ]);

    let req = exec
        .execute_template("tpl-multi", "r", "u", "d", &attrs)
        .unwrap();
    assert_eq!(req.selected_approvers.len(), 2);
}

// ===========================================================================
// 3. DepartmentHead Approver Selection
// ===========================================================================

#[test]
fn test_department_head_selection() {
    let tpl = make_template("tpl-dh", 1, ApproverPool::DepartmentHead, 24, false);
    let exec = ApprovalExecutor::new(vec![tpl]);

    let attrs = make_attr_map(vec![(
        "department_head",
        AbacValue::String("head-tanaka".to_string()),
    )]);

    let req = exec
        .execute_template("tpl-dh", "r", "u", "d", &attrs)
        .expect("should find department head");

    assert_eq!(req.selected_approvers, vec!["head-tanaka"]);
}

#[test]
fn test_department_head_missing_returns_empty() {
    let tpl = make_template("tpl-dh", 1, ApproverPool::DepartmentHead, 24, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]); // No department_head key

    let result = exec.execute_template("tpl-dh", "r", "u", "d", &attrs);
    assert!(matches!(result, Err(ExecutorError::NoApproversAvailable)));
}

// ===========================================================================
// 4. CustomList Approver Selection
// ===========================================================================

#[test]
fn test_custom_list_approver_selection() {
    let tpl = make_template(
        "tpl-custom",
        2,
        custom_pool(&["user-x", "user-y", "user-z"]),
        48,
        true,
    );
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);

    let req = exec
        .execute_template("tpl-custom", "r", "u", "d", &attrs)
        .unwrap();
    assert_eq!(req.selected_approvers, vec!["user-x", "user-y", "user-z"]);
    assert_eq!(req.required_approvers, 2);
}

// ===========================================================================
// 5. Error Paths
// ===========================================================================

#[test]
fn test_template_not_found_error() {
    let exec = ApprovalExecutor::new(vec![]);
    let attrs = make_attr_map(vec![]);

    let err = exec
        .execute_template("nonexistent", "r", "u", "d", &attrs)
        .unwrap_err();
    assert!(matches!(err, ExecutorError::TemplateNotFound(id) if id == "nonexistent"));
}

#[test]
fn test_no_approvers_available_error_for_empty_role_list() {
    let tpl = make_template(
        "tpl-empty-role",
        1,
        role_pool(&["nonexistent_role"]),
        24,
        false,
    );
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]); // No role_members_* keys

    let err = exec
        .execute_template("tpl-empty-role", "r", "u", "d", &attrs)
        .unwrap_err();
    assert!(matches!(err, ExecutorError::NoApproversAvailable));
}

// ===========================================================================
// 6. Timeout Handling
// ===========================================================================

#[test]
fn test_handle_timeout_with_escalation() {
    let tpl = make_template("tpl-e", 1, custom_pool(&["a"]), 1, true);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);

    let req = exec
        .execute_template("tpl-e", "r", "u", "d", &attrs)
        .unwrap();
    let req_id = req.request_id.clone();

    // Run in a blocking context for synchronous test
    let rt = tokio::runtime::Runtime::new().unwrap();
    let status = rt.block_on(exec.handle_timeout(&req_id)).unwrap();

    assert_eq!(status, AbacApprovalStatus::Escalated);
    let updated = exec.get_request_status(&req_id).unwrap();
    assert_eq!(updated.status, AbacApprovalStatus::Escalated);
}

#[test]
fn test_handle_timeout_without_escalation() {
    let tpl = make_template("tpl-te", 1, custom_pool(&["a"]), 1, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);

    let req = exec
        .execute_template("tpl-te", "r", "u", "d", &attrs)
        .unwrap();
    let req_id = req.request_id.clone();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let status = rt.block_on(exec.handle_timeout(&req_id)).unwrap();

    assert_eq!(status, AbacApprovalStatus::TimedOut);
    let updated = exec.get_request_status(&req_id).unwrap();
    assert_eq!(updated.status, AbacApprovalStatus::TimedOut);
}

#[test]
fn test_handle_timeout_nonexistent_request() {
    let exec = ApprovalExecutor::new(vec![]);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let err = rt.block_on(exec.handle_timeout("no-such-id")).unwrap_err();
    assert!(matches!(err, ExecutorError::RequestNotFound(_)));
}

#[test]
fn test_handle_timeout_already_completed() {
    let tpl = make_template("tpl", 1, custom_pool(&["a"]), 1, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);
    let req = exec.execute_template("tpl", "r", "u", "d", &attrs).unwrap();

    // First approve it to terminal state
    exec.record_approval(&req.request_id, "a", true).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let err = rt
        .block_on(exec.handle_timeout(&req.request_id))
        .unwrap_err();
    assert!(
        matches!(err, ExecutorError::InvalidStateTransition { .. }),
        "expected InvalidStateTransition, got {:?}",
        err
    );
}

// ===========================================================================
// 7. Approval Recording — Progression and Auto-Completion
// ===========================================================================

#[test]
fn test_record_approval_progresses_toward_completion() {
    let tpl = make_template("tpl-2", 2, custom_pool(&["a1", "a2", "a3"]), 24, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);
    let req = exec
        .execute_template("tpl-2", "r", "u", "d", &attrs)
        .unwrap();

    // First approval: still pending (need 2)
    let s1 = exec.record_approval(&req.request_id, "a1", true).unwrap();
    assert_eq!(s1, AbacApprovalStatus::Pending);

    let current = exec.get_request_status(&req.request_id).unwrap();
    assert_eq!(current.status, AbacApprovalStatus::Pending);
}

#[test]
fn test_record_approval_auto_completes_when_threshold_met() {
    let tpl = make_template("tpl-2ok", 2, custom_pool(&["a1", "a2"]), 24, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);
    let req = exec
        .execute_template("tpl-2ok", "r", "u", "d", &attrs)
        .unwrap();

    // First approval
    exec.record_approval(&req.request_id, "a1", true).unwrap();
    // Second approval: should auto-complete
    let s2 = exec.record_approval(&req.request_id, "a2", true).unwrap();
    assert_eq!(s2, AbacApprovalStatus::Approved);

    let final_req = exec.get_request_status(&req.request_id).unwrap();
    assert_eq!(final_req.status, AbacApprovalStatus::Approved);
}

#[test]
fn test_record_approval_rejects_if_any_rejects() {
    let tpl = make_template("tpl-rej", 2, custom_pool(&["a1", "a2", "a3"]), 24, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);
    let req = exec
        .execute_template("tpl-rej", "r", "u", "d", &attrs)
        .unwrap();

    // One approval first
    exec.record_approval(&req.request_id, "a1", true).unwrap();
    // Then a rejection: immediate Rejected
    let sr = exec.record_approval(&req.request_id, "a2", false).unwrap();
    assert_eq!(sr, AbacApprovalStatus::Rejected);

    let final_req = exec.get_request_status(&req.request_id).unwrap();
    assert_eq!(final_req.status, AbacApprovalStatus::Rejected);
}

#[test]
fn test_duplicate_approval_error() {
    // Use required_approvers=2 so first approval does NOT auto-complete
    let tpl = make_template("tpl-dup", 2, custom_pool(&["a1", "a2"]), 24, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);
    let req = exec
        .execute_template("tpl-dup", "r", "u", "d", &attrs)
        .unwrap();

    // First response is fine (still pending since need 2 approvals)
    exec.record_approval(&req.request_id, "a1", true).unwrap();
    // Second response from same approver should fail with DuplicateApproval
    let err = exec
        .record_approval(&req.request_id, "a1", false)
        .unwrap_err();
    assert!(matches!(err, ExecutorError::DuplicateApproval(id) if id == "a1"));
}

#[test]
fn test_record_approval_nonexistent_request() {
    let exec = ApprovalExecutor::new(vec![]);
    let err = exec.record_approval("ghost", "someone", true).unwrap_err();
    assert!(matches!(err, ExecutorError::RequestNotFound(_)));
}

#[test]
fn test_record_approval_already_terminal_state() {
    let tpl = make_template("tpl-term", 1, custom_pool(&["a"]), 24, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);
    let req = exec
        .execute_template("tpl-term", "r", "u", "d", &attrs)
        .unwrap();

    // Complete the request
    exec.record_approval(&req.request_id, "a", true).unwrap();

    // Try to record another approval on completed request
    let err = exec
        .record_approval(&req.request_id, "a", true)
        .unwrap_err();
    assert!(
        matches!(err, ExecutorError::InvalidStateTransition { .. }),
        "expected InvalidStateTransition, got {:?}",
        err
    );
}

// ===========================================================================
// 8. Query Operations
// ===========================================================================

#[test]
fn test_get_request_status_existing() {
    let tpl = make_template("tpl-q", 1, custom_pool(&["a"]), 1, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);
    let req = exec
        .execute_template("tpl-q", "r", "u", "d", &attrs)
        .unwrap();

    let found = exec.get_request_status(&req.request_id);
    assert!(found.is_some());
    assert_eq!(found.unwrap().request_id, req.request_id);
}

#[test]
fn test_get_request_status_nonexistent() {
    let exec = ApprovalExecutor::new(vec![]);
    assert!(exec.get_request_status("ghost").is_none());
}

#[test]
fn test_list_pending_for_approver_filters_correctly() {
    let tpl = make_template("tpl-lp", 1, custom_pool(&["app-a", "app-b"]), 24, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);

    // Create a request where both app-a and app-b are approvers
    let req = exec
        .execute_template("tpl-lp", "r", "u", "d", &attrs)
        .unwrap();

    // app-a should see this request
    let for_a = exec.list_pending_for_approver("app-a");
    assert_eq!(for_a.len(), 1);
    assert_eq!(for_a[0].request_id, req.request_id);

    // app-b should also see this request
    let for_b = exec.list_pending_for_approver("app-b");
    assert_eq!(for_b.len(), 1);

    // app-c is not an approver; should see nothing
    let for_c = exec.list_pending_for_approver("app-c");
    assert!(for_c.is_empty());

    // After completion, no one should see it as pending
    exec.record_approval(&req.request_id, "app-a", true)
        .unwrap();
    let for_a_after = exec.list_pending_for_approver("app-a");
    assert!(for_a_after.is_empty());
}

// ===========================================================================
// 9. Cancellation
// ===========================================================================

#[test]
fn test_cancel_request_success() {
    let tpl = make_template("tpl-can", 1, custom_pool(&["a"]), 1, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);
    let req = exec
        .execute_template("tpl-can", "r", "u", "d", &attrs)
        .unwrap();

    exec.cancel_request(&req.request_id).unwrap();

    let cancelled = exec.get_request_status(&req.request_id).unwrap();
    assert_eq!(cancelled.status, AbacApprovalStatus::Cancelled);
}

#[test]
fn test_cancel_nonexistent_request() {
    let exec = ApprovalExecutor::new(vec![]);
    let err = exec.cancel_request("ghost").unwrap_err();
    assert!(matches!(err, ExecutorError::RequestNotFound(_)));
}

#[test]
fn test_cancel_already_completed_request() {
    let tpl = make_template("tpl-can-done", 1, custom_pool(&["a"]), 1, false);
    let exec = ApprovalExecutor::new(vec![tpl]);
    let attrs = make_attr_map(vec![]);
    let req = exec
        .execute_template("tpl-can-done", "r", "u", "d", &attrs)
        .unwrap();

    // Complete first
    exec.record_approval(&req.request_id, "a", true).unwrap();

    // Cancel should fail
    let err = exec.cancel_request(&req.request_id).unwrap_err();
    assert!(
        matches!(err, ExecutorError::InvalidStateTransition { .. }),
        "expected InvalidStateTransition, got {:?}",
        err
    );
}

// ===========================================================================
// 10. Template Management
// ===========================================================================

#[test]
fn test_register_template_adds_new_template() {
    let exec = ApprovalExecutor::new(vec![]);
    let new_tpl = make_template("new-tpl", 1, custom_pool(&["x"]), 12, false);

    exec.register_template(new_tpl);

    let attrs = make_attr_map(vec![]);
    let req = exec.execute_template("new-tpl", "r", "u", "d", &attrs);
    assert!(req.is_ok());
    assert_eq!(req.unwrap().status, AbacApprovalStatus::Pending);
}

#[test]
fn test_register_template_replaces_existing() {
    let tpl_v1 = make_template("tpl-v1", 1, custom_pool(&["old-approver"]), 24, false);
    let exec = ApprovalExecutor::new(vec![tpl_v1]);

    let tpl_v2 = make_template(
        "tpl-v1",
        2,
        custom_pool(&["new-approver-a", "new-approver-b"]),
        48,
        true,
    );
    exec.register_template(tpl_v2);

    let attrs = make_attr_map(vec![]);
    let req = exec
        .execute_template("tpl-v1", "r", "u", "d", &attrs)
        .unwrap();
    assert_eq!(req.required_approvers, 2);
    assert_eq!(req.selected_approvers.len(), 2);
    assert_eq!(req.timeout_hours, 48);
    assert!(req.escalation_on_timeout);
}

// ===========================================================================
// 11. AbacApprovalStatus Terminal State Check
// ===========================================================================

#[test]
fn test_approval_status_is_terminal() {
    assert!(!AbacApprovalStatus::Pending.is_terminal());
    assert!(AbacApprovalStatus::Approved.is_terminal());
    assert!(AbacApprovalStatus::Rejected.is_terminal());
    assert!(AbacApprovalStatus::TimedOut.is_terminal());
    assert!(AbacApprovalStatus::Escalated.is_terminal());
    assert!(AbacApprovalStatus::Cancelled.is_terminal());
}

//! `admin.agent.modify` handler tests (F-B).
//!
//! Lives in a sibling file rather than next to the rest of the agent
//! lifecycle tests in `state_tests.rs` because the latter is close to
//! the per-file CI line cap. The split is purely mechanical — the
//! shared fixture and assertion helpers are re-defined locally so each
//! test is self-contained.

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::groups::{BUILTIN_AGENT, BUILTIN_RESTRICTED};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};
use tempfile::TempDir;

use super::handlers;
use crate::Kernel;

async fn fixture() -> (TempDir, Arc<Kernel>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    (dir, kernel)
}

fn pid(name: &str) -> PrincipalId {
    PrincipalId::new(name).unwrap()
}

fn assert_success(res: &AdminResponseBody) {
    match res {
        AdminResponseBody::Success(_)
        | AdminResponseBody::Quotas(_)
        | AdminResponseBody::Usage(_)
        | AdminResponseBody::AgentList(_)
        | AdminResponseBody::GroupList(_)
        | AdminResponseBody::Invite(_)
        | AdminResponseBody::InviteRedeemed(_)
        | AdminResponseBody::InviteList(_)
        | AdminResponseBody::PairToken(_)
        | AdminResponseBody::PairTokenRedeemed(_) => {},
        AdminResponseBody::Error(msg) => panic!("expected success, got Error: {msg}"),
    }
}

fn assert_error_contains(res: &AdminResponseBody, needle: &str) {
    match res {
        AdminResponseBody::Error(msg) => {
            assert!(
                msg.contains(needle),
                "expected error to contain {needle:?}, got: {msg}"
            );
        },
        other => panic!("expected Error, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_modify_adds_and_removes_groups_idempotently() {
    // F-B: agent.modify should partial-update group membership and
    // be idempotent — re-applying the same change is a no-op.
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "mia".into(),
            groups: vec![BUILTIN_AGENT.into()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;

    // Add `restricted`, no change to existing `agent`.
    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentModify {
            principal: pid("mia"),
            add_groups: vec![BUILTIN_RESTRICTED.into()],
            remove_groups: Vec::new(),
        },
    )
    .await;
    assert_success(&res);
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &pid("mia"));
    let profile = PrincipalProfile::load_from_path(&path).unwrap();
    assert_eq!(
        profile.groups,
        vec![BUILTIN_AGENT.to_string(), BUILTIN_RESTRICTED.to_string()]
    );

    // Re-applying the same add is a no-op (changed = false) but still
    // succeeds so scripts can be re-run safely.
    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentModify {
            principal: pid("mia"),
            add_groups: vec![BUILTIN_RESTRICTED.into()],
            remove_groups: Vec::new(),
        },
    )
    .await;
    assert_success(&res);

    // Remove `agent`. Now mia is only in `restricted`.
    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentModify {
            principal: pid("mia"),
            add_groups: Vec::new(),
            remove_groups: vec![BUILTIN_AGENT.into()],
        },
    )
    .await;
    assert_success(&res);
    let profile = PrincipalProfile::load_from_path(&path).unwrap();
    assert_eq!(profile.groups, vec![BUILTIN_RESTRICTED.to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_modify_rejects_empty_changes() {
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "nina".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentModify {
            principal: pid("nina"),
            add_groups: Vec::new(),
            remove_groups: Vec::new(),
        },
    )
    .await;
    assert_error_contains(&res, "must be non-empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_modify_rejects_unknown_principal() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentModify {
            principal: pid("ghost"),
            add_groups: vec![BUILTIN_RESTRICTED.into()],
            remove_groups: Vec::new(),
        },
    )
    .await;
    // require_principal_exists's phantom-principal guard.
    assert_error_contains(&res, "ghost");
}

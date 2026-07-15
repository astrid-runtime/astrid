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
        | AdminResponseBody::PairTokenRedeemed(_)
        | AdminResponseBody::PairDeviceListed(_)
        | AdminResponseBody::PairDeviceRevoked { .. } => {},
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
            add_capsules: Vec::new(),
            remove_capsules: Vec::new(),
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
            add_capsules: Vec::new(),
            remove_capsules: Vec::new(),
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
            add_capsules: Vec::new(),
            remove_capsules: Vec::new(),
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
            add_capsules: Vec::new(),
            remove_capsules: Vec::new(),
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
            add_capsules: Vec::new(),
            remove_capsules: Vec::new(),
        },
    )
    .await;
    // require_principal_exists's phantom-principal guard.
    assert_error_contains(&res, "ghost");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_modify_check_verifies_target_without_writing_profile() {
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "preflight-target".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    let target = pid("preflight-target");
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &target);
    let before = std::fs::read(&path).unwrap();

    let response = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentModifyCheck {
            principal: target.clone(),
        },
    )
    .await;
    assert_success(&response);
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let missing = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentModifyCheck {
            principal: pid("missing-target"),
        },
    )
    .await;
    assert_error_contains(&missing, "missing-target");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_modify_rejects_invalid_remove_entries() {
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "opal".into(),
            groups: vec![BUILTIN_AGENT.into()],
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
            principal: pid("opal"),
            add_groups: Vec::new(),
            remove_groups: vec!["bad/group".into()],
            add_capsules: Vec::new(),
            remove_capsules: Vec::new(),
        },
    )
    .await;
    assert_error_contains(&res, "group delta rejected");

    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentModify {
            principal: pid("opal"),
            add_groups: Vec::new(),
            remove_groups: Vec::new(),
            add_capsules: Vec::new(),
            remove_capsules: vec!["BadCapsule".into()],
        },
    )
    .await;
    assert_error_contains(&res, "capsule delta rejected");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_modify_adds_and_removes_capsules_idempotently() {
    // #992: agent.modify partial-updates the capsule grant set, mirroring
    // the group mechanism exactly — idempotent add/remove, persisted to
    // the principal's profile (the set the dispatcher gates the
    // user-invocable tool surface against).
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "ivy".into(),
            groups: vec![BUILTIN_AGENT.into()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &pid("ivy"));

    // Fresh agents start with no capsule grants.
    let profile = PrincipalProfile::load_from_path(&path).unwrap();
    assert!(
        profile.capsules.is_empty(),
        "new agents inherit no capsule grants"
    );

    // Grant `identity` and `registry`.
    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentModify {
            principal: pid("ivy"),
            add_groups: Vec::new(),
            remove_groups: Vec::new(),
            add_capsules: vec!["identity".into(), "registry".into()],
            remove_capsules: Vec::new(),
        },
    )
    .await;
    assert_success(&res);
    let profile = PrincipalProfile::load_from_path(&path).unwrap();
    assert_eq!(
        profile.capsules,
        vec!["identity".to_string(), "registry".to_string()]
    );

    // Re-granting `identity` is a no-op; revoking `registry` leaves only
    // `identity`. A (add, remove) in one call applies remove-then-add.
    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentModify {
            principal: pid("ivy"),
            add_groups: Vec::new(),
            remove_groups: Vec::new(),
            add_capsules: vec!["identity".into()],
            remove_capsules: vec!["registry".into()],
        },
    )
    .await;
    assert_success(&res);
    let profile = PrincipalProfile::load_from_path(&path).unwrap();
    assert_eq!(profile.capsules, vec!["identity".to_string()]);

    // Group membership is untouched by capsule-only modifies.
    assert_eq!(profile.groups, vec![BUILTIN_AGENT.to_string()]);
}

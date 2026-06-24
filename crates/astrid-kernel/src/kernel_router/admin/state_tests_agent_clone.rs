//! `admin.agent.create --clone <source>` tests.
//!
//! Carved out of `state_tests.rs` to stay under the per-file CI line cap.
//! The split is purely mechanical — the shared fixture and assertion helpers
//! are re-defined locally so each test file is self-contained.
//!
//! `clone_from` is a full replica of a source principal: its capability +
//! resource profile (groups, grants, revokes, network, process, quotas) AND
//! its state (the same env/KV/secret copy `inherit_from` performs). It does
//! NOT copy the source's `auth` (each principal keeps its own identity) or
//! `enabled` flag (a fresh clone is enabled). Cloning a source that confers
//! admin (`*`) is refused without an explicit acknowledgement.

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::groups::{BUILTIN_ADMIN, BUILTIN_RESTRICTED};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};
use tempfile::TempDir;

use super::handlers;
use crate::Kernel;

/// Build a kernel and seed `default` into the built-in `admin` group, mirroring
/// production's `seed_default_principal_admin_profile`. The admin-source clone
/// tests rely on `default` resolving to the universal `*`.
async fn fixture() -> (TempDir, Arc<Kernel>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    let admin = PrincipalProfile {
        groups: vec![astrid_core::GroupName::new(BUILTIN_ADMIN).unwrap()],
        ..PrincipalProfile::default()
    };
    admin
        .save_to_path(&PrincipalProfile::path_for(
            &kernel.astrid_home,
            &PrincipalId::default(),
        ))
        .expect("seed default admin profile");
    kernel.profile_cache.invalidate(&PrincipalId::default());
    (dir, kernel)
}

fn pid(name: &str) -> PrincipalId {
    PrincipalId::new(name).unwrap()
}

fn assert_success(res: &AdminResponseBody) {
    if let AdminResponseBody::Error(msg) = res {
        panic!("expected success, got Error: {msg}");
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

/// `clone_from` copies the source's capability + resource profile (groups,
/// grants, revokes, quotas) into the new principal, but NOT its `auth` or
/// `enabled` state — a fresh clone is enabled and keeps its own identity.
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_clone_copies_capability_profile() {
    let (_dir, kernel) = fixture().await;

    // A source profile with distinctive, non-default values on disk.
    let mut src = PrincipalProfile {
        groups: vec![astrid_core::GroupName::new(BUILTIN_RESTRICTED).unwrap()],
        grants: vec![astrid_core::CapabilityPattern::new("self:capsule:list").unwrap()],
        revokes: vec![astrid_core::CapabilityPattern::new("self:quota:set").unwrap()],
        enabled: false, // must NOT carry to the clone
        ..PrincipalProfile::default()
    };
    src.quotas.max_background_processes = 7;
    src.save_to_path(&PrincipalProfile::path_for(
        &kernel.astrid_home,
        &pid("src"),
    ))
    .unwrap();
    kernel.profile_cache.invalidate(&pid("src"));

    let res = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "twin".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: Some(pid("src")),
            allow_admin_clone: false,
        },
    )
    .await;
    assert_success(&res);

    let twin = PrincipalProfile::load_from_path(&PrincipalProfile::path_for(
        &kernel.astrid_home,
        &pid("twin"),
    ))
    .unwrap();
    assert_eq!(twin.groups, vec![BUILTIN_RESTRICTED.to_string()]);
    assert_eq!(twin.grants, vec!["self:capsule:list".to_string()]);
    assert_eq!(twin.revokes, vec!["self:quota:set".to_string()]);
    assert_eq!(twin.quotas.max_background_processes, 7);
    // A fresh clone is enabled even though the source was disabled.
    assert!(twin.enabled, "clone must be enabled regardless of source");
}

/// Cloning a source that confers admin (`default`, seeded into the `admin`
/// group → `*`) is refused without the explicit acknowledgement — it would
/// silently mint a second admin.
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_clone_rejects_admin_source_without_ack() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "shadow".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: Some(PrincipalId::default()),
            allow_admin_clone: false,
        },
    )
    .await;
    assert_error_contains(&res, "confers admin");
    assert!(
        !PrincipalProfile::path_for(&kernel.astrid_home, &pid("shadow")).exists(),
        "rejected admin clone left a profile on disk"
    );
}

/// With the explicit acknowledgement, cloning an admin source succeeds and
/// the clone holds the admin group.
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_clone_admin_source_with_ack_succeeds() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "shadow".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: Some(PrincipalId::default()),
            allow_admin_clone: true,
        },
    )
    .await;
    assert_success(&res);
    let shadow = PrincipalProfile::load_from_path(&PrincipalProfile::path_for(
        &kernel.astrid_home,
        &pid("shadow"),
    ))
    .unwrap();
    assert_eq!(shadow.groups, vec![BUILTIN_ADMIN.to_string()]);
}

/// A clone source that does not exist fails loudly (no phantom agent).
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_clone_rejects_nonexistent_source() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "alice".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: Some(pid("ghost")),
            allow_admin_clone: false,
        },
    )
    .await;
    assert_error_contains(&res, "clone_from source rejected");
    assert!(!PrincipalProfile::path_for(&kernel.astrid_home, &pid("alice")).exists());
}

/// Self-clone is meaningless and rejected.
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_clone_rejects_self() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "alice".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: Some(pid("alice")),
            allow_admin_clone: false,
        },
    )
    .await;
    assert_error_contains(&res, "same as the new principal");
}

/// `clone_from` is mutually exclusive with the profile-shaping inputs; the
/// kernel rejects a request that sets both (defense in depth behind the CLI's
/// clap `conflicts_with`). The check fires before source validation, so a
/// bogus combination trips even with a non-existent source.
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_clone_rejects_combined_with_groups() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "alice".into(),
            groups: vec![BUILTIN_RESTRICTED.to_string()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: Some(pid("src")),
            allow_admin_clone: false,
        },
    )
    .await;
    assert_error_contains(&res, "mutually exclusive");
}

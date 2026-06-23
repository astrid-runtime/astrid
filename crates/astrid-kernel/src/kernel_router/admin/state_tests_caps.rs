//! `admin.caps.grant` / `caps.revoke` + concurrency tests.
//!
//! Carved out of `state_tests.rs` because that file hit the
//! per-file CI line cap once `handlers::dispatch` started taking
//! the verified caller principal as an explicit argument (one
//! extra line per call site adds up over ~50 call sites). The
//! split is purely mechanical — the shared fixture and assertion
//! helpers are re-defined locally so each test file is
//! self-contained.

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
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

// ── caps.grant / revoke ──────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn caps_grant_appends_and_invalidates_cache() {
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "grace".into(),
            groups: vec!["restricted".into()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;

    // Pre-check: restricted principal can't do capsule:install.
    use astrid_capabilities::CapabilityCheck;
    {
        let profile = kernel.profile_cache.resolve(&pid("grace")).unwrap();
        let groups = kernel.groups.load_full();
        let check = CapabilityCheck::new(profile.as_ref(), groups.as_ref(), pid("grace"));
        assert!(check.require("capsule:install").is_err());
    }

    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::CapsGrant {
            principal: pid("grace"),
            capabilities: vec!["capsule:install".into()],
            unsafe_admin: false,
        },
    )
    .await;

    // Post: cache invalidated, fresh profile has the grant.
    let profile = kernel.profile_cache.resolve(&pid("grace")).unwrap();
    let groups = kernel.groups.load_full();
    let check = CapabilityCheck::new(profile.as_ref(), groups.as_ref(), pid("grace"));
    check.require("capsule:install").unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn caps_grant_does_not_clear_matching_revoke() {
    // Adversarial: pre-existing `self:*` revoke + caps.grant of a
    // matching cap → authz check still denies (revoke > grant).
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "henry".into(),
            groups: vec!["admin".into()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    // Install a revoke first.
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::CapsRevoke {
            principal: pid("henry"),
            capabilities: vec!["self:*".into()],
        },
    )
    .await;
    // Now grant a cap covered by the revoke pattern.
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::CapsGrant {
            principal: pid("henry"),
            capabilities: vec!["self:capsule:install".into()],
            unsafe_admin: false,
        },
    )
    .await;

    use astrid_capabilities::{CapabilityCheck, PermissionError};
    let profile = kernel.profile_cache.resolve(&pid("henry")).unwrap();
    let groups = kernel.groups.load_full();
    let check = CapabilityCheck::new(profile.as_ref(), groups.as_ref(), pid("henry"));
    let err = check.require("self:capsule:install").unwrap_err();
    assert!(
        matches!(err, PermissionError::RevokedCapability { .. }),
        "grant must not clear revoke: {err:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn caps_revoke_of_unheld_capability_appends_preemptive() {
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "ivy".into(),
            groups: vec!["restricted".into()],
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
        AdminRequestKind::CapsRevoke {
            principal: pid("ivy"),
            capabilities: vec!["capsule:install".into()],
        },
    )
    .await;
    assert_success(&res);

    // Revoke is persisted even though the principal didn't hold the cap.
    let profile = kernel.profile_cache.resolve(&pid("ivy")).unwrap();
    assert!(profile.revokes.iter().any(|r| r == "capsule:install"));
}

#[tokio::test(flavor = "multi_thread")]
async fn caps_grant_is_idempotent_no_disk_growth_on_repeat() {
    // Re-applying the same grant must not duplicate entries in
    // profile.toml — operator scripts that re-run their setup should
    // not see grants/revokes vectors grow unboundedly.
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "indy".into(),
            groups: vec!["restricted".into()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    for _ in 0..5 {
        handlers::dispatch(
            &kernel,
            &astrid_core::PrincipalId::default(),
            AdminRequestKind::CapsGrant {
                principal: pid("indy"),
                capabilities: vec!["capsule:install".into(), "capsule:remove".into()],
                unsafe_admin: false,
            },
        )
        .await;
    }
    let profile = kernel.profile_cache.resolve(&pid("indy")).unwrap();
    let install_count = profile
        .grants
        .iter()
        .filter(|c| *c == "capsule:install")
        .count();
    let remove_count = profile
        .grants
        .iter()
        .filter(|c| *c == "capsule:remove")
        .count();
    assert_eq!(install_count, 1, "duplicate grant: {:?}", profile.grants);
    assert_eq!(remove_count, 1, "duplicate grant: {:?}", profile.grants);
}

#[tokio::test(flavor = "multi_thread")]
async fn caps_revoke_is_idempotent_no_disk_growth_on_repeat() {
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "isaac".into(),
            groups: vec!["admin".into()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    for _ in 0..3 {
        handlers::dispatch(
            &kernel,
            &astrid_core::PrincipalId::default(),
            AdminRequestKind::CapsRevoke {
                principal: pid("isaac"),
                capabilities: vec!["self:*".into()],
            },
        )
        .await;
    }
    let profile = kernel.profile_cache.resolve(&pid("isaac")).unwrap();
    let count = profile.revokes.iter().filter(|c| *c == "self:*").count();
    assert_eq!(count, 1, "duplicate revoke: {:?}", profile.revokes);
}

#[tokio::test(flavor = "multi_thread")]
async fn caps_grant_rejects_invalid_capability_grammar() {
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "julia".into(),
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
        AdminRequestKind::CapsGrant {
            principal: pid("julia"),
            capabilities: vec!["system:shut down".into()], // space → invalid
            unsafe_admin: false,
        },
    )
    .await;
    assert_error_contains(&res, "rejected");
}

#[tokio::test(flavor = "multi_thread")]
async fn caps_grant_universal_requires_unsafe_admin_acknowledgement() {
    // F-E: `caps grant <agent> "*"` must be acknowledged via
    // `unsafe_admin = true`. Mirrors the group-level rail
    // (`group create --caps "*"`) so an individual grant can't
    // silently promote a principal to universal admin.
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "luke".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;

    // 1. Without `unsafe_admin` — rejected with a clear error.
    let rejected = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::CapsGrant {
            principal: pid("luke"),
            capabilities: vec!["*".into()],
            unsafe_admin: false,
        },
    )
    .await;
    assert_error_contains(&rejected, "universal admin");
    assert_error_contains(&rejected, "unsafe_admin");

    // Profile must not have been mutated by the rejected request.
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &pid("luke"));
    let profile = PrincipalProfile::load_from_path(&path).unwrap();
    assert!(profile.grants.is_empty(), "rejected grant must not persist");

    // 2. Multi-segment wildcards stay unaffected — only the literal
    //    bare `*` is gated.
    let scoped = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::CapsGrant {
            principal: pid("luke"),
            capabilities: vec!["network:egress:*".into()],
            unsafe_admin: false,
        },
    )
    .await;
    assert_success(&scoped);

    // 3. With `unsafe_admin = true` — accepted.
    let accepted = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::CapsGrant {
            principal: pid("luke"),
            capabilities: vec!["*".into()],
            unsafe_admin: true,
        },
    )
    .await;
    assert_success(&accepted);
    let profile = PrincipalProfile::load_from_path(&path).unwrap();
    assert!(profile.grants.contains(&"*".to_string()));
    assert!(profile.grants.contains(&"network:egress:*".to_string()));
}

// ── Concurrency: write lock serializes mutations ────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_caps_grants_serialized_by_admin_write_lock() {
    // Two concurrent grants on the same principal must both land.
    // Without the write lock they could interleave load/save and drop
    // one of the grants.
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "kate".into(),
            groups: vec!["restricted".into()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;

    let k1 = Arc::clone(&kernel);
    let k2 = Arc::clone(&kernel);
    let t1 = tokio::spawn(async move {
        handlers::dispatch(
            &k1,
            &astrid_core::PrincipalId::default(),
            AdminRequestKind::CapsGrant {
                principal: pid("kate"),
                capabilities: vec!["capsule:install".into()],
                unsafe_admin: false,
            },
        )
        .await
    });
    let t2 = tokio::spawn(async move {
        handlers::dispatch(
            &k2,
            &astrid_core::PrincipalId::default(),
            AdminRequestKind::CapsGrant {
                principal: pid("kate"),
                capabilities: vec!["capsule:remove".into()],
                unsafe_admin: false,
            },
        )
        .await
    });
    let (r1, r2) = (t1.await.unwrap(), t2.await.unwrap());
    assert_success(&r1);
    assert_success(&r2);

    let profile = kernel.profile_cache.resolve(&pid("kate")).unwrap();
    assert!(profile.grants.iter().any(|c| c == "capsule:install"));
    assert!(profile.grants.iter().any(|c| c == "capsule:remove"));
}

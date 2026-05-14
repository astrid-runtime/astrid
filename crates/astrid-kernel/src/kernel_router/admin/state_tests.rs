//! Stateful admin-handler tests (issue #672).
//!
//! Each test builds a [`test_kernel_with_home`](crate::test_kernel_with_home)
//! rooted in a private tempdir and invokes [`super::handlers::dispatch`]
//! directly, bypassing the IPC dispatch but keeping the write-lock / cache /
//! ArcSwap semantics identical to the production path.
//!
//! These tests cover the Layer 6 behavioural invariants: post-conditions
//! on disk, cache invalidation, ArcSwap hot-reload, adversarial
//! sequences (grant-after-revoke, quota=0 rejection, built-in protection,
//! concurrent writes).

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::groups::{BUILTIN_ADMIN, BUILTIN_AGENT, BUILTIN_RESTRICTED, GroupConfig};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{PrincipalProfile, Quotas};
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody, AgentSummary, GroupSummary};
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
        | AdminResponseBody::AgentList(_)
        | AdminResponseBody::GroupList(_) => {},
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

// ── agent.create ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn agent_create_writes_profile_and_links_identity() {
    let (_dir, kernel) = fixture().await;

    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentCreate {
            name: "alice".into(),
            groups: Vec::new(),
            grants: Vec::new(),
        },
    )
    .await;
    assert_success(&res);

    // Profile written to disk with default group = "agent".
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &pid("alice"));
    let profile = PrincipalProfile::load_from_path(&path).unwrap();
    assert_eq!(profile.groups, vec![BUILTIN_AGENT.to_string()]);
    assert!(profile.enabled);

    // Identity link created.
    let user = kernel.identity_store.resolve("cli", "alice").await.unwrap();
    assert!(user.is_some());

    // Per-principal home tree provisioned. Capsule WASM stays shared
    // (loaded once from default's home), but every per-invocation
    // namespace — KV, log, audit, tmp, tokens, env — needs a place to
    // land before the first interceptor scoped to this principal fires.
    let ph = kernel.astrid_home.principal_home(&pid("alice"));
    assert!(ph.kv_dir().is_dir(), "kv_dir not provisioned");
    assert!(ph.log_dir().is_dir(), "log_dir not provisioned");
    assert!(ph.audit_dir().is_dir(), "audit_dir not provisioned");
    assert!(ph.tmp_dir().is_dir(), "tmp_dir not provisioned");
    assert!(ph.tokens_dir().is_dir(), "tokens_dir not provisioned");
    assert!(ph.env_dir().is_dir(), "env_dir not provisioned");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_create_rejects_collision_with_existing_profile() {
    let (_dir, kernel) = fixture().await;

    handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentCreate {
            name: "alice".into(),
            groups: Vec::new(),
            grants: Vec::new(),
        },
    )
    .await;

    // Second create with the same name → rejected.
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentCreate {
            name: "alice".into(),
            groups: Vec::new(),
            grants: Vec::new(),
        },
    )
    .await;
    assert_error_contains(&res, "already exists");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_create_rejects_invalid_name() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentCreate {
            name: "bad/name".into(),
            groups: Vec::new(),
            grants: Vec::new(),
        },
    )
    .await;
    assert_error_contains(&res, "invalid principal name");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_create_rejects_default_bootstrap_name() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentCreate {
            name: "default".into(),
            groups: Vec::new(),
            grants: Vec::new(),
        },
    )
    .await;
    assert_error_contains(&res, "reserved");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_create_rolls_back_when_home_provisioning_fails() {
    // Confidentiality boundary: if the per-principal home tree cannot be
    // created, downstream per-invocation lookups fall back to the
    // default principal's namespace — a cross-tenant leak. The handler
    // must roll back the identity + profile rather than leave the agent
    // in a half-provisioned state.
    let (_dir, kernel) = fixture().await;

    // Force `principal_home(&blocked).ensure()` to fail by placing a
    // regular file where the principal home directory would live. The
    // `create_dir_all` call inside `ensure()` returns NotADirectory.
    std::fs::create_dir_all(kernel.astrid_home.home_dir()).expect("home_dir");
    let blocked_path = kernel.astrid_home.home_dir().join("blocked");
    std::fs::write(&blocked_path, b"sentinel").expect("write blocker file");

    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentCreate {
            name: "blocked".into(),
            groups: Vec::new(),
            grants: Vec::new(),
        },
    )
    .await;
    assert_error_contains(&res, "home tree provisioning failed");

    // Rollback assertions: identity link gone, user record gone,
    // profile file gone. The blocker file we placed stays.
    let resolved = kernel
        .identity_store
        .resolve("cli", "blocked")
        .await
        .unwrap();
    assert!(
        resolved.is_none(),
        "identity link must be unlinked on rollback"
    );

    let profile_path = PrincipalProfile::path_for(&kernel.astrid_home, &pid("blocked"));
    assert!(
        !profile_path.exists(),
        "profile file must be removed on rollback"
    );

    assert!(
        blocked_path.is_file(),
        "rollback must not touch the unrelated sentinel"
    );
}

// ── agent.delete ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn agent_delete_of_default_always_rejected() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentDelete {
            principal: PrincipalId::default(),
        },
    )
    .await;
    assert_error_contains(&res, "default");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_delete_removes_identity_profile_and_invalidates_cache() {
    let (_dir, kernel) = fixture().await;

    // Create, then resolve via cache so there's an entry to invalidate.
    handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentCreate {
            name: "bob".into(),
            groups: Vec::new(),
            grants: Vec::new(),
        },
    )
    .await;
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &pid("bob"));
    assert!(path.exists(), "profile.toml should be present pre-delete");
    let _warm = kernel.profile_cache.resolve(&pid("bob")).unwrap();

    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentDelete {
            principal: pid("bob"),
        },
    )
    .await;
    assert_success(&res);

    // Identity link gone.
    let user = kernel.identity_store.resolve("cli", "bob").await.unwrap();
    assert!(user.is_none());

    // Profile file removed — without this, future authz checks for
    // `bob` would re-load the old policy and the unlink would only
    // close the login route, not the policy.
    assert!(!path.exists(), "profile.toml must be removed post-delete");

    // Cache cleared: re-resolving returns Default (enabled=true, no
    // groups/grants/revokes), and the Layer 5 enforcement preamble
    // grants no caps for that shape.
    let after = kernel.profile_cache.resolve(&pid("bob")).unwrap();
    assert!(after.groups.is_empty());
    assert!(after.grants.is_empty());
    assert!(after.revokes.is_empty());
}

// ── Phantom-principal rejection (Gemini follow-up + R-thirteen) ──

#[tokio::test(flavor = "multi_thread")]
async fn caps_grant_on_nonexistent_principal_is_rejected() {
    // The headline 3am bug: an admin typo'd
    // `caps.grant alic capsule:install` (missing 'e') would silently
    // create a phantom `alic` profile with the grant. Every mutating
    // handler now requires the profile to already exist.
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::CapsGrant {
            principal: pid("typo_principal"),
            capabilities: vec!["capsule:install".into()],
        },
    )
    .await;
    assert_error_contains(&res, "does not exist");

    // No phantom profile.toml left on disk.
    let phantom_path = PrincipalProfile::path_for(&kernel.astrid_home, &pid("typo_principal"));
    assert!(!phantom_path.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn caps_revoke_on_nonexistent_principal_is_rejected() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::CapsRevoke {
            principal: pid("typo_principal"),
            capabilities: vec!["capsule:install".into()],
        },
    )
    .await;
    assert_error_contains(&res, "does not exist");
}

#[tokio::test(flavor = "multi_thread")]
async fn quota_set_on_nonexistent_principal_is_rejected() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::QuotaSet {
            principal: pid("typo_principal"),
            quotas: Quotas::default(),
        },
    )
    .await;
    assert_error_contains(&res, "does not exist");
}

#[tokio::test(flavor = "multi_thread")]
async fn quota_get_on_nonexistent_principal_is_rejected() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::QuotaGet {
            principal: pid("typo_principal"),
        },
    )
    .await;
    assert_error_contains(&res, "does not exist");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_enable_on_nonexistent_principal_is_rejected() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentEnable {
            principal: pid("typo_principal"),
        },
    )
    .await;
    assert_error_contains(&res, "does not exist");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_disable_on_nonexistent_principal_is_rejected() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentDisable {
            principal: pid("typo_principal"),
        },
    )
    .await;
    assert_error_contains(&res, "does not exist");
}

// ── default-principal lockout protection ─────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn agent_disable_default_is_rejected() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentDisable {
            principal: PrincipalId::default(),
        },
    )
    .await;
    assert_error_contains(&res, "default");
}

#[tokio::test(flavor = "multi_thread")]
async fn caps_revoke_on_default_is_rejected() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::CapsRevoke {
            principal: PrincipalId::default(),
            capabilities: vec!["self:*".into()],
        },
    )
    .await;
    assert_error_contains(&res, "default");
}

// ── agent.enable / disable ──────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn agent_enable_toggle_and_cache_invalidation() {
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentCreate {
            name: "carol".into(),
            groups: Vec::new(),
            grants: Vec::new(),
        },
    )
    .await;

    // Warm cache with enabled=true.
    let warm = kernel.profile_cache.resolve(&pid("carol")).unwrap();
    assert!(warm.enabled);

    // Disable → cache should be invalidated so next resolve sees enabled=false.
    handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentDisable {
            principal: pid("carol"),
        },
    )
    .await;
    let after_disable = kernel.profile_cache.resolve(&pid("carol")).unwrap();
    assert!(!after_disable.enabled);

    // Re-enable roundtrips.
    handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentEnable {
            principal: pid("carol"),
        },
    )
    .await;
    let after_enable = kernel.profile_cache.resolve(&pid("carol")).unwrap();
    assert!(after_enable.enabled);
}

// ── agent.list ───────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn agent_list_returns_every_home_dir_principal() {
    let (_dir, kernel) = fixture().await;
    for name in ["alice", "bob"] {
        handlers::dispatch(
            &kernel,
            AdminRequestKind::AgentCreate {
                name: name.into(),
                groups: Vec::new(),
                grants: Vec::new(),
            },
        )
        .await;
    }

    let res = handlers::dispatch(&kernel, AdminRequestKind::AgentList).await;
    let AdminResponseBody::AgentList(list) = res else {
        panic!("expected AgentList");
    };
    let names: Vec<&str> = list
        .iter()
        .map(|a: &AgentSummary| a.principal.as_str())
        .collect();
    assert!(names.contains(&"alice"), "got: {names:?}");
    assert!(names.contains(&"bob"), "got: {names:?}");
}

// ── quota.set / quota.get ────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn quota_set_rejects_zero_memory() {
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentCreate {
            name: "dave".into(),
            groups: Vec::new(),
            grants: Vec::new(),
        },
    )
    .await;

    let mut q = Quotas::default();
    q.max_memory_bytes = 0;
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::QuotaSet {
            principal: pid("dave"),
            quotas: q,
        },
    )
    .await;
    assert_error_contains(&res, "quotas rejected");
}

#[tokio::test(flavor = "multi_thread")]
async fn quota_set_updates_profile_and_invalidates_cache() {
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentCreate {
            name: "eve".into(),
            groups: Vec::new(),
            grants: Vec::new(),
        },
    )
    .await;
    let _warm = kernel.profile_cache.resolve(&pid("eve")).unwrap();

    let mut q = Quotas::default();
    q.max_memory_bytes = 8 * 1024 * 1024;
    handlers::dispatch(
        &kernel,
        AdminRequestKind::QuotaSet {
            principal: pid("eve"),
            quotas: q,
        },
    )
    .await;
    let fresh = kernel.profile_cache.resolve(&pid("eve")).unwrap();
    assert_eq!(fresh.quotas.max_memory_bytes, 8 * 1024 * 1024);

    // quota.get returns the current value.
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::QuotaGet {
            principal: pid("eve"),
        },
    )
    .await;
    let AdminResponseBody::Quotas(got) = res else {
        panic!("expected Quotas response");
    };
    assert_eq!(got.max_memory_bytes, 8 * 1024 * 1024);
}

// ── group.create / delete / modify / list ───────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn group_create_swaps_arcswap_and_writes_groups_toml() {
    let (_dir, kernel) = fixture().await;

    // Pre: `ops` unknown.
    assert!(kernel.groups.load_full().get("ops").is_none());

    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::GroupCreate {
            name: "ops".into(),
            capabilities: vec!["capsule:install".into()],
            description: Some("deployment operators".into()),
            unsafe_admin: false,
        },
    )
    .await;
    assert_success(&res);

    // ArcSwap observes the new group immediately.
    let cfg = kernel.groups.load_full();
    let ops = cfg.get("ops").expect("ops present post-swap");
    assert_eq!(ops.capabilities, vec!["capsule:install".to_string()]);

    // Disk persists the same state (and excludes built-ins).
    let on_disk = GroupConfig::load_from_path(&GroupConfig::path_for(&kernel.astrid_home)).unwrap();
    assert!(on_disk.get("ops").is_some());
    let raw = std::fs::read_to_string(GroupConfig::path_for(&kernel.astrid_home)).unwrap();
    assert!(!raw.contains("[groups.admin]"));
    assert!(!raw.contains("[groups.agent]"));
    assert!(!raw.contains("[groups.restricted]"));
}

#[tokio::test(flavor = "multi_thread")]
async fn group_delete_rejects_every_builtin() {
    let (_dir, kernel) = fixture().await;
    for name in [BUILTIN_ADMIN, BUILTIN_AGENT, BUILTIN_RESTRICTED] {
        let res =
            handlers::dispatch(&kernel, AdminRequestKind::GroupDelete { name: name.into() }).await;
        assert_error_contains(&res, "built-in");
    }
    // Built-ins still present.
    let cfg = kernel.groups.load_full();
    assert!(cfg.get(BUILTIN_ADMIN).is_some());
    assert!(cfg.get(BUILTIN_AGENT).is_some());
    assert!(cfg.get(BUILTIN_RESTRICTED).is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn group_modify_rejects_every_builtin() {
    let (_dir, kernel) = fixture().await;
    for name in [BUILTIN_ADMIN, BUILTIN_AGENT, BUILTIN_RESTRICTED] {
        let res = handlers::dispatch(
            &kernel,
            AdminRequestKind::GroupModify {
                name: name.into(),
                capabilities: Some(vec!["audit:read".into()]),
                description: None,
                unsafe_admin: None,
            },
        )
        .await;
        assert_error_contains(&res, "built-in");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn group_list_returns_every_group_marked_correctly() {
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        AdminRequestKind::GroupCreate {
            name: "ops".into(),
            capabilities: vec!["capsule:install".into()],
            description: None,
            unsafe_admin: false,
        },
    )
    .await;

    let res = handlers::dispatch(&kernel, AdminRequestKind::GroupList).await;
    let AdminResponseBody::GroupList(list) = res else {
        panic!("expected GroupList");
    };
    let by_name = |name: &str| list.iter().find(|g: &&GroupSummary| g.name == name);

    let admin = by_name("admin").expect("admin present");
    assert!(admin.builtin);
    let ops = by_name("ops").expect("ops present");
    assert!(!ops.builtin);
}

#[tokio::test(flavor = "multi_thread")]
async fn group_delete_reference_from_profile_does_not_elevate_privileges() {
    // Adversarial: a principal's profile references a custom group; we
    // delete that group. The principal must NOT be silently elevated
    // via any other group. Layer 5 fails closed on unknown group refs.
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        AdminRequestKind::GroupCreate {
            name: "ops".into(),
            capabilities: vec!["capsule:install".into()],
            description: None,
            unsafe_admin: false,
        },
    )
    .await;

    // Create an agent with `ops` group membership.
    handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentCreate {
            name: "frank".into(),
            groups: vec!["ops".into()],
            grants: Vec::new(),
        },
    )
    .await;

    // Delete `ops`. Frank's profile now has a dangling group ref.
    handlers::dispatch(
        &kernel,
        AdminRequestKind::GroupDelete { name: "ops".into() },
    )
    .await;

    // Re-resolve Frank's profile via cache. `ops` in groups vec, but
    // GroupConfig no longer contains it — fail-closed: `capsule:install`
    // must NOT be authorized.
    use astrid_capabilities::CapabilityCheck;
    let profile = kernel.profile_cache.resolve(&pid("frank")).unwrap();
    let groups = kernel.groups.load_full();
    let check = CapabilityCheck::new(profile.as_ref(), groups.as_ref(), pid("frank"));
    assert!(
        check.require("capsule:install").is_err(),
        "dangling group reference must not silently elevate"
    );
}

// ── caps.grant / revoke ──────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn caps_grant_appends_and_invalidates_cache() {
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        AdminRequestKind::AgentCreate {
            name: "grace".into(),
            groups: vec!["restricted".into()],
            grants: Vec::new(),
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
        AdminRequestKind::CapsGrant {
            principal: pid("grace"),
            capabilities: vec!["capsule:install".into()],
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
        AdminRequestKind::AgentCreate {
            name: "henry".into(),
            groups: vec!["admin".into()],
            grants: Vec::new(),
        },
    )
    .await;
    // Install a revoke first.
    handlers::dispatch(
        &kernel,
        AdminRequestKind::CapsRevoke {
            principal: pid("henry"),
            capabilities: vec!["self:*".into()],
        },
    )
    .await;
    // Now grant a cap covered by the revoke pattern.
    handlers::dispatch(
        &kernel,
        AdminRequestKind::CapsGrant {
            principal: pid("henry"),
            capabilities: vec!["self:capsule:install".into()],
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
        AdminRequestKind::AgentCreate {
            name: "ivy".into(),
            groups: vec!["restricted".into()],
            grants: Vec::new(),
        },
    )
    .await;
    let res = handlers::dispatch(
        &kernel,
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
        AdminRequestKind::AgentCreate {
            name: "indy".into(),
            groups: vec!["restricted".into()],
            grants: Vec::new(),
        },
    )
    .await;
    for _ in 0..5 {
        handlers::dispatch(
            &kernel,
            AdminRequestKind::CapsGrant {
                principal: pid("indy"),
                capabilities: vec!["capsule:install".into(), "capsule:remove".into()],
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
        AdminRequestKind::AgentCreate {
            name: "isaac".into(),
            groups: vec!["admin".into()],
            grants: Vec::new(),
        },
    )
    .await;
    for _ in 0..3 {
        handlers::dispatch(
            &kernel,
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
        AdminRequestKind::AgentCreate {
            name: "julia".into(),
            groups: Vec::new(),
            grants: Vec::new(),
        },
    )
    .await;
    let res = handlers::dispatch(
        &kernel,
        AdminRequestKind::CapsGrant {
            principal: pid("julia"),
            capabilities: vec!["system:shut down".into()], // space → invalid
        },
    )
    .await;
    assert_error_contains(&res, "rejected");
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
        AdminRequestKind::AgentCreate {
            name: "kate".into(),
            groups: vec!["restricted".into()],
            grants: Vec::new(),
        },
    )
    .await;

    let k1 = Arc::clone(&kernel);
    let k2 = Arc::clone(&kernel);
    let t1 = tokio::spawn(async move {
        handlers::dispatch(
            &k1,
            AdminRequestKind::CapsGrant {
                principal: pid("kate"),
                capabilities: vec!["capsule:install".into()],
            },
        )
        .await
    });
    let t2 = tokio::spawn(async move {
        handlers::dispatch(
            &k2,
            AdminRequestKind::CapsGrant {
                principal: pid("kate"),
                capabilities: vec!["capsule:remove".into()],
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

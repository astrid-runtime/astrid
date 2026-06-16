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
    // Mirror production: `Kernel::new` admin-seeds the `default`
    // principal (lib.rs `seed_default_principal_admin_profile`), so
    // dispatch through `default` carries admin authority. `agent_list`'s
    // authority-scope filter depends on this — without it `default`
    // resolves to an empty profile and is treated as a self-scoped
    // caller, which would (correctly) hide the roster from it.
    let mut admin = PrincipalProfile::default();
    admin.groups = vec![BUILTIN_ADMIN.to_string()];
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

// ── agent.create ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn agent_create_writes_profile_and_links_identity() {
    let (_dir, kernel) = fixture().await;

    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "alice".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
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
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "alice".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;

    // Second create with the same name → rejected.
    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "alice".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
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
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "bad/name".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert_error_contains(&res, "invalid principal name");
}

/// `default` (the single-tenant bootstrap anchor) and `anonymous` (the
/// no-capability identity stamped on unauthenticated connections, #45/#852) are
/// reserved: `agent create` must reject both so neither can be created — and
/// thus never granted capabilities.
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_rejects_reserved_names() {
    let (_dir, kernel) = fixture().await;
    for name in ["default", "anonymous"] {
        let res = handlers::dispatch(
            &kernel,
            &astrid_core::PrincipalId::default(),
            AdminRequestKind::AgentCreate {
                name: name.into(),
                groups: Vec::new(),
                grants: Vec::new(),
                inherit_from: None,
                clone_from: None,
                allow_admin_clone: false,
            },
        )
        .await;
        assert_error_contains(&res, "reserved");
    }
}

/// Security-critical direction: a default `inherit_from: None` create
/// must NOT copy the `default` principal's env JSON into the new agent.
/// Before the opt-in flip this copy happened unconditionally, leaking
/// `default`'s config (and, for registered capsules, KV + secrets/API
/// keys) into every created agent.
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_without_inherit_copies_nothing() {
    let (_dir, kernel) = fixture().await;

    // Seed an env file under `default`'s env dir. If the old
    // unconditional inheritance were still in place, this file would be
    // copied into every new agent.
    let default_env = kernel
        .astrid_home
        .principal_home(&PrincipalId::default())
        .env_dir();
    std::fs::create_dir_all(&default_env).expect("default env dir");
    std::fs::write(default_env.join("openai.json"), br#"{"base_url":"x"}"#)
        .expect("seed default env file");

    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "alice".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert_success(&res);

    // The new principal's env dir was provisioned (empty) but inherited
    // NOTHING from `default`. The seeded file must not be present.
    let alice_env = kernel.astrid_home.principal_home(&pid("alice")).env_dir();
    assert!(
        !alice_env.join("openai.json").exists(),
        "default's env file leaked into a non-inheriting agent"
    );
    let leaked: Vec<_> = std::fs::read_dir(&alice_env)
        .map(|rd| rd.flatten().map(|e| e.file_name()).collect())
        .unwrap_or_default();
    assert!(
        leaked.is_empty(),
        "non-inheriting agent's env dir is not empty: {leaked:?}"
    );
}

/// Opt-in direction: `inherit_from: Some(source)` performs a full copy
/// of the source's per-principal state. The env-dir copy path is the
/// one exercisable here (the empty test registry means `copy_kv_*` /
/// `copy_secret_files` find no capsule namespaces to probe — see the
/// gap note below), so we assert an env file seeded on a real source
/// lands in the new agent.
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_with_inherit_copies_from_source() {
    let (_dir, kernel) = fixture().await;

    // Create the source principal first so its profile + home tree exist.
    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "source".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert_success(&res);

    // Seed an env file under the source's env dir.
    let source_env = kernel.astrid_home.principal_home(&pid("source")).env_dir();
    std::fs::create_dir_all(&source_env).expect("source env dir");
    std::fs::write(source_env.join("openai.json"), br#"{"base_url":"src"}"#)
        .expect("seed source env file");

    // Create the inheriting agent.
    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "child".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: Some(pid("source")),
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert_success(&res);

    // The source's env file landed in the child verbatim.
    let child_env = kernel.astrid_home.principal_home(&pid("child")).env_dir();
    let copied = std::fs::read(child_env.join("openai.json"))
        .expect("source env file should have been copied into the child");
    assert_eq!(copied, br#"{"base_url":"src"}"#);
}

/// A named-but-nonexistent inheritance source must fail loudly rather
/// than silently no-op into an empty agent the operator believes was
/// provisioned from a template.
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_rejects_nonexistent_inherit_source() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "alice".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: Some(pid("ghost")),
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert_error_contains(&res, "inherit_from source rejected");

    // The create was rejected before any state was written.
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &pid("alice"));
    assert!(!path.exists(), "rejected create left a profile on disk");
}

/// Self-inherit is meaningless (the source home tree does not exist at
/// the moment the copy would run) and must be rejected.
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_rejects_self_inherit() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "alice".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: Some(pid("alice")),
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert_error_contains(&res, "same as the new principal");
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
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "blocked".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
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

// `admin.agent.modify` tests live in the sibling
// `state_tests_agent_modify.rs` module — split off so this file stays
// under the per-file CI line cap.

// ── agent.delete ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn agent_delete_of_default_always_rejected() {
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "bob".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &pid("bob"));
    assert!(path.exists(), "profile.toml should be present pre-delete");
    let _warm = kernel.profile_cache.resolve(&pid("bob")).unwrap();

    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::CapsGrant {
            principal: pid("typo_principal"),
            capabilities: vec!["capsule:install".into()],
            unsafe_admin: false,
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
        &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "carol".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;

    // Warm cache with enabled=true.
    let warm = kernel.profile_cache.resolve(&pid("carol")).unwrap();
    assert!(warm.enabled);

    // Disable → cache should be invalidated so next resolve sees enabled=false.
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
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
            &astrid_core::PrincipalId::default(),
            AdminRequestKind::AgentCreate {
                name: name.into(),
                groups: Vec::new(),
                grants: Vec::new(),
                inherit_from: None,
                clone_from: None,
                allow_admin_clone: false,
            },
        )
        .await;
    }

    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentList,
    )
    .await;
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
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "dave".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;

    let mut q = Quotas::default();
    q.max_memory_bytes = 0;
    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "eve".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    let _warm = kernel.profile_cache.resolve(&pid("eve")).unwrap();

    let mut q = Quotas::default();
    q.max_memory_bytes = 8 * 1024 * 1024;
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
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
        let res = handlers::dispatch(
            &kernel,
            &astrid_core::PrincipalId::default(),
            AdminRequestKind::GroupDelete { name: name.into() },
        )
        .await;
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
            &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::GroupCreate {
            name: "ops".into(),
            capabilities: vec!["capsule:install".into()],
            description: None,
            unsafe_admin: false,
        },
    )
    .await;

    let res = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::GroupList,
    )
    .await;
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
        &astrid_core::PrincipalId::default(),
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
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "frank".into(),
            groups: vec!["ops".into()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;

    // Delete `ops`. Frank's profile now has a dangling group ref.
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
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

// ── agent.list authority-scope filter (info-disclosure fix) ──────────

#[tokio::test(flavor = "multi_thread")]
async fn agent_list_filters_to_self_for_non_admin_caller() {
    let (_dir, kernel) = fixture().await;

    // Two ordinary agents — empty groups default to the `agent` builtin,
    // which grants `self:*` / `self:agent:list` but NOT global `agent:list`.
    for name in ["alice", "bob"] {
        let res = handlers::dispatch(
            &kernel,
            &PrincipalId::default(),
            AdminRequestKind::AgentCreate {
                name: name.into(),
                groups: Vec::new(),
                grants: Vec::new(),
                inherit_from: None,
                clone_from: None,
                allow_admin_clone: false,
            },
        )
        .await;
        assert_success(&res);
    }

    // The admin-seeded `default` principal holds `*` → sees the full roster.
    let res = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentList,
    )
    .await;
    let all = match res {
        AdminResponseBody::AgentList(v) => v,
        other => panic!("expected AgentList, got {other:?}"),
    };
    let names: Vec<&str> = all.iter().map(|s| s.principal.as_str()).collect();
    assert!(
        names.contains(&"alice") && names.contains(&"bob"),
        "admin must see the full roster, got {names:?}"
    );

    // A non-admin agent (`alice`) holds only `self:agent:list` → must see
    // ONLY its own row, never the rest of the roster.
    let res = handlers::dispatch(&kernel, &pid("alice"), AdminRequestKind::AgentList).await;
    let mine = match res {
        AdminResponseBody::AgentList(v) => v,
        other => panic!("expected AgentList, got {other:?}"),
    };
    assert_eq!(
        mine.len(),
        1,
        "self-scoped caller must see exactly one row, got {mine:?}"
    );
    assert_eq!(mine[0].principal.as_str(), "alice");
}

//! Stateful admin-handler tests (issue #672).
//!
//! Each test builds a [`test_kernel_with_home`](crate::test_kernel_with_home)
//! rooted in a private tempdir and invokes [`super::handlers::dispatch`]
//! directly, bypassing the IPC dispatch but keeping the write-lock / cache /
//! `ArcSwap` semantics identical to the production path.
//!
//! These tests cover the Layer 6 behavioural invariants: post-conditions
//! on disk, cache invalidation, `ArcSwap` hot-reload, adversarial
//! sequences (grant-after-revoke, quota=0 rejection, built-in protection,
//! concurrent writes).

use std::sync::Arc;

use astrid_capsule::capsule::{Capsule, CapsuleId, CapsuleState};
use astrid_capsule::context::CapsuleContext;
use astrid_capsule::error::CapsuleResult;
use astrid_capsule::manifest::CapsuleManifest;
use astrid_core::dirs::AstridHome;
use astrid_core::groups::{BUILTIN_ADMIN, BUILTIN_AGENT, BUILTIN_RESTRICTED, GroupConfig};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{AuthMethod, DeviceKey, DeviceScope, PrincipalProfile, Quotas};
use astrid_core::{FleetGenesis, FleetIdentity, PrincipalOwnership, UserGenesis, UserIdentity};
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody, AgentSummary, GroupSummary};
use astrid_storage::env::{get_env, principal_env_store, set_env};
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
    let admin = PrincipalProfile {
        groups: vec![BUILTIN_ADMIN.to_string()],
        ..Default::default()
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

struct InheritanceCapsule {
    id: CapsuleId,
    manifest: CapsuleManifest,
}

#[async_trait::async_trait]
impl Capsule for InheritanceCapsule {
    fn id(&self) -> &CapsuleId {
        &self.id
    }

    fn manifest(&self) -> &CapsuleManifest {
        &self.manifest
    }

    fn state(&self) -> CapsuleState {
        CapsuleState::Ready
    }

    async fn load(&mut self, _ctx: &CapsuleContext) -> CapsuleResult<()> {
        Ok(())
    }

    async fn unload(&mut self) -> CapsuleResult<()> {
        Ok(())
    }
}

async fn seed_loaded_capsule(kernel: &Arc<Kernel>, name: &str) {
    let id = CapsuleId::new(name).expect("valid inheritance capsule id");
    let mut manifest = CapsuleManifest::default();
    manifest.package.name = name.to_owned();
    manifest.package.version = "1.0.0".to_owned();
    kernel
        .capsules
        .write()
        .await
        .register(Box::new(InheritanceCapsule { id, manifest }))
        .expect("register inheritance capsule fixture");
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
        | AdminResponseBody::StorageMountLease(_)
        | AdminResponseBody::EnvList(_)
        | AdminResponseBody::AuditStats(_)
        | AdminResponseBody::AuditPruned(_)
        | AdminResponseBody::AuditHealth(_)
        | AdminResponseBody::DistroLock(_)
        | AdminResponseBody::StationLock(_)
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

async fn assert_owned_delete_rejected_after_unlink(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    user_id: uuid::Uuid,
    profile_path: &std::path::Path,
) {
    kernel
        .identity_store
        .unlink("cli", principal.as_str())
        .await
        .unwrap();
    let retried = handlers::dispatch(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;
    assert_error_contains(&retried, "assigned to fleet");
    assert!(
        profile_path.exists(),
        "retried rejection must retain profile"
    );
    assert!(
        kernel
            .identity_store
            .get_user(user_id)
            .await
            .unwrap()
            .is_some(),
        "retried rejection must retain the durable user"
    );
}

fn agent_list_for(response: AdminResponseBody) -> Vec<AgentSummary> {
    match response {
        AdminResponseBody::AgentList(list) => list,
        other => panic!("expected AgentList, got {other:?}"),
    }
}

async fn assert_agent_list_authorization_snapshot(
    kernel: &Arc<Kernel>,
    mut profile: PrincipalProfile,
    global_list_id: &str,
) {
    let authorization = crate::kernel_router::authorize_request(
        kernel,
        &PrincipalId::default(),
        Some(global_list_id),
        "self:agent:list",
    )
    .expect("authorize agent inventory");
    profile.auth.public_keys.clear();
    profile
        .save_to_path(&PrincipalProfile::path_for(
            &kernel.astrid_home,
            &PrincipalId::default(),
        ))
        .expect("revoke inventory device");
    kernel.profile_cache.invalidate(&PrincipalId::default());
    crate::kernel_router::authorize_request(
        kernel,
        &PrincipalId::default(),
        Some(global_list_id),
        "self:agent:list",
    )
    .expect_err("a later request must observe the revoked device");

    let pinned = agent_list_for(
        handlers::dispatch_authorized(kernel, &authorization, AdminRequestKind::AgentList).await,
    );
    assert!(pinned.iter().any(|entry| entry.principal == pid("alice")));
    assert!(pinned.iter().any(|entry| entry.principal == pid("bob")));
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

    // Principal state is UID-bound in the runtime store. Agent creation must
    // not recreate the released native home tree; typed env and all durable
    // content are provisioned through storage projections on first use.
    let ph = kernel.astrid_home.principal_home(&pid("alice"));
    assert!(
        !ph.root().exists(),
        "agent create must not recreate legacy home"
    );
    assert!(kernel.principal_directory.uid_for(&pid("alice")).is_ok());
    assert!(kernel.principal_store.is_some());
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

    // Seed the default principal's host-only control scope. If accidental
    // default inheritance were still enabled, this would leak into alice.
    let default_uid = kernel
        .principal_directory
        .uid_for(&PrincipalId::default())
        .unwrap();
    let default_env = principal_env_store(Arc::clone(&kernel.kv), default_uid, "openai").unwrap();
    set_env(&default_env, "BASE_URL", "x").await.unwrap();

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

    // The new principal's control scope inherited NOTHING from `default`.
    let alice_uid = kernel.principal_directory.uid_for(&pid("alice")).unwrap();
    let alice_env = principal_env_store(Arc::clone(&kernel.kv), alice_uid, "openai").unwrap();
    assert!(get_env(&alice_env, "BASE_URL").await.unwrap().is_none());
    assert!(
        !kernel
            .astrid_home
            .principal_home(&pid("alice"))
            .env_dir()
            .exists()
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
    seed_loaded_capsule(&kernel, "openai").await;

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

    // Seed the source's host-only control scope.
    let source_uid = kernel.principal_directory.uid_for(&pid("source")).unwrap();
    let source_env = principal_env_store(Arc::clone(&kernel.kv), source_uid, "openai").unwrap();
    set_env(&source_env, "BASE_URL", "src").await.unwrap();

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

    // The source's typed env landed in the child verbatim, without a native
    // env path being created.
    let child_uid = kernel.principal_directory.uid_for(&pid("child")).unwrap();
    let child_env = principal_env_store(Arc::clone(&kernel.kv), child_uid, "openai").unwrap();
    assert_eq!(
        get_env(&child_env, "BASE_URL").await.unwrap().as_deref(),
        Some("src")
    );
    assert!(
        !kernel
            .astrid_home
            .principal_home(&pid("child"))
            .env_dir()
            .exists()
    );
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
async fn agent_create_does_not_recreate_legacy_home_tree() {
    let (_dir, kernel) = fixture().await;

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
    assert_success(&res);
    assert!(
        !kernel
            .astrid_home
            .principal_home(&pid("blocked"))
            .root()
            .exists()
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

    // Cache cleared: a deleted non-default identity has no compatibility
    // profile and therefore cannot regain host authority.
    assert!(kernel.profile_cache.resolve(&pid("bob")).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_delete_retry_clears_reservation_after_identity_was_removed() {
    let (_dir, kernel) = fixture().await;
    let principal = pid("recoverable-delete");
    let created = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: principal.to_string(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert_success(&created);

    let user = kernel
        .identity_store
        .resolve("cli", principal.as_str())
        .await
        .unwrap()
        .unwrap();
    let identity = kernel
        .identity_store
        .get_principal_identity(user.id)
        .await
        .unwrap()
        .unwrap();
    let guard = kernel
        .ownership_store
        .guard_principal_deletion_for_alias(identity.uid, principal.clone())
        .await
        .unwrap();
    assert!(kernel.identity_store.delete_user(user.id).await.unwrap());
    drop(guard);

    let retried = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;
    assert_success(&retried);
    assert!(matches!(
        kernel
            .ownership_store
            .guard_principal_deletion(identity.uid)
            .await,
        Err(astrid_storage::OwnershipError::PrincipalNotFound(uid)) if uid == identity.uid
    ));
    assert!(!PrincipalProfile::path_for(&kernel.astrid_home, &principal).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_delete_rejects_a_fleet_owned_principal_without_partial_deletion() {
    let (_dir, kernel) = fixture().await;
    let principal = pid("owned-bob");
    let created = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: principal.to_string(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert_success(&created);

    let user = kernel
        .identity_store
        .resolve("cli", principal.as_str())
        .await
        .unwrap()
        .unwrap();
    let principal_identity = kernel
        .identity_store
        .get_principal_identity(user.id)
        .await
        .unwrap()
        .unwrap();
    let owner = UserIdentity::from_genesis(UserGenesis::from_parts(
        user.id,
        user.created_at,
        principal_identity.genesis.initial_public_key,
    ))
    .unwrap();
    let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        user.id,
        user.created_at,
        owner.uid,
    ))
    .unwrap();
    kernel
        .ownership_store
        .create_user(owner.clone())
        .await
        .unwrap();
    kernel
        .ownership_store
        .create_fleet(fleet.clone())
        .await
        .unwrap();
    kernel
        .ownership_store
        .assign_principal(PrincipalOwnership {
            principal_uid: principal_identity.uid,
            fleet_uid: fleet.uid,
            assigned_by: owner.uid,
        })
        .await
        .unwrap();

    let profile_path = PrincipalProfile::path_for(&kernel.astrid_home, &principal);
    let deleted = handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;
    assert_error_contains(&deleted, "assigned to fleet");

    assert!(
        profile_path.exists(),
        "rejected deletion must retain profile"
    );
    assert!(
        kernel
            .identity_store
            .resolve("cli", principal.as_str())
            .await
            .unwrap()
            .is_some(),
        "rejected deletion must retain the identity link"
    );

    // Model a prior partial attempt that removed the frontend link but failed
    // before deleting the durable user. A retry must recover the user by its
    // stored principal alias and still enforce ownership.
    assert_owned_delete_rejected_after_unlink(&kernel, &principal, user.id, &profile_path).await;
    assert_eq!(
        kernel
            .ownership_store
            .load()
            .await
            .unwrap()
            .principal_owner(principal_identity.uid)
            .unwrap()
            .fleet_uid,
        fleet.uid
    );
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

    let q = Quotas {
        max_memory_bytes: 0,
        ..Default::default()
    };
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

    let q = Quotas {
        max_memory_bytes: 8 * 1024 * 1024,
        ..Default::default()
    };
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
    use astrid_capabilities::CapabilityCheck;
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

#[tokio::test(flavor = "multi_thread")]
async fn agent_list_global_view_is_attenuated_by_device_scope() {
    let (_dir, kernel) = fixture().await;
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

    let full = DeviceKey::new("a".repeat(64), DeviceScope::Full, None, 0);
    let self_only = DeviceKey::new(
        "b".repeat(64),
        DeviceScope::Scoped {
            allow: vec!["self:*".to_string()],
            deny: Vec::new(),
        },
        None,
        0,
    );
    let global_list = DeviceKey::new(
        "c".repeat(64),
        DeviceScope::Scoped {
            allow: vec!["self:*".to_string(), "agent:list".to_string()],
            deny: Vec::new(),
        },
        None,
        0,
    );
    let full_id = full.key_id.clone();
    let self_only_id = self_only.key_id.clone();
    let global_list_id = global_list.key_id.clone();
    let mut profile = PrincipalProfile::load_from_path(&PrincipalProfile::path_for(
        &kernel.astrid_home,
        &PrincipalId::default(),
    ))
    .expect("load default profile");
    profile.auth.methods = vec![AuthMethod::Keypair];
    profile.auth.public_keys = vec![full, self_only, global_list];
    profile
        .save_to_path(&PrincipalProfile::path_for(
            &kernel.astrid_home,
            &PrincipalId::default(),
        ))
        .expect("save device-scoped default profile");
    kernel.profile_cache.invalidate(&PrincipalId::default());

    let full = agent_list_for(
        handlers::dispatch_with_device(
            &kernel,
            &PrincipalId::default(),
            Some(&full_id),
            AdminRequestKind::AgentList,
        )
        .await,
    );
    assert!(full.iter().any(|entry| entry.principal == pid("alice")));
    assert!(full.iter().any(|entry| entry.principal == pid("bob")));

    let global = agent_list_for(
        handlers::dispatch_with_device(
            &kernel,
            &PrincipalId::default(),
            Some(&global_list_id),
            AdminRequestKind::AgentList,
        )
        .await,
    );
    assert!(global.iter().any(|entry| entry.principal == pid("alice")));
    assert!(global.iter().any(|entry| entry.principal == pid("bob")));

    let scoped = agent_list_for(
        handlers::dispatch_with_device(
            &kernel,
            &PrincipalId::default(),
            Some(&self_only_id),
            AdminRequestKind::AgentList,
        )
        .await,
    );
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].principal, PrincipalId::default());

    assert_agent_list_authorization_snapshot(&kernel, profile, &global_list_id).await;
}

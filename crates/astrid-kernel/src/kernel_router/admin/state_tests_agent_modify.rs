//! `admin.agent.modify` handler tests (F-B).
//!
//! Lives in a sibling file rather than next to the rest of the agent
//! lifecycle tests in `state_tests.rs` because the latter is close to
//! the per-file CI line cap. The split is purely mechanical — the
//! shared fixture and assertion helpers are re-defined locally so each
//! test is self-contained.

use std::sync::Arc;

use astrid_capsule::capsule::{Capsule, CapsuleId, CapsuleState};
use astrid_capsule::context::CapsuleContext;
use astrid_capsule::error::CapsuleResult;
use astrid_capsule::manifest::CapsuleManifest;
use astrid_core::dirs::AstridHome;
use astrid_core::groups::{BUILTIN_ADMIN, BUILTIN_AGENT, BUILTIN_RESTRICTED};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};
use astrid_storage::env::{
    SECRET_KEY_PREFIX, get_env, principal_env_store, principal_secret_store, set_env,
    system_secret_store,
};
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

struct UnrestartableCapsule {
    id: CapsuleId,
    manifest: CapsuleManifest,
}

#[async_trait::async_trait]
impl Capsule for UnrestartableCapsule {
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

async fn seed_unrestartable_capsule(kernel: &Arc<Kernel>, name: &str) {
    let id = CapsuleId::new(name).unwrap();
    let mut manifest = CapsuleManifest::default();
    manifest.package.name = name.to_owned();
    manifest.package.version = "1.0.0".to_owned();
    kernel
        .capsules
        .write()
        .await
        .register(Box::new(UnrestartableCapsule { id, manifest }))
        .unwrap();
}

fn publish_env_capsule(kernel: &Arc<Kernel>, name: &str) {
    let dir = kernel
        .astrid_home
        .run_dir()
        .join("test-install-sources")
        .join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("Capsule.toml"),
        format!(
            "[package]\nname = \"{name}\"\nversion = \"1.0.0\"\n\n[env.temperature]\ntype = \"string\"\n"
        ),
    )
    .unwrap();
    let home = kernel.astrid_home.clone();
    let storage = kernel
        .principal_store
        .as_ref()
        .map(|store| Arc::new(store.clone()));
    let source = PrincipalId::default();
    std::thread::spawn(move || {
        astrid_capsule_install::install_from_local_path_for_principal(
            &dir,
            &home,
            astrid_capsule_install::InstallOptions {
                storage,
                ..Default::default()
            },
            &source,
        )
    })
    .join()
    .unwrap()
    .unwrap();
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
async fn agent_modify_empty_delta_verifies_target_without_writing_profile() {
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &astrid_core::PrincipalId::default(),
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
        AdminRequestKind::AgentModify {
            principal: target,
            add_groups: Vec::new(),
            remove_groups: Vec::new(),
            add_capsules: Vec::new(),
            remove_capsules: Vec::new(),
        },
    )
    .await;
    let AdminResponseBody::Success(body) = response else {
        panic!("expected success, got {response:?}");
    };
    assert_eq!(body["changed"], false);
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let missing = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentModify {
            principal: pid("missing-target"),
            add_groups: Vec::new(),
            remove_groups: Vec::new(),
            add_capsules: Vec::new(),
            remove_capsules: Vec::new(),
        },
    )
    .await;
    assert_error_contains(&missing, "missing-target");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_modify_preserves_default_admin_bootstrap_anchor() {
    let (_dir, kernel) = fixture().await;
    let default = PrincipalId::default();
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &default);
    PrincipalProfile {
        groups: vec![BUILTIN_ADMIN.to_string()],
        ..Default::default()
    }
    .save_to_path(&path)
    .expect("seed default admin profile");

    let removal = handlers::dispatch(
        &kernel,
        &default,
        AdminRequestKind::AgentModify {
            principal: default.clone(),
            add_groups: Vec::new(),
            remove_groups: vec![BUILTIN_ADMIN.to_string()],
            add_capsules: Vec::new(),
            remove_capsules: Vec::new(),
        },
    )
    .await;
    assert_error_contains(&removal, "bootstrap anchor");
    assert_eq!(
        PrincipalProfile::load_from_path(&path)
            .expect("reload default profile")
            .groups,
        vec![BUILTIN_ADMIN.to_string()]
    );

    let remove_and_add = handlers::dispatch(
        &kernel,
        &default,
        AdminRequestKind::AgentModify {
            principal: default.clone(),
            add_groups: vec![BUILTIN_ADMIN.to_string()],
            remove_groups: vec![BUILTIN_ADMIN.to_string()],
            add_capsules: Vec::new(),
            remove_capsules: Vec::new(),
        },
    )
    .await;
    assert_success(&remove_and_add);
    assert_eq!(
        PrincipalProfile::load_from_path(&path)
            .expect("reload default profile")
            .groups,
        vec![BUILTIN_ADMIN.to_string()]
    );
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

#[tokio::test(flavor = "multi_thread")]
async fn env_mutations_surface_reload_failure_for_loaded_capsule() {
    let (_dir, kernel) = fixture().await;
    let capsule = "env-reload";
    seed_unrestartable_capsule(&kernel, capsule).await;
    let principal = PrincipalId::default();

    let set = handlers::dispatch(
        &kernel,
        &principal,
        AdminRequestKind::EnvSet {
            principal: principal.clone(),
            capsule: capsule.into(),
            key: "temperature".into(),
            value: "0.7".into(),
            kind: astrid_events::kernel_api::EnvValueKind::Text,
            scope: astrid_events::kernel_api::EnvStorageScope::Agent,
            append: false,
        },
    )
    .await;
    assert_error_contains(&set, "no source directory");

    let uid = kernel.principal_directory.uid_for(&principal).unwrap();
    let env = principal_env_store(Arc::clone(&kernel.kv), uid, capsule).unwrap();
    assert_eq!(
        get_env(&env, "temperature").await.unwrap().as_deref(),
        Some("0.7")
    );

    let deleted = handlers::dispatch(
        &kernel,
        &principal,
        AdminRequestKind::EnvDelete {
            principal: principal.clone(),
            capsule: capsule.into(),
            key: "temperature".into(),
            kind: astrid_events::kernel_api::EnvValueKind::Text,
            scope: astrid_events::kernel_api::EnvStorageScope::Agent,
        },
    )
    .await;
    assert_error_contains(&deleted, "no source directory");
    assert!(get_env(&env, "temperature").await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn assigning_capsule_copies_non_secret_install_env_only() {
    let (_dir, kernel) = fixture().await;
    let capsule = "assigned-env";
    publish_env_capsule(&kernel, capsule);

    let default_uid = kernel
        .principal_directory
        .uid_for(&PrincipalId::default())
        .unwrap();
    let source_env = principal_env_store(Arc::clone(&kernel.kv), default_uid, capsule).unwrap();
    set_env(&source_env, "temperature", "0.7").await.unwrap();
    let source_secret =
        principal_secret_store(Arc::clone(&kernel.kv), default_uid, capsule).unwrap();
    source_secret
        .set(
            &format!("{SECRET_KEY_PREFIX}api_key"),
            b"must-not-copy".to_vec(),
        )
        .await
        .unwrap();
    let shared_secret = system_secret_store(Arc::clone(&kernel.kv), capsule).unwrap();
    shared_secret
        .set(
            &format!("{SECRET_KEY_PREFIX}api_key"),
            b"site-secret-must-not-copy".to_vec(),
        )
        .await
        .unwrap();

    let principal = pid("assigned-agent");
    let created = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: principal.to_string(),
            groups: vec![BUILTIN_AGENT.into()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert_success(&created);

    let assigned = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentModify {
            principal: principal.clone(),
            add_groups: Vec::new(),
            remove_groups: Vec::new(),
            add_capsules: vec![capsule.into()],
            remove_capsules: Vec::new(),
        },
    )
    .await;
    assert_success(&assigned);

    let target_uid = kernel.principal_directory.uid_for(&principal).unwrap();
    let target_env = principal_env_store(Arc::clone(&kernel.kv), target_uid, capsule).unwrap();
    assert_eq!(
        get_env(&target_env, "temperature")
            .await
            .unwrap()
            .as_deref(),
        Some("0.7")
    );
    let target_secret =
        principal_secret_store(Arc::clone(&kernel.kv), target_uid, capsule).unwrap();
    assert!(
        target_secret
            .get(&format!("{SECRET_KEY_PREFIX}api_key"))
            .await
            .unwrap()
            .is_none(),
        "assignment must not copy source secrets"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn env_set_unloaded_capsule_accepts_sequential_writes() {
    let (_dir, kernel) = fixture().await;
    let capsule = "sequential-env";
    let dir = kernel
        .astrid_home
        .run_dir()
        .join("test-install-sources")
        .join(capsule);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("Capsule.toml"),
        format!(
            "[package]\nname = \"{capsule}\"\nversion = \"1.0.0\"\n\n[env.base_url]\ntype = \"string\"\n\n[env.model]\ntype = \"string\"\n"
        ),
    )
    .unwrap();
    let home = kernel.astrid_home.clone();
    let storage = kernel
        .principal_store
        .as_ref()
        .map(|store| Arc::new(store.clone()));
    let source = PrincipalId::default();
    std::thread::spawn(move || {
        astrid_capsule_install::install_from_local_path_for_principal(
            &dir,
            &home,
            astrid_capsule_install::InstallOptions {
                storage,
                ..Default::default()
            },
            &source,
        )
    })
    .join()
    .unwrap()
    .unwrap();

    let principal = PrincipalId::default();
    let first = handlers::dispatch(
        &kernel,
        &principal,
        AdminRequestKind::EnvSet {
            principal: principal.clone(),
            capsule: capsule.into(),
            key: "base_url".into(),
            value: "https://example.test".into(),
            kind: astrid_events::kernel_api::EnvValueKind::Text,
            scope: astrid_events::kernel_api::EnvStorageScope::Agent,
            append: false,
        },
    )
    .await;
    assert_success(&first);
    let second = handlers::dispatch(
        &kernel,
        &principal,
        AdminRequestKind::EnvSet {
            principal: principal.clone(),
            capsule: capsule.into(),
            key: "model".into(),
            value: "gpt-test".into(),
            kind: astrid_events::kernel_api::EnvValueKind::Text,
            scope: astrid_events::kernel_api::EnvStorageScope::Agent,
            append: false,
        },
    )
    .await;
    assert_success(&second);
}

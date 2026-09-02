use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, DistroCapsuleProvenance};
use astrid_core::profile::PrincipalProfile;
use tempfile::TempDir;

use super::handlers;
use crate::Kernel;

async fn fixture() -> (TempDir, Arc<Kernel>) {
    let dir = tempfile::tempdir().unwrap();
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(dir.path())).await;
    (dir, kernel)
}

fn caller() -> PrincipalId {
    PrincipalId::new("worker").unwrap()
}

async fn create_principal(kernel: &Arc<Kernel>, principal: &PrincipalId) {
    let response = handlers::dispatch(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: principal.as_str().to_owned(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert!(
        matches!(response, AdminResponseBody::Success(_)),
        "{response:?}"
    );
}

fn hash(seed: char) -> String {
    format!("blake3:{}", seed.to_string().repeat(64))
}

fn lock(names: &[&str], manifest: Option<String>) -> astrid_core::kernel_api::DistroProvenance {
    astrid_core::kernel_api::DistroProvenance {
        schema_version: 1,
        distro_id: "product".into(),
        distro_version: "1.0.0".into(),
        resolved_at: "2026-01-01T00:00:00Z".into(),
        capsules: names
            .iter()
            .map(|name| DistroCapsuleProvenance {
                name: (*name).into(),
                version: "1.0.0".into(),
                source: "@example/tool".into(),
                hash: hash('a'),
                resolved_ref: None,
            })
            .collect(),
        manifest_hash: manifest,
    }
}

async fn seed_lock(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    provenance: astrid_core::kernel_api::DistroProvenance,
) {
    let uid = kernel.principal_directory.uid_for(principal).unwrap();
    let store = kernel
        .principal_store
        .as_ref()
        .unwrap()
        .principal_control_kv(uid, "distro")
        .unwrap();
    let previous = store.get("provenance").await.unwrap();
    let expected_hash = previous.map(|bytes| format!("blake3:{}", blake3::hash(&bytes).to_hex()));
    let response = handlers::dispatch(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::DistroLockSet {
            principal: principal.clone(),
            lock: provenance,
            expected_hash,
        },
    )
    .await;
    assert!(
        matches!(response, AdminResponseBody::Success(_)),
        "{response:?}"
    );
}

fn seed_profile(kernel: &Arc<Kernel>, principal: &PrincipalId, capsules: &[&str]) {
    let profile = PrincipalProfile {
        capsules: capsules.iter().map(|name| (*name).to_owned()).collect(),
        ..PrincipalProfile::default()
    };
    profile
        .save_to_path(&PrincipalProfile::path_for(&kernel.astrid_home, principal))
        .unwrap();
    kernel.profile_cache.invalidate(principal);
}

fn control_store(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    namespace: &str,
) -> astrid_storage::kv::ScopedKvStore {
    let uid = kernel.principal_directory.uid_for(principal).unwrap();
    astrid_storage::env::principal_env_store(
        Arc::clone(&kernel.principal_store.as_ref().unwrap().kv()),
        uid,
        namespace,
    )
    .unwrap()
}

fn profile_text(kernel: &Arc<Kernel>, principal: &PrincipalId) -> String {
    std::fs::read_to_string(PrincipalProfile::path_for(&kernel.astrid_home, principal)).unwrap()
}

fn capsules(response: AdminResponseBody) -> Vec<String> {
    let AdminResponseBody::Success(value) = response else {
        panic!("expected success");
    };
    serde_json::from_value(value["capsules"].clone()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn grants_exactly_admitted_lock_members_and_replays_without_widening() {
    let (_dir, kernel) = fixture().await;
    let principal = caller();
    create_principal(&kernel, &principal).await;
    seed_lock(
        &kernel,
        &principal,
        lock(&["tool-a", "tool-b"], Some(hash('b'))),
    )
    .await;
    seed_profile(&kernel, &principal, &["tool-outside"]);

    let first = handlers::dispatch(&kernel, &principal, AdminRequestKind::DistroSelfGrant).await;
    assert_eq!(
        capsules(first),
        ["tool-outside", "tool-a", "tool-b"].map(str::to_owned)
    );
    let replay = handlers::dispatch(&kernel, &principal, AdminRequestKind::DistroSelfGrant).await;
    assert_eq!(
        capsules(replay),
        ["tool-outside", "tool-a", "tool-b"].map(str::to_owned)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_empty_or_unbound_locks_fail_closed() {
    let (_dir, kernel) = fixture().await;
    let principal = caller();
    create_principal(&kernel, &principal).await;
    let missing = handlers::dispatch(&kernel, &principal, AdminRequestKind::DistroSelfGrant).await;
    assert!(
        matches!(missing, AdminResponseBody::Error(message) if message.contains("no admitted"))
    );

    seed_lock(&kernel, &principal, lock(&[], Some(hash('b')))).await;
    let empty = handlers::dispatch(&kernel, &principal, AdminRequestKind::DistroSelfGrant).await;
    assert!(matches!(empty, AdminResponseBody::Error(message) if message.contains("no capsules")));

    seed_lock(&kernel, &principal, lock(&["tool-a"], None)).await;
    let unbound = handlers::dispatch(&kernel, &principal, AdminRequestKind::DistroSelfGrant).await;
    assert!(
        matches!(unbound, AdminResponseBody::Error(message) if message.contains("manifest_hash"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn caller_without_lock_cannot_use_another_principals_lock() {
    let (_dir, kernel) = fixture().await;
    let other = PrincipalId::new("other").unwrap();
    create_principal(&kernel, &other).await;
    seed_lock(&kernel, &other, lock(&["tool-a"], Some(hash('b')))).await;
    create_principal(&kernel, &caller()).await;
    let response = handlers::dispatch(&kernel, &caller(), AdminRequestKind::DistroSelfGrant).await;
    assert!(
        matches!(response, AdminResponseBody::Error(message) if message.contains("no admitted"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lock_change_after_observation_fails_instead_of_granting_stale_set() {
    let (_dir, kernel) = fixture().await;
    let principal = caller();
    create_principal(&kernel, &principal).await;
    seed_lock(&kernel, &principal, lock(&["tool-a"], Some(hash('b')))).await;
    seed_profile(&kernel, &principal, &[]);

    let guard = kernel.admin_write_lock.lock().await;
    let task = astrid_runtime::spawn({
        let kernel = Arc::clone(&kernel);
        let principal = principal.clone();
        async move { handlers::dispatch(&kernel, &principal, AdminRequestKind::DistroSelfGrant).await }
    });
    astrid_runtime::time::sleep(std::time::Duration::from_millis(20)).await;

    let uid = kernel.principal_directory.uid_for(&principal).unwrap();
    let store = kernel
        .principal_store
        .as_ref()
        .unwrap()
        .principal_control_kv(uid, "distro")
        .unwrap();
    let previous = store.get("provenance").await.unwrap();
    let changed = lock(&["tool-attacker"], Some(hash('c')));
    let encoded = serde_json::to_vec(&changed).unwrap();
    assert!(
        store
            .compare_and_swap("provenance", previous.as_deref(), encoded)
            .await
            .unwrap()
    );
    drop(guard);

    let response = task.await.unwrap();
    assert!(
        matches!(response, AdminResponseBody::Error(message) if message.contains("changed concurrently"))
    );
    let profile = PrincipalProfile::load_required(&kernel.astrid_home, &principal).unwrap();
    assert!(!profile.capsules.iter().any(|name| name == "tool-attacker"));
}

#[tokio::test(flavor = "multi_thread")]
async fn identical_artifacts_do_not_create_cross_principal_authority_or_storage() {
    let (_dir, kernel) = fixture().await;
    let principal_a = PrincipalId::new("tenant-a").unwrap();
    let principal_b = PrincipalId::new("tenant-b").unwrap();
    create_principal(&kernel, &principal_a).await;
    create_principal(&kernel, &principal_b).await;
    let shared = lock(&["shared-tool"], Some(hash('b')));
    seed_lock(&kernel, &principal_a, shared.clone()).await;
    seed_lock(&kernel, &principal_b, shared).await;
    seed_profile(&kernel, &principal_a, &[]);
    seed_profile(&kernel, &principal_b, &[]);
    let b_store = control_store(&kernel, &principal_b, "probe-tool");
    b_store.set("state", b"tenant-b".to_vec()).await.unwrap();

    handlers::dispatch(&kernel, &principal_a, AdminRequestKind::DistroSelfGrant).await;

    let profile_a = PrincipalProfile::load_required(&kernel.astrid_home, &principal_a).unwrap();
    let profile_b = PrincipalProfile::load_required(&kernel.astrid_home, &principal_b).unwrap();
    assert_eq!(profile_a.capsules, ["shared-tool"].map(str::to_owned));
    assert!(profile_b.capsules.is_empty());
    assert_eq!(
        b_store.get("state").await.unwrap().as_deref(),
        Some(b"tenant-b".as_slice())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tenant_a_lock_upgrade_does_not_mutate_tenant_b() {
    let (_dir, kernel) = fixture().await;
    let principal_a = PrincipalId::new("tenant-a").unwrap();
    let principal_b = PrincipalId::new("tenant-b").unwrap();
    create_principal(&kernel, &principal_a).await;
    create_principal(&kernel, &principal_b).await;
    let shared = lock(&["shared-tool"], Some(hash('b')));
    seed_lock(&kernel, &principal_a, shared.clone()).await;
    seed_lock(&kernel, &principal_b, shared).await;
    seed_profile(&kernel, &principal_a, &["shared-tool"]);
    seed_profile(&kernel, &principal_b, &["shared-tool"]);
    let b_profile = profile_text(&kernel, &principal_b);
    let b_store = control_store(&kernel, &principal_b, "probe-tool");
    b_store.set("state", b"tenant-b".to_vec()).await.unwrap();

    seed_lock(
        &kernel,
        &principal_a,
        lock(&["upgraded-tool"], Some(hash('c'))),
    )
    .await;

    let profile_a = PrincipalProfile::load_required(&kernel.astrid_home, &principal_a).unwrap();
    let profile_b_after =
        PrincipalProfile::load_required(&kernel.astrid_home, &principal_b).unwrap();
    assert!(profile_a.capsules.iter().any(|name| name == "shared-tool"));
    assert_eq!(profile_b_after.capsules, ["shared-tool"].map(str::to_owned));
    assert_eq!(profile_text(&kernel, &principal_b), b_profile);
    assert_eq!(
        b_store.get("state").await.unwrap().as_deref(),
        Some(b"tenant-b".as_slice())
    );
}

#[test]
fn distro_self_grant_wire_has_no_target_or_capsule_list() {
    let value = serde_json::to_value(&AdminRequestKind::DistroSelfGrant).unwrap();
    let params = value["params"].as_object();
    assert_eq!(value["method"], "DistroSelfGrant");
    assert!(params.is_none_or(serde_json::Map::is_empty));
}

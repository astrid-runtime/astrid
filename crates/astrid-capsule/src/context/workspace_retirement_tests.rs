//! Ordinary unload retention versus explicit immutable UID retirement.

use super::*;
use astrid_core::{UserGenesis, UserIdentity};
use astrid_storage::{
    ContentName, KvQuotaResolver, OwnershipStore, StateOwner, WorkspaceBranchStore,
};
use chrono::{TimeZone, Utc};
use std::sync::Arc;
use uuid::Uuid;

struct RetirementContrastFixture {
    _home: tempfile::TempDir,
    store: astrid_storage::RuntimePrincipalStore,
    directory: astrid_storage::PrincipalDirectory,
    ownership: Arc<OwnershipStore>,
    service: Arc<WorkspaceBranchService>,
    alice: PrincipalId,
    uid: astrid_core::PrincipalUid,
}

fn user_identity(id: u128, key: u8) -> UserIdentity {
    UserIdentity::from_genesis(UserGenesis::from_parts(
        Uuid::from_u128(id),
        Utc.timestamp_opt(1_700_000_000, 0)
            .single()
            .expect("user time"),
        [key; 32],
    ))
    .expect("user identity")
}

async fn retirement_fixture() -> RetirementContrastFixture {
    let root = tempfile::tempdir().expect("workspace retirement tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    home.ensure().expect("workspace retirement home");
    let directory = astrid_storage::PrincipalDirectory::default();
    let alice = PrincipalId::new("alice").expect("alice alias");
    let uid = astrid_core::PrincipalUid::from_bytes([0xA1; 32]);
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
        })
    });
    let store = astrid_storage::open_runtime_principal_store_with_directory(
        &home,
        quota,
        directory.clone(),
    )
    .await
    .expect("runtime principal store");
    // Opening refreshes the shared directory from durable identity projection,
    // so fixture-only identities are installed after open.
    directory
        .register(alice.clone(), uid)
        .expect("alice identity");
    let ownership =
        Arc::new(OwnershipStore::new(store.kv(), directory.clone()).expect("ownership store"));
    let owner = user_identity(0xD1, 3);
    ownership.create_user(owner).await.expect("user");
    // Keep the principal unowned so ordinary unload uses the private root and
    // deletion reservation can be taken without device/fleet authority.
    let service = Arc::new(WorkspaceBranchService::new_with_ownership(
        store.clone(),
        directory.clone(),
        Some(Arc::clone(&ownership)),
    ));
    RetirementContrastFixture {
        _home: root,
        store,
        directory,
        ownership,
        service,
        alice,
        uid,
    }
}

async fn seed_live_workspace(
    fixture: &RetirementContrastFixture,
) -> (
    WorkspaceBranchBinding,
    astrid_storage::FilesystemPath,
    ContentName,
) {
    let original = fixture
        .service
        .bind(&fixture.alice)
        .await
        .expect("initial bind");
    assert_eq!(original.uid, fixture.uid);
    let path = astrid_storage::FilesystemPath::new("unload-note").expect("path");
    fixture
        .service
        .filesystem(original)
        .write(&path, b"keep-me")
        .expect("write durable branch data");
    let private = ContentName::new("private-after-unload").expect("private name");
    fixture
        .store
        .content()
        .put(
            &StateOwner::Principal(fixture.uid),
            &private,
            b"private-keep",
        )
        .expect("private content");
    (original, path, private)
}

async fn assert_retained_after_ordinary_unload(
    store: &astrid_storage::RuntimePrincipalStore,
    directory: &astrid_storage::PrincipalDirectory,
    ownership: Arc<OwnershipStore>,
    alice: &PrincipalId,
    original: WorkspaceBranchBinding,
    path: &astrid_storage::FilesystemPath,
    private: &ContentName,
) -> WorkspaceBranchService {
    let recovered = WorkspaceBranchService::new_with_ownership(
        store.clone(),
        directory.clone(),
        Some(ownership),
    );
    let rebound = recovered
        .binding_for(alice)
        .await
        .expect("ordinary unload must rebind the durable live branch");
    assert_eq!(rebound, original);
    assert_eq!(
        recovered
            .filesystem(rebound)
            .read(path, 0, 7)
            .expect("read retained branch"),
        b"keep-me"
    );
    recovered
        .cleanup_orphaned()
        .await
        .expect("boot cleanup preserves valid live branches");
    assert_eq!(
        recovered
            .filesystem(rebound)
            .read(path, 0, 7)
            .expect("branch survives cleanup_orphaned"),
        b"keep-me"
    );
    assert_eq!(
        store
            .content()
            .read(&StateOwner::Principal(original.uid), private)
            .expect("read private"),
        Some(b"private-keep".to_vec())
    );
    recovered
}

fn assert_retired_storage(
    store: &astrid_storage::RuntimePrincipalStore,
    recovered: &WorkspaceBranchService,
    uid: astrid_core::PrincipalUid,
    private: &ContentName,
) {
    let owner = StateOwner::Principal(uid);
    let branches = WorkspaceBranchStore::new(store.content());
    assert!(
        branches
            .list_bindings_by_uid(&owner, uid)
            .expect("list after retire")
            .is_empty()
    );
    assert!(
        recovered.bindings.lock().expect("bindings lock").is_empty(),
        "retire_principal must forget the in-memory binding"
    );
    assert!(
        store
            .content()
            .read(&owner, private)
            .expect("private after retire")
            .is_none()
    );
}

#[tokio::test]
async fn ordinary_service_drop_retains_live_workspace_until_retire_principal() {
    let fixture = retirement_fixture().await;
    let (original, path, private) = seed_live_workspace(&fixture).await;

    // Ordinary capsule/service unload drops only the in-memory handle. Drop is
    // intentionally empty so durable live UID-bound branches survive rebuild.
    drop(fixture.service);

    let recovered = assert_retained_after_ordinary_unload(
        &fixture.store,
        &fixture.directory,
        Arc::clone(&fixture.ownership),
        &fixture.alice,
        original,
        &path,
        &private,
    )
    .await;

    let deletion = fixture
        .ownership
        .guard_principal_deletion_for_alias(fixture.uid, fixture.alice.clone())
        .await
        .expect("durable deletion reservation before reclaim");
    recovered
        .retire_principal(fixture.uid)
        .await
        .expect("explicit UID retirement under reservation");
    assert_retired_storage(&fixture.store, &recovered, fixture.uid, &private);
    let err = recovered
        .binding_for(&fixture.alice)
        .await
        .expect_err("retired/reserving identity must not expose a live workspace");
    assert!(
        err.contains("being retired"),
        "expected retirement fence, got {err}"
    );
    deletion.finish().await.expect("finish reservation");
}

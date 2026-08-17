use super::*;
use astrid_core::{FleetGenesis, FleetIdentity, PrincipalOwnership, UserGenesis, UserIdentity};
use astrid_storage::{KvQuotaResolver, StateOwner};
use chrono::{TimeZone, Utc};
use uuid::Uuid;

struct Fixture {
    _home: tempfile::TempDir,
    store: astrid_storage::RuntimePrincipalStore,
    directory: astrid_storage::PrincipalDirectory,
    service: Arc<WorkspaceBranchService>,
    alice: PrincipalId,
    bob: PrincipalId,
}

async fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("workspace service tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    home.ensure().expect("workspace service home");
    let directory = astrid_storage::PrincipalDirectory::default();
    let alice = PrincipalId::new("alice").expect("alice alias");
    let bob = PrincipalId::new("bob").expect("bob alias");
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
    // Opening the runtime store refreshes the shared directory from its
    // durable identity projection, so install fixture-only identities
    // after open (production callers register through that projection).
    directory
        .register(
            alice.clone(),
            astrid_core::PrincipalUid::from_bytes([0xA1; 32]),
        )
        .expect("alice identity");
    directory
        .register(
            bob.clone(),
            astrid_core::PrincipalUid::from_bytes([0xB2; 32]),
        )
        .expect("bob identity");
    let service = Arc::new(WorkspaceBranchService::new(
        store.clone(),
        directory.clone(),
    ));
    Fixture {
        _home: root,
        store,
        directory,
        service,
        alice,
        bob,
    }
}

fn fleet_identity(id: u128, creator: astrid_core::UserUid) -> FleetIdentity {
    FleetIdentity::from_genesis(FleetGenesis::from_parts(
        Uuid::from_u128(id),
        Utc.timestamp_opt(1_700_000_001, 0)
            .single()
            .expect("fleet time"),
        creator,
    ))
    .expect("fleet identity")
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

#[tokio::test]
async fn concurrent_capsules_share_one_uid_branch() {
    let fixture = fixture().await;
    let left = Arc::clone(&fixture.service);
    let right = Arc::clone(&fixture.service);
    let alice_left = fixture.alice.clone();
    let alice_right = fixture.alice.clone();
    let (left, right) = tokio::join!(
        tokio::task::spawn(async move { left.bind(&alice_left).await }),
        tokio::task::spawn(async move { right.bind(&alice_right).await }),
    );
    let left = left.expect("left bind task").expect("left bind");
    let right = right.expect("right bind task").expect("right bind");
    assert_eq!(left, right);

    let first = fixture.service.filesystem(left);
    let second = fixture.service.filesystem(right);
    let path = astrid_storage::FilesystemPath::new("note").expect("note path");
    first.write(&path, b"shared").expect("first write");
    assert_eq!(second.read(&path, 0, 6).expect("second read"), b"shared");
}

#[tokio::test]
async fn durable_binding_rebinds_after_service_restart() {
    let fixture = fixture().await;
    let original = fixture
        .service
        .bind(&fixture.alice)
        .await
        .expect("initial bind");
    let path = astrid_storage::FilesystemPath::new("restart-note").expect("path");
    fixture
        .service
        .filesystem(original)
        .write(&path, b"durable")
        .expect("write branch data");

    // A fresh service has an empty in-memory cache but must recover the
    // UID-bound branch record from the authoritative owner catalog.
    let recovered = WorkspaceBranchService::new(fixture.store.clone(), fixture.directory.clone());
    let rebound = recovered
        .binding_for(&fixture.alice)
        .await
        .expect("rebind durable branch");
    assert_eq!(rebound, original);
    assert_eq!(
        recovered
            .filesystem(rebound)
            .read(&path, 0, 7)
            .expect("read recovered branch"),
        b"durable"
    );
    recovered
        .cleanup_orphaned()
        .await
        .expect("preserve valid branch during boot cleanup");
    assert!(recovered.filesystem(rebound).read(&path, 0, 7).is_ok());
}

#[tokio::test]
async fn different_principal_uids_are_isolated() {
    let fixture = fixture().await;
    let alice = fixture
        .service
        .bind(&fixture.alice)
        .await
        .expect("alice bind");
    let bob = fixture.service.bind(&fixture.bob).await.expect("bob bind");
    assert_ne!(alice.uid, bob.uid);
    assert_ne!(alice.branch, bob.branch);
    let path = astrid_storage::FilesystemPath::new("note").expect("note path");
    fixture
        .service
        .filesystem(alice)
        .write(&path, b"alice")
        .expect("alice write");
    assert!(matches!(
        fixture.service.filesystem(bob).read(&path, 0, 5),
        Err(astrid_storage::WorkspaceBranchError::Filesystem(
            astrid_storage::FilesystemError::NotFound(_)
        ))
    ));
}

#[tokio::test]
async fn alias_reuse_cannot_rebind_an_old_branch() {
    let fixture = fixture().await;
    let binding = fixture
        .service
        .bind(&fixture.alice)
        .await
        .expect("alice bind");
    let renamed = PrincipalId::new("alice-renamed").expect("renamed alias");
    fixture
        .directory
        .rename(binding.uid, &fixture.alice, renamed.clone())
        .expect("rename alias");
    fixture
        .directory
        .register(
            fixture.alice.clone(),
            astrid_core::PrincipalUid::from_bytes([0xC3; 32]),
        )
        .expect("reuse alias for a new uid");
    assert!(fixture.service.binding_for(&fixture.alice).await.is_err());
    assert!(
        fixture
            .service
            .finish(&fixture.alice, binding, WorkspaceCommitOp::Rollback)
            .await
            .is_err()
    );
    assert_eq!(
        fixture
            .service
            .binding_for(&renamed)
            .await
            .expect("renamed binding"),
        binding
    );
}

#[tokio::test]
async fn boot_cleanup_preserves_durable_uid_binding() {
    let fixture = fixture().await;
    let uid = fixture
        .directory
        .uid_for(&fixture.alice)
        .expect("alice uid");
    let owner = StateOwner::Principal(uid);
    let branches = astrid_storage::WorkspaceBranchStore::new(fixture.store.content());
    let prefix = astrid_storage::ContentName::new(WorkspaceBranchService::ATTACHMENT_PREFIX)
        .expect("attachment prefix");
    let descriptor = branches
        .begin_for_uid_at(&owner, uid, astrid_storage::WorkspaceUid::random(), prefix)
        .expect("orphan branch");
    assert_eq!(
        branches.list_branches(&owner).expect("list branch").len(),
        1
    );
    fixture
        .service
        .cleanup_orphaned()
        .await
        .expect("cleanup branches");
    assert!(
        branches.describe(&owner, descriptor.id()).is_ok(),
        "durable UID-bound branch was removed during cleanup"
    );
}

#[tokio::test]
async fn assigned_fleet_principals_share_base_but_get_independent_branches() {
    let fixture = fixture().await;
    let owner = user_identity(0xD1, 1);
    let fleet = fleet_identity(0xD2, owner.uid);
    let ownership = Arc::new(
        astrid_storage::OwnershipStore::new(fixture.store.kv(), fixture.directory.clone())
            .expect("ownership store"),
    );
    ownership.create_user(owner.clone()).await.expect("user");
    ownership.create_fleet(fleet.clone()).await.expect("fleet");
    ownership
        .assign_principal(PrincipalOwnership {
            principal_uid: fixture
                .directory
                .uid_for(&fixture.alice)
                .expect("alice uid"),
            fleet_uid: fleet.uid,
            assigned_by: owner.uid,
        })
        .await
        .expect("alice assignment");
    ownership
        .assign_principal(PrincipalOwnership {
            principal_uid: fixture.directory.uid_for(&fixture.bob).expect("bob uid"),
            fleet_uid: fleet.uid,
            assigned_by: owner.uid,
        })
        .await
        .expect("bob assignment");
    let service = WorkspaceBranchService::new_with_ownership(
        fixture.store.clone(),
        fixture.directory.clone(),
        Some(ownership),
    );
    let alice = service.bind(&fixture.alice).await.expect("alice bind");
    let bob = service.bind(&fixture.bob).await.expect("bob bind");
    assert_eq!(alice.owner, StateOwner::Fleet(fleet.uid));
    assert_eq!(bob.owner, StateOwner::Fleet(fleet.uid));
    assert_ne!(alice.branch, bob.branch);
}

#[tokio::test]
async fn ownership_move_invalidates_existing_branch_before_finish() {
    let fixture = fixture().await;
    let owner = user_identity(0xE1, 2);
    let first = fleet_identity(0xE2, owner.uid);
    let second = fleet_identity(0xE3, owner.uid);
    let ownership = Arc::new(
        astrid_storage::OwnershipStore::new(fixture.store.kv(), fixture.directory.clone())
            .expect("ownership store"),
    );
    ownership.create_user(owner.clone()).await.expect("user");
    ownership
        .create_fleet(first.clone())
        .await
        .expect("first fleet");
    ownership
        .create_fleet(second.clone())
        .await
        .expect("second fleet");
    let alice_uid = fixture
        .directory
        .uid_for(&fixture.alice)
        .expect("alice uid");
    ownership
        .assign_principal(PrincipalOwnership {
            principal_uid: alice_uid,
            fleet_uid: first.uid,
            assigned_by: owner.uid,
        })
        .await
        .expect("assignment");
    let service = WorkspaceBranchService::new_with_ownership(
        fixture.store.clone(),
        fixture.directory.clone(),
        Some(Arc::clone(&ownership)),
    );
    let binding = service.bind(&fixture.alice).await.expect("bind");
    ownership
        .transfer_principal(alice_uid, first.uid, second.uid, owner.uid)
        .await
        .expect("transfer");
    assert!(service.binding_for(&fixture.alice).await.is_err());
    assert!(
        service
            .finish(&fixture.alice, binding, WorkspaceCommitOp::Promote)
            .await
            .is_err()
    );
}

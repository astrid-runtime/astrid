use super::super::handlers::AGENT_IDENTITY_PLATFORM;
use super::rollback::{
    collect_remove_dir, collect_remove_file, rollback_created_identity_unless_assigned,
};
use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_core::{FleetGenesis, FleetIdentity, PrincipalOwnership, UserGenesis, UserIdentity};

#[test]
fn cleanup_collectors_preserve_every_reclamation_error() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("directory");
    let file = temp.path().join("file");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(&file, b"state").unwrap();
    let mut errors = Vec::new();

    collect_remove_file(&directory, "profile", &mut errors);
    collect_remove_dir(&file, "home", &mut errors);

    assert_eq!(errors.len(), 2, "both independent failures must survive");
    assert!(errors[0].contains("profile"));
    assert!(errors[1].contains("home"));
}

async fn kernel_with_identity(
    name: &str,
) -> (
    tempfile::TempDir,
    std::sync::Arc<crate::Kernel>,
    PrincipalId,
    uuid::Uuid,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(dir.path())).await;
    let principal = PrincipalId::new(name).unwrap();
    let user = kernel
        .identity_store
        .create_principal(principal.clone(), [0x11; 32])
        .await
        .expect("create identity");
    let profile_path = PrincipalProfile::path_for(&kernel.astrid_home, &principal);
    PrincipalProfile::default()
        .save_to_path(&profile_path)
        .expect("save profile");
    (dir, kernel, principal, user.id)
}

#[tokio::test(flavor = "multi_thread")]
async fn assignment_error_preserves_identity_when_graph_already_owns_uid() {
    let (_dir, kernel, principal, user_id) = kernel_with_identity("owned-agent").await;
    let human = UserIdentity::from_genesis(UserGenesis::from_parts(
        uuid::Uuid::from_u128(1),
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        [0x21; 32],
    ))
    .unwrap();
    let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        uuid::Uuid::from_u128(2),
        chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
        human.uid,
    ))
    .unwrap();
    kernel
        .ownership_store
        .create_user(human.clone())
        .await
        .unwrap();
    kernel
        .ownership_store
        .create_fleet(fleet.clone())
        .await
        .unwrap();
    let uid = kernel.principal_directory.uid_for(&principal).unwrap();
    kernel
        .ownership_store
        .assign_principal(PrincipalOwnership {
            principal_uid: uid,
            fleet_uid: fleet.uid,
            assigned_by: human.uid,
        })
        .await
        .unwrap();

    let profile_path = PrincipalProfile::path_for(&kernel.astrid_home, &principal);
    rollback_created_identity_unless_assigned(&kernel, &principal, user_id, &profile_path).await;

    assert!(
        profile_path.exists(),
        "assigned identity must survive an unconfirmed assignment error"
    );
    assert_eq!(
        kernel
            .ownership_store
            .load()
            .await
            .unwrap()
            .principal_owner(uid)
            .map(|owner| owner.fleet_uid),
        Some(fleet.uid)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn assignment_error_rolls_back_identity_when_uid_is_unowned() {
    let (_dir, kernel, principal, user_id) = kernel_with_identity("unowned-agent").await;
    let profile_path = PrincipalProfile::path_for(&kernel.astrid_home, &principal);
    rollback_created_identity_unless_assigned(&kernel, &principal, user_id, &profile_path).await;

    assert!(
        !profile_path.exists(),
        "unowned provisioned identity must roll back"
    );
    assert!(
        kernel
            .identity_store
            .resolve(AGENT_IDENTITY_PLATFORM, principal.as_str())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn changed_assignment_cannot_retire_the_new_owner() {
    let (_dir, kernel, creator, _) = kernel_with_identity("rollback-creator").await;
    let child = PrincipalId::new("transferred-initialization").unwrap();
    let child_user = kernel
        .identity_store
        .create_principal(child.clone(), [0x12; 32])
        .await
        .unwrap();
    kernel
        .identity_store
        .link(
            AGENT_IDENTITY_PLATFORM,
            child.as_str(),
            child_user.id,
            "system",
        )
        .await
        .unwrap();
    let profile = PrincipalProfile::path_for(&kernel.astrid_home, &child);
    PrincipalProfile::default().save_to_path(&profile).unwrap();
    let (human, fleets) = rollback_fleets(&kernel.ownership_store).await;
    let creator_uid = kernel.principal_directory.uid_for(&creator).unwrap();
    let child_uid = kernel.principal_directory.uid_for(&child).unwrap();
    kernel
        .ownership_store
        .assign_principal(PrincipalOwnership {
            principal_uid: creator_uid,
            fleet_uid: fleets[0].uid,
            assigned_by: human.uid,
        })
        .await
        .unwrap();
    let captured = kernel
        .ownership_store
        .capture_derived_ownership(creator_uid)
        .await
        .unwrap();
    let receipt = kernel
        .ownership_store
        .assign_derived_principal_for_initialization(child_uid, &captured)
        .await
        .unwrap();
    kernel
        .ownership_store
        .transfer_principal(child_uid, fleets[0].uid, fleets[1].uid, human.uid)
        .await
        .unwrap();
    let before = kernel.ownership_store.load().await.unwrap();

    let view_id = astrid_capsule_types::CapsuleId::new("provider").unwrap();
    let views = vec![kernel.lock_capsule_view(&child, &view_id).await];
    let response = super::rollback::rollback_failed_initialization_with_views(
        &kernel,
        &child,
        &receipt,
        views,
        super::super::handlers::err_internal("injected initialization failure".into()),
    )
    .await;

    assert!(
        format!("{response:?}").contains("reserve initialization rollback"),
        "{response:?}"
    );
    assert!(!kernel.capabilities.is_principal_retiring(&child).await);
    assert_eq!(before, kernel.ownership_store.load().await.unwrap());
    assert!(
        kernel.capsule_view_locks.is_empty(),
        "failed reservation must release its views"
    );
    assert!(
        profile.exists(),
        "the transferred principal must retain its profile"
    );
    assert!(
        kernel
            .identity_store
            .resolve(AGENT_IDENTITY_PLATFORM, child.as_str())
            .await
            .unwrap()
            .is_some()
    );
}

async fn rollback_fleets(
    store: &astrid_storage::ownership::OwnershipStore,
) -> (UserIdentity, Vec<FleetIdentity>) {
    let human = UserIdentity::from_genesis(UserGenesis::from_parts(
        uuid::Uuid::from_u128(11),
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        [0x21; 32],
    ))
    .unwrap();
    store.create_user(human.clone()).await.unwrap();
    let mut fleets = Vec::new();
    for id in [12, 13] {
        let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
            uuid::Uuid::from_u128(id),
            chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
            human.uid,
        ))
        .unwrap();
        store.create_fleet(fleet.clone()).await.unwrap();
        fleets.push(fleet);
    }
    (human, fleets)
}

#[tokio::test]
async fn rollback_fence_waits_for_an_admitted_capsule_constructor() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    let (_dir, kernel, principal, _) = kernel_with_identity("constructing-agent").await;
    let constructor = kernel.capsule_load_lock.lock().await;
    let mut fence = Box::pin(super::rollback::fence_failed_initialization(
        &kernel,
        &principal,
        Vec::new(),
    ));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(fence.as_mut().poll(&mut context), Poll::Pending));
    assert!(!kernel.capabilities.is_principal_retiring(&principal).await);

    drop(constructor);
    fence.await.unwrap();
    assert!(kernel.capabilities.is_principal_retiring(&principal).await);
}

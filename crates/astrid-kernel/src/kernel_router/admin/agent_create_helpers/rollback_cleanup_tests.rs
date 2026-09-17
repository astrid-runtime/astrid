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

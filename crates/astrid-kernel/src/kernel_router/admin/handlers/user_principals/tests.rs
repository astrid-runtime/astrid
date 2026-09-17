use super::*;
use crate::kernel_router::admin::{handlers, test_support};
use astrid_core::profile::PrincipalProfile;
use astrid_core::{FleetGenesis, FleetIdentity, UserGenesis, UserIdentity};
use astrid_events::kernel_api::AdminRequestKind;

async fn create(kernel: &Arc<Kernel>, name: &str) {
    let result = test_support::dispatch_as_operator(
        kernel,
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
    assert!(!matches!(result, AdminResponseBody::Error(_)), "{result:?}");
}

async fn names(kernel: &Arc<Kernel>) -> Vec<String> {
    let result = test_support::dispatch_as_operator(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::UserPrincipalList,
    )
    .await;
    let AdminResponseBody::AgentList(rows) = result else {
        panic!("{result:?}")
    };
    rows.into_iter()
        .map(|row| row.principal.to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_filters_on_server_even_for_admin_and_rechecks_transfer_and_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(dir.path())).await;
    test_support::seed_operator(&kernel).await;
    create(&kernel, "mine").await;
    create(&kernel, "other").await;
    assert_eq!(names(&kernel).await, ["default", "mine", "other"]);
    let caller = kernel
        .principal_directory
        .uid_for(&PrincipalId::default())
        .unwrap();
    let graph = kernel.ownership_store.load().await.unwrap();
    let owner = graph.principal_owner(caller).unwrap();
    let other = kernel
        .principal_directory
        .uid_for(&PrincipalId::new("other").unwrap())
        .unwrap();
    let bob = UserIdentity::from_genesis(UserGenesis::from_parts(
        uuid::Uuid::from_u128(701),
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        [7; 32],
    ))
    .unwrap();
    kernel
        .ownership_store
        .create_user(bob.clone())
        .await
        .unwrap();
    let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        uuid::Uuid::from_u128(702),
        chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
        bob.uid,
    ))
    .unwrap();
    kernel
        .ownership_store
        .create_fleet(fleet.clone())
        .await
        .unwrap();
    // Transfer requires management of both fleets; explicitly grant it for
    // this transfer, then remove it before testing the scoped directory.
    kernel
        .ownership_store
        .set_membership(
            fleet.uid,
            owner.assigned_by,
            astrid_core::FleetRole::Administrator,
            bob.uid,
        )
        .await
        .unwrap();
    kernel
        .ownership_store
        .transfer_principal(other, owner.fleet_uid, fleet.uid, owner.assigned_by)
        .await
        .unwrap();
    kernel
        .ownership_store
        .remove_member(fleet.uid, owner.assigned_by, bob.uid)
        .await
        .unwrap();
    assert_eq!(names(&kernel).await, ["default", "mine"]);
    let no_device = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::UserPrincipalList,
    )
    .await;
    assert!(matches!(no_device, AdminResponseBody::Error(_)));
    kernel
        .ownership_store
        .revoke_user_device(caller, [0xab; 32], owner.assigned_by)
        .await
        .unwrap();
    let revoked = test_support::dispatch_as_operator(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::UserPrincipalList,
    )
    .await;
    assert!(matches!(revoked, AdminResponseBody::Error(_)));
}

async fn admit_unowned(kernel: &Kernel, name: &str) -> PrincipalId {
    let principal = PrincipalId::new(name).unwrap();
    kernel
        .identity_store
        .create_principal(principal.clone(), [9; 32])
        .await
        .unwrap();
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &principal);
    let profile = PrincipalProfile {
        groups: vec![astrid_core::groups::BUILTIN_AGENT.into()],
        ..PrincipalProfile::default()
    };
    profile.save_to_path(&path).unwrap();
    kernel.profile_cache.invalidate(&principal);
    principal
}

fn claim(name: &str) -> AdminRequestKind {
    AdminRequestKind::UserPrincipalClaim {
        principal: PrincipalId::new(name).unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn named_claim_assigns_unowned_principal_without_inferring_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(dir.path())).await;
    test_support::seed_operator(&kernel).await;
    let claimed = admit_unowned(&kernel, "packed-agent").await;
    let leftover = admit_unowned(&kernel, "other-unowned").await;
    let result =
        test_support::dispatch_as_operator(&kernel, &PrincipalId::default(), claim("packed-agent"))
            .await;
    assert!(
        matches!(result, AdminResponseBody::Success(_)),
        "{result:?}"
    );
    assert_eq!(names(&kernel).await, ["default", "packed-agent"]);
    let graph = kernel.ownership_store.load().await.unwrap();
    assert!(
        graph
            .principal_owner(kernel.principal_directory.uid_for(&claimed).unwrap())
            .is_some()
    );
    assert!(
        graph
            .principal_owner(kernel.principal_directory.uid_for(&leftover).unwrap())
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn extra_user_or_fleet_does_not_block_named_claim() {
    let dir = tempfile::tempdir().unwrap();
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(dir.path())).await;
    test_support::seed_operator(&kernel).await;
    let caller = kernel
        .principal_directory
        .uid_for(&PrincipalId::default())
        .unwrap();
    let owner = kernel
        .ownership_store
        .load()
        .await
        .unwrap()
        .principal_owner(caller)
        .unwrap()
        .clone();
    let extra_user = UserIdentity::from_genesis(UserGenesis::from_parts(
        uuid::Uuid::from_u128(801),
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        [8; 32],
    ))
    .unwrap();
    kernel
        .ownership_store
        .create_user(extra_user.clone())
        .await
        .unwrap();
    let extra_fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        uuid::Uuid::from_u128(802),
        chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
        extra_user.uid,
    ))
    .unwrap();
    kernel
        .ownership_store
        .create_fleet(extra_fleet)
        .await
        .unwrap();
    admit_unowned(&kernel, "packed-agent").await;
    let result =
        test_support::dispatch_as_operator(&kernel, &PrincipalId::default(), claim("packed-agent"))
            .await;
    assert!(
        matches!(result, AdminResponseBody::Success(_)),
        "{result:?}"
    );
    let graph = kernel.ownership_store.load().await.unwrap();
    let packed = kernel
        .principal_directory
        .uid_for(&PrincipalId::new("packed-agent").unwrap())
        .unwrap();
    assert_eq!(
        graph.principal_owner(packed).unwrap().fleet_uid,
        owner.fleet_uid
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn named_claim_never_transfers_an_existing_owner() {
    let dir = tempfile::tempdir().unwrap();
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(dir.path())).await;
    test_support::seed_operator(&kernel).await;
    create(&kernel, "owned").await;
    let caller = kernel
        .principal_directory
        .uid_for(&PrincipalId::default())
        .unwrap();
    let graph = kernel.ownership_store.load().await.unwrap();
    let owner = graph.principal_owner(caller).unwrap().clone();
    let target = kernel
        .principal_directory
        .uid_for(&PrincipalId::new("owned").unwrap())
        .unwrap();
    let bob = UserIdentity::from_genesis(UserGenesis::from_parts(
        uuid::Uuid::from_u128(901),
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        [9; 32],
    ))
    .unwrap();
    kernel
        .ownership_store
        .create_user(bob.clone())
        .await
        .unwrap();
    let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        uuid::Uuid::from_u128(902),
        chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
        bob.uid,
    ))
    .unwrap();
    kernel
        .ownership_store
        .create_fleet(fleet.clone())
        .await
        .unwrap();
    kernel
        .ownership_store
        .set_membership(
            fleet.uid,
            owner.assigned_by,
            astrid_core::FleetRole::Administrator,
            bob.uid,
        )
        .await
        .unwrap();
    kernel
        .ownership_store
        .transfer_principal(target, owner.fleet_uid, fleet.uid, owner.assigned_by)
        .await
        .unwrap();
    let result =
        test_support::dispatch_as_operator(&kernel, &PrincipalId::default(), claim("owned")).await;
    assert!(
        matches!(result, AdminResponseBody::Error(ref error) if error.contains("already owned")),
        "{result:?}"
    );
    assert_eq!(
        kernel
            .ownership_store
            .load()
            .await
            .unwrap()
            .principal_owner(target)
            .unwrap()
            .fleet_uid,
        fleet.uid
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn undelegated_caller_cannot_claim_by_key_possession() {
    let dir = tempfile::tempdir().unwrap();
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(dir.path())).await;
    test_support::seed_operator(&kernel).await;
    admit_unowned(&kernel, "packed-agent").await;
    let missing = handlers::dispatch(&kernel, &PrincipalId::default(), claim("packed-agent")).await;
    assert!(
        matches!(missing, AdminResponseBody::Error(ref error) if error.contains("user-delegated device")),
        "{missing:?}"
    );
    let caller = kernel
        .principal_directory
        .uid_for(&PrincipalId::default())
        .unwrap();
    let actor = kernel
        .ownership_store
        .load()
        .await
        .unwrap()
        .principal_owner(caller)
        .unwrap()
        .assigned_by;
    kernel
        .ownership_store
        .revoke_user_device(caller, [0xab; 32], actor)
        .await
        .unwrap();
    let revoked =
        test_support::dispatch_as_operator(&kernel, &PrincipalId::default(), claim("packed-agent"))
            .await;
    assert!(
        matches!(revoked, AdminResponseBody::Error(ref error) if error.contains("current user delegation")),
        "{revoked:?}"
    );
    assert!(
        kernel
            .ownership_store
            .load()
            .await
            .unwrap()
            .principal_owner(
                kernel
                    .principal_directory
                    .uid_for(&PrincipalId::new("packed-agent").unwrap())
                    .unwrap()
            )
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn list_does_not_adopt_unowned_principals() {
    let dir = tempfile::tempdir().unwrap();
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(dir.path())).await;
    test_support::seed_operator(&kernel).await;
    let leftover = admit_unowned(&kernel, "packed-agent").await;
    assert_eq!(names(&kernel).await, ["default"]);
    let graph = kernel.ownership_store.load().await.unwrap();
    assert!(
        graph
            .principal_owner(kernel.principal_directory.uid_for(&leftover).unwrap())
            .is_none()
    );
    assert_eq!(names(&kernel).await, ["default"]);
    assert!(
        kernel
            .ownership_store
            .load()
            .await
            .unwrap()
            .principal_owner(kernel.principal_directory.uid_for(&leftover).unwrap())
            .is_none()
    );
}

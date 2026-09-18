//! Explicit operator setup for stateful admin tests.
//!
//! These tests start below signature verification. The fixture models an
//! authenticated local device, but still exercises the production registered
//! device, capability, delegation and ownership checks. Negative authorization
//! tests must use `handlers::dispatch` or an explicit device instead.

use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};

use crate::Kernel;
use astrid_storage::ownership::CreationDelegation;

pub(crate) async fn seed_operator(kernel: &Kernel) -> CreationDelegation {
    use astrid_core::profile::{DeviceKey, DeviceScope, PrincipalProfile};
    use astrid_core::{FleetGenesis, FleetIdentity, PrincipalOwnership, UserGenesis, UserIdentity};
    let caller = PrincipalId::default();
    let uid = kernel.principal_directory.uid_for(&caller).unwrap();
    let user = UserIdentity::from_genesis(UserGenesis::from_parts(
        uuid::Uuid::from_u128(555),
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        [5; 32],
    ))
    .unwrap();
    let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        uuid::Uuid::from_u128(556),
        chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
        user.uid,
    ))
    .unwrap();
    kernel
        .ownership_store
        .create_user(user.clone())
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
            principal_uid: uid,
            fleet_uid: fleet.uid,
            assigned_by: user.uid,
        })
        .await
        .unwrap();
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &caller);
    let mut profile = PrincipalProfile::load_from_path(&path).unwrap_or_default();
    profile.groups = vec![astrid_core::groups::BUILTIN_ADMIN.into()];
    if profile.auth.device_by_pubkey(&"ab".repeat(32)).is_none() {
        profile
            .auth
            .public_keys
            .push(DeviceKey::new("ab".repeat(32), DeviceScope::Full, None, 1));
    }
    profile.save_to_path(&path).unwrap();
    kernel.profile_cache.invalidate(&caller);
    kernel
        .ownership_store
        .bind_user_device(uid, [0xab; 32], user.uid, user.uid)
        .await
        .unwrap();
    kernel
        .ownership_store
        .capture_creation_delegation(uid, &[0xab; 32])
        .await
        .unwrap()
}

pub(crate) async fn dispatch_as_operator(
    kernel: &Arc<Kernel>,
    caller: &PrincipalId,
    request: AdminRequestKind,
) -> AdminResponseBody {
    assert_eq!(caller, &PrincipalId::default(), "fixture only owns default");
    let profile =
        PrincipalProfile::load_from_path(&PrincipalProfile::path_for(&kernel.astrid_home, caller))
            .expect("seed operator before dispatch");
    let device = profile
        .auth
        .device_by_pubkey(&"ab".repeat(32))
        .expect("operator device must remain registered");
    super::handlers::dispatch_with_device(kernel, caller, Some(&device.key_id), request).await
}

#[tokio::test(flavor = "multi_thread")]
async fn operator_fixture_does_not_bypass_missing_or_revoked_delegation() {
    let dir = tempfile::tempdir().unwrap();
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(dir.path())).await;
    let delegation = seed_operator(&kernel).await;
    let caller = PrincipalId::default();
    let request = |name: &str| AdminRequestKind::AgentCreate {
        name: name.into(),
        groups: Vec::new(),
        grants: Vec::new(),
        inherit_from: None,
        clone_from: None,
        allow_admin_clone: false,
    };
    let missing = super::handlers::dispatch(&kernel, &caller, request("missing-device")).await;
    assert!(
        matches!(missing, AdminResponseBody::Error(ref error) if error.contains("user-delegated device"))
    );
    let allowed = dispatch_as_operator(&kernel, &caller, request("owned-child")).await;
    assert!(
        matches!(allowed, AdminResponseBody::Success(_)),
        "{allowed:?}"
    );
    let uid = delegation.principal();
    let actor = kernel
        .ownership_store
        .load()
        .await
        .unwrap()
        .user_for_device(uid, delegation.public_key())
        .unwrap();
    kernel
        .ownership_store
        .revoke_user_device(uid, *delegation.public_key(), actor)
        .await
        .unwrap();
    let revoked = dispatch_as_operator(&kernel, &caller, request("revoked-child")).await;
    assert!(
        matches!(revoked, AdminResponseBody::Error(ref error) if error.contains("current user delegation"))
    );
    for name in ["missing-device", "revoked-child"] {
        let principal = PrincipalId::new(name).unwrap();
        assert!(kernel.principal_directory.uid_for(&principal).is_err());
        assert!(!PrincipalProfile::path_for(&kernel.astrid_home, &principal).exists());
    }
}

use super::*;
use crate::kernel_router::admin::{handlers, test_support};
use astrid_core::kernel_api::AdminRequestKind;
use astrid_core::profile::{DeviceKey, DeviceScope, PrincipalProfile};

async fn fixture() -> (tempfile::TempDir, Arc<crate::Kernel>, UserUid) {
    let temp = tempfile::tempdir().unwrap();
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(temp.path())).await;
    test_support::seed_operator(&kernel).await;
    let uid = kernel
        .principal_directory
        .uid_for(&PrincipalId::default())
        .unwrap();
    let graph = kernel.ownership_store.load().await.unwrap();
    let user = graph.accountable_user(uid).unwrap();
    // Faithful old wire shape: ownership existed before accountable_users.
    let mut legacy = serde_json::to_value(graph).unwrap();
    legacy.as_object_mut().unwrap().remove("accountable_users");
    kernel
        .kv
        .set(
            astrid_storage::ownership::OWNERSHIP_NAMESPACE,
            "graph-v1",
            serde_json::to_vec(&legacy).unwrap(),
        )
        .await
        .unwrap();
    (temp, kernel, user)
}

fn request(user: UserUid) -> AdminRequestKind {
    AdminRequestKind::QuotaAssignUser {
        principal: PrincipalId::default(),
        user,
    }
}

#[test]
fn resource_assignment_is_global_even_for_self_and_uses_matching_wire_topic() {
    use crate::kernel_router::admin::{
        AuthorityScope, admin_request_method, admin_target_principal,
        required_capability_for_admin_request, resolve_admin_scope,
    };
    let caller = PrincipalId::default();
    let req = request(UserUid::from_bytes([7; 32]));
    assert_eq!(resolve_admin_scope(&req, &caller), AuthorityScope::Global);
    for scope in [AuthorityScope::Self_, AuthorityScope::Global] {
        assert_eq!(
            required_capability_for_admin_request(&req, scope),
            "quota:set"
        );
    }
    assert_eq!(admin_target_principal(&req), Some(&caller));
    assert_eq!(admin_request_method(&req), "admin.quota.assign_user");
}

#[tokio::test(flavor = "multi_thread")]
async fn operator_resolves_legacy_attribution_idempotently_without_transferring() {
    let (_temp, kernel, user) = fixture().await;
    let caller = PrincipalId::default();
    let uid = kernel.principal_directory.uid_for(&caller).unwrap();
    for _ in 0..2 {
        let result = test_support::dispatch_as_operator(&kernel, &caller, request(user)).await;
        assert!(
            matches!(result, AdminResponseBody::Success(_)),
            "{result:?}"
        );
    }
    let assigned = kernel.ownership_store.load().await.unwrap();
    assert_eq!(assigned.accountable_user(uid), Some(user));
    let result =
        test_support::dispatch_as_operator(&kernel, &caller, request(UserUid::from_bytes([9; 32])))
            .await;
    assert!(matches!(result, AdminResponseBody::Error(_)));
    assert_eq!(kernel.ownership_store.load().await.unwrap(), assigned);
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_user_cannot_leave_partial_attribution() {
    let (_temp, kernel, _) = fixture().await;
    let before = kernel.ownership_store.load().await.unwrap();
    let result = test_support::dispatch_as_operator(
        &kernel,
        &PrincipalId::default(),
        request(UserUid::from_bytes([9; 32])),
    )
    .await;
    assert!(matches!(result, AdminResponseBody::Error(_)));
    assert_eq!(kernel.ownership_store.load().await.unwrap(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn self_scoped_admin_device_cannot_assign_its_resource_user() {
    let (_temp, kernel, user) = fixture().await;
    let caller = PrincipalId::default();
    let before = kernel.ownership_store.load().await.unwrap();
    let path = handlers::principal_profile_path(&kernel, &caller);
    let mut profile = PrincipalProfile::load_from_path(&path).unwrap();
    let device = DeviceKey::new(
        "cd".repeat(32),
        DeviceScope::Scoped {
            allow: vec!["self:*".into()],
            deny: Vec::new(),
        },
        None,
        1,
    );
    let key = device.key_id.clone();
    profile.auth.public_keys.push(device);
    profile.save_to_path(&path).unwrap();
    kernel.profile_cache.invalidate(&caller);
    let authorization = authorize_request(&kernel, &caller, Some(&key), "self:quota:set").unwrap();
    assert!(!authorization.capability_check().has("quota:set"));
    let result = handlers::dispatch_authorized(&kernel, &authorization, request(user)).await;
    assert!(matches!(result, AdminResponseBody::Error(_)), "{result:?}");
    assert_eq!(kernel.ownership_store.load().await.unwrap(), before);
}

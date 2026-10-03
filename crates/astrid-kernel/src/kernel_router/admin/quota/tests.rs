use super::*;
use crate::kernel_router::admin::handlers;
use astrid_core::dirs::AstridHome;
use astrid_core::profile::{DeviceKey, DeviceScope};
use astrid_events::kernel_api::AdminRequestKind;

async fn fixture(admin: bool) -> (tempfile::TempDir, Arc<crate::Kernel>, PrincipalId) {
    let dir = tempfile::tempdir().unwrap();
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(dir.path())).await;
    let caller = PrincipalId::default();
    let profile = PrincipalProfile {
        groups: vec![if admin { "admin" } else { "agent" }.into()],
        ..Default::default()
    };
    profile
        .save_to_path(&principal_profile_path(&kernel, &caller))
        .unwrap();
    kernel.profile_cache.invalidate(&caller);
    (dir, kernel, caller)
}

async fn set(
    kernel: &Arc<crate::Kernel>,
    authorization: &AuthorizedRequest,
    quotas: Quotas,
) -> AdminResponseBody {
    handlers::dispatch_authorized(
        kernel,
        authorization,
        AdminRequestKind::QuotaSet {
            principal: authorization.principal.clone(),
            quotas,
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn self_quota_cannot_raise_any_dimension() {
    let (_dir, kernel, caller) = fixture(false).await;
    let authorization = authorize_request(&kernel, &caller, None, "self:quota:set").unwrap();
    let original = authorization.profile.quotas.clone();
    let increases: [fn(&mut Quotas); 7] = [
        |q| q.max_memory_bytes += 1,
        |q| q.max_timeout_secs += 1,
        |q| q.max_ipc_throughput_bytes += 1,
        |q| q.max_background_processes += 1,
        |q| q.max_storage_bytes += 1,
        |q| q.max_cpu_fuel_per_sec += 1,
        |q| q.max_in_flight_calls += 1,
    ];
    for increase in increases {
        let mut requested = original.clone();
        increase(&mut requested);
        let result = set(&kernel, &authorization, requested).await;
        assert!(
            matches!(result, AdminResponseBody::Error(ref error) if error.contains("requires quota:set")),
            "{result:?}"
        );
        let persisted =
            PrincipalProfile::load_from_path(&principal_profile_path(&kernel, &caller)).unwrap();
        assert_eq!(persisted.quotas, original);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_self_authorization_cannot_restore_a_lowered_allocation() {
    let (_dir, kernel, caller) = fixture(false).await;
    let authorization = authorize_request(&kernel, &caller, None, "self:quota:set").unwrap();
    let original = authorization.profile.quotas.clone();
    let mut lower = original.clone();
    lower.max_cpu_fuel_per_sec /= 2;
    assert!(matches!(
        set(&kernel, &authorization, lower.clone()).await,
        AdminResponseBody::Success(_)
    ));
    assert!(matches!(
        set(&kernel, &authorization, original).await,
        AdminResponseBody::Error(_)
    ));
    assert_eq!(kernel.profile_cache.resolve(&caller).unwrap().quotas, lower);
    assert!(matches!(
        set(&kernel, &authorization, lower).await,
        AdminResponseBody::Success(_)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn operator_can_raise_quota_but_self_scoped_device_cannot() {
    let (_dir, kernel, caller) = fixture(true).await;
    let mut profile = (*kernel.profile_cache.resolve(&caller).unwrap()).clone();
    let device = DeviceKey::new(
        "ab".repeat(32),
        DeviceScope::Scoped {
            allow: vec!["self:*".into()],
            deny: Vec::new(),
        },
        None,
        1,
    );
    let key = device.key_id.clone();
    profile.auth.public_keys.push(device);
    profile
        .save_to_path(&principal_profile_path(&kernel, &caller))
        .unwrap();
    kernel.profile_cache.invalidate(&caller);
    let scoped = authorize_request(&kernel, &caller, Some(&key), "self:quota:set").unwrap();
    let mut raised = profile.quotas;
    raised.max_cpu_fuel_per_sec *= 2;
    assert!(matches!(
        set(&kernel, &scoped, raised.clone()).await,
        AdminResponseBody::Error(_)
    ));
    let operator = authorize_request(&kernel, &caller, None, "self:quota:set").unwrap();
    assert!(matches!(
        set(&kernel, &operator, raised.clone()).await,
        AdminResponseBody::Success(_)
    ));
    assert_eq!(
        kernel.profile_cache.resolve(&caller).unwrap().quotas,
        raised
    );
}

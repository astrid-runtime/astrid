//! A degraded exact component set must invalidate its cached projection.

use std::sync::{Arc, atomic::Ordering};

use astrid_capsule::context::ProcessStorageMountBroker as _;
use astrid_core::PrincipalId;

use super::{KernelProcessStorageMountBroker, fleet_shared_kernel};
use crate::storage_mount::{MountOwnerScope, revoke_lease};

struct CachedMount {
    mount: astrid_capsule::context::ProcessStorageMount,
    projection: Arc<super::super::CachedProcessProjection>,
}

async fn successful_fleet_mount(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    broker: &KernelProcessStorageMountBroker,
    test_id: u64,
) -> CachedMount {
    let mount = super::PROCESS_MOUNT_TEST_ID
        .scope(test_id, broker.mount(caller))
        .await
        .expect("full successful process projection");
    let projections = broker.projections.lock().await;
    assert_eq!(projections.len(), 1);
    let projection = Arc::clone(projections.values().next().expect("cached projection"));
    drop(projections);

    assert_eq!(
        projection.component_mount_ids.len(),
        if projection.binding.targets.fleet_shared.is_some() {
            3
        } else {
            2
        }
    );
    assert_eq!(
        projection.refs.load(Ordering::Acquire),
        1,
        "the first successful mount owns one cached reference"
    );
    assert!(
        projection
            .component_mount_ids
            .iter()
            .all(|mount_id| kernel.storage_mounts.contains_key(mount_id))
    );
    CachedMount { mount, projection }
}

async fn assert_replacement_after_unhealthy_hit(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    broker: &KernelProcessStorageMountBroker,
    stale: CachedMount,
    test_id: u64,
) {
    let stale_root = stale.mount.workspace_root.clone();
    let stale_projection = stale.projection;
    let replacement_mount = super::PROCESS_MOUNT_TEST_ID
        .scope(test_id, broker.mount(caller))
        .await
        .expect("unhealthy hit must clean and admit a replacement");
    assert_ne!(
        replacement_mount.workspace_root, stale_root,
        "a replacement must not return the stale provider root"
    );
    assert!(
        stale_projection
            .component_mount_ids
            .iter()
            .all(|mount_id| !kernel.storage_mounts.contains_key(mount_id)),
        "stale exact set must be absent after cleanup"
    );
    assert_eq!(
        stale_projection.refs.load(Ordering::Acquire),
        1,
        "invalidation must not increment the stale projection"
    );

    let projections = broker.projections.lock().await;
    assert_eq!(projections.len(), 1);
    let replacement_projection = projections
        .values()
        .next()
        .expect("replacement cached projection");
    assert!(!Arc::ptr_eq(replacement_projection, &stale_projection));
    assert_eq!(
        replacement_projection.refs.load(Ordering::Acquire),
        1,
        "only the replacement guard owns a new reference"
    );
    assert!(
        replacement_projection
            .component_mount_ids
            .iter()
            .all(|mount_id| kernel.storage_mounts.contains_key(mount_id))
    );
    drop(projections);

    replacement_mount.close_async().await;
    stale.mount.close_async().await;
    assert!(
        kernel.storage_mounts.is_empty(),
        "the replacement must clean its complete new exact set"
    );
    assert!(broker.projections.lock().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_component_invalidates_cached_exact_set() {
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    let stale = successful_fleet_mount(&kernel, &caller, &broker, 501).await;
    let revoked_mount_id = stale.projection.component_mount_ids[1];

    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        revoked_mount_id,
    )
    .await
    .expect("ordinary authorized revocation of one component");
    assert!(!kernel.storage_mounts.contains_key(&revoked_mount_id));

    assert_replacement_after_unhealthy_hit(&kernel, &caller, &broker, stale, 502).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_component_invalidates_cached_exact_set() {
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    let stale = successful_fleet_mount(&kernel, &caller, &broker, 503).await;
    for mount_id in &stale.projection.component_mount_ids {
        kernel
            .storage_mounts
            .get(mount_id)
            .expect("recorded exact component")
            .expires_at_epoch_secs
            .store(0, Ordering::Release);
    }

    assert_replacement_after_unhealthy_hit(&kernel, &caller, &broker, stale, 504).await;
}

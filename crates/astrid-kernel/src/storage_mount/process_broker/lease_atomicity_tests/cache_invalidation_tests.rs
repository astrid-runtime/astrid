//! A degraded exact component set must invalidate its cached projection.

use std::path::Path;
use std::sync::{Arc, atomic::Ordering};

use astrid_capsule::context::ProcessStorageMountBroker as _;
use astrid_core::PrincipalId;

use super::{KernelProcessStorageMountBroker, fleet_shared_kernel};
use crate::storage_mount::process_broker::{
    CachedProcessProjection, ProjectionCleanup, RetainedIssuePaths, arm_retain_validation_gate,
    cleanup_uncommitted_issue_lease_set, invalidate_unhealthy_projection,
    retain_failed_issue_projection,
};
use crate::storage_mount::{MountOwnerScope, issue_lease, revoke_lease};

fn provider_lane_is_ready(test_name: &str) -> bool {
    let binary_available = std::env::current_exe().is_ok_and(|test_binary| {
        test_binary
            .parent()
            .map(|directory| {
                directory.join(format!(
                    "{}{}",
                    super::super::platform_process_provider_name(),
                    std::env::consts::EXE_SUFFIX
                ))
            })
            .is_some_and(|provider| {
                std::fs::symlink_metadata(provider).is_ok_and(|metadata| metadata.is_file())
            })
    });
    let provider_lane_enabled =
        std::env::var("ASTRID_PROCESS_PROVIDER_TESTS").is_ok_and(|value| value == "1");
    if !(binary_available && provider_lane_enabled) {
        println!(
            "skipping {test_name}: coinstalled native process storage provider is unavailable"
        );
        return false;
    }
    true
}

struct CachedMount {
    mount: astrid_capsule::context::ProcessStorageMount,
    projection: Arc<CachedProcessProjection>,
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
async fn fresh_admission_has_exactly_one_guard_reference() {
    if !provider_lane_is_ready("fresh_admission_has_exactly_one_guard_reference") {
        return;
    }
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));

    let first = super::PROCESS_MOUNT_TEST_ID
        .scope(701, broker.mount(&caller))
        .await
        .expect("fresh process projection");
    let mount_root = first
        .workspace_root
        .parent()
        .and_then(Path::parent)
        .expect("fresh UUID mount root")
        .to_path_buf();
    assert!(mount_root.exists(), "fresh admission must start its root");
    let projections = broker.projections.lock().await;
    assert_eq!(projections.len(), 1);
    let projection = Arc::clone(projections.values().next().expect("fresh projection"));
    drop(projections);
    assert_eq!(projection.refs.load(Ordering::Acquire), 1);
    assert_eq!(projection.component_mount_ids.len(), 3);
    assert!(
        projection
            .component_mount_ids
            .iter()
            .all(|mount_id| kernel.storage_mounts.contains_key(mount_id))
    );

    let reused = super::PROCESS_MOUNT_TEST_ID
        .scope(702, broker.mount(&caller))
        .await
        .expect("cached process projection while the first guard is held");
    assert_eq!(reused.workspace_root, first.workspace_root);
    assert_eq!(reused.home_root, first.home_root);
    assert_eq!(projection.refs.load(Ordering::Acquire), 2);
    assert_eq!(broker.projections.lock().await.len(), 1);

    first.close_async().await;
    assert_eq!(projection.refs.load(Ordering::Acquire), 1);
    assert_eq!(broker.projections.lock().await.len(), 1);
    assert!(mount_root.exists(), "the last close must own cleanup");
    assert!(
        projection
            .component_mount_ids
            .iter()
            .all(|mount_id| kernel.storage_mounts.contains_key(mount_id))
    );

    reused.close_async().await;
    assert_eq!(
        projection.refs.load(Ordering::Acquire),
        0,
        "the last close must drain exactly one reference"
    );
    assert!(broker.projections.lock().await.is_empty());
    assert!(
        projection
            .component_mount_ids
            .iter()
            .all(|mount_id| !kernel.storage_mounts.contains_key(mount_id))
    );
    assert!(!mount_root.exists(), "the last close must clean the root");

    let remounted = super::PROCESS_MOUNT_TEST_ID
        .scope(703, broker.mount(&caller))
        .await
        .expect("fresh process projection after the last close");
    let remounted_projections = broker.projections.lock().await;
    assert_eq!(remounted_projections.len(), 1);
    let remounted_projection = Arc::clone(
        remounted_projections
            .values()
            .next()
            .expect("remounted projection"),
    );
    drop(remounted_projections);
    assert!(!Arc::ptr_eq(&projection, &remounted_projection));
    assert_eq!(remounted_projection.refs.load(Ordering::Acquire), 1);
    assert!(
        remounted_projection
            .component_mount_ids
            .iter()
            .all(|mount_id| kernel.storage_mounts.contains_key(mount_id))
    );
    remounted.close_async().await;
    assert_eq!(remounted_projection.refs.load(Ordering::Acquire), 0);
    assert!(kernel.storage_mounts.is_empty());
    assert!(broker.projections.lock().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_component_invalidates_cached_exact_set() {
    if !provider_lane_is_ready("revoked_component_invalidates_cached_exact_set") {
        return;
    }
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
    if !provider_lane_is_ready("expired_component_invalidates_cached_exact_set") {
        return;
    }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_cannot_interleave_validation_and_cached_reference() {
    if !provider_lane_is_ready("revocation_cannot_interleave_validation_and_cached_reference") {
        return;
    }
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    let stale = successful_fleet_mount(&kernel, &caller, &broker, 601).await;
    let owner_mount_id = stale.projection.component_mount_ids[1];
    let owner_state = kernel
        .storage_mounts
        .get(&owner_mount_id)
        .map(|entry| Arc::clone(entry.value()))
        .expect("owner component");

    let gate = arm_retain_validation_gate();
    let mount_broker = broker.clone();
    let mount_caller = caller.clone();
    let mount_task = tokio::spawn(async move {
        super::PROCESS_MOUNT_TEST_ID
            .scope(602, mount_broker.mount(&mount_caller))
            .await
    });
    gate.entered().notified().await;

    let revoke_kernel = Arc::clone(&kernel);
    let revoke_caller = caller.clone();
    let revocation = tokio::spawn(async move {
        revoke_lease(
            &revoke_kernel,
            &revoke_caller,
            MountOwnerScope::CallerOnly,
            owner_mount_id,
        )
        .await
    });
    while !owner_state
        .revoked
        .load(std::sync::atomic::Ordering::Acquire)
    {
        tokio::task::yield_now().await;
    }
    assert!(
        owner_state.wait_listener_closed().await,
        "revocation must drain the component listener while reference admission is paused"
    );
    gate.release().notify_one();

    let replacement_mount = mount_task
        .await
        .expect("mount admission task")
        .expect("validated unhealthy hit must admit a replacement after cleanup");
    revocation
        .await
        .expect("revocation task")
        .expect("authorized revocation");
    assert_ne!(replacement_mount.workspace_root, stale.mount.workspace_root);
    assert_eq!(
        stale
            .projection
            .refs
            .load(std::sync::atomic::Ordering::Acquire),
        1,
        "the stale projection must not gain a reference after revocation"
    );

    replacement_mount.close_async().await;
    stale.mount.close_async().await;
    assert!(kernel.storage_mounts.is_empty());
    assert!(broker.projections.lock().await.is_empty());
}

#[tokio::test]
async fn externally_removed_member_fences_remaining_exact_authority() {
    let fixture = super::exact_fence_fixture().await;
    let removed_mount_id = fixture.shared.mount_id;
    assert!(
        fixture
            .kernel
            .storage_mounts
            .remove(&removed_mount_id)
            .is_some()
    );

    let cleanup: ProjectionCleanup = Arc::new(|| Box::pin(async { true }));
    let projection = Arc::new(CachedProcessProjection {
        binding: fixture.binding.clone(),
        component_mount_ids: vec![
            fixture.branch.mount_id,
            fixture.owner.mount_id,
            removed_mount_id,
        ],
        workspace_mountpoint: fixture.kernel.astrid_home.run_dir(),
        home_mountpoint: fixture.kernel.astrid_home.run_dir(),
        fleet_shared_mountpoint: None,
        refs: std::sync::atomic::AtomicU64::new(1),
        closing: std::sync::atomic::AtomicBool::new(false),
        cleanup_failed: std::sync::atomic::AtomicBool::new(false),
        cleanup,
    });
    let key = super::ProcessProjectionKey {
        binding: fixture.binding.clone(),
        read_write: true,
    };
    let mut projections = std::collections::BTreeMap::new();
    projections.insert(key.clone(), Arc::clone(&projection));

    assert!(
        invalidate_unhealthy_projection(&fixture.kernel, &projection, &mut projections, &key).await
    );
    assert!(projections.is_empty());
    assert_eq!(
        projection.refs.load(std::sync::atomic::Ordering::Acquire),
        1,
        "invalidation must not add a reference to the degraded set"
    );
    assert!(
        fixture
            .states
            .iter()
            .take(2)
            .all(|state| state.is_revoked_for_test()),
        "remaining authorized members must be fenced before replacement"
    );
}

#[tokio::test]
async fn provider_drift_is_unauthorized_for_cleanup_and_reuse() {
    let fixture = super::exact_fence_fixture().await;
    let drifted_lease = issue_lease(
        &fixture.kernel,
        &crate::storage_mount::test_mount_admission(
            &fixture.kernel,
            &fixture.caller,
            crate::storage_mount::MountOwnerScope::CrossOwnerWrite,
        ),
        astrid_core::storage_provider::StorageProviderViewV1::Principal(fixture.caller.clone()),
        fixture.binding.targets.owner_home.durable_target(),
        astrid_core::storage_provider::StorageProviderAccessV1::ReadWrite,
        "drifted-process-provider".to_owned(),
        fixture.kernel.astrid_home.run_dir().join("drifted-owner"),
    )
    .await
    .expect("issue drifted owner authority");

    let cleanup: ProjectionCleanup = Arc::new(|| Box::pin(async { true }));
    let projection = Arc::new(CachedProcessProjection {
        binding: fixture.binding.clone(),
        component_mount_ids: vec![
            fixture.branch.mount_id,
            drifted_lease.mount_id,
            fixture.shared.mount_id,
        ],
        workspace_mountpoint: fixture.kernel.astrid_home.run_dir(),
        home_mountpoint: fixture.kernel.astrid_home.run_dir(),
        fleet_shared_mountpoint: None,
        refs: std::sync::atomic::AtomicU64::new(1),
        closing: std::sync::atomic::AtomicBool::new(false),
        cleanup_failed: std::sync::atomic::AtomicBool::new(false),
        cleanup,
    });
    let key = super::ProcessProjectionKey {
        binding: fixture.binding.clone(),
        read_write: true,
    };
    let mut projections = std::collections::BTreeMap::new();
    projections.insert(key.clone(), Arc::clone(&projection));

    assert!(
        !invalidate_unhealthy_projection(&fixture.kernel, &projection, &mut projections, &key)
            .await,
        "provider drift must remain retained for administrative cleanup"
    );
    assert!(
        projection
            .cleanup_failed
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert_eq!(projections.len(), 1);
    for state in &fixture.states {
        assert!(!state.is_revoked_for_test());
    }
    assert!(
        !fixture
            .kernel
            .storage_mounts
            .get(&drifted_lease.mount_id)
            .expect("drifted authority remains")
            .is_revoked_for_test()
    );
}

#[tokio::test]
async fn externally_removed_partial_issue_member_is_already_clean() {
    let fixture = super::exact_fence_fixture().await;
    let owner_mount_id = fixture.owner.mount_id;
    assert!(
        fixture
            .kernel
            .storage_mounts
            .remove(&owner_mount_id)
            .is_some()
    );
    let targets = &fixture.binding.targets;
    let branch = super::ProjectionLeaseTarget {
        mount_id: fixture.branch.mount_id,
        target: targets.workspace.clone(),
    };
    let owner = super::ProjectionLeaseTarget {
        mount_id: owner_mount_id,
        target: targets.owner_home.clone(),
    };

    assert!(
        cleanup_uncommitted_issue_lease_set(
            &fixture.kernel,
            &fixture.binding,
            &branch,
            Some(&owner)
        )
        .await
    );
    assert!(!fixture.kernel.storage_mounts.contains_key(&branch.mount_id));
}

#[tokio::test]
async fn mismatched_partial_issue_member_blocks_exact_cleanup() {
    let fixture = super::exact_fence_fixture().await;
    let drifted_lease = issue_lease(
        &fixture.kernel,
        &crate::storage_mount::test_mount_admission(
            &fixture.kernel,
            &fixture.caller,
            crate::storage_mount::MountOwnerScope::CrossOwnerWrite,
        ),
        astrid_core::storage_provider::StorageProviderViewV1::Principal(fixture.caller.clone()),
        fixture.binding.targets.owner_home.durable_target(),
        astrid_core::storage_provider::StorageProviderAccessV1::ReadWrite,
        "drifted-process-provider".to_owned(),
        fixture.kernel.astrid_home.run_dir().join("drifted-owner"),
    )
    .await
    .expect("issue mismatched owner authority");
    let targets = &fixture.binding.targets;
    let branch = super::ProjectionLeaseTarget {
        mount_id: fixture.branch.mount_id,
        target: targets.workspace.clone(),
    };
    let owner = super::ProjectionLeaseTarget {
        mount_id: drifted_lease.mount_id,
        target: targets.owner_home.clone(),
    };

    assert!(
        !cleanup_uncommitted_issue_lease_set(
            &fixture.kernel,
            &fixture.binding,
            &branch,
            Some(&owner)
        )
        .await
    );
    assert!(fixture.kernel.storage_mounts.contains_key(&branch.mount_id));
    assert!(
        fixture
            .kernel
            .storage_mounts
            .contains_key(&drifted_lease.mount_id)
    );
}

#[tokio::test]
async fn failed_issue_cleanup_retains_root_and_retry_authority() {
    let fixture = super::exact_fence_fixture().await;
    let root = tempfile::tempdir().expect("issue cleanup scratch root");
    let mount_root = root.path().join("process-mount");
    std::fs::create_dir_all(&mount_root).expect("create retained issue root");
    let targets = &fixture.binding.targets;
    let branch = super::ProjectionLeaseTarget {
        mount_id: fixture.branch.mount_id,
        target: targets.workspace.clone(),
    };
    let owner = super::ProjectionLeaseTarget {
        mount_id: fixture.owner.mount_id,
        target: targets.owner_home.clone(),
    };
    let key = super::ProcessProjectionKey {
        binding: fixture.binding.clone(),
        read_write: true,
    };
    let mut projections = std::collections::BTreeMap::new();
    retain_failed_issue_projection(
        &mut projections,
        &key,
        &fixture.kernel,
        vec![branch.mount_id, owner.mount_id],
        RetainedIssuePaths {
            workspace: mount_root.join("workspace"),
            home: mount_root.join("owner"),
            fleet_shared: None,
        },
        branch.clone(),
        Some(owner),
    );
    let projection = Arc::clone(projections.get(&key).expect("retained issue blocker"));
    let branch_state = Arc::clone(&fixture.states[0]);
    crate::storage_mount::inject_cleanup_fault_for_test(
        &branch_state,
        crate::storage_mount::MountCleanupStage::Callback,
    );

    assert!(
        !super::retry_failed_projection(&projection, &mut projections, &key).await,
        "an injected cleanup failure must keep the bounded retry blocked"
    );
    assert_eq!(projections.len(), 1);
    assert!(
        projection
            .cleanup_failed
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert!(fixture.kernel.storage_mounts.contains_key(&branch.mount_id));
    assert!(
        fixture
            .kernel
            .storage_mounts
            .contains_key(&fixture.owner.mount_id)
    );
    assert!(
        mount_root.exists(),
        "failed cleanup must retain the UUID root"
    );

    for state in &fixture.states {
        crate::storage_mount::clear_cleanup_fault_for_test(state);
    }
    assert!(super::retry_failed_projection(&projection, &mut projections, &key).await);
    assert!(!fixture.kernel.storage_mounts.contains_key(&branch.mount_id));
    assert!(
        !fixture
            .kernel
            .storage_mounts
            .contains_key(&fixture.owner.mount_id)
    );
    assert!(
        !mount_root.exists(),
        "successful retry must remove the root"
    );
}

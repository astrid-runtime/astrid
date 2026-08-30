//! Deterministic proof that liveness publication shares the retain fence.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::storage_provider::{StorageProviderAccessV1, StorageProviderViewV1};
use astrid_storage::StateOwner;

use super::{
    CachedProcessProjection, ProcessProjectionBinding, ProcessProjectionTargetSet,
    ProjectionCleanup, ProjectionGeneration, projection_leases_are_live,
};
use crate::storage_mount::{MountOwnerScope, issue_lease, test_mount_admission};

struct LinearizationFixture {
    temporary: tempfile::TempDir,
    kernel: Arc<crate::Kernel>,
    projection: Arc<CachedProcessProjection>,
}

#[tokio::test]
async fn revocation_and_expiry_are_visible_inside_the_mutation_fence() {
    let fixture = linearization_fixture().await;
    let retain_fence = fixture.kernel.storage_mount_mutations.lock().await;
    let owner_state = fixture
        .kernel
        .storage_mounts
        .get(&fixture.projection.component_mount_ids[1])
        .map(|entry| Arc::clone(entry.value()))
        .expect("owner member");

    owner_state.revoked.store(true, Ordering::Release);
    assert!(
        !projection_leases_are_live(&fixture.kernel, &fixture.projection),
        "revocation must be visible before the final reference decision"
    );
    owner_state.revoked.store(false, Ordering::Release);

    for mount_id in &fixture.projection.component_mount_ids {
        fixture
            .kernel
            .storage_mounts
            .get(mount_id)
            .expect("mapped member")
            .expires_at_epoch_secs
            .store(0, Ordering::Release);
    }
    assert!(
        !projection_leases_are_live(&fixture.kernel, &fixture.projection),
        "expiry must be visible before the final reference decision"
    );
    assert_eq!(fixture.projection.refs.load(Ordering::Acquire), 0);
    drop(retain_fence);
    assert!(
        fixture.kernel.storage_mount_mutations.try_lock().is_ok(),
        "retain validation and reference acquisition must use the same kernel fence"
    );
    assert!(fixture.temporary.path().is_dir());
}

async fn linearization_fixture() -> LinearizationFixture {
    let temporary = tempfile::tempdir().expect("linearization scratch root");
    let home = AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = crate::test_kernel_with_home(home).await;
    let caller = PrincipalId::default();
    let actor = kernel
        .principal_directory
        .uid_for(&caller)
        .expect("test caller UID");
    let workspace_binding = kernel
        .workspace_branches
        .as_ref()
        .expect("workspace branch service")
        .bind(&caller)
        .await
        .expect("bind test caller workspace");
    let owner = workspace_binding.owner;
    let StateOwner::Fleet(fleet_uid) = owner else {
        panic!("the test first owner must be fleet assigned");
    };
    let binding = ProcessProjectionBinding::new(
        owner,
        actor,
        ProjectionGeneration::capture().expect("test projection generation"),
        ProcessProjectionTargetSet::branch(owner, actor, workspace_binding.branch, Some(fleet_uid))
            .expect("valid target set"),
    )
    .expect("valid projection binding");
    let admission = test_mount_admission(&kernel, &caller, MountOwnerScope::CrossOwnerWrite);
    let provider = "linearization-test-provider".to_owned();
    let members = [
        (
            binding.targets.workspace.durable_target(),
            StorageProviderViewV1::Fleet(fleet_uid),
            temporary.path().join("workspace"),
        ),
        (
            binding.targets.owner_home.durable_target(),
            StorageProviderViewV1::Principal(caller.clone()),
            temporary.path().join("owner-home"),
        ),
        (
            binding
                .targets
                .fleet_shared
                .as_ref()
                .expect("Fleet shared target")
                .durable_target(),
            StorageProviderViewV1::Fleet(fleet_uid),
            temporary.path().join("fleet-shared"),
        ),
    ];
    let mut component_mount_ids = Vec::new();
    for (durable_target, view, mountpoint) in members {
        let lease = issue_lease(
            &kernel,
            &admission,
            view,
            durable_target,
            StorageProviderAccessV1::ReadWrite,
            provider.clone(),
            mountpoint,
        )
        .await
        .expect("issue exact projection member");
        component_mount_ids.push(lease.mount_id);
    }
    let projection = Arc::new(CachedProcessProjection {
        binding: binding.clone(),
        component_mount_ids,
        workspace_mountpoint: temporary.path().join("workspace"),
        home_mountpoint: temporary.path().join("owner-home"),
        fleet_shared_mountpoint: Some(temporary.path().join("fleet-shared")),
        refs: std::sync::atomic::AtomicU64::new(0),
        closing: std::sync::atomic::AtomicBool::new(false),
        cleanup_failed: std::sync::atomic::AtomicBool::new(false),
        cleanup: projection_cleanup(),
    });
    LinearizationFixture {
        temporary,
        kernel,
        projection,
    }
}

fn projection_cleanup() -> ProjectionCleanup {
    Arc::new(|| Box::pin(async { true }))
}

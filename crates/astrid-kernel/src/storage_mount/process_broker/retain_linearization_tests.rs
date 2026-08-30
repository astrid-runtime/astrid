//! Deterministic final-interval proof for cached projection retention.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::storage_provider::{StorageProviderAccessV1, StorageProviderViewV1};
use astrid_storage::StateOwner;

use super::{
    CachedProcessProjection, ProcessProjectionBinding, ProcessProjectionTargetSet,
    ProjectionCleanup, ProjectionGeneration, arm_retain_validation_gate,
    platform_process_provider_name, projection_leases_are_live, retain_locked_projection,
};
use crate::storage_mount::expire_lease_for_test;
use crate::storage_mount::{MountOwnerScope, issue_lease, test_mount_admission};

struct LinearizationFixture {
    #[allow(dead_code)]
    temporary: tempfile::TempDir,
    kernel: Arc<crate::Kernel>,
    projection: Arc<CachedProcessProjection>,
    key: super::ProcessProjectionKey,
    caller: PrincipalId,
}

#[tokio::test]
async fn revocation_and_expiry_are_seen_before_retention() {
    revocation_published_under_the_fence().await;
    expiry_published_under_the_fence().await;
}

async fn revocation_published_under_the_fence() {
    let fixture = linearization_fixture().await;
    assert!(
        projection_leases_are_live(&fixture.kernel, &fixture.projection),
        "the exact platform-provider set must start live"
    );
    let gate = arm_retain_validation_gate();
    let retain_kernel = Arc::clone(&fixture.kernel);
    let retain_projection = Arc::clone(&fixture.projection);
    let retain_cache = Arc::new(tokio::sync::Mutex::new(std::collections::BTreeMap::new()));
    let retain_key = fixture.key.clone();
    let retain = tokio::spawn(async move {
        retain_locked_projection(&retain_kernel, retain_projection, retain_cache, retain_key).await
    });
    gate.entered().notified().await;

    fixture
        .kernel
        .storage_mounts
        .get(&fixture.projection.component_mount_ids[1])
        .expect("owner member")
        .revoked
        .store(true, Ordering::Release);
    gate.release().notify_one();
    let Err(error) = tokio::time::timeout(std::time::Duration::from_secs(5), retain)
        .await
        .expect("retain linearization must not deadlock")
        .expect("retain task joins")
    else {
        panic!("post-publication validation must refuse a reference");
    };
    assert!(
        error.contains("became unhealthy"),
        "unexpected error: {error}"
    );
    assert_eq!(fixture.projection.refs.load(Ordering::Acquire), 0);

    for mount_id in &fixture.projection.component_mount_ids {
        let cleanup = async {
            crate::storage_mount::revoke_lease(
                &fixture.kernel,
                &fixture.caller,
                MountOwnerScope::CrossOwnerWrite,
                *mount_id,
            )
            .await
            .map_err(|error| std::io::Error::other(format!("cleanup revoke failed: {error}")))
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), cleanup)
            .await
            .expect("cleanup revoke must not deadlock")
            .expect("clean the deterministic fixture");
    }
}

async fn expiry_published_under_the_fence() {
    let fixture = linearization_fixture().await;
    assert!(
        projection_leases_are_live(&fixture.kernel, &fixture.projection),
        "the exact platform-provider set must start live"
    );
    let gate = arm_retain_validation_gate();
    let retain_kernel = Arc::clone(&fixture.kernel);
    let retain_projection = Arc::clone(&fixture.projection);
    let retain_cache = Arc::new(tokio::sync::Mutex::new(std::collections::BTreeMap::new()));
    let retain_key = fixture.key.clone();
    let retain = tokio::spawn(async move {
        retain_locked_projection(&retain_kernel, retain_projection, retain_cache, retain_key).await
    });
    gate.entered().notified().await;

    for mount_id in &fixture.projection.component_mount_ids {
        let state = fixture
            .kernel
            .storage_mounts
            .get(mount_id)
            .expect("mapped member");
        expire_lease_for_test(state.value());
    }
    gate.release().notify_one();
    let Err(error) = tokio::time::timeout(std::time::Duration::from_secs(5), retain)
        .await
        .expect("retain linearization must not deadlock")
        .expect("retain task joins")
    else {
        panic!("post-publication validation must refuse a reference");
    };
    assert!(
        error.contains("became unhealthy"),
        "unexpected error: {error}"
    );
    assert_eq!(fixture.projection.refs.load(Ordering::Acquire), 0);

    for mount_id in &fixture.projection.component_mount_ids {
        let cleanup = async {
            crate::storage_mount::revoke_lease(
                &fixture.kernel,
                &fixture.caller,
                MountOwnerScope::CrossOwnerWrite,
                *mount_id,
            )
            .await
            .map_err(|error| std::io::Error::other(format!("cleanup revoke failed: {error}")))
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), cleanup)
            .await
            .expect("cleanup revoke must not deadlock")
            .expect("clean the deterministic fixture");
    }
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
    let key = super::ProcessProjectionKey {
        binding: binding.clone(),
        read_write: true,
    };
    let admission = test_mount_admission(&kernel, &caller, MountOwnerScope::CrossOwnerWrite);
    let provider = platform_process_provider_name().to_owned();
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
        .expect("issue exact platform-provider member");
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
        key,
        caller,
    }
}

fn projection_cleanup() -> ProjectionCleanup {
    Arc::new(|| Box::pin(async { true }))
}

//! Projection lease-set cleanup regressions.

use std::path::Path;
use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::storage_filesystem::StorageFilesystemTargetV1;
use astrid_core::storage_provider::{
    StorageMountId, StorageProviderAccessV1, StorageProviderViewV1,
};

use super::{
    ProcessProjectionBinding, ProcessProjectionTarget, ProcessProjectionTargetSet,
    ProjectionGeneration, ProjectionLeaseTarget, revoke_projection_leases,
};
use crate::storage_mount::{
    MountCleanupStage, MountOwnerScope, clear_cleanup_fault_for_test,
    inject_cleanup_fault_for_test, issue_lease, test_mount_admission,
};

fn projection_binding(kernel: &crate::Kernel, caller: &PrincipalId) -> ProcessProjectionBinding {
    let uid = kernel
        .principal_directory
        .uid_for(caller)
        .expect("test caller storage identity");
    let owner = astrid_storage::StateOwner::Principal(uid);
    ProcessProjectionBinding::new(
        owner,
        uid,
        ProjectionGeneration::capture().expect("test projection generation"),
        ProcessProjectionTargetSet::branch(
            owner,
            uid,
            astrid_core::WorkspaceUid::from_bytes([0xC1; 16]),
            None,
        )
        .expect("valid target set"),
    )
    .expect("valid projection binding")
}

async fn issue_home_lease(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    owner_scope: MountOwnerScope,
    mountpoint: std::path::PathBuf,
) -> astrid_core::storage_filesystem::StorageMountLeaseV1 {
    issue_lease(
        kernel,
        &test_mount_admission(kernel, caller, owner_scope),
        StorageProviderViewV1::Principal(caller.clone()),
        StorageFilesystemTargetV1::OwnerSubtree {
            prefix: "home".to_owned(),
        },
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        mountpoint,
    )
    .await
    .expect("issue projection lease")
}

fn mapped(kernel: &crate::Kernel, mount_id: StorageMountId) -> bool {
    kernel.storage_mounts.contains_key(&mount_id)
}

fn callback_endpoint_present(path: &Path) -> bool {
    astrid_core::local_transport::endpoint_is_present(path).expect("callback endpoint state")
}

fn home_target(
    mount_id: StorageMountId,
    target: &ProcessProjectionTarget,
) -> ProjectionLeaseTarget {
    ProjectionLeaseTarget {
        mount_id,
        target: target.clone(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn projection_cleanup_revokes_every_lease_when_branch_cleanup_fails() {
    for fault in [
        MountCleanupStage::Callback,
        MountCleanupStage::Manifest,
        MountCleanupStage::Directory,
    ] {
        projection_cleanup_revokes_every_lease_on_fault(fault).await;
    }
}

async fn projection_cleanup_revokes_every_lease_on_fault(fault: MountCleanupStage) {
    let temporary = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = PrincipalId::default();
    let binding = projection_binding(&kernel, &caller);
    let branch = issue_home_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        temporary.path().join("branch-mount"),
    )
    .await;
    let owner = issue_home_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        temporary.path().join("owner-mount"),
    )
    .await;
    let shared = issue_home_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        temporary.path().join("shared-mount"),
    )
    .await;
    let branch_state = Arc::clone(kernel.storage_mounts.get(&branch.mount_id).unwrap().value());
    let owner_state = Arc::clone(kernel.storage_mounts.get(&owner.mount_id).unwrap().value());
    let shared_state = Arc::clone(kernel.storage_mounts.get(&shared.mount_id).unwrap().value());
    inject_cleanup_fault_for_test(&branch_state, fault);

    let branch_target = home_target(branch.mount_id, &binding.targets.owner_home);
    let owner_target = home_target(owner.mount_id, &binding.targets.owner_home);
    let shared_target = home_target(shared.mount_id, &binding.targets.owner_home);
    assert!(
        !revoke_projection_leases(
            &kernel,
            &binding,
            &branch_target,
            &owner_target,
            Some(&shared_target),
        )
        .await
    );
    assert!(mapped(&kernel, branch.mount_id));
    assert!(branch_state.is_revoked_for_test());
    assert!(owner_state.is_revoked_for_test());
    assert!(shared_state.is_revoked_for_test());
    match fault {
        MountCleanupStage::Callback => {
            assert_eq!(callback_endpoint_present(&branch.callback_path), cfg!(unix));
        },
        MountCleanupStage::Manifest => {
            assert!(!callback_endpoint_present(&branch.callback_path));
            assert!(branch.resource_path.join("lease.json").exists());
        },
        MountCleanupStage::Directory => {
            assert!(!callback_endpoint_present(&branch.callback_path));
            assert!(branch.resource_path.exists());
        },
    }
    assert!(!mapped(&kernel, owner.mount_id));
    assert!(!mapped(&kernel, shared.mount_id));
    assert!(!callback_endpoint_present(&owner.callback_path));
    assert!(!callback_endpoint_present(&shared.callback_path));

    clear_cleanup_fault_for_test(&branch_state);
    assert!(
        revoke_projection_leases(
            &kernel,
            &binding,
            &branch_target,
            &owner_target,
            Some(&shared_target),
        )
        .await
    );
    assert!(!mapped(&kernel, branch.mount_id));
    assert!(!callback_endpoint_present(&branch.callback_path));
    assert!(!branch.resource_path.exists());
}

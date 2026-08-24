//! Projection lease-set cleanup regressions.

use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::storage_filesystem::StorageFilesystemTargetV1;
use astrid_core::storage_provider::{
    StorageMountId, StorageProviderAccessV1, StorageProviderViewV1,
};

use super::revoke_projection_leases;
use crate::storage_mount::{
    MountCleanupStage, clear_cleanup_fault_for_test, inject_cleanup_fault_for_test, issue_lease,
};

async fn issue_named_lease(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    view: StorageProviderViewV1,
    allow_cross_owner: bool,
    mountpoint: std::path::PathBuf,
) -> astrid_core::storage_filesystem::StorageMountLeaseV1 {
    issue_lease(
        kernel,
        caller.clone(),
        allow_cross_owner,
        view,
        StorageFilesystemTargetV1::OwnerRoot,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn projection_cleanup_revokes_every_lease_when_branch_cleanup_fails() {
    let temporary = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = PrincipalId::default();
    let branch = issue_named_lease(
        &kernel,
        &caller,
        StorageProviderViewV1::Principal(caller.clone()),
        false,
        temporary.path().join("branch-mount"),
    )
    .await;
    let owner = issue_named_lease(
        &kernel,
        &caller,
        StorageProviderViewV1::Principal(caller.clone()),
        false,
        temporary.path().join("owner-mount"),
    )
    .await;
    let shared = issue_named_lease(
        &kernel,
        &caller,
        StorageProviderViewV1::Admin,
        true,
        temporary.path().join("shared-mount"),
    )
    .await;
    let branch_state = Arc::clone(kernel.storage_mounts.get(&branch.mount_id).unwrap().value());
    let owner_state = Arc::clone(kernel.storage_mounts.get(&owner.mount_id).unwrap().value());
    let shared_state = Arc::clone(kernel.storage_mounts.get(&shared.mount_id).unwrap().value());
    inject_cleanup_fault_for_test(&branch_state, MountCleanupStage::Callback);

    assert!(
        !revoke_projection_leases(
            &kernel,
            &caller,
            branch.mount_id,
            owner.mount_id,
            Some(shared.mount_id),
        )
        .await
    );
    assert!(mapped(&kernel, branch.mount_id));
    assert!(branch_state.is_revoked_for_test());
    assert!(owner_state.is_revoked_for_test());
    assert!(shared_state.is_revoked_for_test());
    assert!(branch.callback_path.exists());
    assert!(!mapped(&kernel, owner.mount_id));
    assert!(!mapped(&kernel, shared.mount_id));
    assert!(!owner.callback_path.exists());
    assert!(!shared.callback_path.exists());

    clear_cleanup_fault_for_test(&branch_state);
    assert!(
        revoke_projection_leases(
            &kernel,
            &caller,
            branch.mount_id,
            owner.mount_id,
            Some(shared.mount_id),
        )
        .await
    );
    assert!(!mapped(&kernel, branch.mount_id));
    assert!(!branch.callback_path.exists());
    assert!(!branch.resource_path.exists());
}

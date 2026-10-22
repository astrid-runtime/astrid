//! Callback fixtures must preserve real lease admission and cleanup.

use astrid_core::storage_filesystem::{StorageFilesystemTargetV1, StorageMountLeaseV1};
use astrid_core::storage_provider::{StorageProviderAccessV1, StorageProviderViewV1};
use astrid_core::{PrincipalId, dirs::AstridHome};
use std::sync::Arc;

async fn kernel() -> (tempfile::TempDir, Arc<crate::Kernel>) {
    let temporary = tempfile::tempdir().expect("fixture home");
    let kernel =
        crate::test_kernel_with_home(AstridHome::from_path(temporary.path().join("home"))).await;
    (temporary, kernel)
}

async fn issue(kernel: &Arc<crate::Kernel>) -> Result<StorageMountLeaseV1, String> {
    let caller = PrincipalId::default();
    super::super::issue_lease(
        kernel,
        &super::super::test_mount_admission(
            kernel,
            &caller,
            super::super::MountOwnerScope::CallerOnly,
        ),
        StorageProviderViewV1::Principal(caller),
        StorageFilesystemTargetV1::OwnerSubtree {
            prefix: "home".to_owned(),
        },
        StorageProviderAccessV1::ReadWrite,
        "astrid-storage-provider-fskit".to_owned(),
        kernel.astrid_home.run_dir().join("fixture-mount"),
    )
    .await
}

#[tokio::test]
async fn unavailable_callback_dependency_refuses_before_lease_publication() {
    let (_temporary, kernel) = kernel().await;
    assert!(
        kernel
            .storage_mount_callback_test_resolver
            .resolve(astrid_core::storage_provider::StorageMountId::new())
            .is_none(),
        "test kernels do not silently override production lookup"
    );
    kernel
        .storage_mount_callback_test_resolver
        .refuse_for_test();
    let error = issue(&kernel)
        .await
        .expect_err("missing callback dependency must refuse");
    assert!(error.contains("FSKIT_EXTENSION_UNAVAILABLE"));
    assert!(kernel.storage_mounts.is_empty());
}

#[tokio::test]
async fn private_callback_dependency_is_instance_local_and_revokes_real_socket() {
    let (_temporary, kernel) = kernel().await;
    let (_other_temporary, other) = self::kernel().await;
    kernel
        .storage_mount_callback_test_resolver
        .use_private_callbacks();
    assert!(
        other
            .storage_mount_callback_test_resolver
            .resolve(astrid_core::storage_provider::StorageMountId::new())
            .is_none()
    );
    let lease = issue(&kernel).await.expect("real callback lease");
    let callback = lease.callback_path.clone();
    assert_eq!(
        callback,
        kernel
            .storage_mount_callback_test_resolver
            .resolve(lease.mount_id)
            .unwrap()
            .unwrap(),
        "lease must use the explicit instance callback dependency"
    );
    assert!(astrid_core::local_transport::endpoint_is_present(&callback).unwrap());
    assert_eq!(kernel.storage_mounts.len(), 1);
    super::super::revoke_lease(
        &kernel,
        &PrincipalId::default(),
        super::super::MountOwnerScope::CallerOnly,
        lease.mount_id,
    )
    .await
    .expect("real callback revoke");
    assert!(kernel.storage_mounts.is_empty());
    assert!(!astrid_core::local_transport::endpoint_is_present(&callback).unwrap());
    assert!(!lease.resource_path.exists());
}

#[test]
fn native_provider_lane_keeps_registered_container_dependency() {
    let resolver = super::test_support::CallbackTestResolver::default();
    let mount_id = astrid_core::storage_provider::StorageMountId::new();
    resolver.use_callbacks_for_controlled_provider(true);
    assert!(resolver.resolve(mount_id).is_none());
    resolver.use_callbacks_for_controlled_provider(false);
    assert!(resolver.resolve(mount_id).unwrap().is_ok());
}

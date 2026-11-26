//! Exercise process-local lease authority across an abrupt process exit.
use super::*;

const CHILD_HOME: &str = "ASTRID_MOUNT_RESTART_TEST_HOME";
const ISSUED: i32 = 75;

async fn issue(kernel: &Arc<Kernel>, root: &Path) -> StorageMountLeaseV1 {
    let principal = PrincipalId::default();
    issue_lease(
        kernel,
        principal.clone(),
        false,
        StorageProviderViewV1::Principal(principal),
        StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadOnly,
        "test-provider".to_owned(),
        root.join("mount"),
    )
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "internal subprocess for the mount restart regression"]
async fn exit_with_a_published_mount() {
    let root = PathBuf::from(std::env::var_os(CHILD_HOME).unwrap());
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(&root)).await;
    let lease = issue(&kernel, &root).await;
    assert!(matches!(
        callback(
            &lease,
            &lease.lease_token,
            StorageFilesystemOperationV1::Sync
        )
        .await,
        StorageFilesystemOutcomeV1::Success(_)
    ));
    std::fs::write(root.join("issued-id"), lease.mount_id.to_string()).unwrap();
    std::process::exit(ISSUED);
}

#[tokio::test]
async fn reopening_the_same_home_requires_a_new_mount_credential() {
    let root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "storage_mount::tests::restart_tests::exit_with_a_published_mount",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_HOME, root.path())
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(ISSUED),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let id = std::fs::read_to_string(root.path().join("issued-id")).unwrap();
    let id: StorageMountId = id.parse().unwrap();
    let resource = private_mount_resource_path(id).unwrap();
    let old: StorageMountLeaseV1 =
        serde_json::from_slice(&std::fs::read(resource.join(LEASE_MANIFEST_NAME)).unwrap())
            .unwrap();
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(root.path())).await;
    assert!(lease_status(&kernel, &PrincipalId::default(), false, old.mount_id).is_err());
    assert!(
        astrid_core::local_transport::connect(&old.callback_path)
            .await
            .is_err()
    );
    let fresh = issue(&kernel, root.path()).await;
    assert_ne!(fresh.mount_id, old.mount_id);
    assert!(
        matches!(callback(&fresh, &old.lease_token, StorageFilesystemOperationV1::Sync).await,
        StorageFilesystemOutcomeV1::Failure(ref error) if error.code == "unauthorized")
    );
    assert!(matches!(
        callback(
            &fresh,
            &fresh.lease_token,
            StorageFilesystemOperationV1::Sync
        )
        .await,
        StorageFilesystemOutcomeV1::Success(_)
    ));
    revoke_lease(&kernel, &PrincipalId::default(), false, fresh.mount_id)
        .await
        .unwrap();
    cleanup_resource(&old.resource_path, &old.callback_path);
}

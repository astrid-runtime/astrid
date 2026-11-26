//! Check mount retirement through the same admin handlers used by the daemon.
use super::*;
use astrid_core::storage_filesystem::{StorageFilesystemTargetV1, StorageMountLeaseV1};
use astrid_core::storage_provider::{StorageProviderAccessV1, StorageProviderViewV1};

async fn issue(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    mountpoint: &std::path::Path,
) -> Result<StorageMountLeaseV1, String> {
    crate::storage_mount::issue_lease(
        kernel,
        principal.clone(),
        false,
        StorageProviderViewV1::Principal(principal.clone()),
        StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        mountpoint.to_owned(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabling_and_deleting_a_requester_permanently_close_its_old_leases() {
    let (dir, kernel) = fixture().await;
    let operator = PrincipalId::default();
    let caller = pid("mount-user");
    assert_success(
        &super::super::test_support::dispatch_as_operator(
            &kernel,
            &operator,
            AdminRequestKind::AgentCreate {
                name: caller.to_string(),
                groups: vec![],
                grants: vec![],
                inherit_from: None,
                clone_from: None,
                allow_admin_clone: false,
            },
        )
        .await,
    );
    let mountpoint = dir.path().join("mount");
    let first = issue(&kernel, &caller, &mountpoint).await.unwrap();
    let independent = issue(&kernel, &operator, &mountpoint).await.unwrap();
    let (prepared, resume) = kernel.pending_mount_issues.hold_next_publication();
    let late_issue = {
        let kernel = Arc::clone(&kernel);
        let caller = caller.clone();
        let mountpoint = mountpoint.clone();
        tokio::spawn(async move { issue(&kernel, &caller, &mountpoint).await })
    };
    let (resource, socket) = prepared.await.unwrap();
    assert!(resource.join("lease.json").is_file());
    assert_success(
        &handlers::dispatch(
            &kernel,
            &operator,
            AdminRequestKind::AgentDisable {
                principal: caller.clone(),
            },
        )
        .await,
    );
    assert!(!kernel.storage_mounts.contains_key(&first.mount_id));
    assert!(!first.callback_path.exists());
    assert!(issue(&kernel, &caller, &mountpoint).await.is_err());
    assert!(kernel.storage_mounts.contains_key(&independent.mount_id));
    assert_success(
        &handlers::dispatch(
            &kernel,
            &operator,
            AdminRequestKind::AgentEnable {
                principal: caller.clone(),
            },
        )
        .await,
    );
    resume.send(()).unwrap();
    assert!(
        late_issue
            .await
            .unwrap()
            .unwrap_err()
            .contains("retired during issuance")
    );
    assert!(!resource.exists());
    assert!(!socket.exists());
    let second = issue(&kernel, &caller, &mountpoint).await.unwrap();
    assert_ne!(first.mount_id, second.mount_id);
    assert!(!kernel.storage_mounts.contains_key(&first.mount_id));
    assert_success(
        &super::super::test_support::dispatch_as_operator(
            &kernel,
            &operator,
            AdminRequestKind::AgentDelete {
                principal: caller.clone(),
            },
        )
        .await,
    );
    assert!(!kernel.storage_mounts.contains_key(&second.mount_id));
    assert!(!second.callback_path.exists());
    assert!(kernel.storage_mounts.contains_key(&independent.mount_id));
    crate::storage_mount::revoke_lease(&kernel, &operator, false, independent.mount_id)
        .await
        .unwrap();
}

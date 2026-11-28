//! Check mount retirement through the same admin handlers used by the daemon.
use super::super::test_support::mounts::{PreparedIssue, issue};
use super::*;

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
    let late = PreparedIssue::begin(&kernel, &caller, &mountpoint).await;
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
    late.assert_retired().await;
    let second = issue(&kernel, &caller, &mountpoint).await.unwrap();
    let deleting = PreparedIssue::begin(&kernel, &caller, &mountpoint).await;
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
    deleting.assert_retired().await;
    assert!(!kernel.storage_mounts.contains_key(&second.mount_id));
    assert!(!second.callback_path.exists());
    assert!(kernel.storage_mounts.contains_key(&independent.mount_id));
    crate::storage_mount::revoke_lease(&kernel, &operator, false, independent.mount_id)
        .await
        .unwrap();
}

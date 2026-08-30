//! Proves stale listener state cannot hide a pre-latched filesystem panic.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn agent_delete_observes_pre_latched_panic_with_stale_listener_then_retries() {
    let (dir, kernel) = fixture().await;
    let principal = PrincipalId::new("latched-delete-panic").unwrap();
    create(&kernel, &principal).await;
    let lease = issue_principal_mount(
        &kernel,
        &principal,
        dir.path().join("latched-delete-panic-mount"),
    )
    .await
    .expect("issue principal mount");
    let state = Arc::clone(
        kernel
            .storage_mounts
            .get(&lease.mount_id)
            .expect("mapped principal lease")
            .value(),
    );
    state.set_drain_timeouts_for_test(std::time::Duration::from_millis(80));
    state.arm_stale_join_failure_for_test();
    assert!(!state.is_revoked_for_test());

    let failed = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;
    let AdminResponseBody::Error(failure) = failed else {
        panic!("stale listener must not hide a pre-latched JoinFailed");
    };
    assert!(
        failure.contains("cleanup failed at drain")
            && failure.contains("retained filesystem worker join failed"),
        "expected typed Drain/JoinFailed failure, got {failure}"
    );
    assert!(
        kernel
            .identity_store
            .resolve("cli", principal.as_str())
            .await
            .expect("identity lookup")
            .is_some()
    );
    assert!(PrincipalProfile::path_for(&kernel.astrid_home, &principal).exists());
    assert!(kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(state.is_revoked_for_test());
    assert!(lease.resource_path.exists());
    let retried = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;
    assert!(
        matches!(retried, AdminResponseBody::Success(_)),
        "the settled exact retry must delete: {retried:?}"
    );
    assert_eq!(state.in_flight_mutations_for_test(), 0);
    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(!lease.resource_path.exists());
    assert!(
        kernel
            .identity_store
            .resolve("cli", principal.as_str())
            .await
            .expect("identity lookup")
            .is_none()
    );
}

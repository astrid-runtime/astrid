//! Revocation, cleanup retry, listener drain, and branch-lease tests.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_drains_an_in_flight_mutation_and_fences_new_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = PrincipalId::default();
    let lease = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CrossOwnerWrite),
        StorageProviderViewV1::Admin,
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        temporary.path().join("mount"),
    )
    .await
    .unwrap();
    assert_eq!(
        callback(&lease, &lease.lease_token, create("in-flight.bin")).await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    sync_lease(
        &kernel,
        &caller,
        MountOwnerScope::CrossOwnerWrite,
        lease.mount_id,
    )
    .await
    .unwrap();
    let state = Arc::clone(kernel.storage_mounts.get(&lease.mount_id).unwrap().value());
    let gate = Arc::new(MutationTestGate {
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    *state.mutation_test_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let mutation_kernel = Arc::clone(kernel.as_ref());
    let mutation_state = Arc::clone(&state);
    let mutation = tokio::spawn(async move {
        execute_operation(
            mutation_kernel,
            mutation_state,
            StorageFilesystemOperationV1::Write {
                path: "in-flight.bin".to_owned(),
                offset: 0,
                data: vec![0x36_u8; 64],
            },
        )
        .await
    });
    gate.entered.acquire().await.unwrap().forget();
    assert_eq!(state.in_flight_mutations.load(Ordering::Acquire), 1);
    assert!(!state.dirty.load(Ordering::Acquire));
    let revocation_kernel = Arc::clone(&kernel);
    let revocation_caller = caller.clone();
    let revocation = tokio::spawn(async move {
        revoke_lease(
            &revocation_kernel,
            &revocation_caller,
            MountOwnerScope::CrossOwnerWrite,
            lease.mount_id,
        )
        .await
    });
    while !state.revoked.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    assert!(!revocation.is_finished());
    assert_eq!(state.in_flight_mutations.load(Ordering::Acquire), 1);
    gate.release.add_permits(1);

    let outcome = mutation.await.unwrap();
    assert!(matches!(
        outcome,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Written(64))
    ));
    revocation.await.unwrap().unwrap();
    assert_eq!(state.in_flight_mutations.load(Ordering::Acquire), 0);
    assert!(state.dirty.load(Ordering::Acquire));
    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(!astrid_core::local_transport::endpoint_is_present(&lease.callback_path).unwrap());
    let fenced = execute_operation(
        Arc::clone(kernel.as_ref()),
        Arc::clone(&state),
        create("after-revoke.txt"),
    )
    .await;
    assert!(matches!(
        fenced,
        StorageFilesystemOutcomeV1::Failure(StorageFilesystemFailureV1 { code, .. })
            if code == "stale-lease"
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn revoked_callback_keeps_blocked_job_mapped_until_worker_ends() {
    let temporary = tempfile::tempdir().unwrap();
    let kernel = Arc::new(
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(
            temporary.path().join(".astrid"),
        ))
        .await,
    );
    let caller = PrincipalId::default();
    let mountpoint = temporary.path().join("retained-job-mount");
    let lease = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CrossOwnerWrite),
        StorageProviderViewV1::Admin,
        StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        mountpoint.clone(),
    )
    .await
    .unwrap();
    let state = Arc::clone(kernel.storage_mounts.get(&lease.mount_id).unwrap().value());
    state.set_drain_timeouts_for_test(std::time::Duration::from_millis(80));
    let gate = Arc::new(MutationTestGate {
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    *state.mutation_test_gate.lock().unwrap() = Some(Arc::clone(&gate));

    let callback_lease = lease.clone();
    let mutation = tokio::spawn(async move {
        callback(
            &callback_lease,
            &callback_lease.lease_token,
            create("retained.bin"),
        )
        .await
    });
    gate.entered.acquire().await.unwrap().forget();
    mutation.abort();
    assert_eq!(state.in_flight_mutations.load(Ordering::Acquire), 1);

    let revocation_kernel = Arc::clone(&kernel);
    let revocation_caller = caller.clone();
    let revocation_mount_id = lease.mount_id;
    let revocation = tokio::spawn(async move {
        revoke_lease(
            &revocation_kernel,
            &revocation_caller,
            MountOwnerScope::CrossOwnerWrite,
            revocation_mount_id,
        )
        .await
    });
    let error = revocation.await.unwrap().unwrap_err();
    assert!(
        error.contains("cleanup failed at drain"),
        "expected typed drain cleanup failure, got {error}"
    );
    assert!(state.revoked.load(Ordering::Acquire));
    assert!(kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(lease.resource_path.exists());
    assert!(
        lease
            .resource_path
            .join(super::LEASE_MANIFEST_NAME)
            .exists()
    );

    let duplicate_kernel = Arc::clone(&kernel);
    let duplicate_caller = caller.clone();
    let duplicate = tokio::spawn(async move {
        issue_lease(
            &duplicate_kernel,
            &test_mount_admission(
                &duplicate_kernel,
                &duplicate_caller,
                MountOwnerScope::CrossOwnerWrite,
            ),
            StorageProviderViewV1::Admin,
            StorageFilesystemTargetV1::OwnerRoot,
            StorageProviderAccessV1::ReadWrite,
            "test-provider".to_owned(),
            mountpoint.clone(),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_millis(80), duplicate)
        .await
        .expect_err("the retained admitted job must retain the mutation fence");

    gate.release.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !state.blocking_jobs.lock().await.is_empty() {
            tokio::task::yield_now().await;
        }
        while !state.wait_listener_closed().await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retained job and listener completion");

    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CrossOwnerWrite,
        lease.mount_id,
    )
    .await
    .expect("exact retry after retained job completion");
    assert_eq!(state.in_flight_mutations.load(Ordering::Acquire), 0);
    assert!(state.dirty.load(Ordering::Acquire));
    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(!astrid_core::local_transport::endpoint_is_present(&lease.callback_path).unwrap());
    assert!(!lease.resource_path.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn internal_workspace_branch_lease_fixes_branch_target() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let caller = PrincipalId::default();
    let (user, identity) = crate::bootstrap_cli_root_user(&kernel.identity_store, &home)
        .await
        .unwrap();
    crate::bootstrap_cli_root_ownership(
        kernel.ownership_store().as_ref(),
        &kernel.principal_directory,
        user,
        identity,
        false,
    )
    .await
    .unwrap();
    let uid = kernel.principal_directory.uid_for(&caller).unwrap();
    let owner = astrid_storage::StateOwner::Principal(uid);
    let store = kernel.principal_store.clone().unwrap();
    let branches = astrid_storage::WorkspaceBranchStore::new(store.content());
    let workspace = astrid_core::WorkspaceUid::random();
    branches
        .begin_for_uid_at(
            &owner,
            uid,
            workspace,
            astrid_storage::ContentName::new("workspace/default").unwrap(),
        )
        .unwrap();

    let foreign_workspace = astrid_core::WorkspaceUid::random();
    branches
        .begin_for_uid_at(
            &owner,
            astrid_core::PrincipalUid::from_bytes([0x99; 32]),
            foreign_workspace,
            astrid_storage::ContentName::new("workspace/default").unwrap(),
        )
        .unwrap();
    let foreign_error = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CallerOnly),
        StorageProviderViewV1::Principal(caller.clone()),
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::WorkspaceBranch {
            workspace: foreign_workspace,
        },
        StorageProviderAccessV1::ReadWrite,
        "foreign-branch-test".to_owned(),
        temporary.path().join("foreign-branch-mount"),
    )
    .await
    .expect_err("caller-scoped branch lease must reject another UID's branch");
    assert!(foreign_error.contains("not bound to the authenticated principal"));

    let lease = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CallerOnly),
        StorageProviderViewV1::Principal(caller.clone()),
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::WorkspaceBranch { workspace },
        StorageProviderAccessV1::ReadWrite,
        "internal-branch-test".to_owned(),
        temporary.path().join("branch-mount"),
    )
    .await
    .unwrap();
    let target = kernel
        .storage_mounts
        .get(&lease.mount_id)
        .expect("internal branch lease is registered")
        .target
        .clone();
    assert!(matches!(
        target,
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::WorkspaceBranch {
            workspace: actual
        } if actual == workspace
    ));
    assert_eq!(
        callback(&lease, &lease.lease_token, create("branch.txt")).await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    assert_eq!(
        callback(
            &lease,
            &lease.lease_token,
            StorageFilesystemOperationV1::Write {
                path: "branch.txt".to_owned(),
                offset: 0,
                data: b"promoted branch bytes".to_vec(),
            },
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Written(21))
    );
    assert_eq!(
        callback(
            &lease,
            &lease.lease_token,
            StorageFilesystemOperationV1::Sync,
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    assert!(
        branches
            .read(
                &owner,
                workspace,
                &astrid_storage::content::ContentName::new("branch.txt".to_owned()).unwrap(),
            )
            .unwrap()
            .is_some()
    );
    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        lease.mount_id,
    )
    .await
    .unwrap();
    branches.promote(&owner, workspace).unwrap();
    assert_eq!(
        store
            .content()
            .read(
                &owner,
                &astrid_storage::content::ContentName::new(
                    "workspace/default/branch.txt".to_owned()
                )
                .unwrap(),
            )
            .unwrap(),
        Some(b"promoted branch bytes".to_vec())
    );

    let rollback_workspace = astrid_core::WorkspaceUid::random();
    branches
        .begin_for_uid_at(
            &owner,
            uid,
            rollback_workspace,
            astrid_storage::ContentName::new("workspace/default").unwrap(),
        )
        .unwrap();
    let rollback_lease = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CallerOnly),
        StorageProviderViewV1::Principal(caller.clone()),
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::WorkspaceBranch {
            workspace: rollback_workspace,
        },
        StorageProviderAccessV1::ReadWrite,
        "rollback-branch-test".to_owned(),
        temporary.path().join("rollback-branch-mount"),
    )
    .await
    .unwrap();
    assert_eq!(
        callback(
            &rollback_lease,
            &rollback_lease.lease_token,
            create("rolled-back.txt"),
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        rollback_lease.mount_id,
    )
    .await
    .unwrap();
    branches.rollback(&owner, rollback_workspace).unwrap();
    assert_eq!(
        store
            .content()
            .read(
                &owner,
                &astrid_storage::content::ContentName::new(
                    "workspace/default/rolled-back.txt".to_owned()
                )
                .unwrap(),
            )
            .unwrap(),
        None
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_retries_after_injected_cleanup_failure() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = PrincipalId::default();
    let lease = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CrossOwnerWrite),
        StorageProviderViewV1::Admin,
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        temporary.path().join("cleanup-fault-mount"),
    )
    .await
    .unwrap();
    let state = Arc::clone(kernel.storage_mounts.get(&lease.mount_id).unwrap().value());
    inject_cleanup_fault_for_test(&state, MountCleanupStage::Manifest);
    let error = revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CrossOwnerWrite,
        lease.mount_id,
    )
    .await
    .expect_err("injected manifest cleanup must fail closed");
    assert!(
        error.contains("manifest"),
        "expected manifest cleanup diagnostic, got {error}"
    );
    assert!(
        kernel.storage_mounts.contains_key(&lease.mount_id),
        "failed cleanup must keep the revoked lease mapped"
    );
    assert!(state.is_revoked_for_test());
    assert!(
        lease
            .resource_path
            .join(super::LEASE_MANIFEST_NAME)
            .exists()
    );
    clear_cleanup_fault_for_test(&state);
    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CrossOwnerWrite,
        lease.mount_id,
    )
    .await
    .expect("retry after clearing cleanup fault");
    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(!astrid_core::local_transport::endpoint_is_present(&lease.callback_path).unwrap());
    assert!(!lease.resource_path.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_accepted_connection_is_aborted_before_endpoint_cleanup() {
    let temporary = tempfile::tempdir().unwrap();
    let kernel = crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(
        temporary.path().join(".astrid"),
    ))
    .await;
    let caller = PrincipalId::default();
    let lease = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CrossOwnerWrite),
        StorageProviderViewV1::Admin,
        StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "idle-transport-test-provider".to_owned(),
        temporary.path().join("idle-connection-mount"),
    )
    .await
    .unwrap();
    let state = Arc::clone(kernel.storage_mounts.get(&lease.mount_id).unwrap().value());

    let mut client = astrid_core::local_transport::connect(&lease.callback_path)
        .await
        .unwrap();
    // One byte is consumed by Windows accept authentication and leaves both
    // backends waiting for the first callback frame.
    client.write_all(&[0_u8]).await.unwrap();
    client.flush().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if !state.accepted_tasks.lock().await.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("accepted connection must be tracked");

    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CrossOwnerWrite,
        lease.mount_id,
    )
    .await
    .unwrap();

    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(
        !astrid_core::local_transport::endpoint_is_present(&lease.callback_path).unwrap(),
        "every accepted server handle must close before endpoint cleanup"
    );
    assert!(!lease.resource_path.exists());
    assert!(!kernel.astrid_home.run_dir().join("mount-cleanup").exists());
}

//! Private callback filesystem I/O and protocol-version tests.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn version_one_callback_round_trips_small_binary_io() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = crate::test_kernel_with_home(home).await;
    let lease = issue_lease(
        &kernel,
        &test_mount_admission(
            &kernel,
            &PrincipalId::default(),
            MountOwnerScope::CrossOwnerWrite,
        ),
        StorageProviderViewV1::Admin,
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "v1-test-provider".to_owned(),
        temporary.path().join("mount"),
    )
    .await
    .unwrap();
    assert_eq!(
        callback_v1(&lease, create("legacy.bin")).await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    let expected = vec![0, 1, 127, 128, 255];
    assert_eq!(
        callback_v1(
            &lease,
            StorageFilesystemOperationV1::Write {
                path: "legacy.bin".to_owned(),
                offset: 0,
                data: expected.clone(),
            },
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Written(5))
    );
    assert_eq!(
        callback_v1(
            &lease,
            StorageFilesystemOperationV1::Read {
                path: "legacy.bin".to_owned(),
                offset: 0,
                length: 5,
            },
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Data(expected))
    );
    revoke_lease(
        &kernel,
        &PrincipalId::default(),
        MountOwnerScope::CrossOwnerWrite,
        lease.mount_id,
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn version_two_framing_transports_maximum_file_io() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = crate::test_kernel_with_home(home).await;
    let lease = issue_lease(
        &kernel,
        &test_mount_admission(
            &kernel,
            &PrincipalId::default(),
            MountOwnerScope::CrossOwnerWrite,
        ),
        StorageProviderViewV1::Admin,
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        temporary.path().join("mount"),
    )
    .await
    .unwrap();
    assert_eq!(
        callback(&lease, &lease.lease_token, create("maximum.bin")).await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    let expected = vec![0x5a_u8; usize::try_from(STORAGE_FILESYSTEM_MAX_IO_BYTES).unwrap()];
    assert_eq!(
        callback(
            &lease,
            &lease.lease_token,
            StorageFilesystemOperationV1::Write {
                path: "maximum.bin".to_owned(),
                offset: 0,
                data: expected.clone(),
            },
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Written(
            STORAGE_FILESYSTEM_MAX_IO_BYTES
        ))
    );
    assert_eq!(
        callback(
            &lease,
            &lease.lease_token,
            StorageFilesystemOperationV1::Read {
                path: "maximum.bin".to_owned(),
                offset: 0,
                length: STORAGE_FILESYSTEM_MAX_IO_BYTES,
            },
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Data(expected))
    );
    revoke_lease(
        &kernel,
        &PrincipalId::default(),
        MountOwnerScope::CrossOwnerWrite,
        lease.mount_id,
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dirty_tracks_only_successfully_acknowledged_unsynced_mutations() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = crate::test_kernel_with_home(home).await;
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
    let state = Arc::clone(kernel.storage_mounts.get(&lease.mount_id).unwrap().value());

    let missing = callback(
        &lease,
        &lease.lease_token,
        StorageFilesystemOperationV1::Remove {
            path: "missing.txt".to_owned(),
        },
    )
    .await;
    assert!(matches!(
        missing,
        StorageFilesystemOutcomeV1::Failure(StorageFilesystemFailureV1 { code, .. })
            if code == "not-found"
    ));
    assert!(!state.dirty.load(Ordering::Acquire));
    assert_eq!(state.in_flight_mutations.load(Ordering::Acquire), 0);

    assert_eq!(
        callback(&lease, &lease.lease_token, create("created.txt")).await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    assert!(state.dirty.load(Ordering::Acquire));
    assert_eq!(state.in_flight_mutations.load(Ordering::Acquire), 0);

    let still_missing = callback(
        &lease,
        &lease.lease_token,
        StorageFilesystemOperationV1::Remove {
            path: "still-missing.txt".to_owned(),
        },
    )
    .await;
    assert!(matches!(
        still_missing,
        StorageFilesystemOutcomeV1::Failure(StorageFilesystemFailureV1 { code, .. })
            if code == "not-found"
    ));
    assert!(state.dirty.load(Ordering::Acquire));

    assert_eq!(
        callback(
            &lease,
            &lease.lease_token,
            StorageFilesystemOperationV1::Sync,
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    assert!(!state.dirty.load(Ordering::Acquire));
    assert_eq!(state.in_flight_mutations.load(Ordering::Acquire), 0);
    let status = lease_status(
        &kernel,
        &caller,
        MountOwnerScope::CrossOwnerWrite,
        lease.mount_id,
    )
    .await
    .unwrap();
    assert_eq!(status["dirty"], false);
    assert_eq!(status["in_flight_mutations"], 0);

    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CrossOwnerWrite,
        lease.mount_id,
    )
    .await
    .unwrap();
}

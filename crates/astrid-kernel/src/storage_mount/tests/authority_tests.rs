//! Process-storage authority, isolation, and lease admission tests.

use super::*;

fn ready_test_launch() -> StorageProviderServiceLaunchV1 {
    let lease_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x11_u8; 32]);
    let parent_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x22_u8; 32]);
    #[cfg(unix)]
    let resource_path = PathBuf::from("/private/run/astrid/lease");
    #[cfg(windows)]
    let resource_path = PathBuf::from(r"C:\private\run\astrid\lease");
    let control_path = resource_path.join("process-control.sock");
    StorageProviderServiceLaunchV1 {
        schema: STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1,
        lease: StorageMountLeaseV1 {
            mount_id: StorageMountId::new(),
            view: StorageProviderViewV1::Principal(PrincipalId::default()),
            access: StorageProviderAccessV1::ReadOnly,
            resource_path: resource_path.clone(),
            callback_path: resource_path.join("callback.sock"),
            lease_token,
            expires_at_epoch_secs: u64::MAX,
        },
        mountpoint: {
            #[cfg(unix)]
            let path = PathBuf::from("/private/run/astrid/mount");
            #[cfg(windows)]
            let path = PathBuf::from(r"C:\private\run\astrid\mount");
            path
        },
        control_path: control_path.clone(),
        parent: StorageProviderParentLifetimeV1 {
            pid: 1_234,
            start_identity: Some("123:456".to_owned()),
            token: parent_token,
        },
    }
}

#[cfg(any(unix, windows))]
#[test]
fn process_provider_ready_requires_exact_bound_identity_and_challenge() {
    let launch = ready_test_launch();
    let challenge = storage_provider_service_ready_challenge(
        &launch.parent.token,
        STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1,
        platform_process_provider_name(),
        launch.lease.mount_id.as_uuid(),
        &launch.control_path,
        &launch.lease.resource_path,
        &launch.lease.callback_path,
    )
    .expect("ready challenge");
    let ready = StorageProviderServiceReadyV1 {
        schema: STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1,
        provider: platform_process_provider_name().to_owned(),
        mount_id: launch.lease.mount_id.as_uuid(),
        control_path: launch.control_path.clone(),
        challenge,
    };
    let canonical = serde_json::to_string(&ready).expect("canonical ready");
    validate_process_provider_ready(&launch, &canonical).expect("valid ready frame");

    let wrong = canonical.replace("\"challenge\":\"", "\"challenge\":\"deadbeef");
    assert!(validate_process_provider_ready(&launch, &wrong).is_err());
    let unknown = format!("{},\"extra\":true}}", canonical.trim_end_matches('}'));
    assert!(validate_process_provider_ready(&launch, &unknown).is_err());
    let oversized = format!("{}{}", canonical, "x".repeat(64 * 1024));
    assert!(validate_process_provider_ready(&launch, &oversized).is_err());
}

async fn root_fleet(kernel: &Kernel) -> astrid_core::FleetUid {
    kernel
        .ownership_store()
        .load()
        .await
        .unwrap()
        .fleets()
        .next()
        .unwrap()
        .identity()
        .uid
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_callbacks_bind_authority_and_isolate_principal_and_fleet_views() {
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
    let fleet = root_fleet(&kernel).await;

    let principal = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CallerOnly),
        StorageProviderViewV1::Principal(caller.clone()),
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        temporary.path().join("principal-mount"),
    )
    .await
    .unwrap();
    let transient = astrid_core::local_transport::connect(&principal.callback_path)
        .await
        .unwrap();
    drop(transient);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    #[cfg(unix)]
    {
        assert_eq!(
            std::fs::metadata(&principal.resource_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(principal.resource_path.join(LEASE_MANIFEST_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&principal.callback_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    assert_eq!(
        callback(&principal, &principal.lease_token, create("private.txt")).await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    assert_eq!(
        callback(
            &principal,
            &principal.lease_token,
            StorageFilesystemOperationV1::Write {
                path: "private.txt".to_owned(),
                offset: 0,
                data: b"principal".to_vec(),
            },
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Written(9))
    );
    assert_eq!(
        callback(
            &principal,
            &principal.lease_token,
            StorageFilesystemOperationV1::Read {
                path: "private.txt".to_owned(),
                offset: 0,
                length: 9,
            },
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Data(
            b"principal".to_vec()
        ))
    );
    assert_eq!(
        callback(
            &principal,
            &principal.lease_token,
            StorageFilesystemOperationV1::Write {
                path: "private.txt".to_owned(),
                offset: 4,
                data: b"X".to_vec(),
            },
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Written(9))
    );
    assert_eq!(
        callback(
            &principal,
            &principal.lease_token,
            StorageFilesystemOperationV1::SetLength {
                path: "private.txt".to_owned(),
                length: 5,
            },
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Written(5))
    );
    assert_eq!(
        callback(
            &principal,
            &principal.lease_token,
            StorageFilesystemOperationV1::Rename {
                from: "private.txt".to_owned(),
                to: "renamed.txt".to_owned(),
                replace: false,
            },
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    assert_eq!(
        callback(&principal, &principal.lease_token, create("private.txt")).await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    assert_eq!(
        callback(
            &principal,
            &principal.lease_token,
            StorageFilesystemOperationV1::Rename {
                from: "renamed.txt".to_owned(),
                to: "private.txt".to_owned(),
                replace: true,
            },
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    assert_eq!(
        callback(
            &principal,
            &principal.lease_token,
            StorageFilesystemOperationV1::Create {
                path: "notes".to_owned(),
                kind: StorageFilesystemEntryKindV1::Directory,
            },
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    assert_eq!(
        callback(&principal, &principal.lease_token, create("notes/a.txt")).await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    for path in ["notes/a.txt", "notes"] {
        assert_eq!(
            callback(
                &principal,
                &principal.lease_token,
                StorageFilesystemOperationV1::Remove {
                    path: path.to_owned(),
                },
            )
            .await,
            StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
        );
    }
    assert_eq!(
        callback(
            &principal,
            &principal.lease_token,
            StorageFilesystemOperationV1::Sync,
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );

    let fleet_lease = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CallerOnly),
        StorageProviderViewV1::Fleet(fleet),
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        temporary.path().join("fleet-mount"),
    )
    .await
    .unwrap();
    assert_eq!(
        callback(
            &fleet_lease,
            &fleet_lease.lease_token,
            StorageFilesystemOperationV1::ReadDirectory {
                path: String::new(),
            },
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Entries(vec![]))
    );
    assert_eq!(
        callback(&fleet_lease, &fleet_lease.lease_token, create("shared.txt")).await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );
    let principal_entries = callback(
        &principal,
        &principal.lease_token,
        StorageFilesystemOperationV1::ReadDirectory {
            path: String::new(),
        },
    )
    .await;
    let StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Entries(entries)) =
        principal_entries
    else {
        panic!("expected principal directory entries")
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "private.txt");

    let system_lease = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CrossOwnerWrite),
        StorageProviderViewV1::Admin,
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        temporary.path().join("system-mount"),
    )
    .await
    .unwrap();
    assert_eq!(
        callback(
            &system_lease,
            &system_lease.lease_token,
            create("system.txt")
        )
        .await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );

    let unauthorized = callback(&principal, "wrong-token", create("denied.txt")).await;
    assert!(matches!(
        unauthorized,
        StorageFilesystemOutcomeV1::Failure(StorageFilesystemFailureV1 { code, .. })
            if code == "unauthorized"
    ));

    let read_only = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CallerOnly),
        StorageProviderViewV1::Principal(caller.clone()),
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadOnly,
        "test-provider".to_owned(),
        temporary.path().join("read-only-mount"),
    )
    .await
    .unwrap();
    let denied = callback(&read_only, &read_only.lease_token, create("denied.txt")).await;
    assert!(matches!(
        denied,
        StorageFilesystemOutcomeV1::Failure(StorageFilesystemFailureV1 { code, .. })
            if code == "read-only"
    ));

    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        principal.mount_id,
    )
    .await
    .unwrap();
    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        fleet_lease.mount_id,
    )
    .await
    .unwrap();
    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        system_lease.mount_id,
    )
    .await
    .unwrap();
    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        read_only.mount_id,
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn synced_owner_mounts_reopen_without_cross_view_aliasing() {
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
    let fleet = root_fleet(&kernel).await;

    let principal = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CallerOnly),
        StorageProviderViewV1::Principal(caller.clone()),
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "reopen-principal".to_owned(),
        temporary.path().join("principal-first"),
    )
    .await
    .unwrap();
    let fleet_lease = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CallerOnly),
        StorageProviderViewV1::Fleet(fleet),
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "reopen-fleet".to_owned(),
        temporary.path().join("fleet-first"),
    )
    .await
    .unwrap();

    for (lease, bytes) in [
        (&principal, b"principal-bytes".as_slice()),
        (&fleet_lease, b"fleet-bytes".as_slice()),
    ] {
        assert_eq!(
            callback(lease, &lease.lease_token, create("same-name.txt")).await,
            StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
        );
        assert_eq!(
            callback(
                lease,
                &lease.lease_token,
                StorageFilesystemOperationV1::Write {
                    path: "same-name.txt".to_owned(),
                    offset: 0,
                    data: bytes.to_vec(),
                },
            )
            .await,
            StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Written(
                bytes.len() as u64
            ))
        );
        assert_eq!(
            callback(
                lease,
                &lease.lease_token,
                StorageFilesystemOperationV1::Sync,
            )
            .await,
            StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
        );
    }
    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        principal.mount_id,
    )
    .await
    .unwrap();
    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        fleet_lease.mount_id,
    )
    .await
    .unwrap();

    let principal_reopened = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CallerOnly),
        StorageProviderViewV1::Principal(caller.clone()),
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadOnly,
        "reopen-principal".to_owned(),
        temporary.path().join("principal-second"),
    )
    .await
    .unwrap();
    let fleet_reopened = issue_lease(
        &kernel,
        &test_mount_admission(&kernel, &caller, MountOwnerScope::CallerOnly),
        StorageProviderViewV1::Fleet(fleet),
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadOnly,
        "reopen-fleet".to_owned(),
        temporary.path().join("fleet-second"),
    )
    .await
    .unwrap();

    for (lease, expected) in [
        (&principal_reopened, b"principal-bytes".as_slice()),
        (&fleet_reopened, b"fleet-bytes".as_slice()),
    ] {
        assert_eq!(
            callback(
                lease,
                &lease.lease_token,
                StorageFilesystemOperationV1::Read {
                    path: "same-name.txt".to_owned(),
                    offset: 0,
                    length: 64,
                },
            )
            .await,
            StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Data(
                expected.to_vec()
            ))
        );
        assert!(matches!(
            callback(lease, &lease.lease_token, create("denied.txt")).await,
            StorageFilesystemOutcomeV1::Failure(StorageFilesystemFailureV1 { code, .. })
                if code == "read-only"
        ));
    }

    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        principal_reopened.mount_id,
    )
    .await
    .unwrap();
    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        fleet_reopened.mount_id,
    )
    .await
    .unwrap();
}

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

use super::*;

async fn callback(
    lease: &StorageMountLeaseV1,
    token: &str,
    operation: StorageFilesystemOperationV1,
) -> StorageFilesystemOutcomeV1 {
    let mut stream = astrid_core::local_transport::connect(&lease.callback_path)
        .await
        .unwrap();
    let request = StorageFilesystemRequestV2 {
        protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V2,
        request_id: "test-request".to_owned(),
        lease_token: token.to_owned(),
        operation: encode_operation_v2(operation),
    };
    let bytes = serde_json::to_vec(&request).unwrap();
    let length = u32::try_from(bytes.len()).expect("bounded callback request");
    stream.write_all(&length.to_be_bytes()).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    let mut response_length = [0_u8; 4];
    stream.read_exact(&mut response_length).await.unwrap();
    let mut response = vec![0_u8; u32::from_be_bytes(response_length) as usize];
    stream.read_exact(&mut response).await.unwrap();
    decode_outcome_v2(
        serde_json::from_slice::<StorageFilesystemResponseV2>(&response)
            .unwrap()
            .outcome,
    )
}

async fn callback_v1(
    lease: &StorageMountLeaseV1,
    operation: StorageFilesystemOperationV1,
) -> StorageFilesystemOutcomeV1 {
    let mut stream = astrid_core::local_transport::connect(&lease.callback_path)
        .await
        .unwrap();
    let request = StorageFilesystemRequestV1 {
        protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V1,
        request_id: "v1-compatibility-request".to_owned(),
        lease_token: lease.lease_token.clone(),
        operation,
    };
    let bytes = serde_json::to_vec(&request).unwrap();
    stream
        .write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&bytes).await.unwrap();
    let mut response_length = [0_u8; 4];
    stream.read_exact(&mut response_length).await.unwrap();
    let mut response = vec![0_u8; u32::from_be_bytes(response_length) as usize];
    stream.read_exact(&mut response).await.unwrap();
    let response: StorageFilesystemResponseV1 = serde_json::from_slice(&response).unwrap();
    assert_eq!(response.protocol_version, STORAGE_FILESYSTEM_PROTOCOL_V1);
    response.outcome
}

fn encode_operation_v2(operation: StorageFilesystemOperationV1) -> StorageFilesystemOperationV2 {
    match operation {
        StorageFilesystemOperationV1::Stat { path } => StorageFilesystemOperationV2::Stat { path },
        StorageFilesystemOperationV1::ReadDirectory { path } => {
            StorageFilesystemOperationV2::ReadDirectory { path }
        },
        StorageFilesystemOperationV1::Read {
            path,
            offset,
            length,
        } => StorageFilesystemOperationV2::Read {
            path,
            offset,
            length,
        },
        StorageFilesystemOperationV1::Write { path, offset, data } => {
            StorageFilesystemOperationV2::Write {
                path,
                offset,
                data_base64: base64::engine::general_purpose::STANDARD.encode(data),
            }
        },
        StorageFilesystemOperationV1::SetLength { path, length } => {
            StorageFilesystemOperationV2::SetLength { path, length }
        },
        StorageFilesystemOperationV1::Create { path, kind } => {
            StorageFilesystemOperationV2::Create { path, kind }
        },
        StorageFilesystemOperationV1::Remove { path } => {
            StorageFilesystemOperationV2::Remove { path }
        },
        StorageFilesystemOperationV1::Rename { from, to, replace } => {
            StorageFilesystemOperationV2::Rename { from, to, replace }
        },
        StorageFilesystemOperationV1::Sync => StorageFilesystemOperationV2::Sync,
    }
}

fn decode_outcome_v2(outcome: StorageFilesystemOutcomeV2) -> StorageFilesystemOutcomeV1 {
    match outcome {
        StorageFilesystemOutcomeV2::Success(success) => {
            StorageFilesystemOutcomeV1::Success(match success {
                StorageFilesystemSuccessV2::Done => StorageFilesystemSuccessV1::Done,
                StorageFilesystemSuccessV2::Entry(entry) => {
                    StorageFilesystemSuccessV1::Entry(entry)
                },
                StorageFilesystemSuccessV2::Entries(entries) => {
                    StorageFilesystemSuccessV1::Entries(entries)
                },
                StorageFilesystemSuccessV2::Data { data_base64 } => {
                    StorageFilesystemSuccessV1::Data(
                        base64::engine::general_purpose::STANDARD
                            .decode(data_base64)
                            .unwrap(),
                    )
                },
                StorageFilesystemSuccessV2::Written(length) => {
                    StorageFilesystemSuccessV1::Written(length)
                },
            })
        },
        StorageFilesystemOutcomeV2::Failure(failure) => {
            StorageFilesystemOutcomeV1::Failure(failure)
        },
    }
}

fn create(path: &str) -> StorageFilesystemOperationV1 {
    StorageFilesystemOperationV1::Create {
        path: path.to_owned(),
        kind: StorageFilesystemEntryKindV1::File,
    }
}

#[tokio::test]
async fn private_mount_manifest_and_callback_endpoint_are_owner_scoped() {
    let temporary = tempfile::tempdir().unwrap();
    astrid_core::platform_fs::ensure_private_directory(temporary.path()).unwrap();
    let lease = StorageMountLeaseV1 {
        mount_id: StorageMountId::new(),
        view: StorageProviderViewV1::Principal(PrincipalId::default()),
        access: StorageProviderAccessV1::ReadOnly,
        resource_path: temporary.path().to_path_buf(),
        callback_path: temporary.path().join("control.sock"),
        lease_token: "test-token".to_owned(),
        expires_at_epoch_secs: u64::MAX,
    };

    let manifest_path = temporary.path().join("lease.json");
    write_private_manifest(&manifest_path, &lease).unwrap();
    let listener = bind_private_listener(&lease.callback_path).unwrap();

    astrid_core::platform_fs::validate_private_file(&manifest_path).unwrap();
    let manifest = std::fs::symlink_metadata(&manifest_path).unwrap();
    assert!(manifest.is_file());

    #[cfg(unix)]
    {
        let socket = std::fs::symlink_metadata(&lease.callback_path).unwrap();
        assert_eq!(manifest.permissions().mode() & 0o777, 0o600);
        assert!(socket.file_type().is_socket());
        assert_eq!(socket.permissions().mode() & 0o777, 0o600);
    }

    #[cfg(windows)]
    {
        let (client, server) = tokio::join!(
            astrid_core::local_transport::connect(&lease.callback_path),
            astrid_core::local_transport::accept(&listener),
        );
        drop(client.unwrap());
        drop(server.unwrap());
    }
    drop(listener);
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
        caller.clone(),
        false,
        StorageProviderViewV1::Principal(caller.clone()),
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
        caller.clone(),
        false,
        StorageProviderViewV1::Fleet(fleet),
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
        caller.clone(),
        true,
        StorageProviderViewV1::Admin,
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
        caller.clone(),
        false,
        StorageProviderViewV1::Principal(caller.clone()),
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

    revoke_lease(&kernel, &caller, false, principal.mount_id)
        .await
        .unwrap();
    revoke_lease(&kernel, &caller, false, fleet_lease.mount_id)
        .await
        .unwrap();
    revoke_lease(&kernel, &caller, false, system_lease.mount_id)
        .await
        .unwrap();
    revoke_lease(&kernel, &caller, false, read_only.mount_id)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn version_one_callback_round_trips_small_binary_io() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = crate::test_kernel_with_home(home).await;
    let lease = issue_lease(
        &kernel,
        PrincipalId::default(),
        true,
        StorageProviderViewV1::Admin,
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
    revoke_lease(&kernel, &PrincipalId::default(), true, lease.mount_id)
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
        PrincipalId::default(),
        true,
        StorageProviderViewV1::Admin,
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
    revoke_lease(&kernel, &PrincipalId::default(), true, lease.mount_id)
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
        caller.clone(),
        true,
        StorageProviderViewV1::Admin,
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
    let status = lease_status(&kernel, &caller, true, lease.mount_id).unwrap();
    assert_eq!(status["dirty"], false);
    assert_eq!(status["in_flight_mutations"], 0);

    revoke_lease(&kernel, &caller, true, lease.mount_id)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_drains_an_in_flight_mutation_and_fences_new_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = PrincipalId::default();
    let lease = issue_lease(
        &kernel,
        caller.clone(),
        true,
        StorageProviderViewV1::Admin,
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
    sync_lease(&kernel, &caller, true, lease.mount_id)
        .await
        .unwrap();
    let state = Arc::clone(kernel.storage_mounts.get(&lease.mount_id).unwrap().value());
    let gate = Arc::new(MutationTestGate {
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    *state.mutation_test_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let mutation_kernel = Arc::clone(&kernel);
    let mutation_state = Arc::clone(&state);
    let mutation = tokio::spawn(async move {
        execute_operation(
            &mutation_kernel,
            &mutation_state,
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
        revoke_lease(&revocation_kernel, &revocation_caller, true, lease.mount_id).await
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
    assert!(!lease.callback_path.exists());
    let fenced = execute_operation(&kernel, &state, create("after-revoke.txt")).await;
    assert!(matches!(
        fenced,
        StorageFilesystemOutcomeV1::Failure(StorageFilesystemFailureV1 { code, .. })
            if code == "stale-lease"
    ));
}

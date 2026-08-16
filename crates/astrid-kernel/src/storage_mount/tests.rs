use std::os::unix::fs::PermissionsExt as _;

use super::*;

async fn callback(
    lease: &StorageMountLeaseV1,
    token: &str,
    operation: StorageFilesystemOperationV1,
) -> StorageFilesystemOutcomeV1 {
    let mut stream = tokio::net::UnixStream::connect(&lease.callback_path)
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
    let mutation_kernel = Arc::clone(&kernel);
    let mutation_state = Arc::clone(&state);
    let mutation_bytes = vec![0x36_u8; usize::try_from(STORAGE_FILESYSTEM_MAX_IO_BYTES).unwrap()];
    let mutation = tokio::spawn(async move {
        execute_operation(
            &mutation_kernel,
            &mutation_state,
            StorageFilesystemOperationV1::Write {
                path: "in-flight.bin".to_owned(),
                offset: 0,
                data: mutation_bytes,
            },
        )
        .await
    });
    while !state.dirty.load(Ordering::Acquire) {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    let revocation_kernel = Arc::clone(&kernel);
    let revocation_caller = caller.clone();
    let revocation = tokio::spawn(async move {
        revoke_lease(&revocation_kernel, &revocation_caller, true, lease.mount_id).await
    });

    let outcome = mutation.await.unwrap();
    assert!(matches!(
        outcome,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Written(
            STORAGE_FILESYSTEM_MAX_IO_BYTES
        ))
    ));
    revocation.await.unwrap().unwrap();
    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(!lease.callback_path.exists());
    let fenced = execute_operation(&kernel, &state, create("after-revoke.txt")).await;
    assert!(matches!(
        fenced,
        StorageFilesystemOutcomeV1::Failure(StorageFilesystemFailureV1 { code, .. })
            if code == "stale-lease"
    ));
}

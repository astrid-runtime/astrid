#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

use super::filesystem::CallbackFilesystem;
use super::*;
use astrid_core::storage_filesystem::{
    StorageFilesystemOperationV2, StorageFilesystemOutcomeV2, StorageFilesystemRequestV1,
    StorageFilesystemRequestV2, StorageFilesystemResponseV2, StorageFilesystemSuccessV2,
};

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

/// Callback adapter that makes any attempted full-file read or replacement
/// write observable. The oversized-operation test below returns sentinel
/// errors from both seams so a correct preflight cannot accidentally pass.
struct ReadBoundarySpy<F> {
    inner: F,
    reads: Arc<AtomicU64>,
    writes: Arc<AtomicU64>,
}

impl<F: CallbackFilesystem> CallbackFilesystem for ReadBoundarySpy<F> {
    fn stat(&self, path: &FilesystemPath) -> Result<FilesystemEntry, FilesystemError> {
        self.inner.stat(path)
    }

    fn read_dir(&self, path: &FilesystemPath) -> Result<Vec<FilesystemEntry>, FilesystemError> {
        self.inner.read_dir(path)
    }

    fn read(
        &self,
        _path: &FilesystemPath,
        _offset: u64,
        _length: u64,
    ) -> Result<Vec<u8>, FilesystemError> {
        self.reads.fetch_add(1, Ordering::AcqRel);
        Err(FilesystemError::Staging(
            "full-file read reached before size preflight".to_owned(),
        ))
    }

    fn write(&self, _path: &FilesystemPath, _bytes: &[u8]) -> Result<(), FilesystemError> {
        self.writes.fetch_add(1, Ordering::AcqRel);
        Err(FilesystemError::Staging(
            "replacement write reached before size preflight".to_owned(),
        ))
    }

    fn create_dir(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        self.inner.create_dir(path)
    }

    fn remove(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        self.inner.remove(path)
    }

    fn rename(
        &self,
        from: &FilesystemPath,
        to: &FilesystemPath,
        replace: bool,
    ) -> Result<(), FilesystemError> {
        self.inner.rename(from, to, replace)
    }

    fn sync(&self) -> Result<(), FilesystemError> {
        self.inner.sync()
    }
}

#[tokio::test]
async fn oversized_set_length_and_random_write_preflight_before_full_read() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = crate::test_kernel_with_home(home).await;
    let store = kernel.principal_store.clone().unwrap();
    let filesystem = AstridFilesystem::new(
        store.content(),
        StateOwner::Principal(astrid_core::PrincipalUid::from_bytes([0xA4; 32])),
    );
    let path = FilesystemPath::new("probe.bin").unwrap();
    filesystem.write(&path, b"seed").unwrap();
    let oversized_path = FilesystemPath::new("oversized.bin").unwrap();
    filesystem
        .write(
            &oversized_path,
            &vec![
                0_u8;
                usize::try_from(STORAGE_FILESYSTEM_MAX_IO_BYTES.saturating_add(1)).unwrap()
            ],
        )
        .unwrap();
    let reads = Arc::new(AtomicU64::new(0));
    let writes = Arc::new(AtomicU64::new(0));
    let spy = ReadBoundarySpy {
        inner: filesystem,
        reads: Arc::clone(&reads),
        writes: Arc::clone(&writes),
    };

    let set_length = execute_blocking(
        &spy,
        StorageFilesystemOperationV1::SetLength {
            path: "probe.bin".to_owned(),
            length: STORAGE_FILESYSTEM_MAX_IO_BYTES.saturating_add(1),
        },
    );
    let set_length_preflighted =
        matches!(set_length, Err(FilesystemError::InvalidPath(path)) if path == "probe.bin");
    let set_length_reads = reads.load(Ordering::Acquire);
    let set_length_writes = writes.load(Ordering::Acquire);

    let random_write = execute_blocking(
        &spy,
        StorageFilesystemOperationV1::Write {
            path: "probe.bin".to_owned(),
            offset: STORAGE_FILESYSTEM_MAX_IO_BYTES,
            data: vec![0x5A],
        },
    );
    let random_write_preflighted =
        matches!(random_write, Err(FilesystemError::InvalidPath(path)) if path == "probe.bin");
    let random_write_reads = reads.load(Ordering::Acquire);
    let random_write_writes = writes.load(Ordering::Acquire);

    assert!(
        set_length_preflighted,
        "SetLength above the callback/quota ceiling must fail during preflight"
    );
    assert_eq!(
        set_length_reads, 0,
        "SetLength must reject before reading/rebuilding the current file"
    );
    assert_eq!(
        set_length_writes, 0,
        "SetLength must reject before publishing replacement bytes"
    );
    assert!(
        random_write_preflighted,
        "random writes whose resulting length exceeds the ceiling must fail during preflight"
    );
    assert_eq!(
        random_write_reads, 0,
        "random write must reject before reading/rebuilding the current file"
    );
    assert_eq!(
        random_write_writes, 0,
        "random write must reject before publishing replacement bytes"
    );

    let truncation = execute_blocking(
        &spy,
        StorageFilesystemOperationV1::SetLength {
            path: "oversized.bin".to_owned(),
            length: 0,
        },
    );
    assert!(
        matches!(truncation, Err(FilesystemError::InvalidPath(path)) if path == "oversized.bin"),
        "truncating an already oversized file must fail before rebuilding its contents"
    );
    assert_eq!(
        reads.load(Ordering::Acquire),
        0,
        "oversized truncation must not read the legacy file"
    );
    assert_eq!(
        writes.load(Ordering::Acquire),
        0,
        "oversized truncation must not publish replacement bytes"
    );
}

#[tokio::test]
async fn private_mount_manifest_and_callback_endpoint_are_owner_scoped() {
    let temporary = tempfile::tempdir().unwrap();
    let private_root = temporary.path().join("private");
    astrid_core::platform_fs::ensure_private_directory(&private_root).unwrap();
    let lease = StorageMountLeaseV1 {
        mount_id: StorageMountId::new(),
        view: StorageProviderViewV1::Principal(PrincipalId::default()),
        access: StorageProviderAccessV1::ReadOnly,
        resource_path: private_root.clone(),
        callback_path: private_root.join("control.sock"),
        lease_token: "test-token".to_owned(),
        expires_at_epoch_secs: u64::MAX,
    };

    let manifest_path = private_root.join("lease.json");
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
        let exchange = async {
            let client = async {
                let mut client =
                    astrid_core::local_transport::connect(&lease.callback_path).await?;
                client.write_all(&[0xA5]).await?;
                client.flush().await?;
                Ok::<_, std::io::Error>(client)
            };
            let (client, server) =
                tokio::join!(client, astrid_core::local_transport::accept(&listener),);
            let client = client.unwrap();
            let mut server = server.unwrap();
            let mut replayed = [0_u8; 1];
            server.read_exact(&mut replayed).await.unwrap();
            assert_eq!(replayed, [0xA5]);
            drop(client);
            drop(server);
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), exchange)
            .await
            .expect("Windows callback endpoint exchange timed out");
    }
    drop(listener);
}

#[tokio::test]
async fn principal_home_subtree_cannot_reach_capsule_catalog() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = crate::test_kernel_with_home(home).await;
    let uid = astrid_core::PrincipalUid::from_bytes([0xD0; 32]);
    let store = kernel.principal_store.clone().unwrap();
    let root = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
    root.create_dir(&FilesystemPath::new("home").unwrap())
        .unwrap();
    root.create_dir(&FilesystemPath::new("capsules").unwrap())
        .unwrap();
    root.write(
        &FilesystemPath::new("capsules/secret").unwrap(),
        b"package-authority",
    )
    .unwrap();

    let scoped = PrefixedFilesystem {
        inner: root,
        prefix: "home".to_owned(),
    };
    let listing = execute_blocking(
        &scoped,
        StorageFilesystemOperationV1::ReadDirectory {
            path: String::new(),
        },
    )
    .unwrap();
    assert!(
        matches!(listing, StorageFilesystemSuccessV1::Entries(entries) if entries
        .iter()
        .all(|entry| entry.name != "capsules"))
    );
    assert!(matches!(
        execute_blocking(
            &scoped,
            StorageFilesystemOperationV1::Read {
                path: "capsules/secret".to_owned(),
                offset: 0,
                length: 64,
            },
        ),
        Err(FilesystemError::NotFound(_))
    ));
}

#[tokio::test]
async fn fleet_shared_subtree_cannot_reach_workspace_or_siblings() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = crate::test_kernel_with_home(home).await;
    let store = kernel.principal_store.clone().unwrap();
    let fleet = astrid_core::FleetUid::from_bytes([0xF1; 32]);
    let root = AstridFilesystem::new(store.content(), StateOwner::Fleet(fleet));
    root.create_dir(&FilesystemPath::new("shared").unwrap())
        .unwrap();
    root.write(
        &FilesystemPath::new("shared/cookie").unwrap(),
        b"fleet-cookie",
    )
    .unwrap();
    root.create_dir(&FilesystemPath::new("workspace").unwrap())
        .unwrap();
    root.create_dir(&FilesystemPath::new("workspace/default").unwrap())
        .unwrap();
    root.write(
        &FilesystemPath::new("workspace/default/private").unwrap(),
        b"branch-only",
    )
    .unwrap();
    let scoped = AstridFilesystem::new_fleet_shared(store.content(), StateOwner::Fleet(fleet));
    let listing = scoped.read_dir(&FilesystemPath::root()).unwrap();
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].name(), "cookie");
    assert_eq!(
        scoped
            .read(&FilesystemPath::new("cookie").unwrap(), 0, 12)
            .unwrap(),
        b"fleet-cookie"
    );
    assert!(matches!(
        scoped.read(
            &FilesystemPath::new("workspace/default/private").unwrap(),
            0,
            64,
        ),
        Err(FilesystemError::NotFound(_))
    ));
}

#[cfg(any(unix, windows))]
mod authority_tests;
mod io_tests;
mod lifecycle_tests;
mod retained_worker_tests;

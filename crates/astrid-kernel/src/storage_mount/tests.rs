#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

use super::filesystem::CallbackFilesystem;
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
#[tokio::test]
async fn process_projection_cache_reuses_one_pair_until_last_close() {
    let cleanup_count = Arc::new(AtomicU64::new(0));
    let cleanup_count_for_projection = Arc::clone(&cleanup_count);
    let projection = Arc::new(CachedProcessProjection {
        workspace_mountpoint: PathBuf::from("/private/workspace"),
        home_mountpoint: PathBuf::from("/private/home"),
        fleet_shared_mountpoint: None,
        refs: AtomicU64::new(0),
        closing: AtomicBool::new(false),
        cleanup_failed: AtomicBool::new(false),
        cleanup: Arc::new(move || {
            let cleanup_count = Arc::clone(&cleanup_count_for_projection);
            Box::pin(async move {
                cleanup_count.fetch_add(1, Ordering::AcqRel);
                true
            })
        }),
    });
    let cache = Arc::new(tokio::sync::Mutex::new(std::collections::BTreeMap::new()));
    let key = ProcessProjectionKey {
        principal_uid: astrid_core::PrincipalUid::from_bytes([0xA1; 32]),
        owner: StateOwner::Principal(astrid_core::PrincipalUid::from_bytes([0xA1; 32])),
        branch: astrid_core::WorkspaceUid::from_bytes([0xB2; 16]),
        read_write: true,
    };
    cache.lock().await.insert(key, Arc::clone(&projection));

    let mut tasks = Vec::new();
    for _ in 0..100 {
        let projection = Arc::clone(&projection);
        let cache = Arc::clone(&cache);
        tasks.push(tokio::spawn(async move {
            cached_projection_mount(projection, cache, key)
                .await
                .expect("cached projection mount")
        }));
    }
    let mut mounts = Vec::new();
    for task in tasks {
        mounts.push(task.await.expect("projection task"));
    }
    assert_eq!(projection.refs.load(Ordering::Acquire), 100);
    assert!(
        mounts
            .iter()
            .all(|mount| mount.workspace_root.as_path() == Path::new("/private/workspace"))
    );
    assert!(
        mounts
            .iter()
            .all(|mount| mount.home_root.as_path() == Path::new("/private/home"))
    );

    let closes = mounts
        .into_iter()
        .map(|mount| tokio::spawn(mount.close_async()))
        .collect::<Vec<_>>();
    for close in closes {
        close.await.expect("projection close task");
    }
    assert_eq!(cleanup_count.load(Ordering::Acquire), 1);
    assert!(cache.lock().await.is_empty());
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn last_close_refuses_remount_while_projection_is_closing() {
    let release = Arc::new(tokio::sync::Notify::new());
    let entered = Arc::new(tokio::sync::Notify::new());
    let projection = Arc::new(CachedProcessProjection {
        workspace_mountpoint: PathBuf::from("/private/workspace-close"),
        home_mountpoint: PathBuf::from("/private/home-close"),
        fleet_shared_mountpoint: None,
        refs: AtomicU64::new(0),
        closing: AtomicBool::new(false),
        cleanup_failed: AtomicBool::new(false),
        cleanup: {
            let release = Arc::clone(&release);
            let entered = Arc::clone(&entered);
            Arc::new(move || {
                let release = Arc::clone(&release);
                let entered = Arc::clone(&entered);
                Box::pin(async move {
                    entered.notify_one();
                    release.notified().await;
                    true
                })
            })
        },
    });
    let cache = Arc::new(tokio::sync::Mutex::new(std::collections::BTreeMap::new()));
    let key = ProcessProjectionKey {
        principal_uid: astrid_core::PrincipalUid::from_bytes([0xA3; 32]),
        owner: StateOwner::Principal(astrid_core::PrincipalUid::from_bytes([0xA3; 32])),
        branch: astrid_core::WorkspaceUid::from_bytes([0xB4; 16]),
        read_write: true,
    };
    cache.lock().await.insert(key, Arc::clone(&projection));

    let mount = cached_projection_mount(Arc::clone(&projection), Arc::clone(&cache), key)
        .await
        .expect("initial mount");
    let close = tokio::spawn(mount.close_async());
    entered.notified().await;
    assert!(projection.closing.load(Ordering::Acquire));
    let Err(error) =
        cached_projection_mount(Arc::clone(&projection), Arc::clone(&cache), key).await
    else {
        panic!("remount during last-close must fail closed");
    };
    assert!(error.contains("closing"));
    release.notify_one();
    close.await.expect("projection close task");
    assert!(cache.lock().await.is_empty());
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn failed_projection_cleanup_retries_before_new_mount() {
    let attempts = Arc::new(AtomicU64::new(0));
    let attempts_for_projection = Arc::clone(&attempts);
    let projection = Arc::new(CachedProcessProjection {
        workspace_mountpoint: PathBuf::from("/private/workspace-retry"),
        home_mountpoint: PathBuf::from("/private/home-retry"),
        fleet_shared_mountpoint: None,
        refs: AtomicU64::new(0),
        closing: AtomicBool::new(false),
        cleanup_failed: AtomicBool::new(false),
        cleanup: Arc::new(move || {
            let attempts = Arc::clone(&attempts_for_projection);
            Box::pin(async move { attempts.fetch_add(1, Ordering::AcqRel) >= 1 })
        }),
    });
    let cache = Arc::new(tokio::sync::Mutex::new(std::collections::BTreeMap::new()));
    let key = ProcessProjectionKey {
        principal_uid: astrid_core::PrincipalUid::from_bytes([0xA2; 32]),
        owner: StateOwner::Principal(astrid_core::PrincipalUid::from_bytes([0xA2; 32])),
        branch: astrid_core::WorkspaceUid::from_bytes([0xB3; 16]),
        read_write: true,
    };
    cache.lock().await.insert(key, Arc::clone(&projection));

    let mount = cached_projection_mount(Arc::clone(&projection), Arc::clone(&cache), key)
        .await
        .expect("cached projection mount");
    mount.close_async().await;
    assert!(projection.cleanup_failed.load(Ordering::Acquire));
    assert!(cache.lock().await.contains_key(&key));

    assert!(retry_failed_projection(&projection, &cache, key).await);
    assert_eq!(attempts.load(Ordering::Acquire), 2);
    assert!(cache.lock().await.is_empty());
}

#[cfg(any(unix, windows))]
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
    assert!(!lease.callback_path.exists());
    let fenced = execute_operation(&kernel, &state, create("after-revoke.txt")).await;
    assert!(matches!(
        fenced,
        StorageFilesystemOutcomeV1::Failure(StorageFilesystemFailureV1 { code, .. })
            if code == "stale-lease"
    ));
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
    assert!(!lease.callback_path.exists());
    assert!(!lease.resource_path.exists());
}

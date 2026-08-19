use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::{Arc, Mutex};

use astrid_core::storage_filesystem::{
    STORAGE_FILESYSTEM_PROTOCOL_V2, StorageFilesystemEntryKindV1, StorageFilesystemEntryV1,
    StorageFilesystemFailureV1, StorageFilesystemOperationV1, StorageFilesystemOperationV2,
    StorageFilesystemOutcomeV2, StorageFilesystemRequestV2, StorageFilesystemResponseV2,
    StorageFilesystemSuccessV1, StorageFilesystemSuccessV2, StorageMountLeaseV1,
};
use astrid_core::storage_provider::{
    StorageMountId, StorageProviderAccessV1, StorageProviderViewV1,
};
use base64::Engine as _;

use super::filesystem::CallbackFs;
use super::*;

type FakeState = Arc<Mutex<BTreeMap<String, (StorageFilesystemEntryKindV1, Vec<u8>)>>>;

#[test]
fn winfsp_drive_root_is_passed_as_a_drive_designator() {
    assert_eq!(
        native_mountpoint(Path::new("Q:\\")).unwrap(),
        Path::new("Q:")
    );
    assert!(is_drive_designator(Path::new("Q:")));
    assert_eq!(
        native_mountpoint(Path::new(r"C:\mounts\astrid")).unwrap(),
        Path::new(r"C:\mounts\astrid")
    );
}

#[test]
fn native_winfsp_translates_filesystem_operations() {
    if std::env::var_os("ASTRID_WINFSP_NATIVE_TEST").is_none() {
        eprintln!("skipping native WinFsp runtime test; set ASTRID_WINFSP_NATIVE_TEST=1");
        return;
    }

    // Mirror daemon startup before touching any delay-loaded WinFsp symbol. The
    // developer import library is sufficient to link this test, but the runtime
    // DLL lives under WinFsp's registered installation directory rather than on
    // the test process PATH.
    initialize_winfsp().expect("initialize installed WinFsp runtime");

    let temporary = tempfile::tempdir().expect("temporary WinFsp directory");
    let callback_path = temporary.path().join("callback.endpoint");
    let mountpoint = temporary.path().join("mount");
    assert!(mountpoint.symlink_metadata().is_err());
    let state: FakeState = Arc::new(Mutex::new(BTreeMap::new()));
    let server_runtime = tokio::runtime::Runtime::new().expect("fake callback runtime");
    let listener = {
        let _runtime_guard = server_runtime.enter();
        Arc::new(local_transport::bind(&callback_path).expect("fake callback"))
    };
    let server = server_runtime.spawn(fake_callback_server(
        Arc::clone(&listener),
        Arc::clone(&state),
    ));
    let runtime = Arc::new(tokio::runtime::Runtime::new().expect("callback runtime"));
    let lease = StorageMountLeaseV1 {
        mount_id: StorageMountId::new(),
        view: StorageProviderViewV1::Admin,
        access: StorageProviderAccessV1::ReadWrite,
        resource_path: temporary.path().join("resource"),
        callback_path: callback_path.clone(),
        lease_token: "native-test-token".to_owned(),
        expires_at_epoch_secs: u64::MAX,
    };
    let callback = CallbackFs::new(lease, runtime).expect("build callback filesystem");
    let native_mountpoint =
        U16CString::from_os_str(mountpoint.as_os_str()).expect("mountpoint UTF-16");
    let filesystem = FileSystem::start(
        volume_params(StorageProviderAccessV1::ReadWrite),
        Some(&native_mountpoint),
        callback,
    )
    .expect("start native WinFsp filesystem");
    wait_for_mountpoint_ready(&mountpoint).expect("wait for native WinFsp mountpoint");

    std::fs::write(mountpoint.join("hello.txt"), b"astrid").expect("write through WinFsp");
    assert_eq!(
        std::fs::read(mountpoint.join("hello.txt")).expect("read through WinFsp"),
        b"astrid"
    );
    std::fs::create_dir(mountpoint.join("notes")).expect("create directory");
    std::fs::rename(
        mountpoint.join("hello.txt"),
        mountpoint.join("notes").join("greeting.txt"),
    )
    .expect("rename through WinFsp");
    assert!(mountpoint.join("hello.txt").symlink_metadata().is_err());
    assert_eq!(
        std::fs::read(mountpoint.join("notes").join("greeting.txt")).expect("read renamed file"),
        b"astrid"
    );

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(mountpoint.join("notes").join("greeting.txt"))
        .expect("open for append");
    file.write_all(b" filesystem").expect("append");
    file.set_len(20).expect("truncate through WinFsp");
    file.sync_all().expect("sync through WinFsp");
    drop(file);
    assert_eq!(
        std::fs::metadata(mountpoint.join("notes").join("greeting.txt"))
            .expect("renamed metadata")
            .len(),
        20
    );

    let root_names = std::fs::read_dir(&mountpoint)
        .expect("enumerate root")
        .map(|entry| {
            entry
                .expect("root entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(root_names, vec!["notes".to_owned()]);
    std::fs::remove_file(mountpoint.join("notes").join("greeting.txt"))
        .expect("remove through WinFsp");
    assert!(
        mountpoint
            .join("notes")
            .join("greeting.txt")
            .symlink_metadata()
            .is_err()
    );

    filesystem.stop();
    assert!(
        mountpoint.symlink_metadata().is_err(),
        "WinFsp must remove the owned mountpoint leaf after stop"
    );
    server.abort();
    drop(server_runtime);
}

async fn fake_callback_server(listener: Arc<local_transport::LocalListener>, state: FakeState) {
    loop {
        let Ok(mut stream) = local_transport::accept(&listener).await else {
            break;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut length = [0_u8; 4];
            if stream.read_exact(&mut length).await.is_err() {
                return;
            }
            let request_length =
                usize::try_from(u32::from_be_bytes(length)).expect("bounded request length");
            let mut request = vec![0_u8; request_length];
            if stream.read_exact(&mut request).await.is_err() {
                return;
            }
            let Ok(request) = serde_json::from_slice::<StorageFilesystemRequestV2>(&request) else {
                return;
            };
            let outcome = if request.lease_token.as_str() == "native-test-token" {
                match decode_fake_operation(request.operation)
                    .and_then(|operation| fake_apply(&state, operation))
                {
                    Ok(success) => {
                        StorageFilesystemOutcomeV2::Success(encode_fake_success(success))
                    },
                    Err((code, message)) => fake_failure(&code, &message),
                }
            } else {
                fake_failure("unauthorized", "invalid test token")
            };
            let response = StorageFilesystemResponseV2 {
                protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V2,
                request_id: request.request_id,
                outcome,
            };
            let Ok(bytes) = serde_json::to_vec(&response) else {
                return;
            };
            let Ok(length) = u32::try_from(bytes.len()) else {
                return;
            };
            if stream.write_all(&length.to_be_bytes()).await.is_err() {
                return;
            }
            if stream.write_all(&bytes).await.is_err() {
                return;
            }
            let _ = stream.flush().await;
        });
    }
}

fn fake_failure(code: &str, message: &str) -> StorageFilesystemOutcomeV2 {
    StorageFilesystemOutcomeV2::Failure(StorageFilesystemFailureV1 {
        code: code.to_owned(),
        message: message.to_owned(),
    })
}

fn decode_fake_operation(
    operation: StorageFilesystemOperationV2,
) -> Result<StorageFilesystemOperationV1, (String, String)> {
    Ok(match operation {
        StorageFilesystemOperationV2::Stat { path } => StorageFilesystemOperationV1::Stat { path },
        StorageFilesystemOperationV2::ReadDirectory { path } => {
            StorageFilesystemOperationV1::ReadDirectory { path }
        },
        StorageFilesystemOperationV2::Read {
            path,
            offset,
            length,
        } => StorageFilesystemOperationV1::Read {
            path,
            offset,
            length,
        },
        StorageFilesystemOperationV2::Write {
            path,
            offset,
            data_base64,
        } => {
            let data = base64::engine::general_purpose::STANDARD
                .decode(data_base64.as_bytes())
                .map_err(|error| ("invalid-data".to_owned(), error.to_string()))?;
            StorageFilesystemOperationV1::Write { path, offset, data }
        },
        StorageFilesystemOperationV2::SetLength { path, length } => {
            StorageFilesystemOperationV1::SetLength { path, length }
        },
        StorageFilesystemOperationV2::Create { path, kind } => {
            StorageFilesystemOperationV1::Create { path, kind }
        },
        StorageFilesystemOperationV2::Remove { path } => {
            StorageFilesystemOperationV1::Remove { path }
        },
        StorageFilesystemOperationV2::Rename { from, to, replace } => {
            StorageFilesystemOperationV1::Rename { from, to, replace }
        },
        StorageFilesystemOperationV2::Sync => StorageFilesystemOperationV1::Sync,
    })
}

fn encode_fake_success(success: StorageFilesystemSuccessV1) -> StorageFilesystemSuccessV2 {
    match success {
        StorageFilesystemSuccessV1::Done => StorageFilesystemSuccessV2::Done,
        StorageFilesystemSuccessV1::Entry(entry) => StorageFilesystemSuccessV2::Entry(entry),
        StorageFilesystemSuccessV1::Entries(entries) => {
            StorageFilesystemSuccessV2::Entries(entries)
        },
        StorageFilesystemSuccessV1::Data(data) => StorageFilesystemSuccessV2::Data {
            data_base64: base64::engine::general_purpose::STANDARD.encode(data),
        },
        StorageFilesystemSuccessV1::Written(length) => StorageFilesystemSuccessV2::Written(length),
    }
}

#[allow(clippy::too_many_lines)]
fn fake_apply(
    state: &FakeState,
    operation: StorageFilesystemOperationV1,
) -> Result<StorageFilesystemSuccessV1, (String, String)> {
    let mut entries = state
        .lock()
        .map_err(|_| ("internal".to_owned(), "test state poisoned".to_owned()))?;
    match operation {
        StorageFilesystemOperationV1::Stat { path } => {
            if path.is_empty() {
                return Ok(StorageFilesystemSuccessV1::Entry(fake_entry(
                    "",
                    StorageFilesystemEntryKindV1::Directory,
                    0,
                )));
            }
            let (_, bytes) = entries
                .get(&path)
                .ok_or_else(|| ("not-found".to_owned(), path.clone()))?;
            Ok(StorageFilesystemSuccessV1::Entry(fake_entry(
                path.rsplit('/').next().unwrap_or(&path),
                entries[&path].0,
                u64::try_from(bytes.len()).expect("bounded test file length"),
            )))
        },
        StorageFilesystemOperationV1::Create { path, kind } => {
            if entries.contains_key(&path) {
                return Err(("already-exists".to_owned(), path));
            }
            entries.insert(path, (kind, Vec::new()));
            Ok(StorageFilesystemSuccessV1::Done)
        },
        StorageFilesystemOperationV1::Read {
            path,
            offset,
            length,
        } => {
            let bytes = entries
                .get(&path)
                .ok_or_else(|| ("not-found".to_owned(), path.clone()))?
                .1
                .clone();
            let byte_length = u64::try_from(bytes.len()).expect("bounded test file length");
            let start = usize::try_from(offset.min(byte_length)).expect("bounded offset");
            let end = usize::try_from(offset.saturating_add(length).min(byte_length))
                .expect("bounded read end");
            Ok(StorageFilesystemSuccessV1::Data(bytes[start..end].to_vec()))
        },
        StorageFilesystemOperationV1::Write { path, offset, data } => {
            let (_, bytes) = entries
                .get_mut(&path)
                .ok_or_else(|| ("not-found".to_owned(), path.clone()))?;
            let data_length = u64::try_from(data.len()).expect("bounded test write length");
            let end = usize::try_from(
                offset
                    .checked_add(data_length)
                    .expect("bounded test write end"),
            )
            .expect("bounded test write end");
            if end > bytes.len() {
                bytes.resize(end, 0);
            }
            let start = usize::try_from(offset).expect("bounded test offset");
            bytes[start..end].copy_from_slice(&data);
            Ok(StorageFilesystemSuccessV1::Written(
                u64::try_from(bytes.len()).expect("bounded test file length"),
            ))
        },
        StorageFilesystemOperationV1::SetLength { path, length } => {
            let (_, bytes) = entries
                .get_mut(&path)
                .ok_or_else(|| ("not-found".to_owned(), path.clone()))?;
            bytes.resize(usize::try_from(length).expect("bounded test length"), 0);
            Ok(StorageFilesystemSuccessV1::Done)
        },
        StorageFilesystemOperationV1::Remove { path } => {
            entries
                .remove(&path)
                .ok_or_else(|| ("not-found".to_owned(), path.clone()))?;
            Ok(StorageFilesystemSuccessV1::Done)
        },
        StorageFilesystemOperationV1::Rename {
            from,
            to,
            replace: _,
        } => {
            let value = entries
                .remove(&from)
                .ok_or_else(|| ("not-found".to_owned(), from.clone()))?;
            entries.insert(to, value);
            Ok(StorageFilesystemSuccessV1::Done)
        },
        StorageFilesystemOperationV1::Sync => Ok(StorageFilesystemSuccessV1::Done),
        StorageFilesystemOperationV1::ReadDirectory { path } => {
            let prefix = if path.is_empty() {
                String::new()
            } else {
                format!("{path}/")
            };
            let children = entries
                .iter()
                .filter(|(name, _)| {
                    name.starts_with(&prefix)
                        && name[prefix.len()..]
                            .split('/')
                            .next()
                            .is_some_and(|segment| !segment.is_empty())
                        && !name[prefix.len()..].contains('/')
                })
                .map(|(name, (kind, bytes))| {
                    fake_entry(
                        name.rsplit('/').next().unwrap_or(name),
                        *kind,
                        bytes.len() as u64,
                    )
                })
                .collect::<Vec<_>>();
            Ok(StorageFilesystemSuccessV1::Entries(children))
        },
    }
}

fn fake_entry(
    name: &str,
    kind: StorageFilesystemEntryKindV1,
    logical_bytes: u64,
) -> StorageFilesystemEntryV1 {
    StorageFilesystemEntryV1 {
        name: name.to_owned(),
        kind,
        logical_bytes,
    }
}

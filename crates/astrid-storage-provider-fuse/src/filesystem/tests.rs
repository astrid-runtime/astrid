#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::if_not_else,
    clippy::let_and_return,
    clippy::manual_assert,
    clippy::match_same_arms,
    clippy::too_many_lines,
    clippy::unwrap_used
)]
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{Arc, Mutex};

use astrid_core::PrincipalId;
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
use uuid::Uuid;

use super::{AstridFuseFilesystem, CALLBACK_CHUNK_BYTES, InodeTable, join_path, start_session};
use crate::callback::{CallbackClient, CallbackError, callback_errno};

const TOKEN: &str = "fuse-test-lease-token";

#[derive(Clone, Debug, Default)]
struct FakeFilesystem {
    files: BTreeMap<String, Vec<u8>>,
    directories: BTreeSet<String>,
}
#[derive(Clone, Debug, Default)]
struct CallbackTelemetry {
    maximum_read: usize,
    maximum_write: usize,
    authenticated_calls: usize,
    rejected_calls: usize,
}

fn entry(
    path: &str,
    kind: StorageFilesystemEntryKindV1,
    length: u64,
) -> StorageFilesystemEntryV1 {
    let name = path.rsplit('/').next().unwrap_or(path);
    StorageFilesystemEntryV1 {
        name: if path.is_empty() {
            "/".to_owned()
        } else {
            name.to_owned()
        },
        kind,
        logical_bytes: length,
    }
}

fn parent(path: &str) -> String {
    match path.rfind('/') {
        None | Some(0) => String::new(),
        Some(index) => path[..index].to_owned(),
    }
}

fn fake_operation(
    state: &FakeFilesystem,
    operation: StorageFilesystemOperationV1,
) -> Result<StorageFilesystemSuccessV1, StorageFilesystemFailureV1> {
    let result = match operation {
        StorageFilesystemOperationV1::Stat { path } => {
            if let Some(data) = state.files.get(&path) {
                Ok(StorageFilesystemSuccessV1::Entry(entry(
                    &path,
                    StorageFilesystemEntryKindV1::File,
                    data.len() as u64,
                )))
            } else if state.directories.contains(&path) {
                Ok(StorageFilesystemSuccessV1::Entry(entry(
                    &path,
                    StorageFilesystemEntryKindV1::Directory,
                    0,
                )))
            } else {
                return Err(failure_detail("not-found", "entry does not exist"));
            }
        },
        StorageFilesystemOperationV1::ReadDirectory { path } => {
            if !state.directories.contains(&path) {
                return Err(failure_detail("not-found", "directory does not exist"));
            }
            let mut entries = Vec::new();
            for (child, data) in &state.files {
                if parent(child) == path {
                    entries.push(entry(
                        child,
                        StorageFilesystemEntryKindV1::File,
                        data.len() as u64,
                    ));
                }
            }
            for child in &state.directories {
                if parent(child) == path {
                    entries.push(entry(child, StorageFilesystemEntryKindV1::Directory, 0));
                }
            }
            Ok(StorageFilesystemSuccessV1::Entries(entries))
        },
        StorageFilesystemOperationV1::Read {
            path,
            offset,
            length,
        } => {
            let Some(data) = state.files.get(&path) else {
                return Err(failure_detail("not-found", "file does not exist"));
            };
            let start = usize::try_from(offset).unwrap_or(data.len());
            let end = start.saturating_add(usize::try_from(length).unwrap_or(0));
            let bytes = data.get(start..end).unwrap_or(&[]).to_vec();
            Ok(StorageFilesystemSuccessV1::Data(bytes))
        },
        StorageFilesystemOperationV1::Write { path, offset, data } => {
            let Some(file) = state.files.get(&path) else {
                return Err(failure_detail("not-found", "file does not exist"));
            };
            let mut updated = file.clone();
            let start = usize::try_from(offset).unwrap_or(updated.len());
            let end = start.saturating_add(data.len());
            if updated.len() < end {
                updated.resize(end, 0);
            }
            if start <= updated.len() {
                updated[start..end].copy_from_slice(&data);
            }
            Ok(StorageFilesystemSuccessV1::Written(updated.len() as u64))
        },
        StorageFilesystemOperationV1::SetLength { path, length } => {
            let Some(file) = state.files.get(&path) else {
                return Err(failure_detail("not-found", "file does not exist"));
            };
            let mut updated = file.clone();
            updated.resize(usize::try_from(length).unwrap_or(usize::MAX), 0);
            Ok(StorageFilesystemSuccessV1::Written(updated.len() as u64))
        },
        StorageFilesystemOperationV1::Create { path, kind } => {
            if state.files.contains_key(&path) || state.directories.contains(&path) {
                return Err(failure_detail("already-exists", "entry already exists"));
            }
            if !state.directories.contains(&parent(&path)) {
                return Err(failure_detail("not-directory", "parent does not exist"));
            }
            match kind {
                StorageFilesystemEntryKindV1::File => Ok(StorageFilesystemSuccessV1::Done),
                StorageFilesystemEntryKindV1::Directory => Ok(StorageFilesystemSuccessV1::Done),
            }
        },
        StorageFilesystemOperationV1::Remove { path } => {
            if state.directories.contains(&path)
                && (state.files.keys().any(|child| parent(child) == path)
                    || state.directories.iter().any(|child| parent(child) == path))
            {
                Err(failure_detail(
                    "directory-not-empty",
                    "directory is not empty",
                ))
            } else if state.files.contains_key(&path) || state.directories.contains(&path) {
                Ok(StorageFilesystemSuccessV1::Done)
            } else {
                Err(failure_detail("not-found", "entry does not exist"))
            }
        },
        StorageFilesystemOperationV1::Rename { from, to, replace } => {
            if !state.files.contains_key(&from) && !state.directories.contains(&from) {
                return Err(failure_detail("not-found", "source does not exist"));
            }
            if state.files.contains_key(&to) && !replace {
                return Err(failure_detail("already-exists", "destination exists"));
            }
            Ok(StorageFilesystemSuccessV1::Done)
        },
        StorageFilesystemOperationV1::Sync => Ok(StorageFilesystemSuccessV1::Done),
    };
    result
}

fn failure(code: &str, message: &str) -> StorageFilesystemOutcomeV2 {
    StorageFilesystemOutcomeV2::Failure(failure_detail(code, message))
}

fn failure_detail(code: &str, message: &str) -> StorageFilesystemFailureV1 {
    StorageFilesystemFailureV1 {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

fn decode_operation(operation: StorageFilesystemOperationV2) -> StorageFilesystemOperationV1 {
    match operation {
        StorageFilesystemOperationV2::Stat { path } => {
            StorageFilesystemOperationV1::Stat { path }
        },
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
        } => StorageFilesystemOperationV1::Write {
            path,
            offset,
            data: base64::engine::general_purpose::STANDARD
                .decode(data_base64)
                .expect("decode fake callback payload"),
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
    }
}

fn encode_success(success: StorageFilesystemSuccessV1) -> StorageFilesystemSuccessV2 {
    match success {
        StorageFilesystemSuccessV1::Done => StorageFilesystemSuccessV2::Done,
        StorageFilesystemSuccessV1::Entry(entry) => StorageFilesystemSuccessV2::Entry(entry),
        StorageFilesystemSuccessV1::Entries(entries) => {
            StorageFilesystemSuccessV2::Entries(entries)
        },
        StorageFilesystemSuccessV1::Data(data) => StorageFilesystemSuccessV2::Data {
            data_base64: base64::engine::general_purpose::STANDARD.encode(data),
        },
        StorageFilesystemSuccessV1::Written(length) => {
            StorageFilesystemSuccessV2::Written(length)
        },
    }
}

#[allow(clippy::too_many_lines)]
fn spawn_fake_callback(
    path: &Path,
    state: FakeFilesystem,
) -> (Arc<Mutex<FakeFilesystem>>, Arc<Mutex<CallbackTelemetry>>) {
    let state = Arc::new(Mutex::new(state));
    let telemetry = Arc::new(Mutex::new(CallbackTelemetry::default()));
    let listener = UnixListener::bind(path).expect("bind fake callback socket");
    let callback_state = Arc::clone(&state);
    let callback_telemetry = Arc::clone(&telemetry);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            let mut length = [0_u8; 4];
            if stream.read_exact(&mut length).is_err() {
                break;
            }
            let length = u32::from_be_bytes(length) as usize;
            let mut bytes = vec![0_u8; length];
            if stream.read_exact(&mut bytes).is_err() {
                break;
            }
            let request: StorageFilesystemRequestV2 =
                serde_json::from_slice(&bytes).expect("decode fake callback request");
            assert_eq!(request.protocol_version, STORAGE_FILESYSTEM_PROTOCOL_V2);
            let operation = decode_operation(request.operation);
            let outcome = if request.lease_token != TOKEN {
                callback_telemetry.lock().unwrap().rejected_calls += 1;
                failure("unauthorized", "invalid lease token")
            } else {
                let maximum_read = match &operation {
                    StorageFilesystemOperationV1::Read { length, .. } => Some(*length),
                    _ => None,
                };
                let maximum_write = match &operation {
                    StorageFilesystemOperationV1::Write { data, .. } => Some(data.len() as u64),
                    _ => None,
                };
                {
                    let mut telemetry = callback_telemetry.lock().unwrap();
                    telemetry.authenticated_calls += 1;
                    telemetry.maximum_read = telemetry
                        .maximum_read
                        .max(maximum_read.unwrap_or(0) as usize);
                    telemetry.maximum_write = telemetry
                        .maximum_write
                        .max(maximum_write.unwrap_or(0) as usize);
                }
                let mut state = callback_state.lock().unwrap();
                match fake_operation(&state, operation.clone()) {
                    Ok(success) => {
                        apply_fake_mutation(&mut state, &operation);
                        StorageFilesystemOutcomeV2::Success(encode_success(success))
                    },
                    Err(failure) => StorageFilesystemOutcomeV2::Failure(failure),
                }
            };
            let response = StorageFilesystemResponseV2 {
                protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V2,
                request_id: request.request_id,
                outcome,
            };
            let bytes = serde_json::to_vec(&response).expect("encode fake callback response");
            let length = u32::try_from(bytes.len()).expect("bounded fake response");
            stream
                .write_all(&length.to_be_bytes())
                .expect("write length");
            stream.write_all(&bytes).expect("write fake response");
        }
    });
    (state, telemetry)
}

fn apply_fake_mutation(state: &mut FakeFilesystem, operation: &StorageFilesystemOperationV1) {
    match operation {
        StorageFilesystemOperationV1::Create { path, kind } => match kind {
            StorageFilesystemEntryKindV1::File => {
                state.files.insert(path.clone(), Vec::new());
            },
            StorageFilesystemEntryKindV1::Directory => {
                state.directories.insert(path.clone());
            },
        },
        StorageFilesystemOperationV1::Write { path, offset, data } => {
            if let Some(file) = state.files.get_mut(path) {
                let start = usize::try_from(*offset).unwrap_or(file.len());
                let end = start.saturating_add(data.len());
                if file.len() < end {
                    file.resize(end, 0);
                }
                file[start..end].copy_from_slice(data);
            }
        },
        StorageFilesystemOperationV1::SetLength { path, length } => {
            if let Some(file) = state.files.get_mut(path) {
                file.resize(usize::try_from(*length).unwrap_or(usize::MAX), 0);
            }
        },
        StorageFilesystemOperationV1::Remove { path } => {
            state.files.remove(path);
            state.directories.remove(path);
        },
        StorageFilesystemOperationV1::Rename { from, to, .. } => {
            if let Some(file) = state.files.remove(from) {
                state.files.insert(to.clone(), file);
            } else if state.directories.remove(from) {
                state.directories.insert(to.clone());
            }
        },
        _ => {},
    }
}

fn test_lease(callback_path: &Path, access: StorageProviderAccessV1) -> StorageMountLeaseV1 {
    StorageMountLeaseV1 {
        mount_id: StorageMountId::from_uuid(Uuid::new_v4()),
        view: StorageProviderViewV1::Principal(PrincipalId::default()),
        access,
        resource_path: callback_path.parent().unwrap().join("resource"),
        callback_path: callback_path.to_path_buf(),
        lease_token: TOKEN.to_owned(),
        expires_at_epoch_secs: u64::MAX,
    }
}

#[test]
fn callback_io_is_chunked_and_authenticated() {
    let temporary = tempfile::tempdir().unwrap();
    let callback_path = temporary.path().join("callback.sock");
    let mut fake = FakeFilesystem::default();
    fake.directories.insert(String::new());
    fake.files.insert(
        "large.bin".to_owned(),
        vec![0; CALLBACK_CHUNK_BYTES * 2 + 1024],
    );
    let (_state, telemetry) = spawn_fake_callback(&callback_path, fake);
    let lease = test_lease(&callback_path, StorageProviderAccessV1::ReadWrite);
    let filesystem = AstridFuseFilesystem::new(lease.clone());
    let data: Vec<_> = (0..(CALLBACK_CHUNK_BYTES * 2 + 1024))
        .map(|index| (index % 251) as u8)
        .collect();

    filesystem
        .write_range("large.bin", 0, &data)
        .expect("chunked FUSE write");
    let read = filesystem
        .read_range("large.bin", 0, u32::try_from(data.len()).unwrap())
        .expect("chunked FUSE read");

    assert_eq!(read, data);
    let telemetry = telemetry.lock().unwrap();
    assert!(telemetry.authenticated_calls >= 6);
    assert!(telemetry.maximum_write <= CALLBACK_CHUNK_BYTES);
    assert!(telemetry.maximum_read <= CALLBACK_CHUNK_BYTES);
    assert_eq!(telemetry.rejected_calls, 0);

    let mut unauthorized = lease;
    unauthorized.lease_token = "wrong-token".to_owned();
    let error = CallbackClient::new(unauthorized)
        .call(StorageFilesystemOperationV1::Stat {
            path: String::new(),
        })
        .expect_err("callback must reject an invalid bearer");
    assert!(matches!(error, CallbackError::Failure(_)));
    assert_eq!(
        callback_errno(error),
        fuser::Errno::EACCES,
        "unauthorized callback must map to EACCES"
    );
    assert_eq!(telemetry.rejected_calls, 1);
}

#[test]
fn native_paths_reject_traversal_and_alias_segments() {
    assert_eq!(join_path("", "file.txt").unwrap(), "file.txt");
    assert_eq!(join_path("dir", "file.txt").unwrap(), "dir/file.txt");
    assert!(super::valid_name(std::ffi::OsStr::new("..")).is_err());
    assert!(super::valid_name(std::ffi::OsStr::new("a/b")).is_err());
    assert!(super::valid_name(std::ffi::OsStr::new("")).is_err());
}

#[test]
fn directory_rename_updates_cached_descendant_inodes() {
    let mut inodes = InodeTable::default();
    let source = inodes.intern("old").unwrap();
    let child = inodes.intern("old/child").unwrap();
    let replaced = inodes.intern("new").unwrap();

    inodes.renamed("old", "new");

    assert_eq!(
        inodes.path(fuser::INodeNo(source)).map(String::as_str),
        Some("new")
    );
    assert_eq!(
        inodes.path(fuser::INodeNo(child)).map(String::as_str),
        Some("new/child")
    );
    assert!(inodes.path(fuser::INodeNo(replaced)).is_none());
}

#[test]
#[ignore = "requires a Linux kernel FUSE device; run with ASTRID_FUSE_E2E=1"]
fn linux_native_fuse_mount_supports_all_required_operations() {
    assert_eq!(
        std::env::var("ASTRID_FUSE_E2E").as_deref(),
        Ok("1"),
        "native E2E was selected but ASTRID_FUSE_E2E is not explicitly enabled"
    );
    if !Path::new("/dev/fuse").exists() {
        panic!("native E2E was selected but /dev/fuse is unavailable");
    }

    let temporary = tempfile::tempdir().unwrap();
    let callback_path = temporary.path().join("callback.sock");
    let mut fake = FakeFilesystem::default();
    fake.directories.insert(String::new());
    let (state, telemetry) = spawn_fake_callback(&callback_path, fake);
    let mountpoint = temporary.path().join("native-mount");
    std::fs::create_dir(&mountpoint).unwrap();
    std::fs::set_permissions(&mountpoint, std::fs::Permissions::from_mode(0o700)).unwrap();
    let lease = test_lease(&callback_path, StorageProviderAccessV1::ReadWrite);
    let session = start_session(lease, &mountpoint).expect("mount real Linux FUSE filesystem");

    assert!(crate::mountpoint::mountinfo_contains(&mountpoint).unwrap());
    std::fs::write(mountpoint.join("hello.txt"), b"Astrid FUSE").unwrap();
    assert_eq!(
        std::fs::read(mountpoint.join("hello.txt")).unwrap(),
        b"Astrid FUSE".to_vec()
    );
    std::fs::create_dir(mountpoint.join("directory")).unwrap();
    std::fs::rename(
        mountpoint.join("hello.txt"),
        mountpoint.join("directory").join("renamed.txt"),
    )
    .unwrap();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(mountpoint.join("directory").join("renamed.txt"))
        .unwrap();
    file.set_len(6).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert_eq!(
        std::fs::metadata(mountpoint.join("directory").join("renamed.txt"))
            .unwrap()
            .len(),
        6
    );
    assert!(std::fs::read_dir(&mountpoint).unwrap().count() >= 1);
    std::fs::remove_file(mountpoint.join("directory").join("renamed.txt")).unwrap();
    std::fs::remove_dir(mountpoint.join("directory")).unwrap();

    let fake_state = state.lock().unwrap();
    assert!(fake_state.files.is_empty());
    assert!(fake_state.directories.contains(""));
    drop(fake_state);
    let telemetry = telemetry.lock().unwrap();
    assert!(telemetry.authenticated_calls >= 10);
    assert_eq!(telemetry.rejected_calls, 0);
    drop(telemetry);
    session
        .umount_and_join()
        .expect("unmount real FUSE session");

    let readonly_mountpoint = temporary.path().join("read-only-mount");
    std::fs::create_dir(&readonly_mountpoint).unwrap();
    std::fs::set_permissions(&readonly_mountpoint, std::fs::Permissions::from_mode(0o700))
        .unwrap();
    let readonly_lease = test_lease(&callback_path, StorageProviderAccessV1::ReadOnly);
    let readonly_session = start_session(readonly_lease, &readonly_mountpoint)
        .expect("mount read-only Linux FUSE filesystem");
    let denied = std::fs::write(readonly_mountpoint.join("denied.txt"), b"denied")
        .expect_err("read-only mount must reject writes");
    assert_eq!(
        denied.raw_os_error(),
        Some(nix::errno::Errno::EROFS as i32),
        "read-only mount must return EROFS, got {denied}"
    );
    readonly_session
        .umount_and_join()
        .expect("unmount read-only FUSE session");
}

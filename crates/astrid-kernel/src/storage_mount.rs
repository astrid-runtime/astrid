//! Native filesystem lease lifecycle and private callback service.

use std::io::{self, Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use astrid_core::PrincipalId;
use astrid_core::storage_filesystem::{
    STORAGE_FILESYSTEM_MAX_IO_BYTES, STORAGE_FILESYSTEM_PROTOCOL_V1, StorageFilesystemEntryKindV1,
    StorageFilesystemEntryV1, StorageFilesystemFailureV1, StorageFilesystemOperationV1,
    StorageFilesystemOutcomeV1, StorageFilesystemRequestV1, StorageFilesystemResponseV1,
    StorageFilesystemSuccessV1, StorageMountLeaseV1,
};
use astrid_core::storage_provider::{
    StorageMountId, StorageProviderAccessV1, StorageProviderViewV1,
};
use astrid_storage::{
    AstridFilesystem, FilesystemEntry, FilesystemEntryKind, FilesystemError, FilesystemPath,
    StateOwner,
};
use base64::Engine as _;
use rand::{TryRng as _, rngs::SysRng};
use serde_json::json;
use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::watch;

use crate::Kernel;

const LEASE_IDLE_TTL_SECS: u64 = 60 * 60;
const MAX_CALLBACK_FRAME_BYTES: usize = 8 * 1024 * 1024;
const LEASE_MANIFEST_NAME: &str = "lease.json";

/// In-memory authority fixed when a native filesystem lease is issued.
pub(crate) struct StorageMountLeaseState {
    mount_id: StorageMountId,
    requested_by: PrincipalId,
    owner: StateOwner,
    view: StorageProviderViewV1,
    access: StorageProviderAccessV1,
    provider: String,
    mountpoint: PathBuf,
    resource_path: PathBuf,
    callback_path: PathBuf,
    token_hash: [u8; 32],
    expires_at_epoch_secs: AtomicU64,
    revoked: AtomicBool,
    dirty: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
}

impl StorageMountLeaseState {
    fn is_owned_by(&self, caller: &PrincipalId) -> bool {
        &self.requested_by == caller
    }

    fn is_live(&self) -> bool {
        !self.revoked.load(Ordering::Acquire)
            && now_epoch_secs() <= self.expires_at_epoch_secs.load(Ordering::Acquire)
    }

    fn renew(&self) {
        self.expires_at_epoch_secs.store(
            now_epoch_secs().saturating_add(LEASE_IDLE_TTL_SECS),
            Ordering::Release,
        );
    }

    fn public_lease(&self, token: String) -> StorageMountLeaseV1 {
        StorageMountLeaseV1 {
            mount_id: self.mount_id,
            view: self.view.clone(),
            access: self.access,
            resource_path: self.resource_path.clone(),
            callback_path: self.callback_path.clone(),
            lease_token: token,
            expires_at_epoch_secs: self.expires_at_epoch_secs.load(Ordering::Acquire),
        }
    }
}

/// Resolve and issue one native mount lease.
pub(crate) async fn issue_lease(
    kernel: &Arc<Kernel>,
    caller: PrincipalId,
    allow_cross_owner: bool,
    view: StorageProviderViewV1,
    access: StorageProviderAccessV1,
    provider: String,
    mountpoint: PathBuf,
) -> Result<StorageMountLeaseV1, String> {
    if provider.is_empty() || provider.len() > 128 || provider.chars().any(char::is_control) {
        return Err("native storage provider identity is invalid".to_owned());
    }
    if !mountpoint.is_absolute() {
        return Err("native storage mountpoint must be absolute".to_owned());
    }
    let owner = resolve_owner(kernel, &caller, allow_cross_owner, &view).await?;
    let mount_id = StorageMountId::new();
    #[cfg(unix)]
    let resource_path = private_mount_resource_path(mount_id)?;
    #[cfg(not(unix))]
    let resource_path = kernel
        .astrid_home
        .run_dir()
        .join("mounts")
        .join(mount_id.to_string());
    astrid_core::platform_fs::ensure_private_directory(&resource_path)
        .map_err(|error| format!("create private mount resource: {error}"))?;
    let (token, token_hash) = generate_lease_token()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    #[cfg(unix)]
    let callback_path = resource_path.join("control.sock");
    #[cfg(not(unix))]
    let callback_path = resource_path.join("control.endpoint");
    let state = Arc::new(StorageMountLeaseState {
        mount_id,
        requested_by: caller,
        owner,
        view,
        access,
        provider,
        mountpoint,
        resource_path: resource_path.clone(),
        callback_path: callback_path.clone(),
        token_hash,
        expires_at_epoch_secs: AtomicU64::new(now_epoch_secs().saturating_add(LEASE_IDLE_TTL_SECS)),
        revoked: AtomicBool::new(false),
        dirty: AtomicBool::new(false),
        shutdown_tx,
    });

    #[cfg(unix)]
    let listener = bind_private_listener(&callback_path)?;
    #[cfg(not(unix))]
    return Err("native mount callback transport is not implemented on this platform".to_owned());

    let lease = state.public_lease(token);
    write_private_manifest(&resource_path.join(LEASE_MANIFEST_NAME), &lease)
        .map_err(|error| format!("write private mount manifest: {error}"))?;
    kernel.storage_mounts.insert(mount_id, Arc::clone(&state));

    #[cfg(unix)]
    {
        let weak_kernel = Arc::downgrade(kernel);
        astrid_runtime::spawn(serve_listener(weak_kernel, state, listener, shutdown_rx));
    }
    Ok(lease)
}

/// Return non-secret status for a lease owned by the caller.
pub(crate) fn lease_status(
    kernel: &Kernel,
    caller: &PrincipalId,
    allow_cross_owner: bool,
    mount_id: StorageMountId,
) -> Result<serde_json::Value, String> {
    let state = owned_lease(kernel, caller, allow_cross_owner, mount_id)?;
    state.renew();
    Ok(json!({
        "mount_id": state.mount_id,
        "view": state.view,
        "access": state.access,
        "provider": state.provider,
        "mountpoint": state.mountpoint,
        "resource_path": state.resource_path,
        "callback_path": state.callback_path,
        "dirty": state.dirty.load(Ordering::Acquire),
        "expires_at_epoch_secs": state.expires_at_epoch_secs.load(Ordering::Acquire),
    }))
}

/// Flush one lease's authoritative owner store.
pub(crate) async fn sync_lease(
    kernel: &Kernel,
    caller: &PrincipalId,
    allow_cross_owner: bool,
    mount_id: StorageMountId,
) -> Result<(), String> {
    let state = owned_lease(kernel, caller, allow_cross_owner, mount_id)?;
    let store = kernel
        .principal_store
        .clone()
        .ok_or_else(|| "native principal store is unavailable".to_owned())?;
    let owner = state.owner;
    tokio::task::spawn_blocking(move || AstridFilesystem::new(store.content(), owner).sync())
        .await
        .map_err(|error| format!("mount sync worker failed: {error}"))?
        .map_err(|error| error.to_string())?;
    state.dirty.store(false, Ordering::Release);
    state.renew();
    Ok(())
}

/// Revoke one lease and retire its callback resource.
pub(crate) fn revoke_lease(
    kernel: &Kernel,
    caller: &PrincipalId,
    allow_cross_owner: bool,
    mount_id: StorageMountId,
) -> Result<(), String> {
    let state = owned_lease(kernel, caller, allow_cross_owner, mount_id)?;
    state.revoked.store(true, Ordering::Release);
    let _ = state.shutdown_tx.send(true);
    kernel.storage_mounts.remove(&mount_id);
    cleanup_resource(&state.resource_path, &state.callback_path);
    Ok(())
}

fn owned_lease(
    kernel: &Kernel,
    caller: &PrincipalId,
    allow_cross_owner: bool,
    mount_id: StorageMountId,
) -> Result<Arc<StorageMountLeaseState>, String> {
    let state = kernel
        .storage_mounts
        .get(&mount_id)
        .map(|entry| Arc::clone(entry.value()))
        .ok_or_else(|| format!("storage mount lease {mount_id} was not found"))?;
    if !state.is_owned_by(caller) && !allow_cross_owner {
        return Err("storage mount lease belongs to another principal".to_owned());
    }
    if !state.is_live() {
        return Err("storage mount lease is expired or revoked".to_owned());
    }
    Ok(state)
}

async fn resolve_owner(
    kernel: &Kernel,
    caller: &PrincipalId,
    allow_cross_owner: bool,
    view: &StorageProviderViewV1,
) -> Result<StateOwner, String> {
    match view {
        StorageProviderViewV1::Principal(principal) => {
            if principal != caller && !allow_cross_owner {
                return Err("principal filesystem view belongs to another principal".to_owned());
            }
            kernel
                .principal_directory
                .uid_for(principal)
                .map(StateOwner::Principal)
                .map_err(|error| {
                    format!("principal `{principal}` has no immutable storage identity: {error}")
                })
        },
        StorageProviderViewV1::Fleet(fleet) => {
            if !allow_cross_owner {
                let caller_uid = kernel
                    .principal_directory
                    .uid_for(caller)
                    .map_err(|error| {
                        format!("principal `{caller}` has no immutable storage identity: {error}")
                    })?;
                let ownership = kernel
                    .ownership_store()
                    .load()
                    .await
                    .map_err(|error| format!("read fleet ownership graph: {error}"))?;
                let admitted = ownership
                    .principal_owner(caller_uid)
                    .is_some_and(|owner| owner.fleet_uid == *fleet);
                if !admitted {
                    return Err(
                        "requested fleet filesystem is outside the caller's fleet".to_owned()
                    );
                }
            }
            Ok(StateOwner::Fleet(*fleet))
        },
        StorageProviderViewV1::Admin => {
            if !allow_cross_owner {
                return Err("system filesystem view requires global storage authority".to_owned());
            }
            Ok(StateOwner::System)
        },
    }
}

#[cfg(unix)]
fn bind_private_listener(callback_path: &Path) -> Result<tokio::net::UnixListener, String> {
    use std::os::unix::fs::PermissionsExt as _;

    let listener = tokio::net::UnixListener::bind(callback_path)
        .map_err(|error| format!("bind private mount callback socket: {error}"))?;
    std::fs::set_permissions(callback_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("restrict private mount callback socket: {error}"))?;
    Ok(listener)
}

#[cfg(unix)]
fn private_mount_resource_path(mount_id: StorageMountId) -> Result<PathBuf, String> {
    #[cfg(target_os = "macos")]
    let temporary_root = "/private/tmp";
    #[cfg(not(target_os = "macos"))]
    let temporary_root = "/tmp";
    let root =
        PathBuf::from(temporary_root).join(format!("astrid-mounts-{}", nix::unistd::getuid()));
    astrid_core::platform_fs::ensure_private_directory(&root)
        .map_err(|error| format!("create private mount resource root: {error}"))?;
    Ok(root.join(mount_id.to_string()))
}

#[cfg(unix)]
async fn serve_listener(
    kernel: std::sync::Weak<Kernel>,
    state: Arc<StorageMountLeaseState>,
    listener: tokio::net::UnixListener,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut expiry_check = tokio::time::interval(std::time::Duration::from_mins(1));
    expiry_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            _ = expiry_check.tick() => {
                if !state.is_live() {
                    state.revoked.store(true, Ordering::Release);
                    if let Some(kernel) = kernel.upgrade() {
                        kernel.storage_mounts.remove(&state.mount_id);
                    }
                    cleanup_resource(&state.resource_path, &state.callback_path);
                    break;
                }
            },
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                let Some(kernel) = kernel.upgrade() else { break };
                let state = Arc::clone(&state);
                astrid_runtime::spawn(async move {
                    handle_connection(kernel, state, stream).await;
                });
            }
        }
    }
}

#[cfg(unix)]
async fn handle_connection(
    kernel: Arc<Kernel>,
    state: Arc<StorageMountLeaseState>,
    mut stream: tokio::net::UnixStream,
) {
    loop {
        let Ok(Some(request)) = read_request(&mut stream).await else {
            return;
        };
        let response = dispatch_request(&kernel, &state, request).await;
        if write_response(&mut stream, &response).await.is_err() {
            return;
        }
    }
}

#[cfg(unix)]
async fn read_request(
    stream: &mut tokio::net::UnixStream,
) -> Result<Option<StorageFilesystemRequestV1>, io::Error> {
    let mut length = [0_u8; 4];
    match stream.read_exact(&mut length).await {
        Ok(_) => {},
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_CALLBACK_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mount callback frame exceeds limit",
        ));
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(io::Error::other)
}

#[cfg(unix)]
async fn write_response(
    stream: &mut tokio::net::UnixStream,
    response: &StorageFilesystemResponseV1,
) -> Result<(), io::Error> {
    let bytes = serde_json::to_vec(response).map_err(io::Error::other)?;
    let length = u32::try_from(bytes.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "mount callback response is too large",
        )
    })?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}

async fn dispatch_request(
    kernel: &Kernel,
    state: &StorageMountLeaseState,
    request: StorageFilesystemRequestV1,
) -> StorageFilesystemResponseV1 {
    let request_id = request.request_id.clone();
    let outcome = if request.protocol_version != STORAGE_FILESYSTEM_PROTOCOL_V1 {
        failure("protocol", "unsupported storage filesystem protocol")
    } else if !state.is_live() {
        failure("stale-lease", "storage mount lease is expired or revoked")
    } else if !token_matches(&state.token_hash, &request.lease_token) {
        failure("unauthorized", "storage mount lease token is invalid")
    } else {
        state.renew();
        execute_operation(kernel, state, request.operation).await
    };
    StorageFilesystemResponseV1 {
        protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V1,
        request_id,
        outcome,
    }
}

async fn execute_operation(
    kernel: &Kernel,
    state: &StorageMountLeaseState,
    operation: StorageFilesystemOperationV1,
) -> StorageFilesystemOutcomeV1 {
    if is_mutation(&operation) && state.access != StorageProviderAccessV1::ReadWrite {
        return failure("read-only", "storage mount lease is read-only");
    }
    let _mutation_guard = if is_mutation(&operation) {
        Some(kernel.storage_mount_mutations.lock().await)
    } else {
        None
    };
    let Some(store) = kernel.principal_store.clone() else {
        return failure("unavailable", "native principal store is unavailable");
    };
    let owner = state.owner;
    let result = tokio::task::spawn_blocking(move || {
        let filesystem = AstridFilesystem::new(store.content(), owner);
        execute_blocking(&filesystem, operation)
    })
    .await;
    match result {
        Ok(Ok(success)) => StorageFilesystemOutcomeV1::Success(success),
        Ok(Err(error)) => map_filesystem_error(&error),
        Err(error) => failure("internal", &format!("filesystem worker failed: {error}")),
    }
}

fn execute_blocking<E>(
    filesystem: &AstridFilesystem<StateOwner, E>,
    operation: StorageFilesystemOperationV1,
) -> Result<StorageFilesystemSuccessV1, FilesystemError>
where
    E: astrid_storage::engine::PrincipalProjectionEngine<StateOwner>,
{
    match operation {
        StorageFilesystemOperationV1::Stat { path } => {
            let path = FilesystemPath::new(path)?;
            Ok(StorageFilesystemSuccessV1::Entry(entry(
                &filesystem.stat(&path)?,
            )))
        },
        StorageFilesystemOperationV1::ReadDirectory { path } => {
            let path = FilesystemPath::new(path)?;
            Ok(StorageFilesystemSuccessV1::Entries(
                filesystem.read_dir(&path)?.iter().map(entry).collect(),
            ))
        },
        StorageFilesystemOperationV1::Read {
            path,
            offset,
            length,
        } => {
            if length > STORAGE_FILESYSTEM_MAX_IO_BYTES {
                return Err(FilesystemError::InvalidPath(path));
            }
            let path = FilesystemPath::new(path)?;
            let stat = filesystem.stat(&path)?;
            let available = stat.logical_bytes().saturating_sub(offset);
            let length = length.min(available);
            Ok(StorageFilesystemSuccessV1::Data(
                filesystem.read(&path, offset, length)?,
            ))
        },
        StorageFilesystemOperationV1::Write { path, offset, data } => {
            write_range(filesystem, path, offset, &data)
        },
        StorageFilesystemOperationV1::SetLength { path, length } => {
            let path = FilesystemPath::new(path)?;
            let current_length = require_file(filesystem, &path)?;
            if current_length == length {
                return Ok(StorageFilesystemSuccessV1::Written(length));
            }
            let mut staged = stage_existing_file(filesystem, &path, current_length)?;
            staged
                .set_len(length)
                .map_err(|error| staging_error(&error))?;
            staged
                .seek(io::SeekFrom::Start(0))
                .map_err(|error| staging_error(&error))?;
            filesystem.write_streaming(&path, staged)?;
            Ok(StorageFilesystemSuccessV1::Written(length))
        },
        StorageFilesystemOperationV1::Create { path, kind } => {
            let path = FilesystemPath::new(path)?;
            match kind {
                StorageFilesystemEntryKindV1::File => {
                    match filesystem.stat(&path) {
                        Ok(_) => return Err(FilesystemError::AlreadyExists(path)),
                        Err(FilesystemError::NotFound(_)) => {},
                        Err(error) => return Err(error),
                    }
                    filesystem.write(&path, &[])?;
                },
                StorageFilesystemEntryKindV1::Directory => filesystem.create_dir(&path)?,
            }
            Ok(StorageFilesystemSuccessV1::Done)
        },
        StorageFilesystemOperationV1::Remove { path } => {
            filesystem.remove(&FilesystemPath::new(path)?)?;
            Ok(StorageFilesystemSuccessV1::Done)
        },
        StorageFilesystemOperationV1::Rename { from, to, replace } => {
            let from = FilesystemPath::new(from)?;
            let to = FilesystemPath::new(to)?;
            if replace {
                filesystem.rename_replacing(&from, &to)?;
            } else {
                filesystem.rename(&from, &to)?;
            }
            Ok(StorageFilesystemSuccessV1::Done)
        },
        StorageFilesystemOperationV1::Sync => {
            filesystem.sync()?;
            Ok(StorageFilesystemSuccessV1::Done)
        },
    }
}

fn write_range<E>(
    filesystem: &AstridFilesystem<StateOwner, E>,
    path: String,
    offset: u64,
    data: &[u8],
) -> Result<StorageFilesystemSuccessV1, FilesystemError>
where
    E: astrid_storage::engine::PrincipalProjectionEngine<StateOwner>,
{
    let data_length = u64::try_from(data.len()).unwrap_or(u64::MAX);
    if data_length > STORAGE_FILESYSTEM_MAX_IO_BYTES {
        return Err(FilesystemError::InvalidPath(path));
    }
    let path = FilesystemPath::new(path)?;
    let current_length = require_file(filesystem, &path)?;
    if data.is_empty() {
        return Ok(StorageFilesystemSuccessV1::Written(current_length));
    }
    let end = offset
        .checked_add(data_length)
        .ok_or_else(|| FilesystemError::InvalidPath(path.as_str().to_owned()))?;
    let mut staged = stage_existing_file(filesystem, &path, current_length)?;
    staged
        .seek(io::SeekFrom::Start(offset))
        .map_err(|error| staging_error(&error))?;
    staged
        .write_all(data)
        .map_err(|error| staging_error(&error))?;
    staged
        .seek(io::SeekFrom::Start(0))
        .map_err(|error| staging_error(&error))?;
    filesystem.write_streaming(&path, staged)?;
    Ok(StorageFilesystemSuccessV1::Written(current_length.max(end)))
}

fn require_file<E>(
    filesystem: &AstridFilesystem<StateOwner, E>,
    path: &FilesystemPath,
) -> Result<u64, FilesystemError>
where
    E: astrid_storage::engine::PrincipalProjectionEngine<StateOwner>,
{
    let stat = filesystem.stat(path)?;
    if stat.kind() != FilesystemEntryKind::File {
        return Err(FilesystemError::IsDirectory(path.clone()));
    }
    Ok(stat.logical_bytes())
}

fn stage_existing_file<E>(
    filesystem: &AstridFilesystem<StateOwner, E>,
    path: &FilesystemPath,
    length: u64,
) -> Result<std::fs::File, FilesystemError>
where
    E: astrid_storage::engine::PrincipalProjectionEngine<StateOwner>,
{
    let mut staged = tempfile::tempfile().map_err(|error| staging_error(&error))?;
    let mut offset = 0_u64;
    while offset < length {
        let wanted = length
            .checked_sub(offset)
            .ok_or_else(|| FilesystemError::InvalidPath(path.as_str().to_owned()))?
            .min(STORAGE_FILESYSTEM_MAX_IO_BYTES);
        let bytes = filesystem.read(path, offset, wanted)?;
        if bytes.is_empty() {
            return Err(FilesystemError::InvalidPath(path.as_str().to_owned()));
        }
        staged
            .write_all(&bytes)
            .map_err(|error| staging_error(&error))?;
        offset = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| FilesystemError::InvalidPath(path.as_str().to_owned()))?;
    }
    Ok(staged)
}

fn staging_error(error: &io::Error) -> FilesystemError {
    FilesystemError::Staging(error.to_string())
}

fn entry(value: &FilesystemEntry) -> StorageFilesystemEntryV1 {
    StorageFilesystemEntryV1 {
        name: value.name().to_owned(),
        kind: match value.kind() {
            FilesystemEntryKind::File => StorageFilesystemEntryKindV1::File,
            FilesystemEntryKind::Directory => StorageFilesystemEntryKindV1::Directory,
        },
        logical_bytes: value.logical_bytes(),
    }
}

fn map_filesystem_error(error: &FilesystemError) -> StorageFilesystemOutcomeV1 {
    let code = match error {
        FilesystemError::InvalidPath(_) => "invalid-path",
        FilesystemError::NotFound(_) => "not-found",
        FilesystemError::IsDirectory(_) => "is-directory",
        FilesystemError::NotDirectory(_) => "not-directory",
        FilesystemError::AlreadyExists(_) => "already-exists",
        FilesystemError::DirectoryNotEmpty(_) => "directory-not-empty",
        FilesystemError::NamespaceConflict(_) => "namespace-conflict",
        FilesystemError::Staging(_) => "staging",
        FilesystemError::Content(_) => "storage",
    };
    failure(code, &error.to_string())
}

fn failure(code: &str, message: &str) -> StorageFilesystemOutcomeV1 {
    StorageFilesystemOutcomeV1::Failure(StorageFilesystemFailureV1 {
        code: code.to_owned(),
        message: message.chars().take(1024).collect(),
    })
}

fn is_mutation(operation: &StorageFilesystemOperationV1) -> bool {
    matches!(
        operation,
        StorageFilesystemOperationV1::Write { .. }
            | StorageFilesystemOperationV1::SetLength { .. }
            | StorageFilesystemOperationV1::Create { .. }
            | StorageFilesystemOperationV1::Remove { .. }
            | StorageFilesystemOperationV1::Rename { .. }
    )
}

fn generate_lease_token() -> Result<(String, [u8; 32]), String> {
    let mut secret = [0_u8; 32];
    SysRng
        .try_fill_bytes(&mut secret)
        .map_err(|error| format!("generate mount lease token: {error}"))?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
    Ok((token.clone(), token_hash(&token)))
}

fn token_hash(token: &str) -> [u8; 32] {
    blake3::derive_key(
        "astrid native storage mount lease token v1",
        token.as_bytes(),
    )
}

fn token_matches(expected: &[u8; 32], supplied: &str) -> bool {
    bool::from(expected.ct_eq(&token_hash(supplied)))
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn write_private_manifest(path: &Path, lease: &StorageMountLeaseV1) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(lease).map_err(io::Error::other)?;
    bytes.push(b'\n');
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()
    }
    #[cfg(not(unix))]
    {
        astrid_core::platform_fs::atomic_write_private_file(path, &bytes)
    }
}

fn cleanup_resource(resource_path: &Path, callback_path: &Path) {
    let _ = std::fs::remove_file(callback_path);
    let _ = std::fs::remove_file(resource_path.join(LEASE_MANIFEST_NAME));
    let _ = std::fs::remove_dir(resource_path);
    if let Some(root) = resource_path.parent() {
        let _ = std::fs::remove_dir(root);
    }
}

#[cfg(all(test, unix))]
mod tests {
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
        let request = StorageFilesystemRequestV1 {
            protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V1,
            request_id: "test-request".to_owned(),
            lease_token: token.to_owned(),
            operation,
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let length = u32::try_from(bytes.len()).expect("bounded callback request");
        stream.write_all(&length.to_be_bytes()).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        let mut response_length = [0_u8; 4];
        stream.read_exact(&mut response_length).await.unwrap();
        let mut response = vec![0_u8; u32::from_be_bytes(response_length) as usize];
        stream.read_exact(&mut response).await.unwrap();
        serde_json::from_slice::<StorageFilesystemResponseV1>(&response)
            .unwrap()
            .outcome
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

        revoke_lease(&kernel, &caller, false, principal.mount_id).unwrap();
        revoke_lease(&kernel, &caller, false, fleet_lease.mount_id).unwrap();
        revoke_lease(&kernel, &caller, false, read_only.mount_id).unwrap();
    }
}

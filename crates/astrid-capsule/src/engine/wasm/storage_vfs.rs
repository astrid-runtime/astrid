//! Native VFS adapter backed by the authoritative Astrid filesystem.
//!
//! Unlike [`astrid_vfs::HostVfs`], this provider has no host directory.  Paths
//! are validated as canonical Astrid namespace names and file contents are
//! buffered for the lifetime of a VFS file handle.  A dirty handle publishes
//! one complete immutable object when it is closed. Concurrent writable
//! handles intentionally use last-close-wins publication: each handle
//! snapshots authoritative bytes at open, and closing it publishes that
//! complete snapshot atomically.

#![cfg(not(target_family = "wasm"))]

use std::collections::HashMap;
use std::sync::Arc;

use astrid_capabilities::{DirHandle, FileHandle};
use astrid_storage::{
    AstridFilesystem, FilesystemEntryKind, FilesystemError, FilesystemPath,
    NativePrincipalContentStore, RuntimePrincipalStore, StateOwner,
};
use async_trait::async_trait;
use tokio::sync::{Mutex, RwLock};

use astrid_vfs::{Vfs, VfsDirEntry, VfsError, VfsMetadata, VfsResult};

type RuntimeFilesystem = AstridFilesystem<
    StateOwner,
    astrid_storage::engine::DurableEngine<
        StateOwner,
        astrid_storage::Blake3ObjectIdentityV1,
        astrid_storage::StateOwnerCodecV2,
    >,
>;

type RuntimeWorkspaceFilesystem = astrid_storage::WorkspaceFilesystem<
    StateOwner,
    astrid_storage::engine::DurableEngine<
        StateOwner,
        astrid_storage::Blake3ObjectIdentityV1,
        astrid_storage::StateOwnerCodecV2,
    >,
>;

trait StorageBackend: Send + Sync {
    fn stat(
        &self,
        path: &FilesystemPath,
    ) -> Result<astrid_storage::FilesystemEntry, FilesystemError>;
    fn read_dir(
        &self,
        path: &FilesystemPath,
    ) -> Result<Vec<astrid_storage::FilesystemEntry>, FilesystemError>;
    fn read(
        &self,
        path: &FilesystemPath,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, FilesystemError>;
    fn write(&self, path: &FilesystemPath, bytes: &[u8]) -> Result<(), FilesystemError>;
    fn create_dir(&self, path: &FilesystemPath) -> Result<(), FilesystemError>;
    fn remove(&self, path: &FilesystemPath) -> Result<(), FilesystemError>;
}

struct OwnerBackend(RuntimeFilesystem);

impl StorageBackend for OwnerBackend {
    fn stat(
        &self,
        path: &FilesystemPath,
    ) -> Result<astrid_storage::FilesystemEntry, FilesystemError> {
        self.0.stat(path)
    }

    fn read_dir(
        &self,
        path: &FilesystemPath,
    ) -> Result<Vec<astrid_storage::FilesystemEntry>, FilesystemError> {
        self.0.read_dir(path)
    }

    fn read(
        &self,
        path: &FilesystemPath,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, FilesystemError> {
        self.0.read(path, offset, length)
    }

    fn write(&self, path: &FilesystemPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        self.0.write(path, bytes).map(|_| ())
    }

    fn create_dir(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        self.0.create_dir(path)
    }

    fn remove(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        self.0.remove(path)
    }
}

struct WorkspaceBackend(RuntimeWorkspaceFilesystem);

impl StorageBackend for WorkspaceBackend {
    fn stat(
        &self,
        path: &FilesystemPath,
    ) -> Result<astrid_storage::FilesystemEntry, FilesystemError> {
        self.0.stat(path).map_err(map_workspace_error)
    }

    fn read_dir(
        &self,
        path: &FilesystemPath,
    ) -> Result<Vec<astrid_storage::FilesystemEntry>, FilesystemError> {
        self.0.read_dir(path).map_err(map_workspace_error)
    }

    fn read(
        &self,
        path: &FilesystemPath,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, FilesystemError> {
        self.0
            .read(path, offset, length)
            .map_err(map_workspace_error)
    }

    fn write(&self, path: &FilesystemPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        self.0.write(path, bytes).map_err(map_workspace_error)
    }

    fn create_dir(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        self.0.create_dir(path).map_err(map_workspace_error)
    }

    fn remove(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        self.0.remove(path).map_err(map_workspace_error)
    }
}

struct OpenFile {
    path: FilesystemPath,
    bytes: Vec<u8>,
    offset: usize,
    writable: bool,
    dirty: bool,
}

/// A principal-owned VFS view over `AstridFilesystem`.
pub(crate) struct AstridStorageVfs {
    filesystem: Box<dyn StorageBackend>,
    open_dirs: RwLock<HashMap<DirHandle, FilesystemPath>>,
    open_files: RwLock<HashMap<FileHandle, Arc<Mutex<OpenFile>>>>,
}

impl AstridStorageVfs {
    /// Bind one already-authorized owner to the durable content projection.
    #[cfg(test)]
    pub(crate) fn new(store: &RuntimePrincipalStore, owner: StateOwner, root: DirHandle) -> Self {
        Self::from_content(store.content(), owner, root)
    }

    /// Bind one principal's home projection under the stable owner-local
    /// `home/` prefix. The principal argument is retained for the caller's
    /// authorization boundary but is never persisted in the path: aliases are
    /// mutable projections and must not become durable storage identity.
    pub(crate) fn home(
        store: &RuntimePrincipalStore,
        owner: StateOwner,
        principal: &astrid_core::PrincipalId,
        root: DirHandle,
    ) -> VfsResult<Self> {
        let _ = principal;
        let prefix = FilesystemPath::new("home".to_owned()).map_err(map_filesystem_error)?;
        Self::from_content_at_prefix(store.content(), owner, prefix, root)
    }

    /// Bind one owner-internal workspace branch to the same path-free VFS
    /// contract. The branch identity is already authorized by the kernel or
    /// capsule runtime; no host path is consulted.
    pub(crate) fn workspace(
        store: &RuntimePrincipalStore,
        owner: StateOwner,
        branch: astrid_core::WorkspaceUid,
        root: DirHandle,
    ) -> Self {
        let branches = astrid_storage::WorkspaceBranchStore::new(store.content());
        let filesystem = branches.filesystem(owner, branch);
        let mut open_dirs = HashMap::new();
        open_dirs.insert(root, FilesystemPath::root());
        Self {
            filesystem: Box::new(WorkspaceBackend(filesystem)),
            open_dirs: RwLock::new(open_dirs),
            open_files: RwLock::new(HashMap::new()),
        }
    }

    /// Bind one owner to a content projection.  Kept separate for focused
    /// adapter tests and callers that already hold the projection.
    #[cfg(test)]
    pub(crate) fn from_content(
        content: Arc<NativePrincipalContentStore>,
        owner: StateOwner,
        root: DirHandle,
    ) -> Self {
        let mut open_dirs = HashMap::new();
        open_dirs.insert(root, FilesystemPath::root());
        Self {
            filesystem: Box::new(OwnerBackend(AstridFilesystem::new(content, owner))),
            open_dirs: RwLock::new(open_dirs),
            open_files: RwLock::new(HashMap::new()),
        }
    }

    fn from_content_at_prefix(
        content: Arc<NativePrincipalContentStore>,
        owner: StateOwner,
        prefix: FilesystemPath,
        root: DirHandle,
    ) -> VfsResult<Self> {
        Self::with_prefix(
            Box::new(OwnerBackend(AstridFilesystem::new(content, owner))),
            prefix,
            root,
        )
    }

    fn with_prefix(
        filesystem: Box<dyn StorageBackend>,
        prefix: FilesystemPath,
        root: DirHandle,
    ) -> VfsResult<Self> {
        let vfs = Self {
            filesystem,
            open_dirs: RwLock::new(HashMap::new()),
            open_files: RwLock::new(HashMap::new()),
        };
        vfs.ensure_prefix(&prefix)?;
        let mut open_dirs = HashMap::new();
        open_dirs.insert(root, prefix);
        Ok(Self {
            filesystem: vfs.filesystem,
            open_dirs: RwLock::new(open_dirs),
            open_files: vfs.open_files,
        })
    }

    fn ensure_prefix(&self, prefix: &FilesystemPath) -> VfsResult<()> {
        if prefix.as_str().is_empty() {
            return Ok(());
        }
        let mut current = FilesystemPath::root();
        for segment in prefix.as_str().split('/') {
            current = Self::join(&current, segment)?;
            match self.filesystem.stat(&current) {
                Ok(entry) if entry.kind() == FilesystemEntryKind::Directory => continue,
                Ok(_) => {
                    return Err(map_filesystem_error(FilesystemError::NotDirectory(current)));
                },
                Err(FilesystemError::NotFound(_)) => match self.filesystem.create_dir(&current) {
                    Ok(()) => {},
                    Err(FilesystemError::AlreadyExists(_)) => {
                        let entry = self
                            .filesystem
                            .stat(&current)
                            .map_err(map_filesystem_error)?;
                        if entry.kind() != FilesystemEntryKind::Directory {
                            return Err(map_filesystem_error(FilesystemError::NotDirectory(
                                current,
                            )));
                        }
                    },
                    Err(error) => return Err(map_filesystem_error(error)),
                },
                Err(error) => return Err(map_filesystem_error(error)),
            }
        }
        Ok(())
    }

    async fn dir_path(&self, handle: &DirHandle) -> VfsResult<FilesystemPath> {
        self.open_dirs
            .read()
            .await
            .get(handle)
            .cloned()
            .ok_or(VfsError::InvalidHandle)
    }

    fn parse_relative(raw: &str) -> VfsResult<FilesystemPath> {
        FilesystemPath::new(raw.to_owned()).map_err(map_filesystem_error)
    }

    fn join(base: &FilesystemPath, raw: &str) -> VfsResult<FilesystemPath> {
        let relative = Self::parse_relative(raw)?;
        if relative.as_str().is_empty() {
            return Ok(base.clone());
        }
        if base.as_str().is_empty() {
            return Ok(relative);
        }
        Self::parse_relative(&format!("{}/{}", base.as_str(), relative.as_str()))
    }

    async fn path_for(&self, handle: &DirHandle, raw: &str) -> VfsResult<FilesystemPath> {
        let base = self.dir_path(handle).await?;
        Self::join(&base, raw)
    }

    async fn file_entry(
        &self,
        path: &FilesystemPath,
        write: bool,
        truncate: bool,
    ) -> VfsResult<(Vec<u8>, bool)> {
        let existing = match self.filesystem.stat(path) {
            Ok(entry) => Some(entry),
            Err(FilesystemError::NotFound(_)) => None,
            Err(error) => return Err(map_filesystem_error(error)),
        };
        if let Some(entry) = &existing
            && entry.kind() != FilesystemEntryKind::File
        {
            return Err(map_filesystem_error(FilesystemError::IsDirectory(
                path.clone(),
            )));
        }
        if !write && existing.is_none() {
            return Err(map_filesystem_error(FilesystemError::NotFound(
                path.clone(),
            )));
        }
        if !write && truncate {
            return Err(VfsError::PermissionDenied(
                "truncate requires a writable file handle".to_owned(),
            ));
        }

        let created_or_truncated = write && (truncate || existing.is_none());
        let bytes = if created_or_truncated {
            Vec::new()
        } else {
            let length = existing
                .as_ref()
                .map_or(0, astrid_storage::FilesystemEntry::logical_bytes);
            self.filesystem
                .read(path, 0, length)
                .map_err(map_filesystem_error)?
        };
        Ok((bytes, created_or_truncated))
    }
}

#[async_trait]
impl Vfs for AstridStorageVfs {
    async fn exists(&self, handle: &DirHandle, path: &str) -> VfsResult<bool> {
        let path = self.path_for(handle, path).await?;
        match self.filesystem.stat(&path) {
            Ok(_) => Ok(true),
            Err(FilesystemError::NotFound(_)) => Ok(false),
            Err(error) => Err(map_filesystem_error(error)),
        }
    }

    async fn readdir(&self, handle: &DirHandle, path: &str) -> VfsResult<Vec<VfsDirEntry>> {
        let path = self.path_for(handle, path).await?;
        self.filesystem
            .read_dir(&path)
            .map_err(map_filesystem_error)
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|entry| VfsDirEntry {
                        name: entry.name().to_owned(),
                        is_dir: entry.kind() == FilesystemEntryKind::Directory,
                    })
                    .collect()
            })
    }

    async fn stat(&self, handle: &DirHandle, path: &str) -> VfsResult<VfsMetadata> {
        let path = self.path_for(handle, path).await?;
        let entry = self.filesystem.stat(&path).map_err(map_filesystem_error)?;
        Ok(VfsMetadata {
            is_dir: entry.kind() == FilesystemEntryKind::Directory,
            is_file: entry.kind() == FilesystemEntryKind::File,
            size: entry.logical_bytes(),
            mtime: 0,
        })
    }

    async fn mkdir(&self, handle: &DirHandle, path: &str) -> VfsResult<()> {
        let path = self.path_for(handle, path).await?;
        if path.as_str().is_empty() {
            return Err(VfsError::PermissionDenied(
                "cannot operate on capability root directly".to_owned(),
            ));
        }

        // The VFS contract has one mkdir operation while the fs host exposes
        // both strict and recursive forms.  Recursive creation preserves the
        // existing HostVfs contract; fs-mkdir performs its own parent check.
        let mut current = FilesystemPath::root();
        for segment in path.as_str().split('/') {
            current = Self::join(&current, segment)?;
            match self.filesystem.stat(&current) {
                Ok(entry) if entry.kind() == FilesystemEntryKind::Directory => continue,
                Ok(_) => {
                    return Err(map_filesystem_error(FilesystemError::NotDirectory(current)));
                },
                Err(FilesystemError::NotFound(_)) => self
                    .filesystem
                    .create_dir(&current)
                    .map_err(map_filesystem_error)?,
                Err(error) => return Err(map_filesystem_error(error)),
            }
        }
        Ok(())
    }

    async fn unlink(&self, handle: &DirHandle, path: &str) -> VfsResult<()> {
        let path = self.path_for(handle, path).await?;
        if path.as_str().is_empty() {
            return Err(VfsError::PermissionDenied(
                "cannot operate on capability root directly".to_owned(),
            ));
        }
        self.filesystem.remove(&path).map_err(map_filesystem_error)
    }

    async fn open(
        &self,
        handle: &DirHandle,
        path: &str,
        write: bool,
        truncate: bool,
    ) -> VfsResult<FileHandle> {
        let path = self.path_for(handle, path).await?;
        if path.as_str().is_empty() {
            return Err(VfsError::PermissionDenied(
                "cannot open capability root as a file".to_owned(),
            ));
        }
        let (bytes, dirty) = self.file_entry(&path, write, truncate).await?;
        let new_handle = FileHandle::new();
        self.open_files.write().await.insert(
            new_handle.clone(),
            Arc::new(Mutex::new(OpenFile {
                path,
                bytes,
                offset: 0,
                writable: write,
                dirty,
            })),
        );
        Ok(new_handle)
    }

    async fn open_dir(
        &self,
        handle: &DirHandle,
        path: &str,
        new_handle: DirHandle,
    ) -> VfsResult<()> {
        let path = self.path_for(handle, path).await?;
        let entry = self.filesystem.stat(&path).map_err(map_filesystem_error)?;
        if entry.kind() != FilesystemEntryKind::Directory {
            return Err(map_filesystem_error(FilesystemError::NotDirectory(path)));
        }
        self.open_dirs.write().await.insert(new_handle, path);
        Ok(())
    }

    async fn close_dir(&self, handle: &DirHandle) -> VfsResult<()> {
        self.open_dirs
            .write()
            .await
            .remove(handle)
            .map(|_| ())
            .ok_or(VfsError::InvalidHandle)
    }

    async fn read(&self, handle: &FileHandle) -> VfsResult<Vec<u8>> {
        let file = self
            .open_files
            .read()
            .await
            .get(handle)
            .cloned()
            .ok_or(VfsError::InvalidHandle)?;
        let mut file = file.lock().await;
        let bytes = file.bytes[file.offset..].to_vec();
        file.offset = file.bytes.len();
        Ok(bytes)
    }

    async fn write(&self, handle: &FileHandle, content: &[u8]) -> VfsResult<()> {
        let file = self
            .open_files
            .read()
            .await
            .get(handle)
            .cloned()
            .ok_or(VfsError::InvalidHandle)?;
        let mut file = file.lock().await;
        if !file.writable {
            return Err(VfsError::PermissionDenied(
                "file was not opened for writing".to_owned(),
            ));
        }
        let end = file
            .offset
            .checked_add(content.len())
            .ok_or_else(|| VfsError::PermissionDenied("file is too large".to_owned()))?;
        if end > file.bytes.len() {
            file.bytes.resize(end, 0);
        }
        let offset = file.offset;
        file.bytes[offset..end].copy_from_slice(content);
        file.offset = end;
        file.dirty = true;
        Ok(())
    }

    async fn close(&self, handle: &FileHandle) -> VfsResult<()> {
        let file = self
            .open_files
            .write()
            .await
            .remove(handle)
            .ok_or(VfsError::InvalidHandle)?;
        let file = file.lock().await;
        if file.writable && file.dirty {
            self.filesystem
                .write(&file.path, &file.bytes)
                .map_err(map_filesystem_error)?;
        }
        Ok(())
    }
}

fn map_filesystem_error(error: FilesystemError) -> VfsError {
    match error {
        FilesystemError::InvalidPath(path) => VfsError::SandboxViolation(path),
        FilesystemError::NotFound(path) => VfsError::NotFound(path.as_str().to_owned()),
        FilesystemError::IsDirectory(path) => VfsError::Io(std::io::Error::new(
            std::io::ErrorKind::IsADirectory,
            path.as_str().to_owned(),
        )),
        FilesystemError::NotDirectory(path) => VfsError::Io(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            path.as_str().to_owned(),
        )),
        FilesystemError::AlreadyExists(path) => VfsError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            path.as_str().to_owned(),
        )),
        FilesystemError::DirectoryNotEmpty(path) => VfsError::Io(std::io::Error::new(
            std::io::ErrorKind::DirectoryNotEmpty,
            path.as_str().to_owned(),
        )),
        FilesystemError::NamespaceConflict(path) => VfsError::Io(std::io::Error::other(format!(
            "namespace conflict at {}",
            path.as_str()
        ))),
        FilesystemError::Staging(message) => VfsError::Io(std::io::Error::other(message)),
        FilesystemError::Content(error) => VfsError::Io(std::io::Error::other(error.to_string())),
    }
}

fn map_workspace_error(error: astrid_storage::WorkspaceBranchError) -> FilesystemError {
    match error {
        astrid_storage::WorkspaceBranchError::Filesystem(error) => error,
        other => FilesystemError::Staging(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_core::{PrincipalId, PrincipalUid};
    use astrid_storage::{KvQuotaResolver, open_runtime_principal_store};

    async fn fixture() -> (tempfile::TempDir, RuntimePrincipalStore) {
        let directory = tempfile::tempdir().expect("storage root");
        let home = astrid_core::dirs::AstridHome::from_path(directory.path());
        home.ensure().expect("home layout");
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
                astrid_storage::StateOwner::User(_) => {
                    Err(astrid_storage::StorageError::Internal(
                        "test quota resolver rejects user StateOwner".to_owned(),
                    ))?
                },
            })
        });
        let store = open_runtime_principal_store(&home, quota)
            .await
            .expect("runtime store");
        (directory, store)
    }

    #[tokio::test]
    async fn buffers_until_close_and_reopens_from_authoritative_content() {
        let (_directory, store) = fixture().await;
        let root = DirHandle::new();
        let owner = StateOwner::Principal(PrincipalUid::from_bytes([0x11; 32]));
        let vfs = AstridStorageVfs::new(&store, owner, root.clone());
        let handle = vfs.open(&root, "note", true, true).await.expect("open");
        vfs.write(&handle, b"persisted").await.expect("write");
        assert!(
            !vfs.exists(&root, "note")
                .await
                .expect("exists before close")
        );
        vfs.close(&handle).await.expect("close");

        let direct = AstridFilesystem::new(store.content(), owner);
        let note = FilesystemPath::new("note").expect("canonical note path");
        assert_eq!(
            direct
                .read(
                    &note,
                    0,
                    direct.stat(&note).expect("direct stat").logical_bytes()
                )
                .expect("direct read"),
            b"persisted"
        );
        let read_handle = vfs.open(&root, "note", false, false).await.expect("reopen");
        assert_eq!(vfs.read(&read_handle).await.expect("read"), b"persisted");
        vfs.close(&read_handle).await.expect("close read");
    }

    #[tokio::test]
    async fn directories_truncate_and_unlink_match_filesystem_semantics() {
        let (_directory, store) = fixture().await;
        let root = DirHandle::new();
        let vfs = AstridStorageVfs::new(
            &store,
            StateOwner::Principal(PrincipalUid::from_bytes([0x33; 32])),
            root.clone(),
        );
        vfs.mkdir(&root, "nested/dir").await.expect("mkdir");
        assert!(vfs.stat(&root, "nested/dir").await.expect("stat").is_dir);

        let handle = vfs
            .open(&root, "nested/dir/value", true, true)
            .await
            .expect("open");
        vfs.write(&handle, b"abcdef").await.expect("write");
        vfs.close(&handle).await.expect("close");
        let truncate = vfs
            .open(&root, "nested/dir/value", true, true)
            .await
            .expect("truncate open");
        vfs.write(&truncate, b"xy").await.expect("truncate write");
        vfs.close(&truncate).await.expect("truncate close");
        let read = vfs
            .open(&root, "nested/dir/value", false, false)
            .await
            .expect("read open");
        assert_eq!(vfs.read(&read).await.expect("read"), b"xy");
        vfs.close(&read).await.expect("read close");

        assert!(matches!(
            vfs.unlink(&root, "nested").await,
            Err(VfsError::Io(error)) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty
        ));
        vfs.unlink(&root, "nested/dir/value")
            .await
            .expect("unlink file");
        vfs.unlink(&root, "nested/dir").await.expect("unlink dir");
        vfs.unlink(&root, "nested").await.expect("unlink parent");
    }

    #[tokio::test]
    async fn owner_views_are_isolated_and_unsafe_paths_are_rejected() {
        let (directory, store) = fixture().await;
        let first_root = DirHandle::new();
        let second_root = DirHandle::new();
        let first = AstridStorageVfs::new(
            &store,
            StateOwner::Principal(PrincipalUid::from_bytes([0x11; 32])),
            first_root.clone(),
        );
        let second = AstridStorageVfs::new(
            &store,
            StateOwner::Principal(PrincipalUid::from_bytes([0x22; 32])),
            second_root.clone(),
        );
        let path = "same";
        let first_handle = first
            .open(&first_root, path, true, true)
            .await
            .expect("open first");
        first
            .write(&first_handle, b"first")
            .await
            .expect("write first");
        first.close(&first_handle).await.expect("close first");
        let second_handle = second
            .open(&second_root, path, true, true)
            .await
            .expect("open second");
        second
            .write(&second_handle, b"second")
            .await
            .expect("write second");
        second.close(&second_handle).await.expect("close second");
        let first_read = first
            .open(&first_root, path, false, false)
            .await
            .expect("reopen first");
        let second_read = second
            .open(&second_root, path, false, false)
            .await
            .expect("reopen second");
        assert_eq!(first.read(&first_read).await.expect("read first"), b"first");
        assert_eq!(
            second.read(&second_read).await.expect("read second"),
            b"second"
        );
        first.close(&first_read).await.expect("close first read");
        second.close(&second_read).await.expect("close second read");
        assert!(matches!(
            first.open(&first_root, "../escape", false, false).await,
            Err(VfsError::SandboxViolation(_))
        ));
        for unsafe_path in ["/absolute", "a//b", "./dot", "nul\0byte", "trailing/"] {
            assert!(
                matches!(
                    first.open(&first_root, unsafe_path, false, false).await,
                    Err(VfsError::SandboxViolation(_))
                ),
                "unsafe path must be rejected: {unsafe_path:?}"
            );
        }

        drop(first);
        drop(second);
        drop(store);
        let home = astrid_core::dirs::AstridHome::from_path(directory.path());
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
                astrid_storage::StateOwner::User(_) => {
                    Err(astrid_storage::StorageError::Internal(
                        "test quota resolver rejects user StateOwner".to_owned(),
                    ))?
                },
            })
        });
        let reopened = open_runtime_principal_store(&home, quota)
            .await
            .expect("reopen store");
        let reopened_root = DirHandle::new();
        let reopened_view = AstridStorageVfs::new(
            &reopened,
            StateOwner::Principal(PrincipalUid::from_bytes([0x11; 32])),
            reopened_root.clone(),
        );
        let reopened_handle = reopened_view
            .open(&reopened_root, path, false, false)
            .await
            .expect("reopen persisted");
        assert_eq!(
            reopened_view
                .read(&reopened_handle)
                .await
                .expect("read persisted"),
            b"first"
        );
        reopened_view
            .close(&reopened_handle)
            .await
            .expect("close persisted");
    }

    #[tokio::test]
    async fn concurrent_writers_publish_last_close_snapshot() {
        let (_directory, store) = fixture().await;
        let root = DirHandle::new();
        let vfs = AstridStorageVfs::new(
            &store,
            StateOwner::Principal(PrincipalUid::from_bytes([0x44; 32])),
            root.clone(),
        );
        let seed = vfs
            .open(&root, "race", true, true)
            .await
            .expect("seed open");
        vfs.write(&seed, b"base").await.expect("seed write");
        vfs.close(&seed).await.expect("seed close");

        let first = vfs
            .open(&root, "race", true, false)
            .await
            .expect("first open");
        let second = vfs
            .open(&root, "race", true, false)
            .await
            .expect("second open");
        vfs.write(&first, b"first").await.expect("first write");
        vfs.write(&second, b"second").await.expect("second write");
        vfs.close(&first).await.expect("first close");
        vfs.close(&second).await.expect("second close");

        let read = vfs
            .open(&root, "race", false, false)
            .await
            .expect("read open");
        assert_eq!(vfs.read(&read).await.expect("read"), b"second");
        vfs.close(&read).await.expect("read close");
    }

    #[tokio::test]
    async fn home_and_workspace_prefixes_do_not_alias() {
        let (_directory, store) = fixture().await;
        let owner = StateOwner::Principal(PrincipalUid::from_bytes([0x55; 32]));
        let home_root = DirHandle::new();
        let workspace_root = DirHandle::new();
        let home = AstridStorageVfs::from_content_at_prefix(
            store.content(),
            owner,
            FilesystemPath::new("home").expect("home prefix"),
            home_root.clone(),
        )
        .expect("home view");
        let workspace = AstridStorageVfs::from_content_at_prefix(
            store.content(),
            owner,
            FilesystemPath::new("workspace/attachment-1").expect("workspace prefix"),
            workspace_root.clone(),
        )
        .expect("workspace view");

        let home_file = home
            .open(&home_root, "note", true, true)
            .await
            .expect("home open");
        home.write(&home_file, b"home").await.expect("home write");
        home.close(&home_file).await.expect("home close");
        assert!(matches!(
            workspace.open(&workspace_root, "note", false, false).await,
            Err(VfsError::NotFound(_))
        ));

        let workspace_file = workspace
            .open(&workspace_root, "note", true, true)
            .await
            .expect("workspace open");
        workspace
            .write(&workspace_file, b"workspace")
            .await
            .expect("workspace write");
        workspace
            .close(&workspace_file)
            .await
            .expect("workspace close");
        let home_read = home
            .open(&home_root, "note", false, false)
            .await
            .expect("home reopen");
        assert_eq!(home.read(&home_read).await.expect("home read"), b"home");
        home.close(&home_read).await.expect("home read close");
    }

    #[tokio::test]
    async fn home_view_survives_mutable_principal_alias_rename() {
        let (_directory, store) = fixture().await;
        let owner = StateOwner::Principal(PrincipalUid::from_bytes([0x66; 32]));
        let old_alias = PrincipalId::new("before").expect("old alias");
        let new_alias = PrincipalId::new("after").expect("new alias");
        let old_root = DirHandle::new();
        let old_view = AstridStorageVfs::home(&store, owner, &old_alias, old_root.clone())
            .expect("old home view");
        let file = old_view
            .open(&old_root, "note", true, true)
            .await
            .expect("open home file");
        old_view
            .write(&file, b"stable-owner-home")
            .await
            .expect("write");
        old_view.close(&file).await.expect("close");

        // PrincipalDirectory aliases are mutable projections. Rebinding the
        // same authorized owner must select the exact same durable subtree.
        let new_root = DirHandle::new();
        let new_view = AstridStorageVfs::home(&store, owner, &new_alias, new_root.clone())
            .expect("new home view");
        let reopened = new_view
            .open(&new_root, "note", false, false)
            .await
            .expect("reopen after alias rename");
        assert_eq!(
            new_view.read(&reopened).await.expect("read"),
            b"stable-owner-home"
        );
        new_view.close(&reopened).await.expect("close reopened");
    }
}

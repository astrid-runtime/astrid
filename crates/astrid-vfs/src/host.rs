use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use astrid_capabilities::{DirHandle, FileHandle};
use async_trait::async_trait;
use cap_std::fs::Dir;
use tokio::fs;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};

use crate::host_address::{self, Address, retain};
use crate::{Vfs, VfsDirEntry, VfsError, VfsMetadata, VfsResult};

/// An open file and its associated semaphore permit, tying the FD quota to the struct's lifetime.
type OpenFileEntry = Arc<RwLock<(fs::File, OwnedSemaphorePermit)>>;

/// Strip any leading absolute slashes or prefixes from the requested path
/// so that `cap_std` can operate on it safely within its sandbox.
fn make_relative(requested: &str) -> &Path {
    let path = Path::new(requested);
    let mut components = path.components();
    while let Some(c) = components.clone().next() {
        if matches!(c, Component::RootDir | Component::Prefix(_)) {
            components.next(); // consume it
        } else {
            break;
        }
    }
    components.as_path()
}

/// Preserve filesystem conditions that callers need for control flow while
/// retaining all other native failures as opaque I/O errors.
fn classify_io_error(error: std::io::Error) -> VfsError {
    match error.kind() {
        std::io::ErrorKind::NotFound => VfsError::NotFound(error.to_string()),
        std::io::ErrorKind::PermissionDenied => VfsError::PermissionDenied(error.to_string()),
        _ => VfsError::Io(error),
    }
}

/// An implementation of `Vfs` backed by the physical host filesystem.
pub struct HostVfs {
    open_dirs: RwLock<HashMap<DirHandle, Arc<Dir>>>,
    open_files: RwLock<HashMap<FileHandle, OpenFileEntry>>,
    fd_semaphore: Arc<Semaphore>,
}

impl HostVfs {
    /// Create a new host VFS.
    #[must_use]
    pub fn new() -> Self {
        Self {
            open_dirs: RwLock::new(HashMap::new()),
            open_files: RwLock::new(HashMap::new()),
            fd_semaphore: Arc::new(Semaphore::new(64)),
        }
    }

    /// Create a host VFS with one root capability already registered.
    ///
    /// This is the synchronous constructor for synchronous WIT host calls that
    /// must switch principal mounts before returning to the guest. It performs
    /// the same ambient-directory open as [`register_dir`](Self::register_dir)
    /// but initializes the lock before the VFS becomes shared, avoiding a
    /// nested async-runtime bridge.
    ///
    /// # Errors
    ///
    /// Returns a typed VFS error when the directory cannot be opened.
    pub fn with_registered_dir(handle: DirHandle, physical_path: &Path) -> VfsResult<Self> {
        let opened = Self::open_root(handle, physical_path).map_err(classify_io_error)?;
        let mut open_dirs = HashMap::new();
        opened.publish(&mut open_dirs);
        Ok(Self {
            open_dirs: RwLock::new(open_dirs),
            open_files: RwLock::new(HashMap::new()),
            fd_semaphore: Arc::new(Semaphore::new(64)),
        })
    }

    fn open_root(
        handle: DirHandle,
        path: &Path,
    ) -> std::io::Result<host_address::OpenedDirectory<DirHandle, Dir>> {
        host_address::OpenedDirectory::open(handle, path, |selected| {
            Dir::open_ambient_dir(selected, cap_std::ambient_authority())
        })
    }

    /// Register a root directory capability manually (e.g. from the Daemon).
    ///
    /// # Panics
    ///
    /// # Errors
    ///
    /// Returns a typed VFS error if the directory cannot be opened.
    pub async fn register_dir(&self, handle: DirHandle, physical_path: PathBuf) -> VfsResult<()> {
        let dir_res = tokio::task::spawn_blocking(move || Self::open_root(handle, &physical_path))
            .await
            .expect("spawn_blocking panicked");

        match dir_res {
            Ok(opened) => {
                let mut dirs: tokio::sync::RwLockWriteGuard<'_, HashMap<DirHandle, Arc<Dir>>> =
                    self.open_dirs.write().await;
                opened.publish(&mut dirs);
                Ok(())
            },
            Err(e) => {
                tracing::error!("Failed to register root capability: {}", e);
                Err(classify_io_error(e))
            },
        }
    }

    async fn address(&self, handle: &DirHandle, path: &str) -> VfsResult<Address<Dir, PathBuf>> {
        let dir = retain(&*self.open_dirs.read().await, handle).ok_or(VfsError::InvalidHandle)?;
        Ok(Address::new(dir, path, |text| {
            make_relative(text).to_path_buf()
        }))
    }
}

impl crate::open_options::Options for cap_std::fs::OpenOptions {
    fn new() -> Self {
        Self::new()
    }
    fn read(&mut self, value: bool) {
        self.read(value);
    }
    fn write(&mut self, value: bool) {
        self.write(value);
    }
    fn create(&mut self, value: bool) {
        self.create(value);
    }
    fn truncate(&mut self, value: bool) {
        self.truncate(value);
    }
}

impl Address<Dir, PathBuf> {
    fn blocking<T: Send + 'static>(
        self,
        work: impl FnOnce(Arc<Dir>, PathBuf) -> T + Send + 'static,
    ) -> tokio::task::JoinHandle<T> {
        tokio::task::spawn_blocking(move || self.run(work))
    }
}

impl Default for HostVfs {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Vfs for HostVfs {
    async fn exists(&self, handle: &DirHandle, path: &str) -> VfsResult<bool> {
        let address = self.address(handle, path).await?;
        if address.path().as_os_str().is_empty() {
            return Ok(true);
        }
        let res = address
            .blocking(move |dir, safe_path| dir.exists(&safe_path))
            .await
            .expect("spawn_blocking panicked");
        Ok(res)
    }

    async fn readdir(&self, handle: &DirHandle, path: &str) -> VfsResult<Vec<VfsDirEntry>> {
        let address = self.address(handle, path).await?;

        address
            .blocking(move |dir, safe_path| {
                let iter = if safe_path.as_os_str().is_empty() {
                    dir.entries()
                } else {
                    dir.read_dir(&safe_path)
                }
                .map_err(classify_io_error)?;

                let mut entries = Vec::new();
                for entry_res in iter {
                    let entry = entry_res.map_err(classify_io_error)?;
                    let is_dir = entry.file_type().is_ok_and(|ft| ft.is_dir());
                    entries.push(VfsDirEntry {
                        name: entry.file_name().to_string_lossy().to_string(),
                        is_dir,
                    });
                }
                Ok(entries)
            })
            .await
            .expect("spawn_blocking panicked")
    }

    async fn stat(&self, handle: &DirHandle, path: &str) -> VfsResult<VfsMetadata> {
        let address = self.address(handle, path).await?;

        address
            .blocking(move |dir, safe_path| {
                let meta = if safe_path.as_os_str().is_empty() {
                    dir.dir_metadata()
                } else {
                    dir.symlink_metadata(&safe_path)
                }
                .map_err(classify_io_error)?;

                let mtime = meta
                    .modified()
                    .ok()
                    .map(cap_std::time::SystemTime::into_std)
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0u64, |d| d.as_secs());

                Ok(VfsMetadata {
                    is_dir: meta.is_dir(),
                    is_file: meta.is_file(),
                    size: meta.len(),
                    mtime,
                })
            })
            .await
            .expect("spawn_blocking panicked")
    }

    async fn mkdir(&self, handle: &DirHandle, path: &str) -> VfsResult<()> {
        let address = self.address(handle, path).await?;
        if address.path().as_os_str().is_empty() {
            return Err(VfsError::PermissionDenied(
                "Cannot operate on capability root directly".into(),
            ));
        }

        address
            .blocking(move |dir, safe_path| dir.create_dir_all(&safe_path))
            .await
            .expect("spawn_blocking panicked")
            .map_err(classify_io_error)
    }

    async fn unlink(&self, handle: &DirHandle, path: &str) -> VfsResult<()> {
        let address = self.address(handle, path).await?;
        if address.path().as_os_str().is_empty() {
            return Err(VfsError::PermissionDenied(
                "Cannot operate on capability root directly".into(),
            ));
        }

        address
            .blocking(move |dir, safe_path| {
                let meta = dir
                    .symlink_metadata(&safe_path)
                    .map_err(classify_io_error)?;
                if meta.is_dir() {
                    dir.remove_dir(&safe_path).map_err(classify_io_error)
                } else {
                    dir.remove_file(&safe_path).map_err(classify_io_error)
                }
            })
            .await
            .expect("spawn_blocking panicked")
    }

    async fn open(
        &self,
        handle: &DirHandle,
        path: &str,
        write: bool,
        truncate: bool,
    ) -> VfsResult<FileHandle> {
        let address = self.address(handle, path).await?;

        // Prevent transient FD exhaustion via semaphore before calling the OS
        let permit = self
            .fd_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| VfsError::PermissionDenied("Too many open files".into()))?;

        let std_file = address
            .blocking(move |dir, safe_path| {
                crate::open_options::open_with(
                    dir,
                    safe_path,
                    write,
                    truncate,
                    |dir, path, options: cap_std::fs::OpenOptions| dir.open_with(path, &options),
                )
            })
            .await
            .expect("spawn_blocking panicked")
            .map_err(classify_io_error)?;

        // Convert the cap_std File into a tokio async File
        let tokio_file = tokio::fs::File::from_std(std_file.into_std());

        let mut files: tokio::sync::RwLockWriteGuard<'_, HashMap<FileHandle, OpenFileEntry>> =
            self.open_files.write().await;
        if files.len() >= 64 {
            return Err(VfsError::PermissionDenied("Too many open files".into()));
        }

        let new_handle = FileHandle::new();
        host_address::install(
            &mut files,
            new_handle.clone(),
            Arc::new(RwLock::new((tokio_file, permit))),
        );

        Ok(new_handle)
    }

    async fn open_dir(
        &self,
        handle: &DirHandle,
        path: &str,
        new_handle: DirHandle,
    ) -> VfsResult<()> {
        let address = self.address(handle, path).await?;

        let new_dir = address
            .blocking(move |dir, safe_path| {
                if safe_path.as_os_str().is_empty() {
                    dir.try_clone()
                } else {
                    dir.open_dir(&safe_path)
                }
            })
            .await
            .expect("spawn_blocking panicked")
            .map_err(classify_io_error)?;

        let mut dirs: tokio::sync::RwLockWriteGuard<'_, HashMap<DirHandle, Arc<Dir>>> =
            self.open_dirs.write().await;
        if dirs.len() >= 64 {
            return Err(VfsError::PermissionDenied(
                "Too many open directories".into(),
            ));
        }

        host_address::install(&mut dirs, new_handle, Arc::new(new_dir));
        Ok(())
    }

    async fn close_dir(&self, handle: &DirHandle) -> VfsResult<()> {
        let mut dirs: tokio::sync::RwLockWriteGuard<'_, HashMap<DirHandle, Arc<Dir>>> =
            self.open_dirs.write().await;
        if !host_address::close(&mut dirs, handle) {
            return Err(VfsError::InvalidHandle);
        }
        Ok(())
    }

    async fn read(&self, handle: &FileHandle) -> VfsResult<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let file_arc = {
            let files: tokio::sync::RwLockReadGuard<'_, HashMap<FileHandle, OpenFileEntry>> =
                self.open_files.read().await;
            retain(&*files, handle).ok_or(VfsError::InvalidHandle)?
        };

        let mut file_tuple = file_arc.write().await;
        let file = &mut file_tuple.0;

        let meta = file.metadata().await.map_err(classify_io_error)?;
        let max_size = 50 * 1024 * 1024;
        if meta.len() > max_size as u64 {
            return Err(VfsError::PermissionDenied(
                "File is too large to read into memory (> 50MB)".into(),
            ));
        }

        let mut buffer = Vec::new();
        let mut file_handle = (&mut *file).take((max_size as u64).saturating_add(1));
        file_handle
            .read_to_end(&mut buffer)
            .await
            .map_err(classify_io_error)?;

        if buffer.len() > max_size {
            return Err(VfsError::PermissionDenied(
                "File grew beyond size limit during read (> 50MB)".into(),
            ));
        }

        Ok(buffer)
    }

    async fn write(&self, handle: &FileHandle, content: &[u8]) -> VfsResult<()> {
        use tokio::io::AsyncWriteExt;
        let file_arc = {
            let files: tokio::sync::RwLockReadGuard<'_, HashMap<FileHandle, OpenFileEntry>> =
                self.open_files.read().await;
            retain(&*files, handle).ok_or(VfsError::InvalidHandle)?
        };

        let mut file_tuple = file_arc.write().await;
        let file = &mut file_tuple.0;
        file.write_all(content).await.map_err(classify_io_error)?;
        file.flush().await.map_err(classify_io_error)?;
        Ok(())
    }

    async fn close(&self, handle: &FileHandle) -> VfsResult<()> {
        let mut files: tokio::sync::RwLockWriteGuard<'_, HashMap<FileHandle, OpenFileEntry>> =
            self.open_files.write().await;
        if !host_address::close(&mut files, handle) {
            return Err(VfsError::InvalidHandle);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn synchronous_constructor_registers_the_root() {
        let root = tempfile::tempdir().expect("root");
        std::fs::write(root.path().join("visible.txt"), b"ok").expect("fixture");
        let handle = DirHandle::new();
        let vfs = HostVfs::with_registered_dir(handle.clone(), root.path()).expect("VFS");

        assert!(vfs.exists(&handle, "visible.txt").await.expect("exists"));
    }

    #[tokio::test]
    async fn queued_address_keeps_the_registered_directory_through_close_and_rebind() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        for (root, contents) in [
            (&first, b"first".as_slice()),
            (&second, b"second".as_slice()),
        ] {
            std::fs::write(root.path().join("item"), contents).unwrap();
        }
        let handle = DirHandle::new();
        let vfs = HostVfs::with_registered_dir(handle.clone(), first.path()).unwrap();
        let captured = vfs.address(&handle, "/item").await.unwrap();
        vfs.close_dir(&handle).await.unwrap();
        assert!(matches!(
            vfs.address(&handle, "item").await,
            Err(VfsError::InvalidHandle)
        ));
        vfs.register_dir(handle.clone(), second.path().to_path_buf())
            .await
            .unwrap();
        let replacement = vfs.address(&handle, "item").await.unwrap();
        for (address, expected) in [
            (captured, b"first".as_slice()),
            (replacement, b"second".as_slice()),
        ] {
            let bytes = address
                .blocking(|dir, path| dir.read(path))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(bytes, expected);
        }
    }

    #[tokio::test]
    async fn missing_paths_are_reported_as_not_found() {
        let root = tempfile::tempdir().expect("root");
        let handle = DirHandle::new();
        let vfs = HostVfs::with_registered_dir(handle.clone(), root.path()).expect("VFS");

        assert!(matches!(
            vfs.stat(&handle, "missing").await,
            Err(VfsError::NotFound(_))
        ));
        assert!(matches!(
            vfs.readdir(&handle, "missing").await,
            Err(VfsError::NotFound(_))
        ));
        assert!(matches!(
            vfs.open(&handle, "missing", false, false).await,
            Err(VfsError::NotFound(_))
        ));
    }

    #[test]
    fn synchronous_constructor_rejects_a_missing_root() {
        let root = tempfile::tempdir().expect("root");
        let missing = root.path().join("missing");
        let result = HostVfs::with_registered_dir(DirHandle::new(), &missing);
        assert!(matches!(result, Err(VfsError::NotFound(_))));
    }
}

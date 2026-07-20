use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use astrid_capabilities::{DirHandle, FileHandle};
use async_trait::async_trait;
use cap_std::fs::Dir;
use tokio::fs;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};

use crate::{Vfs, VfsDirEntry, VfsError, VfsMetadata, VfsOpenMode, VfsResult};

/// An open file and its associated semaphore permit, tying the FD quota to the struct's lifetime.
type OpenFileEntry = Arc<RwLock<(fs::File, OwnedSemaphorePermit)>>;

#[derive(Clone, Copy)]
enum HostOpenMode {
    Read,
    Write,
    Append,
    ReadWrite,
    /// Compatibility behavior of the original `Vfs::open(write=true,
    /// truncate=false)` surface.
    ReadWriteCreate,
}

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

#[cfg(unix)]
fn cap_metadata_mode(metadata: &cap_std::fs::Metadata) -> u32 {
    use cap_std::fs::MetadataExt;
    metadata.mode()
}

#[cfg(not(unix))]
fn cap_metadata_mode(_metadata: &cap_std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn std_metadata_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode()
}

#[cfg(not(unix))]
fn std_metadata_mode(_metadata: &std::fs::Metadata) -> u32 {
    0
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
        let dir = Dir::open_ambient_dir(physical_path, cap_std::ambient_authority())
            .map_err(classify_io_error)?;
        let mut open_dirs = HashMap::new();
        open_dirs.insert(handle, Arc::new(dir));
        Ok(Self {
            open_dirs: RwLock::new(open_dirs),
            open_files: RwLock::new(HashMap::new()),
            fd_semaphore: Arc::new(Semaphore::new(64)),
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
        let dir_res = tokio::task::spawn_blocking(move || {
            Dir::open_ambient_dir(&physical_path, cap_std::ambient_authority())
        })
        .await
        .expect("spawn_blocking panicked");

        match dir_res {
            Ok(dir) => {
                let mut dirs: tokio::sync::RwLockWriteGuard<'_, HashMap<DirHandle, Arc<Dir>>> =
                    self.open_dirs.write().await;
                dirs.insert(handle, Arc::new(dir));
                Ok(())
            },
            Err(e) => {
                tracing::error!("Failed to register root capability: {}", e);
                Err(classify_io_error(e))
            },
        }
    }

    async fn get_dir(&self, handle: &DirHandle) -> VfsResult<Arc<Dir>> {
        let dirs: tokio::sync::RwLockReadGuard<'_, HashMap<DirHandle, Arc<Dir>>> =
            self.open_dirs.read().await;
        dirs.get(handle).cloned().ok_or(VfsError::InvalidHandle)
    }

    async fn open_with_mode(
        &self,
        handle: &DirHandle,
        path: &str,
        mode: HostOpenMode,
    ) -> VfsResult<FileHandle> {
        let dir = self.get_dir(handle).await?;
        let safe_path = make_relative(path).to_path_buf();

        // Prevent transient FD exhaustion before asking the OS to open a file.
        let permit = self
            .fd_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| VfsError::PermissionDenied("Too many open files".into()))?;

        let std_file = tokio::task::spawn_blocking(move || {
            let mut options = cap_std::fs::OpenOptions::new();
            match mode {
                HostOpenMode::Read => {
                    options.read(true);
                },
                HostOpenMode::Write => {
                    options.write(true).create(true).truncate(true);
                },
                HostOpenMode::Append => {
                    options.write(true).create(true).append(true);
                },
                HostOpenMode::ReadWrite => {
                    options.read(true).write(true);
                },
                HostOpenMode::ReadWriteCreate => {
                    options.read(true).write(true).create(true);
                },
            }
            dir.open_with(&safe_path, &options)
        })
        .await
        .expect("spawn_blocking panicked")
        .map_err(classify_io_error)?;

        let tokio_file = tokio::fs::File::from_std(std_file.into_std());
        let mut files = self.open_files.write().await;
        if files.len() >= 64 {
            return Err(VfsError::PermissionDenied("Too many open files".into()));
        }

        let new_handle = FileHandle::new();
        files.insert(
            new_handle.clone(),
            Arc::new(RwLock::new((tokio_file, permit))),
        );
        Ok(new_handle)
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
        let dir = self.get_dir(handle).await?;
        let safe_path = make_relative(path).to_path_buf();
        if safe_path.as_os_str().is_empty() {
            return Ok(true);
        }
        let res = tokio::task::spawn_blocking(move || dir.exists(&safe_path))
            .await
            .expect("spawn_blocking panicked");
        Ok(res)
    }

    async fn readdir(&self, handle: &DirHandle, path: &str) -> VfsResult<Vec<VfsDirEntry>> {
        let dir = self.get_dir(handle).await?;
        let safe_path = make_relative(path).to_path_buf();

        tokio::task::spawn_blocking(move || {
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
        let dir = self.get_dir(handle).await?;
        let safe_path = make_relative(path).to_path_buf();

        tokio::task::spawn_blocking(move || {
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

    async fn mode(&self, handle: &DirHandle, path: &str) -> VfsResult<u32> {
        let dir = self.get_dir(handle).await?;
        let safe_path = make_relative(path).to_path_buf();
        tokio::task::spawn_blocking(move || {
            let metadata = if safe_path.as_os_str().is_empty() {
                dir.dir_metadata()
            } else {
                dir.symlink_metadata(&safe_path)
            }
            .map_err(classify_io_error)?;
            Ok(cap_metadata_mode(&metadata))
        })
        .await
        .expect("spawn_blocking panicked")
    }

    async fn mkdir(&self, handle: &DirHandle, path: &str) -> VfsResult<()> {
        let dir = self.get_dir(handle).await?;
        let safe_path = make_relative(path).to_path_buf();
        if safe_path.as_os_str().is_empty() {
            return Err(VfsError::PermissionDenied(
                "Cannot operate on capability root directly".into(),
            ));
        }

        tokio::task::spawn_blocking(move || dir.create_dir_all(&safe_path))
            .await
            .expect("spawn_blocking panicked")
            .map_err(classify_io_error)
    }

    async fn unlink(&self, handle: &DirHandle, path: &str) -> VfsResult<()> {
        let dir = self.get_dir(handle).await?;
        let safe_path = make_relative(path).to_path_buf();
        if safe_path.as_os_str().is_empty() {
            return Err(VfsError::PermissionDenied(
                "Cannot operate on capability root directly".into(),
            ));
        }

        tokio::task::spawn_blocking(move || {
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
        let mode = match (write, truncate) {
            (false, _) => HostOpenMode::Read,
            (true, true) => HostOpenMode::Write,
            (true, false) => HostOpenMode::ReadWriteCreate,
        };
        self.open_with_mode(handle, path, mode).await
    }

    async fn open_mode(
        &self,
        handle: &DirHandle,
        path: &str,
        mode: VfsOpenMode,
    ) -> VfsResult<FileHandle> {
        match mode {
            VfsOpenMode::Read => self.open_with_mode(handle, path, HostOpenMode::Read).await,
            VfsOpenMode::Write => self.open_with_mode(handle, path, HostOpenMode::Write).await,
            VfsOpenMode::Append => {
                self.open_with_mode(handle, path, HostOpenMode::Append)
                    .await
            },
            VfsOpenMode::ReadWrite => {
                self.open_with_mode(handle, path, HostOpenMode::ReadWrite)
                    .await
            },
        }
    }

    async fn open_dir(
        &self,
        handle: &DirHandle,
        path: &str,
        new_handle: DirHandle,
    ) -> VfsResult<()> {
        let dir = self.get_dir(handle).await?;
        let safe_path = make_relative(path).to_path_buf();

        let new_dir = tokio::task::spawn_blocking(move || {
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

        dirs.insert(new_handle, Arc::new(new_dir));
        Ok(())
    }

    async fn close_dir(&self, handle: &DirHandle) -> VfsResult<()> {
        let mut dirs: tokio::sync::RwLockWriteGuard<'_, HashMap<DirHandle, Arc<Dir>>> =
            self.open_dirs.write().await;
        if dirs.remove(handle).is_none() {
            return Err(VfsError::InvalidHandle);
        }
        Ok(())
    }

    async fn read(&self, handle: &FileHandle) -> VfsResult<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let file_arc = {
            let files: tokio::sync::RwLockReadGuard<'_, HashMap<FileHandle, OpenFileEntry>> =
                self.open_files.read().await;
            files.get(handle).cloned().ok_or(VfsError::InvalidHandle)?
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

    async fn read_at(
        &self,
        handle: &FileHandle,
        offset: u64,
        max_bytes: u32,
    ) -> VfsResult<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let file_arc = {
            let files = self.open_files.read().await;
            files.get(handle).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let mut file_tuple = file_arc.write().await;
        let file = &mut file_tuple.0;
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(classify_io_error)?;
        let mut bytes = Vec::with_capacity(max_bytes as usize);
        file.take(u64::from(max_bytes))
            .read_to_end(&mut bytes)
            .await
            .map_err(classify_io_error)?;
        Ok(bytes)
    }

    async fn write(&self, handle: &FileHandle, content: &[u8]) -> VfsResult<()> {
        use tokio::io::AsyncWriteExt;
        let file_arc = {
            let files: tokio::sync::RwLockReadGuard<'_, HashMap<FileHandle, OpenFileEntry>> =
                self.open_files.read().await;
            files.get(handle).cloned().ok_or(VfsError::InvalidHandle)?
        };

        let mut file_tuple = file_arc.write().await;
        let file = &mut file_tuple.0;
        file.write_all(content).await.map_err(classify_io_error)?;
        file.flush().await.map_err(classify_io_error)?;
        Ok(())
    }

    async fn write_at(&self, handle: &FileHandle, offset: u64, content: &[u8]) -> VfsResult<u32> {
        use tokio::io::{AsyncSeekExt, AsyncWriteExt};
        let file_arc = {
            let files = self.open_files.read().await;
            files.get(handle).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let mut file_tuple = file_arc.write().await;
        let file = &mut file_tuple.0;
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(classify_io_error)?;
        let written = file.write(content).await.map_err(classify_io_error)?;
        u32::try_from(written)
            .map_err(|_| VfsError::PermissionDenied("write count exceeds u32".into()))
    }

    async fn sync_data(&self, handle: &FileHandle) -> VfsResult<()> {
        let file_arc = {
            let files = self.open_files.read().await;
            files.get(handle).cloned().ok_or(VfsError::InvalidHandle)?
        };
        file_arc
            .write()
            .await
            .0
            .sync_data()
            .await
            .map_err(classify_io_error)
    }

    async fn sync_all(&self, handle: &FileHandle) -> VfsResult<()> {
        let file_arc = {
            let files = self.open_files.read().await;
            files.get(handle).cloned().ok_or(VfsError::InvalidHandle)?
        };
        file_arc
            .write()
            .await
            .0
            .sync_all()
            .await
            .map_err(classify_io_error)
    }

    async fn file_stat(&self, handle: &FileHandle) -> VfsResult<VfsMetadata> {
        let file_arc = {
            let files = self.open_files.read().await;
            files.get(handle).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let metadata = file_arc
            .read()
            .await
            .0
            .metadata()
            .await
            .map_err(classify_io_error)?;
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_secs());
        Ok(VfsMetadata {
            is_dir: metadata.is_dir(),
            is_file: metadata.is_file(),
            size: metadata.len(),
            mtime,
        })
    }

    async fn file_mode(&self, handle: &FileHandle) -> VfsResult<u32> {
        let file_arc = {
            let files = self.open_files.read().await;
            files.get(handle).cloned().ok_or(VfsError::InvalidHandle)?
        };
        let metadata = file_arc
            .read()
            .await
            .0
            .metadata()
            .await
            .map_err(classify_io_error)?;
        Ok(std_metadata_mode(&metadata))
    }

    async fn set_len(&self, handle: &FileHandle, size: u64) -> VfsResult<()> {
        let file_arc = {
            let files = self.open_files.read().await;
            files.get(handle).cloned().ok_or(VfsError::InvalidHandle)?
        };
        file_arc
            .write()
            .await
            .0
            .set_len(size)
            .await
            .map_err(classify_io_error)
    }

    async fn rename(&self, handle: &DirHandle, src: &str, dst: &str) -> VfsResult<()> {
        let dir = self.get_dir(handle).await?;
        let src = make_relative(src).to_path_buf();
        let dst = make_relative(dst).to_path_buf();
        if src.as_os_str().is_empty() || dst.as_os_str().is_empty() {
            return Err(VfsError::PermissionDenied(
                "Cannot rename a capability root".into(),
            ));
        }
        tokio::task::spawn_blocking(move || dir.rename(src, &dir, dst))
            .await
            .expect("spawn_blocking panicked")
            .map_err(classify_io_error)
    }

    async fn close(&self, handle: &FileHandle) -> VfsResult<()> {
        let mut files: tokio::sync::RwLockWriteGuard<'_, HashMap<FileHandle, OpenFileEntry>> =
            self.open_files.write().await;
        if files.remove(handle).is_none() {
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

    #[tokio::test]
    async fn positional_io_append_and_rename_preserve_open_handle_semantics() {
        let root = tempfile::tempdir().expect("root");
        let dir = DirHandle::new();
        let vfs = HostVfs::with_registered_dir(dir.clone(), root.path()).expect("VFS");

        let writer = vfs
            .open_mode(&dir, "build.log", VfsOpenMode::Write)
            .await
            .expect("writer");
        assert_eq!(
            vfs.write_at(&writer, 4, b"done")
                .await
                .expect("positioned write"),
            4
        );
        vfs.set_len(&writer, 10).await.expect("extend");
        assert_eq!(vfs.file_stat(&writer).await.expect("fstat").size, 10);
        vfs.close(&writer).await.expect("close writer");

        let appender = vfs
            .open_mode(&dir, "build.log", VfsOpenMode::Append)
            .await
            .expect("appender");
        vfs.write_at(&appender, 0, b"!")
            .await
            .expect("append ignores offset");
        vfs.sync_data(&appender).await.expect("sync");
        vfs.close(&appender).await.expect("close appender");

        vfs.rename(&dir, "build.log", "renamed.log")
            .await
            .expect("rename");
        assert!(!root.path().join("build.log").exists());
        assert_eq!(
            std::fs::read(root.path().join("renamed.log")).expect("renamed bytes"),
            b"\0\0\0\0done\0\0!"
        );
    }

    #[tokio::test]
    async fn read_write_mode_requires_an_existing_file() {
        let root = tempfile::tempdir().expect("root");
        let dir = DirHandle::new();
        let vfs = HostVfs::with_registered_dir(dir.clone(), root.path()).expect("VFS");
        assert!(matches!(
            vfs.open_mode(&dir, "missing", VfsOpenMode::ReadWrite).await,
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

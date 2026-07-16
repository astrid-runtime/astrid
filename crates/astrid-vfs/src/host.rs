use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use astrid_capabilities::{DirHandle, FileHandle};
use async_trait::async_trait;
use cap_std::fs::Dir;
use tokio::fs;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};

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
    /// Returns `VfsError::Io` when the directory cannot be opened.
    pub fn with_registered_dir(handle: DirHandle, physical_path: &Path) -> VfsResult<Self> {
        let dir = Dir::open_ambient_dir(physical_path, cap_std::ambient_authority())
            .map_err(VfsError::Io)?;
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
    /// Returns a `VfsError::Io` if the directory cannot be opened.
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
                Err(VfsError::Io(e))
            },
        }
    }

    async fn get_dir(&self, handle: &DirHandle) -> VfsResult<Arc<Dir>> {
        let dirs: tokio::sync::RwLockReadGuard<'_, HashMap<DirHandle, Arc<Dir>>> =
            self.open_dirs.read().await;
        dirs.get(handle).cloned().ok_or(VfsError::InvalidHandle)
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
            .map_err(VfsError::Io)?;

            let mut entries = Vec::new();
            for entry_res in iter {
                let entry = entry_res.map_err(VfsError::Io)?;
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
            .map_err(VfsError::Io)?;

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
            .map_err(VfsError::Io)
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
            let meta = dir.symlink_metadata(&safe_path).map_err(VfsError::Io)?;
            if meta.is_dir() {
                dir.remove_dir(&safe_path).map_err(VfsError::Io)
            } else {
                dir.remove_file(&safe_path).map_err(VfsError::Io)
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
        let dir = self.get_dir(handle).await?;
        let safe_path = make_relative(path).to_path_buf();

        // Prevent transient FD exhaustion via semaphore before calling the OS
        let permit = self
            .fd_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| VfsError::PermissionDenied("Too many open files".into()))?;

        let std_file = tokio::task::spawn_blocking(move || {
            let mut options = cap_std::fs::OpenOptions::new();
            options
                .read(true)
                .write(write)
                .create(write)
                .truncate(truncate);
            dir.open_with(&safe_path, &options)
        })
        .await
        .expect("spawn_blocking panicked")
        .map_err(VfsError::Io)?;

        // Convert the cap_std File into a tokio async File
        let tokio_file = tokio::fs::File::from_std(std_file.into_std());

        let mut files: tokio::sync::RwLockWriteGuard<'_, HashMap<FileHandle, OpenFileEntry>> =
            self.open_files.write().await;
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
        .map_err(VfsError::Io)?;

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

        let meta = file.metadata().await.map_err(VfsError::Io)?;
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
            .map_err(VfsError::Io)?;

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
            files.get(handle).cloned().ok_or(VfsError::InvalidHandle)?
        };

        let mut file_tuple = file_arc.write().await;
        let file = &mut file_tuple.0;
        file.write_all(content).await.map_err(VfsError::Io)?;
        file.flush().await.map_err(VfsError::Io)?;
        Ok(())
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

    #[test]
    fn synchronous_constructor_rejects_a_missing_root() {
        let root = tempfile::tempdir().expect("root");
        let missing = root.path().join("missing");
        let result = HostVfs::with_registered_dir(DirHandle::new(), &missing);
        assert!(matches!(result, Err(VfsError::Io(_))));
    }
}

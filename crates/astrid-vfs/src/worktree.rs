use crate::boundary::IgnoreBoundary;
use crate::{HostVfs, Vfs, VfsDirEntry, VfsError, VfsMetadata, VfsOpenMode, VfsResult};
use astrid_capabilities::{DirHandle, FileHandle};
use async_trait::async_trait;
use std::path::{Path, PathBuf};

/// A Virtual Filesystem that wraps a `HostVfs` and strictly enforces `.astridignore` rules.
///
/// This is used to lock agents into their dedicated git worktrees while mathematically
/// preventing them from accessing or modifying local state (like `.env` files or databases)
/// that might be present in the worktree but ignored by Git.
pub(crate) struct WorktreeVfs {
    /// The underlying capability-based filesystem.
    inner: HostVfs,
    /// The absolute security boundary.
    boundary: IgnoreBoundary,
}

impl WorktreeVfs {
    /// Creates a new `WorktreeVfs`.
    ///
    /// # Arguments
    /// * `inner` - A `HostVfs` instance already bound to the physical worktree directory.
    /// * `boundary` - The loaded `.astridignore` rules to enforce.
    #[must_use]
    pub(crate) fn new(inner: HostVfs, boundary: IgnoreBoundary) -> Self {
        Self { inner, boundary }
    }

    /// Helper to verify a path against the boundary before passing it to the inner VFS.
    fn check_access(&self, path: &str, is_dir: bool) -> VfsResult<()> {
        if self.boundary.is_ignored(path, is_dir) {
            return Err(VfsError::PermissionDenied(format!(
                "Path is protected by .astridignore boundary: {path}"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl Vfs for WorktreeVfs {
    async fn exists(&self, handle: &DirHandle, path: &str) -> VfsResult<bool> {
        // We don't know if it's a file or dir yet, but usually exists checks are conservative.
        // We check it as a file first. If the file exists but is blocked, we pretend it doesn't exist.
        if self.boundary.is_ignored(path, false) || self.boundary.is_ignored(path, true) {
            return Ok(false);
        }
        self.inner.exists(handle, path).await
    }

    async fn readdir(&self, handle: &DirHandle, path: &str) -> VfsResult<Vec<VfsDirEntry>> {
        self.check_access(path, true)?;
        let mut entries = self.inner.readdir(handle, path).await?;

        // Filter out entries that match the ignore boundary.
        let base_path = Path::new(path);
        entries.retain(|entry| {
            let entry_path = if path.is_empty() {
                PathBuf::from(&entry.name)
            } else {
                base_path.join(&entry.name)
            };
            !self.boundary.is_ignored(&entry_path, entry.is_dir)
        });

        Ok(entries)
    }

    async fn stat(&self, handle: &DirHandle, path: &str) -> VfsResult<VfsMetadata> {
        // Have to stat it first to know if it's a dir, but we can't let them stat blocked paths.
        // We do the stat on inner first. If inner fails, we fail. If it succeeds, we check boundary.
        let meta = self.inner.stat(handle, path).await?;
        self.check_access(path, meta.is_dir)?;
        Ok(meta)
    }

    async fn mode(&self, handle: &DirHandle, path: &str) -> VfsResult<u32> {
        let meta = self.inner.stat(handle, path).await?;
        self.check_access(path, meta.is_dir)?;
        self.inner.mode(handle, path).await
    }

    async fn mkdir(&self, handle: &DirHandle, path: &str) -> VfsResult<()> {
        self.check_access(path, true)?;
        self.inner.mkdir(handle, path).await
    }

    async fn unlink(&self, handle: &DirHandle, path: &str) -> VfsResult<()> {
        // We don't know if it's a file or dir being unlinked without a stat,
        // so we protect against both forms of ignore rules to be safe.
        if self.boundary.is_ignored(path, false) || self.boundary.is_ignored(path, true) {
            return Err(VfsError::PermissionDenied(format!(
                "Path is protected by .astridignore boundary: {path}"
            )));
        }
        self.inner.unlink(handle, path).await
    }

    async fn open(
        &self,
        handle: &DirHandle,
        path: &str,
        write: bool,
        truncate: bool,
    ) -> VfsResult<FileHandle> {
        self.check_access(path, false)?;
        self.inner.open(handle, path, write, truncate).await
    }

    async fn open_mode(
        &self,
        handle: &DirHandle,
        path: &str,
        mode: VfsOpenMode,
    ) -> VfsResult<FileHandle> {
        self.check_access(path, false)?;
        self.inner.open_mode(handle, path, mode).await
    }

    async fn open_dir(
        &self,
        handle: &DirHandle,
        path: &str,
        new_handle: DirHandle,
    ) -> VfsResult<()> {
        self.check_access(path, true)?;
        self.inner.open_dir(handle, path, new_handle).await
    }

    async fn close_dir(&self, handle: &DirHandle) -> VfsResult<()> {
        // Close operations don't take paths, just opaque handles, so no boundary check needed.
        self.inner.close_dir(handle).await
    }

    async fn read(&self, handle: &FileHandle) -> VfsResult<Vec<u8>> {
        self.inner.read(handle).await
    }

    async fn read_at(
        &self,
        handle: &FileHandle,
        offset: u64,
        max_bytes: u32,
    ) -> VfsResult<Vec<u8>> {
        self.inner.read_at(handle, offset, max_bytes).await
    }

    async fn write(&self, handle: &FileHandle, content: &[u8]) -> VfsResult<()> {
        self.inner.write(handle, content).await
    }

    async fn write_at(&self, handle: &FileHandle, offset: u64, content: &[u8]) -> VfsResult<u32> {
        self.inner.write_at(handle, offset, content).await
    }

    async fn sync_data(&self, handle: &FileHandle) -> VfsResult<()> {
        self.inner.sync_data(handle).await
    }

    async fn sync_all(&self, handle: &FileHandle) -> VfsResult<()> {
        self.inner.sync_all(handle).await
    }

    async fn file_stat(&self, handle: &FileHandle) -> VfsResult<VfsMetadata> {
        self.inner.file_stat(handle).await
    }

    async fn file_mode(&self, handle: &FileHandle) -> VfsResult<u32> {
        self.inner.file_mode(handle).await
    }

    async fn set_len(&self, handle: &FileHandle, size: u64) -> VfsResult<()> {
        self.inner.set_len(handle, size).await
    }

    async fn rename(&self, handle: &DirHandle, src: &str, dst: &str) -> VfsResult<()> {
        let src_meta = self.inner.stat(handle, src).await?;
        self.check_access(src, src_meta.is_dir)?;
        // A missing destination has no metadata to classify. Check both ignore
        // forms so a rename cannot create either a protected file or directory.
        if self.boundary.is_ignored(dst, false) || self.boundary.is_ignored(dst, true) {
            return Err(VfsError::PermissionDenied(format!(
                "Path is protected by .astridignore boundary: {dst}"
            )));
        }
        self.inner.rename(handle, src, dst).await
    }

    async fn close(&self, handle: &FileHandle) -> VfsResult<()> {
        self.inner.close(handle).await
    }
}

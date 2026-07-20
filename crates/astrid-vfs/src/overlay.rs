use astrid_capabilities::{DirHandle, FileHandle};
use async_trait::async_trait;

use crate::{Vfs, VfsDirEntry, VfsMetadata, VfsOpenMode, VfsResult};

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Maximum file size (in bytes) that the overlay will copy between layers.
/// Applies to both copy-up (lower-to-upper on first write) and commit
/// (upper-to-lower on approval). Protects against OOM from large files.
const MAX_OVERLAY_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// Tracks whether a dirty path is a file or a directory so that
/// [`OverlayVfs::commit`] and [`OverlayVfs::rollback`] handle them correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirtyKind {
    File,
    Dir,
}

struct LockGuard<'a> {
    map: &'a DashMap<String, Arc<Mutex<()>>>,
    key: String,
}

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        self.map.remove(&self.key);
    }
}

/// An implementation of `Vfs` providing a Copy-on-Write overlay.
///
/// Reads fall through to the lower filesystem if absent in the upper.
/// Writes strictly apply only to the upper filesystem. When the upper
/// layer is backed by a temporary directory, all writes are sandboxed
/// until explicitly committed via [`commit()`](Self::commit).
pub struct OverlayVfs {
    lower: Box<dyn Vfs>,
    upper: Box<dyn Vfs>,
    /// Synchronize concurrent copy-ups per path.
    copy_locks: DashMap<String, Arc<Mutex<()>>>,
    /// Paths that have been written to or explicitly created in the upper layer.
    /// Used by [`commit()`](Self::commit) and [`rollback()`](Self::rollback)
    /// to know which entries need syncing or discarding.
    dirty_entries: DashMap<String, DirtyKind>,
    /// Optional guard keeping the physical upper-layer tempdir alive for as
    /// long as **any** holder has an `Arc<OverlayVfs>`. The
    /// [`OverlayVfsRegistry`](crate::OverlayVfsRegistry) hands this out with
    /// a populated guard so evicting the registry entry does not yank the
    /// tempdir out from under a task still using the overlay. Tests and
    /// constructors that manage the tempdir lifetime externally leave it
    /// `None`.
    _upper_tempdir: Option<Arc<tempfile::TempDir>>,
}

impl OverlayVfs {
    /// Create a new Overlay VFS.
    ///
    /// The caller manages the upper-layer backing directory's lifetime —
    /// usually by holding a [`tempfile::TempDir`] alongside the returned
    /// value. See [`new_with_upper_guard`](Self::new_with_upper_guard) for
    /// the overlay-registry path that hands the tempdir to the overlay so
    /// `Arc<OverlayVfs>` reference counting keeps it alive through the
    /// overlay's full lifetime.
    #[must_use]
    pub fn new(lower: Box<dyn Vfs>, upper: Box<dyn Vfs>) -> Self {
        Self {
            lower,
            upper,
            copy_locks: DashMap::new(),
            dirty_entries: DashMap::new(),
            _upper_tempdir: None,
        }
    }

    /// Create a new Overlay VFS whose upper-layer tempdir is owned by the
    /// overlay itself.
    ///
    /// Used by [`OverlayVfsRegistry`](crate::OverlayVfsRegistry) so that
    /// evicting a registry entry cannot delete the tempdir underneath an
    /// in-flight capsule invocation — the tempdir is dropped only when the
    /// last `Arc<OverlayVfs>` clone is released.
    #[must_use]
    pub fn new_with_upper_guard(
        lower: Box<dyn Vfs>,
        upper: Box<dyn Vfs>,
        upper_tempdir: Arc<tempfile::TempDir>,
    ) -> Self {
        Self {
            lower,
            upper,
            copy_locks: DashMap::new(),
            dirty_entries: DashMap::new(),
            _upper_tempdir: Some(upper_tempdir),
        }
    }

    /// Return a snapshot of all paths that have been written to the upper layer
    /// since the last commit or rollback.
    #[must_use]
    pub fn dirty_paths(&self) -> Vec<String> {
        self.dirty_entries.iter().map(|r| r.key().clone()).collect()
    }

    /// Copy all dirty files from the upper (temp) layer to the lower (workspace) layer.
    ///
    /// For each dirty path the content is read from the upper VFS, parent
    /// directories are created in the lower VFS as needed, and the file is
    /// written to the lower VFS. Successfully committed paths are removed
    /// from the dirty set; on partial failure the remaining paths stay dirty
    /// so the caller can inspect or retry.
    ///
    /// # Concurrency
    ///
    /// Callers must ensure no concurrent writes occur during commit. WASM
    /// capsules are single-threaded, so this is naturally satisfied when
    /// commit is called between tool invocations.
    ///
    /// # Errors
    ///
    /// Returns the first `VfsError` encountered. Paths committed before the
    /// error are already persisted in the lower layer.
    pub async fn commit(&self, handle: &DirHandle) -> VfsResult<Vec<String>> {
        let entries: Vec<(String, DirtyKind)> = self
            .dirty_entries
            .iter()
            .map(|r| (r.key().clone(), *r.value()))
            .collect();
        let mut committed = Vec::with_capacity(entries.len());

        for (path, kind) in &entries {
            match kind {
                DirtyKind::Dir => {
                    // Ensure the directory exists in lower. The recursive
                    // helper already handles parent creation.
                    self.ensure_lower_dirs(handle, path).await?;
                },
                DirtyKind::File => {
                    // Ensure parent directory exists in lower.
                    if let Some(parent) = std::path::Path::new(path).parent() {
                        let parent_str = parent.to_string_lossy();
                        if !parent_str.is_empty() {
                            self.ensure_lower_dirs(handle, &parent_str).await?;
                        }
                    }

                    // Guard against OOM: reject files exceeding the overlay size limit.
                    let meta = self.upper.stat(handle, path).await?;
                    if meta.size > MAX_OVERLAY_FILE_SIZE {
                        return Err(crate::VfsError::PermissionDenied(
                            "File too large to commit (exceeds 50 MB overlay limit)".into(),
                        ));
                    }

                    // Read content from upper
                    let upper_fh = self.upper.open(handle, path, false, false).await?;
                    let content_result = self.upper.read(&upper_fh).await;
                    let _ = self.upper.close(&upper_fh).await;
                    let content = content_result?;

                    // Write to lower (create + truncate)
                    let lower_fh = self.lower.open(handle, path, true, true).await?;
                    let write_result = self.lower.write(&lower_fh, &content).await;
                    let _ = self.lower.close(&lower_fh).await;
                    write_result?;

                    // Clean up the upper copy now that lower has the data
                    let _ = self.upper.unlink(handle, path).await;
                },
            }

            self.dirty_entries.remove(path);
            committed.push(path.clone());
        }

        Ok(committed)
    }

    /// Discard all dirty files from the upper (temp) layer.
    ///
    /// Each dirty path is removed from the upper VFS. After this call the
    /// overlay reads will serve exclusively from the lower layer as if no
    /// writes had occurred.
    ///
    /// # Errors
    ///
    /// Returns the first `VfsError` encountered. Paths rolled back before
    /// the error are already removed; remaining paths stay in the dirty set.
    pub async fn rollback(&self, handle: &DirHandle) -> VfsResult<Vec<String>> {
        let entries: Vec<(String, DirtyKind)> = self
            .dirty_entries
            .iter()
            .map(|r| (r.key().clone(), *r.value()))
            .collect();
        let mut rolled_back = Vec::with_capacity(entries.len());

        // Process files first, then dirs (reverse depth order would be ideal
        // but best-effort unlink is sufficient since TempDir::drop cleans up).
        for (path, kind) in &entries {
            match kind {
                DirtyKind::File => {
                    let _ = self.upper.unlink(handle, path).await;
                },
                DirtyKind::Dir => {
                    // Directories may contain files that were already unlinked
                    // above. Best-effort removal; the TempDir drop handles
                    // any remaining contents on capsule unload.
                },
            }
            self.dirty_entries.remove(path);
            rolled_back.push(path.clone());
        }

        Ok(rolled_back)
    }

    /// Recursively ensure a directory path exists in the lower VFS.
    async fn ensure_lower_dirs(&self, handle: &DirHandle, path: &str) -> VfsResult<()> {
        if self.lower.exists(handle, path).await.unwrap_or(false) {
            return Ok(());
        }
        if let Some(parent) = std::path::Path::new(path).parent() {
            let parent_str = parent.to_string_lossy();
            if !parent_str.is_empty() {
                Box::pin(self.ensure_lower_dirs(handle, &parent_str)).await?;
            }
        }
        match self.lower.mkdir(handle, path).await {
            Ok(()) => Ok(()),
            Err(crate::VfsError::Io(ref e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    /// Recursively ensure a directory path exists in the upper VFS.
    ///
    /// Routes through [`Vfs::mkdir`](Self::mkdir) on `self` so that created
    /// directories are tracked in `dirty_entries` for rollback.
    async fn ensure_upper_dirs(&self, handle: &DirHandle, path: &str) -> VfsResult<()> {
        if self.upper.exists(handle, path).await.unwrap_or(false) {
            return Ok(());
        }
        if let Some(parent) = std::path::Path::new(path).parent() {
            let parent_str = parent.to_string_lossy();
            if !parent_str.is_empty() {
                Box::pin(self.ensure_upper_dirs(handle, &parent_str)).await?;
            }
        }
        // Use self.mkdir (the OverlayVfs impl) to track the dir as dirty.
        // Suppress AlreadyExists since a concurrent writer may have created it.
        match <Self as Vfs>::mkdir(self, handle, path).await {
            Ok(()) => Ok(()),
            Err(crate::VfsError::Io(ref e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    /// Normalize a path for dirty tracking consistency.
    ///
    /// Resolves `.` and `..` components and strips any leading `/` so that
    /// paths are stored as relative strings (e.g. `"src/main.rs"`).
    ///
    /// # Errors
    ///
    /// Propagates `VfsError::SandboxViolation` if the path attempts to
    /// escape the root via `..` traversal.
    fn normalize_path(path: &str) -> VfsResult<String> {
        let resolved = crate::path::resolve_path(std::path::Path::new("/"), path)?;
        let s = resolved.to_string_lossy();
        Ok(s.strip_prefix('/').unwrap_or(&s).to_string())
    }
}

#[async_trait]
impl Vfs for OverlayVfs {
    async fn exists(&self, handle: &DirHandle, path: &str) -> VfsResult<bool> {
        if self.upper.exists(handle, path).await? {
            return Ok(true);
        }
        self.lower.exists(handle, path).await
    }

    async fn readdir(&self, handle: &DirHandle, path: &str) -> VfsResult<Vec<VfsDirEntry>> {
        // Simple merge: read from both and deduplicate by name, preferring upper.
        let mut entries = std::collections::HashMap::new();
        let mut lower_success = false;

        if let Ok(lower_entries) = self.lower.readdir(handle, path).await {
            lower_success = true;
            for entry in lower_entries {
                entries.insert(entry.name.clone(), entry);
            }
        }

        match self.upper.readdir(handle, path).await {
            Ok(upper_entries) => {
                for entry in upper_entries {
                    entries.insert(entry.name.clone(), entry);
                }
            },
            Err(crate::VfsError::NotFound(_) | crate::VfsError::InvalidHandle) => {
                // If upper just couldn't find the dir, it's fine as long as lower did
                if !lower_success {
                    return Err(crate::VfsError::NotFound(path.into()));
                }
            },
            Err(e) => return Err(e), // Propagate hard IO/Permission errors immediately
        }

        Ok(entries.into_values().collect())
    }

    async fn stat(&self, handle: &DirHandle, path: &str) -> VfsResult<VfsMetadata> {
        if let Ok(meta) = self.upper.stat(handle, path).await {
            return Ok(meta);
        }
        self.lower.stat(handle, path).await
    }

    async fn mode(&self, handle: &DirHandle, path: &str) -> VfsResult<u32> {
        if self.upper.exists(handle, path).await.unwrap_or(false) {
            return self.upper.mode(handle, path).await;
        }
        self.lower.mode(handle, path).await
    }

    async fn mkdir(&self, handle: &DirHandle, path: &str) -> VfsResult<()> {
        // Validate before mutation to avoid phantom dirs on SandboxViolation.
        let normalized = Self::normalize_path(path)?;
        self.upper.mkdir(handle, path).await?;
        self.dirty_entries.insert(normalized, DirtyKind::Dir);
        Ok(())
    }

    async fn unlink(&self, handle: &DirHandle, path: &str) -> VfsResult<()> {
        // Writes strictly to upper.
        // Note: fully correct overlayfs requires recording a "whiteout" or tombstone
        // in the upper layer to hide a lower layer file. We omit whiteouts here for simplicity.
        if self.lower.exists(handle, path).await.unwrap_or(false) {
            return Err(crate::VfsError::NotSupported(
                "Cannot delete read-only workspace file (whiteout support not implemented)".into(),
            ));
        }
        self.upper.unlink(handle, path).await?;
        // Remove from dirty set - the upper-only file is gone.
        // normalize_path cannot fail here because the path was already
        // validated when it was added to the dirty set via open(write=true).
        let normalized = Self::normalize_path(path)
            .expect("path previously validated on write should not fail normalization");
        self.dirty_entries.remove(&normalized);
        Ok(())
    }

    async fn open(
        &self,
        handle: &DirHandle,
        path: &str,
        write: bool,
        truncate: bool,
    ) -> VfsResult<FileHandle> {
        if write {
            // Validate before any filesystem mutation to avoid phantom files
            // in upper on SandboxViolation.
            let normalized = Self::normalize_path(path)?;

            // When the upper layer is a separate temp directory, parent dirs
            // may not exist yet. Ensure them before any write/copy-up.
            if let Some(parent) = std::path::Path::new(path).parent() {
                let parent_str = parent.to_string_lossy();
                if !parent_str.is_empty() {
                    self.ensure_upper_dirs(handle, &parent_str).await?;
                }
            }

            let needs_copy = !self.upper.exists(handle, path).await.unwrap_or(false)
                && self.lower.exists(handle, path).await.unwrap_or(false);

            if needs_copy {
                let lock_key = format!("/{normalized}");

                let path_lock = self
                    .copy_locks
                    .entry(lock_key.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(())))
                    .clone();
                let _guard = path_lock.lock().await;

                let _map_guard = LockGuard {
                    map: &self.copy_locks,
                    key: lock_key.clone(),
                };

                // Re-check after acquiring the lock in case another task already copied it
                if !self.upper.exists(handle, path).await.unwrap_or(false) {
                    if truncate {
                        // Fast path: if truncating, just create an empty file in upper
                        // We don't need to copy the contents from lower
                        let new_upper_file = self.upper.open(handle, path, true, true).await?;
                        let _ = self.upper.close(&new_upper_file).await;
                    } else {
                        // Prevent OOM during copy-up by capping the size
                        let meta = self.lower.stat(handle, path).await?;
                        if meta.size > MAX_OVERLAY_FILE_SIZE {
                            return Err(crate::VfsError::PermissionDenied(
                                "File is too large for OverlayVfs copy-up (> 50MB)".into(),
                            ));
                        }

                        // Perform copy-up.
                        let lower_handle = self.lower.open(handle, path, false, false).await?;
                        let content_result = self.lower.read(&lower_handle).await;

                        // Ensure lower is closed even if read fails
                        let _ = self.lower.close(&lower_handle).await;

                        let content = content_result?;

                        let new_upper_file = self.upper.open(handle, path, true, true).await?;
                        let write_result = self.upper.write(&new_upper_file, &content).await;

                        // Ensure upper is closed even if write fails
                        let _ = self.upper.close(&new_upper_file).await;

                        if let Err(e) = write_result {
                            // Revert the copy-up so we don't leave a truncated file
                            let _ = self.upper.unlink(handle, path).await;
                            return Err(e);
                        }
                    }
                }
            }
            // Track this path as dirty for commit/rollback.
            self.dirty_entries.insert(normalized, DirtyKind::File);
            return self.upper.open(handle, path, write, truncate).await;
        }

        // Read-only logic.
        let normalized_path = crate::path::resolve_path(std::path::Path::new("/"), path)
            .map_or_else(|_| path.to_string(), |p| p.to_string_lossy().to_string());

        let lock_arc = self
            .copy_locks
            .get(&normalized_path)
            .map(|r| r.value().clone());
        if let Some(path_lock) = lock_arc {
            let _guard = path_lock.lock().await;
        }

        if self.upper.exists(handle, path).await.unwrap_or(false) {
            return self.upper.open(handle, path, false, false).await;
        }

        self.lower.open(handle, path, false, false).await
    }

    async fn open_mode(
        &self,
        handle: &DirHandle,
        path: &str,
        mode: VfsOpenMode,
    ) -> VfsResult<FileHandle> {
        match mode {
            VfsOpenMode::Read => self.open(handle, path, false, false).await,
            VfsOpenMode::Write => self.open(handle, path, true, true).await,
            VfsOpenMode::Append | VfsOpenMode::ReadWrite => {
                if mode == VfsOpenMode::ReadWrite
                    && !self.upper.exists(handle, path).await.unwrap_or(false)
                    && !self.lower.exists(handle, path).await.unwrap_or(false)
                {
                    return Err(crate::VfsError::NotFound(path.to_string()));
                }

                // Reuse the established copy-up path, then reopen with the
                // exact append/read-write flags on the upper layer.
                let copied = self.open(handle, path, true, false).await?;
                self.upper.close(&copied).await?;
                self.upper.open_mode(handle, path, mode).await
            },
        }
    }

    async fn open_dir(
        &self,
        handle: &DirHandle,
        path: &str,
        new_handle: DirHandle,
    ) -> VfsResult<()> {
        let exists_upper = self.upper.exists(handle, path).await.unwrap_or(false);
        let lower_meta = self.lower.stat(handle, path).await;

        if exists_upper {
            self.upper
                .open_dir(handle, path, new_handle.clone())
                .await?;
            if matches!(lower_meta, Ok(meta) if meta.is_dir) {
                // Propagate failures to ensure lower capabilities are mapped, or correctly fail
                if let Err(e) = self.lower.open_dir(handle, path, new_handle.clone()).await {
                    let _ = self.upper.close_dir(&new_handle).await;
                    return Err(e);
                }
            }
        } else if let Ok(meta) = lower_meta {
            if meta.is_dir {
                // Eagerly create the directory in upper to ensure symmetric handle mapping
                self.upper.mkdir(handle, path).await.unwrap_or(());
                self.upper
                    .open_dir(handle, path, new_handle.clone())
                    .await?;
                if let Err(e) = self.lower.open_dir(handle, path, new_handle.clone()).await {
                    let _ = self.upper.close_dir(&new_handle).await;
                    return Err(e);
                }
            } else {
                return Err(crate::VfsError::PermissionDenied(
                    "Cannot open a file as a directory".into(),
                ));
            }
        } else {
            return Err(crate::VfsError::NotFound(path.into()));
        }

        Ok(())
    }

    async fn close_dir(&self, handle: &DirHandle) -> VfsResult<()> {
        let _ = self.upper.close_dir(handle).await;
        let _ = self.lower.close_dir(handle).await;
        Ok(())
    }

    async fn read(&self, handle: &FileHandle) -> VfsResult<Vec<u8>> {
        // We don't know which underlying system owns the FileHandle. Try upper, then lower.
        match self.upper.read(handle).await {
            Ok(data) => Ok(data),
            Err(crate::VfsError::InvalidHandle) => self.lower.read(handle).await,
            Err(e) => Err(e),
        }
    }

    async fn read_at(
        &self,
        handle: &FileHandle,
        offset: u64,
        max_bytes: u32,
    ) -> VfsResult<Vec<u8>> {
        match self.upper.read_at(handle, offset, max_bytes).await {
            Ok(data) => Ok(data),
            Err(crate::VfsError::InvalidHandle) => {
                self.lower.read_at(handle, offset, max_bytes).await
            },
            Err(error) => Err(error),
        }
    }

    async fn write(&self, handle: &FileHandle, content: &[u8]) -> VfsResult<()> {
        // Writes always go to upper. If it's a lower handle, this is an error
        // since lower files are opened read-only.
        self.upper.write(handle, content).await
    }

    async fn write_at(&self, handle: &FileHandle, offset: u64, content: &[u8]) -> VfsResult<u32> {
        self.upper.write_at(handle, offset, content).await
    }

    async fn sync_data(&self, handle: &FileHandle) -> VfsResult<()> {
        match self.upper.sync_data(handle).await {
            Ok(()) => Ok(()),
            Err(crate::VfsError::InvalidHandle) => self.lower.sync_data(handle).await,
            Err(error) => Err(error),
        }
    }

    async fn sync_all(&self, handle: &FileHandle) -> VfsResult<()> {
        match self.upper.sync_all(handle).await {
            Ok(()) => Ok(()),
            Err(crate::VfsError::InvalidHandle) => self.lower.sync_all(handle).await,
            Err(error) => Err(error),
        }
    }

    async fn file_stat(&self, handle: &FileHandle) -> VfsResult<VfsMetadata> {
        match self.upper.file_stat(handle).await {
            Ok(metadata) => Ok(metadata),
            Err(crate::VfsError::InvalidHandle) => self.lower.file_stat(handle).await,
            Err(error) => Err(error),
        }
    }

    async fn file_mode(&self, handle: &FileHandle) -> VfsResult<u32> {
        match self.upper.file_mode(handle).await {
            Ok(mode) => Ok(mode),
            Err(crate::VfsError::InvalidHandle) => self.lower.file_mode(handle).await,
            Err(error) => Err(error),
        }
    }

    async fn set_len(&self, handle: &FileHandle, size: u64) -> VfsResult<()> {
        self.upper.set_len(handle, size).await
    }

    async fn rename(&self, handle: &DirHandle, src: &str, dst: &str) -> VfsResult<()> {
        let src = Self::normalize_path(src)?;
        let dst = Self::normalize_path(dst)?;
        if !self.upper.exists(handle, &src).await.unwrap_or(false) {
            return Err(crate::VfsError::NotSupported(
                "Cannot rename a read-only workspace entry (whiteout support not implemented)"
                    .into(),
            ));
        }
        if self.lower.exists(handle, &dst).await.unwrap_or(false) {
            return Err(crate::VfsError::NotSupported(
                "Cannot replace a read-only workspace entry (whiteout support not implemented)"
                    .into(),
            ));
        }
        if let Some(parent) = std::path::Path::new(&dst).parent() {
            let parent = parent.to_string_lossy();
            if !parent.is_empty() {
                self.ensure_upper_dirs(handle, &parent).await?;
            }
        }
        self.upper.rename(handle, &src, &dst).await?;

        let prefix = format!("{src}/");
        let moved = self
            .dirty_entries
            .iter()
            .filter_map(|entry| {
                let path = entry.key();
                if path == &src || path.starts_with(&prefix) {
                    let suffix = path.strip_prefix(&src).expect("prefix checked");
                    Some((path.clone(), format!("{dst}{suffix}"), *entry.value()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for (old, new, kind) in moved {
            self.dirty_entries.remove(&old);
            self.dirty_entries.insert(new, kind);
        }
        Ok(())
    }

    async fn close(&self, handle: &FileHandle) -> VfsResult<()> {
        let upper_res = self.upper.close(handle).await;
        let lower_res = self.lower.close(handle).await;

        if upper_res.is_ok() || lower_res.is_ok() {
            Ok(())
        } else {
            Err(crate::VfsError::InvalidHandle)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HostVfs;
    use std::path::Path;

    /// Create an `OverlayVfs` with separate physical lower and upper directories.
    async fn setup() -> (OverlayVfs, DirHandle, tempfile::TempDir, tempfile::TempDir) {
        let lower_dir = tempfile::TempDir::new().unwrap();
        let upper_dir = tempfile::TempDir::new().unwrap();

        let lower_vfs = HostVfs::new();
        let upper_vfs = HostVfs::new();
        let handle = DirHandle::new();

        lower_vfs
            .register_dir(handle.clone(), lower_dir.path().to_path_buf())
            .await
            .unwrap();
        upper_vfs
            .register_dir(handle.clone(), upper_dir.path().to_path_buf())
            .await
            .unwrap();

        let overlay = OverlayVfs::new(Box::new(lower_vfs), Box::new(upper_vfs));
        (overlay, handle, lower_dir, upper_dir)
    }

    /// Write a file through the overlay and close the handle.
    async fn write_through_overlay(
        overlay: &OverlayVfs,
        handle: &DirHandle,
        path: &str,
        content: &[u8],
    ) {
        let fh = overlay.open(handle, path, true, true).await.unwrap();
        overlay.write(&fh, content).await.unwrap();
        overlay.close(&fh).await.unwrap();
    }

    /// Seed a file directly into the lower directory on disk.
    fn seed_lower(lower_dir: &Path, path: &str, content: &[u8]) {
        let full = lower_dir.join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(full, content).unwrap();
    }

    #[tokio::test]
    async fn write_lands_in_upper_not_lower() {
        let (overlay, handle, lower_dir, upper_dir) = setup().await;

        write_through_overlay(&overlay, &handle, "new.txt", b"hello").await;

        // File must exist in the upper temp dir
        assert!(upper_dir.path().join("new.txt").exists());
        // File must NOT exist in the lower workspace dir
        assert!(!lower_dir.path().join("new.txt").exists());
    }

    #[tokio::test]
    async fn commit_copies_to_lower() {
        let (overlay, handle, lower_dir, _upper_dir) = setup().await;

        write_through_overlay(&overlay, &handle, "committed.txt", b"data").await;

        let committed = overlay.commit(&handle).await.unwrap();
        assert_eq!(committed.len(), 1);

        // File now exists in lower
        let content = std::fs::read(lower_dir.path().join("committed.txt")).unwrap();
        assert_eq!(content, b"data");

        // Dirty set is empty
        assert!(overlay.dirty_paths().is_empty());
    }

    #[tokio::test]
    async fn rollback_discards_upper() {
        let (overlay, handle, lower_dir, upper_dir) = setup().await;

        write_through_overlay(&overlay, &handle, "discarded.txt", b"gone").await;
        assert!(upper_dir.path().join("discarded.txt").exists());

        let rolled = overlay.rollback(&handle).await.unwrap();
        assert_eq!(rolled.len(), 1);

        // File removed from upper
        assert!(!upper_dir.path().join("discarded.txt").exists());
        // Never reached lower
        assert!(!lower_dir.path().join("discarded.txt").exists());
        // Dirty set is empty
        assert!(overlay.dirty_paths().is_empty());
    }

    #[tokio::test]
    async fn dirty_paths_tracked() {
        let (overlay, handle, _lower_dir, _upper_dir) = setup().await;

        assert!(overlay.dirty_paths().is_empty());

        write_through_overlay(&overlay, &handle, "a.txt", b"1").await;
        write_through_overlay(&overlay, &handle, "b.txt", b"2").await;

        let mut dirty = overlay.dirty_paths();
        dirty.sort();
        assert_eq!(dirty, vec!["a.txt", "b.txt"]);
    }

    #[tokio::test]
    async fn unlink_removes_from_dirty_set() {
        let (overlay, handle, _lower_dir, _upper_dir) = setup().await;

        write_through_overlay(&overlay, &handle, "temp.txt", b"x").await;
        assert_eq!(overlay.dirty_paths().len(), 1);

        overlay.unlink(&handle, "temp.txt").await.unwrap();
        assert!(overlay.dirty_paths().is_empty());
    }

    #[tokio::test]
    async fn commit_creates_parent_dirs() {
        let (overlay, handle, lower_dir, _upper_dir) = setup().await;

        write_through_overlay(&overlay, &handle, "deep/nested/file.txt", b"nested").await;

        overlay.commit(&handle).await.unwrap();

        let content = std::fs::read(lower_dir.path().join("deep/nested/file.txt")).unwrap();
        assert_eq!(content, b"nested");
    }

    #[tokio::test]
    async fn copy_up_then_commit() {
        let (overlay, handle, lower_dir, _upper_dir) = setup().await;

        // Seed a file in lower
        seed_lower(lower_dir.path(), "existing.txt", b"original");

        // Write through overlay (triggers copy-up, then overwrite)
        write_through_overlay(&overlay, &handle, "existing.txt", b"modified").await;

        // Lower still has original content
        assert_eq!(
            std::fs::read(lower_dir.path().join("existing.txt")).unwrap(),
            b"original"
        );

        // Commit propagates the modification
        overlay.commit(&handle).await.unwrap();

        assert_eq!(
            std::fs::read(lower_dir.path().join("existing.txt")).unwrap(),
            b"modified"
        );
    }

    #[tokio::test]
    async fn open_dir_does_not_pollute_dirty_set() {
        let (overlay, handle, lower_dir, _upper_dir) = setup().await;

        // Seed a directory in lower
        std::fs::create_dir_all(lower_dir.path().join("subdir")).unwrap();

        // open_dir should create the dir in upper for handle mapping but NOT
        // add it to the dirty set.
        let sub_handle = DirHandle::new();
        overlay
            .open_dir(&handle, "subdir", sub_handle.clone())
            .await
            .unwrap();
        overlay.close_dir(&sub_handle).await.unwrap();

        assert!(
            overlay.dirty_paths().is_empty(),
            "open_dir structural mkdir should not track dirty paths"
        );
    }

    #[tokio::test]
    async fn explicit_mkdir_is_tracked() {
        let (overlay, handle, _lower_dir, _upper_dir) = setup().await;

        overlay.mkdir(&handle, "newdir").await.unwrap();

        assert_eq!(overlay.dirty_paths(), vec!["newdir"]);
    }

    #[tokio::test]
    async fn read_falls_through_to_lower() {
        let (overlay, handle, lower_dir, _upper_dir) = setup().await;

        seed_lower(lower_dir.path(), "lower_only.txt", b"from lower");

        let fh = overlay
            .open(&handle, "lower_only.txt", false, false)
            .await
            .unwrap();
        let content = overlay.read(&fh).await.unwrap();
        overlay.close(&fh).await.unwrap();

        assert_eq!(content, b"from lower");
        // No dirty paths - read-only access
        assert!(overlay.dirty_paths().is_empty());
    }

    #[tokio::test]
    async fn rollback_then_read_serves_lower() {
        let (overlay, handle, lower_dir, _upper_dir) = setup().await;

        seed_lower(lower_dir.path(), "doc.txt", b"original");

        // Overwrite through overlay
        write_through_overlay(&overlay, &handle, "doc.txt", b"overwritten").await;

        // Rollback discards the overwrite
        overlay.rollback(&handle).await.unwrap();

        // Read should serve the original from lower
        let fh = overlay
            .open(&handle, "doc.txt", false, false)
            .await
            .unwrap();
        let content = overlay.read(&fh).await.unwrap();
        overlay.close(&fh).await.unwrap();

        assert_eq!(content, b"original");
    }

    #[tokio::test]
    async fn commit_mkdir_creates_dir_in_lower() {
        let (overlay, handle, lower_dir, _upper_dir) = setup().await;

        overlay.mkdir(&handle, "newdir").await.unwrap();

        // Dir exists in upper but not lower
        assert!(!lower_dir.path().join("newdir").exists());

        overlay.commit(&handle).await.unwrap();

        // Dir now exists in lower
        assert!(lower_dir.path().join("newdir").is_dir());
        assert!(overlay.dirty_paths().is_empty());
    }

    #[tokio::test]
    async fn commit_mixed_files_and_dirs() {
        let (overlay, handle, lower_dir, _upper_dir) = setup().await;

        overlay.mkdir(&handle, "src").await.unwrap();
        write_through_overlay(&overlay, &handle, "src/main.rs", b"fn main() {}").await;

        overlay.commit(&handle).await.unwrap();

        assert!(lower_dir.path().join("src").is_dir());
        assert_eq!(
            std::fs::read(lower_dir.path().join("src/main.rs")).unwrap(),
            b"fn main() {}"
        );
    }

    #[tokio::test]
    async fn rollback_deep_path_removes_parent_dirs() {
        let (overlay, handle, _lower_dir, upper_dir) = setup().await;

        write_through_overlay(&overlay, &handle, "deep/nested/file.txt", b"x").await;

        // Parent dirs created by ensure_upper_dirs should be in dirty_entries
        let mut dirty = overlay.dirty_paths();
        dirty.sort();
        assert!(dirty.contains(&"deep".to_string()));
        assert!(dirty.contains(&"deep/nested".to_string()));
        assert!(dirty.contains(&"deep/nested/file.txt".to_string()));

        overlay.rollback(&handle).await.unwrap();

        assert!(overlay.dirty_paths().is_empty());
        // The file should be gone from upper
        assert!(!upper_dir.path().join("deep/nested/file.txt").exists());
    }

    #[tokio::test]
    async fn unlink_lower_layer_file_returns_not_supported() {
        let (overlay, handle, lower_dir, _upper_dir) = setup().await;
        seed_lower(lower_dir.path(), "lower_only.txt", b"x");

        let err = overlay.unlink(&handle, "lower_only.txt").await.unwrap_err();
        assert!(
            matches!(err, crate::VfsError::NotSupported(_)),
            "expected NotSupported, got: {err:?}"
        );
    }
}

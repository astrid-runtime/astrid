//! Astrid Virtual File System (VFS).
//!
//! Provides an abstraction over filesystem operations to support strict sandboxing,
//! capability-based access, and overlay (copy-on-write) implementations.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

/// Security boundary enforcement via ignore rules.
#[allow(dead_code)]
pub(crate) mod boundary;
/// Virtual filesystem error types.
pub mod error;
/// Host-backed virtual filesystem implementation.
pub mod host;
/// Overlay (copy-on-write) virtual filesystem implementation.
pub mod overlay;
/// Per-principal registry of [`OverlayVfs`] instances (Layer 4, issue #668).
pub mod overlay_registry;
/// Path resolution and sandboxing utilities.
pub mod path;
/// OS-level copy-on-write for non-git agent workspaces (overlayfs / APFS
/// clonefile / fail-closed No-CoW) — the merged filesystem the fs host AND
/// spawned processes share.
pub mod workspace_cow;
/// Worktree-specific virtual filesystem implementation.
#[allow(dead_code)]
pub(crate) mod worktree;

pub use error::{VfsError, VfsResult};
pub use host::HostVfs;
pub use overlay::OverlayVfs;
pub use overlay_registry::OverlayVfsRegistry;
pub use workspace_cow::{
    CowCapability, NoCow, PreparedWorkspace, WorkspaceCow, detect_cow_backend, no_cow_workspace,
    prepare_workspace_cow,
};

use astrid_capabilities::{DirHandle, FileHandle};
use async_trait::async_trait;

/// File-open behavior understood by the VFS.
///
/// This is deliberately an enum instead of a collection of booleans so a
/// caller cannot construct an incoherent combination such as append plus
/// truncate. It matches the frozen `astrid:fs@1.0.0` open-mode contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsOpenMode {
    /// Open an existing file for reading only.
    Read,
    /// Open or create a file for writing and truncate existing content.
    Write,
    /// Open or create a file for append-only writes.
    Append,
    /// Open an existing file for reading and writing without truncation.
    ReadWrite,
}

/// File metadata returned by stat.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VfsMetadata {
    /// True if the entry is a directory.
    pub is_dir: bool,
    /// True if the entry is a file.
    pub is_file: bool,
    /// Size of the file in bytes.
    pub size: u64,
    /// Modification time in seconds since the UNIX epoch.
    pub mtime: u64,
}

/// Directory entry returned by readdir.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VfsDirEntry {
    /// Name of the entry.
    pub name: String,
    /// True if the entry is a directory.
    pub is_dir: bool,
}

/// A core virtual filesystem providing sandboxed operations.
#[async_trait]
pub trait Vfs: Send + Sync {
    /// Check if a path exists within the sandbox.
    async fn exists(&self, handle: &DirHandle, path: &str) -> VfsResult<bool>;

    /// Read the contents of a directory.
    async fn readdir(&self, handle: &DirHandle, path: &str) -> VfsResult<Vec<VfsDirEntry>>;

    /// Get metadata for a path.
    async fn stat(&self, handle: &DirHandle, path: &str) -> VfsResult<VfsMetadata>;

    /// Return best-effort POSIX mode bits for a path.
    ///
    /// Filesystems without a mode concept return zero. This separate additive
    /// method preserves the source-compatible shape of [`VfsMetadata`].
    async fn mode(&self, _handle: &DirHandle, _path: &str) -> VfsResult<u32> {
        Ok(0)
    }

    /// Create a new directory.
    async fn mkdir(&self, handle: &DirHandle, path: &str) -> VfsResult<()>;

    /// Remove a file.
    async fn unlink(&self, handle: &DirHandle, path: &str) -> VfsResult<()>;

    /// Open a file for reading/writing. Returns a handle.
    async fn open(
        &self,
        handle: &DirHandle,
        path: &str,
        write: bool,
        truncate: bool,
    ) -> VfsResult<FileHandle>;

    /// Open a file with the precise semantics of [`VfsOpenMode`].
    ///
    /// The default keeps older VFS implementations source-compatible for the
    /// two modes expressible by the original boolean API. Implementations that
    /// support append and non-creating read/write should override this method.
    async fn open_mode(
        &self,
        handle: &DirHandle,
        path: &str,
        mode: VfsOpenMode,
    ) -> VfsResult<FileHandle> {
        match mode {
            VfsOpenMode::Read => self.open(handle, path, false, false).await,
            VfsOpenMode::Write => self.open(handle, path, true, true).await,
            VfsOpenMode::Append | VfsOpenMode::ReadWrite => Err(VfsError::NotSupported(
                "precise append/read-write open mode".to_string(),
            )),
        }
    }

    /// Open a subdirectory, granting a new narrowed capability handle.
    async fn open_dir(
        &self,
        handle: &DirHandle,
        path: &str,
        new_handle: DirHandle,
    ) -> VfsResult<()>;

    /// Close a directory handle.
    async fn close_dir(&self, handle: &DirHandle) -> VfsResult<()>;

    /// Read from an open file handle.
    async fn read(&self, handle: &FileHandle) -> VfsResult<Vec<u8>>;

    /// Read from an open file at an explicit byte offset.
    async fn read_at(
        &self,
        _handle: &FileHandle,
        _offset: u64,
        _max_bytes: u32,
    ) -> VfsResult<Vec<u8>> {
        Err(VfsError::NotSupported("positional file read".to_string()))
    }

    /// Write to an open file handle.
    async fn write(&self, handle: &FileHandle, content: &[u8]) -> VfsResult<()>;

    /// Write to an open file at an explicit byte offset.
    async fn write_at(
        &self,
        _handle: &FileHandle,
        _offset: u64,
        _content: &[u8],
    ) -> VfsResult<u32> {
        Err(VfsError::NotSupported("positional file write".to_string()))
    }

    /// Flush file data without requiring metadata durability.
    async fn sync_data(&self, _handle: &FileHandle) -> VfsResult<()> {
        Err(VfsError::NotSupported("file data sync".to_string()))
    }

    /// Flush file data and metadata.
    async fn sync_all(&self, _handle: &FileHandle) -> VfsResult<()> {
        Err(VfsError::NotSupported("file metadata sync".to_string()))
    }

    /// Return metadata for an already-open file handle.
    async fn file_stat(&self, _handle: &FileHandle) -> VfsResult<VfsMetadata> {
        Err(VfsError::NotSupported("open-file metadata".to_string()))
    }

    /// Return best-effort POSIX mode bits for an already-open file handle.
    async fn file_mode(&self, _handle: &FileHandle) -> VfsResult<u32> {
        Ok(0)
    }

    /// Truncate or extend an already-open file.
    async fn set_len(&self, _handle: &FileHandle, _size: u64) -> VfsResult<()> {
        Err(VfsError::NotSupported("open-file resize".to_string()))
    }

    /// Atomically rename a path within one directory-capability root.
    async fn rename(&self, _handle: &DirHandle, _src: &str, _dst: &str) -> VfsResult<()> {
        Err(VfsError::NotSupported("rename".to_string()))
    }

    /// Close a file handle.
    async fn close(&self, handle: &FileHandle) -> VfsResult<()>;
}

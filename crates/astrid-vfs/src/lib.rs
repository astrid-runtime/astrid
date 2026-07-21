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

/// Metadata returned by a non-following symbolic-link stat.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VfsSymlinkMetadata {
    /// Metadata for the directory entry itself.
    pub metadata: VfsMetadata,
    /// True when the entry is a symbolic link rather than its resolved target.
    pub is_symlink: bool,
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

    /// Get metadata for a path without following its final symbolic link.
    async fn stat_symlink(
        &self,
        _handle: &DirHandle,
        _path: &str,
    ) -> VfsResult<VfsSymlinkMetadata> {
        Err(VfsError::NotSupported(
            "non-following metadata is not supported by this VFS".to_owned(),
        ))
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

    /// Write to an open file handle.
    async fn write(&self, handle: &FileHandle, content: &[u8]) -> VfsResult<()>;

    /// Close a file handle.
    async fn close(&self, handle: &FileHandle) -> VfsResult<()>;

    /// Read bytes at an absolute offset without retaining an implicit cursor.
    async fn read_at(
        &self,
        _handle: &FileHandle,
        _offset: u64,
        _max_bytes: u32,
    ) -> VfsResult<Vec<u8>> {
        Err(VfsError::NotSupported(
            "positional file reads are not supported by this VFS".to_owned(),
        ))
    }

    /// Write bytes at an absolute offset without retaining an implicit cursor.
    async fn write_at(
        &self,
        _handle: &FileHandle,
        _offset: u64,
        _content: &[u8],
    ) -> VfsResult<u32> {
        Err(VfsError::NotSupported(
            "positional file writes are not supported by this VFS".to_owned(),
        ))
    }

    /// Get metadata from an already-open file handle.
    async fn file_stat(&self, _handle: &FileHandle) -> VfsResult<VfsMetadata> {
        Err(VfsError::NotSupported(
            "open-file metadata is not supported by this VFS".to_owned(),
        ))
    }

    /// Flush an already-open file, optionally including metadata.
    async fn sync_file(&self, _handle: &FileHandle, _data_only: bool) -> VfsResult<()> {
        Err(VfsError::NotSupported(
            "file synchronization is not supported by this VFS".to_owned(),
        ))
    }

    /// Truncate or extend an already-open file.
    async fn set_len(&self, _handle: &FileHandle, _size: u64) -> VfsResult<()> {
        Err(VfsError::NotSupported(
            "file resizing is not supported by this VFS".to_owned(),
        ))
    }

    /// Atomically rename a path within one directory capability root.
    async fn rename(&self, _handle: &DirHandle, _src: &str, _dst: &str) -> VfsResult<()> {
        Err(VfsError::NotSupported(
            "rename is not supported by this VFS".to_owned(),
        ))
    }
}

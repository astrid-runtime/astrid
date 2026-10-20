//! Owned file objects. No operation re-resolves an opened pathname.

use async_trait::async_trait;

use crate::{VfsMetadata, VfsResult};

/// Retains an already-admitted operation's authority until backend work settles.
///
/// This token does not authorize an operation. The host constructs it from its
/// principal invocation guard and workspace work lease after admission. Providers
/// must move it into any detached/native job, rather than retain it only in the
/// awaiting future. Idle file objects must not retain an operation's lease.
/// Tests and callers without authority accounting must explicitly supply their
/// inert value; there is deliberately no default or optional guard.
pub struct FileOperationGuard {
    _lease: Box<dyn Send + 'static>,
}

impl FileOperationGuard {
    /// Own the caller's admitted lease, or a tuple of leases, for this operation.
    #[must_use]
    pub fn new(lease: impl Send + 'static) -> Self {
        Self {
            _lease: Box::new(lease),
        }
    }
}

/// Byte position in an opened file, distinct from a file's length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileOffset(u64);

impl FileOffset {
    /// Construct a byte position; an individual backend may reject positions
    /// outside its native offset range.
    #[must_use]
    pub const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Return the byte position.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }
}

/// Logical byte length for an opened file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileLength(u64);

impl FileLength {
    /// Construct a logical length. Host policy must admit extension before
    /// calling a provider; sparse native extension is not a quota exemption.
    #[must_use]
    pub const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Return the logical length.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }
}

/// Requested read payload size. The host boundary enforces its wire and
/// principal limits before constructing this request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadLength(u32);

impl ReadLength {
    /// Construct a request for at most this many returned bytes.
    #[must_use]
    pub const fn new(bytes: u32) -> Self {
        Self(bytes)
    }

    /// Return the requested maximum payload size.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.0
    }
}

/// Explicit access and creation behavior; matches the frozen fs host modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenMode {
    /// Read an existing file; never create it.
    Read,
    /// Create or truncate a file for writing only.
    Write,
    /// Create or append to a file for writing only.
    Append,
    /// Read and write an existing file; never create it.
    ReadWrite,
}

/// An owned backend object, not a pathname or a dirty-close snapshot.
///
/// Dropping the last owner releases the object without publishing buffered
/// mutations. Implementations must retain any descriptor admission until
/// outstanding native work actually settles, even if its awaiting future is
/// cancelled. The host must separately retain operation authority through
/// that same interval via the required operation guard; possession of this object does not grant new authority.
#[async_trait]
pub trait VfsFile: Send + Sync {
    /// Read a bounded payload at the supplied offset, without a shared cursor.
    async fn read_at(
        &self,
        offset: FileOffset,
        length: ReadLength,
        guard: FileOperationGuard,
    ) -> VfsResult<Vec<u8>>;

    /// Perform one write and return its actual byte count. Append-mode objects
    /// issue one append-mode write, ignoring the supplied offset. A short write
    /// is returned as such; arbitrary-sized record atomicity is not guaranteed.
    async fn write_at(
        &self,
        offset: FileOffset,
        bytes: &[u8],
        guard: FileOperationGuard,
    ) -> VfsResult<usize>;

    /// Synchronize data with the backend's real persistence boundary.
    async fn sync_data(&self, guard: FileOperationGuard) -> VfsResult<()>;

    /// Synchronize data and metadata with the backend's persistence boundary.
    async fn sync_all(&self, guard: FileOperationGuard) -> VfsResult<()>;

    /// Inspect the opened object without looking up its former name.
    async fn stat(&self, guard: FileOperationGuard) -> VfsResult<VfsMetadata>;

    /// Truncate or extend the opened object, zero-filling newly exposed bytes.
    async fn set_len(&self, length: FileLength, guard: FileOperationGuard) -> VfsResult<()>;
}

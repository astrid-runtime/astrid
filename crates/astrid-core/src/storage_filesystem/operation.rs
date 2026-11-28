//! Native mount callback operation and entry kind shared with the verifier.
use vstd::prelude::*;

verus! {

/// Provider-independent filesystem entry kind.
#[cfg_attr(not(verus_keep_ghost), derive(Clone, Copy, Debug, serde::Deserialize, PartialEq, Eq, serde::Serialize))]
#[cfg_attr(not(verus_keep_ghost), serde(rename_all = "kebab-case"))]
pub enum StorageFilesystemEntryKindV1 {
    /// Regular byte file.
    File,
    /// Namespace directory.
    Directory,
}

/// One filesystem operation over the owner already bound to the lease.
#[cfg_attr(not(verus_keep_ghost), derive(Clone, Debug, serde::Deserialize, PartialEq, Eq, serde::Serialize))]
#[cfg_attr(not(verus_keep_ghost), serde(rename_all = "kebab-case", tag = "operation"))]
pub enum StorageFilesystemOperationV1 {
    /// Read volume presentation and current backing capacity as JSON Data.
    /// The object contains `volume_name`, `block_size`, `total_blocks`, `free_blocks`,
    /// and `available_blocks`. Capacity is physical, not a quota reservation.
    VolumeInfo,
    /// Inspect a relative path. The empty string is the root.
    Stat {
        /// Canonical slash-separated relative path.
        path: String,
    },
    /// Enumerate direct children.
    ReadDirectory {
        /// Canonical slash-separated relative path.
        path: String,
    },
    /// Read one exact file range.
    Read {
        /// Canonical slash-separated relative path.
        path: String,
        /// Initial byte offset.
        offset: u64,
        /// Requested byte count, bounded by [`super::STORAGE_FILESYSTEM_MAX_IO_BYTES`].
        length: u64,
    },
    /// Replace a range, extending with zeroes when necessary.
    Write {
        /// Canonical slash-separated relative path.
        path: String,
        /// Initial byte offset.
        offset: u64,
        /// Replacement bytes, bounded by [`super::STORAGE_FILESYSTEM_MAX_IO_BYTES`].
        data: Vec<u8>,
    },
    /// Set exact file length, truncating or zero-extending.
    SetLength {
        /// Canonical slash-separated relative path.
        path: String,
        /// New logical byte length.
        length: u64,
    },
    /// Create an empty regular file or directory.
    Create {
        /// Canonical slash-separated relative path.
        path: String,
        /// Requested entry kind.
        kind: StorageFilesystemEntryKindV1,
    },
    /// Remove one file or empty directory.
    Remove {
        /// Canonical slash-separated relative path.
        path: String,
    },
    /// Rename an entry within the same mounted owner view.
    Rename {
        /// Existing relative path.
        from: String,
        /// New relative path.
        to: String,
        /// Atomically replace a compatible destination when it exists.
        replace: bool,
    },
    /// Flush all acknowledged mutations to durable storage.
    Sync,
}

}

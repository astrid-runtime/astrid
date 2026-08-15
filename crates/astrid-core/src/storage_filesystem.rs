//! Kernel-to-native-provider filesystem and mount-lease contracts.
//!
//! The management connection authenticates an acting principal before a lease
//! is issued. Native filesystem callbacks then use only the private control
//! endpoint and bearer secret returned for that lease; paths and owner hints in
//! callback messages never select authority.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::storage_provider::{StorageMountId, StorageProviderAccessV1, StorageProviderViewV1};

/// Current private mount-service protocol version.
pub const STORAGE_FILESYSTEM_PROTOCOL_V1: u16 = 1;

/// Maximum byte payload accepted in one filesystem callback.
pub const STORAGE_FILESYSTEM_MAX_IO_BYTES: u64 = 4 * 1024 * 1024;

/// Lease material returned only to an authenticated native provider.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageMountLeaseV1 {
    /// Kernel-issued mount identity.
    pub mount_id: StorageMountId,
    /// Admitted owner view, fixed for the lease lifetime.
    pub view: StorageProviderViewV1,
    /// Admitted access, enforced on every mutation.
    pub access: StorageProviderAccessV1,
    /// Private directory used as the native FSKit/FUSE/WinFsp source resource.
    pub resource_path: PathBuf,
    /// Private callback endpoint selected by the kernel for this platform.
    ///
    /// This is separate from `resource_path` because Unix-domain socket paths
    /// have much smaller platform limits than ordinary filesystem paths.
    pub callback_path: PathBuf,
    /// Random bearer secret used only on the private callback endpoint.
    pub lease_token: String,
    /// Unix epoch second after which callbacks fail closed.
    pub expires_at_epoch_secs: u64,
}

/// Provider-independent filesystem entry kind.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageFilesystemEntryKindV1 {
    /// Regular byte file.
    File,
    /// Namespace directory.
    Directory,
}

/// Provider-independent filesystem metadata.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFilesystemEntryV1 {
    /// Final UTF-8 path segment.
    pub name: String,
    /// Entry kind.
    pub kind: StorageFilesystemEntryKindV1,
    /// Logical file length, or zero for a directory.
    pub logical_bytes: u64,
}

/// One filesystem operation over the owner already bound to the lease.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "operation")]
pub enum StorageFilesystemOperationV1 {
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
        /// Requested byte count, bounded by [`STORAGE_FILESYSTEM_MAX_IO_BYTES`].
        length: u64,
    },
    /// Replace a range, extending with zeroes when necessary.
    Write {
        /// Canonical slash-separated relative path.
        path: String,
        /// Initial byte offset.
        offset: u64,
        /// Replacement bytes, bounded by [`STORAGE_FILESYSTEM_MAX_IO_BYTES`].
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

/// One authenticated request on a private mount callback endpoint.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFilesystemRequestV1 {
    /// Exact protocol version.
    pub protocol_version: u16,
    /// Caller-generated correlation identity.
    pub request_id: String,
    /// Random secret from [`StorageMountLeaseV1`].
    pub lease_token: String,
    /// Requested operation.
    pub operation: StorageFilesystemOperationV1,
}

/// Successful filesystem result.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "result", content = "value")]
pub enum StorageFilesystemSuccessV1 {
    /// Operation completed without a value.
    Done,
    /// One entry was found.
    Entry(StorageFilesystemEntryV1),
    /// Directory children in canonical order.
    Entries(Vec<StorageFilesystemEntryV1>),
    /// Exact bytes read.
    Data(Vec<u8>),
    /// A write published this exact logical file length.
    Written(u64),
}

/// Stable error returned to native filesystem adapters.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFilesystemFailureV1 {
    /// Stable code mapped to the native provider's closest errno/status.
    pub code: String,
    /// Bounded diagnostic safe to log locally.
    pub message: String,
}

/// One callback result.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status", content = "detail")]
pub enum StorageFilesystemOutcomeV1 {
    /// The operation completed.
    Success(StorageFilesystemSuccessV1),
    /// The operation failed without changing lease authority.
    Failure(StorageFilesystemFailureV1),
}

/// One response on a private mount callback endpoint.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFilesystemResponseV1 {
    /// Exact protocol version.
    pub protocol_version: u16,
    /// Correlation identity copied from the request.
    pub request_id: String,
    /// Operation result.
    pub outcome: StorageFilesystemOutcomeV1,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_request_contains_no_owner_selector() {
        let request = StorageFilesystemRequestV1 {
            protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V1,
            request_id: "request-1".to_owned(),
            lease_token: "secret".to_owned(),
            operation: StorageFilesystemOperationV1::Read {
                path: "notes/a.txt".to_owned(),
                offset: 0,
                length: 16,
            },
        };
        let value = serde_json::to_value(request).unwrap();
        let text = value.to_string();
        assert!(!text.contains("principal"));
        assert!(!text.contains("fleet"));
        assert!(!text.contains("admin"));
    }
}

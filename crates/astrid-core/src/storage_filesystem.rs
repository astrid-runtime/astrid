//! Kernel-to-native-provider filesystem and mount-lease contracts.
//!
//! The management connection authenticates an acting principal before a lease
//! is issued. Native filesystem callbacks then use only the private control
//! endpoint and bearer secret returned for that lease; paths and owner hints in
//! callback messages never select authority.

use std::path::{Component, Path, PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::WorkspaceUid;
use crate::storage_provider::{StorageMountId, StorageProviderAccessV1, StorageProviderViewV1};

/// Current private mount-service protocol version.
pub const STORAGE_FILESYSTEM_PROTOCOL_V1: u16 = 1;

/// Version-two framing encodes byte payloads as base64 strings.
pub const STORAGE_FILESYSTEM_PROTOCOL_V2: u16 = 2;

/// Version of the private provider-service launch envelope.
pub const STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1: u16 = 1;

/// Version of the provider readiness response bound to one launch envelope.
pub const STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1: u16 = 1;

/// Maximum byte payload accepted in one filesystem callback.
pub const STORAGE_FILESYSTEM_MAX_IO_BYTES: u64 = 4 * 1024 * 1024;

/// The authoritative target fixed into one native mount lease.
///
/// Callback operations carry only relative paths.  In particular, they never
/// carry an owner or branch selector: the kernel binds that selector here when
/// issuing the lease and dispatches every callback against the same target.
/// The target is an internal kernel lease attribute and is intentionally not
/// serialized in the provider-facing V1 lease material below.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "workspace")]
pub enum StorageFilesystemTargetV1 {
    /// The selected owner's canonical content root.
    #[default]
    OwnerRoot,
    /// One owner-internal authoritative workspace branch.
    WorkspaceBranch {
        /// Opaque branch identity bound to the lease's admitted owner view.
        workspace: WorkspaceUid,
    },
    /// One explicitly admitted owner-local subtree (for example Fleet
    /// `shared/`). The prefix is fixed by the kernel lease and never supplied
    /// by a provider callback.
    OwnerSubtree {
        /// Canonical slash-separated owner-local prefix.
        prefix: String,
    },
}

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

/// Kernel-created lifetime identity for a private provider service.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageProviderParentLifetimeV1 {
    /// Process ID of the broker that owns the service lifetime.
    pub pid: u32,
    /// Optional platform process-start identity used to defeat PID reuse.
    pub start_identity: Option<String>,
    /// Random bearer accepted only on the private control endpoint.
    pub token: String,
}

/// Private launch material accepted by provider service modes only.
///
/// This envelope deliberately contains the public target-free lease, an exact
/// mountpoint/control endpoint, and the broker lifetime. It has no owner,
/// branch, or target selector: those remain kernel-internal lease state.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageProviderServiceLaunchV1 {
    /// Exact launch schema version.
    pub schema: u16,
    /// Pre-issued kernel lease, including the callback bearer.
    pub lease: StorageMountLeaseV1,
    /// Exact native mountpoint selected by the kernel broker.
    pub mountpoint: PathBuf,
    /// Exact private provider control endpoint selected by the broker.
    pub control_path: PathBuf,
    /// Parent process lifetime and control bearer.
    pub parent: StorageProviderParentLifetimeV1,
}

/// Exact readiness response emitted by a private provider service.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageProviderServiceReadyV1 {
    /// Readiness schema version.
    pub schema: u16,
    /// Provider identity expected by the kernel broker.
    pub provider: String,
    /// Mount identity bound to the launch lease.
    pub mount_id: Uuid,
    /// Exact control endpoint retained by the service.
    pub control_path: PathBuf,
    /// Keyed challenge proving possession of the launch parent bearer.
    pub challenge: String,
}

/// Derive the private-service readiness challenge.
///
/// The parent bearer is URL-safe base64 for exactly 32 random bytes. The
/// challenge binds the schema, provider, mount identity, and every exact
/// private path in the launch envelope under the domain-separated keyed BLAKE3
/// contract. Providers must emit this value only after callback and mount
/// readiness checks; brokers compare it in constant time.
///
/// # Errors
///
/// Returns an error when the parent token is not URL-safe base64 for exactly
/// 32 bytes, a provider/path field is empty or unrepresentable as canonical
/// UTF-8, or a path is relative/traversing.
pub fn storage_provider_service_ready_challenge(
    parent_token: &str,
    schema: u16,
    provider: &str,
    mount_id: Uuid,
    control_path: &Path,
    resource_path: &Path,
    callback_path: &Path,
) -> Result<String, String> {
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parent_token.as_bytes())
        .map_err(|_| "parent token is not URL-safe base64".to_owned())?;
    if key.len() != 32 {
        return Err("parent token must decode to exactly 32 bytes".to_owned());
    }
    let provider = provider.as_bytes();
    if provider.is_empty() || provider.len() > 4_294_967_295 {
        return Err("provider identity is outside the bounded challenge size".to_owned());
    }
    let control = canonical_challenge_path(control_path)?;
    let resource = canonical_challenge_path(resource_path)?;
    let callback = canonical_challenge_path(callback_path)?;
    let mut message = Vec::new();
    message.extend_from_slice(b"astrid storage provider ready v1\0");
    message.extend_from_slice(&schema.to_be_bytes());
    append_challenge_bytes(&mut message, provider)?;
    message.extend_from_slice(mount_id.as_bytes());
    append_challenge_bytes(&mut message, control.as_bytes())?;
    append_challenge_bytes(&mut message, resource.as_bytes())?;
    append_challenge_bytes(&mut message, callback.as_bytes())?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| "parent token key has an invalid length")?;
    Ok(hex::encode(blake3::keyed_hash(&key, &message).as_bytes()))
}

fn append_challenge_bytes(message: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let length = u32::try_from(value.len()).map_err(|_| "challenge field is too large")?;
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(value);
    Ok(())
}

fn canonical_challenge_path(path: &Path) -> Result<String, String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err("challenge path is not absolute and canonical".to_owned());
    }
    path.to_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "challenge path is not valid UTF-8".to_owned())
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

/// Version-two wire operation with bounded base64 byte fields.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "operation")]
pub enum StorageFilesystemOperationV2 {
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
        /// Standard base64 with padding, bounded after decoding by
        /// [`STORAGE_FILESYSTEM_MAX_IO_BYTES`].
        data_base64: String,
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

/// One authenticated version-two callback request.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFilesystemRequestV2 {
    /// Exact protocol version.
    pub protocol_version: u16,
    /// Caller-generated correlation identity.
    pub request_id: String,
    /// Random secret from [`StorageMountLeaseV1`].
    pub lease_token: String,
    /// Requested operation.
    pub operation: StorageFilesystemOperationV2,
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

/// Version-two successful result with bounded base64 byte payloads.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "result", content = "value")]
pub enum StorageFilesystemSuccessV2 {
    /// Operation completed without a value.
    Done,
    /// One entry was found.
    Entry(StorageFilesystemEntryV1),
    /// Directory children in canonical order.
    Entries(Vec<StorageFilesystemEntryV1>),
    /// Exact bytes read as standard base64 with padding.
    Data {
        /// Standard base64 with padding.
        data_base64: String,
    },
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

/// One version-two callback result.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status", content = "detail")]
pub enum StorageFilesystemOutcomeV2 {
    /// The operation completed.
    Success(StorageFilesystemSuccessV2),
    /// The operation failed without changing lease authority.
    Failure(StorageFilesystemFailureV1),
}

/// One version-two response on a private mount callback endpoint.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFilesystemResponseV2 {
    /// Exact protocol version.
    pub protocol_version: u16,
    /// Correlation identity copied from the request.
    pub request_id: String,
    /// Operation result.
    pub outcome: StorageFilesystemOutcomeV2,
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

    #[test]
    fn provider_lease_rejects_injected_workspace_target() {
        let lease = StorageMountLeaseV1 {
            mount_id: StorageMountId::new(),
            view: StorageProviderViewV1::Principal(crate::PrincipalId::default()),
            access: StorageProviderAccessV1::ReadWrite,
            resource_path: PathBuf::from("/private/run/lease"),
            callback_path: PathBuf::from("/private/run/lease/control.sock"),
            lease_token: "opaque-token".to_owned(),
            expires_at_epoch_secs: u64::MAX,
        };
        let mut encoded = serde_json::to_value(lease).expect("encode provider lease");
        encoded.as_object_mut().expect("lease object").insert(
            "target".to_owned(),
            serde_json::json!({
                "kind": "workspace-branch",
                "workspace": { "workspace": [1, 2, 3, 4] }
            }),
        );
        assert!(
            serde_json::from_value::<StorageMountLeaseV1>(encoded).is_err(),
            "provider-facing V1 must reject target fields rather than defaulting"
        );
    }

    #[test]
    fn version_two_fits_a_maximum_write_in_the_transport_frame() {
        let request = StorageFilesystemRequestV2 {
            protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V2,
            request_id: "frame-test".to_owned(),
            lease_token: "secret".to_owned(),
            operation: StorageFilesystemOperationV2::Write {
                path: "maximum.bin".to_owned(),
                offset: 0,
                data_base64: "A".repeat(5_592_408),
            },
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        assert!(
            encoded.len() <= 8 * 1024 * 1024,
            "version-two frame length {}",
            encoded.len()
        );
    }

    #[test]
    fn readiness_challenge_binds_parent_and_exact_launch_fields() {
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let mount_id = Uuid::from_u128(1);
        let control = Path::new("/private/resource/process-control.sock");
        let resource = Path::new("/private/resource");
        let callback = Path::new("/private/resource/control.sock");
        let first = storage_provider_service_ready_challenge(
            &token,
            STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1,
            "astrid-storage-provider-fuse",
            mount_id,
            control,
            resource,
            callback,
        )
        .unwrap();
        let same = storage_provider_service_ready_challenge(
            &token,
            STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1,
            "astrid-storage-provider-fuse",
            mount_id,
            control,
            resource,
            callback,
        )
        .unwrap();
        assert_eq!(first, same);
        let changed = storage_provider_service_ready_challenge(
            &token,
            STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1,
            "astrid-storage-provider-fskit",
            mount_id,
            control,
            resource,
            callback,
        )
        .unwrap();
        assert_ne!(first, changed);
    }

    #[test]
    fn readiness_challenge_rejects_noncanonical_paths_and_short_tokens() {
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let error = storage_provider_service_ready_challenge(
            &token,
            STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1,
            "provider",
            Uuid::from_u128(1),
            Path::new("relative/control.sock"),
            Path::new("/private/resource"),
            Path::new("/private/resource/control.sock"),
        )
        .unwrap_err();
        assert!(error.contains("absolute"));
        let error = storage_provider_service_ready_challenge(
            "c2hvcnQ",
            STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1,
            "provider",
            Uuid::from_u128(1),
            Path::new("/private/control.sock"),
            Path::new("/private/resource"),
            Path::new("/private/resource/control.sock"),
        )
        .unwrap_err();
        assert!(error.contains("32 bytes"));
    }
}

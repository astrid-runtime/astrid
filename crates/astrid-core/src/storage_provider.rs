//! Versioned wire contract for lifecycle-independent native storage providers.
//!
//! The CLI sends exactly one JSON request on standard input and expects exactly
//! one JSON response on standard output. Provider processes independently
//! authenticate to the daemon; the acting principal in this message is only a
//! requested identity selector and is never authorization evidence.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{FleetUid, PrincipalId};

/// Current native storage-provider protocol version.
pub const STORAGE_PROVIDER_PROTOCOL_V1: u16 = 1;

/// Correlation identity for one provider request.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct StorageProviderRequestId(Uuid);

impl StorageProviderRequestId {
    /// Generate a fresh request identity.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for StorageProviderRequestId {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable provider-issued identity for one admitted mount lease.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct StorageMountId(Uuid);

impl StorageMountId {
    /// Construct a mount identity from provider-generated UUID bytes.
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }
}

impl fmt::Display for StorageMountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::str::FromStr for StorageMountId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::from_str(value).map(Self)
    }
}

/// Filesystem view requested from the daemon by a native provider.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "identity")]
pub enum StorageProviderViewV1 {
    /// View admitted for one principal overlay.
    Principal(PrincipalId),
    /// Shared view admitted for one fleet.
    Fleet(FleetUid),
    /// Supported logical system-administration view.
    Admin,
}

/// Requested filesystem access class.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageProviderAccessV1 {
    /// No mutation may be published through the mount.
    ReadOnly,
    /// Authorized mutations may be staged and published.
    ReadWrite,
}

/// Existing mount selector accepted by lifecycle operations.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum StorageMountSelectorV1 {
    /// Select by a stable provider-issued mount identity.
    MountId(StorageMountId),
    /// Resolve a user-supplied native mount path to its stable identity.
    NativePath(PathBuf),
}

/// One typed operation in provider protocol version one.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "operation")]
pub enum StorageProviderOperationV1 {
    /// Acquire a lease and attach one native filesystem projection.
    Mount {
        /// Requested admitted view.
        view: StorageProviderViewV1,
        /// Requested access class.
        access: StorageProviderAccessV1,
        /// Optional native target selected by the user.
        mountpoint: Option<PathBuf>,
    },
    /// Wait for acknowledged dirty state to publish.
    Sync {
        /// Existing mount to synchronize.
        selector: StorageMountSelectorV1,
    },
    /// Inspect the current lease and publication state.
    Status {
        /// Existing mount to inspect.
        selector: StorageMountSelectorV1,
    },
    /// Revoke the lease and detach its native projection.
    Unmount {
        /// Existing mount to detach.
        selector: StorageMountSelectorV1,
    },
}

/// One CLI-to-provider request.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageProviderRequestV1 {
    /// Exact protocol version expected by the CLI.
    pub protocol_version: u16,
    /// Correlation identity that the response must echo.
    pub request_id: StorageProviderRequestId,
    /// Requested acting principal; the provider independently authenticates it.
    pub acting_principal_hint: PrincipalId,
    /// Requested lifecycle operation.
    pub operation: StorageProviderOperationV1,
}

impl StorageProviderRequestV1 {
    /// Construct a version-one request with a fresh correlation identity.
    #[must_use]
    pub fn new(acting_principal_hint: PrincipalId, operation: StorageProviderOperationV1) -> Self {
        Self {
            protocol_version: STORAGE_PROVIDER_PROTOCOL_V1,
            request_id: StorageProviderRequestId::new(),
            acting_principal_hint,
            operation,
        }
    }
}

/// Capability advertised by a native provider implementation.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageProviderCapabilityV1 {
    /// Provider supports principal-overlay views.
    PrincipalView,
    /// Provider supports fleet-shared views.
    FleetView,
    /// Provider supports logical administration views.
    AdminView,
    /// Provider supports read-only lease enforcement.
    ReadOnly,
    /// Provider supports staged writable publication.
    ReadWrite,
    /// Provider supports sync, status, and unmount lifecycle requests.
    Lifecycle,
}

/// Provider metadata returned with every response as the protocol handshake.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageProviderIdentityV1 {
    /// Stable provider implementation name.
    pub name: String,
    /// Provider implementation version.
    pub version: String,
    /// Explicitly supported protocol behavior.
    pub capabilities: Vec<StorageProviderCapabilityV1>,
}

/// Successful provider result.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "result")]
pub enum StorageProviderSuccessV1 {
    /// A new lease and native projection were created.
    Mounted {
        /// Stable lease identity.
        mount_id: StorageMountId,
        /// Native path selected by the provider.
        mountpoint: PathBuf,
    },
    /// Dirty state was durably published.
    Synced {
        /// Stable lease identity.
        mount_id: StorageMountId,
    },
    /// Current state of an existing mount.
    Status {
        /// Stable lease identity.
        mount_id: StorageMountId,
        /// Current native mount path.
        mountpoint: PathBuf,
        /// Current admitted access class.
        access: StorageProviderAccessV1,
        /// Whether acknowledged dirty state remains unpublished.
        dirty: bool,
    },
    /// An existing lease was revoked and detached.
    Unmounted {
        /// Stable lease identity.
        mount_id: StorageMountId,
    },
}

/// Structured provider failure safe to render to an operator.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageProviderFailureV1 {
    /// Stable machine-readable error code.
    pub code: String,
    /// Bounded human-readable explanation.
    pub message: String,
}

/// Successful or failed result of one provider request.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status", content = "detail")]
pub enum StorageProviderOutcomeV1 {
    /// The requested operation completed successfully.
    Success(StorageProviderSuccessV1),
    /// The provider refused or could not complete the request.
    Failure(StorageProviderFailureV1),
}

/// One provider-to-CLI response.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageProviderResponseV1 {
    /// Exact protocol version implemented by the provider.
    pub protocol_version: u16,
    /// Correlation identity copied from the request.
    pub request_id: StorageProviderRequestId,
    /// Provider identity and capabilities, forming the version handshake.
    pub provider: StorageProviderIdentityV1,
    /// Exactly one success or structured failure.
    pub outcome: StorageProviderOutcomeV1,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_v1_round_trips_without_ambient_authority_fields() {
        let request = StorageProviderRequestV1::new(
            PrincipalId::new("operator").unwrap(),
            StorageProviderOperationV1::Mount {
                view: StorageProviderViewV1::Fleet(FleetUid::from_bytes([7; 32])),
                access: StorageProviderAccessV1::ReadWrite,
                mountpoint: Some(PathBuf::from("/mnt/astrid")),
            },
        );

        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: StorageProviderRequestV1 = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(decoded, request);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("acting_principal_hint"));
        assert!(!text.contains("token"));
        assert!(!text.contains("authorized"));
    }

    #[test]
    fn request_v1_rejects_unknown_fields() {
        let request = StorageProviderRequestV1::new(
            PrincipalId::new("operator").unwrap(),
            StorageProviderOperationV1::Status {
                selector: StorageMountSelectorV1::NativePath(PathBuf::from("/mnt/astrid")),
            },
        );
        let mut value = serde_json::to_value(request).unwrap();
        value.as_object_mut().unwrap().insert(
            "ambient_authority".to_owned(),
            serde_json::Value::Bool(true),
        );

        assert!(serde_json::from_value::<StorageProviderRequestV1>(value).is_err());
    }
}

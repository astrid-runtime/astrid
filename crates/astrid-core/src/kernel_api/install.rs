//! Capsule install and environment wire types.

use super::response_types::StationLock;
use serde::{Deserialize, Serialize};

/// Host-owned projection selected by an env/secret admin request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EnvStorageScope {
    /// Principal-scoped control namespace.
    Agent,
    /// System/host-scoped control namespace.
    Shared,
}

/// Typed values managed by the env admin API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EnvValueKind {
    /// Non-secret environment configuration.
    Text,
    /// Secret-typed environment configuration.
    Secret,
}

/// A redacted env/secret key returned by the admin list API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvEntry {
    /// Capsule whose host-owned projection contains the key.
    pub capsule: String,
    /// Manifest env/secret key.
    pub key: String,
    /// Whether this row is secret-typed.
    pub kind: EnvValueKind,
    /// Principal or host scope containing the value.
    pub scope: EnvStorageScope,
}

/// Bounded provenance supplied with a daemon-owned capsule install.
///
/// Provenance is descriptive input to the kernel's integrity gate, never an
/// authority grant.  The kernel validates the fields against the local source
/// before publishing the durable package and rejects overlong or malformed
/// values.  Keeping this as a small typed object avoids allowing a caller to
/// smuggle an unbounded distro manifest or arbitrary metadata through the
/// management wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleInstallProvenance {
    /// Stable distro identifier, when the source came from a sealed distro.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distro: Option<String>,
    /// Canonical BLAKE3 digest of the source artifact, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_digest: Option<String>,
}

/// Caller-authorized trust posture for one daemon-owned capsule install.
///
/// The kernel computes and verifies the artifact digest itself; this value
/// only carries the authenticated caller's decision across the management
/// boundary. It never trusts caller-supplied artifact identity bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleInstallAuthority {
    /// Accept only an artifact signed by this runtime's build identity.
    #[default]
    Automatic,
    /// Approve this exact inspected artifact once.
    ExplicitApproval,
    /// Install an artifact selected by an operator-approved distro.
    OperatorDistribution,
}

/// One bounded, typed environment value accompanying a daemon capsule install.
///
/// This wire shape is intentionally separate from
/// [`AdminRequestKind::EnvSet`](super::AdminRequestKind::EnvSet) so the kernel can snapshot and
/// roll back the previous value if an install lifecycle fails. Secret bytes never appear in kernel
/// errors or audit rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleInstallEnv {
    /// Manifest-declared field name.
    pub key: String,
    /// Value to stage in the owner's host-only control namespace.
    pub value: String,
    /// Secret or non-secret projection.
    pub kind: EnvValueKind,
}

/// Typed Station handoff bound into one daemon-owned install transaction.
///
/// When this value accompanies [`KernelRequest::InstallCapsule`](super::KernelRequest::InstallCapsule),
/// the daemon verifies that the exact source bytes named by the embedded
/// Station lock are staged once into private storage, installs only those
/// bytes, and persists the lock inside the same owner/capsule critical
/// section as the package mutation. `expected_hash` follows the same create
/// semantics as the typed Station lock admin API: `None` means the caller
/// expects no prior lock, never "mutate unconditionally". Omitting the whole
/// binding performs no Station mutation at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StationInstallBinding {
    /// Capsule package key owning the durable Station lock record.
    pub capsule: String,
    /// Exact verified Station lock whose artifact digests name these bytes.
    pub lock: Box<StationLock>,
    /// Canonical BLAKE3 digest of the prior owner-scoped lock JSON. `None`
    /// expects no prior record; a supplied digest must still be present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_hash: Option<String>,
}

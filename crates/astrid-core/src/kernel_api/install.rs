//! Capsule install and environment wire types.

use serde::{Deserialize, Serialize};

/// Highest capsule-install batch protocol revision supported by this build.
pub const CAPSULE_INSTALL_BATCH_PROTOCOL_V1: u16 = 1;
use uuid::Uuid;

/// Opaque kernel-issued identifier for one bounded capsule-install batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapsuleInstallBatchId(Uuid);

impl CapsuleInstallBatchId {
    /// Mint a fresh unpredictable batch identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for CapsuleInstallBatchId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for CapsuleInstallBatchId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// One exact local archive admitted into a bounded install batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleInstallBatchMember {
    /// Canonical capsule identifier.
    pub id: String,
    /// Exact manifest version expected from the archive.
    pub version: String,
    /// Canonical `blake3:<64 lowercase hex>` digest of the archive bytes.
    pub source_digest: String,
    /// Canonical `blake3:<64 lowercase hex>` digest of the normalized archive
    /// that must become the durable package.
    pub archive_digest: String,
    /// Exact compressed archive size.
    pub source_bytes: u64,
    /// Observed package generation; filtered refresh fail-closes on mismatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_generation: Option<InstalledCapsuleGeneration>,
}

/// Lease reference carried by one ordinary capsule install request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleInstallBatchContext {
    /// Kernel-issued lease identifier.
    pub batch_id: CapsuleInstallBatchId,
    /// Declared member this request attempts to install.
    pub member_id: String,
}

/// Immutable object generation for one durable installed-capsule package.
///
/// Each field is a lowercase BLAKE3 object identifier rendered as 64 hex
/// characters. Keeping the token purpose-specific prevents callers from
/// receiving package bytes or the storage map while still allowing a resume
/// check to bind all three fixed package files to one owner-root snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledCapsuleGeneration {
    /// Object identifier for the canonical archive bytes.
    pub archive: String,
    /// Object identifier for the install metadata bytes.
    pub metadata: String,
    /// Object identifier for the authority receipt bytes.
    pub authority: String,
}

/// Caller-scoped identity of one complete durable capsule installation.
///
/// This response deliberately carries only the capsule identifier, its
/// immutable package generation, the raw archive digest used by the registry,
/// and (when present) the verified WASM content address. It is not a metadata
/// or package-byte query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledCapsuleIdentity {
    /// Canonical capsule identifier.
    pub id: String,
    /// Immutable package generation captured from one owner-root snapshot.
    pub generation: InstalledCapsuleGeneration,
    /// BLAKE3 digest of the canonical archive bytes.
    pub archive_digest: String,
    /// Raw lowercase BLAKE3 digest of the verified WASM component, when one
    /// exists. This is absent for non-WASM capsules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm_hash: Option<String>,
}

/// Crash-safe caller-scoped proof that one capsule installation completed.
///
/// The receipt is stored under the authenticated principal's immutable UID;
/// it deliberately carries no principal selector so it cannot be replayed
/// across owners. A resume skip requires every field to match the fresh
/// [`InstalledCapsuleIdentity`](super::KernelResponse) query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleInstallResumeReceipt {
    /// Canonical capsule identifier used as the control-store key.
    pub id: String,
    /// BLAKE3 digest of the canonical archive bytes.
    pub archive_digest: String,
    /// Immutable package generation captured by the install.
    pub generation: InstalledCapsuleGeneration,
}

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

#[cfg(test)]
mod tests {
    use super::super::KernelRequest;

    #[test]
    fn install_request_without_batch_remains_decodable() {
        let request: KernelRequest = serde_json::from_value(serde_json::json!({
            "method": "InstallCapsule",
            "params": { "source": "demo.capsule", "workspace": false }
        }))
        .expect("pre-batch request");
        assert!(matches!(
            request,
            KernelRequest::InstallCapsule {
                batch: None,
                expected_generation: None,
                ..
            }
        ));
    }

    #[test]
    fn batch_member_without_generation_decodes_as_none() {
        let member: super::CapsuleInstallBatchMember = serde_json::from_value(serde_json::json!({
            "id": "demo",
            "version": "1.0.0",
            "source_digest": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "archive_digest": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "source_bytes": 12
        }))
        .expect("pre-generation member");
        assert_eq!(member.expected_generation, None);
    }
}

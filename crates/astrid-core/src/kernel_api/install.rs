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

/// Versioned read-only prerequisites attested by the selected daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeProtectionCapabilitiesV1 {
    /// Wire schema revision.
    pub schema_version: u16,
    /// Random identity minted once per kernel boot.
    pub daemon_incarnation: Uuid,
    /// Opaque BLAKE3 binding to the immutable selected workspace and home.
    pub context_digest: String,
    /// Durable identity of the queried principal.
    pub principal_uid: crate::PrincipalUid,
    /// Implemented and qualified protection features.
    pub features: std::collections::BTreeSet<String>,
    /// Verified installed adapter identity and current approval verdict.
    pub adapter: Option<NativeAdapterApprovalV1>,
}

/// Installed authority and live identity of the Oracle native hook adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdapterApprovalV1 {
    /// Verified complete durable package identity.
    pub identity: InstalledCapsuleIdentity,
    /// Actual source UUID of the loaded principal-scoped runtime.
    pub source_id: Uuid,
    /// Verified authority path (kebab-case).
    pub authority_class: String,
    /// Approved package content digest, as lowercase BLAKE3 hex.
    pub authority_digest: String,
    /// Current receipt, manifest, executable and principal grants agree.
    pub approved_for_native_hook: bool,
}

#[cfg(test)]
mod native_capabilities_tests {
    use super::*;

    #[test]
    fn native_capabilities_wire_rejects_unknown_fields() {
        let response = NativeProtectionCapabilitiesV1 {
            schema_version: 1,
            daemon_incarnation: Uuid::new_v4(),
            context_digest: "a".repeat(64),
            principal_uid: crate::PrincipalUid::from_bytes([7; 32]),
            features: std::collections::BTreeSet::new(),
            adapter: None,
        };
        let mut wire = serde_json::to_value(&response).unwrap();
        assert_eq!(
            serde_json::from_value::<NativeProtectionCapabilitiesV1>(wire.clone()).unwrap(),
            response
        );
        wire["environment"] = serde_json::json!({"token": "secret-value"});
        assert!(serde_json::from_value::<NativeProtectionCapabilitiesV1>(wire).is_err());
        let mut adapter = serde_json::json!({"identity": {"id": "aos-hook-adapter-oracle", "generation": {"archive": "a".repeat(64), "metadata": "b".repeat(64), "authority": "c".repeat(64)}, "archive_digest": "a".repeat(64)}, "source_id": Uuid::new_v4(), "authority_class": "explicit-approval", "authority_digest": "d".repeat(64), "approved_for_native_hook": false});
        assert!(serde_json::from_value::<NativeAdapterApprovalV1>(adapter.clone()).is_ok());
        adapter["approved_by_caller"] = true.into();
        assert!(serde_json::from_value::<NativeAdapterApprovalV1>(adapter).is_err());
    }
}

/// Exactly the protected principal's two installed native members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePairIdentityV1 {
    /// Durable enforcer identity.
    pub enforcer: InstalledCapsuleIdentity,
    /// Durable protocol identity.
    pub protocol: InstalledCapsuleIdentity,
    /// Authenticated enforcer source.
    pub enforcer_source: Uuid,
    /// Authenticated protocol source.
    pub protocol_source: Uuid,
}

/// One archive and its generation-scoped text environment.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePairMemberV1 {
    /// One of the two fixed Codewall capsule IDs.
    pub id: String,
    /// Raw lowercase BLAKE3 digest of the exact transferred archive.
    pub source_digest: String,
    /// Exact compressed byte count, at most 64 `MiB`.
    pub source_bytes: u64,
    /// Authenticated install decision, never an additional grant.
    pub authority: CapsuleInstallAuthority,
    /// Proposed text values; secret/shared writes are forbidden.
    pub env: Vec<CapsuleInstallEnv>,
}
impl std::fmt::Debug for NativePairMemberV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativePairMemberV1")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Begin an unpublished, bounded native pair lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginNativePairUpgrade {
    /// Explicit target; authorization still comes from the authenticated caller.
    pub target_principal: crate::PrincipalId,
    /// Immutable target UID observed during preflight.
    pub principal_uid: crate::identity::PrincipalUid,
    /// Daemon selected during preflight.
    pub daemon_incarnation: Uuid,
    /// Exact old durable identities and sources.
    pub expected_old: NativePairIdentityV1,
    /// Both members, even if one is unchanged.
    pub members: [NativePairMemberV1; 2],
    /// Absolute deadline, at most 300 seconds in the future.
    pub expires_at_unix_ms: u64,
    /// Replay protection scoped to the authenticated caller.
    pub nonce: Uuid,
    /// Existing installation binding.
    pub installation_id: Uuid,
    /// Existing journal binding.
    pub journal_id: Uuid,
}

/// Authenticated assertions used to access an existing lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePairLeaseRefV1 {
    /// Unpredictable daemon-issued lease ID.
    pub lease_id: Uuid,
    /// Target selector, checked against the lease after ordinary authorization.
    pub target_principal: crate::PrincipalId,
    /// Immutable target UID.
    pub principal_uid: crate::identity::PrincipalUid,
    /// Owning daemon incarnation.
    pub daemon_incarnation: Uuid,
}

/// One contiguous bounded archive chunk.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageNativePairMember {
    /// Lease authority assertions.
    pub lease: NativePairLeaseRefV1,
    /// Fixed declared member ID.
    pub member_id: String,
    /// Expected next byte offset.
    pub offset: u64,
    /// Declared total archive size.
    pub total_bytes: u64,
    /// At most 256 `KiB`; serialized request plus envelope must fit 2 `MiB`.
    pub chunk: Vec<u8>,
    /// True exactly when this chunk completes the declared archive.
    pub final_chunk: bool,
}
impl std::fmt::Debug for StageNativePairMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StageNativePairMember")
            .field("lease", &self.lease)
            .field("member_id", &self.member_id)
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

/// Process-local unpublished upgrade lease; never an install authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePairLeaseV1 {
    /// Opaque lease identifier.
    pub lease_id: Uuid,
    /// Owning boot identity.
    pub daemon_incarnation: Uuid,
    /// Target owner.
    pub principal_uid: crate::identity::PrincipalUid,
    /// Absolute expiry.
    pub expires_at_unix_ms: u64,
    /// Pinned old pair.
    pub old: NativePairIdentityV1,
    /// Reserved candidate runtime identities, populated by candidate preparation.
    pub candidate: Option<NativePairIdentityV1>,
    /// Absent until a consistent policy snapshot is captured under its write fence.
    pub policy_snapshot_digest: Option<String>,
}

/// Native transaction phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativePairPhaseV1 {
    /// Private package transfer/verification; no policy snapshot promise.
    Staging,
    /// Fenced snapshot and candidate prepared.
    Ready,
    /// Durable commit in progress.
    CommitIntent,
    /// Pair committed.
    Committed,
    /// Old pair restored.
    RolledBack,
    /// Retained rollback generation retired.
    Finalized,
    /// Private staging discarded.
    Aborted,
}

/// Redacted lease/transaction status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePairStateV1 {
    /// Lease binding and phase-dependent candidate/snapshot identity.
    pub lease: NativePairLeaseV1,
    /// Current phase.
    pub phase: NativePairPhaseV1,
}

#[cfg(test)]
mod native_pair_wire_tests {
    use super::*;
    #[test]
    fn native_pair_lease_wire_rejects_unrecognized_authority_fields() {
        let reference = NativePairLeaseRefV1 {
            lease_id: Uuid::new_v4(),
            target_principal: crate::PrincipalId::default(),
            principal_uid: crate::identity::PrincipalUid::from_bytes([1; 32]),
            daemon_incarnation: Uuid::new_v4(),
        };
        let mut wire = serde_json::to_value(reference).unwrap();
        wire["enrollment_grant"] = serde_json::json!("never-accepted");
        assert!(serde_json::from_value::<NativePairLeaseRefV1>(wire).is_err());
        let member = NativePairMemberV1 {
            id: "codewall-protocol".into(),
            source_digest: "a".repeat(64),
            source_bytes: 1,
            authority: CapsuleInstallAuthority::Automatic,
            env: vec![CapsuleInstallEnv {
                key: "PIN".into(),
                value: "private-value-marker".into(),
                kind: EnvValueKind::Text,
            }],
        };
        assert!(!format!("{member:?}").contains("private-value-marker"));
    }
}

//! Canonical deterministic proof adapter for native compaction.

use crate::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, RetentionPolicyId,
};

use super::{CompactionFacts, CompactionProofVerifier, CompactionRetention, DurableError};

const DETERMINISTIC_PROOF_PREFIX: &[u8] = b"astrid-gc-native-proof-v1\0";

/// Native deterministic proof adapter used when a Tensor Logic evaluator is
/// not available in the daemon process.
///
/// The adapter is deliberately strict: it accepts only a canonical proof
/// record generated from the exact operation contract, retention policy,
/// frozen fact snapshot, ordered condemned set, and retained-root set supplied
/// to the verifier. The durable engine still recomputes liveness and the fact
/// snapshot while holding its mutation fence immediately before replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeterministicCompactionProofVerifier {
    operation_contract: ObjectId,
    policy: RetentionPolicyId,
    retained_roots_digest: [u8; 32],
}

impl DeterministicCompactionProofVerifier {
    /// Bind the verifier to one canonical retention contract.
    #[must_use]
    pub fn new(retention: &CompactionRetention) -> Self {
        Self {
            operation_contract: retention.operation_contract(),
            policy: retention.policy(),
            retained_roots_digest: retained_roots_digest(retention),
        }
    }
}

impl CompactionProofVerifier for DeterministicCompactionProofVerifier {
    fn verify(
        &self,
        facts: &CompactionFacts,
        _policy: &ObjectRecord,
        proof: &ObjectRecord,
    ) -> bool {
        if facts.condemned().is_empty() {
            return false;
        }
        let expected = deterministic_proof_bytes(
            self.operation_contract,
            self.policy,
            facts.snapshot(),
            facts.condemned(),
            self.retained_roots_digest,
        );
        proof.kind() == ObjectKind::Evidence
            && proof.format_version() == ObjectFormatVersion::V1
            && proof.class() == ObjectClass::Metadata
            && proof.logical_bytes() == 0
            && proof.references().is_empty()
            && proof.canonical_bytes() == expected
    }
}

/// Construct the canonical native proof record for one captured fact snapshot.
///
/// # Errors
///
/// Returns a durable evidence error if the condemned set is empty or the
/// canonical record cannot be represented.
pub fn deterministic_compaction_proof(
    retention: &CompactionRetention,
    facts: &CompactionFacts,
) -> Result<ObjectRecord, DurableError> {
    if facts.condemned().is_empty() {
        return Err(DurableError::NoCompactionWork);
    }
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        deterministic_proof_bytes(
            retention.operation_contract(),
            retention.policy(),
            facts.snapshot(),
            facts.condemned(),
            retained_roots_digest(retention),
        ),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .map_err(|_| DurableError::InvalidCompactionEvidence("native proof record is non-canonical"))
}

fn deterministic_proof_bytes(
    operation_contract: ObjectId,
    policy: RetentionPolicyId,
    snapshot: crate::storage_model::GcFactSnapshotId,
    condemned: &[ObjectId],
    retained_roots_digest: [u8; 32],
) -> Vec<u8> {
    // Five 32-byte fields plus one eight-byte count, in addition to the
    // fixed domain prefix. Keep this a literal capacity so the strict
    // arithmetic-side-effects lint cannot turn a malformed count into a
    // capacity overflow concern.
    let mut bytes = Vec::with_capacity(208);
    bytes.extend_from_slice(DETERMINISTIC_PROOF_PREFIX);
    bytes.extend_from_slice(operation_contract.as_bytes());
    bytes.extend_from_slice(policy.object_id().as_bytes());
    bytes.extend_from_slice(snapshot.object_id().as_bytes());
    bytes.extend_from_slice(&count_bytes(condemned.len()));
    bytes.extend_from_slice(&condemned_digest(condemned));
    bytes.extend_from_slice(&retained_roots_digest);
    bytes
}

fn condemned_digest(condemned: &[ObjectId]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("astrid-gc-condemned-set-v1");
    hasher.update(&count_bytes(condemned.len()));
    for object in condemned {
        hasher.update(object.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn retained_roots_digest(retention: &CompactionRetention) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("astrid-gc-retained-roots-v1");
    hasher.update(&count_bytes(retention.additional_roots().len()));
    for root in retention.additional_roots() {
        hasher.update(&[root.kind().code()]);
        hasher.update(root.object().as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn count_bytes(count: usize) -> [u8; 8] {
    u64::try_from(count).unwrap_or(u64::MAX).to_le_bytes()
}

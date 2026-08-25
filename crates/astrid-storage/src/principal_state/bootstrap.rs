//! Registered standalone objects required to reopen a runtime store.

use std::sync::Arc;

use crate::engine::{
    CompactionEvidenceBundle, CompactionReport, CompactionRetainedRoot, CompactionRetention,
    CompactionRootKind, DeterministicCompactionProofVerifier, DurableError,
    deterministic_compaction_proof,
};
use crate::storage_model::{
    GcCommitId, ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord,
    RetentionPolicyId,
};

use super::format_amendment::format_spec_record;
use super::{RuntimeEngine, RuntimePrincipalStore, StorageError, StorageResult};

/// One standalone object that runtime composition must keep outside principal roots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RuntimeBootstrapObject {
    /// Byte-exact specification required to decode the authoritative files.
    RunatalFormatSpecification,
    /// Byte-exact specification required to decode content-catalog trees.
    ContentCatalogFormatSpecification,
}

const CONTENT_CATALOG_FORMAT_SPEC: &[u8] = include_bytes!("../../formats/content-catalog-v2.txt");
const RUNTIME_BOOTSTRAP_OBJECTS: &[RuntimeBootstrapObject] = &[
    RuntimeBootstrapObject::RunatalFormatSpecification,
    RuntimeBootstrapObject::ContentCatalogFormatSpecification,
];

impl RuntimeBootstrapObject {
    /// Return every standalone object protected by runtime composition.
    pub(super) const fn registered() -> &'static [Self] {
        RUNTIME_BOOTSTRAP_OBJECTS
    }

    /// Construct the exact record persisted for this bootstrap role.
    pub(super) fn record(self) -> StorageResult<ObjectRecord> {
        match self {
            Self::RunatalFormatSpecification => format_spec_record(),
            Self::ContentCatalogFormatSpecification => ObjectRecord::new(
                ObjectKind::Evidence,
                ObjectFormatVersion::V1,
                CONTENT_CATALOG_FORMAT_SPEC.to_vec(),
                Vec::new(),
                0,
                ObjectClass::Metadata,
            )
            .map_err(|error| {
                StorageError::Serialization(format!(
                    "construct in-band content catalog format specification: {error}"
                ))
            }),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::RunatalFormatSpecification => "RÚNATAL format specification",
            Self::ContentCatalogFormatSpecification => "content catalog format specification",
        }
    }
}

pub(super) fn format_specification() -> StorageResult<ObjectRecord> {
    RuntimeBootstrapObject::RunatalFormatSpecification.record()
}

pub(super) fn content_catalog_format_specification() -> StorageResult<ObjectRecord> {
    RuntimeBootstrapObject::ContentCatalogFormatSpecification.record()
}

fn compaction_retention(
    engine: &RuntimeEngine,
    operation_contract: ObjectId,
    policy: RetentionPolicyId,
    mut additional_roots: Vec<CompactionRetainedRoot>,
) -> StorageResult<CompactionRetention> {
    for bootstrap in RuntimeBootstrapObject::registered() {
        let expected = bootstrap.record()?;
        let object = engine.identify(&expected);
        let actual = engine
            .object(object)
            .map_err(|error| {
                StorageError::Connection(format!(
                    "verify protected {} before compaction: {error}",
                    bootstrap.name()
                ))
            })?
            .ok_or_else(|| {
                StorageError::Connection(format!(
                    "protected {} is missing before compaction",
                    bootstrap.name()
                ))
            })?;
        if actual != expected {
            return Err(StorageError::Connection(format!(
                "protected {} does not match the registered object",
                bootstrap.name()
            )));
        }
        additional_roots.push(CompactionRetainedRoot::new(
            CompactionRootKind::System,
            object,
        ));
    }
    Ok(CompactionRetention::new(
        operation_contract,
        policy,
        additional_roots,
    ))
}

impl RuntimePrincipalStore {
    /// Construct production compaction retention with every bootstrap root.
    ///
    /// Runtime composition, including future schedulers, must use this method
    /// instead of constructing the policy-neutral engine type directly.
    /// Registered standalone objects are identity-checked before the
    /// retention value is returned, so a destructive plan cannot be verified
    /// after one has already disappeared.
    ///
    /// # Errors
    ///
    /// Returns a storage error if a registered bootstrap record cannot be
    /// constructed, read, identity-verified, or matched byte-for-byte.
    pub async fn prepare_compaction_retention(
        &self,
        operation_contract: ObjectId,
        policy: RetentionPolicyId,
        additional_roots: Vec<CompactionRetainedRoot>,
    ) -> StorageResult<CompactionRetention> {
        let mut additional_roots = additional_roots;
        additional_roots.extend(self.compaction_read_handle_roots().into_iter().map(
            |(_, object)| CompactionRetainedRoot::new(CompactionRootKind::ReadHandle, object),
        ));
        let engine = Arc::clone(&self.engine);
        tokio::task::spawn_blocking(move || {
            compaction_retention(&engine, operation_contract, policy, additional_roots)
        })
        .await
        .map_err(|error| {
            StorageError::Connection(format!(
                "production compaction-retention worker failed: {error}"
            ))
        })?
    }

    /// Compact the native principal store with the production deterministic
    /// proof adapter.
    ///
    /// The coordinator owns the composition boundary: bootstrap objects and
    /// open content-handle roots are added to the caller's retained roots,
    /// the policy identity is checked inside the engine's mutation-fenced
    /// verification, and the physical replacement is committed only after
    /// the canonical proof is accepted. The resulting evidence remains in
    /// the engine outbox until an independent audit sink acknowledges it.
    ///
    /// # Errors
    ///
    /// Returns a storage error when free space is insufficient, a bootstrap
    /// or handle root cannot be retained, the deterministic proof cannot be
    /// constructed, or the engine refuses the fenced replacement.
    pub async fn compact_with_deterministic_proof(
        &self,
        operation_contract: ObjectId,
        policy: ObjectRecord,
        additional_roots: Vec<CompactionRetainedRoot>,
    ) -> StorageResult<CompactionReport> {
        ensure_compaction_headroom(&self.engine)?;
        let policy_id = RetentionPolicyId::new(self.engine.identify(&policy));
        let engine = Arc::clone(&self.engine);
        let content = Arc::clone(&self.content);
        let mut additional_roots = additional_roots;
        additional_roots.extend(self.compaction_read_handle_roots().into_iter().map(
            |(_, object)| CompactionRetainedRoot::new(CompactionRootKind::ReadHandle, object),
        ));
        tokio::task::spawn_blocking(move || {
            let retention =
                compaction_retention(&engine, operation_contract, policy_id, additional_roots)
                    .map_err(|error| {
                        StorageError::Connection(format!("prepare compaction retention: {error}"))
                    })?;
            let facts = engine
                .capture_compaction_facts(&retention)
                .map_err(|error| {
                    StorageError::Connection(format!("capture compaction facts: {error}"))
                })?;
            let proof = deterministic_compaction_proof(&retention, &facts).map_err(|error| {
                StorageError::Connection(format!("construct compaction proof: {error}"))
            })?;
            let verifier = DeterministicCompactionProofVerifier::new(&retention);
            let plan = engine
                .verify_compaction_plan(retention, facts, policy, proof, &verifier)
                .map_err(|error| {
                    StorageError::Connection(format!("verify compaction proof: {error}"))
                })?;
            engine
                .compact_with_live_read_handles(&plan, || {
                    let observation = content
                        .begin_compaction_observation()
                        .map_err(|_| DurableError::CompactionSnapshotChanged)?;
                    Ok((observation.live_object_ids(), observation))
                })
                .map_err(|error| {
                    StorageError::Connection(format!("compact durable store: {error}"))
                })
        })
        .await
        .map_err(|error| StorageError::Connection(format!("compaction worker failed: {error}")))?
    }

    /// Return completed compaction receipts awaiting independent audit.
    ///
    /// Reading the outbox does not acknowledge delivery. Callers must persist
    /// the complete evidence bundle before invoking
    /// [`Self::acknowledge_compaction_evidence`].
    ///
    /// # Errors
    ///
    /// Returns a storage error if the outbox cannot be recovered or decoded.
    pub fn pending_compaction_evidence(&self) -> StorageResult<Vec<CompactionEvidenceBundle>> {
        self.engine
            .pending_compaction_evidence()
            .map_err(|error| StorageError::Connection(format!("read compaction evidence: {error}")))
    }

    /// Acknowledge one durable compaction receipt after audit persistence.
    ///
    /// Acknowledgement is idempotent and removes only the delivery copy; it
    /// never changes principal roots or the compacted arena generation.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the receipt cannot be verified or removed.
    pub fn acknowledge_compaction_evidence(&self, commit: GcCommitId) -> StorageResult<()> {
        self.engine
            .acknowledge_compaction_evidence(commit)
            .map_err(|error| {
                StorageError::Connection(format!("acknowledge compaction evidence: {error}"))
            })
    }
}

const COMPACTION_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;

fn ensure_compaction_headroom(engine: &RuntimeEngine) -> StorageResult<()> {
    let (available, arena_bytes) = engine
        .compaction_capacity()
        .map_err(|error| StorageError::Connection(format!("inspect compaction capacity: {error}")))?
        .ok_or_else(|| {
            StorageError::Connection(
                "compaction media does not report native free capacity".to_owned(),
            )
        })?;
    validate_compaction_headroom(available, arena_bytes)
}

fn validate_compaction_headroom(available: u64, arena_bytes: u64) -> StorageResult<()> {
    let required = arena_bytes
        .checked_add(COMPACTION_HEADROOM_BYTES)
        .ok_or_else(|| StorageError::Connection("compaction headroom overflow".to_owned()))?;
    if available < required {
        return Err(StorageError::Connection(format!(
            "insufficient free space for compaction: need {required} bytes, have {available} bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_compaction_headroom;

    #[test]
    fn compaction_refuses_insufficient_headroom_before_mutation() {
        assert!(validate_compaction_headroom(64, 1).is_err());
        assert!(validate_compaction_headroom(u64::MAX, u64::MAX).is_err());
    }

    #[test]
    fn compaction_accepts_exact_headroom_boundary() {
        assert!(validate_compaction_headroom(64 * 1024 * 1024 + 7, 7).is_ok());
    }
}

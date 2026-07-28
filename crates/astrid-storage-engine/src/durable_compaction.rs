//! Proof-bound liveness capture and crash-recoverable arena compaction.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::Path;

use astrid_storage_model::{
    GcFactSnapshotId, GcPlanEvidence, ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind,
    ObjectRecord, RetentionPolicyId, RootState, TensorLogicProofId,
};

use crate::refinery::{EngineCompactionPass, NativeArenaCompactionPass};

use super::{
    ARENA_FILE, ARENA_MAGIC, ArenaLocation, DurableEngine, DurableError, DurableFiles,
    DurableInner, FaultPoint, INDEX_FILE, IndexState, PersistentObjectIdentity, PrincipalCodec,
    ROOT_FILE, ROOT_MAGIC, RecoveryLimits, append_frame, encode_object_frame, encode_root_snapshot,
    ensure_payload_limit, io_error, live_files_mut, materialize_closure, open_rw,
    read_indexed_object, recover_arena, recover_roots, replace_index, sync_store_directory,
};

const FACT_SNAPSHOT_PREFIX: &[u8] = b"astrid-gc-fact-snapshot-v1\0";
pub(super) const COMPACTION_INTENT_FILE: &str = "compaction.intent";
pub(super) const COMPACTION_INTENT_TEMP: &str = "compaction.intent.tmp";
const COMPACTION_MAGIC: [u8; 8] = *b"ASTCMP1\0";
const COMPACTION_INTENT_V1: [u8; 1] = [1];
pub(super) const ARENA_COMPACTING: &str = "objects.arena.compacting";
pub(super) const ROOTS_COMPACTING: &str = "roots.journal.compacting";
pub(super) const ARENA_PREVIOUS: &str = "objects.arena.previous";
pub(super) const ROOTS_PREVIOUS: &str = "roots.journal.previous";

#[path = "durable_compaction_recovery.rs"]
mod recovery;

use recovery::{
    backup_active, cleanup_without_intent, prepare_finish_compaction, promote_compacting,
    remove_compaction_intent, write_compaction_intent,
};

pub(super) fn recover_interrupted_compaction<P, I, C>(
    directory: &Path,
    codec: &C,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    recovery::recover_interrupted_compaction(directory, codec, identity, limits)
}

/// Explicit liveness policy supplied by native composition.
///
/// Current principal roots are always retained. Additional roots cover
/// operator pins, independent audit anchors, open-handle closures, and
/// externally rooted bootstrap objects. There is intentionally no default
/// history policy: the caller must identify the exact retained policy object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactionRetention {
    operation_contract: ObjectId,
    policy: RetentionPolicyId,
    additional_roots: Vec<CompactionRetainedRoot>,
}

/// Native reason an object closure remains live during compaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompactionRootKind {
    /// Store or runtime bootstrap data retained independently of a principal.
    System,
    /// Named checkpoint, legal hold, or operator-selected history pin.
    ExplicitPin,
    /// Export, import, ingest, placement, or other bounded operation lease.
    OperationLease,
    /// Immutable content selected by a currently open read handle.
    ReadHandle,
    /// Condemned content awaiting the selected resurrection-fence epoch.
    Quarantine,
    /// Evidence retained by an audit or re-attestation custody policy.
    AuditCustody,
}

impl CompactionRootKind {
    const fn code(self) -> u8 {
        match self {
            Self::System => 0,
            Self::ExplicitPin => 1,
            Self::OperationLease => 2,
            Self::ReadHandle => 3,
            Self::Quarantine => 4,
            Self::AuditCustody => 5,
        }
    }
}

/// One typed non-principal root interpreted by a retention policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompactionRetainedRoot {
    kind: CompactionRootKind,
    object: ObjectId,
}

impl CompactionRetainedRoot {
    /// Construct one explicit retained-root fact.
    #[must_use]
    pub const fn new(kind: CompactionRootKind, object: ObjectId) -> Self {
        Self { kind, object }
    }

    /// Return why this root remains live.
    #[must_use]
    pub const fn kind(self) -> CompactionRootKind {
        self.kind
    }

    /// Return the root object whose complete owning closure remains live.
    #[must_use]
    pub const fn object(self) -> ObjectId {
        self.object
    }
}

impl CompactionRetention {
    /// Construct a canonical retained-root set under one identified policy.
    #[must_use]
    pub fn new(
        operation_contract: ObjectId,
        policy: RetentionPolicyId,
        additional_roots: impl IntoIterator<Item = CompactionRetainedRoot>,
    ) -> Self {
        let mut additional_roots = additional_roots.into_iter().collect::<Vec<_>>();
        additional_roots.sort_unstable();
        additional_roots.dedup();
        Self {
            operation_contract,
            policy,
            additional_roots,
        }
    }

    /// Return the pinned native compaction operation contract.
    #[must_use]
    pub const fn operation_contract(&self) -> ObjectId {
        self.operation_contract
    }

    /// Return the exact retention-policy identity.
    #[must_use]
    pub const fn policy(&self) -> RetentionPolicyId {
        self.policy
    }

    /// Borrow the strictly ordered additional retained roots.
    #[must_use]
    pub fn additional_roots(&self) -> &[CompactionRetainedRoot] {
        &self.additional_roots
    }
}

/// Native relation snapshot and proposed condemned set for one GC proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactionFacts {
    snapshot: GcFactSnapshotId,
    snapshot_record: ObjectRecord,
    condemned: Vec<ObjectId>,
}

impl CompactionFacts {
    /// Return the identity of the complete frozen relation snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> GcFactSnapshotId {
        self.snapshot
    }

    /// Borrow the canonical relation snapshot supplied to the auditor.
    #[must_use]
    pub const fn snapshot_record(&self) -> &ObjectRecord {
        &self.snapshot_record
    }

    /// Borrow the strictly ordered native condemned set.
    #[must_use]
    pub fn condemned(&self) -> &[ObjectId] {
        &self.condemned
    }
}

/// Trusted adapter to Astrid's deterministic Tensor Logic auditor.
///
/// The proof never authorizes deletion by itself. The durable engine derives
/// liveness natively, requires this audit, then re-derives the same snapshot
/// while holding the mutation fence immediately before physical replacement.
pub trait CompactionProofVerifier {
    /// Return whether `proof` proves that `facts.condemned` intersects no
    /// closure retained by `policy`.
    fn verify(&self, facts: &CompactionFacts, policy: &ObjectRecord, proof: &ObjectRecord) -> bool;
}

/// Proof-audited plan that can enter the engine-only compaction path.
#[derive(Clone, Debug)]
pub struct VerifiedCompactionPlan {
    retention: CompactionRetention,
    facts: CompactionFacts,
    plan: GcPlanEvidence,
    policy_record: ObjectRecord,
    proof_record: ObjectRecord,
}

impl VerifiedCompactionPlan {
    /// Borrow the canonical GC plan evidence.
    #[must_use]
    pub const fn plan(&self) -> &GcPlanEvidence {
        &self.plan
    }

    /// Borrow the exact native facts audited by the plan.
    #[must_use]
    pub const fn facts(&self) -> &CompactionFacts {
        &self.facts
    }

    /// Borrow the explicit retention contract used for native liveness.
    #[must_use]
    pub const fn retention(&self) -> &CompactionRetention {
        &self.retention
    }
}

/// Physical result of one completed arena generation replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactionReport {
    objects_before: u64,
    objects_after: u64,
    objects_reclaimed: u64,
    arena_bytes_before: u64,
    arena_bytes_after: u64,
    fact_snapshot: GcFactSnapshotId,
}

impl CompactionReport {
    /// Return the number of indexed objects before replacement.
    #[must_use]
    pub const fn objects_before(self) -> u64 {
        self.objects_before
    }

    /// Return the number of objects in the replacement arena.
    #[must_use]
    pub const fn objects_after(self) -> u64 {
        self.objects_after
    }

    /// Return the number of old objects omitted as unreachable.
    #[must_use]
    pub const fn objects_reclaimed(self) -> u64 {
        self.objects_reclaimed
    }

    /// Return physical arena bytes before replacement.
    #[must_use]
    pub const fn arena_bytes_before(self) -> u64 {
        self.arena_bytes_before
    }

    /// Return physical arena bytes after replacement.
    #[must_use]
    pub const fn arena_bytes_after(self) -> u64 {
        self.arena_bytes_after
    }

    /// Return the fence-held relation snapshot executed by this rewrite.
    #[must_use]
    pub const fn fact_snapshot(self) -> GcFactSnapshotId {
        self.fact_snapshot
    }
}

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Capture complete GC relation facts without mutating the store.
    ///
    /// # Errors
    ///
    /// Returns a recovery, identity, graph, principal-codec, or encoding error.
    pub fn capture_compaction_facts(
        &self,
        retention: &CompactionRetention,
    ) -> Result<CompactionFacts, DurableError> {
        let mut inner = self.inner.lock();
        super::ensure_usable(&inner)?;
        self.capture_facts_locked(&mut inner, retention)
            .map(|(facts, _)| facts)
    }

    /// Bind a Tensor Logic proof to freshly rechecked native facts.
    ///
    /// # Errors
    ///
    /// Rejects stale facts, malformed evidence records, an empty condemned
    /// set, or a proof rejected by the trusted adapter.
    pub fn verify_compaction_plan<V: CompactionProofVerifier>(
        &self,
        retention: CompactionRetention,
        facts: CompactionFacts,
        policy_record: ObjectRecord,
        proof_record: ObjectRecord,
        verifier: &V,
    ) -> Result<VerifiedCompactionPlan, DurableError> {
        let current = self.capture_compaction_facts(&retention)?;
        if current != facts {
            return Err(DurableError::CompactionSnapshotChanged);
        }
        if facts.condemned.is_empty() {
            return Err(DurableError::NoCompactionWork);
        }
        require_evidence_record(&policy_record, "retention policy must be Evidence")?;
        require_evidence_record(&proof_record, "Tensor Logic proof must be Evidence")?;
        let policy_id = self.identify(&policy_record);
        if policy_id != retention.policy.object_id() {
            return Err(DurableError::InvalidCompactionEvidence(
                "retention policy identity mismatch",
            ));
        }
        if !verifier.verify(&facts, &policy_record, &proof_record) {
            return Err(DurableError::CompactionProofRejected);
        }
        let proof = TensorLogicProofId::new(self.identify(&proof_record));
        let plan = GcPlanEvidence::new(
            facts.snapshot,
            retention.policy,
            proof,
            facts.condemned.clone(),
        )
        .map_err(|_| DurableError::InvalidCompactionEvidence("non-canonical GC plan"))?;
        Ok(VerifiedCompactionPlan {
            retention,
            facts,
            plan,
            policy_record,
            proof_record,
        })
    }

    /// Execute one proof-audited compaction under the native mutation fence.
    ///
    /// # Errors
    ///
    /// Fails closed if roots, pins, handles, quarantine, or the object
    /// universe changed after proof; I/O or injected faults require reopen.
    pub fn compact(
        &self,
        authorization: &VerifiedCompactionPlan,
    ) -> Result<CompactionReport, DurableError> {
        let mut inner = self.inner.lock();
        super::ensure_usable(&inner)?;
        let (facts, live) = self.capture_facts_locked(&mut inner, &authorization.retention)?;
        if facts != authorization.facts {
            return Err(DurableError::CompactionSnapshotChanged);
        }
        let result = self.compact_locked(&mut inner, authorization, &live);
        if inner.files.is_none()
            || matches!(
                &result,
                Err(DurableError::FaultInjected(_) | DurableError::Io { .. })
            )
        {
            inner.poisoned = true;
        }
        result
    }

    fn capture_facts_locked(
        &self,
        inner: &mut DurableInner<P>,
        retention: &CompactionRetention,
    ) -> Result<(CompactionFacts, BTreeSet<ObjectId>), DurableError> {
        let live = self.live_objects(inner, retention)?;
        let record = self.fact_snapshot_record(inner, retention)?;
        let snapshot = GcFactSnapshotId::new(self.identify(&record));
        let condemned = inner
            .index
            .keys()
            .filter(|id| !live.contains(id))
            .copied()
            .collect();
        Ok((
            CompactionFacts {
                snapshot,
                snapshot_record: record,
                condemned,
            },
            live,
        ))
    }

    fn live_objects(
        &self,
        inner: &mut DurableInner<P>,
        retention: &CompactionRetention,
    ) -> Result<BTreeSet<ObjectId>, DurableError> {
        let roots = inner
            .roots_by_principal
            .values()
            .map(|root| root.commit)
            .chain(retention.additional_roots.iter().map(|root| root.object()))
            .collect::<Vec<_>>();
        let mut live = BTreeSet::new();
        let super::DurableInner { files, index, .. } = inner;
        let files = live_files_mut(files)?;
        for root in roots {
            let closure = materialize_closure(
                &mut files.arena,
                index,
                &BTreeMap::new(),
                root,
                &self.identity,
                self.limits,
            )?;
            live.extend(closure.into_iter().map(|(id, _)| id));
        }
        Ok(live)
    }

    fn fact_snapshot_record(
        &self,
        inner: &mut DurableInner<P>,
        retention: &CompactionRetention,
    ) -> Result<ObjectRecord, DurableError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(FACT_SNAPSHOT_PREFIX);
        bytes.extend_from_slice(retention.operation_contract.as_bytes());
        bytes.extend_from_slice(retention.policy.object_id().as_bytes());
        encode_current_roots(&mut bytes, &inner.roots_by_principal, &self.principal_codec)?;
        encode_retained_roots(&mut bytes, &retention.additional_roots)?;
        let object_count =
            u64::try_from(inner.index.len()).map_err(|_| DurableError::EncodingOverflow)?;
        bytes.extend_from_slice(&object_count.to_le_bytes());
        let super::DurableInner { files, index, .. } = inner;
        let files = live_files_mut(files)?;
        for (id, location) in index.iter() {
            let record = read_indexed_object(
                &mut files.arena,
                *id,
                *location,
                &self.identity,
                self.limits,
            )?;
            bytes.extend_from_slice(id.as_bytes());
            let count = u64::try_from(record.references().len())
                .map_err(|_| DurableError::EncodingOverflow)?;
            bytes.extend_from_slice(&count.to_le_bytes());
            for reference in record.references() {
                let label = reference.label().as_bytes();
                let label_len =
                    u64::try_from(label.len()).map_err(|_| DurableError::EncodingOverflow)?;
                bytes.extend_from_slice(&label_len.to_le_bytes());
                bytes.extend_from_slice(label);
                bytes.extend_from_slice(reference.target().as_bytes());
                bytes.push(reference.kind().code());
            }
        }
        ObjectRecord::new(
            ObjectKind::Evidence,
            ObjectFormatVersion::V1,
            bytes,
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .map_err(DurableError::Model)
    }
}

fn encode_current_roots<P: Ord, C: PrincipalCodec<P>>(
    bytes: &mut Vec<u8>,
    roots: &BTreeMap<P, RootState>,
    codec: &C,
) -> Result<(), DurableError> {
    let mut encoded = roots
        .iter()
        .map(|(principal, root)| (codec.encode(principal), *root))
        .collect::<Vec<_>>();
    encoded.sort_by(|left, right| left.0.cmp(&right.0));
    if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(DurableError::InvalidCompactionEvidence(
            "principal codec collides in fact snapshot",
        ));
    }
    let count = u64::try_from(encoded.len()).map_err(|_| DurableError::EncodingOverflow)?;
    bytes.extend_from_slice(&count.to_le_bytes());
    for (principal, root) in encoded {
        let len = u64::try_from(principal.len()).map_err(|_| DurableError::EncodingOverflow)?;
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&principal);
        bytes.extend_from_slice(&root.generation.get().to_le_bytes());
        bytes.extend_from_slice(root.commit.as_bytes());
    }
    Ok(())
}

fn encode_retained_roots(
    bytes: &mut Vec<u8>,
    roots: &[CompactionRetainedRoot],
) -> Result<(), DurableError> {
    let count = u64::try_from(roots.len()).map_err(|_| DurableError::EncodingOverflow)?;
    bytes.extend_from_slice(&count.to_le_bytes());
    for root in roots {
        bytes.push(root.kind().code());
        bytes.extend_from_slice(root.object().as_bytes());
    }
    Ok(())
}

fn require_evidence_record(
    record: &ObjectRecord,
    detail: &'static str,
) -> Result<(), DurableError> {
    if record.kind() != ObjectKind::Evidence {
        return Err(DurableError::InvalidCompactionEvidence(detail));
    }
    Ok(())
}

struct ReplacementState<P: Ord> {
    roots: BTreeMap<P, RootState>,
    index: BTreeMap<ObjectId, ArenaLocation>,
    validated: BTreeSet<ObjectId>,
    arena_len: u64,
    arena_tail: Option<ArenaLocation>,
}

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    fn compact_locked(
        &self,
        inner: &mut DurableInner<P>,
        authorization: &VerifiedCompactionPlan,
        live: &BTreeSet<ObjectId>,
    ) -> Result<CompactionReport, DurableError> {
        let pass = NativeArenaCompactionPass::new(authorization.retention.operation_contract);
        if pass.operation_contract() != authorization.retention.operation_contract {
            return Err(DurableError::InvalidCompactionEvidence(
                "native compaction operation contract mismatch",
            ));
        }
        let evidence = self.compaction_evidence(authorization)?;
        if evidence
            .keys()
            .any(|id| authorization.facts.condemned.binary_search(id).is_ok())
        {
            return Err(DurableError::InvalidCompactionEvidence(
                "retained compaction evidence was condemned by its own plan",
            ));
        }
        cleanup_without_intent(&self.directory)?;
        let objects_before =
            u64::try_from(inner.index.len()).map_err(|_| DurableError::EncodingOverflow)?;
        let arena_bytes_before = live_files_mut(&mut inner.files)?.arena_len;
        self.write_replacement_files(inner, live, &evidence)?;
        self.fail_if(FaultPoint::AfterCompactionFilesFlush)?;
        write_compaction_intent(&self.directory)?;
        self.fail_if(FaultPoint::AfterCompactionIntentFlush)?;

        drop(inner.files.take());
        self.promote_replacement_files()?;
        sync_store_directory(&self.directory)?;
        self.fail_if(FaultPoint::AfterCompactionDirectoryFlush)?;
        let replacement = self.open_replacement_files()?;
        let objects_after =
            u64::try_from(replacement.index.len()).map_err(|_| DurableError::EncodingOverflow)?;
        let objects_reclaimed = u64::try_from(authorization.facts.condemned.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        let index_state = IndexState {
            arena_len: replacement.arena_len,
            arena_tail: replacement.arena_tail,
            objects: replacement.index.clone(),
        };
        let index_cache = replace_index(&self.directory, &index_state, self.identity.scheme());
        let mut arena = open_rw(&self.directory.join(ARENA_FILE))?;
        let mut roots = open_rw(&self.directory.join(ROOT_FILE))?;
        arena
            .seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek compacted object arena", source))?;
        roots
            .seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek compacted root journal", source))?;
        inner.roots_by_principal = replacement.roots;
        inner.index = replacement.index;
        inner.validated = replacement.validated;
        inner.files = Some(DurableFiles {
            arena,
            roots,
            index_cache,
            arena_len: replacement.arena_len,
            arena_tail: replacement.arena_tail,
        });
        prepare_finish_compaction(&self.directory)?;
        self.fail_if(FaultPoint::BeforeCompactionIntentRemoval)?;
        remove_compaction_intent(&self.directory)?;
        Ok(CompactionReport {
            objects_before,
            objects_after,
            objects_reclaimed,
            arena_bytes_before,
            arena_bytes_after: replacement.arena_len,
            fact_snapshot: authorization.facts.snapshot,
        })
    }

    fn compaction_evidence(
        &self,
        authorization: &VerifiedCompactionPlan,
    ) -> Result<BTreeMap<ObjectId, ObjectRecord>, DurableError> {
        let plan_record = authorization
            .plan
            .to_object_record()
            .map_err(|_| DurableError::InvalidCompactionEvidence("GC plan encoding failed"))?;
        let mut records = BTreeMap::new();
        for record in [
            authorization.facts.snapshot_record.clone(),
            authorization.policy_record.clone(),
            authorization.proof_record.clone(),
            plan_record,
        ] {
            if record.owning_references().next().is_some()
                && record.kind() != ObjectKind::GcPlanEvidence
            {
                return Err(DurableError::InvalidCompactionEvidence(
                    "supplied evidence must not introduce an unavailable owning closure",
                ));
            }
            let id = self.identify(&record);
            match records.get(&id) {
                Some(existing) if existing == &record => {},
                Some(_) => return Err(astrid_storage_model::ModelError::ObjectCollision(id).into()),
                None => {
                    records.insert(id, record);
                },
            }
        }
        Ok(records)
    }

    fn write_replacement_files(
        &self,
        inner: &mut DurableInner<P>,
        live: &BTreeSet<ObjectId>,
        evidence: &BTreeMap<ObjectId, ObjectRecord>,
    ) -> Result<(), DurableError> {
        let mut arena = create_private_file(&self.directory.join(ARENA_COMPACTING))?;
        let mut new_index = BTreeMap::new();
        let ids = live
            .iter()
            .copied()
            .chain(evidence.keys().copied())
            .collect::<BTreeSet<_>>();
        let super::DurableInner { files, index, .. } = inner;
        let files = live_files_mut(files)?;
        for id in ids {
            let record = if let Some(record) = evidence.get(&id) {
                if let Some(location) = index.get(&id).copied() {
                    let existing = read_indexed_object(
                        &mut files.arena,
                        id,
                        location,
                        &self.identity,
                        self.limits,
                    )?;
                    if existing != *record {
                        return Err(astrid_storage_model::ModelError::ObjectCollision(id).into());
                    }
                }
                record.clone()
            } else {
                let location = index
                    .get(&id)
                    .copied()
                    .ok_or(astrid_storage_model::ModelError::MissingObject(id))?;
                read_indexed_object(&mut files.arena, id, location, &self.identity, self.limits)?
            };
            let payload = encode_object_frame(self.identity.scheme(), id, &record)?;
            ensure_payload_limit(ARENA_FILE, 0, payload.len(), self.limits)?;
            let location = append_frame(&mut arena, ARENA_MAGIC, &payload)?;
            new_index.insert(id, location);
        }
        arena
            .sync_data()
            .map_err(|source| io_error("flush compacted object arena", source))?;

        let roots = encoded_roots(&inner.roots_by_principal, &self.principal_codec)?;
        let payload = encode_root_snapshot(self.identity.scheme(), &roots)?;
        ensure_payload_limit(ROOT_FILE, 0, payload.len(), self.limits)?;
        let mut journal = create_private_file(&self.directory.join(ROOTS_COMPACTING))?;
        append_frame(&mut journal, ROOT_MAGIC, &payload)?;
        journal
            .sync_data()
            .map_err(|source| io_error("flush compacted root snapshot", source))?;
        sync_store_directory(&self.directory)?;
        validate_replacement(
            &mut arena,
            &mut journal,
            &new_index,
            &self.principal_codec,
            &self.identity,
            self.limits,
        )
    }

    fn promote_replacement_files(&self) -> Result<(), DurableError> {
        backup_active(&self.directory, ARENA_FILE, ARENA_PREVIOUS)?;
        self.fail_if(FaultPoint::AfterCompactionArenaBackup)?;
        promote_compacting(&self.directory, ARENA_COMPACTING, ARENA_FILE)?;
        self.fail_if(FaultPoint::AfterCompactionArenaPromote)?;
        backup_active(&self.directory, ROOT_FILE, ROOTS_PREVIOUS)?;
        self.fail_if(FaultPoint::AfterCompactionRootsBackup)?;
        promote_compacting(&self.directory, ROOTS_COMPACTING, ROOT_FILE)?;
        self.fail_if(FaultPoint::AfterCompactionRootsPromote)
    }

    fn open_replacement_files(&self) -> Result<ReplacementState<P>, DurableError> {
        let mut arena = open_rw(&self.directory.join(ARENA_FILE))?;
        let mut roots = open_rw(&self.directory.join(ROOT_FILE))?;
        let (index, arena_tail) = recover_arena(&mut arena, &self.identity, self.limits)?;
        let (roots_by_principal, validated) = recover_roots(
            &mut roots,
            &mut arena,
            &index,
            &self.principal_codec,
            &self.identity,
            self.limits,
        )?;
        let arena_len = arena
            .metadata()
            .map_err(|source| io_error("read compacted arena metadata", source))?
            .len();
        Ok(ReplacementState {
            roots: roots_by_principal,
            index,
            validated,
            arena_len,
            arena_tail,
        })
    }
}

fn encoded_roots<P: Ord, C: PrincipalCodec<P>>(
    roots: &BTreeMap<P, RootState>,
    codec: &C,
) -> Result<Vec<(Vec<u8>, RootState)>, DurableError> {
    let mut encoded = roots
        .iter()
        .map(|(principal, root)| (codec.encode(principal), *root))
        .collect::<Vec<_>>();
    encoded.sort_by(|left, right| left.0.cmp(&right.0));
    if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(DurableError::InvalidCompactionEvidence(
            "principal codec collides in root snapshot",
        ));
    }
    Ok(encoded)
}

fn create_private_file(path: &Path) -> Result<File, DurableError> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|source| io_error("create compaction file", source))
}

fn validate_replacement<P, I, C>(
    arena: &mut File,
    roots: &mut File,
    expected_index: &BTreeMap<ObjectId, ArenaLocation>,
    codec: &C,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let (recovered, _) = recover_arena(arena, identity, limits)?;
    if &recovered != expected_index {
        return Err(DurableError::InvalidCompactionEvidence(
            "replacement arena index changed during verification",
        ));
    }
    recover_roots(roots, arena, &recovered, codec, identity, limits)?;
    Ok(())
}

//! Crash and authority tests for proof-audited durable compaction.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use astrid_storage_model::{GcCommitEvidence, GcPlanEvidence, RetentionPolicyId};

use super::compaction::{
    ARENA_COMPACTING, ARENA_PREVIOUS, COMPACTION_INTENT_FILE, COMPACTION_INTENT_TEMP,
    ROOTS_COMPACTING, ROOTS_PREVIOUS,
};
use super::tests::{TestEngine, TestIdentity, Utf8Codec, limits, open_with_cache, transaction};
use super::*;

#[derive(Clone, Copy, Debug)]
struct AcceptProof;

impl CompactionProofVerifier for AcceptProof {
    fn verify(
        &self,
        facts: &CompactionFacts,
        _policy: &ObjectRecord,
        _proof: &ObjectRecord,
    ) -> bool {
        !facts.condemned().is_empty()
    }
}

#[derive(Clone, Copy, Debug)]
struct RejectProof;

impl CompactionProofVerifier for RejectProof {
    fn verify(
        &self,
        _facts: &CompactionFacts,
        _policy: &ObjectRecord,
        _proof: &ObjectRecord,
    ) -> bool {
        false
    }
}

#[derive(Debug)]
struct FailAt(FaultPoint);

impl FaultInjector for FailAt {
    fn should_fail(&self, point: FaultPoint) -> bool {
        point == self.0
    }
}

fn evidence(bytes: &[u8]) -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        bytes.to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}

fn retention(
    engine: &TestEngine,
    policy: &ObjectRecord,
    additional_roots: impl IntoIterator<Item = CompactionRetainedRoot>,
) -> CompactionRetention {
    CompactionRetention::new(
        ObjectId::new([0xC0; 32]),
        RetentionPolicyId::new(engine.identify(policy)),
        additional_roots,
    )
}

fn plan(
    engine: &TestEngine,
    retention: CompactionRetention,
    policy: ObjectRecord,
) -> VerifiedCompactionPlan {
    let facts = engine.capture_compaction_facts(&retention).unwrap();
    engine
        .verify_compaction_plan(
            retention,
            facts,
            policy,
            evidence(b"tensor-logic-proof"),
            &AcceptProof,
        )
        .unwrap()
}

fn open_with_fault(path: &Path, point: FaultPoint) -> TestEngine {
    DurableEngine::open_with_faults(
        path,
        TestIdentity,
        Utf8Codec,
        limits(),
        Arc::new(FailAt(point)),
    )
    .unwrap()
}

fn two_versions(engine: &TestEngine) -> (RootState, RootState) {
    let (_, first) = transaction("alice", None, &vec![0x41; 128 * 1024]);
    let first = engine.commit(first).unwrap().root();
    let (_, second) = transaction("alice", Some(first), b"current");
    let second = engine.commit(second).unwrap().root();
    (first, second)
}

fn only_ready_evidence(directory: &Path) -> PathBuf {
    let entries = std::fs::read_dir(directory.join("gc-outbox"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let ready = entries
        .into_iter()
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".ready"))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    assert_eq!(ready.len(), 1);
    ready.into_iter().next().unwrap()
}

#[test]
fn local_compaction_recovery_magics_are_stable() {
    let directory = tempfile::tempdir().unwrap();
    let engine = super::tests::open(directory.path());
    two_versions(&engine);
    let policy = evidence(b"retain-current-roots");
    let authorization = plan(&engine, retention(&engine, &policy, []), policy);
    drop(engine);

    let interrupted = open_with_fault(directory.path(), FaultPoint::AfterCompactionIntentFlush);
    assert!(interrupted.compact(&authorization).is_err());
    drop(interrupted);

    let intent = std::fs::read(directory.path().join(COMPACTION_INTENT_FILE)).unwrap();
    assert_eq!(&intent[..8], b"ASTCMP1\0");
    assert_eq!(&intent[8..10], &1_u16.to_le_bytes());
    assert_eq!(&intent[10..12], &[0, 0]);

    let prepared = std::fs::read_dir(directory.path().join("gc-outbox"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "prepared")
        })
        .unwrap();
    let outbox = std::fs::read(prepared).unwrap();
    assert_eq!(&outbox[..8], b"ASTGCO1\0");
    assert_eq!(&outbox[8..10], &1_u16.to_le_bytes());
    assert_eq!(&outbox[10..12], &[0, 0]);
}

#[test]
fn compaction_reclaims_only_unreachable_objects_and_preserves_root_generation() {
    let directory = tempfile::tempdir().unwrap();
    let engine = super::tests::open(directory.path());
    let (first, current) = two_versions(&engine);
    let bytes_before = std::fs::metadata(directory.path().join(ARENA_FILE))
        .unwrap()
        .len();
    let policy = evidence(b"retain-current-roots");
    let authorization = plan(&engine, retention(&engine, &policy, []), policy);

    assert!(authorization.facts().condemned().contains(&first.commit));
    let report = engine.compact(&authorization).unwrap();

    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(current));
    assert!(engine.object(first.commit).unwrap().is_none());
    assert!(engine.object(current.commit).unwrap().is_some());
    assert!(report.objects_reclaimed() >= 2);
    assert!(report.arena_bytes_after() < bytes_before);
    assert_eq!(report.fact_snapshot(), authorization.facts().snapshot());
    let pending = engine.pending_compaction_evidence().unwrap();
    assert_eq!(pending.len(), 1);
    let bundle = &pending[0];
    assert_eq!(bundle.commit_id(), report.gc_commit());
    let evidence_plan = GcPlanEvidence::from_object_record(bundle.plan()).unwrap();
    let evidence_commit = GcCommitEvidence::from_object_record(bundle.commit()).unwrap();
    evidence_commit
        .validate_plan(&evidence_plan, &TestIdentity)
        .unwrap();
    assert_eq!(evidence_commit.snapshot(), authorization.facts().snapshot());
    assert!(
        engine
            .object(authorization.facts().snapshot().object_id())
            .unwrap()
            .is_none(),
        "audit delivery records must not become hidden arena roots"
    );

    drop(engine);
    let reopened = super::tests::open(directory.path());
    assert_eq!(reopened.pending_compaction_evidence().unwrap(), pending);
    reopened
        .acknowledge_compaction_evidence(report.gc_commit())
        .unwrap();
    assert!(reopened.pending_compaction_evidence().unwrap().is_empty());
    reopened
        .acknowledge_compaction_evidence(report.gc_commit())
        .unwrap();
    assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(current));
    let (_, next) = transaction("alice", Some(current), b"after-compaction");
    let next = reopened.commit(next).unwrap().root();
    assert_eq!(next.generation.get(), current.generation.get() + 1);
}

#[test]
fn compaction_invalidates_evidence_for_reclaimed_staged_objects() {
    let directory = tempfile::tempdir().unwrap();
    let engine = super::tests::open(directory.path());
    let staged = evidence(b"complete but unreachable staged object");
    let (staged_id, _) = engine.stage_object(&staged).unwrap();
    assert!(engine.inner.lock().validated.contains(&staged_id));
    let policy = evidence(b"retain-current-roots");
    let authorization = plan(&engine, retention(&engine, &policy, []), policy);

    assert!(authorization.facts().condemned().contains(&staged_id));
    engine.compact(&authorization).unwrap();

    let inner = engine.inner.lock();
    assert!(!inner.index.contains_key(&staged_id));
    assert!(!inner.validated.contains(&staged_id));
}

#[test]
fn compaction_rebases_direct_authority_before_retiring_old_placements() {
    let directory = tempfile::tempdir().unwrap();
    let engine = super::tests::open(directory.path());
    let (first, current) = two_versions(&engine);
    let specification = evidence(b"physical format specification");
    let (specification_id, _) = engine.persist_standalone_object(&specification).unwrap();
    engine
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
    let policy = evidence(b"retain-current-roots");
    let authorization = plan(
        &engine,
        retention(
            &engine,
            &policy,
            [CompactionRetainedRoot::new(
                CompactionRootKind::System,
                specification_id,
            )],
        ),
        policy,
    );

    engine.compact(&authorization).unwrap();
    assert!(engine.object(first.commit).unwrap().is_none());
    assert!(engine.object(current.commit).unwrap().is_some());
    {
        let inner = engine.inner.lock();
        let representations = inner.representations.as_ref().unwrap();
        assert!(!representations.contains_direct(first.commit));
        assert!(representations.contains_direct(current.commit));
        assert!(!representations.contains_direct(specification_id));
    }
    engine.close().unwrap();
    drop(engine);

    let reopened = super::tests::open(directory.path());
    assert!(reopened.object(first.commit).unwrap().is_none());
    assert!(reopened.object(current.commit).unwrap().is_some());
}

#[test]
fn compaction_discards_cached_objects_that_leave_the_authoritative_index() {
    let directory = tempfile::tempdir().unwrap();
    let controller = ObjectCacheController::new(ObjectCacheCapacity::Unbounded);
    let engine = open_with_cache(directory.path(), controller);
    let (first, current) = two_versions(&engine);
    let principal = "alice".to_owned();
    let stale_record = engine.object(first.commit).unwrap().unwrap();

    assert!(
        engine
            .object_for(&principal, first.commit)
            .unwrap()
            .is_some()
    );
    assert!(
        engine
            .object_for(&principal, current.commit)
            .unwrap()
            .is_some()
    );
    let policy = evidence(b"retain-current-roots");
    let authorization = plan(&engine, retention(&engine, &policy, []), policy);
    assert!(authorization.facts().condemned().contains(&first.commit));

    engine.compact(&authorization).unwrap();

    assert!(
        engine
            .retain_loaded_object_if_current(&principal, first.commit, 0, stale_record)
            .unwrap()
            .is_none(),
        "a read completed against the old arena generation was retained after compaction"
    );

    assert!(
        engine
            .object_for(&principal, first.commit)
            .unwrap()
            .is_none()
    );
    assert!(
        engine
            .object_for(&principal, current.commit)
            .unwrap()
            .is_some()
    );
}

#[test]
fn explicit_additional_roots_pin_their_complete_closure() {
    let directory = tempfile::tempdir().unwrap();
    let engine = super::tests::open(directory.path());
    let (first, _) = two_versions(&engine);
    let orphan = evidence(b"unreachable-bootstrap-object");
    let (orphan_id, _) = engine.persist_standalone_object(&orphan).unwrap();
    let policy = evidence(b"retain-open-handle-roots");
    let retention = retention(
        &engine,
        &policy,
        [CompactionRetainedRoot::new(
            CompactionRootKind::ReadHandle,
            first.commit,
        )],
    );
    let authorization = plan(&engine, retention, policy);

    assert!(!authorization.facts().condemned().contains(&first.commit));
    assert!(authorization.facts().condemned().contains(&orphan_id));
    engine.compact(&authorization).unwrap();

    assert!(engine.object(first.commit).unwrap().is_some());
    assert!(engine.object(orphan_id).unwrap().is_none());
}

#[test]
fn fact_identity_binds_the_native_reason_for_retention() {
    let directory = tempfile::tempdir().unwrap();
    let engine = super::tests::open(directory.path());
    let (first, _) = two_versions(&engine);
    let policy = evidence(b"typed-retention-reasons");
    let policy_id = RetentionPolicyId::new(engine.identify(&policy));
    let system = CompactionRetention::new(
        ObjectId::new([0xC0; 32]),
        policy_id,
        [CompactionRetainedRoot::new(
            CompactionRootKind::System,
            first.commit,
        )],
    );
    let handle = CompactionRetention::new(
        ObjectId::new([0xC0; 32]),
        policy_id,
        [CompactionRetainedRoot::new(
            CompactionRootKind::ReadHandle,
            first.commit,
        )],
    );

    let system = engine.capture_compaction_facts(&system).unwrap();
    let handle = engine.capture_compaction_facts(&handle).unwrap();
    assert_eq!(system.condemned(), handle.condemned());
    assert_ne!(system.snapshot(), handle.snapshot());
    assert_ne!(system.snapshot_record(), handle.snapshot_record());
}

#[test]
fn changed_fence_snapshot_rejects_a_previously_verified_plan_without_rewrite() {
    let directory = tempfile::tempdir().unwrap();
    let engine = super::tests::open(directory.path());
    let (_, current) = two_versions(&engine);
    let policy = evidence(b"retain-current-roots");
    let authorization = plan(&engine, retention(&engine, &policy, []), policy);
    let (_, next) = transaction("alice", Some(current), b"changed-after-proof");
    let next = engine.commit(next).unwrap().root();
    let bytes_after_commit = std::fs::metadata(directory.path().join(ARENA_FILE))
        .unwrap()
        .len();

    assert!(matches!(
        engine.compact(&authorization),
        Err(DurableError::CompactionSnapshotChanged)
    ));
    assert_eq!(
        std::fs::metadata(directory.path().join(ARENA_FILE))
            .unwrap()
            .len(),
        bytes_after_commit
    );
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(next));
    assert!(!directory.path().join(COMPACTION_INTENT_FILE).exists());
}

#[test]
fn rejected_tensor_logic_proof_never_mints_an_authorization() {
    let directory = tempfile::tempdir().unwrap();
    let engine = super::tests::open(directory.path());
    two_versions(&engine);
    let policy = evidence(b"retain-current-roots");
    let retention = retention(&engine, &policy, []);
    let facts = engine.capture_compaction_facts(&retention).unwrap();

    assert!(matches!(
        engine.verify_compaction_plan(
            retention,
            facts,
            policy,
            evidence(b"rejected-proof"),
            &RejectProof,
        ),
        Err(DurableError::CompactionProofRejected)
    ));
}

#[test]
fn plan_rejects_evidence_that_the_durable_outbox_cannot_deliver() {
    let directory = tempfile::tempdir().unwrap();
    let engine = super::tests::open(directory.path());
    two_versions(&engine);

    let invalid_policy = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"data-class-policy".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Data,
    )
    .unwrap();
    let invalid_retention = retention(&engine, &invalid_policy, []);
    let invalid_policy_facts = engine.capture_compaction_facts(&invalid_retention).unwrap();
    assert!(matches!(
        engine.verify_compaction_plan(
            invalid_retention,
            invalid_policy_facts,
            invalid_policy,
            evidence(b"valid-proof"),
            &AcceptProof,
        ),
        Err(DurableError::InvalidCompactionEvidence(
            "retention policy must be canonical generic Evidence"
        ))
    ));

    let policy = evidence(b"valid-policy");
    let valid_retention = retention(&engine, &policy, []);
    let valid_facts = engine.capture_compaction_facts(&valid_retention).unwrap();
    let invalid_proof = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"data-class-proof".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Data,
    )
    .unwrap();
    assert!(matches!(
        engine.verify_compaction_plan(
            valid_retention,
            valid_facts,
            policy,
            invalid_proof,
            &AcceptProof,
        ),
        Err(DurableError::InvalidCompactionEvidence(
            "Tensor Logic proof must be canonical generic Evidence"
        ))
    ));
}

#[test]
fn placement_before_binds_the_physical_arena_after_staging() {
    let directory = tempfile::tempdir().unwrap();
    let engine = super::tests::open(directory.path());
    two_versions(&engine);
    engine
        .stage_object(&evidence(b"unpublished-staged-evidence"))
        .unwrap();
    let physical_arena_bytes = std::fs::metadata(directory.path().join(ARENA_FILE))
        .unwrap()
        .len();
    let policy = evidence(b"retain-current-roots");
    let authorization = plan(&engine, retention(&engine, &policy, []), policy);

    let report = engine.compact(&authorization).unwrap();
    let pending = engine.pending_compaction_evidence().unwrap();
    let placement = pending[0].placement_before().canonical_bytes();
    let arena_bytes_offset = b"astrid-gc-placement-set-v1\0".len() + 32;
    let receipted_arena_bytes = u64::from_le_bytes(
        placement[arena_bytes_offset..arena_bytes_offset + 8]
            .try_into()
            .unwrap(),
    );

    assert_eq!(report.arena_bytes_before(), physical_arena_bytes);
    assert_eq!(receipted_arena_bytes, physical_arena_bytes);
}

#[test]
fn every_named_compaction_crash_boundary_recovers_a_complete_authority_pair() {
    let points = [
        FaultPoint::AfterCompactionFilesFlush,
        FaultPoint::AfterCompactionEvidencePrepare,
        FaultPoint::AfterCompactionIntentFlush,
        FaultPoint::AfterCompactionArenaBackup,
        FaultPoint::AfterCompactionArenaPromote,
        FaultPoint::AfterCompactionRootsBackup,
        FaultPoint::AfterCompactionRootsPromote,
        FaultPoint::AfterCompactionDirectoryFlush,
        FaultPoint::AfterCompactionEvidenceReady,
        FaultPoint::BeforeCompactionIntentRemoval,
    ];
    for point in points {
        let directory = tempfile::tempdir().unwrap();
        let engine = super::tests::open(directory.path());
        let (first, current) = two_versions(&engine);
        let policy = evidence(b"retain-current-roots");
        let authorization = plan(&engine, retention(&engine, &policy, []), policy);
        drop(engine);

        let interrupted = open_with_fault(directory.path(), point);
        assert!(matches!(
            interrupted.compact(&authorization),
            Err(DurableError::FaultInjected(actual)) if actual == point
        ));
        assert_eq!(
            interrupted.root(&"alice".to_owned()).unwrap(),
            Some(current)
        );
        let transition_committed = !matches!(
            point,
            FaultPoint::AfterCompactionFilesFlush | FaultPoint::AfterCompactionEvidencePrepare
        );
        assert_eq!(
            interrupted.object(first.commit).unwrap().is_none(),
            transition_committed,
            "recovery selected the wrong physical generation at {point:?}"
        );
        assert_eq!(
            interrupted.pending_compaction_evidence().unwrap().len(),
            usize::from(transition_committed),
            "outbox readiness disagrees with physical publication at {point:?}"
        );
        let (_, next) = transaction("alice", Some(current), b"post-recovery");
        interrupted.commit(next).unwrap();
        for remnant in [
            COMPACTION_INTENT_FILE,
            COMPACTION_INTENT_TEMP,
            ARENA_COMPACTING,
            ROOTS_COMPACTING,
            ARENA_PREVIOUS,
            ROOTS_PREVIOUS,
        ] {
            assert!(
                !directory.path().join(remnant).exists(),
                "{remnant} survived recovery at {point:?}"
            );
        }
    }
}

#[test]
fn recovery_never_falls_back_to_an_old_pair_after_receipted_intent() {
    let directory = tempfile::tempdir().unwrap();
    let engine = super::tests::open(directory.path());
    two_versions(&engine);
    let policy = evidence(b"retain-current-roots");
    let authorization = plan(&engine, retention(&engine, &policy, []), policy);
    drop(engine);

    let interrupted = open_with_fault(directory.path(), FaultPoint::AfterCompactionIntentFlush);
    assert!(matches!(
        interrupted.compact(&authorization),
        Err(DurableError::FaultInjected(
            FaultPoint::AfterCompactionIntentFlush
        ))
    ));
    drop(interrupted);
    std::fs::remove_file(directory.path().join(ARENA_COMPACTING)).unwrap();

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::InvalidCompactionEvidence(
            "no authority pair matches the receipted compacted placement"
        ))
    ));
}

#[test]
fn recovery_requires_the_self_contained_evidence_named_by_the_intent() {
    let directory = tempfile::tempdir().unwrap();
    let engine = super::tests::open(directory.path());
    two_versions(&engine);
    let policy = evidence(b"retain-current-roots");
    let authorization = plan(&engine, retention(&engine, &policy, []), policy);
    drop(engine);

    let interrupted = open_with_fault(directory.path(), FaultPoint::AfterCompactionIntentFlush);
    assert!(interrupted.compact(&authorization).is_err());
    drop(interrupted);
    let prepared = std::fs::read_dir(directory.path().join("gc-outbox"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "prepared")
        })
        .unwrap();
    std::fs::remove_file(prepared).unwrap();

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::InvalidCompactionEvidence(
            "durable compaction intent has no matching evidence bundle"
        ))
    ));
}

#[test]
fn tampered_ready_evidence_fails_closed_without_changing_store_authority() {
    let directory = tempfile::tempdir().unwrap();
    let engine = super::tests::open(directory.path());
    let (_, current) = two_versions(&engine);
    let policy = evidence(b"retain-current-roots");
    let authorization = plan(&engine, retention(&engine, &policy, []), policy);
    engine.compact(&authorization).unwrap();

    let ready = only_ready_evidence(directory.path());
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(ready)
        .unwrap();
    file.seek(SeekFrom::Start(52)).unwrap();
    let mut original = [0_u8; 1];
    file.read_exact(&mut original).unwrap();
    file.seek(SeekFrom::Start(52)).unwrap();
    file.write_all(&[original[0] ^ 0xFF]).unwrap();
    file.sync_data().unwrap();
    file.seek(SeekFrom::Start(52)).unwrap();
    let mut changed = [0_u8; 1];
    file.read_exact(&mut changed).unwrap();
    assert_ne!(original, changed);

    let error = engine.pending_compaction_evidence().unwrap_err();
    assert!(
        matches!(
            error,
            DurableError::Corrupt {
                file: "GC evidence outbox",
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(current));
}

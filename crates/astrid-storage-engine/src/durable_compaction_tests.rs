//! Crash and authority tests for proof-audited durable compaction.

use std::path::Path;
use std::sync::Arc;

use astrid_storage_model::RetentionPolicyId;

use super::compaction::{
    ARENA_COMPACTING, ARENA_PREVIOUS, COMPACTION_INTENT_FILE, COMPACTION_INTENT_TEMP,
    ROOTS_COMPACTING, ROOTS_PREVIOUS,
};
use super::tests::{TestEngine, TestIdentity, Utf8Codec, limits, transaction};
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

    drop(engine);
    let reopened = super::tests::open(directory.path());
    assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(current));
    let (_, next) = transaction("alice", Some(current), b"after-compaction");
    let next = reopened.commit(next).unwrap().root();
    assert_eq!(next.generation.get(), current.generation.get() + 1);
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
fn every_named_compaction_crash_boundary_recovers_a_complete_authority_pair() {
    let points = [
        FaultPoint::AfterCompactionFilesFlush,
        FaultPoint::AfterCompactionIntentFlush,
        FaultPoint::AfterCompactionArenaBackup,
        FaultPoint::AfterCompactionArenaPromote,
        FaultPoint::AfterCompactionRootsBackup,
        FaultPoint::AfterCompactionRootsPromote,
        FaultPoint::AfterCompactionDirectoryFlush,
        FaultPoint::BeforeCompactionIntentRemoval,
    ];
    for point in points {
        let directory = tempfile::tempdir().unwrap();
        let engine = super::tests::open(directory.path());
        let (_, current) = two_versions(&engine);
        let policy = evidence(b"retain-current-roots");
        let authorization = plan(&engine, retention(&engine, &policy, []), policy);
        drop(engine);

        let interrupted = open_with_fault(directory.path(), point);
        assert!(matches!(
            interrupted.compact(&authorization),
            Err(DurableError::FaultInjected(actual)) if actual == point
        ));
        assert!(matches!(
            interrupted.root(&"alice".to_owned()),
            Err(DurableError::RequiresRecovery)
        ));
        drop(interrupted);

        let recovered = super::tests::open(directory.path());
        assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(current));
        let (_, next) = transaction("alice", Some(current), b"post-recovery");
        recovered.commit(next).unwrap();
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

use super::{InMemoryEngine, KvProjectionEngine, RootTransaction};
use crate::storage_model::{
    ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectIdentity, ObjectKind,
    ObjectRecord, ObjectReference, ReferenceLabel,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::principal_state::Blake3ObjectIdentityV1 as TestIdentity;

#[derive(Clone, Debug)]
struct CountingIdentity {
    chunk_bytes: Arc<AtomicU64>,
}

impl ObjectIdentity for CountingIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        if record.kind() == ObjectKind::Chunk {
            self.chunk_bytes
                .fetch_add(record.canonical_bytes().len() as u64, Ordering::Relaxed);
        }
        TestIdentity.identify(record)
    }
}

fn chunk(bytes: &[u8]) -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        bytes.to_vec(),
        Vec::new(),
        u64::try_from(bytes.len()).unwrap(),
        ObjectClass::Data,
    )
    .unwrap()
}

fn commit_for(leaf: ObjectId) -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        Vec::new(),
        vec![ObjectReference::owns(
            ReferenceLabel::new(b"state".to_vec()),
            leaf,
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}

fn sealed_chunk_transaction(
    engine: &InMemoryEngine<&str, CountingIdentity>,
    payload: &[u8],
) -> (RootTransaction<&'static str>, u64) {
    let session = engine
        .kv_identity_session()
        .expect("in-memory engine exposes a captured session");
    let leaf = chunk(payload);
    let leaf_id = session.identify(&leaf);
    let commit = commit_for(leaf_id);
    let commit_id = session.identify(&commit);
    let transaction = session.seal_transaction(
        "alice",
        None,
        commit_id,
        vec![(leaf_id, leaf), (commit_id, commit)],
    );
    (transaction, payload.len() as u64)
}

#[test]
fn raw_constructor_still_rehashes_lying_ids() {
    let engine = InMemoryEngine::new(TestIdentity);
    let leaf = chunk(b"payload");
    let forged = ObjectId::new([7; 32]);
    let result = engine.commit(RootTransaction::new(
        "alice",
        None,
        forged,
        vec![(forged, leaf)],
    ));
    assert!(matches!(
        result,
        Err(ModelError::ObjectIdentityMismatch { declared, .. }) if declared == forged
    ));
    assert_eq!(engine.object_count(), 0);
}

#[test]
fn matching_session_skips_only_the_identity_loop() {
    let chunk_bytes = Arc::new(AtomicU64::new(0));
    let engine = InMemoryEngine::new(CountingIdentity {
        chunk_bytes: Arc::clone(&chunk_bytes),
    });
    let payload = vec![0x11; 64];
    let (transaction, _) = sealed_chunk_transaction(&engine, &payload);
    chunk_bytes.store(0, Ordering::Relaxed);
    engine.commit(transaction).unwrap();
    assert_eq!(chunk_bytes.load(Ordering::Relaxed), 0);
    assert_eq!(engine.object_count(), 2);
}

#[test]
fn clone_strips_the_seal_and_rehashes() {
    let chunk_bytes = Arc::new(AtomicU64::new(0));
    let engine = InMemoryEngine::new(CountingIdentity {
        chunk_bytes: Arc::clone(&chunk_bytes),
    });
    let payload = vec![0x22; 96];
    let (transaction, expected) = sealed_chunk_transaction(&engine, &payload);
    let cloned = transaction.clone();
    assert_eq!(cloned, transaction);
    chunk_bytes.store(0, Ordering::Relaxed);
    engine.commit(cloned).unwrap();
    assert_eq!(chunk_bytes.load(Ordering::Relaxed), expected);
}

#[test]
fn foreign_engine_authority_does_not_skip() {
    let payload = vec![0x33; 48];
    let source = InMemoryEngine::new(CountingIdentity {
        chunk_bytes: Arc::new(AtomicU64::new(0)),
    });
    let (transaction, expected) = sealed_chunk_transaction(&source, &payload);
    let observed = Arc::new(AtomicU64::new(0));
    let foreign = InMemoryEngine::new(CountingIdentity {
        chunk_bytes: Arc::clone(&observed),
    });
    foreign.commit(transaction).unwrap();
    assert_eq!(observed.load(Ordering::Relaxed), expected);
}

#[test]
fn reconstructed_transaction_does_not_inherit_the_seal() {
    let observed = Arc::new(AtomicU64::new(0));
    let engine = InMemoryEngine::new(CountingIdentity {
        chunk_bytes: Arc::clone(&observed),
    });
    let (sealed, bytes) = sealed_chunk_transaction(&engine, b"reconstructed");
    let raw = RootTransaction::new(
        *sealed.principal(),
        sealed.expected(),
        sealed.commit(),
        sealed.records().to_vec(),
    );
    assert_eq!(raw, sealed);
    observed.store(0, Ordering::Relaxed);
    engine.commit(raw).unwrap();
    assert_eq!(observed.load(Ordering::Relaxed), bytes);
}

#[test]
fn sealed_missing_closure_is_rejected_without_admission() {
    let engine = InMemoryEngine::new(TestIdentity);
    let session = engine.kv_identity_session().unwrap();
    let missing = ObjectId::new([0x63; 32]);
    let commit = commit_for(missing);
    let commit_id = session.identify(&commit);
    let transaction = session.seal_transaction("alice", None, commit_id, vec![(commit_id, commit)]);
    assert!(
        matches!(engine.commit(transaction), Err(ModelError::MissingObject(id)) if id == missing)
    );
    assert_eq!(engine.object_count(), 0);
    assert_eq!(engine.root(&"alice"), None);
}

#[test]
fn sealed_stale_root_does_not_admit_records() {
    let observed = Arc::new(AtomicU64::new(0));
    let engine = InMemoryEngine::new(CountingIdentity {
        chunk_bytes: Arc::clone(&observed),
    });
    let (first, _) = sealed_chunk_transaction(&engine, b"first");
    let (stale, _) = sealed_chunk_transaction(&engine, b"stale");
    let committed = engine.commit(first).unwrap();
    let before = engine.object_count();
    observed.store(0, Ordering::Relaxed);
    assert!(
        matches!(engine.commit(stale), Err(ModelError::RootConflict { expected: None, actual: Some(actual) }) if actual == committed.root())
    );
    assert_eq!(engine.object_count(), before);
    assert_eq!(engine.root(&"alice"), Some(committed.root()));
    assert_eq!(
        observed.load(Ordering::Relaxed),
        0,
        "only identity recomputation is skipped"
    );
}

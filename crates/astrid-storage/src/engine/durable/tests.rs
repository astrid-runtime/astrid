//! Durable-engine tests split by responsibility for reviewable coverage.

include!("test_cases/foundation.rs");
include!("test_cases/representations.rs");
include!("test_cases/operations_tests.rs");
include!("test_cases/standalone_volume.rs");

#[path = "test_cases/bootstrap_exclusion.rs"]
mod bootstrap_exclusion;

#[test]
fn commit_reports_the_first_misnamed_record_before_admission() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path());
    let (_, mut txn) = transaction("alice", None, b"commit");
    let (_, other) = transaction("bob", None, b"other");
    txn.records.extend(other.records);
    let first = ObjectId::new([0x51; 32]);
    let computed = engine.identify(&txn.records[1].1);
    txn.records[1].0 = first;
    txn.records[3].0 = ObjectId::new([0x52; 32]);
    assert!(
        matches!(engine.commit(txn), Err(DurableError::Model(ModelError::ObjectIdentityMismatch {
        declared,computed:actual
    })) if declared == first && actual == computed)
    );
    assert_eq!(engine.object_count().unwrap(), 0);
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), None);
}

#[test]
fn restore_rejects_a_misnamed_record_before_publishing_anything() {
    let source_dir = tempfile::tempdir().unwrap();
    let source = open(source_dir.path());
    let (_, txn) = transaction("alice", None, b"restore");
    source.commit(txn).unwrap();
    let mut snapshot = source.snapshot(&"alice".to_owned()).unwrap().unwrap();
    let declared = ObjectId::new([0x53; 32]);
    let computed = source.identify(&snapshot.records[1].1);
    snapshot.records[1].0 = declared;
    let destination_dir = tempfile::tempdir().unwrap();
    let destination = open(destination_dir.path());
    assert!(
        matches!(destination.restore_snapshots(vec![("alice".to_owned(), snapshot)]),
        Err(DurableError::Model(ModelError::ObjectIdentityMismatch {declared:name,computed:actual}))
        if name == declared && actual == computed)
    );
    assert_eq!(destination.object_count().unwrap(), 0);
    drop(destination);
    let reopened = open(destination_dir.path());
    assert_eq!(reopened.object_count().unwrap(), 0);
    assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), None);
}

#[test]
fn durable_admission_rechecks_a_foreign_seal_with_the_receiving_identity() {
    let local_dir = tempfile::tempdir().unwrap();
    let local = open(local_dir.path());
    let foreign_dir = tempfile::tempdir().unwrap();
    let foreign =
        DurableEngine::open(foreign_dir.path(), ConstantIdentity, Utf8Codec, limits()).unwrap();
    let session = local.captured_identity_session();
    let sealed = || {
        let (_, txn) = transaction("alice", None, b"sealed");
        session.seal_transaction(txn.principal, txn.expected, txn.commit, txn.records)
    };
    let attempt = sealed();
    let declared = attempt.records()[0].0;
    let computed = ConstantIdentity.identify(&attempt.records()[0].1);
    assert!(
        matches!(foreign.commit(attempt), Err(DurableError::Model(ModelError::ObjectIdentityMismatch {declared:id,computed:digest})) if id == declared && digest == computed)
    );
    assert_eq!(foreign.object_count().unwrap(), 0);
    let root = local.commit(sealed()).unwrap().root();
    drop(local);
    assert_eq!(
        open(local_dir.path()).root(&"alice".to_owned()).unwrap(),
        Some(root)
    );
}

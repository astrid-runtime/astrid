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
    let (_, txn) = transaction("alice", None, b"commit");
    let (_, other) = transaction("bob", None, b"other");
    let mut rows = txn.records().to_vec();
    rows.extend_from_slice(other.records());
    let first = ObjectId::new([0x51; 32]);
    let computed = engine.identify(&rows[1].1);
    rows[1].0 = first;
    rows[3].0 = ObjectId::new([0x52; 32]);
    let txn = RootTransaction::new(txn.principal().clone(), txn.expected(), txn.commit(), rows);
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
        session.seal_transaction(
            txn.principal().clone(),
            txn.expected(),
            txn.commit(),
            txn.records().to_vec(),
        )
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

#[test]
fn preloaded_recovery_agrees_with_fresh_world_validation() {
    use crate::storage_model::World;
    let (root, txn) = transaction("alice", None, b"recovery");
    let table: BTreeMap<_, _> = txn.records().iter().cloned().collect();
    let leaf = txn.records()[0].0;
    let mut incomplete = table.clone();
    incomplete.remove(&leaf);
    let mut cyclic = table.clone();
    cyclic.insert(leaf, table[&root].clone());
    let missing = ObjectId::new([0x73; 32]);
    let wrong_kind_with_missing_child = BTreeMap::from([(
        root,
        ObjectRecord::new(
            ObjectKind::Chunk,
            ObjectFormatVersion::V1,
            Vec::new(),
            vec![ObjectReference::owns(label(b"missing"), missing)],
            0,
            ObjectClass::Data,
        )
        .unwrap(),
    )]);
    for (table, root) in [
        (&table, root),
        (&table, leaf),
        (&table, missing),
        (&incomplete, root),
        (&cyclic, root),
        (&wrong_kind_with_missing_child, root),
    ] {
        let mut source = World::<()>::new();
        for (id, record) in table {
            source.insert_object(*id, record.clone()).unwrap();
        }
        let expected = source.closure(root).and_then(|ids| {
            let records = ids
                .iter()
                .map(|id| (*id, table[id].clone()))
                .collect::<Vec<_>>();
            let mut fresh = World::<()>::new();
            fresh.import_closure(&records, root)?;
            fresh.compare_and_swap_root((), None, root)?;
            Ok(ids)
        });

        let history = BTreeMap::from([(
            "alice",
            (
                RootState {
                    commit: root,
                    generation: RootGeneration::INITIAL,
                },
                913,
            ),
        )]);
        let result = roots::validate_preloaded(&history, table).map_err(|error| match error {
            DurableError::RecoveryModel {
                file: ROOT_FILE,
                offset: 913,
                source,
            } => source,
            other => panic!("unexpected recovery error: {other:?}"),
        });
        assert_eq!(result, expected);
    }
}

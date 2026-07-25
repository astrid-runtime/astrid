//! Tests for the KV compatibility projection.
use super::*;

#[derive(Clone, Copy, Debug)]
struct TestIdentity;

impl ObjectIdentity for TestIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut hasher =
            blake3::Hasher::new_derive_key("astrid storage engine KV projection test v1");
        hasher.update(&record.kind().code().to_le_bytes());
        hasher.update(&record.format_version().get().to_le_bytes());
        hasher.update(&(record.canonical_bytes().len() as u128).to_le_bytes());
        hasher.update(record.canonical_bytes());
        hasher.update(&record.logical_bytes().to_le_bytes());
        hasher.update(&[record.class().code()]);
        hasher.update(&(record.references().len() as u128).to_le_bytes());
        for reference in record.references() {
            hasher.update(&(reference.label().as_bytes().len() as u128).to_le_bytes());
            hasher.update(reference.label().as_bytes());
            hasher.update(reference.target().as_bytes());
            hasher.update(&[reference.kind().code()]);
        }
        ObjectId::new(*hasher.finalize().as_bytes())
    }
}

fn identified(
    engine: &InMemoryEngine<String, TestIdentity>,
    records: &mut BTreeMap<ObjectId, ObjectRecord>,
    record: ObjectRecord,
) -> ObjectId {
    let id = engine.identify(&record);
    records.insert(id, record);
    id
}

#[test]
fn projection_round_trips_namespaces_and_values() {
    let engine = InMemoryEngine::new(TestIdentity);
    let mut snapshot = engine.kv_snapshot("alice".to_owned()).unwrap();
    snapshot
        .state_mut()
        .set(
            "alice:capsule:build".to_owned(),
            "toolchain".to_owned(),
            b"rust".to_vec(),
        )
        .unwrap();
    snapshot
        .state_mut()
        .set(
            "alice:capsule:build".to_owned(),
            "empty".to_owned(),
            Vec::new(),
        )
        .unwrap();
    snapshot
        .state_mut()
        .set(
            "alice:capsule:shell".to_owned(),
            "cwd".to_owned(),
            b"/workspace".to_vec(),
        )
        .unwrap();

    let committed = engine.commit_kv(snapshot).unwrap();
    let decoded = engine.kv_snapshot("alice".to_owned()).unwrap();

    assert_eq!(decoded.root(), Some(committed.root()));
    assert_eq!(
        decoded.state().get("alice:capsule:build", "toolchain"),
        Some(b"rust".as_slice())
    );
    assert_eq!(
        decoded.state().get("alice:capsule:build", "empty"),
        Some([].as_slice())
    );
    assert_eq!(decoded.state().keys("alice:capsule:shell"), vec!["cwd"]);
}

#[test]
fn logical_usage_counts_repeated_visible_values() {
    let engine = InMemoryEngine::new(TestIdentity);
    let mut snapshot = engine.kv_snapshot("alice".to_owned()).unwrap();
    snapshot
        .state_mut()
        .set(
            "alice:capsule:a".to_owned(),
            "same".to_owned(),
            b"repeat".to_vec(),
        )
        .unwrap();
    snapshot
        .state_mut()
        .set(
            "alice:capsule:b".to_owned(),
            "same".to_owned(),
            b"repeat".to_vec(),
        )
        .unwrap();
    engine.commit_kv(snapshot).unwrap();

    let usage = engine.principal_usage(&"alice".to_owned()).unwrap();

    assert_eq!(usage.logical_bytes, 12);
    assert_eq!(
        engine
            .snapshot(&"alice".to_owned())
            .unwrap()
            .unwrap()
            .records()
            .iter()
            .filter(|(_, record)| record.kind() == ObjectKind::KvLeaf)
            .count(),
        1
    );
}

#[test]
fn kv_commit_preserves_non_kv_components_and_commit_annotations() {
    let engine = InMemoryEngine::new(TestIdentity);
    let mut records = BTreeMap::new();
    let files = ObjectRecord::new(
        ObjectKind::Directory,
        FORMAT_VERSION,
        Vec::new(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let files_id = identified(&engine, &mut records, files);
    let namespace_map = ObjectRecord::new(
        ObjectKind::NamespaceMap,
        FORMAT_VERSION,
        Vec::new(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let namespace_map_id = identified(&engine, &mut records, namespace_map);
    let principal_state = ObjectRecord::new(
        ObjectKind::PrincipalState,
        FORMAT_VERSION,
        Vec::new(),
        vec![
            ObjectReference::owns(ReferenceLabel::new(b"files".to_vec()), files_id),
            ObjectReference::owns(ReferenceLabel::new(KV_LABEL.to_vec()), namespace_map_id),
        ],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let state_id = identified(&engine, &mut records, principal_state);
    let annotation_target = ObjectId::new([91; 32]);
    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        FORMAT_VERSION,
        Vec::new(),
        vec![
            ObjectReference::new(
                ReferenceLabel::new(b"audit".to_vec()),
                annotation_target,
                ReferenceKind::Evidence,
            ),
            ObjectReference::owns(ReferenceLabel::new(STATE_LABEL.to_vec()), state_id),
        ],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let commit_id = identified(&engine, &mut records, commit);
    engine
        .commit(RootTransaction::new(
            "alice".to_owned(),
            None,
            commit_id,
            records.into_iter().collect(),
        ))
        .unwrap();

    let mut snapshot = engine.kv_snapshot("alice".to_owned()).unwrap();
    snapshot
        .state_mut()
        .set(
            "alice:capsule:shell".to_owned(),
            "cwd".to_owned(),
            b"/workspace".to_vec(),
        )
        .unwrap();
    let outcome = engine.commit_kv(snapshot).unwrap();
    let root_snapshot = engine.snapshot(&"alice".to_owned()).unwrap().unwrap();
    let record_map: BTreeMap<_, _> = root_snapshot.records().iter().cloned().collect();
    let next_commit = record_map.get(&outcome.root().commit).unwrap();
    let next_state_id = next_commit.reference(STATE_LABEL).unwrap().target();
    let next_state = record_map.get(&next_state_id).unwrap();

    assert_eq!(next_state.reference(b"files").unwrap().target(), files_id);
    assert_eq!(
        next_commit.reference(b"audit").unwrap().target(),
        annotation_target
    );
    assert_eq!(
        next_commit.reference(PARENT_LABEL).unwrap().target(),
        commit_id
    );
}

#[test]
fn malformed_state_kind_is_rejected_during_decode() {
    let engine = InMemoryEngine::new(TestIdentity);
    let wrong_state = ObjectRecord::new(
        ObjectKind::Chunk,
        FORMAT_VERSION,
        b"not state".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Data,
    )
    .unwrap();
    let wrong_state_id = engine.identify(&wrong_state);
    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        FORMAT_VERSION,
        Vec::new(),
        vec![ObjectReference::owns(
            ReferenceLabel::new(STATE_LABEL.to_vec()),
            wrong_state_id,
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let commit_id = engine.identify(&commit);
    engine
        .commit(RootTransaction::new(
            "alice".to_owned(),
            None,
            commit_id,
            vec![(wrong_state_id, wrong_state), (commit_id, commit)],
        ))
        .unwrap();

    let result = engine.kv_snapshot("alice".to_owned());

    assert!(matches!(
        result,
        Err(KvProjectionError::InvalidFormat {
            object,
            detail: "object has the wrong semantic kind",
        }) if object == wrong_state_id
    ));
}

#[test]
fn malformed_parent_edge_is_rejected_during_decode() {
    let engine = InMemoryEngine::new(TestIdentity);
    let mut records = BTreeMap::new();
    let state = ObjectRecord::new(
        ObjectKind::PrincipalState,
        FORMAT_VERSION,
        Vec::new(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let state_id = identified(&engine, &mut records, state);
    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        FORMAT_VERSION,
        Vec::new(),
        vec![
            ObjectReference::new(
                ReferenceLabel::new(PARENT_LABEL.to_vec()),
                ObjectId::new([17; 32]),
                ReferenceKind::Evidence,
            ),
            ObjectReference::owns(ReferenceLabel::new(STATE_LABEL.to_vec()), state_id),
        ],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let commit_id = identified(&engine, &mut records, commit);
    engine
        .commit(RootTransaction::new(
            "alice".to_owned(),
            None,
            commit_id,
            records.into_iter().collect(),
        ))
        .unwrap();

    assert!(matches!(
        engine.kv_snapshot("alice".to_owned()),
        Err(KvProjectionError::InvalidFormat {
            object,
            detail: "commit `parent` reference is not lineage",
        }) if object == commit_id
    ));
}

#[test]
fn invalid_names_cannot_enter_a_snapshot() {
    let engine = InMemoryEngine::new(TestIdentity);
    let mut snapshot = engine.kv_snapshot("alice".to_owned()).unwrap();

    assert_eq!(
        snapshot
            .state_mut()
            .set(String::new(), "key".to_owned(), Vec::new()),
        Err(KvProjectionError::InvalidName { name: "namespace" })
    );
    assert_eq!(
        snapshot
            .state_mut()
            .set("namespace".to_owned(), "bad\0key".to_owned(), Vec::new()),
        Err(KvProjectionError::InvalidName { name: "key" })
    );
    assert!(snapshot.state().is_empty());
    assert!(engine.root(&"alice".to_owned()).is_none());
}

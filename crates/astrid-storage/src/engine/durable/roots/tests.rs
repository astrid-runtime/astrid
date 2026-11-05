//! Recovery graph checks preserve error priority and authenticated arena bytes.

use std::io::{Read, Seek};

use super::*;
use crate::engine::durable::tests::TEST_IDENTITY_SCHEME;
use crate::engine::durable::{ARENA_MAGIC, append_frame, encode_object_frame};
use crate::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectIdentity, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceLabel,
};

struct GraphIdentity;
impl ObjectIdentity for GraphIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        // This synthetic identity permits authenticated cycles so recovery's
        // graph validator can be tested independently of hash preimages.
        ObjectId::new([record.canonical_bytes()[0]; 32])
    }
}
impl PersistentObjectIdentity for GraphIdentity {
    fn scheme(&self) -> IdentityScheme {
        TEST_IDENTITY_SCHEME
    }
}

fn id(value: u8) -> ObjectId {
    ObjectId::new([value; 32])
}

fn record(value: u8, kind: ObjectKind, children: &[u8]) -> (ObjectId, ObjectRecord) {
    let references = children
        .iter()
        .enumerate()
        .map(|(index, child)| {
            ObjectReference::owns(
                ReferenceLabel::new(index.to_be_bytes().to_vec()),
                id(*child),
            )
        })
        .collect();
    (
        id(value),
        ObjectRecord::new(
            kind,
            ObjectFormatVersion::V1,
            vec![value],
            references,
            0,
            ObjectClass::Metadata,
        )
        .unwrap(),
    )
}

fn check_recovery(
    records: &[(ObjectId, ObjectRecord)],
    roots: BTreeMap<u8, (RootState, u64)>,
    expected: Result<BTreeSet<ObjectId>, (u64, ModelError)>,
) {
    let mut arena = File::native(tempfile::tempfile().unwrap());
    let mut index = BTreeMap::new();
    for (id, record) in records {
        let payload = encode_object_frame(TEST_IDENTITY_SCHEME, *id, record).unwrap();
        index.insert(
            *id,
            append_frame(&mut arena, ARENA_MAGIC, &payload).unwrap(),
        );
    }
    let mut before = Vec::new();
    arena.rewind().unwrap();
    arena.read_to_end(&mut before).unwrap();
    let recovered = roots
        .iter()
        .map(|(principal, (root, _))| (*principal, *root))
        .collect::<BTreeMap<_, _>>();
    let result = validate_recovered_roots(
        roots,
        &mut arena,
        &index,
        &GraphIdentity,
        RecoveryLimits::process_addressable(),
    );
    match expected {
        Ok(ids) => assert_eq!(result.unwrap(), (recovered, ids)),
        Err((expected_offset, expected_source)) => {
            let Err(DurableError::RecoveryModel {
                file,
                offset,
                source,
            }) = result
            else {
                panic!("expected model recovery failure: {result:?}")
            };
            assert_eq!(file, ROOT_FILE);
            assert_eq!(offset, expected_offset);
            assert_eq!(source, expected_source);
        },
    }
    arena.rewind().unwrap();
    let mut after = Vec::new();
    arena.read_to_end(&mut after).unwrap();
    assert_eq!(
        after, before,
        "validation must not mutate authenticated authority"
    );
}

fn root(value: u8, offset: u64) -> (RootState, u64) {
    (
        RootState {
            generation: RootGeneration::INITIAL,
            commit: id(value),
        },
        offset,
    )
}

#[test]
fn recovered_graphs_preserve_cycle_and_kind_error_priority() {
    for kind in [ObjectKind::Commit, ObjectKind::Chunk] {
        check_recovery(
            &[record(1, kind, &[2]), record(2, ObjectKind::Chunk, &[1])],
            BTreeMap::from([(7, root(1, 43))]),
            Err((43, ModelError::ObjectCycle(id(1)))),
        );
    }
    check_recovery(
        &[record(1, ObjectKind::Chunk, &[])],
        BTreeMap::from([(7, root(1, 43))]),
        Err((
            43,
            ModelError::RootNotCommit {
                object: id(1),
                actual: ObjectKind::Chunk,
            },
        )),
    );
}

#[test]
fn recovered_graphs_preserve_principal_error_offsets_and_preload_priority() {
    let records = [
        record(1, ObjectKind::Commit, &[]),
        record(2, ObjectKind::Chunk, &[]),
    ];
    check_recovery(
        &records,
        BTreeMap::from([(7, root(1, 43)), (9, root(2, 87))]),
        Err((
            87,
            ModelError::RootNotCommit {
                object: id(2),
                actual: ObjectKind::Chunk,
            },
        )),
    );
    // Preloading the union still discovers missing objects before validating
    // individual roots, and reports the existing first-root journal offset.
    check_recovery(
        &[
            record(1, ObjectKind::Chunk, &[]),
            record(2, ObjectKind::Commit, &[3]),
        ],
        BTreeMap::from([(7, root(1, 43)), (9, root(2, 87))]),
        Err((43, ModelError::MissingObject(id(3)))),
    );
}

#[test]
fn recovered_graphs_preserve_empty_shared_and_disjoint_principal_roots() {
    check_recovery(&[], BTreeMap::new(), Ok(BTreeSet::new()));
    let records = [
        record(1, ObjectKind::Commit, &[3]),
        record(2, ObjectKind::Commit, &[3]),
        record(3, ObjectKind::Chunk, &[]),
        record(4, ObjectKind::Commit, &[]),
    ];
    let mut advanced = root(1, 43);
    advanced.0.generation = RootGeneration::INITIAL.checked_next().unwrap();
    check_recovery(
        &records,
        BTreeMap::from([
            (7, advanced),
            (9, root(1, 87)),
            (11, root(2, 131)),
            (13, root(4, 175)),
        ]),
        Ok(BTreeSet::from([id(1), id(2), id(3), id(4)])),
    );
}

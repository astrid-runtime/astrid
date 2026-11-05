use super::super::{
    Blake3PhysicalIdentity, CanonicalPhysicalMap, Coverage, LOCAL_STORAGE_NODE, PhysicalMapDomain,
    RecoveryLimits, Replica, RepresentationRecordId, StorageNodeId, open_store_root,
};
use super::*;

fn location(offset: u64) -> ArenaLocation {
    ArenaLocation {
        offset,
        payload_len: 8,
        checksum: [3; 32],
    }
}

fn replica(generation: u64, offset: u64) -> Replica {
    Replica::new(
        LOCAL_STORAGE_NODE,
        ReplicaLocator::ArenaFrame {
            arena_generation: generation,
            offset,
            payload_length: 8,
            frame_checksum: [3; 32],
        },
    )
    .unwrap()
}

fn add(
    store: &mut RepresentationStore,
    object: ObjectId,
    payload: u8,
    replicas: Vec<Replica>,
) -> (RepresentationRecordId, crate::storage_model::BlobId) {
    let described = store
        .describe_direct(object, &[payload; 8], location(1))
        .unwrap();
    let record = RepresentationRecord::new(
        store.direct_profile,
        Coverage::exact(object, 8).unwrap(),
        Recipe::DirectCanonical {
            blob: described.blob,
        },
        8,
        8,
        None,
    )
    .unwrap();
    let id = record.identify(&Blake3PhysicalIdentity).unwrap();
    store
        .representations
        .insert(
            &Blake3PhysicalIdentity,
            PhysicalMapKey::from(id),
            record.encode().unwrap(),
        )
        .unwrap();
    let placement = PlacementEntry::new(described.blob, store.direct_profile, 8, replicas).unwrap();
    store
        .placement_entries
        .insert(
            &Blake3PhysicalIdentity,
            PhysicalMapKey::from(described.blob),
            placement.encode().unwrap(),
        )
        .unwrap();
    store.reverse.entry(object).or_default().push(id);
    (id, described.blob)
}

fn with_store(run: impl FnOnce(&mut RepresentationStore)) {
    let directory = tempfile::tempdir().unwrap();
    let root = open_store_root(directory.path()).unwrap();
    let mut store = RepresentationStore::activate(
        &root,
        RecoveryLimits::process_addressable(),
        ObjectId::new([9; 32]),
        [],
    )
    .unwrap();
    run(&mut store);
}

#[test]
fn selected_first_placement_protects_all_gen0_replicas_and_accepts_any_matching_one() {
    with_store(|store| {
        let object = ObjectId::new([1; 32]);
        add(
            store,
            object,
            1,
            vec![
                replica(0, 10),
                Replica::new(
                    StorageNodeId::new(7),
                    ReplicaLocator::ArenaFrame {
                        arena_generation: 0,
                        offset: 100,
                        payload_length: 8,
                        frame_checksum: [3; 32],
                    },
                )
                .unwrap(),
                replica(1, 900),
                Replica::new(
                    LOCAL_STORAGE_NODE,
                    ReplicaLocator::PackFrame {
                        pack_generation: 0,
                        offset: u64::MAX,
                        frame_length: FRAME_HEADER_LEN + 8,
                        frame_checksum: [3; 32],
                    },
                )
                .unwrap(),
            ],
        );
        add(store, object, 2, vec![replica(0, 800)]);
        assert_eq!(
            store.generation_zero_protected_len().unwrap(),
            100 + FRAME_HEADER_LEN + 8
        );
        store
            .validate_generation_zero_index(&BTreeMap::from([(object, location(100))]))
            .unwrap();
        assert!(
            store
                .validate_generation_zero_index(&BTreeMap::from([(object, location(800))]))
                .is_err()
        );
        assert!(
            store
                .validate_generation_zero_index(&BTreeMap::new())
                .is_err()
        );
    });
}

#[test]
fn topology_preserves_empty_selection_and_rejects_mismatched_frame_fields() {
    with_store(|store| {
        let first = ObjectId::new([1; 32]);
        let second = ObjectId::new([2; 32]);
        let mut index = BTreeMap::from([(first, location(10)), (second, location(20))]);
        assert_eq!(store.generation_zero_protected_len().unwrap(), 0);
        store.validate_generation_zero_index(&index).unwrap();
        add(store, first, 1, vec![replica(0, 10)]);
        add(store, second, 2, vec![replica(0, 20)]);
        store.validate_generation_zero_index(&index).unwrap();
        for invalid in [
            location(11),
            ArenaLocation {
                payload_len: 9,
                ..location(10)
            },
            ArenaLocation {
                checksum: [4; 32],
                ..location(10)
            },
            location(20),
        ] {
            index.insert(first, invalid);
            assert!(matches!(
                store.validate_generation_zero_index(&index),
                Err(DurableError::InvalidRepresentationState(
                    "generation-zero placement disagrees with the arena index",
                ))
            ));
        }
    });
}

#[test]
fn streaming_delivers_one_placement_before_later_selection_failure() {
    with_store(|store| {
        add(store, ObjectId::new([1; 32]), 1, vec![replica(0, 10)]);
        store.reverse.insert(ObjectId::new([2; 32]), Vec::new());
        let mut delivered = 0;
        let result = store.visit_direct_placements(|_, placement| {
            delivered += 1;
            assert_eq!(locations(placement).count(), 1);
            Ok(())
        });
        assert_eq!(delivered, 1);
        assert!(matches!(
            result,
            Err(DurableError::InvalidRepresentationState(
                "reverse index has no direct representation",
            ))
        ));
    });
}

#[test]
fn later_selection_error_precedes_earlier_overflow_or_topology_error() {
    with_store(|store| {
        add(store, ObjectId::new([1; 32]), 1, vec![replica(0, u64::MAX)]);
        store.reverse.insert(ObjectId::new([2; 32]), Vec::new());
        for result in [
            store.generation_zero_protected_len(),
            store
                .validate_generation_zero_index(&BTreeMap::new())
                .map(|()| 0),
        ] {
            assert!(matches!(
                result,
                Err(DurableError::InvalidRepresentationState(
                    "reverse index has no direct representation",
                ))
            ));
        }
        store.reverse.remove(&ObjectId::new([2; 32]));
        assert!(matches!(
            store.generation_zero_protected_len(),
            Err(DurableError::EncodingOverflow)
        ));
    });
}

#[test]
fn selected_placement_without_gen0_fails_before_prior_consumer_error() {
    with_store(|store| {
        add(store, ObjectId::new([1; 32]), 1, vec![replica(0, u64::MAX)]);
        add(store, ObjectId::new([2; 32]), 2, vec![replica(1, 10)]);
        assert!(matches!(
            store.generation_zero_protected_len(),
            Err(DurableError::InvalidRepresentationState(
                "direct representation has no generation-zero arena placement",
            ))
        ));
    });
}

#[test]
fn later_malformed_placement_precedes_earlier_fold_errors() {
    with_store(|store| {
        let (_, first) = add(store, ObjectId::new([1; 32]), 1, vec![replica(0, u64::MAX)]);
        let (_, second) = add(store, ObjectId::new([2; 32]), 2, vec![replica(0, 10)]);
        let first_bytes = store
            .placement_entries
            .get(PhysicalMapKey::from(first))
            .unwrap()
            .to_vec();
        store.placement_entries = CanonicalPhysicalMap::build_dense(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Placement,
            vec![
                (PhysicalMapKey::from(first), first_bytes),
                (PhysicalMapKey::from(second), vec![0]),
            ],
        )
        .unwrap();
        assert!(matches!(
            store.generation_zero_protected_len(),
            Err(DurableError::PhysicalModel(_))
        ));
        assert!(matches!(
            store.validate_generation_zero_index(&BTreeMap::new()),
            Err(DurableError::PhysicalModel(_))
        ));
    });
}

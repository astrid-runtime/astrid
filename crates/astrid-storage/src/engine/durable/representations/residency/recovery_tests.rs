use std::collections::BTreeSet;
use std::sync::Arc;

use super::super::{ArenaLocation, ObjectId, RecoveryLimits, open_store_root};
use super::super::{RepresentationStore, append_new_reachable_map_nodes};
use crate::volume::{AstridVolume, HostedFileVolume};

fn populate(store: &mut RepresentationStore) {
    for sequence in 0_u64..128 {
        let bytes = sequence.to_le_bytes();
        let direct = store
            .describe_direct(
                ObjectId::new(*blake3::hash(&bytes).as_bytes()),
                &bytes,
                ArenaLocation {
                    offset: sequence.checked_mul(100).unwrap(),
                    payload_len: 8,
                    checksum: [3; 32],
                },
            )
            .unwrap();
        let pending = store.append_direct_update(&[direct]).unwrap().unwrap();
        store.publish_direct_update(pending).unwrap();
    }
    store.flush().unwrap();
}

fn assert_first_walk_reuses_recovered_closure(mut store: RepresentationStore) {
    let active = store.active;
    let metadata_bytes = store.metadata.metadata().unwrap().len();
    let mut metadata = Vec::new();
    let mut appended = BTreeSet::new();
    for map in [
        store.representations.as_canonical(),
        store.placement_entries.as_canonical(),
        store.profiles.as_canonical(),
    ] {
        let visited = append_new_reachable_map_nodes(
            &mut metadata,
            map,
            &mut store.persisted_map_nodes,
            &mut appended,
            &mut store.complete_map_subtrees,
        )
        .unwrap();
        assert_eq!(
            visited, 0,
            "recovery already authenticated this complete closure"
        );
    }
    assert!(
        store
            .persisted_map_nodes
            .is_disjoint(&store.complete_map_subtrees)
    );
    assert!(metadata.is_empty());
    assert!(appended.is_empty());
    assert_eq!(store.active, active);
    assert_eq!(store.metadata.metadata().unwrap().len(), metadata_bytes);
    for sequence in 0_u64..128 {
        assert!(store.contains_direct(ObjectId::new(
            *blake3::hash(&sequence.to_le_bytes()).as_bytes()
        )));
    }
}

#[test]
fn native_recovery_reuses_complete_closures_on_first_append_walk() {
    let directory = tempfile::tempdir().unwrap();
    let root = open_store_root(directory.path()).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate(&root, limits, ObjectId::new([1; 32]), []).unwrap();
    populate(&mut store);
    drop(store);
    assert_first_walk_reuses_recovered_closure(
        RepresentationStore::open(&root, limits).unwrap().unwrap(),
    );
}

#[test]
fn volume_recovery_reuses_complete_closures_on_first_append_walk() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("recovery.volume")).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    populate(&mut store);
    drop(store);
    assert_first_walk_reuses_recovered_closure(
        RepresentationStore::open_volume(&volume, limits)
            .unwrap()
            .unwrap(),
    );
}

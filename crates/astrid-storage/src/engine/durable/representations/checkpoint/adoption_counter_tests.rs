//! Automatic maintenance preserves the live maps; compaction still reconstructs.

use std::sync::Arc;

use super::super::recovery::{recover_active_nodes_calls, reset_recover_active_nodes_calls};
use super::super::{ArenaLocation, ObjectId, open_store_root};
use super::{RecoveryLimits, RepresentationStore};
use crate::volume::{AstridVolume, HostedFileVolume};

fn accumulate_history(store: &mut RepresentationStore) {
    for offset in 1..=32 {
        let object = store
            .describe_direct(
                ObjectId::new([7; 32]),
                &[42; 8],
                ArenaLocation {
                    offset,
                    payload_len: 8,
                    checksum: [3; 32],
                },
            )
            .unwrap();
        store.rebase_all_direct(&[object]).unwrap();
    }
    assert!(store.should_checkpoint_representations_metadata());
}

#[test]
fn automatic_volume_checkpoint_does_not_reconstruct_live_maps() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("checkpoint.volume")).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    accumulate_history(&mut store);
    let active = store.active;
    let previous_generation = store.journal_generation;
    reset_recover_active_nodes_calls();
    assert!(store.maybe_checkpoint_volume(&volume, limits).unwrap());
    assert_eq!(
        recover_active_nodes_calls(),
        0,
        "automatic maintenance must retain live maps"
    );
    assert_eq!(store.active, active);
    assert_eq!(store.journal_generation, previous_generation + 1);
    assert!(store.map_frame_count() <= store.resident_map_node_count());
    drop(store);
    reset_recover_active_nodes_calls();
    let reopened = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(
        recover_active_nodes_calls(),
        3,
        "cold open must still independently reconstruct"
    );
    assert_eq!(reopened.active, active);
    assert_eq!(reopened.journal_generation, previous_generation + 1);
    assert!(reopened.contains_direct(ObjectId::new([7; 32])));
}

#[test]
fn automatic_native_checkpoint_does_not_reconstruct_live_maps() {
    let directory = tempfile::tempdir().unwrap();
    let root = open_store_root(directory.path()).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate(&root, limits, ObjectId::new([1; 32]), []).unwrap();
    accumulate_history(&mut store);
    let active = store.active;
    let previous_generation = store.journal_generation;
    reset_recover_active_nodes_calls();
    assert!(store.maybe_checkpoint_native(&root, limits).unwrap());
    assert_eq!(
        recover_active_nodes_calls(),
        0,
        "automatic maintenance must retain live maps"
    );
    assert_eq!(store.active, active);
    drop(store);
    reset_recover_active_nodes_calls();
    let reopened = RepresentationStore::open(&root, limits).unwrap().unwrap();
    assert_eq!(
        recover_active_nodes_calls(),
        3,
        "cold open must still independently reconstruct"
    );
    assert_eq!(reopened.active, active);
    assert_eq!(reopened.journal_generation, previous_generation + 1);
    assert!(reopened.contains_direct(ObjectId::new([7; 32])));
}

#[test]
fn independent_checkpoint_preparation_and_native_compaction_still_reconstruct() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("prepared.volume")).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    accumulate_history(&mut store);
    let active = store.active;
    let generation = store.journal_generation;
    reset_recover_active_nodes_calls();
    let prepared = store.prepare_checkpoint_volume(&volume, limits).unwrap();
    assert_eq!(recover_active_nodes_calls(), 3);
    assert_eq!(prepared.active, active);
    assert_eq!(prepared.journal_generation, generation + 1);
    assert_eq!(
        store.journal_generation, generation,
        "preparation must not publish CURRENT"
    );
    assert_eq!(
        RepresentationStore::open_volume(&volume, limits)
            .unwrap()
            .unwrap()
            .journal_generation,
        generation
    );

    let native_directory = tempfile::tempdir().unwrap();
    let root = open_store_root(native_directory.path()).unwrap();
    let mut native =
        RepresentationStore::activate(&root, limits, ObjectId::new([1; 32]), []).unwrap();
    accumulate_history(&mut native);
    let active = native.active;
    reset_recover_active_nodes_calls();
    native.checkpoint_native(&root, limits).unwrap();
    assert_eq!(
        recover_active_nodes_calls(),
        3,
        "native compaction retains independent reconstruction"
    );
    assert_eq!(native.active, active);
}

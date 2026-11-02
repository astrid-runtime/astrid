use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::storage_model::{CanonicalPhysicalMap, PhysicalMapNode, PhysicalMapNodeId};
use crate::volume::{AstridVolume, HostedFileVolume};

use super::super::scan_frames;
use super::format::{METADATA_FILE, METADATA_MAGIC, MetadataFrame, MetadataKind};
use super::{
    ArenaLocation, DirectArenaObject, ObjectId, RecoveryLimits, RepresentationStore,
    append_new_reachable_map_nodes, append_unpersisted_reachable_map_nodes,
};

fn open_volume(name: &str) -> (tempfile::TempDir, Arc<dyn AstridVolume>) {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join(name)).unwrap();
    (directory, volume)
}

fn activate(volume: &Arc<dyn AstridVolume>) -> RepresentationStore {
    RepresentationStore::activate_volume(
        volume,
        RecoveryLimits::process_addressable(),
        ObjectId::new([1; 32]),
        [],
    )
    .unwrap()
}

fn describe(store: &RepresentationStore, sequence: u64, offset: u64) -> DirectArenaObject {
    let bytes = sequence.to_le_bytes();
    store
        .describe_direct(
            ObjectId::new(*blake3::hash(&bytes).as_bytes()),
            &bytes,
            ArenaLocation {
                offset,
                payload_len: 8,
                checksum: [3; 32],
            },
        )
        .unwrap()
}

fn publish_one(store: &mut RepresentationStore, sequence: u64, offset: u64) {
    let direct = describe(store, sequence, offset);
    let update = store.append_direct_update(&[direct]).unwrap().unwrap();
    store.publish_direct_update(update).unwrap();
}

fn map_node_positions(store: &mut RepresentationStore) -> BTreeMap<[u8; 32], usize> {
    let mut positions = BTreeMap::new();
    let mut index = 0_usize;
    scan_frames(
        &mut store.metadata,
        METADATA_FILE,
        METADATA_MAGIC,
        RecoveryLimits::process_addressable(),
        |_, payload| {
            let frame = MetadataFrame::decode(payload)?;
            if frame.kind == MetadataKind::MapNode {
                positions.entry(frame.identity).or_insert(index);
                index = index.checked_add(1).unwrap();
            }
            Ok(())
        },
    )
    .unwrap();
    positions
}

fn count_identity_frames(store: &mut RepresentationStore, id: PhysicalMapNodeId) -> usize {
    let mut copies = 0_usize;
    scan_frames(
        &mut store.metadata,
        METADATA_FILE,
        METADATA_MAGIC,
        RecoveryLimits::process_addressable(),
        |_, payload| {
            let frame = MetadataFrame::decode(payload)?;
            if frame.kind == MetadataKind::MapNode && frame.identity == *id.as_bytes() {
                copies = copies.checked_add(1).unwrap();
            }
            Ok(())
        },
    )
    .unwrap();
    copies
}

fn assert_children_before_parents(
    store: &RepresentationStore,
    positions: &BTreeMap<[u8; 32], usize>,
    emitted: &BTreeSet<PhysicalMapNodeId>,
) {
    for map in [&store.representations, &store.placement_entries] {
        for (parent, node) in map.nodes() {
            if !emitted.contains(parent) {
                continue;
            }
            let Some(parent_position) = positions.get(parent.as_bytes()) else {
                continue;
            };
            let children = match node {
                PhysicalMapNode::Branch { zero, one, .. } => vec![*zero, *one],
                PhysicalMapNode::Radix { children, .. } => children.clone(),
                PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => Vec::new(),
            };
            assert!(children.iter().all(|child| {
                !emitted.contains(child)
                    || positions
                        .get(child.as_bytes())
                        .is_some_and(|child_position| child_position < parent_position)
            }));
        }
    }
}

#[test]
fn recovered_store_pending_is_empty_while_maps_have_nodes() {
    let (_directory, volume) = open_volume("pending-open.volume");
    let mut store = activate(&volume);
    for sequence in 0_u64..8 {
        publish_one(&mut store, sequence, sequence.checked_mul(100).unwrap());
    }
    let resident = store.profiles.nodes().len()
        + store.representations.nodes().len()
        + store.placement_entries.nodes().len();
    assert!(resident > 1);
    assert!(store.pending_unpersisted_map_nodes.is_empty());
    drop(store);
    let reopened = RepresentationStore::open_volume(&volume, RecoveryLimits::process_addressable())
        .unwrap()
        .unwrap();
    let reopened_resident = reopened.profiles.nodes().len()
        + reopened.representations.nodes().len()
        + reopened.placement_entries.nodes().len();
    assert!(reopened_resident > 1);
    assert!(reopened.pending_unpersisted_map_nodes.is_empty());
}

#[test]
fn metadata_append_failure_retries_pending_children_before_parent() {
    let (_directory, volume) = open_volume("pending-retry.volume");
    let mut store = activate(&volume);
    publish_one(&mut store, 0, 100);
    assert!(store.pending_unpersisted_map_nodes.is_empty());
    RepresentationStore::fail_next_metadata_append();
    let second = describe(&store, 1, 200);
    assert!(
        store
            .append_direct_update(std::slice::from_ref(&second))
            .is_err()
    );
    assert!(!store.pending_unpersisted_map_nodes.is_empty());
    let emitted = store.pending_unpersisted_map_nodes.clone();
    let update = store.append_direct_update(&[second]).unwrap().unwrap();
    let positions = map_node_positions(&mut store);
    assert_children_before_parents(&store, &positions, &emitted);
    assert!(
        emitted
            .iter()
            .all(|id| positions.contains_key(id.as_bytes()))
    );
    assert!(
        emitted
            .iter()
            .all(|id| !store.pending_unpersisted_map_nodes.contains(id))
    );
    store.publish_direct_update(update).unwrap();
}

#[test]
fn rebase_omits_reused_representation_ids() {
    let (_directory, volume) = open_volume("pending-rebase.volume");
    let mut store = activate(&volume);
    let first = describe(&store, 0, 100);
    let second = describe(&store, 1, 200);
    let update = store
        .append_direct_update(&[first.clone(), second.clone()])
        .unwrap()
        .unwrap();
    store.publish_direct_update(update).unwrap();
    let representation_root = store.representations.root().unwrap();
    let placement_root = store.placement_entries.root().unwrap();
    let old_placement: BTreeSet<_> = store.placement_entries.nodes().keys().copied().collect();
    assert_eq!(count_identity_frames(&mut store, representation_root), 1);
    let moved = [describe(&store, 0, 300), describe(&store, 1, 400)];
    store.rebase_all_direct(&moved).unwrap();
    assert_eq!(store.representations.root(), Some(representation_root));
    assert_ne!(store.placement_entries.root(), Some(placement_root));
    assert_eq!(count_identity_frames(&mut store, representation_root), 1);
    let replacement_root = store.placement_entries.root().unwrap();
    assert_eq!(count_identity_frames(&mut store, replacement_root), 1);
    assert!(store.pending_unpersisted_map_nodes.is_empty());
    assert!(old_placement.iter().all(|id| {
        store.placement_entries.nodes().contains_key(id)
            || !store.pending_unpersisted_map_nodes.contains(id)
    }));
}

#[test]
fn checkpoint_emits_every_reachable_node_when_pending_is_empty() {
    let (_directory, volume) = open_volume("pending-checkpoint.volume");
    let mut store = activate(&volume);
    for sequence in 0_u64..8 {
        publish_one(&mut store, sequence, sequence.checked_mul(100).unwrap());
    }
    assert!(store.pending_unpersisted_map_nodes.is_empty());
    let mut checkpoint = Vec::new();
    let mut appended = BTreeSet::new();
    append_new_reachable_map_nodes(
        &mut checkpoint,
        &store.representations,
        &BTreeSet::new(),
        &mut appended,
        &mut BTreeSet::new(),
    )
    .unwrap();
    let mut active = store.representations.clone();
    active.reclaim_unreachable_nodes().unwrap();
    let reachable: BTreeSet<_> = active.nodes().keys().copied().collect();
    assert_eq!(appended, reachable);
    assert!(appended.len() > 1);
    let mut incremental = Vec::new();
    let mut skipped = BTreeSet::new();
    append_unpersisted_reachable_map_nodes(
        &mut incremental,
        &store.representations,
        &store.pending_unpersisted_map_nodes,
        &mut skipped,
        &mut BTreeSet::new(),
    )
    .unwrap();
    assert!(incremental.is_empty());
    assert!(skipped.is_empty());
}

#[test]
fn append_occupancy_reports_follow_the_copied_path() {
    let (_directory, volume) = open_volume("pending-path.volume");
    let mut store = activate(&volume);
    for sequence in 0_u64..32 {
        publish_one(&mut store, sequence, sequence.checked_mul(100).unwrap());
    }
    let before = store.representations.nodes().len() + store.placement_entries.nodes().len();
    CanonicalPhysicalMap::take_occupancy_reports();
    publish_one(&mut store, 32, 3200);
    let reports = CanonicalPhysicalMap::take_occupancy_reports();
    assert!(reports > 0);
    assert!(reports < before);
    assert!(store.pending_unpersisted_map_nodes.is_empty());
}

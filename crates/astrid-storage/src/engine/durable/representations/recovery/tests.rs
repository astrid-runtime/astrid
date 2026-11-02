use super::*;
use crate::storage_model::PhysicalMapDomain;

#[test]
fn recovery_memo_never_remembers_an_incomplete_closure() {
    let map = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        (0_u32..32)
            .map(|ordinal| {
                (
                    PhysicalMapKey::new(*blake3::hash(&ordinal.to_le_bytes()).as_bytes()),
                    ordinal.to_le_bytes().to_vec(),
                )
            })
            .collect(),
    )
    .unwrap();
    let root = map.root().unwrap();
    assert!(map.nodes().len() > 1);
    let mut partial = MetadataIndex::default();
    partial
        .insert(MetadataFrame::map_node(&Blake3PhysicalIdentity, &map.nodes()[&root]).unwrap())
        .unwrap();
    let mut incomplete = partial.nodes.closure_checker();
    assert!(!incomplete.complete(Some(root)));
    assert_eq!(incomplete.len(), 0);
    assert!(!incomplete.complete(Some(root)));
    assert_eq!(incomplete.len(), 0);
    let mut metadata = MetadataIndex::default();
    for node in map.nodes().values() {
        metadata
            .insert(MetadataFrame::map_node(&Blake3PhysicalIdentity, node).unwrap())
            .unwrap();
    }
    let mut complete = metadata.nodes.closure_checker();
    assert!(complete.complete(Some(root)));
    assert_eq!(complete.len(), map.nodes().len());
    let verified = complete.len();
    assert!(complete.complete(Some(root)));
    assert_eq!(complete.len(), verified);
    let absent = PhysicalMapKey::new([255; 32]);
    let other = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![(absent, vec![0])],
    )
    .unwrap();
    assert!(!complete.complete(other.root()));
    assert_eq!(complete.len(), verified);
}

fn dense_representation_map() -> CanonicalPhysicalMap {
    CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        (0_u32..32)
            .map(|ordinal| {
                (
                    PhysicalMapKey::new(*blake3::hash(&ordinal.to_le_bytes()).as_bytes()),
                    ordinal.to_le_bytes().to_vec(),
                )
            })
            .collect(),
    )
    .unwrap()
}

fn index_with_state(
    map: &CanonicalPhysicalMap,
    catalogue: RepresentationCatalogueRoot,
    placements: PlacementSet,
    state: RepresentationState,
) -> (MetadataIndex, RepresentationStateId) {
    let identity = Blake3PhysicalIdentity;
    let mut index = MetadataIndex::default();
    for node in map.nodes().values() {
        index
            .insert(MetadataFrame::map_node(&identity, node).unwrap())
            .unwrap();
    }
    index
        .insert(MetadataFrame::catalogue(&identity, catalogue))
        .unwrap();
    index
        .insert(MetadataFrame::placement(&identity, placements))
        .unwrap();
    let state_id = state.identify(&identity);
    index
        .insert(MetadataFrame::state(&identity, state))
        .unwrap();
    (index, state_id)
}

fn shared_roots(map: &CanonicalPhysicalMap) -> (RepresentationCatalogueRoot, PlacementSet) {
    let leaves = 32;
    (
        RepresentationCatalogueRoot::new(1, map.root(), leaves, map.root(), leaves).unwrap(),
        PlacementSet::new(1, map.root(), leaves, leaves).unwrap(),
    )
}

fn later_journal_checkpoint(
    active: RepresentationStateId,
    state_generation: u64,
) -> (JournalEntry, CurrentPointer) {
    (
        JournalEntry::Checkpoint {
            journal_generation: FIRST_JOURNAL_GENERATION + 1,
            active: Some(active),
            state_generation,
            prior_journal_digest: Some([7; 32]),
        },
        CurrentPointer {
            journal_generation: FIRST_JOURNAL_GENERATION + 1,
            checkpoint_digest: [1; 32],
            max_tail_frames: 8,
            max_tail_bytes: 64,
        },
    )
}

#[test]
fn checkpoint_closure_is_reused_by_the_first_shared_cas() {
    let map = dense_representation_map();
    let (catalogue, placements) = shared_roots(&map);
    let identity = Blake3PhysicalIdentity;
    let checkpoint_state = RepresentationState::new(
        1,
        None,
        catalogue.identify(&identity),
        placements.identify(&identity),
    )
    .unwrap();
    let (mut metadata, checkpoint_id) =
        index_with_state(&map, catalogue, placements, checkpoint_state);
    let cas_state = RepresentationState::new(
        2,
        Some(checkpoint_id),
        catalogue.identify(&identity),
        placements.identify(&identity),
    )
    .unwrap();
    let cas_id = cas_state.identify(&identity);
    metadata
        .insert(MetadataFrame::state(&identity, cas_state))
        .unwrap();
    let (checkpoint, current) = later_journal_checkpoint(checkpoint_id, 1);
    let mut complete = metadata.nodes.closure_checker();
    recover_checkpoint(checkpoint, current, &metadata, &mut complete).unwrap();
    assert_eq!(complete.len(), map.nodes().len());
    let visited = complete.visits();
    assert!(state_metadata_closure_complete(cas_id, &metadata, &mut complete).unwrap());
    assert_eq!(
        complete.visits(),
        visited,
        "the first CAS must reuse checkpoint closure proofs"
    );
    // The immutable borrow prevents a proof surviving metadata mutation.
    drop(complete);
    metadata.nodes.take(&map.root().unwrap()).unwrap();
    let mut changed = metadata.nodes.closure_checker();
    assert!(
        !state_metadata_closure_complete(cas_id, &metadata, &mut changed).unwrap(),
        "a new snapshot must observe the missing node",
    );
}

#[test]
fn incomplete_checkpoint_cannot_populate_closure_proofs() {
    let map = dense_representation_map();
    let root = map.root().unwrap();
    let (catalogue, placements) = shared_roots(&map);
    let identity = Blake3PhysicalIdentity;
    let state = RepresentationState::new(
        1,
        None,
        catalogue.identify(&identity),
        placements.identify(&identity),
    )
    .unwrap();
    let (mut metadata, state_id) = index_with_state(&map, catalogue, placements, state);
    for id in map.nodes().keys().filter(|id| **id != root) {
        metadata.nodes.take(id).unwrap();
    }
    let (checkpoint, current) = later_journal_checkpoint(state_id, 1);
    let mut complete = metadata.nodes.closure_checker();
    let error = recover_checkpoint(checkpoint, current, &metadata, &mut complete).unwrap_err();
    assert!(matches!(
        error,
        DurableError::InvalidRepresentationState(
            "representation checkpoint has an incomplete metadata closure",
        )
    ));
    assert!(
        complete.len() == 0,
        "failed checkpoint must not retain partial map proofs"
    );
}

#[test]
fn metadata_recovery_keeps_only_links_and_loads_active_bodies() {
    let node = PhysicalMapNode::leaf(
        PhysicalMapDomain::Representation,
        PhysicalMapKey::new([7; 32]),
        vec![42; 4096],
    );
    let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, &node).unwrap();
    let mut file = tempfile::tempfile().unwrap();
    for _ in 0..2 {
        super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    }
    let limits = RecoveryLimits::process_addressable();
    let mut index = recover_metadata(&mut file, limits).unwrap();
    assert_eq!(index.nodes.len(), 1);
    assert_eq!(index.nodes.edge_count(), 0);
    let map = index
        .recover_active_map(
            PhysicalMapDomain::Representation,
            Some(map_node_id(frame.identity)),
            &file,
            limits,
        )
        .unwrap();
    assert_eq!(map.nodes()[&map_node_id(frame.identity)], node);
    assert!(index.nodes.len() == 0);
    assert!(
        index.values.is_empty(),
        "historical node bodies must not be retained as encoded payloads"
    );
}

#[test]
fn metadata_recovery_rejects_map_bytes_with_another_nodes_identity() {
    let node = PhysicalMapNode::leaf(
        PhysicalMapDomain::Representation,
        PhysicalMapKey::new([7; 32]),
        vec![42; 4096],
    );
    let mut frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, &node).unwrap();
    frame.identity[0] ^= 1;
    let mut index = MetadataIndex::default();
    assert!(index.insert(frame).is_err());
    assert!(index.nodes.len() == 0);
    assert!(index.values.is_empty());
}

use super::super::{ArenaLocation, RepresentationStore};
use crate::storage_model::{
    BlobId, PlacementEntry, Replica, ReplicaLocator, RepresentationProfileId,
    RepresentationRecordId, StorageNodeId,
};
use crate::volume::{AstridVolume, HostedFileVolume};
use std::sync::Arc;

fn location(offset: u64, marker: u8) -> ArenaLocation {
    ArenaLocation {
        offset,
        payload_len: 8,
        checksum: [marker; 32],
    }
}

fn arena_replica(offset: u64, marker: u8) -> Replica {
    Replica::new(
        StorageNodeId::new(0),
        ReplicaLocator::ArenaFrame {
            arena_generation: 0,
            offset,
            payload_length: 8,
            frame_checksum: [marker; 32],
        },
    )
    .unwrap()
}

fn placement(
    blob: BlobId,
    profile: RepresentationProfileId,
    replicas: Vec<Replica>,
) -> PlacementEntry {
    PlacementEntry::new(blob, profile, 8, replicas).unwrap()
}

#[test]
fn generation_zero_handoff_keeps_first_record_and_object_order() {
    let identity = Blake3PhysicalIdentity;
    let (profile, profile_id) =
        super::super::activation::direct_profile(ObjectId::new([7; 32])).unwrap();
    let profiles = CanonicalPhysicalMap::build_dense(
        &identity,
        PhysicalMapDomain::Profile,
        vec![(PhysicalMapKey::from(profile_id), profile.encode().unwrap())],
    )
    .unwrap();
    let mut records = Vec::new();
    let mut placements = Vec::new();
    let mut expected = BTreeMap::new();
    // Two records for object 1 have different blobs and replica locations.
    // Input order differs from both object and authenticated record-id order.
    for (object_byte, blob_byte) in [(2, 3), (1, 2), (1, 1)] {
        let object = ObjectId::new([object_byte; 32]);
        let blob = BlobId::new([blob_byte; 32]);
        let record = RepresentationRecord::new(
            profile_id,
            Coverage::exact(object, 8).unwrap(),
            Recipe::DirectCanonical { blob },
            8,
            8,
            None,
        )
        .unwrap();
        let id = record.identify(&identity).unwrap();
        let first = location(u64::from(blob_byte) * 10, blob_byte);
        let second = location(u64::from(blob_byte) * 10 + 1, blob_byte);
        let placement = placement(
            blob,
            profile_id,
            vec![
                arena_replica(first.offset, blob_byte),
                arena_replica(second.offset, blob_byte),
            ],
        );
        records.push((PhysicalMapKey::from(id), record.encode().unwrap()));
        placements.push((PhysicalMapKey::from(blob), placement.encode().unwrap()));
        let candidate = (id, [first, second]);
        expected
            .entry(object)
            .and_modify(
                |current: &mut (RepresentationRecordId, [ArenaLocation; 2])| {
                    if id < current.0 {
                        *current = candidate;
                    }
                },
            )
            .or_insert(candidate);
    }
    let records =
        CanonicalPhysicalMap::build_dense(&identity, PhysicalMapDomain::Representation, records)
            .unwrap();
    let placements =
        CanonicalPhysicalMap::build_dense(&identity, PhysicalMapDomain::Placement, placements)
            .unwrap();
    let ValidatedRepresentations {
        reverse,
        extent_count,
        locations: actual,
    } = validate_representations(&profiles, &records, &placements, profile_id).unwrap();
    assert_eq!(extent_count, 6);
    assert_eq!(reverse[&ObjectId::new([1; 32])].len(), 2);
    let expected: Vec<_> = expected
        .into_iter()
        .flat_map(|(object, (_, replicas))| {
            replicas.into_iter().map(move |replica| (object, replica))
        })
        .collect();
    assert_eq!(actual.as_slice(), expected.as_slice());
    assert!(
        actual
            .as_slice()
            .windows(2)
            .all(|pair| pair[0].0 <= pair[1].0)
    );
    assert!(matches!(
        validate_representations(
            &profiles,
            &records,
            &placements,
            RepresentationProfileId::new([255; 32])
        ),
        Err(DurableError::InvalidRepresentationState(
            "reverse index has no direct representation"
        ))
    ));
}

#[test]
fn generation_zero_handoff_rejects_missing_direct_profile() {
    let object = ObjectId::new([1; 32]);
    let reverse = BTreeMap::from([(object, vec![RepresentationRecordId::new([1; 32])])]);
    let error = super::generation_zero_locations_from_selected(
        &reverse,
        &BTreeMap::new(),
        &BTreeMap::new(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        DurableError::InvalidRepresentationState("reverse index has no direct representation")
    ));
}

#[test]
fn generation_zero_handoff_matches_independent_direct_arena_locations() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("handoff.volume")).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([7; 32]), []).unwrap();
    let mut index = BTreeMap::new();
    for (ordinal, object_byte) in [3_u8, 1, 4, 2].into_iter().enumerate() {
        let object = ObjectId::new([object_byte; 32]);
        let bytes = [object_byte; 8];
        let loc = location(u64::try_from(ordinal).unwrap() * 100 + 52, object_byte);
        let direct = store.describe_direct(object, &bytes, loc).unwrap();
        let update = store.append_direct_update(&[direct]).unwrap().unwrap();
        store.publish_direct_update(update).unwrap();
        index.insert(object, loc);
    }
    drop(store);
    let (reopened, locations) = RepresentationStore::open_volume_recovered(&volume, limits)
        .unwrap()
        .unwrap();
    let independent = reopened.direct_arena_locations().unwrap();
    assert_eq!(locations.as_slice(), independent.as_slice());
    assert_eq!(
        locations
            .as_slice()
            .iter()
            .map(|(object, _)| *object)
            .collect::<Vec<_>>(),
        [1, 2, 3, 4].map(|byte| ObjectId::new([byte; 32]))
    );
    locations.validate_index(&index).unwrap();
}

#[test]
fn validate_generation_zero_index_rejects_corrupt_and_missing_locations() {
    let object = ObjectId::new([1; 32]);
    let replica = location(10, 1);
    let extra = location(20, 2);
    let locations = [(object, replica), (object, extra)];
    let mut index = BTreeMap::from([(object, extra)]);
    GenerationZeroLocations::new(locations.to_vec())
        .validate_index(&index)
        .unwrap();
    index.insert(object, location(99, 9));
    assert!(matches!(
        GenerationZeroLocations::new(locations.to_vec()).validate_index(&index),
        Err(DurableError::InvalidRepresentationState(
            "generation-zero placement disagrees with the arena index"
        ))
    ));
    assert!(matches!(
        GenerationZeroLocations::new(locations.to_vec()).validate_index(&BTreeMap::new()),
        Err(DurableError::InvalidRepresentationState(
            "direct representation names a missing logical object"
        ))
    ));
}

#[test]
fn metadata_recovery_loads_root_before_child_history_without_retaining_old_values() {
    let map = dense_representation_map();
    let root = map.root().unwrap();
    let mut file = tempfile::tempfile().unwrap();
    let mut order = vec![root];
    order.extend(map.nodes().keys().copied().filter(|id| *id != root));
    for id in order {
        let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, &map.nodes()[&id]).unwrap();
        super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    }
    // These unreachable historical bodies remain on disk and are authenticated,
    // but have no reason to occupy decoded buffers during journal recovery.
    for marker in 0_u8..64 {
        let node = PhysicalMapNode::leaf(
            PhysicalMapDomain::Representation,
            PhysicalMapKey::new([marker; 32]),
            vec![marker; 65536],
        );
        let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, &node).unwrap();
        super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    }
    let before = file.metadata().unwrap().len();
    let limits = RecoveryLimits::process_addressable();
    let mut index = recover_metadata(&mut file, limits).unwrap();
    assert_eq!(index.nodes.len(), map.nodes().len().strict_add(64));
    assert!(index.nodes.edge_count() < index.nodes.len());
    let mut complete = index.nodes.closure_checker();
    assert!(complete.complete(Some(root)));
    drop(complete);
    let recovered = index
        .recover_active_map(PhysicalMapDomain::Representation, Some(root), &file, limits)
        .unwrap();
    assert_eq!(recovered.nodes(), map.nodes());
    assert_eq!(index.nodes.len(), 64);
    assert!(
        index.values.is_empty(),
        "historical values remain on disk only"
    );
    assert_eq!(
        file.metadata().unwrap().len(),
        before,
        "recovery must not delete historical metadata"
    );
}

#[test]
fn metadata_duplicate_identity_requires_exact_body_equality() {
    let node = PhysicalMapNode::leaf(
        PhysicalMapDomain::Representation,
        PhysicalMapKey::new([7; 32]),
        vec![42; 4096],
    );
    let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, &node).unwrap();
    let mut index = MetadataIndex::default();
    index.insert(frame.clone()).unwrap();
    let mut different = frame.clone();
    different.value = PhysicalMapNode::leaf(
        PhysicalMapDomain::Representation,
        PhysicalMapKey::new([7; 32]),
        vec![43; 4096],
    )
    .encode()
    .unwrap();
    // Deliberately supply an earlier body with the same identity envelope:
    // checking the envelope alone would wrongly accept this duplicate.
    let result = index.insert_at(52, frame, |_| different.encode());
    assert!(matches!(
        result,
        Err(DurableError::InvalidRepresentationState(
            "physical metadata identity collision"
        ))
    ));
    assert_eq!(index.nodes.len(), 1);
}

#[test]
fn active_map_body_rereads_validate_the_frame_again() {
    use std::io::{Seek, Write};

    let node = PhysicalMapNode::leaf(
        PhysicalMapDomain::Representation,
        PhysicalMapKey::new([7; 32]),
        vec![42; 4096],
    );
    let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, &node).unwrap();
    let mut file = tempfile::tempfile().unwrap();
    let location =
        super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut index = recover_metadata(&mut file, limits).unwrap();
    file.seek(SeekFrom::Start(
        location.offset.strict_add(FRAME_HEADER_LEN),
    ))
    .unwrap();
    file.write_all(&[0xff]).unwrap();
    assert!(
        index
            .recover_active_map(
                PhysicalMapDomain::Representation,
                Some(map_node_id(frame.identity)),
                &file,
                limits,
            )
            .is_err(),
        "active bodies must pass full frame validation when loaded"
    );
}

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
    let partial = BTreeMap::from([(root, map.nodes()[&root].clone())]);
    let mut complete = BTreeSet::new();
    assert!(!map_closure_complete(Some(root), &partial, &mut complete));
    assert!(complete.is_empty());
    assert!(!map_closure_complete(Some(root), &partial, &mut complete));
    assert!(map_closure_complete(Some(root), map.nodes(), &mut complete));
    assert_eq!(complete.len(), map.nodes().len());
    let verified = complete.clone();
    assert!(map_closure_complete(Some(root), map.nodes(), &mut complete));
    assert_eq!(complete, verified);
    let absent = PhysicalMapKey::new([255; 32]);
    let other = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![(absent, vec![0])],
    )
    .unwrap();
    assert!(!map_closure_complete(
        other.root(),
        map.nodes(),
        &mut complete
    ));
    assert_eq!(complete, verified);
}

#[test]
fn metadata_recovery_keeps_one_owned_copy_of_each_map_node() {
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
    let index = recover_metadata(&mut file, RecoveryLimits::process_addressable()).unwrap();
    assert_eq!(index.nodes.len(), 1);
    assert_eq!(index.nodes[&map_node_id(frame.identity)], node);
    assert!(
        index.values.is_empty(),
        "decoded nodes must not retain a second encoded payload"
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
    assert!(index.nodes.is_empty());
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

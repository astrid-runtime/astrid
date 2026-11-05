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

#[test]
#[cfg(not(target_family = "wasm"))]
fn placement_validation_retains_only_the_join_fields_after_each_decode() {
    use super::super::{LOCAL_STORAGE_NODE, activation};
    use crate::storage_model::{BlobId, Replica, ReplicaLocator};

    const PLACEMENTS: u8 = 64;
    const REPLICAS: u64 = 256;
    let (profile, profile_id) = activation::direct_profile(ObjectId::new([9; 32])).unwrap();
    let profiles = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        vec![(PhysicalMapKey::from(profile_id), profile.encode().unwrap())],
    )
    .unwrap();
    let entries = (0..PLACEMENTS)
        .map(|ordinal| {
            let blob =
                BlobId::identify(&Blake3PhysicalIdentity, profile_id, &[ordinal; 8]).unwrap();
            let replicas = (0..REPLICAS)
                .map(|offset| {
                    Replica::new(
                        LOCAL_STORAGE_NODE,
                        ReplicaLocator::ArenaFrame {
                            arena_generation: 0,
                            offset,
                            payload_length: 8,
                            frame_checksum: [ordinal; 32],
                        },
                    )
                    .unwrap()
                })
                .collect();
            let placement = PlacementEntry::new(blob, profile_id, 8, replicas).unwrap();
            (PhysicalMapKey::from(blob), placement.encode().unwrap())
        })
        .collect();
    let placements = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        entries,
    )
    .unwrap();
    let representations = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        Vec::new(),
    )
    .unwrap();
    // Keep all authenticated inputs alive outside accounting. Invoke the real
    // validator: every replica must be decoded and counted, but its backing
    // array has no consumer after the placement-to-record join is recorded.
    let (result, peak) = crate::allocation_test_support::peak_during(|| {
        validate_representations(&profiles, &representations, &placements)
    });
    let (reverse, extent_count) = result.unwrap();
    assert!(reverse.is_empty());
    assert_eq!(extent_count, u64::from(PLACEMENTS) * REPLICAS);
    let replica_backing = usize::from(PLACEMENTS)
        * usize::try_from(REPLICAS).unwrap()
        * std::mem::size_of::<Replica>();
    assert!(
        peak < replica_backing / 4,
        "placement validation retained {peak} temporary bytes for {replica_backing} replica bytes"
    );
}

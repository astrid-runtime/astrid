use super::*;
use crate::engine::durable::representations::activation::CompleteNodes;

fn map(value: u8) -> CanonicalPhysicalMap {
    CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        (0_u16..256)
            .map(|ordinal| {
                let key = blake3::hash(&ordinal.to_le_bytes());
                (PhysicalMapKey::new(*key.as_bytes()), vec![value; 16])
            })
            .collect(),
    )
    .unwrap()
}

fn append_nodes(file: &File, nodes: impl Iterator<Item = PhysicalMapNode>) {
    for node in nodes {
        let payload = MetadataFrame::map_node(&Blake3PhysicalIdentity, &node)
            .unwrap()
            .encode()
            .unwrap();
        append_frame(&mut file.try_clone().unwrap(), METADATA_MAGIC, &payload).unwrap();
    }
}

#[test]
fn recovery_proves_only_complete_active_nodes_and_keeps_last_duplicate_frames() {
    let active = map(1);
    let historical = map(2);
    let file = File::native(tempfile::tempfile().unwrap());
    append_nodes(&file, historical.nodes().values().cloned());
    append_nodes(&file, active.nodes().values().cloned());
    append_nodes(&file, active.nodes().values().cloned());
    let budget = LocationIndexMemoryBudget::new(std::num::NonZeroU64::new(352).unwrap()).unwrap();
    let nodes = ColdNodes::from_validated_maps(
        &file,
        RecoveryLimits::process_addressable(),
        budget,
        &[&active],
    )
    .unwrap();
    assert_eq!(nodes.len(), active.nodes().len() + historical.nodes().len());
    for (id, node) in active.nodes() {
        assert!(nodes.complete(id).unwrap());
        assert_eq!(nodes.node(*id).unwrap().unwrap().as_ref(), node);
    }
    for id in historical.nodes().keys() {
        assert!(!nodes.complete(id).unwrap());
    }
    let root = active.root().unwrap();
    let mut metadata = Vec::new();
    let mut appended = std::collections::BTreeSet::new();
    assert_eq!(
        super::super::super::activation::append_new_reachable_map_nodes(
            &mut metadata,
            &active,
            &nodes,
            &mut appended,
            &mut nodes.clone(),
        )
        .unwrap(),
        0,
    );
    nodes.0.lock().locations.truncate_test_run();
    assert!(
        super::super::super::activation::append_new_reachable_map_nodes(
            &mut metadata,
            &active,
            &nodes,
            &mut appended,
            &mut nodes.clone(),
        )
        .is_err(),
        "a new traversal must authenticate the proof again",
    );
    assert!(nodes.complete(&root).is_err());
    assert!(
        nodes.failed(),
        "proof lookup must still fence damaged scratch"
    );
}

#[test]
fn duplicate_active_frames_cannot_hide_a_missing_validated_node() {
    let active = map(1);
    let file = File::native(tempfile::tempfile().unwrap());
    let omitted = *active.nodes().keys().next().unwrap();
    for _ in 0..2 {
        append_nodes(
            &file,
            active
                .nodes()
                .iter()
                .filter(|(id, _)| **id != omitted)
                .map(|(_, node)| node.clone()),
        );
    }
    assert!(
        ColdNodes::from_validated_maps(
            &file,
            RecoveryLimits::process_addressable(),
            LocationIndexMemoryBudget::default(),
            &[&active]
        )
        .is_err()
    );
}

#[test]
fn first_post_recovery_path_copy_does_not_expand_unchanged_complete_subtrees() {
    use crate::engine::durable::representations::activation::append_new_reachable_map_nodes;
    let active = map(1);
    let file = File::native(tempfile::tempfile().unwrap());
    append_nodes(&file, active.nodes().values().cloned());
    let nodes = ColdNodes::from_validated_maps(
        &file,
        RecoveryLimits::process_addressable(),
        LocationIndexMemoryBudget::default(),
        &[&active],
    )
    .unwrap();
    let original_count = active.nodes().len();
    let mut backed = active.with_node_provider(nodes.clone());
    backed
        .insert(
            &Blake3PhysicalIdentity,
            PhysicalMapKey::new([0xff; 32]),
            vec![3; 16],
        )
        .unwrap();
    let mut metadata = Vec::new();
    let mut appended = std::collections::BTreeSet::new();
    let visited = append_new_reachable_map_nodes(
        &mut metadata,
        &backed,
        &nodes,
        &mut appended,
        &mut nodes.clone(),
    )
    .unwrap();
    assert!(
        visited > 0 && visited < original_count,
        "only the new path must be expanded"
    );
    assert_eq!(metadata.len(), visited);
    assert_eq!(appended.len(), visited);
}

#[test]
fn canonical_proof_handoff_reads_one_source_pass_and_discards_historical_proofs() {
    use crate::engine::durable::locations::test_take_page_auth_count;
    let active = map(1);
    let historical = map(2);
    let file = File::native(tempfile::tempfile().unwrap());
    let mut locations = std::collections::BTreeMap::new();
    for node in active.nodes().values().chain(historical.nodes().values()) {
        let payload = MetadataFrame::map_node(&Blake3PhysicalIdentity, node)
            .unwrap()
            .encode()
            .unwrap();
        let location =
            append_frame(&mut file.try_clone().unwrap(), METADATA_MAGIC, &payload).unwrap();
        locations.insert(
            ObjectId::new(*node.identify(&Blake3PhysicalIdentity).unwrap().as_bytes()),
            location,
        );
    }
    let all_proven = locations.keys().copied().collect();
    let source = PagedLocations::from_map_with_proofs(
        locations,
        &all_proven,
        std::num::NonZeroUsize::new(8).unwrap(),
    )
    .unwrap();
    test_take_page_auth_count();
    let count = source
        .locations()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .len();
    let one_pass = test_take_page_auth_count();
    assert!(one_pass > 0);
    let budget = LocationIndexMemoryBudget::new(std::num::NonZeroU64::new(352).unwrap()).unwrap();
    let nodes = ColdNodes::from_recovered_locations(
        file,
        source,
        RecoveryLimits::process_addressable(),
        budget,
        &[&active],
    )
    .unwrap();
    assert_eq!(
        test_take_page_auth_count(),
        one_pass,
        "canonical proof handoff must not re-sort ordered input"
    );
    assert_eq!(nodes.len(), count);
    for id in active.nodes().keys() {
        assert!(nodes.complete(id).unwrap());
    }
    for id in historical.nodes().keys() {
        assert!(
            !nodes.complete(id).unwrap(),
            "historical source proofs cannot confer canonical membership"
        );
    }
}

#[test]
fn canonical_proof_handoff_authenticates_source_again_before_publication() {
    let map = (0_u64..127)
        .map(|index| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&index.to_be_bytes());
            (
                ObjectId::new(bytes),
                ArenaLocation {
                    offset: index,
                    payload_len: 48,
                    checksum: [5; 32],
                },
            )
        })
        .collect();
    let source = PagedLocations::from_map(map, std::num::NonZeroUsize::new(8).unwrap()).unwrap();
    source.truncate_test_run_without_epoch();
    assert!(
        ColdNodes::from_recovered_locations(
            File::native(tempfile::tempfile().unwrap()),
            source,
            RecoveryLimits::process_addressable(),
            LocationIndexMemoryBudget::default(),
            &[],
        )
        .is_err()
    );
}

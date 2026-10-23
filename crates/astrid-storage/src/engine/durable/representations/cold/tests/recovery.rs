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

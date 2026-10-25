use super::*;
use crate::storage_model::{PhysicalMapDomain, PhysicalMapKey};
use crate::volume::{AstridVolume, HostedFileVolume};

fn leaf() -> PhysicalMapNode {
    PhysicalMapNode::leaf(
        PhysicalMapDomain::Representation,
        PhysicalMapKey::new([9; 32]),
        vec![3; 32],
    )
}

fn exercise(file: &File) {
    let limits = RecoveryLimits::new(4096).unwrap();
    let mut nodes =
        ColdNodes::from_metadata(file, limits, LocationIndexMemoryBudget::default()).unwrap();
    let node = leaf();
    let id = node.identify(&Blake3PhysicalIdentity).unwrap();
    assert!(nodes.node(id).unwrap().is_none());
    nodes.put(id, node.clone()).unwrap();
    assert_eq!(
        file.metadata().unwrap().len(),
        0,
        "path copies remain private until promotion"
    );
    let payload = MetadataFrame::map_node(&Blake3PhysicalIdentity, &node)
        .unwrap()
        .encode()
        .unwrap();
    let mut writer = file.try_clone().unwrap();
    let location = append_frame(&mut writer, METADATA_MAGIC, &payload).unwrap();
    nodes.promote(id, location).unwrap();
    nodes.finish_staging();
    let after = file.metadata().unwrap().len();
    nodes.put(id, node.clone()).unwrap();
    assert_eq!(
        file.metadata().unwrap().len(),
        after,
        "immutable node is not duplicated"
    );
    assert_eq!(nodes.node(id).unwrap().unwrap().as_ref(), &node);
    assert_eq!(nodes.0.lock().limits, limits);
    drop(nodes);
    let nodes =
        ColdNodes::from_metadata(file, limits, LocationIndexMemoryBudget::default()).unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes.node(id).unwrap().unwrap().as_ref(), &node);
    let mut map = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![(PhysicalMapKey::new([9; 32]), vec![3; 32])],
    )
    .unwrap()
    .with_node_provider(nodes.clone());
    assert_eq!(
        map.try_get(&Blake3PhysicalIdentity, PhysicalMapKey::new([9; 32]))
            .unwrap(),
        Some(vec![3; 32])
    );
    file.set_len(after.strict_sub(1)).unwrap();
    assert!(
        map.try_get(&Blake3PhysicalIdentity, PhysicalMapKey::new([9; 32]))
            .is_err()
    );
    assert!(
        nodes.failed(),
        "reachable frame truncation must latch recovery"
    );
    assert!(
        map.insert(
            &Blake3PhysicalIdentity,
            PhysicalMapKey::new([8; 32]),
            vec![2]
        )
        .is_err()
    );
    assert_eq!(map.entry_count(), 1);
}

#[test]
fn native_frames_are_reused_and_reachable_truncation_is_never_absence() {
    exercise(&File::native(tempfile::tempfile().unwrap()));
}

#[test]
fn volume_frames_are_reused_and_reachable_truncation_is_never_absence() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("cold.volume")).unwrap();
    exercise(&File::volume(volume, "physical-nodes", true).unwrap());
}

#[test]
fn indexed_frame_substitution_is_rejected_even_with_a_valid_frame_checksum() {
    let file = File::native(tempfile::tempfile().unwrap());
    let mut nodes = ColdNodes::from_metadata(
        &file,
        RecoveryLimits::process_addressable(),
        LocationIndexMemoryBudget::default(),
    )
    .unwrap();
    let node = leaf();
    let id = node.identify(&Blake3PhysicalIdentity).unwrap();
    nodes.put(id, node.clone()).unwrap();
    let payload = MetadataFrame::map_node(&Blake3PhysicalIdentity, &node)
        .unwrap()
        .encode()
        .unwrap();
    let location = append_frame(&mut file.try_clone().unwrap(), METADATA_MAGIC, &payload).unwrap();
    nodes.promote(id, location).unwrap();
    nodes.finish_staging();
    let other = PhysicalMapNode::leaf(
        PhysicalMapDomain::Representation,
        PhysicalMapKey::new([9; 32]),
        vec![4; 32],
    );
    let payload = MetadataFrame::map_node(&Blake3PhysicalIdentity, &other)
        .unwrap()
        .encode()
        .unwrap();
    file.set_len(0).unwrap();
    let mut replacement = file.try_clone().unwrap();
    append_frame(&mut replacement, METADATA_MAGIC, &payload).unwrap();
    assert!(nodes.node(id).is_err());
    // The old root cannot accept either a different frame or a different node
    // identity, even though the replacement is independently well formed.
    let map = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![(PhysicalMapKey::new([9; 32]), vec![3; 32])],
    )
    .unwrap()
    .with_node_provider(nodes.clone());
    assert!(
        map.try_get(&Blake3PhysicalIdentity, PhysicalMapKey::new([9; 32]))
            .is_err()
    );
    assert!(nodes.failed());
}

#[test]
fn oversized_node_is_rejected_before_staging_and_a_valid_retry_reopens() {
    let small = leaf();
    let payload = MetadataFrame::map_node(&Blake3PhysicalIdentity, &small)
        .unwrap()
        .encode()
        .unwrap();
    let limits = RecoveryLimits::new(u64::try_from(payload.len()).unwrap()).unwrap();
    let file = File::native(tempfile::tempfile().unwrap());
    let mut nodes =
        ColdNodes::from_metadata(&file, limits, LocationIndexMemoryBudget::default()).unwrap();
    let large = PhysicalMapNode::leaf(
        PhysicalMapDomain::Representation,
        PhysicalMapKey::new([8; 32]),
        vec![4; 4096],
    );
    let large_id = large.identify(&Blake3PhysicalIdentity).unwrap();
    assert!(matches!(
        nodes.put(large_id, large),
        Err(DurableError::FrameTooLarge { .. })
    ));
    assert!(nodes.0.lock().staged.is_none());
    assert_eq!(nodes.len(), 0);
    assert!(!nodes.failed());
    assert_eq!(file.metadata().unwrap().len(), 0);
    let id = small.identify(&Blake3PhysicalIdentity).unwrap();
    nodes.put(id, small.clone()).unwrap();
    assert_eq!(file.metadata().unwrap().len(), 0);
    let location = append_frame(&mut file.try_clone().unwrap(), METADATA_MAGIC, &payload).unwrap();
    nodes.promote(id, location).unwrap();
    nodes.finish_staging();
    let reopened =
        ColdNodes::from_metadata(&file, limits, LocationIndexMemoryBudget::default()).unwrap();
    assert_eq!(reopened.len(), 1);
    assert_eq!(reopened.node(id).unwrap().unwrap().as_ref(), &small);
}

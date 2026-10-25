use super::super::format::Blake3PhysicalIdentity;
use super::*;
use crate::storage_model::{PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode, PhysicalMapNodes};
use std::io::{Read, Seek};

#[test]
fn streamed_batch_matches_existing_framing_and_relocates_every_node() {
    let mut batch = MetadataBatch::new(RecoveryLimits::new(4096).unwrap()).unwrap();
    let mut expected = DurableFile::native(tempfile::tempfile().unwrap());
    let mut frames = Vec::new();
    let mut node_ids = Vec::new();
    for byte in 0..64 {
        let node = PhysicalMapNode::leaf(
            PhysicalMapDomain::Representation,
            PhysicalMapKey::new([byte; 32]),
            vec![byte; 512],
        );
        let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, &node).unwrap();
        node_ids.push((node.identify(&Blake3PhysicalIdentity).unwrap(), node));
        batch.push(&frame).unwrap();
        frames.push(frame.encode().unwrap());
    }
    crate::engine::durable::append_frames(&mut expected, METADATA_MAGIC, &frames).unwrap();
    let mut destination = DurableFile::native(tempfile::tempfile().unwrap());
    // Preserve a prefix so successful locator lookup depends on relocation.
    append_frame(&mut destination, METADATA_MAGIC, &frames[0]).unwrap();
    let limits = RecoveryLimits::new(4096).unwrap();
    let nodes = ColdNodes::from_metadata(
        &destination,
        limits,
        crate::engine::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
    let base = batch.append_to(&mut destination).unwrap();
    assert!(base > 0);
    batch.promote_nodes(&nodes, base, limits).unwrap();
    for (id, node) in node_ids {
        assert_eq!(nodes.node(id).unwrap().unwrap().as_ref(), &node);
    }
    let mut expected_bytes = Vec::new();
    expected.rewind().unwrap();
    expected.read_to_end(&mut expected_bytes).unwrap();
    let mut actual = Vec::new();
    destination.seek(SeekFrom::Start(base)).unwrap();
    destination.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, expected_bytes);
}

#[test]
fn failed_destination_write_leaves_private_batch_retryable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("read-only");
    std::fs::write(&path, []).unwrap();
    let mut destination = DurableFile::native(std::fs::File::open(&path).unwrap());
    let mut batch = MetadataBatch::new(RecoveryLimits::new(4096).unwrap()).unwrap();
    let node = PhysicalMapNode::leaf(
        PhysicalMapDomain::Representation,
        PhysicalMapKey::new([1; 32]),
        vec![2],
    );
    batch
        .push(&MetadataFrame::map_node(&Blake3PhysicalIdentity, &node).unwrap())
        .unwrap();
    assert!(batch.append_to(&mut destination).is_err());
    let mut destination = DurableFile::native(tempfile::tempfile().unwrap());
    assert_eq!(batch.append_to(&mut destination).unwrap(), 0);
    assert!(destination.metadata().unwrap().len() > 0);
}

#[test]
fn oversized_frame_is_rejected_before_spooling_and_a_valid_retry_reopens() {
    let small = PhysicalMapNode::leaf(
        PhysicalMapDomain::Representation,
        PhysicalMapKey::new([1; 32]),
        vec![2],
    );
    let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, &small).unwrap();
    let limits =
        RecoveryLimits::new(u64::try_from(frame.encode().unwrap().len()).unwrap()).unwrap();
    let mut batch = MetadataBatch::new(limits).unwrap();
    let large = PhysicalMapNode::leaf(
        PhysicalMapDomain::Representation,
        PhysicalMapKey::new([3; 32]),
        vec![4; 4096],
    );
    assert!(matches!(
        batch.push(&MetadataFrame::map_node(&Blake3PhysicalIdentity, &large).unwrap()),
        Err(DurableError::FrameTooLarge { .. })
    ));
    assert_eq!(batch.spool.metadata().unwrap().len(), 0);
    batch.push(&frame).unwrap();
    let mut destination = DurableFile::native(tempfile::tempfile().unwrap());
    assert_eq!(destination.metadata().unwrap().len(), 0);
    batch.append_to(&mut destination).unwrap();
    let reopened = ColdNodes::from_metadata(
        &destination,
        limits,
        crate::engine::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
    assert_eq!(reopened.len(), 1);
    let id = small.identify(&Blake3PhysicalIdentity).unwrap();
    assert_eq!(reopened.node(id).unwrap().unwrap().as_ref(), &small);
}

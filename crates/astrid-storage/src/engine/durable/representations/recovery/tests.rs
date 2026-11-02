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

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
fn metadata_recovery_retains_each_map_node_only_once() {
    let map = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        (0_u32..32)
            .map(|ordinal| {
                (
                    PhysicalMapKey::new(*blake3::hash(&ordinal.to_le_bytes()).as_bytes()),
                    vec![u8::try_from(ordinal).unwrap(); 4096],
                )
            })
            .collect(),
    )
    .unwrap();
    let mut file = tempfile::tempfile().unwrap();
    for node in map.nodes().values() {
        let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, node).unwrap();
        for _ in 0..2 {
            super::super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap())
                .unwrap();
        }
    }
    let catalogue = RepresentationCatalogueRoot::new(1, None, 0, None, 0).unwrap();
    let frame = MetadataFrame::catalogue(&Blake3PhysicalIdentity, catalogue);
    super::super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    let index = recover_metadata(&mut file, RecoveryLimits::process_addressable()).unwrap();
    assert_eq!(&index.nodes, map.nodes());
    assert_eq!(index.values.len(), 1, "retain only non-node metadata bytes");
    assert_eq!(
        index
            .value(MetadataKind::Catalogue, &frame.identity)
            .unwrap(),
        frame.value
    );
    let recovered = CanonicalPhysicalMap::recover(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        map.root(),
        index.nodes,
    )
    .unwrap();
    assert_eq!(recovered.root(), map.root());
    assert_eq!(recovered.entry_count(), map.entry_count());
}

#[test]
fn metadata_node_rejection_preserves_verified_index() {
    let map = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        vec![(PhysicalMapKey::new([7; 32]), vec![42])],
    )
    .unwrap();
    let frame = MetadataFrame::map_node(
        &Blake3PhysicalIdentity,
        map.nodes().values().next().unwrap(),
    )
    .unwrap();
    let mut index = MetadataIndex::default();
    index.insert(frame.clone()).unwrap();
    let mut forged = frame.clone();
    forged.identity[0] ^= 1;
    assert!(index.insert(forged).is_err());
    let mut noncanonical = frame;
    noncanonical.value.push(0);
    assert!(index.insert(noncanonical).is_err());
    assert_eq!(&index.nodes, map.nodes());
    assert!(index.values.is_empty());
}

#[test]
fn metadata_recovery_rejects_a_forged_node_after_valid_frames() {
    let map = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        vec![(PhysicalMapKey::new([7; 32]), vec![42])],
    )
    .unwrap();
    let mut file = tempfile::tempfile().unwrap();
    let mut frame = MetadataFrame::map_node(
        &Blake3PhysicalIdentity,
        map.nodes().values().next().unwrap(),
    )
    .unwrap();
    super::super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    frame.identity[0] ^= 1;
    super::super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    assert!(matches!(
        recover_metadata(&mut file, RecoveryLimits::process_addressable()),
        Err(DurableError::InvalidRepresentationState(
            "metadata identity does not match canonical value"
        ))
    ));
}

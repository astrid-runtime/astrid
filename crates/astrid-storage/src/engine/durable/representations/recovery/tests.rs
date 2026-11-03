use super::*;
use crate::storage_model::{PhysicalMapDomain, PhysicalMapKey, RepresentationProfileId};

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
fn alternate_recipe_coverage_of_excluded_bootstrap_is_rejected() {
    let excluded_object = ObjectId::new([0xB0; 32]);
    let excluded = BTreeSet::from([excluded_object]);
    let evidence = ObjectId::new([0xE1; 32]);
    let profile = RepresentationProfileId::new([0xA1; 32]);
    let recipes = [
        Recipe::PackedSlice {
            blob: crate::storage_model::BlobId::new([0x51; 32]),
            offset: 0,
            length: 64,
        },
        Recipe::Compressed {
            blob: crate::storage_model::BlobId::new([0x52; 32]),
            dictionary: None,
        },
        Recipe::Delta {
            patch: crate::storage_model::BlobId::new([0x53; 32]),
            base: ObjectId::new([0x54; 32]),
        },
    ];
    for recipe in recipes {
        let record = RepresentationRecord::new(
            profile,
            Coverage::exact(excluded_object, 64).unwrap(),
            recipe,
            64,
            64,
            Some(evidence),
        )
        .unwrap();
        let record_id = record.identify(&Blake3PhysicalIdentity).unwrap();
        let representations = CanonicalPhysicalMap::build(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Representation,
            vec![(PhysicalMapKey::from(record_id), record.encode().unwrap())],
        )
        .unwrap();
        // Old reverse-only lookup misses non-DirectCanonical coverage.
        let reverse = BTreeMap::<ObjectId, Vec<RepresentationRecordId>>::new();
        assert!(
            !reverse.contains_key(&excluded_object),
            "causal proof: reverse index has no DirectCanonical hit"
        );
        let error = ensure_no_excluded_object_coverage(&representations, &reverse, &excluded)
            .expect_err("alternate recipe must count as relocatable bootstrap coverage");
        assert!(matches!(
            error,
            DurableError::InvalidRepresentationState(
                "bootstrap object has a relocatable representation"
            )
        ));
    }
}

#[test]
fn excluded_bootstrap_coverage_check_fails_closed_on_decode_errors() {
    let excluded = BTreeSet::from([ObjectId::new([0xB0; 32])]);
    let representations = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![(PhysicalMapKey::new([0xDE; 32]), vec![0xFF, 0x00, 0x01])],
    )
    .unwrap();
    let reverse = BTreeMap::<ObjectId, Vec<RepresentationRecordId>>::new();
    assert!(ensure_no_excluded_object_coverage(&representations, &reverse, &excluded).is_err());
}

#[test]
fn reverse_direct_hit_still_rejects_excluded_bootstrap_without_map_scan_need() {
    let excluded_object = ObjectId::new([0xB0; 32]);
    let excluded = BTreeSet::from([excluded_object]);
    let representations = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        Vec::new(),
    )
    .unwrap();
    let reverse = BTreeMap::from([(
        excluded_object,
        vec![RepresentationRecordId::new([0xC1; 32])],
    )]);
    let error = ensure_no_excluded_object_coverage(&representations, &reverse, &excluded)
        .expect_err("DirectCanonical reverse hit must reject");
    assert!(matches!(
        error,
        DurableError::InvalidRepresentationState(
            "bootstrap object has a relocatable representation"
        )
    ));
}

fn direct_canonical_record(object: ObjectId, blob_byte: u8) -> (RepresentationRecordId, Vec<u8>) {
    let profile = RepresentationProfileId::new([0xA1; 32]);
    let evidence = ObjectId::new([0xE1; 32]);
    let record = RepresentationRecord::new(
        profile,
        Coverage::exact(object, 64).unwrap(),
        Recipe::DirectCanonical {
            blob: crate::storage_model::BlobId::new([blob_byte; 32]),
        },
        64,
        64,
        Some(evidence),
    )
    .unwrap();
    let record_id = record.identify(&Blake3PhysicalIdentity).unwrap();
    (record_id, record.encode().unwrap())
}

#[test]
fn all_direct_disjoint_excluded_skips_fallback_map_visit() {
    let kept = ObjectId::new([0x10; 32]);
    let excluded_object = ObjectId::new([0xB0; 32]);
    let excluded = BTreeSet::from([excluded_object]);
    let (record_id, encoded) = direct_canonical_record(kept, 0x61);
    let representations = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![(PhysicalMapKey::from(record_id), encoded)],
    )
    .unwrap();
    let reverse = BTreeMap::from([(kept, vec![record_id])]);
    assert_eq!(
        u64::try_from(reverse.len()).unwrap(),
        representations.entry_count(),
        "all-direct distinct reverse keys must equal leaf count"
    );
    let visited = ensure_no_excluded_object_coverage_scanned(&representations, &reverse, &excluded)
        .expect("disjoint excluded bootstrap must be clean when every record is direct");
    assert_eq!(
        visited, 0,
        "O(1) all-direct proof must not decode map leaves"
    );
}

#[test]
fn mixed_alternate_coverage_forces_fallback_visit_and_rejects_excluded() {
    let kept = ObjectId::new([0x10; 32]);
    let excluded_object = ObjectId::new([0xB0; 32]);
    let excluded = BTreeSet::from([excluded_object]);
    let (direct_id, direct_encoded) = direct_canonical_record(kept, 0x61);
    let packed = RepresentationRecord::new(
        RepresentationProfileId::new([0xA1; 32]),
        Coverage::exact(excluded_object, 64).unwrap(),
        Recipe::PackedSlice {
            blob: crate::storage_model::BlobId::new([0x51; 32]),
            offset: 0,
            length: 64,
        },
        64,
        64,
        Some(ObjectId::new([0xE1; 32])),
    )
    .unwrap();
    let packed_id = packed.identify(&Blake3PhysicalIdentity).unwrap();
    let representations = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![
            (PhysicalMapKey::from(direct_id), direct_encoded),
            (PhysicalMapKey::from(packed_id), packed.encode().unwrap()),
        ],
    )
    .unwrap();
    // validate_representations indexes only the DirectCanonical record into reverse.
    let reverse = BTreeMap::from([(kept, vec![direct_id])]);
    assert!(
        !reverse.contains_key(&excluded_object),
        "packed coverage must not appear in reverse"
    );
    assert_ne!(
        u64::try_from(reverse.len()).unwrap(),
        representations.entry_count(),
        "mixed recipes must miss the all-direct fast proof"
    );
    let error = ensure_no_excluded_object_coverage_scanned(&representations, &reverse, &excluded)
        .expect_err("packed Exact coverage of excluded bootstrap must fail closed");
    // Error path still proves fallback ran: fast proof was impossible above.
    assert!(matches!(
        error,
        DurableError::InvalidRepresentationState(
            "bootstrap object has a relocatable representation"
        )
    ));
}

#[test]
fn mixed_benign_alternate_still_visits_when_fast_proof_misses() {
    let kept = ObjectId::new([0x10; 32]);
    let other = ObjectId::new([0x20; 32]);
    let excluded_object = ObjectId::new([0xB0; 32]);
    let excluded = BTreeSet::from([excluded_object]);
    let (direct_id, direct_encoded) = direct_canonical_record(kept, 0x61);
    let packed = RepresentationRecord::new(
        RepresentationProfileId::new([0xA1; 32]),
        Coverage::exact(other, 64).unwrap(),
        Recipe::Compressed {
            blob: crate::storage_model::BlobId::new([0x52; 32]),
            dictionary: None,
        },
        64,
        64,
        Some(ObjectId::new([0xE1; 32])),
    )
    .unwrap();
    let packed_id = packed.identify(&Blake3PhysicalIdentity).unwrap();
    let representations = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![
            (PhysicalMapKey::from(direct_id), direct_encoded),
            (PhysicalMapKey::from(packed_id), packed.encode().unwrap()),
        ],
    )
    .unwrap();
    let reverse = BTreeMap::from([(kept, vec![direct_id])]);
    let visited = ensure_no_excluded_object_coverage_scanned(&representations, &reverse, &excluded)
        .expect("excluded object absent from all Exact coverage must pass");
    assert_eq!(
        visited,
        representations.entry_count(),
        "fallback must stream every active leaf when alternate recipes exist"
    );
}

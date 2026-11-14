use super::*;
use crate::storage_model::physical::{PlacementMap, ProfileMap, RepresentationMap};
use crate::storage_model::{PhysicalMapDomain, PhysicalMapKey, RepresentationProfileId};
use std::collections::BTreeMap;

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
    let root = Some(map_node_id(frame.identity));
    let map = RepresentationMap::recover_exact(
        root,
        index
            .recover_active_nodes(PhysicalMapDomain::Representation, root, &file, limits)
            .unwrap(),
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
    let recovered = RepresentationMap::recover_exact(
        Some(root),
        index
            .recover_active_nodes(PhysicalMapDomain::Representation, Some(root), &file, limits)
            .unwrap(),
    )
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
    let result = index.insert_at(
        crate::engine::durable::format::FrameLocation::for_test(
            52,
            u64::try_from(frame.encode().unwrap().len()).unwrap(),
        ),
        frame,
        |_| different.encode(),
    );
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
            .recover_active_nodes(
                PhysicalMapDomain::Representation,
                Some(map_node_id(frame.identity)),
                &file,
                limits,
            )
            .is_err(),
        "active bodies must pass full frame validation when loaded"
    );
}

#[test]
fn indexed_active_recovery_validates_domain_and_consumes_each_node_once() {
    let node = PhysicalMapNode::Page {
        domain: PhysicalMapDomain::Profile,
        entries: vec![(PhysicalMapKey::new([8; 32]), vec![9])],
    };
    let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, &node).unwrap();
    let root = map_node_id(frame.identity);
    let mut file = tempfile::tempfile().unwrap();
    super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut index = recover_metadata(&mut file, limits).unwrap();
    let nodes = index
        .recover_active_nodes(PhysicalMapDomain::Placement, Some(root), &file, limits)
        .unwrap();
    assert!(
        PlacementMap::recover_exact(Some(root), nodes).is_err(),
        "authenticated node bytes must not authorize a different map domain"
    );
    let mut index = recover_metadata(&mut file, limits).unwrap();
    let recovered = ProfileMap::recover_exact(
        Some(root),
        index
            .recover_active_nodes(PhysicalMapDomain::Profile, Some(root), &file, limits)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(recovered.nodes(), &BTreeMap::from([(root, node)]));
    assert_eq!(index.nodes.len(), 0);
    assert!(matches!(
        index.recover_active_nodes(PhysicalMapDomain::Profile, Some(root), &file, limits),
        Err(DurableError::InvalidRepresentationState(
            "active physical map closure is incomplete"
        ))
    ));
}

#[test]
fn indexed_active_recovery_rejects_incomplete_and_forged_subtree_counts() {
    let leaf = PhysicalMapNode::leaf(
        PhysicalMapDomain::Representation,
        PhysicalMapKey::new([8; 32]),
        vec![9],
    );
    let other = PhysicalMapNode::leaf(
        PhysicalMapDomain::Representation,
        PhysicalMapKey::new([128; 32]),
        vec![10],
    );
    // Frames and identities are valid, but two leaves cannot justify a count of three.
    let branch = PhysicalMapNode::branch(
        PhysicalMapDomain::Representation,
        0,
        vec![],
        leaf.identify(&Blake3PhysicalIdentity).unwrap(),
        other.identify(&Blake3PhysicalIdentity).unwrap(),
        3,
    )
    .unwrap();
    let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, &branch).unwrap();
    let root = map_node_id(frame.identity);
    let mut file = tempfile::tempfile().unwrap();
    super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut index = recover_metadata(&mut file, limits).unwrap();
    assert!(matches!(
        index.recover_active_nodes(PhysicalMapDomain::Representation, Some(root), &file, limits),
        Err(DurableError::InvalidRepresentationState(
            "active physical map closure is incomplete"
        ))
    ));
    for node in [&leaf, &other] {
        let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, node).unwrap();
        super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    }
    let mut index = recover_metadata(&mut file, limits).unwrap();
    assert!(
        index
            .recover_active_nodes(PhysicalMapDomain::Representation, Some(root), &file, limits,)
            .and_then(|nodes| {
                RepresentationMap::recover_exact(Some(root), nodes).map_err(Into::into)
            })
            .is_err(),
        "indexed traversal must retain canonical shape validation"
    );
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

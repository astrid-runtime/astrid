//! Canonical map, catalogue, placement, and state tests.

extern crate std;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::{format, vec, vec::Vec};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

use crate::storage_model::{BlobId, ObjectId, StorageNodeId};

use super::Coverage;
use super::{
    CanonicalPhysicalMap, PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode,
    PhysicalMapNodeId, PhysicalModelError, PlacementEntry, PlacementSet, PlacementSetId,
    ProfileKind, Recipe, ReconstructionBounds, Replica, ReplicaLocator,
    RepresentationCatalogueRoot, RepresentationCatalogueRootId, RepresentationProfile,
    RepresentationProfileId, RepresentationRecord, RepresentationRecordId, RepresentationState,
    RepresentationStateId,
};

#[derive(Clone, Copy)]
struct Blake3PhysicalIdentity;

impl PhysicalIdentity for Blake3PhysicalIdentity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(material);
        *hasher.finalize().as_bytes()
    }
}

fn key(value: u8) -> PhysicalMapKey {
    PhysicalMapKey::new([value; 32])
}

fn object(value: u8) -> ObjectId {
    ObjectId::new([value; 32])
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().checked_mul(2).unwrap_or(bytes.len()));
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn fixture_profile(kind: ProfileKind) -> RepresentationProfile {
    RepresentationProfile::new_builtin(
        kind,
        ReconstructionBounds::new(
            8,
            32,
            8 * 1024 * 1024,
            16 * 1024 * 1024,
            1_000_000,
            32 * 1024 * 1024,
            5_000_000,
        )
        .unwrap(),
        object(1),
    )
    .unwrap()
}

struct LogicalFixture {
    profile_bytes: Vec<u8>,
    profile_id: RepresentationProfileId,
    second_profile_bytes: Vec<u8>,
    second_profile_id: RepresentationProfileId,
    encoded_blob: &'static [u8],
    blob_id: BlobId,
    record_bytes: Vec<u8>,
    record_id: RepresentationRecordId,
}

fn logical_fixture() -> LogicalFixture {
    let profile = fixture_profile(ProfileKind::DirectCanonical);
    let profile_bytes = profile.encode().unwrap();
    let profile_id = profile.identify(&Blake3PhysicalIdentity).unwrap();
    let second_profile = fixture_profile(ProfileKind::PackedCanonical);
    let second_profile_bytes = second_profile.encode().unwrap();
    let second_profile_id = second_profile.identify(&Blake3PhysicalIdentity).unwrap();
    let encoded_blob = b"Astrid physical representation vector".as_slice();
    let blob_id = BlobId::identify(&Blake3PhysicalIdentity, profile_id, encoded_blob).unwrap();
    let output_bytes = u64::try_from(encoded_blob.len()).unwrap();
    let record = RepresentationRecord::new(
        profile_id,
        Coverage::exact(object(2), output_bytes).unwrap(),
        Recipe::DirectCanonical { blob: blob_id },
        output_bytes,
        output_bytes,
        None,
    )
    .unwrap();
    let record_bytes = record.encode().unwrap();
    let record_id = record.identify(&Blake3PhysicalIdentity).unwrap();
    LogicalFixture {
        profile_bytes,
        profile_id,
        second_profile_bytes,
        second_profile_id,
        encoded_blob,
        blob_id,
        record_bytes,
        record_id,
    }
}

struct CatalogueFixture {
    logical: LogicalFixture,
    nodes: BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    catalogue: RepresentationCatalogueRoot,
    placement_set: PlacementSet,
    state: RepresentationState,
}

fn catalogue_components() -> CatalogueFixture {
    let logical = logical_fixture();
    let profiles = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        vec![
            (
                PhysicalMapKey::from(logical.profile_id),
                logical.profile_bytes.clone(),
            ),
            (
                PhysicalMapKey::from(logical.second_profile_id),
                logical.second_profile_bytes.clone(),
            ),
        ],
    )
    .unwrap();
    let representations = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![(
            PhysicalMapKey::from(logical.record_id),
            logical.record_bytes.clone(),
        )],
    )
    .unwrap();
    let catalogue = RepresentationCatalogueRoot::new(
        0,
        profiles.root(),
        profiles.entry_count(),
        representations.root(),
        representations.entry_count(),
    )
    .unwrap();
    let placement_entry = PlacementEntry::new(
        logical.blob_id,
        logical.profile_id,
        u64::try_from(logical.encoded_blob.len()).unwrap(),
        vec![replica(
            1,
            ReplicaLocator::ArenaFrame {
                arena_generation: 0,
                offset: 4096,
                payload_length: 128,
                frame_checksum: [0xa5; 32],
            },
        )],
    )
    .unwrap();
    let placements = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        vec![(
            PhysicalMapKey::from(logical.blob_id),
            placement_entry.encode().unwrap(),
        )],
    )
    .unwrap();
    let placement_set =
        PlacementSet::new(0, placements.root(), placements.entry_count(), 1).unwrap();
    let catalogue_id = catalogue.identify(&Blake3PhysicalIdentity);
    let placement_id = placement_set.identify(&Blake3PhysicalIdentity);
    let state = RepresentationState::new(1, None, catalogue_id, placement_id).unwrap();
    let mut nodes = BTreeMap::new();
    nodes.extend(
        profiles
            .nodes()
            .iter()
            .map(|(id, node)| (*id, node.clone())),
    );
    nodes.extend(
        representations
            .nodes()
            .iter()
            .map(|(id, node)| (*id, node.clone())),
    );
    nodes.extend(
        placements
            .nodes()
            .iter()
            .map(|(id, node)| (*id, node.clone())),
    );
    CatalogueFixture {
        logical,
        nodes,
        catalogue,
        placement_set,
        state,
    }
}

fn catalogue_fixture() -> String {
    let fixture = catalogue_components();
    let nodes_json = fixture
        .nodes
        .iter()
        .map(|(id, node)| {
            format!(
                "    {{\"id\": \"1:2:32:{}\", \"canonical_hex\": \"{}\"}}",
                to_hex(id.as_bytes()),
                to_hex(&node.encode().unwrap()),
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    format!(
        concat!(
            "{{\n",
            "  \"profile\": {{\"id\": \"1:2:32:{}\", \"canonical_hex\": \"{}\"}},\n",
            "  \"blob\": {{\"id\": \"1:2:32:{}\", \"profile\": \"1:2:32:{}\", \"encoded_hex\": \"{}\"}},\n",
            "  \"representation\": {{\"id\": \"1:2:32:{}\", \"canonical_hex\": \"{}\"}},\n",
            "  \"catalogue\": {{\n",
            "    \"nodes\": [\n{}\n    ],\n",
            "    \"root\": {{\"id\": \"1:2:32:{}\", \"canonical_hex\": \"{}\"}},\n",
            "    \"placement_set\": {{\"id\": \"1:2:32:{}\", \"canonical_hex\": \"{}\"}},\n",
            "    \"state\": {{\"id\": \"1:2:32:{}\", \"canonical_hex\": \"{}\"}}\n",
            "  }}\n",
            "}}\n",
        ),
        to_hex(fixture.logical.profile_id.as_bytes()),
        to_hex(&fixture.logical.profile_bytes),
        to_hex(fixture.logical.blob_id.as_bytes()),
        to_hex(fixture.logical.profile_id.as_bytes()),
        to_hex(fixture.logical.encoded_blob),
        to_hex(fixture.logical.record_id.as_bytes()),
        to_hex(&fixture.logical.record_bytes),
        nodes_json,
        to_hex(
            fixture
                .catalogue
                .identify(&Blake3PhysicalIdentity)
                .as_bytes()
        ),
        to_hex(&fixture.catalogue.encode()),
        to_hex(
            fixture
                .placement_set
                .identify(&Blake3PhysicalIdentity)
                .as_bytes()
        ),
        to_hex(&fixture.placement_set.encode()),
        to_hex(fixture.state.identify(&Blake3PhysicalIdentity).as_bytes()),
        to_hex(&fixture.state.encode()),
    )
}

fn run_catalogue_fixture(fixture: &str) -> Output {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(fixture.as_bytes()).unwrap();
    file.flush().unwrap();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    Command::new("python3")
        .arg(repository.join("scripts/runatal_v1_physical.py"))
        .arg(file.path())
        .output()
        .unwrap()
}

#[test]
fn independent_physical_validation_regressions_pass() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .arg(repository.join("scripts/test_runatal_v1_physical_validation.py"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "independent physical validation regressions failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn catalogue_golden_vector_is_shared_with_the_independent_reader() {
    let fixture = catalogue_fixture();
    assert_eq!(
        include_str!("../../../../../scripts/fixtures/runatal-physical-catalogue-v1.json"),
        fixture
    );
    let output = run_catalogue_fixture(&fixture);
    assert!(
        output.status.success(),
        "independent catalogue reader failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decoded = String::from_utf8(output.stdout).unwrap();
    assert!(decoded.contains("08f3cf267b17198c8d22c85927c948cf5bd47772aa459f00377462c2a160d87c"));
    assert!(decoded.contains("9a0457bfa5c4049cbe0bc4510747c52273219859058966cab6a8dbe17dabe400"));
    assert!(decoded.contains("11dda7568ef055e28b53faea4bda7c004f60603d65e91f72d1504fae42712f83"));
}

#[test]
fn independent_reader_rejects_catalogue_node_tampering() {
    let fixture = catalogue_fixture();
    let tampered = fixture.replacen(
        "0b08bde71e96bd583ff3022b4180bdbdf73bcf2b4ea95e661a87797eafb8c0e0",
        "0b08bde71e96bd583ff3022b4180bdbdf73bcf2b4ea95e661a87797eafb8c0e1",
        1,
    );
    assert_ne!(fixture, tampered);
    assert!(!run_catalogue_fixture(&tampered).status.success());
}

fn map_entries() -> Vec<(PhysicalMapKey, Vec<u8>)> {
    vec![(key(3), vec![30]), (key(1), vec![10]), (key(2), vec![20])]
}

#[test]
fn canonical_map_shape_is_independent_of_insertion_order() {
    let forward = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        map_entries(),
    )
    .unwrap();
    let reverse = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        map_entries().into_iter().rev().collect(),
    )
    .unwrap();
    assert_eq!(forward.root(), reverse.root());
    assert_eq!(forward.entry_count(), 3);
    assert_eq!(forward.get(key(2)), Some([20].as_slice()));
    assert_eq!(forward.get(key(9)), None);
    assert_eq!(
        CanonicalPhysicalMap::validate_root(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Profile,
            forward.root(),
            forward.nodes(),
        )
        .unwrap(),
        3
    );
}

#[test]
fn path_copy_insertion_matches_a_clean_rebuild_and_keeps_old_roots() {
    let mut map = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![(key(1), vec![10]), (key(3), vec![30])],
    )
    .unwrap();
    let old_root = map.root().unwrap();
    assert!(
        map.insert(&Blake3PhysicalIdentity, key(2), vec![20])
            .unwrap()
    );
    assert!(
        !map.insert(&Blake3PhysicalIdentity, key(2), vec![20])
            .unwrap()
    );
    assert!(map.nodes().contains_key(&old_root));
    assert_eq!(map.entry_count(), 3);
    let rebuilt = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![(key(1), vec![10]), (key(2), vec![20]), (key(3), vec![30])],
    )
    .unwrap();
    assert_eq!(map.root(), rebuilt.root());
    assert_eq!(
        CanonicalPhysicalMap::validate_root(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Representation,
            map.root(),
            map.nodes(),
        )
        .unwrap(),
        3
    );
    assert!(matches!(
        map.insert(&Blake3PhysicalIdentity, key(2), vec![99]),
        Err(PhysicalModelError::InvalidMap(
            "leaf key has unequal canonical bytes"
        ))
    ));
}

#[test]
fn bulk_rebuild_matches_sequential_insertion_and_keeps_old_roots() {
    let initial = vec![(key(1), vec![10]), (key(4), vec![40])];
    let additions = vec![(key(2), vec![20]), (key(3), vec![30]), (key(5), vec![50])];
    let mut bulk = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        initial.clone(),
    )
    .unwrap();
    let old_root = bulk.root().unwrap();
    let mut sequential = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        initial,
    )
    .unwrap();
    for (key, value) in additions.iter().cloned() {
        assert!(
            sequential
                .insert(&Blake3PhysicalIdentity, key, value)
                .unwrap()
        );
    }

    assert_eq!(
        bulk.rebuild_with_entries(&Blake3PhysicalIdentity, additions)
            .unwrap(),
        3
    );
    assert_eq!(bulk.root(), sequential.root());
    assert_eq!(bulk.entry_count(), 5);
    assert!(bulk.nodes().contains_key(&old_root));
    assert_eq!(
        CanonicalPhysicalMap::validate_root(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Representation,
            Some(old_root),
            bulk.nodes(),
        )
        .unwrap(),
        2
    );
    assert_eq!(
        CanonicalPhysicalMap::validate_root(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Representation,
            bulk.root(),
            bulk.nodes(),
        )
        .unwrap(),
        5
    );
}

#[test]
fn canonical_map_rejects_duplicate_keys_and_forged_summaries() {
    assert!(matches!(
        CanonicalPhysicalMap::build(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Profile,
            vec![(key(1), vec![1]), (key(1), vec![2])],
        ),
        Err(PhysicalModelError::InvalidMap("duplicate leaf key"))
    ));

    let map = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        vec![(key(1), vec![1]), (key(2), vec![2])],
    )
    .unwrap();
    let root = map.root().unwrap();
    let PhysicalMapNode::Branch {
        domain,
        prefix_bits,
        prefix,
        zero,
        one,
        subtree_entries,
    } = map.nodes().get(&root).unwrap()
    else {
        panic!("two leaves must produce one branch root");
    };
    let forged = PhysicalMapNode::branch(
        *domain,
        *prefix_bits,
        prefix.clone(),
        *zero,
        *one,
        subtree_entries.checked_add(1).unwrap(),
    )
    .unwrap();
    let forged_id = forged.identify(&Blake3PhysicalIdentity).unwrap();
    let mut nodes = map.nodes().clone();
    nodes.insert(forged_id, forged);
    assert!(matches!(
        CanonicalPhysicalMap::validate_root(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Profile,
            Some(forged_id),
            &nodes,
        ),
        Err(PhysicalModelError::InvalidMap(
            "node graph is not the unique canonical trie"
        ))
    ));
}

#[test]
fn every_map_node_round_trips_canonically() {
    let map = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        map_entries(),
    )
    .unwrap();
    for (id, node) in map.nodes() {
        let encoded = node.encode().unwrap();
        let decoded = PhysicalMapNode::decode(&encoded).unwrap();
        assert_eq!(&decoded, node);
        assert_eq!(decoded.identify(&Blake3PhysicalIdentity).unwrap(), *id);
    }
}

#[test]
fn catalogue_and_state_require_consistent_generation_shapes() {
    let node = PhysicalMapNodeId::new([4; 32]);
    assert!(RepresentationCatalogueRoot::new(0, None, 1, None, 0).is_err());
    let catalogue = RepresentationCatalogueRoot::new(0, Some(node), 1, Some(node), 2).unwrap();
    assert_eq!(
        RepresentationCatalogueRoot::decode(&catalogue.encode()).unwrap(),
        catalogue
    );
    let catalogue_id = catalogue.identify(&Blake3PhysicalIdentity);
    let placements = PlacementSetId::from_digest([5; 32]);
    let state = RepresentationState::new(1, None, catalogue_id, placements).unwrap();
    assert_eq!(RepresentationState::decode(&state.encode()).unwrap(), state);
    assert!(RepresentationState::new(2, None, catalogue_id, placements).is_err());
    assert!(
        RepresentationState::new(
            1,
            Some(RepresentationStateId::new([6; 32])),
            catalogue_id,
            placements,
        )
        .is_err()
    );
}

fn replica(node: u32, locator: ReplicaLocator) -> Replica {
    Replica::new(StorageNodeId::new(node), locator).unwrap()
}

#[test]
fn placement_entries_sort_replicas_and_reject_duplicates() {
    let arena = ReplicaLocator::ArenaFrame {
        arena_generation: 0,
        offset: 128,
        payload_length: 64,
        frame_checksum: [8; 32],
    };
    let loose = ReplicaLocator::LooseBlob {
        namespace_generation: 7,
    };
    let entry = PlacementEntry::new(
        BlobId::new([1; 32]),
        RepresentationProfileId::new([2; 32]),
        64,
        vec![replica(2, loose), replica(1, arena)],
    )
    .unwrap();
    assert_eq!(entry.replicas()[0].storage_node(), StorageNodeId::new(1));
    assert_eq!(
        PlacementEntry::decode(&entry.encode().unwrap()).unwrap(),
        entry
    );
    assert!(
        PlacementEntry::new(
            BlobId::new([1; 32]),
            RepresentationProfileId::new([2; 32]),
            64,
            vec![replica(1, arena), replica(1, arena)],
        )
        .is_err()
    );
}

#[test]
fn placement_set_counts_are_structurally_bounded() {
    let node = PhysicalMapNodeId::new([9; 32]);
    assert!(PlacementSet::new(0, None, 1, 1).is_err());
    assert!(PlacementSet::new(0, Some(node), 2, 1).is_err());
    let set = PlacementSet::new(0, Some(node), 2, 3).unwrap();
    assert_eq!(PlacementSet::decode(&set.encode()).unwrap(), set);
    assert_eq!(
        set.identify(&Blake3PhysicalIdentity),
        PlacementSet::decode(&set.encode())
            .unwrap()
            .identify(&Blake3PhysicalIdentity)
    );
}

#[test]
fn typed_map_keys_preserve_current_physical_digest_bytes() {
    assert_eq!(
        PhysicalMapKey::from(RepresentationProfileId::new([1; 32])).as_bytes(),
        &[1; 32]
    );
    assert_eq!(
        PhysicalMapKey::from(RepresentationRecordId::new([2; 32])).as_bytes(),
        &[2; 32]
    );
    assert_eq!(
        PhysicalMapKey::from(BlobId::new([3; 32])).as_bytes(),
        &[3; 32]
    );
}

#[test]
fn placement_set_id_retains_gc_evidence_wire_compatibility() {
    let logical = ObjectId::new([42; 32]);
    let placement = PlacementSetId::new(logical);
    assert_eq!(placement.object_id(), logical);
}

#[test]
fn validating_a_root_ignores_unreachable_historical_nodes() {
    let map = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        vec![(key(1), vec![1]), (key(2), vec![2])],
    )
    .unwrap();
    let mut nodes = map.nodes().clone();
    let historical = PhysicalMapNode::leaf(PhysicalMapDomain::Placement, key(99), vec![99]);
    nodes.insert(
        historical.identify(&Blake3PhysicalIdentity).unwrap(),
        historical,
    );
    assert_eq!(
        CanonicalPhysicalMap::validate_root(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Placement,
            map.root(),
            &nodes,
        )
        .unwrap(),
        2
    );
}

#[test]
fn map_validation_fails_closed_on_missing_children() {
    let map = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        vec![(key(1), vec![1]), (key(2), vec![2])],
    )
    .unwrap();
    let mut nodes: BTreeMap<_, _> = map.nodes().clone();
    let leaf = nodes
        .iter()
        .find_map(|(id, node)| matches!(node, PhysicalMapNode::Leaf { .. }).then_some(*id))
        .unwrap();
    nodes.remove(&leaf);
    assert!(matches!(
        CanonicalPhysicalMap::validate_root(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Profile,
            map.root(),
            &nodes,
        ),
        Err(PhysicalModelError::InvalidMap("missing map node"))
    ));
}

#[test]
fn representative_identifiers_are_distinct_newtypes() {
    let catalogue = RepresentationCatalogueRootId::new([1; 32]);
    let state = RepresentationStateId::new([1; 32]);
    assert_eq!(catalogue.as_bytes(), state.as_bytes());
}

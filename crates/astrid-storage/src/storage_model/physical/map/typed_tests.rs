use alloc::vec;
use alloc::vec::Vec;

use super::super::Blake3PhysicalIdentity;
use super::super::PhysicalModelError;
use super::{
    CanonicalPhysicalMap, MapConstruction, PhysicalMapDomain, PhysicalMapKey, ProfileMap,
    RepresentationMap,
};

fn key_material(tag: u8, ordinal: u32) -> PhysicalMapKey {
    let mut material = [tag; 32];
    material[..4].copy_from_slice(&ordinal.to_le_bytes());
    PhysicalMapKey::new(*blake3::hash(&material).as_bytes())
}

fn sample_entries(tag: u8, count: u32) -> Vec<(PhysicalMapKey, Vec<u8>)> {
    (0..count)
        .map(|ordinal| {
            let [low, high, ..] = ordinal.to_le_bytes();
            (key_material(tag, ordinal), vec![tag, low, high])
        })
        .collect()
}

#[test]
fn recover_exact_rejects_wrong_domain_and_unauthenticated_extras() {
    let entries = sample_entries(0xA1, 3);
    let foreign = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        entries.clone(),
    )
    .unwrap();
    assert!(matches!(
        ProfileMap::recover_exact(foreign.root(), foreign.nodes().clone()),
        Err(PhysicalModelError::InvalidMap(_))
    ));

    let profile = ProfileMap::build_dense(entries).unwrap();
    let orphan = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        vec![(PhysicalMapKey::new([0xEE; 32]), vec![7])],
    )
    .unwrap();
    let mut with_extra = profile.nodes().clone();
    with_extra.extend(orphan.nodes().iter().map(|(id, node)| (*id, node.clone())));
    assert!(matches!(
        ProfileMap::recover_exact(profile.root(), with_extra),
        Err(PhysicalModelError::InvalidMap(
            "unauthenticated historical map nodes outside the active closure"
        ))
    ));
}

fn assert_independent_root_proof(map: &RepresentationMap) {
    let count = CanonicalPhysicalMap::validate_root(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        map.root(),
        map.nodes(),
    )
    .unwrap();
    assert_eq!(map.entry_count(), count);
}

#[test]
fn representation_insert_and_rebuild_match_independent_validate_root() {
    let base = sample_entries(0x10, 8);
    let fresh = sample_entries(0x20, 5); // disjoint key tag space from base
    let mut rebuilt = RepresentationMap::build_dense(base.clone()).unwrap();
    rebuilt.rebuild_with_entries(fresh.clone()).unwrap();
    assert_independent_root_proof(&rebuilt);

    let mut path_copy = RepresentationMap::build_dense(base).unwrap();
    for (key, value) in &fresh {
        assert!(path_copy.insert(*key, value.clone()).unwrap());
    }
    assert_eq!(path_copy.root(), rebuilt.root());
    assert_eq!(path_copy.entry_count(), rebuilt.entry_count());
    assert_independent_root_proof(&path_copy);

    // Split the same fresh set across a second rebuild batch; tip must converge.
    let (first, second) = fresh.split_at(2);
    let mut batched = RepresentationMap::build_dense(sample_entries(0x10, 8)).unwrap();
    batched.rebuild_with_entries(first.to_vec()).unwrap();
    batched.rebuild_with_entries(second.to_vec()).unwrap();
    assert_eq!(batched.root(), rebuilt.root());
    assert_independent_root_proof(&batched);
}

fn build_representation_map(
    construction: MapConstruction,
    entries: Vec<(PhysicalMapKey, Vec<u8>)>,
) -> RepresentationMap {
    match construction {
        MapConstruction::LegacyBinary => RepresentationMap::build(entries).unwrap(),
        MapConstruction::DenseRadix => RepresentationMap::build_dense(entries).unwrap(),
    }
}

fn prefix_entries(count: u32) -> Vec<(PhysicalMapKey, Vec<u8>)> {
    (0..count)
        .map(|ordinal| {
            let mut key = [0x5A; 32];
            key[28..].copy_from_slice(&ordinal.to_be_bytes());
            (PhysicalMapKey::new(key), ordinal.to_le_bytes().to_vec())
        })
        .collect()
}

#[test]
fn legacy_and_dense_mutations_match_independent_proof_across_shapes() {
    for count in [0, 1, 2, 15, 16, 17, 31, 32, 33, 64] {
        for entries in [sample_entries(0x73, count), prefix_entries(count)] {
            for construction in [MapConstruction::LegacyBinary, MapConstruction::DenseRadix] {
                let expected = build_representation_map(construction, entries.clone());
                assert_independent_root_proof(&expected);
                for reverse in [false, true] {
                    let mut ordered = entries.clone();
                    if reverse {
                        ordered.reverse();
                    }
                    let mut inserted = build_representation_map(construction, vec![]);
                    for (key, value) in &ordered {
                        assert!(inserted.insert(*key, value.clone()).unwrap());
                        assert_independent_root_proof(&inserted);
                    }
                    assert_eq!(inserted.root(), expected.root());
                    assert_eq!(inserted.entry_count(), u64::from(count));
                    for (key, value) in &entries {
                        assert_eq!(inserted.as_canonical().get(*key), Some(value.as_slice()));
                    }

                    let mut rebuilt = build_representation_map(construction, vec![]);
                    for batch in ordered.chunks(7) {
                        rebuilt.rebuild_with_entries(batch.to_vec()).unwrap();
                        assert_independent_root_proof(&rebuilt);
                    }
                    assert_eq!(rebuilt.root(), expected.root());
                    assert_eq!(rebuilt.rebuild_with_entries(entries.clone()).unwrap(), 0);
                    rebuilt.reclaim_unreachable_nodes().unwrap();
                    assert_independent_root_proof(&rebuilt);
                    let recovered =
                        RepresentationMap::recover_exact(rebuilt.root(), rebuilt.nodes().clone())
                            .unwrap();
                    assert_eq!(recovered.root(), expected.root());
                    assert_eq!(recovered.entry_count(), u64::from(count));
                }
            }
        }
    }
}

#[test]
fn collision_and_partial_mutation_keep_tip_valid() {
    let mut map = RepresentationMap::build_dense(sample_entries(0x30, 6)).unwrap();
    let root = map.root();
    let count = map.entry_count();
    let snapshot = map.nodes().clone();
    let existing_key = map
        .nodes()
        .values()
        .find_map(|node| match node {
            super::PhysicalMapNode::Leaf { key, .. } => Some(*key),
            super::PhysicalMapNode::Page { entries, .. } => entries.first().map(|(key, _)| *key),
            _ => None,
        })
        .expect("dense fixture retains at least one leaf or page");
    assert!(map.insert(existing_key, vec![0xFF, 0x00, 0x11]).is_err());
    assert_eq!(map.root(), root);
    assert_eq!(map.entry_count(), count);
    assert_eq!(map.nodes(), &snapshot);
    assert_independent_root_proof(&map);

    let fresh_key = key_material(0x99, 1);
    assert!(map.insert(fresh_key, vec![0x10, 0x20, 0x30]).unwrap());
    assert_ne!(map.root(), root);
    assert_independent_root_proof(&map);

    // Failed rebuild batch must leave the prior tip intact.
    let before_root = map.root();
    let before_count = map.entry_count();
    let before_nodes = map.nodes().clone();
    let mut colliding = sample_entries(0x40, 2);
    colliding.push((existing_key, vec![1, 2, 3]));
    assert!(map.rebuild_with_entries(colliding).is_err());
    assert_eq!(map.root(), before_root);
    assert_eq!(map.entry_count(), before_count);
    assert_eq!(map.nodes(), &before_nodes);
    assert_independent_root_proof(&map);
}

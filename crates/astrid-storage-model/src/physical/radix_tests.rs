//! Dense physical-map construction tests.

extern crate std;

use alloc::vec;
use alloc::vec::Vec;

use super::map::validate_radix;
use super::{
    CanonicalPhysicalMap, PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode,
    PhysicalMapNodeId, PhysicalModelError,
};

#[derive(Clone, Copy)]
struct Blake3Identity;

impl PhysicalIdentity for Blake3Identity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(material);
        *hasher.finalize().as_bytes()
    }
}

fn entry(index: u32) -> (PhysicalMapKey, Vec<u8>) {
    let digest = blake3::hash(&index.to_le_bytes());
    (
        PhysicalMapKey::new(*digest.as_bytes()),
        index.to_le_bytes().to_vec(),
    )
}

#[test]
fn dense_root_is_independent_of_input_and_insertion_order() {
    let entries = (0..1_024).map(entry).collect::<Vec<_>>();
    let mut reversed = entries.clone();
    reversed.reverse();
    let forward = CanonicalPhysicalMap::build_dense(
        &Blake3Identity,
        PhysicalMapDomain::Representation,
        entries.clone(),
    )
    .unwrap();
    let reverse = CanonicalPhysicalMap::build_dense(
        &Blake3Identity,
        PhysicalMapDomain::Representation,
        reversed,
    )
    .unwrap();
    assert_eq!(forward.root(), reverse.root());

    let mut incremental = CanonicalPhysicalMap::build_dense(
        &Blake3Identity,
        PhysicalMapDomain::Representation,
        Vec::new(),
    )
    .unwrap();
    for (key, value) in entries {
        assert!(incremental.insert(&Blake3Identity, key, value).unwrap());
    }
    assert_eq!(forward.root(), incremental.root());
    assert_eq!(forward.entry_count(), incremental.entry_count());
}

#[test]
fn dense_map_bounds_pages_and_survives_adversarial_prefixes() {
    let entries = (0_u32..4_096)
        .map(|index| {
            let mut key = [0x55; 32];
            key[28..].copy_from_slice(&index.to_be_bytes());
            (PhysicalMapKey::new(key), index.to_le_bytes().to_vec())
        })
        .collect::<Vec<_>>();
    let map = CanonicalPhysicalMap::build_dense(
        &Blake3Identity,
        PhysicalMapDomain::Placement,
        entries.clone(),
    )
    .unwrap();
    assert_eq!(map.entry_count(), 4_096);
    assert!(map.nodes().values().all(|node| match node {
        PhysicalMapNode::Page { entries, .. } => entries.len() == 1,
        PhysicalMapNode::Radix { children, .. } => (2..=16).contains(&children.len()),
        PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Branch { .. } => false,
    }));
    for (key, value) in entries.iter().step_by(257) {
        assert_eq!(map.get(*key), Some(value.as_slice()));
    }
    assert_eq!(
        CanonicalPhysicalMap::validate_root(
            &Blake3Identity,
            PhysicalMapDomain::Placement,
            map.root(),
            map.nodes(),
        ),
        Ok(4_096)
    );
}

#[test]
fn legacy_and_dense_nodes_use_distinct_identity_domains() {
    let legacy =
        CanonicalPhysicalMap::build(&Blake3Identity, PhysicalMapDomain::Profile, vec![entry(7)])
            .unwrap();
    let dense = CanonicalPhysicalMap::build_dense(
        &Blake3Identity,
        PhysicalMapDomain::Profile,
        vec![entry(7)],
    )
    .unwrap();
    assert_ne!(legacy.root(), dense.root());
    assert_eq!(
        CanonicalPhysicalMap::recover(
            &Blake3Identity,
            PhysicalMapDomain::Profile,
            legacy.root(),
            legacy.nodes().clone(),
        )
        .unwrap()
        .get(entry(7).0),
        Some(entry(7).1.as_slice())
    );
}

#[test]
fn dense_decoder_rejects_an_empty_page() {
    let encoded = [2, 0, 0, 0, 0];
    assert_eq!(
        PhysicalMapNode::decode(&encoded),
        Err(PhysicalModelError::InvalidMap(
            "radix page count is outside its bound"
        ))
    );
}

#[test]
fn dense_branch_rejects_non_adjacent_child_aliases() {
    let first = PhysicalMapNodeId::new([1; 32]);
    let second = PhysicalMapNodeId::new([2; 32]);
    assert_eq!(
        validate_radix(0, &[], 0b111, &[first, second, first], 3),
        Err(PhysicalModelError::InvalidMap(
            "radix branch aliases its children"
        ))
    );
}

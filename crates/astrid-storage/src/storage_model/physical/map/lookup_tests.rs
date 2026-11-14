//! Lookup preparation follows the reachable construction, including old roots.

use super::super::codec::{encoder_finishes, reset_encoder_finishes};
use super::*;

struct Blake3Identity;

impl PhysicalIdentity for Blake3Identity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        blake3::derive_key(context, material)
    }
}

fn key(last: u8) -> PhysicalMapKey {
    let mut bytes = [0x55; 32];
    bytes[31] = last;
    PhysicalMapKey::new(bytes)
}

fn entries() -> Vec<(PhysicalMapKey, Vec<u8>)> {
    [0x10, 0x11, 0x18, 0x20]
        .into_iter()
        .map(|last| (key(last), vec![last]))
        .collect()
}

fn assert_lookup(
    map: &CanonicalPhysicalMap,
    key: PhysicalMapKey,
    expected: Option<&[u8]>,
    preparations: usize,
) {
    reset_encoder_finishes();
    assert_eq!(map.get(key), expected);
    // get's only Encoder::finish is the allocating legacy search-key encoding.
    assert_eq!(encoder_finishes(), preparations);
}

fn assert_lookups(map: &CanonicalPhysicalMap, preparations: usize) {
    for last in [0x10, 0x11, 0x18, 0x20] {
        assert_lookup(map, key(last), Some(&[last]), preparations);
    }
    // Absent dense selector and a different key reaching the singleton page.
    for last in [0x12, 0x21] {
        assert_lookup(map, key(last), None, preparations);
    }
    let mut different_prefix = *key(0x10).as_bytes();
    different_prefix[0] = 0x54;
    assert_lookup(
        map,
        PhysicalMapKey::new(different_prefix),
        None,
        preparations,
    );
}

#[test]
fn dense_hits_and_misses_do_not_prepare_legacy_search_keys() {
    for domain in [
        PhysicalMapDomain::Profile,
        PhysicalMapDomain::Representation,
        PhysicalMapDomain::Placement,
    ] {
        let map = CanonicalPhysicalMap::build_dense(&Blake3Identity, domain, entries()).unwrap();
        assert!(matches!(
            map.nodes()[&map.root().unwrap()],
            PhysicalMapNode::Radix { .. }
        ));
        assert_lookups(&map, 0);
    }
}

#[test]
fn legacy_branches_prepare_once_and_single_leaves_need_no_search_key() {
    for domain in [
        PhysicalMapDomain::Profile,
        PhysicalMapDomain::Representation,
        PhysicalMapDomain::Placement,
    ] {
        let map = CanonicalPhysicalMap::build(&Blake3Identity, domain, entries()).unwrap();
        // These keys send 0x10 through all three binary branches before its leaf.
        assert_eq!(
            map.nodes()
                .values()
                .filter(|node| matches!(node, PhysicalMapNode::Branch { .. }))
                .count(),
            3
        );
        assert_lookups(&map, 1);
        for map in [
            CanonicalPhysicalMap::build(&Blake3Identity, domain, vec![(key(0x10), vec![0x10])])
                .unwrap(),
            CanonicalPhysicalMap::build_dense(
                &Blake3Identity,
                domain,
                vec![(key(0x10), vec![0x10])],
            )
            .unwrap(),
        ] {
            assert_lookup(&map, key(0x10), Some(&[0x10]), 0);
            assert_lookup(&map, key(0x11), None, 0);
        }
        for map in [
            CanonicalPhysicalMap::build(&Blake3Identity, domain, vec![]).unwrap(),
            CanonicalPhysicalMap::build_dense(&Blake3Identity, domain, vec![]).unwrap(),
        ] {
            assert_lookup(&map, key(0x10), None, 0);
        }
    }
}

#[test]
fn recovered_historical_roots_in_mixed_arenas_prepare_for_the_active_format() {
    for domain in [
        PhysicalMapDomain::Profile,
        PhysicalMapDomain::Representation,
        PhysicalMapDomain::Placement,
    ] {
        let legacy = CanonicalPhysicalMap::build(&Blake3Identity, domain, entries()).unwrap();
        let dense = CanonicalPhysicalMap::build_dense(&Blake3Identity, domain, entries()).unwrap();
        let mut arena = legacy.nodes().clone();
        arena.extend(dense.nodes().iter().map(|(id, node)| (*id, node.clone())));
        // Canonical validation rebuilds the root's construction: a single active
        // closure cannot mix formats, but historical roots may share an arena.
        for (root, preparations) in [(dense.root(), 0), (legacy.root(), 1)] {
            let recovered =
                CanonicalPhysicalMap::recover(&Blake3Identity, domain, root, arena.clone())
                    .unwrap();
            assert_eq!(recovered.nodes().len(), arena.len());
            assert_lookups(&recovered, preparations);
        }
    }
}

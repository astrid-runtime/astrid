//! Regressions for transactional borrowed/new-only map rebuild.

use alloc::vec;
use alloc::vec::Vec;

use super::*;

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

fn fingerprint(map: &CanonicalPhysicalMap) -> (Option<PhysicalMapNodeId>, u64, Vec<u8>) {
    let mut material = Vec::new();
    for (id, node) in map.nodes() {
        material.extend_from_slice(id.as_bytes());
        material.extend_from_slice(&node.encode().expect("node encodes"));
    }
    (
        map.root(),
        map.entry_count(),
        blake3::hash(&material).as_bytes().to_vec(),
    )
}

fn assert_unchanged(
    before: &(Option<PhysicalMapNodeId>, u64, Vec<u8>),
    map: &CanonicalPhysicalMap,
) {
    assert_eq!(&fingerprint(map), before);
}

#[test]
fn rebuild_matches_full_build_for_legacy_and_dense() {
    let initial = vec![(key(1), vec![10]), (key(4), vec![40])];
    let additions = vec![(key(2), vec![20]), (key(3), vec![30]), (key(5), vec![50])];
    let union = {
        let mut all = initial.clone();
        all.extend(additions.iter().cloned());
        all
    };

    for (build, expected) in [
        (
            CanonicalPhysicalMap::build(
                &Blake3PhysicalIdentity,
                PhysicalMapDomain::Representation,
                initial.clone(),
            )
            .unwrap(),
            CanonicalPhysicalMap::build(
                &Blake3PhysicalIdentity,
                PhysicalMapDomain::Representation,
                union.clone(),
            )
            .unwrap(),
        ),
        (
            CanonicalPhysicalMap::build_dense(
                &Blake3PhysicalIdentity,
                PhysicalMapDomain::Representation,
                initial.clone(),
            )
            .unwrap(),
            CanonicalPhysicalMap::build_dense(
                &Blake3PhysicalIdentity,
                PhysicalMapDomain::Representation,
                union.clone(),
            )
            .unwrap(),
        ),
    ] {
        let mut bulk = build;
        let old_root = bulk.root().unwrap();
        let old_nodes = bulk.nodes().keys().copied().collect::<Vec<_>>();
        assert_eq!(
            bulk.rebuild_with_entries(&Blake3PhysicalIdentity, additions.clone())
                .unwrap(),
            3
        );
        assert_eq!(bulk.root(), expected.root());
        assert_eq!(bulk.entry_count(), expected.entry_count());
        assert!(bulk.nodes().contains_key(&old_root));
        for id in old_nodes {
            assert!(bulk.nodes().contains_key(&id));
        }
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
}

#[test]
fn idempotent_additions_leave_state_unchanged() {
    let mut map = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        vec![(key(1), vec![1]), (key(2), vec![2])],
    )
    .unwrap();
    let before = fingerprint(&map);
    let before_len = map.nodes().len();
    assert_eq!(
        map.rebuild_with_entries(
            &Blake3PhysicalIdentity,
            vec![(key(1), vec![1]), (key(2), vec![2])],
        )
        .unwrap(),
        0
    );
    assert_unchanged(&before, &map);
    assert_eq!(map.nodes().len(), before_len);
}

#[test]
fn unequal_existing_key_preserves_map_state() {
    let mut map = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        vec![(key(1), vec![1]), (key(2), vec![2])],
    )
    .unwrap();
    let before = fingerprint(&map);
    assert!(matches!(
        map.rebuild_with_entries(&Blake3PhysicalIdentity, vec![(key(1), vec![9])]),
        Err(PhysicalModelError::InvalidMap(
            "leaf key has unequal canonical bytes"
        ))
    ));
    assert_unchanged(&before, &map);
}

#[test]
fn missing_active_node_preserves_map_state() {
    let mut map = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        vec![(key(1), vec![1]), (key(2), vec![2])],
    )
    .unwrap();
    let root = map.root().unwrap();
    let PhysicalMapNode::Branch { zero, .. } = map.nodes.get(&root).cloned().unwrap() else {
        panic!("expected legacy branch root");
    };
    map.nodes.remove(&zero);
    let before = fingerprint(&map);
    assert!(matches!(
        map.rebuild_with_entries(&Blake3PhysicalIdentity, vec![(key(3), vec![3])]),
        Err(PhysicalModelError::InvalidMap("missing active map node"))
    ));
    assert_unchanged(&before, &map);
}

#[test]
fn entry_count_mismatch_preserves_map_state() {
    let mut map = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        vec![(key(1), vec![1]), (key(2), vec![2])],
    )
    .unwrap();
    map.entry_count = 99;
    let before = fingerprint(&map);
    assert!(matches!(
        map.rebuild_with_entries(&Blake3PhysicalIdentity, vec![(key(3), vec![3])]),
        Err(PhysicalModelError::InvalidMap(
            "active map count does not match its leaves"
        ))
    ));
    assert_unchanged(&before, &map);
}

#[test]
fn cycle_in_active_graph_preserves_map_state() {
    let mut map = CanonicalPhysicalMap::build(
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
        one: _,
        subtree_entries,
    } = map.nodes.get(&root).cloned().unwrap()
    else {
        panic!("expected legacy branch root");
    };
    // Point both children at the root so traversal revisits a node.
    map.nodes.insert(
        root,
        PhysicalMapNode::branch(domain, prefix_bits, prefix, zero, root, subtree_entries).unwrap(),
    );
    let before = fingerprint(&map);
    assert!(matches!(
        map.rebuild_with_entries(&Blake3PhysicalIdentity, vec![(key(3), vec![3])]),
        Err(PhysicalModelError::InvalidMap(
            "active map traversal revisited a node"
        ))
    ));
    assert_unchanged(&before, &map);
}

#[test]
fn forged_existing_node_collision_preserves_map_state() {
    let initial = vec![(key(1), vec![10]), (key(4), vec![40])];
    let additions = vec![(key(2), vec![20])];
    let mut union = initial.clone();
    union.extend(additions.iter().cloned());
    let expected = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        union,
    )
    .unwrap();
    // Collide with the replacement root, which is built after its children.
    // An old active-node collision would corrupt the input traversal instead
    // of exercising failure after the transactional sink has staged nodes.
    let victim = expected.root().expect("expected replacement root");
    let forged = PhysicalMapNode::leaf(PhysicalMapDomain::Representation, key(0xff), vec![0xde]);

    let mut map = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        initial,
    )
    .unwrap();
    assert!(!map.nodes.contains_key(&victim));
    map.nodes.insert(victim, forged);
    let before = fingerprint(&map);
    assert!(matches!(
        map.rebuild_with_entries(&Blake3PhysicalIdentity, additions),
        Err(PhysicalModelError::InvalidMap(
            "physical map-node identity collision"
        ))
    ));
    assert_unchanged(&before, &map);
}

#[test]
fn rebuild_node_growth_stays_below_full_rebuilt_arena() {
    let initial = (1_u8..=32)
        .map(|index| (key(index), vec![index]))
        .collect::<Vec<_>>();
    let additions = (33_u8..=40)
        .map(|index| (key(index), vec![index]))
        .collect::<Vec<_>>();
    let mut union = initial.clone();
    union.extend(additions.iter().cloned());
    let full = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        union,
    )
    .unwrap();
    let mut map = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        initial,
    )
    .unwrap();
    let existing_before = map.nodes().len();
    assert_eq!(
        map.rebuild_with_entries(&Blake3PhysicalIdentity, additions)
            .unwrap(),
        8
    );
    let growth = map.nodes().len() - existing_before;
    // Observable stand-in for the old parallel full-arena retain: growth must
    // stay below both the pre-existing arena and a from-scratch union build.
    assert!(growth < full.nodes().len());
    assert!(growth < existing_before);
    assert_eq!(map.root(), full.root());
}

#[test]
fn empty_map_rebuild_owns_all_additions() {
    let mut map = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        Vec::new(),
    )
    .unwrap();
    let additions = vec![(key(1), vec![1]), (key(2), vec![2])];
    let expected = CanonicalPhysicalMap::build(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        additions.clone(),
    )
    .unwrap();
    assert_eq!(
        map.rebuild_with_entries(&Blake3PhysicalIdentity, additions)
            .unwrap(),
        2
    );
    assert_eq!(map.root(), expected.root());
    assert_eq!(map.nodes().len(), expected.nodes().len());
}

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;

use super::{
    AuthenticatedMapRecovery, CanonicalPhysicalMap, MapConstruction, PhysicalIdentity,
    PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode, PhysicalMapNodeId, PhysicalModelError,
};

struct Identity;

impl PhysicalIdentity for Identity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        blake3::derive_key(context, material)
    }
}

#[derive(Default)]
struct CountingIdentity {
    calls: Cell<usize>,
}

impl PhysicalIdentity for CountingIdentity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        self.calls.set(self.calls.get().strict_add(1));
        Identity.identify(context, material)
    }
}

impl CountingIdentity {
    fn take(&self) -> usize {
        self.calls.replace(0)
    }
}

struct FixedIdentity([u8; 32]);

impl PhysicalIdentity for FixedIdentity {
    fn identify(&self, _context: &'static str, _material: &[u8]) -> [u8; 32] {
        self.0
    }
}

struct GraphIdentity<'a>(&'a BTreeMap<PhysicalMapNodeId, PhysicalMapNode>);

impl PhysicalIdentity for GraphIdentity<'_> {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        self.0
            .iter()
            .find_map(|(id, node)| {
                (node.identity_context() == context && node.encode().unwrap() == material)
                    .then_some(*id.as_bytes())
            })
            .unwrap_or_else(|| Identity.identify(context, material))
    }
}

const DOMAINS: [PhysicalMapDomain; 3] = [
    PhysicalMapDomain::Profile,
    PhysicalMapDomain::Representation,
    PhysicalMapDomain::Placement,
];
const CONSTRUCTIONS: [MapConstruction; 2] =
    [MapConstruction::LegacyBinary, MapConstruction::DenseRadix];

fn entries(count: u32, common_prefix: bool) -> Vec<(PhysicalMapKey, Vec<u8>)> {
    (0..count)
        .rev()
        .map(|index| {
            let mut key = if common_prefix {
                [0x55; 32]
            } else {
                *blake3::hash(&index.to_be_bytes()).as_bytes()
            };
            if common_prefix {
                key[28..].copy_from_slice(&index.to_be_bytes());
            }
            let value = vec![key[31]; usize::try_from(index % 4).unwrap().strict_mul(17)];
            (PhysicalMapKey::new(key), value)
        })
        .collect()
}

fn encoded_arena(
    nodes: &BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) -> Vec<(PhysicalMapNodeId, Vec<u8>)> {
    nodes
        .iter()
        .map(|(id, node)| (*id, node.encode().unwrap()))
        .collect()
}

fn finish_encoded<I: PhysicalIdentity>(
    identity: &I,
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    encoded: &[(PhysicalMapNodeId, Vec<u8>)],
) -> Result<CanonicalPhysicalMap, PhysicalModelError> {
    let mut recovery = AuthenticatedMapRecovery::new(identity, domain, root);
    for (id, bytes) in encoded {
        recovery.authenticate(*id, bytes)?;
    }
    recovery.finish()
}

fn garbage_node() -> (PhysicalMapNodeId, PhysicalMapNode, Vec<u8>) {
    let node = PhysicalMapNode::leaf(
        PhysicalMapDomain::Placement,
        PhysicalMapKey::new([0xff; 32]),
        vec![0xff; 8],
    );
    let id = node.identify(&Identity).unwrap();
    let encoded = node.encode().unwrap();
    (id, node, encoded)
}

fn reachable_len(map: &CanonicalPhysicalMap) -> usize {
    let mut stack: Vec<_> = map.root().into_iter().collect();
    let mut visited = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !visited.insert(id) {
            continue;
        }
        match &map.nodes()[&id] {
            PhysicalMapNode::Branch { zero, one, .. } => {
                stack.push(*one);
                stack.push(*zero);
            },
            PhysicalMapNode::Radix { children, .. } => stack.extend(children.iter().copied()),
            PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => {},
        }
    }
    visited.len()
}

fn synthetic_branch(
    domain: PhysicalMapDomain,
    construction: MapConstruction,
    zero: PhysicalMapNodeId,
    one: PhysicalMapNodeId,
) -> PhysicalMapNode {
    match construction {
        MapConstruction::LegacyBinary => PhysicalMapNode::Branch {
            domain,
            prefix_bits: 0,
            prefix: Vec::new(),
            zero,
            one,
            subtree_entries: 2,
        },
        MapConstruction::DenseRadix => PhysicalMapNode::Radix {
            domain,
            prefix_nibbles: 0,
            prefix: Vec::new(),
            child_bitmap: 3,
            children: vec![zero, one],
            subtree_entries: 2,
        },
    }
}

#[test]
fn authenticated_finish_matches_public_recover_for_every_construction_and_domain() {
    let (garbage_id, garbage, garbage_bytes) = garbage_node();
    for domain in DOMAINS {
        for construction in CONSTRUCTIONS {
            for common_prefix in [false, true] {
                for count in [0_u32, 1, 2, 17] {
                    let map = CanonicalPhysicalMap::build_with_construction(
                        &Identity,
                        domain,
                        entries(count, common_prefix),
                        construction,
                    )
                    .unwrap();
                    for reverse in [false, true] {
                        let mut encoded = encoded_arena(map.nodes());
                        encoded.push((garbage_id, garbage_bytes.clone()));
                        if reverse {
                            encoded.reverse();
                        }
                        let finished =
                            finish_encoded(&Identity, domain, map.root(), &encoded).unwrap();
                        let mut supplied = map.nodes().clone();
                        supplied.insert(garbage_id, garbage.clone());
                        let public =
                            CanonicalPhysicalMap::recover(&Identity, domain, map.root(), supplied)
                                .unwrap();
                        assert_eq!(finished, public);
                        assert_eq!(finished.root(), map.root());
                        assert_eq!(finished.entry_count(), u64::from(count));
                        for (key, value) in entries(count, common_prefix) {
                            assert_eq!(finished.get(key), Some(value.as_slice()));
                            assert_eq!(public.get(key), finished.get(key));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn authenticated_finish_rejects_the_same_malformed_graphs_as_public_recover() {
    for domain in DOMAINS {
        for construction in CONSTRUCTIONS {
            let map = CanonicalPhysicalMap::build_with_construction(
                &Identity,
                domain,
                entries(17, true),
                construction,
            )
            .unwrap();
            let root = map.root().unwrap();
            assert_both_reject(
                domain,
                Some(PhysicalMapNodeId::new([0x11; 32])),
                map.nodes(),
            );

            let mut missing = map.nodes().clone();
            let missing_child = match &missing[&root] {
                PhysicalMapNode::Branch { zero, .. } => *zero,
                PhysicalMapNode::Radix { children, .. } => children[0],
                _ => panic!("expected an internal root"),
            };
            missing.remove(&missing_child);
            assert_both_reject(domain, Some(root), &missing);

            for wrong in DOMAINS.into_iter().filter(|candidate| *candidate != domain) {
                assert_both_reject(wrong, Some(root), map.nodes());
            }

            mutate_and_reject(&map, |node| match node {
                PhysicalMapNode::Branch {
                    subtree_entries, ..
                }
                | PhysicalMapNode::Radix {
                    subtree_entries, ..
                } => *subtree_entries = subtree_entries.strict_add(1),
                _ => unreachable!(),
            });
            mutate_and_reject(&map, |node| match node {
                PhysicalMapNode::Branch { zero, one, .. } => core::mem::swap(zero, one),
                PhysicalMapNode::Radix { children, .. } => children.reverse(),
                _ => unreachable!(),
            });
            mutate_and_reject(&map, |node| match node {
                PhysicalMapNode::Branch { prefix, .. } | PhysicalMapNode::Radix { prefix, .. } => {
                    prefix[0] ^= 0x80;
                },
                _ => unreachable!(),
            });
        }
    }
}

fn assert_both_reject(
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: &BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) {
    assert!(CanonicalPhysicalMap::recover(&Identity, domain, root, nodes.clone()).is_err());
    assert!(finish_encoded(&Identity, domain, root, &encoded_arena(nodes)).is_err());
}

fn mutate_and_reject(map: &CanonicalPhysicalMap, change: impl FnOnce(&mut PhysicalMapNode)) {
    let mut node = map.nodes()[&map.root().unwrap()].clone();
    change(&mut node);
    let id = node.identify(&Identity).unwrap();
    let mut nodes = map.nodes().clone();
    nodes.insert(id, node);
    assert_both_reject(map.domain(), Some(id), &nodes);
}

#[test]
fn authenticate_rejects_stale_proof_for_changed_encoded_bytes() {
    for construction in CONSTRUCTIONS {
        let map = CanonicalPhysicalMap::build_with_construction(
            &Identity,
            PhysicalMapDomain::Representation,
            entries(8, true),
            construction,
        )
        .unwrap();
        let root = map.root().unwrap();
        let original = map.nodes()[&root].encode().unwrap();
        let mut changed = map.nodes()[&root].clone();
        match &mut changed {
            PhysicalMapNode::Branch {
                subtree_entries, ..
            }
            | PhysicalMapNode::Radix {
                subtree_entries, ..
            } => *subtree_entries = subtree_entries.strict_add(1),
            _ => unreachable!(),
        }
        let changed_bytes = changed.encode().unwrap();
        let mut recovery = AuthenticatedMapRecovery::new(&Identity, map.domain(), Some(root));
        assert_eq!(
            recovery.authenticate(root, &changed_bytes).unwrap_err(),
            PhysicalModelError::InvalidMap("map-node identity mismatch")
        );
        recovery.authenticate(root, &original).unwrap();
        assert_eq!(
            recovery.authenticate(root, &changed_bytes).unwrap_err(),
            PhysicalModelError::InvalidMap("map-node identity mismatch")
        );
    }
}

#[test]
fn owned_authentication_skips_walk_reencode_of_authenticated_nodes() {
    for construction in CONSTRUCTIONS {
        for count in [1_u32, 2, 17] {
            let map = CanonicalPhysicalMap::build_with_construction(
                &Identity,
                PhysicalMapDomain::Representation,
                entries(count, false),
                construction,
            )
            .unwrap();
            let (garbage_id, _, garbage_bytes) = garbage_node();
            let mut encoded = encoded_arena(map.nodes());
            encoded.push((garbage_id, garbage_bytes));
            let reachable = reachable_len(&map);
            let owned = encoded.len();
            PhysicalMapNode::take_encode_count();
            let identity = CountingIdentity::default();
            let mut recovery = AuthenticatedMapRecovery::new(&identity, map.domain(), map.root());
            for (id, bytes) in &encoded {
                recovery.authenticate(*id, bytes).unwrap();
            }
            assert_eq!(identity.take(), owned);
            assert_eq!(PhysicalMapNode::take_encode_count(), 0);

            recovery.finish().unwrap();
            let finish_identifies = identity.take();
            let finish_encodes = PhysicalMapNode::take_encode_count();

            CanonicalPhysicalMap::validate_root(&identity, map.domain(), map.root(), map.nodes())
                .unwrap();
            let public_identifies = identity.take();
            let public_encodes = PhysicalMapNode::take_encode_count();

            assert_eq!(finish_identifies.strict_add(reachable), public_identifies);
            assert_eq!(finish_encodes.strict_add(reachable), public_encodes);
            assert!(finish_encodes < public_encodes);
            assert_eq!(finish_encodes, finish_identifies);
            assert_eq!(public_encodes, public_identifies);
        }
    }
}

#[test]
fn authenticate_collision_and_duplicate_bodies_match_occupancy_rules() {
    let node = PhysicalMapNode::leaf(
        PhysicalMapDomain::Profile,
        PhysicalMapKey::new([1; 32]),
        vec![1],
    );
    let other = PhysicalMapNode::leaf(
        PhysicalMapDomain::Profile,
        PhysicalMapKey::new([2; 32]),
        vec![2],
    );
    let id = PhysicalMapNodeId::new([9; 32]);
    let identity = FixedIdentity(*id.as_bytes());
    let mut recovery =
        AuthenticatedMapRecovery::new(&identity, PhysicalMapDomain::Profile, Some(id));
    assert_eq!(
        recovery.authenticate(id, &node.encode().unwrap()).unwrap(),
        &node
    );
    assert_eq!(
        recovery.authenticate(id, &node.encode().unwrap()).unwrap(),
        &node
    );
    assert_eq!(
        recovery
            .authenticate(id, &other.encode().unwrap())
            .unwrap_err(),
        PhysicalModelError::InvalidMap("physical map-node identity collision")
    );
}

#[test]
fn authenticate_requires_canonical_bytes_and_finish_consumes_the_arena() {
    let map = CanonicalPhysicalMap::build_dense(
        &Identity,
        PhysicalMapDomain::Placement,
        entries(4, false),
    )
    .unwrap();
    let root = map.root().unwrap();
    let mut recovery = AuthenticatedMapRecovery::new(&Identity, map.domain(), Some(root));
    assert!(recovery.authenticate(root, &[]).is_err());
    let mut encoded = encoded_arena(map.nodes());
    encoded[0].1.push(0xff);
    assert!(recovery.authenticate(encoded[0].0, &encoded[0].1).is_err());
    let finished = finish_encoded(
        &Identity,
        map.domain(),
        Some(root),
        &encoded_arena(map.nodes()),
    )
    .unwrap();
    assert_eq!(finished.nodes().len(), map.nodes().len());
    assert!(!AuthenticatedMapRecovery::new(&Identity, map.domain(), Some(root)).contains(root));
}

#[test]
fn authenticated_finish_rejects_cycles_and_shared_parents() {
    for domain in DOMAINS {
        for construction in CONSTRUCTIONS {
            let [root, inner, leaf, other] =
                [1, 2, 3, 4].map(|value| PhysicalMapNodeId::new([value; 32]));
            for cyclic in [false, true] {
                let mut nodes = BTreeMap::new();
                nodes.insert(
                    root,
                    synthetic_branch(
                        domain,
                        construction,
                        if cyclic { root } else { inner },
                        leaf,
                    ),
                );
                nodes.insert(inner, synthetic_branch(domain, construction, leaf, other));
                nodes.insert(
                    leaf,
                    PhysicalMapNode::leaf(domain, PhysicalMapKey::new([3; 32]), vec![3]),
                );
                nodes.insert(
                    other,
                    PhysicalMapNode::leaf(domain, PhysicalMapKey::new([4; 32]), vec![4]),
                );
                let identity = GraphIdentity(&nodes);
                assert_eq!(
                    CanonicalPhysicalMap::recover(&identity, domain, Some(root), nodes.clone()),
                    Err(PhysicalModelError::InvalidMap(
                        "node is cyclic or shared by two parents"
                    ))
                );
                assert_eq!(
                    finish_encoded(&identity, domain, Some(root), &encoded_arena(&nodes)),
                    Err(PhysicalModelError::InvalidMap(
                        "node is cyclic or shared by two parents"
                    ))
                );
            }
        }
    }
}

#[test]
fn accumulator_api_binds_identity_at_construction() {
    fn finish_with_bound_identity<I: PhysicalIdentity>(
        identity: &I,
        domain: PhysicalMapDomain,
        root: Option<PhysicalMapNodeId>,
        encoded: &[(PhysicalMapNodeId, Vec<u8>)],
    ) -> Result<CanonicalPhysicalMap, PhysicalModelError> {
        let mut recovery = AuthenticatedMapRecovery::new(identity, domain, root);
        for (id, bytes) in encoded {
            recovery.authenticate(*id, bytes)?;
        }
        recovery.finish()
    }

    let map =
        CanonicalPhysicalMap::build_dense(&Identity, PhysicalMapDomain::Profile, entries(2, false))
            .unwrap();
    let finished = finish_with_bound_identity(
        &Identity,
        map.domain(),
        map.root(),
        &encoded_arena(map.nodes()),
    )
    .unwrap();
    let public =
        CanonicalPhysicalMap::recover(&Identity, map.domain(), map.root(), map.nodes().clone())
            .unwrap();
    assert_eq!(finished, public);
}

#[test]
fn owned_and_public_recovery_reject_authenticated_bytes_from_another_domain() {
    for construction in CONSTRUCTIONS {
        let map = CanonicalPhysicalMap::build_with_construction(
            &Identity,
            PhysicalMapDomain::Profile,
            entries(4, false),
            construction,
        )
        .unwrap();
        let encoded = encoded_arena(map.nodes());
        let mut recovery =
            AuthenticatedMapRecovery::new(&Identity, PhysicalMapDomain::Placement, map.root());
        for (id, bytes) in &encoded {
            recovery.authenticate(*id, bytes).unwrap();
        }
        assert_eq!(
            recovery.finish().unwrap_err(),
            PhysicalModelError::InvalidMap("map domain mismatch")
        );
        assert_eq!(
            CanonicalPhysicalMap::recover(
                &Identity,
                PhysicalMapDomain::Placement,
                map.root(),
                map.nodes().clone(),
            )
            .unwrap_err(),
            PhysicalModelError::InvalidMap("map domain mismatch")
        );
    }
}

//! Differential controls for the former fully materialized validation path.

use super::super::{CanonicalPhysicalMap, MapConstruction, PhysicalMapKey};
use super::*;

struct Identity;

impl PhysicalIdentity for Identity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        blake3::derive_key(context, material)
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
            let value = vec![key[31]; usize::try_from(index % 4).unwrap().strict_mul(2_731)];
            (PhysicalMapKey::new(key), value)
        })
        .collect()
}

fn compare<I: PhysicalIdentity>(
    identity: &I,
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: &BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) -> Result<u64, PhysicalModelError> {
    let expected = materialized_validate_root(identity, domain, root, nodes);
    let actual = CanonicalPhysicalMap::validate_root(identity, domain, root, nodes);
    assert_eq!(actual, expected);
    actual
}

#[test]
fn borrowed_validation_matches_materialized_for_every_construction_and_domain() {
    for domain in DOMAINS {
        for construction in CONSTRUCTIONS {
            for common_prefix in [false, true] {
                for count in [0, 1, 2, 17, 65] {
                    let map = CanonicalPhysicalMap::build_with_construction(
                        &Identity,
                        domain,
                        entries(count, common_prefix),
                        construction,
                    )
                    .unwrap();
                    assert_eq!(
                        compare(&Identity, domain, map.root, &map.nodes),
                        Ok(u64::from(count))
                    );
                    let mut nodes = map.nodes;
                    // Historical garbage is outside the active root's authority.
                    nodes.insert(
                        PhysicalMapNodeId::new([0xff; 32]),
                        PhysicalMapNode::Page {
                            domain: PhysicalMapDomain::Placement,
                            entries: Vec::new(),
                        },
                    );
                    assert_eq!(
                        compare(&Identity, domain, map.root, &nodes),
                        Ok(u64::from(count))
                    );
                    assert_eq!(compare(&Identity, domain, None, &nodes), Ok(0));
                }
            }
        }
    }
}

// A non-Clone view makes the shared builders' borrowed-value input explicit.
struct ValueView<'a>(&'a [u8]);

impl AsRef<[u8]> for ValueView<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

#[test]
fn borrowed_builders_emit_the_exact_materialized_nodes() {
    for domain in DOMAINS {
        for construction in CONSTRUCTIONS {
            let values = entries(65, true);
            let materialized = CanonicalPhysicalMap::build_with_construction(
                &Identity,
                domain,
                values.clone(),
                construction,
            )
            .unwrap();
            let mut borrowed: Vec<_> = values
                .iter()
                .map(|(key, value)| (*key, ValueView(value)))
                .collect();
            let mut emitted = 0_usize;
            let (root, count) =
                super::super::build_root(domain, &mut borrowed, construction, &mut |node| {
                    let id = node.identify(&Identity)?;
                    assert_eq!(materialized.nodes.get(&id), Some(&node));
                    emitted = emitted.strict_add(1);
                    // Nothing retains this emitted node after this call returns.
                    Ok(id)
                })
                .unwrap();
            assert_eq!(root, materialized.root);
            assert_eq!(count, materialized.entry_count);
            assert_eq!(emitted, materialized.nodes.len());
        }
    }
}

fn child(node: &PhysicalMapNode) -> PhysicalMapNodeId {
    match node {
        PhysicalMapNode::Branch { zero, .. } => *zero,
        PhysicalMapNode::Radix { children, .. } => children[0],
        _ => panic!("multiple entries require a branch"),
    }
}

fn changed_root(
    map: &CanonicalPhysicalMap,
    change: impl FnOnce(&mut PhysicalMapNode),
) -> (
    PhysicalMapNodeId,
    BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) {
    let mut node = map.nodes[&map.root.unwrap()].clone();
    change(&mut node);
    let id = node.identify(&Identity).unwrap();
    let mut nodes = map.nodes.clone();
    nodes.insert(id, node);
    (id, nodes)
}

fn compare_changed(map: &CanonicalPhysicalMap, change: impl FnOnce(&mut PhysicalMapNode)) {
    let (root, nodes) = changed_root(map, change);
    assert!(compare(&Identity, map.domain, Some(root), &nodes).is_err());
}

#[test]
fn borrowed_validation_matches_materialized_rejections() {
    for domain in DOMAINS {
        for construction in CONSTRUCTIONS {
            let map = CanonicalPhysicalMap::build_with_construction(
                &Identity,
                domain,
                entries(17, true),
                construction,
            )
            .unwrap();
            let root = map.root.unwrap();
            assert!(
                compare(
                    &Identity,
                    domain,
                    Some(PhysicalMapNodeId::new([0xff; 32])),
                    &map.nodes
                )
                .is_err()
            );
            let mut missing = map.nodes.clone();
            let missing_child = child(&missing[&root]);
            missing.remove(&missing_child);
            assert!(compare(&Identity, domain, Some(root), &missing).is_err());
            let mut tampered = map.nodes.clone();
            tampered.insert(
                root,
                PhysicalMapNode::leaf(domain, PhysicalMapKey::new([0; 32]), vec![9]),
            );
            assert!(compare(&Identity, domain, Some(root), &tampered).is_err());
            for wrong in DOMAINS.into_iter().filter(|candidate| *candidate != domain) {
                assert!(compare(&Identity, wrong, Some(root), &map.nodes).is_err());
            }
            compare_changed(&map, |node| match node {
                PhysicalMapNode::Branch {
                    subtree_entries, ..
                }
                | PhysicalMapNode::Radix {
                    subtree_entries, ..
                } => *subtree_entries = subtree_entries.strict_add(1),
                _ => unreachable!(),
            });
            compare_changed(&map, |node| match node {
                PhysicalMapNode::Branch { zero, one, .. } => core::mem::swap(zero, one),
                PhysicalMapNode::Radix { children, .. } => children.reverse(),
                _ => unreachable!(),
            });
            compare_changed(&map, |node| match node {
                PhysicalMapNode::Branch { prefix, .. } | PhysicalMapNode::Radix { prefix, .. } => {
                    prefix[0] ^= 0x80;
                },
                _ => unreachable!(),
            });
            reject_duplicate_and_mixed_leaves(&map);
        }
    }
}

fn reject_duplicate_and_mixed_leaves(map: &CanonicalPhysicalMap) {
    let mut nodes = map.nodes.clone();
    let (id, leaf) = nodes
        .iter()
        .find(|(_, node)| {
            matches!(
                node,
                PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. }
            )
        })
        .unwrap();
    let id = *id;
    let replacement = match leaf {
        PhysicalMapNode::Leaf { domain, key, value } => PhysicalMapNode::Page {
            domain: *domain,
            entries: vec![(*key, value.clone())],
        },
        PhysicalMapNode::Page { domain, entries } => {
            PhysicalMapNode::leaf(*domain, entries[0].0, entries[0].1.clone())
        },
        _ => unreachable!(),
    };
    let replacement_id = replacement.identify(&Identity).unwrap();
    nodes.insert(replacement_id, replacement);
    let (root, changed) = changed_root(map, |node| match node {
        PhysicalMapNode::Branch { zero, .. } => *zero = replacement_id,
        PhysicalMapNode::Radix { children, .. } => children[0] = replacement_id,
        _ => unreachable!(),
    });
    nodes.extend(changed);
    assert!(compare(&Identity, map.domain, Some(root), &nodes).is_err());
    // Two distinct authenticated leaves carry the same key with unequal bytes.
    let key = match &nodes[&id] {
        PhysicalMapNode::Leaf { key, .. } => *key,
        PhysicalMapNode::Page { entries, .. } => entries[0].0,
        _ => unreachable!(),
    };
    let leaves = [vec![1], vec![2]].map(|value| match map.construction {
        MapConstruction::LegacyBinary => PhysicalMapNode::leaf(map.domain, key, value),
        MapConstruction::DenseRadix => PhysicalMapNode::Page {
            domain: map.domain,
            entries: vec![(key, value)],
        },
    });
    let mut nodes = BTreeMap::new();
    let ids = leaves.map(|node| {
        let id = node.identify(&Identity).unwrap();
        nodes.insert(id, node);
        id
    });
    let root = synthetic_branch(map.domain, map.construction, ids[0], ids[1]);
    let root_id = root.identify(&Identity).unwrap();
    nodes.insert(root_id, root);
    assert_eq!(
        compare(&Identity, map.domain, Some(root_id), &nodes),
        Err(PhysicalModelError::InvalidMap("duplicate leaf key"))
    );
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

// Authenticate synthetic graph IDs so cycle/shared-parent checks are reached
// without requiring a fixed point in a real cryptographic digest function.
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

#[test]
fn borrowed_validation_preserves_cycle_and_shared_parent_rejection() {
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
                assert_eq!(
                    compare(&GraphIdentity(&nodes), domain, Some(root), &nodes),
                    Err(PhysicalModelError::InvalidMap(
                        "node is cyclic or shared by two parents"
                    ))
                );
            }
        }
    }
}

// Kept from the previous public validator (only Self is qualified), including
// traversal order, value clones and the retained rebuild. This oracle shares
// the refactored builders; frozen vectors and old/new builder controls provide
// the independent construction-parity evidence.
fn materialized_validate_root<I: PhysicalIdentity>(
    identity: &I,
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: &BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) -> Result<u64, PhysicalModelError> {
    let Some(root) = root else {
        return Ok(0);
    };
    let construction = nodes
        .get(&root)
        .ok_or(PhysicalModelError::InvalidMap("missing map root"))?
        .construction();
    let mut stack = vec![root];
    let mut visited = BTreeSet::new();
    let mut entries = Vec::new();
    while let Some(node_id) = stack.pop() {
        if !visited.insert(node_id) {
            return Err(PhysicalModelError::InvalidMap(
                "node is cyclic or shared by two parents",
            ));
        }
        let node = nodes
            .get(&node_id)
            .ok_or(PhysicalModelError::InvalidMap("missing map node"))?;
        if node.domain() != domain {
            return Err(PhysicalModelError::InvalidMap("map domain mismatch"));
        }
        if node.identify(identity)? != node_id {
            return Err(PhysicalModelError::InvalidMap("map-node identity mismatch"));
        }
        match node {
            PhysicalMapNode::Leaf { key, value, .. } => {
                entries.push((*key, value.clone()));
            },
            PhysicalMapNode::Branch { zero, one, .. } => {
                stack.push(*one);
                stack.push(*zero);
            },
            PhysicalMapNode::Page {
                entries: page_entries,
                ..
            } => entries.extend(page_entries.iter().cloned()),
            PhysicalMapNode::Radix { children, .. } => {
                stack.extend(children.iter().rev().copied());
            },
        }
    }
    let rebuilt =
        CanonicalPhysicalMap::build_with_construction(identity, domain, entries, construction)?;
    if rebuilt.root != Some(root) {
        return Err(PhysicalModelError::InvalidMap(
            "node graph is not the unique canonical trie",
        ));
    }
    Ok(rebuilt.entry_count)
}

#[derive(Default)]
struct RecordingIdentity {
    preimages: core::cell::RefCell<Vec<(&'static str, Vec<u8>)>>,
}

impl PhysicalIdentity for RecordingIdentity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        // Copy here: validation deliberately reuses the input slice's storage.
        self.preimages
            .borrow_mut()
            .push((context, material.to_vec()));
        Identity.identify(context, material)
    }
}

#[test]
fn reused_validation_preserves_every_injected_identity_preimage() {
    use super::super::super::codec::{encoder_finishes, reset_encoder_finishes};

    for domain in DOMAINS {
        for construction in CONSTRUCTIONS {
            for common_prefix in [false, true] {
                for count in [0, 1, 2, 17, 65] {
                    let map = CanonicalPhysicalMap::build_with_construction(
                        &Identity,
                        domain,
                        entries(count, common_prefix),
                        construction,
                    )
                    .unwrap();
                    let direct = RecordingIdentity::default();
                    reset_encoder_finishes();
                    let expected =
                        materialized_validate_root(&direct, domain, map.root, &map.nodes);
                    let owned_finishes = encoder_finishes();
                    let expected_preimages = direct.preimages.into_inner();
                    let reused = RecordingIdentity::default();
                    reset_encoder_finishes();
                    let actual =
                        CanonicalPhysicalMap::validate_root(&reused, domain, map.root, &map.nodes);
                    let reused_finishes = encoder_finishes();
                    assert_eq!(actual, expected);
                    assert_eq!(reused.preimages.into_inner(), expected_preimages);
                    // Legacy key-search encodings still finish normally. The
                    // removed finishes correspond exactly to identified nodes.
                    assert_eq!(
                        owned_finishes,
                        reused_finishes.strict_add(expected_preimages.len())
                    );
                    if construction == MapConstruction::DenseRadix {
                        assert_eq!(reused_finishes, 0);
                    }
                }
            }
        }
    }
}

#[test]
fn reused_node_identity_clears_longer_preimages_before_the_next_node() {
    for domain in DOMAINS {
        for construction in CONSTRUCTIONS {
            let direct = RecordingIdentity::default();
            let reused = RecordingIdentity::default();
            let mut scratch = Vec::new();
            for length in [8_193, 0, 1, 65_537, 3] {
                let key = PhysicalMapKey::new([7; 32]);
                let value = vec![9; length];
                let node = match construction {
                    MapConstruction::LegacyBinary => PhysicalMapNode::leaf(domain, key, value),
                    MapConstruction::DenseRadix => PhysicalMapNode::Page {
                        domain,
                        entries: vec![(key, value)],
                    },
                };
                assert_eq!(
                    super::identify_encoded(&reused, &node, &mut scratch).unwrap(),
                    node.identify(&direct).unwrap()
                );
                assert_eq!(scratch, node.encode().unwrap());
            }
            assert_eq!(reused.preimages.into_inner(), direct.preimages.into_inner());
        }
    }
}

//! Differential oracle for the frozen canonical-shape guarantee.
use super::*;
use crate::storage_model::physical::map::PhysicalMapKey;

struct Identity;
impl PhysicalIdentity for Identity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key(context);
        h.update(material);
        *h.finalize().as_bytes()
    }
}

fn reference(
    domain: PhysicalMapDomain,
    root: PhysicalMapNodeId,
    nodes: &BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) -> Result<u64, PhysicalModelError> {
    let construction = nodes
        .get(&root)
        .ok_or(PhysicalModelError::InvalidMap("missing map root"))?
        .construction();
    let mut pending = vec![root];
    let mut visited = BTreeSet::new();
    let mut entries = Vec::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            return Err(PhysicalModelError::InvalidMap("shared or cyclic"));
        }
        let n = nodes
            .get(&id)
            .ok_or(PhysicalModelError::InvalidMap("missing node"))?;
        if n.domain() != domain || n.identify(&Identity)? != id {
            return Err(PhysicalModelError::InvalidMap("wrong domain or identity"));
        }
        match n {
            PhysicalMapNode::Leaf { key, value, .. } => entries.push((*key, value.clone())),
            PhysicalMapNode::Page { entries: page, .. } => entries.extend(page.iter().cloned()),
            PhysicalMapNode::Branch { zero, one, .. } => pending.extend([*one, *zero]),
            PhysicalMapNode::Radix { children, .. } => {
                pending.extend(children.iter().rev().copied());
            },
        }
    }
    let rebuilt = super::super::CanonicalPhysicalMap::build_with_construction(
        &Identity,
        domain,
        entries,
        construction,
    )?;
    if rebuilt.root() != Some(root) {
        return Err(PhysicalModelError::InvalidMap("noncanonical"));
    }
    Ok(rebuilt.entry_count())
}

#[test]
fn borrowed_canonical_proof_agrees_with_full_rebuild_for_valid_and_forged_roots() {
    for domain in [
        PhysicalMapDomain::Profile,
        PhysicalMapDomain::Representation,
        PhysicalMapDomain::Placement,
    ] {
        for construction in [MapConstruction::LegacyBinary, MapConstruction::DenseRadix] {
            for count in [1_u32, 2, 17, 257] {
                let entries = (0..count)
                    .map(|n| {
                        let mut k = [0x55; 32];
                        k[28..].copy_from_slice(&n.to_be_bytes());
                        (
                            PhysicalMapKey::new(k),
                            vec![u8::try_from(n % 256).unwrap(); 129],
                        )
                    })
                    .collect();
                let map = super::super::CanonicalPhysicalMap::build_with_construction(
                    &Identity,
                    domain,
                    entries,
                    construction,
                )
                .unwrap();
                let root = map.root().unwrap();
                assert_eq!(
                    validate_root(&Identity, domain, Some(root), map.nodes()),
                    reference(domain, root, map.nodes())
                );
                for mutation in 0..4 {
                    let mut nodes = map.nodes().clone();
                    let mut node = nodes[&root].clone();
                    match &mut node {
                        PhysicalMapNode::Leaf { domain, .. }
                        | PhysicalMapNode::Page { domain, .. } => {
                            *domain = if *domain == PhysicalMapDomain::Profile {
                                PhysicalMapDomain::Placement
                            } else {
                                PhysicalMapDomain::Profile
                            }
                        },
                        PhysicalMapNode::Branch {
                            subtree_entries,
                            prefix,
                            zero,
                            one,
                            ..
                        } => match mutation {
                            0 => *subtree_entries += 1,
                            1 => prefix[0] ^= 0x80,
                            2 => core::mem::swap(zero, one),
                            _ => {
                                nodes.remove(zero);
                            },
                        },
                        PhysicalMapNode::Radix {
                            subtree_entries,
                            prefix,
                            children,
                            ..
                        } => match mutation {
                            0 => *subtree_entries += 1,
                            1 => prefix[0] ^= 0x80,
                            2 => children.swap(0, 1),
                            _ => {
                                nodes.remove(&children[0]);
                            },
                        },
                    }
                    let forged = node.identify(&Identity).unwrap();
                    nodes.insert(forged, node);
                    assert!(
                        reference(domain, forged, &nodes).is_err(),
                        "mutation {mutation} must invalidate {construction:?}"
                    );
                    assert!(
                        validate_root(&Identity, domain, Some(forged), &nodes).is_err(),
                        "mutation {mutation} accepted by borrowed proof"
                    );
                }
            }
        }
    }
}

/// The production builders accept borrowed, non-Clone values and a sink that
/// owns no new node arena. Both constructions must retain identical roots.
#[test]
fn canonical_builders_hash_nonclone_borrowed_values_into_discarding_sink() {
    struct Borrowed<'a>(&'a [u8]);
    impl AsRef<[u8]> for Borrowed<'_> {
        fn as_ref(&self) -> &[u8] {
            self.0
        }
    }
    let entries = (0_u32..128)
        .map(|n| {
            (
                PhysicalMapKey::new(*blake3::hash(&n.to_be_bytes()).as_bytes()),
                vec![0x33; 4096],
            )
        })
        .collect::<Vec<_>>();
    for construction in [MapConstruction::LegacyBinary, MapConstruction::DenseRadix] {
        let map = super::super::CanonicalPhysicalMap::build_with_construction(
            &Identity,
            PhysicalMapDomain::Placement,
            entries.clone(),
            construction,
        )
        .unwrap();
        let mut borrowed = entries
            .iter()
            .map(|(k, v)| (*k, Borrowed(v)))
            .collect::<Vec<_>>();
        borrowed.sort_unstable_by_key(|(k, _)| *k);
        let mut sink = ValidationNodes(map.nodes());
        let root = match construction {
            MapConstruction::LegacyBinary => legacy::build(
                &Identity,
                PhysicalMapDomain::Placement,
                &borrowed,
                &mut sink,
            )
            .unwrap(),
            MapConstruction::DenseRadix => radix::build(
                &Identity,
                PhysicalMapDomain::Placement,
                &borrowed,
                &mut sink,
            )
            .unwrap(),
        };
        assert_eq!(Some(root), map.root());
        assert_eq!(map.entry_count(), 128);
    }
}

//! Differential oracle for the frozen canonical-shape guarantee.
use super::{CanonicalNodeSink, *};
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

#[test]
fn canonical_builders_reject_unequal_nodes_with_the_same_identity() {
    struct Collision;
    impl PhysicalIdentity for Collision {
        fn identify(&self, _: &'static str, _: &[u8]) -> [u8; 32] {
            [0x55; 32]
        }
    }
    for construction in [MapConstruction::LegacyBinary, MapConstruction::DenseRadix] {
        let entries = vec![
            (PhysicalMapKey::new([0; 32]), vec![1]),
            (PhysicalMapKey::new([1; 32]), vec![2]),
        ];
        let result = super::super::CanonicalPhysicalMap::build_with_construction(
            &Collision,
            PhysicalMapDomain::Placement,
            entries,
            construction,
        );
        assert!(
            matches!(
                result,
                Err(PhysicalModelError::InvalidMap(
                    "physical map-node identity collision"
                ))
            ),
            "{construction:?} must reject an unequal colliding node"
        );
    }
}

#[test]
fn incremental_builders_reject_collisions_without_changing_the_active_map() {
    struct Collision;
    impl PhysicalIdentity for Collision {
        fn identify(&self, _: &'static str, _: &[u8]) -> [u8; 32] {
            [0x55; 32]
        }
    }
    for construction in [MapConstruction::LegacyBinary, MapConstruction::DenseRadix] {
        let mut map = super::super::CanonicalPhysicalMap::build_with_construction(
            &Collision,
            PhysicalMapDomain::Placement,
            vec![(PhysicalMapKey::new([0; 32]), vec![1])],
            construction,
        )
        .unwrap();
        let original = map.clone();
        let result = map.insert(&Collision, PhysicalMapKey::new([1; 32]), vec![2]);
        assert!(
            matches!(
                result,
                Err(PhysicalModelError::InvalidMap(
                    "physical map-node identity collision"
                ))
            ),
            "{construction:?} incremental insertion must reject colliding nodes"
        );
        assert_eq!(map.root(), original.root());
        assert_eq!(map.entry_count(), original.entry_count());
        assert_eq!(map.nodes(), original.nodes());
    }
}

struct CountingIdentity(core::cell::Cell<usize>);

impl PhysicalIdentity for CountingIdentity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        self.0.set(self.0.get().strict_add(1));
        Identity.identify(context, material)
    }
}

#[test]
fn public_recovery_identifies_each_canonical_node_once() {
    for construction in [MapConstruction::LegacyBinary, MapConstruction::DenseRadix] {
        for count in [1_u32, 2, 17, 257] {
            let entries = (0..count)
                .map(|n| {
                    (
                        PhysicalMapKey::new(*blake3::hash(&n.to_be_bytes()).as_bytes()),
                        vec![3; 129],
                    )
                })
                .collect();
            let map = super::super::CanonicalPhysicalMap::build_with_construction(
                &Identity,
                PhysicalMapDomain::Placement,
                entries,
                construction,
            )
            .unwrap();
            let identity = CountingIdentity(core::cell::Cell::new(0));
            let recovered = super::super::CanonicalPhysicalMap::recover(
                &identity,
                PhysicalMapDomain::Placement,
                map.root(),
                map.nodes().clone(),
            )
            .unwrap();
            assert_eq!(recovered.entry_count(), u64::from(count));
            assert_eq!(recovered.root(), map.root());
            assert_eq!(identity.0.get(), map.nodes().len(), "{construction:?}");
        }
    }
}

#[test]
fn canonical_builder_validation_requires_every_constructed_node() {
    let entries = vec![(PhysicalMapKey::new([1; 32]), vec![1])];
    for construction in [MapConstruction::LegacyBinary, MapConstruction::DenseRadix] {
        let nodes = BTreeMap::new();
        let mut sink = ValidationNodes(&nodes);
        let result = match construction {
            MapConstruction::LegacyBinary => {
                legacy::build(&Identity, PhysicalMapDomain::Placement, &entries, &mut sink)
            },
            MapConstruction::DenseRadix => {
                radix::build(&Identity, PhysicalMapDomain::Placement, &entries, &mut sink)
            },
        };
        assert_eq!(
            result,
            Err(PhysicalModelError::InvalidMap("missing canonical map node"))
        );
    }
}

#[test]
fn public_recovery_rejects_forged_leaf_bodies_under_original_identities() {
    for construction in [MapConstruction::LegacyBinary, MapConstruction::DenseRadix] {
        let entries = (0_u32..257)
            .map(|n| {
                (
                    PhysicalMapKey::new(*blake3::hash(&n.to_be_bytes()).as_bytes()),
                    vec![3; 129],
                )
            })
            .collect();
        let map = super::super::CanonicalPhysicalMap::build_with_construction(
            &Identity,
            PhysicalMapDomain::Placement,
            entries,
            construction,
        )
        .unwrap();
        let root = map.root().unwrap();
        let mut nodes = map.nodes().clone();
        let body = nodes
            .values_mut()
            .find(|node| {
                matches!(
                    node,
                    PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. }
                )
            })
            .unwrap();
        match body {
            PhysicalMapNode::Leaf { value, .. } => value[0] ^= 1,
            PhysicalMapNode::Page { entries, .. } => entries[0].1[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(reference(PhysicalMapDomain::Placement, root, &nodes).is_err());
        assert!(
            super::super::CanonicalPhysicalMap::recover(
                &Identity,
                PhysicalMapDomain::Placement,
                Some(root),
                nodes,
            )
            .is_err()
        );
    }
}

#[test]
fn validation_sink_rejects_unequal_bodies_even_when_identity_collides() {
    struct Collision;
    impl PhysicalIdentity for Collision {
        fn identify(&self, _: &'static str, _: &[u8]) -> [u8; 32] {
            [0x55; 32]
        }
    }
    for construction in [MapConstruction::LegacyBinary, MapConstruction::DenseRadix] {
        let entries = vec![(PhysicalMapKey::new([1; 32]), vec![1])];
        let map = super::super::CanonicalPhysicalMap::build_with_construction(
            &Collision,
            PhysicalMapDomain::Placement,
            entries.clone(),
            construction,
        )
        .unwrap();
        let mut nodes = map.nodes().clone();
        match nodes.values_mut().next().unwrap() {
            PhysicalMapNode::Leaf { value, .. } => value[0] = 2,
            PhysicalMapNode::Page { entries, .. } => entries[0].1[0] = 2,
            _ => unreachable!(),
        }
        let mut sink = ValidationNodes(&nodes);
        let result = match construction {
            MapConstruction::LegacyBinary => legacy::build(
                &Collision,
                PhysicalMapDomain::Placement,
                &entries,
                &mut sink,
            ),
            MapConstruction::DenseRadix => radix::build(
                &Collision,
                PhysicalMapDomain::Placement,
                &entries,
                &mut sink,
            ),
        };
        assert_eq!(
            result,
            Err(PhysicalModelError::InvalidMap(
                "physical map-node identity collision"
            ))
        );
    }
}

#[test]
fn public_recovery_rejects_noncanonical_body_even_when_root_digest_collides() {
    struct ForgedRootIdentity {
        forged: Vec<u8>,
        root: PhysicalMapNodeId,
    }
    impl PhysicalIdentity for ForgedRootIdentity {
        fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
            if material == self.forged {
                *self.root.as_bytes()
            } else {
                Identity.identify(context, material)
            }
        }
    }
    for construction in [MapConstruction::LegacyBinary, MapConstruction::DenseRadix] {
        let entries = (0_u32..257)
            .map(|n| {
                (
                    PhysicalMapKey::new(*blake3::hash(&n.to_be_bytes()).as_bytes()),
                    vec![3],
                )
            })
            .collect();
        let map = super::super::CanonicalPhysicalMap::build_with_construction(
            &Identity,
            PhysicalMapDomain::Placement,
            entries,
            construction,
        )
        .unwrap();
        let root = map.root().unwrap();
        let mut nodes = map.nodes().clone();
        let forged = nodes.get_mut(&root).unwrap();
        match forged {
            PhysicalMapNode::Branch {
                subtree_entries, ..
            }
            | PhysicalMapNode::Radix {
                subtree_entries, ..
            } => {
                *subtree_entries = subtree_entries.strict_add(1);
            },
            _ => panic!("exercise a multi-node canonical tree"),
        }
        let identity = ForgedRootIdentity {
            forged: forged.encode().unwrap(),
            root,
        };
        assert_eq!(forged.identify(&identity).unwrap(), root);
        assert!(matches!(
            super::super::CanonicalPhysicalMap::recover(
                &identity,
                PhysicalMapDomain::Placement,
                Some(root),
                nodes,
            ),
            Err(PhysicalModelError::InvalidMap(
                "physical map-node identity collision"
            ))
        ));
    }
}

#[test]
fn canonical_proof_keeps_only_active_ids_and_borrows_sorted_leaf_values() {
    let active = super::super::CanonicalPhysicalMap::build_dense(
        &Identity,
        PhysicalMapDomain::Placement,
        vec![
            (PhysicalMapKey::new([2; 32]), vec![7]),
            (PhysicalMapKey::new([1; 32]), vec![8]),
        ],
    )
    .unwrap();
    let historical = super::super::CanonicalPhysicalMap::build_dense(
        &Identity,
        PhysicalMapDomain::Placement,
        vec![(PhysicalMapKey::new([2; 32]), vec![9])],
    )
    .unwrap();
    let old = historical.root().unwrap();
    let mut nodes = active.nodes().clone();
    nodes.extend(historical.nodes().clone());
    let map = super::super::CanonicalPhysicalMap::recover(
        &Identity,
        PhysicalMapDomain::Placement,
        active.root(),
        nodes,
    )
    .unwrap();
    let proof = map
        .prove_root(&Identity, PhysicalMapDomain::Placement)
        .unwrap();
    assert!(!proof.visited().contains(&old));
    assert!(proof.visited().contains(&map.root().unwrap()));
    assert_eq!(proof.entries().len(), 2);
    assert!(proof.entries().windows(2).all(|pair| pair[0].0 < pair[1].0));
    for (key, value) in proof.entries() {
        assert!(core::ptr::eq(*value, map.get(*key).unwrap()));
    }
    assert!(
        map.prove_root(&Identity, PhysicalMapDomain::Profile)
            .is_err()
    );
    let empty = prove_root(&Identity, PhysicalMapDomain::Placement, None, map.nodes()).unwrap();
    assert!(empty.visited().is_empty());
    assert!(empty.entries().is_empty());
}

#[test]
fn borrowed_builder_bytes_match_owned_node_encoding_and_identity() {
    for construction in [MapConstruction::LegacyBinary, MapConstruction::DenseRadix] {
        for count in [1_u32, 2, 17] {
            let entries = (0..count)
                .map(|n| {
                    (
                        PhysicalMapKey::new(*blake3::hash(&n.to_be_bytes()).as_bytes()),
                        vec![u8::try_from(n % 251).unwrap().saturating_add(1); 17],
                    )
                })
                .collect();
            let map = super::super::CanonicalPhysicalMap::build_with_construction(
                &Identity,
                PhysicalMapDomain::Placement,
                entries,
                construction,
            )
            .unwrap();
            let mut kinds = BTreeSet::new();
            encode_live_root_into(
                PhysicalMapDomain::Placement,
                map.root(),
                map.nodes(),
                map.entry_count(),
                |id, bytes| {
                    let live = &map.nodes()[&id];
                    kinds.insert(match live {
                        PhysicalMapNode::Leaf { .. } => "leaf",
                        PhysicalMapNode::Branch { .. } => "branch",
                        PhysicalMapNode::Page { .. } => "page",
                        PhysicalMapNode::Radix { .. } => "radix",
                    });
                    assert_eq!(
                        bytes,
                        live.encode().unwrap().as_slice(),
                        "{construction:?} count={count}"
                    );
                    assert_eq!(live.identify(&Identity).unwrap(), id);
                    assert_eq!(PhysicalMapNode::decode(bytes).unwrap(), *live);
                    Ok::<_, PhysicalModelError>(())
                },
            )
            .unwrap();
            match construction {
                MapConstruction::LegacyBinary if count == 1 => assert!(kinds.contains("leaf")),
                MapConstruction::LegacyBinary => assert!(kinds.contains("branch")),
                MapConstruction::DenseRadix if count == 1 => assert!(kinds.contains("page")),
                MapConstruction::DenseRadix => assert!(kinds.contains("radix")),
            }
        }
    }
}

#[test]
fn encode_live_allocates_one_owned_encoding_per_visited_node() {
    for construction in [MapConstruction::LegacyBinary, MapConstruction::DenseRadix] {
        for count in [1_u32, 2, 17, 257] {
            let entries = (0..count)
                .map(|n| {
                    (
                        PhysicalMapKey::new(*blake3::hash(&n.to_be_bytes()).as_bytes()),
                        vec![3; 9],
                    )
                })
                .collect();
            let map = super::super::CanonicalPhysicalMap::build_with_construction(
                &Identity,
                PhysicalMapDomain::Placement,
                entries,
                construction,
            )
            .unwrap();
            // encode_live_root_into is the automatic-seal emitter: one owned
            // encoding per visited live node, no rebuild/identify storm.
            let (result, encodings) = PhysicalMapNode::count_encodings_during(|| {
                encode_live_root_into(
                    PhysicalMapDomain::Placement,
                    map.root(),
                    map.nodes(),
                    map.entry_count(),
                    |_, _| Ok::<_, PhysicalModelError>(()),
                )
            });
            let proof = result.unwrap();
            assert_eq!(
                encodings,
                proof.visited().len(),
                "allocated live encodings {construction:?} count={count}"
            );
        }
    }
}

#[test]
fn matches_encoded_does_not_allocate_a_canonical_encoding() {
    for construction in [MapConstruction::LegacyBinary, MapConstruction::DenseRadix] {
        let map = super::super::CanonicalPhysicalMap::build_with_construction(
            &Identity,
            PhysicalMapDomain::Placement,
            vec![
                (PhysicalMapKey::new([1; 32]), vec![7, 8, 9]),
                (PhysicalMapKey::new([2; 32]), vec![4, 5, 6]),
            ],
            construction,
        )
        .unwrap();
        for node in map.nodes().values() {
            let bytes = node.encode().unwrap();
            let (result, encodings) =
                PhysicalMapNode::count_encodings_during(|| node.matches_encoded(&bytes));
            result.unwrap();
            assert_eq!(
                encodings, 0,
                "matches_encoded must not count as an allocated encoding {construction:?}"
            );
        }
    }
}

#[test]
fn proof_sink_matches_encoded_bytes_without_retaining() {
    for construction in [MapConstruction::LegacyBinary, MapConstruction::DenseRadix] {
        let map = super::super::CanonicalPhysicalMap::build_with_construction(
            &Identity,
            PhysicalMapDomain::Placement,
            vec![(PhysicalMapKey::new([1; 32]), vec![7, 8, 9])],
            construction,
        )
        .unwrap();
        let id = map.root().unwrap();
        let bytes = map.nodes()[&id].encode().unwrap();
        let mut sink = ValidationNodes(map.nodes());
        sink.put_encoded(id, &bytes, || {
            panic!("proof sink must not retain owned nodes")
        })
        .unwrap();

        let empty = BTreeMap::new();
        let mut missing = ValidationNodes(&empty);
        assert_eq!(
            missing.put_encoded(id, &bytes, || panic!(
                "proof sink must not retain owned nodes"
            )),
            Err(PhysicalModelError::InvalidMap("missing canonical map node"))
        );

        let mut tampered = map.nodes().clone();
        match tampered.get_mut(&id).unwrap() {
            PhysicalMapNode::Leaf { value, .. } => value[0] ^= 1,
            PhysicalMapNode::Page { entries, .. } => entries[0].1[0] ^= 1,
            other => panic!("expected a leaf or page, got {other:?}"),
        }
        let mut colliding = ValidationNodes(&tampered);
        assert_eq!(
            colliding.put_encoded(id, &bytes, || panic!(
                "proof sink must not retain owned nodes"
            )),
            Err(PhysicalModelError::InvalidMap(
                "physical map-node identity collision"
            ))
        );
    }
}

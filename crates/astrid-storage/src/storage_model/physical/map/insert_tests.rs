use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use super::super::Blake3PhysicalIdentity;
use super::super::PhysicalModelError;
use super::validation::walk_root;
use super::{
    CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode, PhysicalMapNodeId,
    PlacementMap, RepresentationMap,
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

fn prefix_entries(count: u32) -> Vec<(PhysicalMapKey, Vec<u8>)> {
    (0..count)
        .map(|ordinal| {
            let mut key = [0x5A; 32];
            key[28..].copy_from_slice(&ordinal.to_be_bytes());
            (PhysicalMapKey::new(key), ordinal.to_le_bytes().to_vec())
        })
        .collect()
}

fn selector_entries(selectors: &[u8]) -> Vec<(PhysicalMapKey, Vec<u8>)> {
    selectors
        .iter()
        .map(|selector| {
            let mut key = [0; 32];
            key[0] = selector << 4;
            (PhysicalMapKey::new(key), vec![*selector])
        })
        .collect()
}

fn empty_dense(domain: PhysicalMapDomain) -> CanonicalPhysicalMap {
    CanonicalPhysicalMap::build_dense(&Blake3PhysicalIdentity, domain, Vec::new()).unwrap()
}

fn reachable_ids(map: &CanonicalPhysicalMap) -> BTreeSet<PhysicalMapNodeId> {
    walk_root(map.domain(), map.root(), map.nodes())
        .unwrap()
        .visited()
        .clone()
}

fn assert_independent_root(map: &CanonicalPhysicalMap) {
    let count = super::validation::validate_root(
        &Blake3PhysicalIdentity,
        map.domain(),
        map.root(),
        map.nodes(),
    )
    .unwrap();
    assert_eq!(map.entry_count(), count);
    map.prove_root(&Blake3PhysicalIdentity, map.domain())
        .unwrap();
}

fn assert_same_frontier(left: &CanonicalPhysicalMap, right: &CanonicalPhysicalMap) {
    assert_eq!(left.root(), right.root());
    assert_eq!(left.entry_count(), right.entry_count());
    assert_eq!(
        walk_root(left.domain(), left.root(), left.nodes())
            .unwrap()
            .entries(),
        walk_root(right.domain(), right.root(), right.nodes())
            .unwrap()
            .entries()
    );
}

fn sequential_insert(
    domain: PhysicalMapDomain,
    base: &[(PhysicalMapKey, Vec<u8>)],
    additions: &[(PhysicalMapKey, Vec<u8>)],
) -> CanonicalPhysicalMap {
    let mut map =
        CanonicalPhysicalMap::build_dense(&Blake3PhysicalIdentity, domain, base.to_vec()).unwrap();
    for (key, value) in additions {
        map.insert(&Blake3PhysicalIdentity, *key, value.clone())
            .unwrap();
    }
    map
}

fn merge_entries(
    base: &[(PhysicalMapKey, Vec<u8>)],
    additions: &[(PhysicalMapKey, Vec<u8>)],
) -> Vec<(PhysicalMapKey, Vec<u8>)> {
    let mut merged = BTreeMap::new();
    for (key, value) in base.iter().chain(additions) {
        match merged.get(key) {
            Some(existing) if existing == value => {},
            Some(_) => panic!("fixture reuses a key with unequal bytes"),
            None => {
                merged.insert(*key, value.clone());
            },
        }
    }
    merged.into_iter().collect()
}

fn batch_and_count(
    map: &mut CanonicalPhysicalMap,
    additions: Vec<(PhysicalMapKey, Vec<u8>)>,
) -> u64 {
    let before = reachable_ids(map);
    let (inserted, identifies) = PhysicalMapNode::count_identifies_during(|| {
        map.insert_entries(&Blake3PhysicalIdentity, additions)
            .unwrap()
    });
    let after = reachable_ids(map);
    let new_reachable = after.difference(&before).count();
    assert_eq!(
        identifies, new_reachable,
        "batch identify births must equal reachable new nodes"
    );
    inserted
}

#[test]
fn dense_radix_batch_insert_identifies_only_final_reachable_new_nodes() {
    let domain = PhysicalMapDomain::Representation;
    let cases = [
        (Vec::new(), Vec::new()),
        (Vec::new(), sample_entries(0x10, 1)),
        (Vec::new(), sample_entries(0x11, 8)),
        (sample_entries(0x12, 3), sample_entries(0x13, 5)),
        (prefix_entries(2), prefix_entries(8)[2..].to_vec()),
        (sample_entries(0x14, 4), prefix_entries(6)),
        (prefix_entries(1), prefix_entries(9)[1..].to_vec()),
        (sample_entries(0x15, 1), sample_entries(0x15, 1)),
        // The existing key must not leak into the preceding selector's range.
        (selector_entries(&[2]), selector_entries(&[1, 2, 3])),
        (selector_entries(&[2]), selector_entries(&[1, 2])),
        (selector_entries(&[2]), selector_entries(&[2, 3])),
        (prefix_entries(5), prefix_entries(9)),
        (sample_entries(0x16, 64), sample_entries(0x16, 96)),
        // Wrap an existing compressed radix, both outside and inside its prefix.
        (prefix_entries(5), sample_entries(0x17, 32)),
        (
            prefix_entries(5),
            prefix_entries(9)
                .into_iter()
                .chain(sample_entries(0x18, 8))
                .collect(),
        ),
        (Vec::new(), selector_entries(&[3, 1, 2, 2, 1])),
    ];
    for (base, additions) in cases {
        let mut batched =
            CanonicalPhysicalMap::build_dense(&Blake3PhysicalIdentity, domain, base.clone())
                .unwrap();
        let expected_inserted = {
            let existing: BTreeSet<_> = walk_root(domain, batched.root(), batched.nodes())
                .unwrap()
                .entries()
                .iter()
                .map(|(key, _)| *key)
                .collect();
            u64::try_from(
                additions
                    .iter()
                    .map(|(key, _)| *key)
                    .filter(|key| !existing.contains(key))
                    .collect::<BTreeSet<_>>()
                    .len(),
            )
            .unwrap()
        };
        let inserted = batch_and_count(&mut batched, additions.clone());
        assert_eq!(inserted, expected_inserted);
        assert_independent_root(&batched);

        let sequential = sequential_insert(domain, &base, &additions);
        assert_same_frontier(&batched, &sequential);

        let rebuilt = CanonicalPhysicalMap::build_dense(
            &Blake3PhysicalIdentity,
            domain,
            merge_entries(&base, &additions),
        )
        .unwrap();
        assert_same_frontier(&batched, &rebuilt);

        let recovered = CanonicalPhysicalMap::recover(
            &Blake3PhysicalIdentity,
            domain,
            batched.root(),
            batched.nodes().clone(),
        )
        .unwrap();
        assert_same_frontier(&batched, &recovered);
        assert_eq!(
            recovered
                .prove_root(&Blake3PhysicalIdentity, domain)
                .unwrap()
                .entries()
                .len() as u64,
            recovered.entry_count()
        );
    }

    let mut typed = RepresentationMap::build_dense(sample_entries(0x21, 4)).unwrap();
    assert_eq!(typed.insert_entries(sample_entries(0x22, 3)).unwrap(), 3);
    let mut placement = PlacementMap::build_dense(prefix_entries(3)).unwrap();
    assert_eq!(
        placement
            .insert_entries(prefix_entries(5)[3..].to_vec())
            .unwrap(),
        2
    );
    assert!(
        !placement
            .insert(prefix_entries(5)[4].0, prefix_entries(5)[4].1.clone())
            .unwrap()
    );
}

#[test]
fn dense_radix_batch_insert_rejects_collisions_without_committing_root() {
    let mut map = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        sample_entries(0x30, 6),
    )
    .unwrap();
    let root = map.root();
    let count = map.entry_count();
    let nodes_before = map.nodes().len();
    let existing = walk_root(map.domain(), map.root(), map.nodes())
        .unwrap()
        .entries()[0]
        .0;

    assert!(matches!(
        map.insert_entries(&Blake3PhysicalIdentity, vec![(existing, vec![0xFF, 0x00])]),
        Err(PhysicalModelError::InvalidMap(
            "page key has unequal canonical bytes"
        ))
    ));
    assert_eq!(map.root(), root);
    assert_eq!(map.entry_count(), count);
    assert_eq!(map.nodes().len(), nodes_before);

    let mut mixed = sample_entries(0x40, 3);
    mixed.push((existing, vec![1, 2, 3]));
    assert!(map.insert_entries(&Blake3PhysicalIdentity, mixed).is_err());
    assert_eq!(map.root(), root);
    assert_eq!(map.entry_count(), count);
    assert!(map.nodes().len() >= nodes_before);

    let mut duplicates = sample_entries(0x41, 2);
    duplicates.push(duplicates[0].clone());
    duplicates[2].1 = vec![9, 9, 9];
    let before_nodes = map.nodes().clone();
    assert!(matches!(
        map.insert_entries(&Blake3PhysicalIdentity, duplicates),
        Err(PhysicalModelError::InvalidMap(
            "page key has unequal canonical bytes"
        ))
    ));
    assert_eq!(map.root(), root);
    assert_eq!(map.entry_count(), count);
    assert_eq!(map.nodes(), &before_nodes);

    let mut typed = RepresentationMap::build_dense(sample_entries(0x50, 2)).unwrap();
    let typed_root = typed.root().expect("non-empty fixture");
    let faulted = match typed.nodes()[&typed_root].as_ref() {
        PhysicalMapNode::Radix {
            prefix_nibbles,
            prefix,
            child_bitmap,
            children,
            subtree_entries,
            ..
        } => PhysicalMapNode::Radix {
            domain: PhysicalMapDomain::Profile,
            prefix_nibbles: *prefix_nibbles,
            prefix: prefix.clone(),
            child_bitmap: *child_bitmap,
            children: children.clone(),
            subtree_entries: *subtree_entries,
        },
        PhysicalMapNode::Page { entries, .. } => PhysicalMapNode::Page {
            domain: PhysicalMapDomain::Profile,
            entries: entries.clone(),
        },
        other => panic!("unexpected dense root {other:?}"),
    };
    assert!(typed.replace_arena_node_for_fault(typed_root, faulted));
    let typed_count = typed.entry_count();
    assert!(typed.insert_entries(sample_entries(0x51, 1)).is_err());
    assert_eq!(typed.root(), Some(typed_root));
    assert_eq!(typed.entry_count(), typed_count);
}

#[test]
fn dense_radix_batch_insert_retains_source_payload_and_arc_snapshots() {
    let key = key_material(0x61, 1);
    let value = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let pointer = value.as_ptr();
    let mut owned = empty_dense(PhysicalMapDomain::Placement);
    assert!(owned.insert(&Blake3PhysicalIdentity, key, value).unwrap());
    assert_eq!(owned.get(key).unwrap().as_ptr(), pointer);

    let mut batched = empty_dense(PhysicalMapDomain::Placement);
    let payload = vec![0x11, 0x22, 0x33];
    let batch_pointer = payload.as_ptr();
    let batch_key = key_material(0x62, 2);
    batched
        .insert_entries(&Blake3PhysicalIdentity, vec![(batch_key, payload)])
        .unwrap();
    assert_eq!(batched.get(batch_key).unwrap().as_ptr(), batch_pointer);

    let live = RepresentationMap::build_dense(sample_entries(0x63, 8)).unwrap();
    let snapshot = live.clone();
    let mut live = live;
    live.insert_entries(sample_entries(0x64, 4)).unwrap();
    for (id, snap) in snapshot.nodes() {
        let retained = live
            .nodes()
            .get(id)
            .expect("path-copy retains historical nodes");
        assert!(Arc::ptr_eq(snap, retained));
    }
    assert_ne!(live.root(), snapshot.root());
}

#[test]
fn legacy_batch_insert_matches_sequential_root_without_birth_bound() {
    let entries = sample_entries(0x70, 8);
    let additions = sample_entries(0x71, 5);
    let mut batched = RepresentationMap::build(entries.clone()).unwrap();
    let before = batched.nodes().len();
    assert_eq!(batched.insert_entries(additions.clone()).unwrap(), 5);
    let mut sequential = RepresentationMap::build(entries).unwrap();
    for (key, value) in &additions {
        assert!(sequential.insert(*key, value.clone()).unwrap());
    }
    assert_eq!(batched.root(), sequential.root());
    assert_eq!(batched.entry_count(), sequential.entry_count());
    assert!(batched.nodes().len() >= before);
}

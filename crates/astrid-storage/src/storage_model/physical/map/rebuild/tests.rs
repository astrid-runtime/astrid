//! Regressions for lazy `put_encoded` retention on production sinks.
//!
//! Occupied identities compare an already-borrowed live node with the sealed
//! canonical bytes and skip `retain`. Vacant identities retain exactly once.
//! Strengthened `matches_encoded` rejects malformed public enum aliases before
//! byte comparison, so unequal fields cannot pass as an encoded hit.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;

use super::super::super::Blake3PhysicalIdentity;
use super::super::validation::CanonicalNodeSink;
use super::super::{
    PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode, PhysicalMapNodeId, PhysicalModelError,
    radix,
};
use super::NewOnlySink;

fn key(value: u8) -> PhysicalMapKey {
    PhysicalMapKey::new([value; 32])
}

fn dense_entries() -> Vec<(PhysicalMapKey, Vec<u8>)> {
    (1_u8..=8)
        .map(|index| (key(index), vec![index, index.wrapping_add(1)]))
        .collect()
}

/// Forwards a real sink while counting only when that sink invokes `retain`.
struct CountRetaining<'a, S> {
    inner: &'a mut S,
    retains: &'a Cell<usize>,
}

impl<S> CanonicalNodeSink for CountRetaining<'_, S>
where
    S: CanonicalNodeSink,
{
    type Error = S::Error;

    fn put(
        &mut self,
        id: PhysicalMapNodeId,
        canonical_bytes: &[u8],
        node: PhysicalMapNode,
    ) -> Result<(), Self::Error> {
        self.inner.put(id, canonical_bytes, node)
    }

    fn put_encoded<R>(
        &mut self,
        id: PhysicalMapNodeId,
        canonical_bytes: &[u8],
        retain: R,
    ) -> Result<(), Self::Error>
    where
        R: FnOnce() -> Result<PhysicalMapNode, PhysicalModelError>,
    {
        let retains = self.retains;
        self.inner.put_encoded(id, canonical_bytes, || {
            retains.set(retains.get().strict_add(1));
            retain()
        })
    }
}

#[test]
fn identical_dense_rebuild_over_new_only_sink_retains_nothing() {
    let entries = dense_entries();
    let domain = PhysicalMapDomain::Representation;
    let identity = Blake3PhysicalIdentity;

    let first_retains = Cell::new(0);
    let mut arena = BTreeMap::<PhysicalMapNodeId, PhysicalMapNode>::new();
    let first_root = {
        let mut sink = CountRetaining {
            inner: &mut arena,
            retains: &first_retains,
        };
        radix::build(&identity, domain, &entries, &mut sink).unwrap()
    };
    let first_count = first_retains.get();
    assert!(
        first_count > 0,
        "fresh BTreeMap build must retain each new canonical node"
    );
    assert_eq!(
        arena.len(),
        first_count,
        "each retain inserts one arena node"
    );

    let second_retains = Cell::new(0);
    let (second_root, fresh) = {
        let mut new_only = NewOnlySink {
            existing: &arena,
            fresh: BTreeMap::new(),
        };
        let mut sink = CountRetaining {
            inner: &mut new_only,
            retains: &second_retains,
        };
        let root = radix::build(&identity, domain, &entries, &mut sink).unwrap();
        (root, new_only.fresh)
    };

    assert_eq!(second_root, first_root);
    assert!(
        fresh.is_empty(),
        "identical rebuild must not stage duplicate fresh nodes"
    );
    assert_eq!(
        second_retains.get(),
        0,
        "NewOnlySink must not re-materialize already-authenticated bodies"
    );
}

#[test]
fn identical_dense_rebuild_over_occupied_btree_retains_nothing() {
    let entries = dense_entries();
    let domain = PhysicalMapDomain::Placement;
    let identity = Blake3PhysicalIdentity;

    let mut arena = BTreeMap::<PhysicalMapNodeId, PhysicalMapNode>::new();
    let first_root = radix::build(&identity, domain, &entries, &mut arena).unwrap();
    let len_before = arena.len();
    assert!(len_before > 0);

    let retains = Cell::new(0);
    let second_root = {
        let mut sink = CountRetaining {
            inner: &mut arena,
            retains: &retains,
        };
        radix::build(&identity, domain, &entries, &mut sink).unwrap()
    };

    assert_eq!(second_root, first_root);
    assert_eq!(arena.len(), len_before);
    assert_eq!(
        retains.get(),
        0,
        "occupied BTreeMap identities must compare without retain"
    );
}

#[test]
fn new_only_sink_retains_each_new_node_exactly_once() {
    let initial = dense_entries();
    let domain = PhysicalMapDomain::Placement;
    let identity = Blake3PhysicalIdentity;

    let mut existing = BTreeMap::<PhysicalMapNodeId, PhysicalMapNode>::new();
    radix::build(&identity, domain, &initial, &mut existing).unwrap();

    let mut extended = initial;
    extended.push((key(9), vec![9, 10]));
    extended.sort_by_key(|(entry_key, _)| *entry_key);

    let retains = Cell::new(0);
    let (root, mut fresh) = {
        let mut new_only = NewOnlySink {
            existing: &existing,
            fresh: BTreeMap::new(),
        };
        let mut sink = CountRetaining {
            inner: &mut new_only,
            retains: &retains,
        };
        let root = radix::build(&identity, domain, &extended, &mut sink).unwrap();
        (root, new_only.fresh)
    };

    assert_eq!(retains.get(), fresh.len());
    assert!(!fresh.is_empty());
    for id in fresh.keys() {
        assert!(
            !existing.contains_key(id),
            "fresh ids must be absent from the immutable existing arena"
        );
    }
    let mut union = existing;
    union.append(&mut fresh);
    let expected = radix::build(
        &identity,
        domain,
        &extended,
        &mut BTreeMap::<PhysicalMapNodeId, PhysicalMapNode>::new(),
    )
    .unwrap();
    assert_eq!(root, expected);
    assert!(union.contains_key(&root));
}

#[test]
fn new_only_sink_rejects_encoded_identity_collision_without_retaining() {
    let entries = dense_entries();
    let domain = PhysicalMapDomain::Representation;
    let identity = Blake3PhysicalIdentity;

    let mut existing = BTreeMap::<PhysicalMapNodeId, PhysicalMapNode>::new();
    let root = radix::build(&identity, domain, &entries, &mut existing).unwrap();

    let mut tampered = existing.clone();
    match tampered.get_mut(&root).expect("root present") {
        PhysicalMapNode::Radix {
            subtree_entries, ..
        } => *subtree_entries = subtree_entries.saturating_add(1),
        PhysicalMapNode::Page { entries, .. } => entries[0].1[0] ^= 0xff,
        other => panic!("unexpected dense root {other:?}"),
    }

    let retains = Cell::new(0);
    let error = {
        let mut new_only = NewOnlySink {
            existing: &tampered,
            fresh: BTreeMap::new(),
        };
        let mut sink = CountRetaining {
            inner: &mut new_only,
            retains: &retains,
        };
        radix::build(&identity, domain, &entries, &mut sink).unwrap_err()
    };

    assert_eq!(
        error,
        PhysicalModelError::InvalidMap("physical map-node identity collision")
    );
    assert_eq!(retains.get(), 0);
}

#[test]
fn new_only_sink_rejects_malformed_existing_alias_without_retaining() {
    // Malformed public fields can encode identically without representing the
    // same node. Reusing an occupied identity must reject that alias first.
    let mut first = [1; 32];
    first[30..].copy_from_slice(&3_u16.to_le_bytes());
    let children = vec![
        PhysicalMapNodeId::new(first),
        PhysicalMapNodeId::new([2; 32]),
        PhysicalMapNodeId::new([3; 32]),
    ];
    let valid = PhysicalMapNode::radix(
        PhysicalMapDomain::Representation,
        0,
        vec![],
        7,
        children.clone(),
        3,
    )
    .unwrap();
    let (bytes, id) = valid.encode_and_identify(&Blake3PhysicalIdentity).unwrap();

    let mut child_encoding = super::super::super::codec::Encoder::new();
    super::super::super::identity::encode_map_node_id(&mut child_encoding, children[0]);
    let child_encoding = child_encoding.finish();
    let mut prefix = 7_u16.to_le_bytes().to_vec();
    prefix.extend_from_slice(&child_encoding[..child_encoding.len() - 2]);
    let malformed = PhysicalMapNode::Radix {
        domain: PhysicalMapDomain::Representation,
        prefix_nibbles: 0,
        prefix,
        child_bitmap: 3,
        children: children[1..].to_vec(),
        subtree_entries: 3,
    };
    assert_ne!(malformed, valid);
    assert_eq!(malformed.encode().unwrap(), bytes);
    assert!(malformed.matches_encoded(&bytes).is_err());

    let mut existing = BTreeMap::<PhysicalMapNodeId, PhysicalMapNode>::new();
    existing.insert(id, malformed);

    let retains = Cell::new(0);
    let error = {
        let mut new_only = NewOnlySink {
            existing: &existing,
            fresh: BTreeMap::new(),
        };
        let mut sink = CountRetaining {
            inner: &mut new_only,
            retains: &retains,
        };
        sink.put_encoded(id, &bytes, || Ok(valid)).unwrap_err()
    };
    assert!(matches!(error, PhysicalModelError::InvalidMap(_)));
    assert_eq!(retains.get(), 0);
}

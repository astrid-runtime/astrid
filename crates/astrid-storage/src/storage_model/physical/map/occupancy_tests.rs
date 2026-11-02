use std::collections::BTreeSet;

use super::{
    CanonicalPhysicalMap, PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode,
    PhysicalMapNodeId, PhysicalModelError,
};

struct Identity;

impl PhysicalIdentity for Identity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        blake3::derive_key(context, material)
    }
}

struct FixedIdentity([u8; 32]);

impl PhysicalIdentity for FixedIdentity {
    fn identify(&self, _context: &'static str, _material: &[u8]) -> [u8; 32] {
        self.0
    }
}

struct ParentCollides {
    root: PhysicalMapNodeId,
}

impl PhysicalIdentity for ParentCollides {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        match PhysicalMapNode::decode(material) {
            Ok(PhysicalMapNode::Radix { .. } | PhysicalMapNode::Branch { .. }) => {
                *self.root.as_bytes()
            },
            _ => blake3::derive_key(context, material),
        }
    }
}

fn collision() -> PhysicalModelError {
    PhysicalModelError::InvalidMap("physical map-node identity collision")
}

fn dense_entries(count: u8) -> Vec<(PhysicalMapKey, Vec<u8>)> {
    (0..count)
        .map(|ordinal| {
            (
                PhysicalMapKey::new(*blake3::hash(&ordinal.to_le_bytes()).as_bytes()),
                vec![ordinal],
            )
        })
        .collect()
}

#[test]
fn colliding_identity_rejects_without_changing_root_or_pending() {
    let mut map = CanonicalPhysicalMap::build_dense(
        &Identity,
        PhysicalMapDomain::Representation,
        dense_entries(1),
    )
    .unwrap();
    let root = map.root();
    let nodes = map.nodes().clone();
    let mut pending = BTreeSet::new();
    let colliding = FixedIdentity(*root.unwrap().as_bytes());
    assert_eq!(
        map.insert_with_occupancy(
            &colliding,
            PhysicalMapKey::new([0x42; 32]),
            vec![7],
            &mut pending,
        ),
        Err(collision())
    );
    assert_eq!(map.root(), root);
    assert_eq!(map.nodes(), &nodes);
    assert!(pending.is_empty());
}

#[test]
fn failed_parent_insert_keeps_orphan_page_pending_for_reuse() {
    let mut map = CanonicalPhysicalMap::build_dense(
        &Identity,
        PhysicalMapDomain::Representation,
        dense_entries(1),
    )
    .unwrap();
    let root = map.root();
    let before: BTreeSet<_> = map.nodes().keys().copied().collect();
    let mut pending = BTreeSet::new();
    let colliding = ParentCollides {
        root: root.unwrap(),
    };
    let key = PhysicalMapKey::new([0x42; 32]);
    assert_eq!(
        map.insert_with_occupancy(&colliding, key, vec![9], &mut pending),
        Err(collision())
    );
    assert_eq!(map.root(), root);
    assert_eq!(map.entry_count(), 1);
    let orphans: BTreeSet<_> = map
        .nodes()
        .keys()
        .copied()
        .filter(|id| !before.contains(id))
        .collect();
    assert!(!orphans.is_empty());
    assert_eq!(pending, orphans);

    CanonicalPhysicalMap::take_occupancy_reports();
    assert!(
        map.insert_with_occupancy(&Identity, key, vec![9], &mut pending)
            .unwrap()
    );
    assert_ne!(map.root(), root);
    assert!(orphans.iter().all(|id| pending.contains(id)));
    assert!(
        CanonicalPhysicalMap::take_occupancy_reports() > 0,
        "retry must still occupy a vacant parent after the orphan page is shared"
    );
}

#[test]
fn equal_bytes_share_occupancy_without_reporting() {
    let mut map = CanonicalPhysicalMap::build_dense(
        &Identity,
        PhysicalMapDomain::Representation,
        dense_entries(1),
    )
    .unwrap();
    let (key, value) = dense_entries(1).into_iter().next().unwrap();
    let mut pending = BTreeSet::new();
    CanonicalPhysicalMap::take_occupancy_reports();
    assert!(
        !map.insert_with_occupancy(&Identity, key, value, &mut pending)
            .unwrap()
    );
    assert!(pending.is_empty());
    assert_eq!(CanonicalPhysicalMap::take_occupancy_reports(), 0);
}

#[test]
fn rebuild_reports_only_vacant_ids() {
    let mut map = CanonicalPhysicalMap::build_dense(
        &Identity,
        PhysicalMapDomain::Representation,
        dense_entries(8),
    )
    .unwrap();
    let old: BTreeSet<_> = map.nodes().keys().copied().collect();
    let mut pending = BTreeSet::new();
    assert_eq!(
        map.rebuild_with_occupancy(
            &Identity,
            vec![(PhysicalMapKey::new([0x7a; 32]), vec![3])],
            &mut pending,
        )
        .unwrap(),
        1
    );
    let vacant: BTreeSet<_> = map
        .nodes()
        .keys()
        .copied()
        .filter(|id| !old.contains(id))
        .collect();
    assert_eq!(pending, vacant);
    assert!(!vacant.is_empty());
    assert!(vacant.len() < map.nodes().len());
    assert!(old.iter().any(|id| map.nodes().contains_key(id)));
}

#[test]
fn occupancy_reports_follow_the_copied_path() {
    let mut map = CanonicalPhysicalMap::build_dense(
        &Identity,
        PhysicalMapDomain::Representation,
        dense_entries(64),
    )
    .unwrap();
    let before = map.nodes().len();
    let mut pending = BTreeSet::new();
    CanonicalPhysicalMap::take_occupancy_reports();
    assert!(
        map.insert_with_occupancy(
            &Identity,
            PhysicalMapKey::new([0xff; 32]),
            vec![1],
            &mut pending,
        )
        .unwrap()
    );
    let reports = CanonicalPhysicalMap::take_occupancy_reports();
    let grown = map.nodes().len().checked_sub(before).unwrap();
    assert_eq!(reports, grown);
    assert_eq!(pending.len(), grown);
    assert!(reports < before);
}

#[test]
fn public_insert_does_not_build_a_discarded_occupancy_memo() {
    let mut map = CanonicalPhysicalMap::build_dense(
        &Identity,
        PhysicalMapDomain::Representation,
        dense_entries(1),
    )
    .unwrap();
    let before = map.nodes().len();
    CanonicalPhysicalMap::take_occupancy_reports();
    assert!(
        map.insert(&Identity, PhysicalMapKey::new([0xff; 32]), vec![9])
            .unwrap()
    );
    assert!(map.nodes().len() > before);
    assert_eq!(CanonicalPhysicalMap::take_occupancy_reports(), 0);
}

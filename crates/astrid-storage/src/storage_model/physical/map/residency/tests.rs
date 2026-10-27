extern crate std;

use alloc::vec;
use alloc::vec::Vec;

use super::super::{
    CanonicalPhysicalMap, PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNodeId,
};

struct Identity;

impl PhysicalIdentity for Identity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        let mut hash = blake3::Hasher::new_derive_key(context);
        hash.update(material);
        *hash.finalize().as_bytes()
    }
}

#[test]
fn reclaim_preserves_legacy_and_dense_roots_and_accepts_more_insertions() {
    for dense in [false, true] {
        let mut map = if dense {
            CanonicalPhysicalMap::build_dense(&Identity, PhysicalMapDomain::Placement, Vec::new())
        } else {
            CanonicalPhysicalMap::build(&Identity, PhysicalMapDomain::Placement, Vec::new())
        }
        .unwrap();
        let mut entries = Vec::new();
        for sequence in 0_u32..256 {
            let bytes = sequence.to_le_bytes().to_vec();
            let key = PhysicalMapKey::new(*blake3::hash(&bytes).as_bytes());
            map.insert(&Identity, key, bytes.clone()).unwrap();
            entries.push((key, bytes));
        }
        let historical_count = map.nodes.len();
        let root = map.root;
        map.reclaim_unreachable_nodes().unwrap();
        assert!(map.nodes.len() < historical_count);
        assert_eq!(map.root, root);
        assert_eq!(
            CanonicalPhysicalMap::validate_root(&Identity, map.domain, map.root, &map.nodes)
                .unwrap(),
            256,
        );
        for (key, value) in entries {
            assert_eq!(map.get(key), Some(value.as_slice()));
            assert!(!map.insert(&Identity, key, value).unwrap());
        }
        map.insert(&Identity, PhysicalMapKey::new([0x73; 32]), vec![1])
            .unwrap();
        map.reclaim_unreachable_nodes().unwrap();
        assert_eq!(
            map.get(PhysicalMapKey::new([0x73; 32])),
            Some([1].as_slice())
        );
        assert_eq!(map.entry_count(), 257);
    }
}

#[test]
fn incomplete_closure_does_not_partially_reclaim_the_arena() {
    let mut map = CanonicalPhysicalMap::build_dense(
        &Identity,
        PhysicalMapDomain::Profile,
        vec![(PhysicalMapKey::new([1; 32]), vec![1])],
    )
    .unwrap();
    map.root = Some(PhysicalMapNodeId::new([0x71; 32]));
    let before = map.clone();
    assert!(map.reclaim_unreachable_nodes().is_err());
    assert_eq!(map, before);
}

//! Provider failures must preserve canonical roots and remain distinguishable from absence.
use super::*;
struct Blake3PhysicalIdentity;
impl PhysicalIdentity for Blake3PhysicalIdentity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        blake3::derive_key(context, material)
    }
}
use alloc::borrow::Cow;
use alloc::collections::BTreeMap;

mod batch;

#[derive(Debug, PartialEq)]
enum ProviderError {
    Model(PhysicalModelError),
    Io,
}
impl From<PhysicalModelError> for ProviderError {
    fn from(error: PhysicalModelError) -> Self {
        Self::Model(error)
    }
}

struct OwnedNodes {
    nodes: BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    fail_read: bool,
    writes_until_failure: Option<usize>,
}
impl PhysicalMapNodes for OwnedNodes {
    type Error = ProviderError;
    fn node(&self, id: PhysicalMapNodeId) -> Result<Option<Cow<'_, PhysicalMapNode>>, Self::Error> {
        if self.fail_read {
            return Err(ProviderError::Io);
        }
        Ok(self.nodes.get(&id).cloned().map(Cow::Owned))
    }
}
impl PhysicalMapMutNodes for OwnedNodes {
    fn put(&mut self, id: PhysicalMapNodeId, node: PhysicalMapNode) -> Result<(), Self::Error> {
        if let Some(left) = self.writes_until_failure.as_mut() {
            if *left == 0 {
                return Err(ProviderError::Io);
            }
            *left = left.strict_sub(1);
        }
        self.nodes.insert(id, node);
        Ok(())
    }
}
fn key(number: u64) -> PhysicalMapKey {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&number.to_be_bytes());
    PhysicalMapKey::new(bytes)
}
fn provider(map: &CanonicalPhysicalMap) -> OwnedNodes {
    OwnedNodes {
        nodes: map.nodes.clone(),
        fail_read: false,
        writes_until_failure: None,
    }
}
fn maps(dense: bool) -> CanonicalPhysicalMap {
    let entries = (0..64_u64)
        .map(|n| (key(n), n.to_le_bytes().to_vec()))
        .collect();
    if dense {
        CanonicalPhysicalMap::build_dense(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Representation,
            entries,
        )
        .unwrap()
    } else {
        CanonicalPhysicalMap::build(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Representation,
            entries,
        )
        .unwrap()
    }
}

#[test]
fn owned_provider_preserves_both_frozen_constructions_and_every_insertion_root() {
    for dense in [false, true] {
        let mut oracle = maps(dense);
        let mut backed = oracle.with_node_provider(provider(&oracle));
        for n in 0..64_u64 {
            assert_eq!(
                backed.try_get(&Blake3PhysicalIdentity, key(n)).unwrap(),
                oracle.get(key(n)).map(<[u8]>::to_vec)
            );
        }
        assert_eq!(
            backed.try_get(&Blake3PhysicalIdentity, key(999)).unwrap(),
            None
        );
        for n in 64..128_u64 {
            let bytes = n.to_le_bytes().to_vec();
            assert!(
                backed
                    .insert(&Blake3PhysicalIdentity, key(n), bytes.clone())
                    .unwrap()
            );
            oracle
                .insert(&Blake3PhysicalIdentity, key(n), bytes)
                .unwrap();
            assert_eq!(backed.root(), oracle.root());
            assert_eq!(backed.entry_count(), oracle.entry_count());
            assert_eq!(backed.nodes.nodes, oracle.nodes);
        }
    }
}

#[test]
fn provider_io_missing_reachable_node_and_identity_substitution_are_errors() {
    for dense in [false, true] {
        let oracle = maps(dense);
        let mut backed = oracle.with_node_provider(provider(&oracle));
        backed.nodes.fail_read = true;
        assert_eq!(
            backed.try_get(&Blake3PhysicalIdentity, key(0)),
            Err(ProviderError::Io)
        );
        backed.nodes.fail_read = false;
        let root = oracle.root().unwrap();
        let original = backed.nodes.nodes.remove(&root).unwrap();
        assert!(matches!(
            backed.try_get(&Blake3PhysicalIdentity, key(0)),
            Err(ProviderError::Model(_))
        ));
        let substitute = PhysicalMapNode::leaf(PhysicalMapDomain::Representation, key(0), vec![9]);
        backed.nodes.nodes.insert(root, substitute);
        assert!(backed.try_get(&Blake3PhysicalIdentity, key(0)).is_err());
        backed.nodes.nodes.insert(root, original);
        assert_eq!(
            backed.try_get(&Blake3PhysicalIdentity, key(0)).unwrap(),
            Some(0_u64.to_le_bytes().to_vec())
        );
    }
}

#[test]
fn failed_path_copy_retains_old_root_and_retry_matches_the_format_oracle() {
    for dense in [false, true] {
        let mut oracle = maps(dense);
        let mut backed = oracle.with_node_provider(provider(&oracle));
        let old = (backed.root(), backed.entry_count());
        let before_nodes = backed.nodes.nodes.len();
        backed.nodes.writes_until_failure = Some(1);
        assert_eq!(
            backed.insert(&Blake3PhysicalIdentity, key(100), vec![8]),
            Err(ProviderError::Io)
        );
        assert_eq!((backed.root(), backed.entry_count()), old);
        assert_eq!(backed.nodes.nodes.len(), before_nodes + 1);
        assert_eq!(
            backed.try_get(&Blake3PhysicalIdentity, key(100)).unwrap(),
            None
        );
        for n in 0..64_u64 {
            assert!(
                backed
                    .try_get(&Blake3PhysicalIdentity, key(n))
                    .unwrap()
                    .is_some()
            );
        }
        backed.nodes.writes_until_failure = None;
        assert!(
            backed
                .insert(&Blake3PhysicalIdentity, key(100), vec![8])
                .unwrap()
        );
        oracle
            .insert(&Blake3PhysicalIdentity, key(100), vec![8])
            .unwrap();
        assert_eq!(backed.root(), oracle.root());
    }
}

#[test]
fn batch_path_copy_matches_sequential_insertions_and_rolls_back_authority_on_failure() {
    for dense in [false, true] {
        let mut oracle = maps(dense);
        let mut backed = oracle.with_node_provider(provider(&oracle));
        let additions = vec![(key(100), vec![8]), (key(101), vec![9])];
        let old = (backed.root(), backed.entry_count());
        // Let the first insertion finish, then fail in the second path copy.
        let mut probe = oracle.with_node_provider(provider(&oracle));
        probe
            .insert(&Blake3PhysicalIdentity, key(100), vec![8])
            .unwrap();
        let first_writes = probe.nodes.nodes.len() - oracle.nodes.len();
        backed.nodes.writes_until_failure = Some(first_writes + 1);
        assert_eq!(
            backed.insert_entries(&Blake3PhysicalIdentity, additions.clone()),
            Err(ProviderError::Io)
        );
        assert_eq!((backed.root(), backed.entry_count()), old);
        assert!(backed.nodes.nodes.len() > oracle.nodes.len());
        for n in [100, 101] {
            assert_eq!(
                backed.try_get(&Blake3PhysicalIdentity, key(n)).unwrap(),
                None
            );
        }
        backed.nodes.writes_until_failure = None;
        assert_eq!(
            backed
                .insert_entries(&Blake3PhysicalIdentity, additions.clone())
                .unwrap(),
            2
        );
        for (key, value) in additions {
            oracle.insert(&Blake3PhysicalIdentity, key, value).unwrap();
        }
        assert_eq!(backed.root(), oracle.root());
        assert_eq!(backed.entry_count(), oracle.entry_count());
    }
}

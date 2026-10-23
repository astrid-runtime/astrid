//! Bulk publication must emit final canonical paths, with no intermediate roots.
use super::*;
use alloc::collections::BTreeSet;
use core::cell::RefCell;

struct CountedNodes {
    inner: OwnedNodes,
    original: BTreeSet<PhysicalMapNodeId>,
    reads: RefCell<BTreeMap<PhysicalMapNodeId, usize>>,
    writes: usize,
}

impl PhysicalMapNodes for CountedNodes {
    type Error = ProviderError;

    fn node(&self, id: PhysicalMapNodeId) -> Result<Option<Cow<'_, PhysicalMapNode>>, Self::Error> {
        if self.original.contains(&id) {
            let mut reads = self.reads.borrow_mut();
            let count = reads.entry(id).or_default();
            *count = count.strict_add(1);
        }
        self.inner.node(id)
    }
}

impl PhysicalMapMutNodes for CountedNodes {
    fn put(&mut self, id: PhysicalMapNodeId, node: PhysicalMapNode) -> Result<(), Self::Error> {
        self.writes = self.writes.strict_add(1);
        self.inner.put(id, node)
    }
}

fn distributed(number: u64) -> (PhysicalMapKey, Vec<u8>) {
    let bytes = number.to_le_bytes();
    (
        PhysicalMapKey::new(*blake3::hash(&bytes).as_bytes()),
        bytes.to_vec(),
    )
}

#[test]
fn batch_authenticates_bounded_old_paths_and_writes_only_final_nodes() {
    let initial: Vec<_> = (0..2048).map(distributed).collect();
    let additions: Vec<_> = (2048..4096).rev().map(distributed).collect();
    let oracle = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        initial.clone(),
    )
    .unwrap();
    let mut backed = oracle.with_node_provider(CountedNodes {
        inner: provider(&oracle),
        original: oracle.nodes.keys().copied().collect(),
        reads: RefCell::default(),
        writes: 0,
    });
    assert_eq!(
        backed
            .insert_entries(&Blake3PhysicalIdentity, additions.clone())
            .unwrap(),
        2048
    );
    let final_map = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        initial.into_iter().chain(additions).collect(),
    )
    .unwrap();
    assert_eq!(backed.root(), final_map.root());
    assert_eq!(backed.entry_count(), final_map.entry_count());
    // An affected path is authenticated once. Reusing a split page may also
    // probe its immutable identity through the collision-checking store API.
    assert!(
        backed
            .nodes
            .reads
            .borrow()
            .values()
            .all(|count| *count <= 2)
    );
    let expected_new: BTreeSet<_> = final_map
        .nodes
        .keys()
        .filter(|id| !oracle.nodes.contains_key(id))
        .copied()
        .collect();
    let actual_new: BTreeSet<_> = backed
        .nodes
        .inner
        .nodes
        .keys()
        .filter(|id| !oracle.nodes.contains_key(id))
        .copied()
        .collect();
    assert_eq!(
        actual_new, expected_new,
        "batch retained obsolete intermediate paths"
    );
    assert_eq!(backed.nodes.writes, expected_new.len());
    for number in 0..4096 {
        let (key, value) = distributed(number);
        assert_eq!(
            backed.try_get(&Blake3PhysicalIdentity, key).unwrap(),
            Some(value)
        );
    }
}

#[test]
fn every_interrupted_batch_write_keeps_the_old_root_and_retry_is_canonical() {
    let oracle = maps(true);
    let additions: Vec<_> = (64..320).map(distributed).collect();
    let mut completed = oracle.with_node_provider(provider(&oracle));
    completed
        .insert_entries(&Blake3PhysicalIdentity, additions.clone())
        .unwrap();
    let writes = completed.nodes.nodes.len().strict_sub(oracle.nodes.len());
    assert!(writes > 1);
    for cut in 0..writes {
        let mut backed = oracle.with_node_provider(provider(&oracle));
        backed.nodes.writes_until_failure = Some(cut);
        assert_eq!(
            backed.insert_entries(&Blake3PhysicalIdentity, additions.clone()),
            Err(ProviderError::Io)
        );
        assert_eq!(backed.root(), oracle.root());
        assert_eq!(backed.entry_count(), oracle.entry_count());
        for (key, _) in &additions {
            assert_eq!(backed.try_get(&Blake3PhysicalIdentity, *key).unwrap(), None);
        }
        backed.nodes.writes_until_failure = None;
        backed
            .insert_entries(&Blake3PhysicalIdentity, additions.clone())
            .unwrap();
        assert_eq!(backed.root(), completed.root());
        assert_eq!(backed.entry_count(), completed.entry_count());
    }
}

#[test]
fn batch_promotes_prefixes_and_matches_every_sequential_root() {
    let mut oracle = maps(true);
    let mut backed = oracle.with_node_provider(provider(&oracle));
    for range in [64..128, 128..512, 512..1024] {
        let additions: Vec<_> = range.map(distributed).collect();
        backed
            .insert_entries(&Blake3PhysicalIdentity, additions.clone())
            .unwrap();
        for (key, value) in additions {
            oracle.insert(&Blake3PhysicalIdentity, key, value).unwrap();
        }
        assert_eq!(backed.root(), oracle.root());
        assert_eq!(backed.entry_count(), oracle.entry_count());
    }
}

#[test]
fn batch_deduplicates_identical_rows_and_rejects_conflicts_without_publication() {
    let empty = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        Vec::new(),
    )
    .unwrap();
    let mut backed = empty.with_node_provider(provider(&empty));
    assert_eq!(
        backed
            .insert_entries(&Blake3PhysicalIdentity, Vec::new())
            .unwrap(),
        0
    );
    let rows = vec![(key(1), vec![1]), (key(1), vec![1]), (key(2), vec![2])];
    assert_eq!(
        backed
            .insert_entries(&Blake3PhysicalIdentity, rows.clone())
            .unwrap(),
        2
    );
    let authority = (backed.root(), backed.entry_count());
    let nodes = backed.nodes.nodes.len();
    assert_eq!(
        backed
            .insert_entries(&Blake3PhysicalIdentity, rows)
            .unwrap(),
        0
    );
    assert_eq!(backed.nodes.nodes.len(), nodes);
    for rows in [
        vec![(key(3), vec![3]), (key(3), vec![4])],
        vec![(key(4), vec![4]), (key(1), vec![9])],
    ] {
        assert!(
            backed
                .insert_entries(&Blake3PhysicalIdentity, rows)
                .is_err()
        );
        assert_eq!((backed.root(), backed.entry_count()), authority);
        assert_eq!(
            backed.try_get(&Blake3PhysicalIdentity, key(4)).unwrap(),
            None
        );
    }
}

#[test]
fn batch_provider_failure_and_count_overflow_preserve_old_authority() {
    let oracle = maps(true);
    let mut backed = oracle.with_node_provider(provider(&oracle));
    let authority = (backed.root(), backed.entry_count());
    backed.nodes.fail_read = true;
    assert_eq!(
        backed.insert_entries(&Blake3PhysicalIdentity, vec![distributed(999)]),
        Err(ProviderError::Io)
    );
    assert_eq!((backed.root(), backed.entry_count()), authority);
    backed.nodes.fail_read = false;
    backed.entry_count = u64::MAX;
    assert!(
        backed
            .insert_entries(&Blake3PhysicalIdentity, vec![distributed(999)])
            .is_err()
    );
    assert_eq!(backed.root(), authority.0);
    assert_eq!(backed.entry_count(), u64::MAX);
    assert_eq!(
        backed
            .try_get(&Blake3PhysicalIdentity, distributed(999).0)
            .unwrap(),
        None
    );
}

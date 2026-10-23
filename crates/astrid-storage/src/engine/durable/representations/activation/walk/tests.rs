use super::*;
use crate::storage_model::{CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapKey};
use std::cell::RefCell;
use std::collections::BTreeMap;

mod reference;

struct CountedPresence {
    values: BTreeSet<PhysicalMapNodeId>,
    reads: RefCell<BTreeMap<PhysicalMapNodeId, usize>>,
}
impl NodePresence for CountedPresence {
    fn has_node(&self, id: &PhysicalMapNodeId) -> Result<bool, DurableError> {
        increment(&mut self.reads.borrow_mut(), *id);
        Ok(self.values.contains(id))
    }
}
#[derive(Default)]
struct CountedProofs {
    values: BTreeSet<PhysicalMapNodeId>,
    reads: RefCell<BTreeMap<PhysicalMapNodeId, usize>>,
    writes: BTreeMap<PhysicalMapNodeId, usize>,
}
impl CompleteNodes for CountedProofs {
    fn complete(&self, id: &PhysicalMapNodeId) -> Result<bool, DurableError> {
        increment(&mut self.reads.borrow_mut(), *id);
        Ok(self.values.contains(id))
    }
    fn remember(&mut self, id: PhysicalMapNodeId) -> Result<(), DurableError> {
        increment(&mut self.writes, id);
        self.values.insert(id);
        Ok(())
    }
}
struct CountedMap<'a> {
    map: &'a CanonicalPhysicalMap,
    reads: RefCell<BTreeMap<PhysicalMapNodeId, usize>>,
}
impl MapView for CountedMap<'_> {
    fn view_root(&self) -> Option<PhysicalMapNodeId> {
        self.map.root()
    }
    fn view_count(&self) -> u64 {
        self.map.entry_count()
    }
    fn view_node(&self, id: PhysicalMapNodeId) -> Result<PhysicalMapNode, DurableError> {
        increment(&mut self.reads.borrow_mut(), id);
        self.map.view_node(id)
    }
}
fn maps() -> [CanonicalPhysicalMap; 2] {
    let entries: Vec<_> = (0_u32..64)
        .map(|i| {
            (
                PhysicalMapKey::new(*blake3::hash(&i.to_le_bytes()).as_bytes()),
                i.to_le_bytes().to_vec(),
            )
        })
        .collect();
    [
        CanonicalPhysicalMap::build(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Representation,
            entries.clone(),
        )
        .unwrap(),
        CanonicalPhysicalMap::build_dense(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Representation,
            entries,
        )
        .unwrap(),
    ]
}
fn increment(counts: &mut BTreeMap<PhysicalMapNodeId, usize>, id: PhysicalMapNodeId) {
    let count = counts.entry(id).or_default();
    *count = count.strict_add(1);
}

fn assert_once(reads: &BTreeMap<PhysicalMapNodeId, usize>, count: usize) {
    assert_eq!(reads.len(), count);
    assert!(
        reads.values().all(|value| *value == 1),
        "repeated authenticated lookup: {reads:?}"
    );
}

#[test]
fn each_unknown_node_is_read_and_proven_once_per_traversal() {
    for map in maps() {
        let counted = CountedMap {
            map: &map,
            reads: RefCell::default(),
        };
        let durable = CountedPresence {
            values: map.nodes().keys().copied().collect(),
            reads: RefCell::default(),
        };
        let mut proofs = CountedProofs::default();
        let mut metadata = Vec::new();
        let mut appended = BTreeSet::new();
        let visited = append_new_reachable_map_nodes(
            &mut metadata,
            &counted,
            &durable,
            &mut appended,
            &mut proofs,
        )
        .unwrap();
        assert_eq!(visited, map.nodes().len());
        assert!(metadata.is_empty() && appended.is_empty());
        assert_eq!(proofs.values, durable.values);
        assert_once(&proofs.reads.borrow(), visited);
        assert_once(&durable.reads.borrow(), visited);
        assert_once(&counted.reads.borrow(), visited);
        assert_once(&proofs.writes, visited);
    }
}

#[test]
fn traversal_results_match_reference_for_partial_durable_closures() {
    for map in maps() {
        for mask in 0..8 {
            let durable: BTreeSet<_> = map
                .nodes()
                .keys()
                .enumerate()
                .filter(|(i, _)| mask & (1 << (i % 3)) != 0)
                .map(|(_, id)| *id)
                .collect();
            let initial: BTreeSet<_> = map
                .nodes()
                .iter()
                .filter(|(id, node)| {
                    durable.contains(id)
                        && matches!(
                            node,
                            PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. }
                        )
                })
                .map(|(id, _)| *id)
                .collect();
            let mut actual_proofs = initial.clone();
            let mut expected_proofs = initial;
            let pending: BTreeSet<_> = map
                .nodes()
                .keys()
                .enumerate()
                .filter(|(i, _)| i % 7 == 0)
                .map(|(_, id)| *id)
                .collect();
            let mut actual_appended = pending.clone();
            let mut expected_appended = pending;
            let mut actual = Vec::new();
            let mut expected = Vec::new();
            let visited = append_new_reachable_map_nodes(
                &mut actual,
                &map,
                &durable,
                &mut actual_appended,
                &mut actual_proofs,
            )
            .unwrap();
            let old_visited = reference::append(
                &mut expected,
                &map,
                &durable,
                &mut expected_appended,
                &mut expected_proofs,
            )
            .unwrap();
            assert_eq!(visited, old_visited);
            assert_eq!(actual_appended, expected_appended);
            assert_eq!(actual_proofs, expected_proofs);
            assert_eq!(
                actual
                    .iter()
                    .map(|f| f.encode().unwrap())
                    .collect::<Vec<_>>(),
                expected
                    .iter()
                    .map(|f| f.encode().unwrap())
                    .collect::<Vec<_>>()
            );
        }
    }
}

//! Both frozen constructions must read each checkpoint node once.
use super::*;
use crate::storage_model::PhysicalMapDomain;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

struct CountedView<'a> {
    map: &'a CanonicalPhysicalMap,
    reads: RefCell<BTreeMap<PhysicalMapNodeId, usize>>,
    fail: Cell<Option<PhysicalMapNodeId>>,
}

impl MapView for CountedView<'_> {
    fn view_root(&self) -> Option<PhysicalMapNodeId> {
        self.map.root()
    }
    fn view_count(&self) -> u64 {
        self.map.entry_count()
    }
    fn view_node(&self, id: PhysicalMapNodeId) -> Result<PhysicalMapNode, DurableError> {
        let mut reads = self.reads.borrow_mut();
        let count = reads.entry(id).or_default();
        *count = count.strict_add(1);
        if self.fail.get() == Some(id) {
            return Err(DurableError::InvalidRepresentationState(
                "injected node read failure",
            ));
        }
        self.map.view_node(id)
    }
}

fn fixture(dense: bool, count: u64) -> CanonicalPhysicalMap {
    let entries = (0..count)
        .map(|number| {
            let bytes = number.to_be_bytes();
            (
                PhysicalMapKey::new(*blake3::hash(&bytes).as_bytes()),
                bytes.to_vec(),
            )
        })
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
fn checkpoint_walk_authenticates_each_node_once_and_rereads_on_the_next_walk() {
    for dense in [false, true] {
        let map = fixture(dense, 2048);
        let view = CountedView {
            map: &map,
            reads: RefCell::default(),
            fail: Cell::new(None),
        };
        let mut found = BTreeMap::new();
        visit_nodes(&view, |node| {
            let id = node.identify(&Blake3PhysicalIdentity)?;
            assert!(found.insert(id, node).is_none());
            Ok(())
        })
        .unwrap();
        assert_eq!(&found, map.nodes());
        assert_eq!(view.reads.borrow().len(), map.nodes().len());
        assert!(view.reads.borrow().values().all(|n| *n == 1));
        let child = map
            .nodes()
            .keys()
            .find(|id| Some(**id) != map.root())
            .copied()
            .unwrap();
        view.fail.set(Some(child));
        assert!(visit_nodes(&view, |_| Ok(())).is_err());
        view.fail.set(None);
        assert!(
            visit_nodes(&view, |_| Err(DurableError::InvalidRepresentationState(
                "visitor failure"
            )))
            .is_err()
        );
        visit_nodes(&view, |_| Ok(())).unwrap();
    }
}

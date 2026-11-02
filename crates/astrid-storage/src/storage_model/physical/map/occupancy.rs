//! Vacant occupancy reporting for the durable unpersisted-map-node memo.

use alloc::collections::btree_map::Entry;
use alloc::collections::{BTreeMap, BTreeSet};

use super::{PhysicalIdentity, PhysicalMapNode, PhysicalMapNodeId, PhysicalModelError};

pub(super) struct Occupancy<'a> {
    pub nodes: &'a mut BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    pub pending: Option<&'a mut BTreeSet<PhysicalMapNodeId>>,
}

#[cfg(test)]
std::thread_local! {
    static OCCUPANCY_REPORTS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn take_occupancy_reports() -> usize {
    OCCUPANCY_REPORTS.with(|count| count.replace(0))
}

pub(super) fn occupy_node<I: PhysicalIdentity>(
    identity: &I,
    occupancy: Occupancy<'_>,
    node: PhysicalMapNode,
) -> Result<PhysicalMapNodeId, PhysicalModelError> {
    let id = node.identify(identity)?;
    match occupancy.nodes.entry(id) {
        Entry::Vacant(slot) => {
            slot.insert(node);
            if let Some(pending) = occupancy.pending {
                observe_vacant(pending, id);
            }
            Ok(id)
        },
        Entry::Occupied(existing) if existing.get() == &node => Ok(id),
        Entry::Occupied(_) => Err(PhysicalModelError::InvalidMap(
            "physical map-node identity collision",
        )),
    }
}

pub(super) fn observe_vacant(pending: &mut BTreeSet<PhysicalMapNodeId>, id: PhysicalMapNodeId) {
    pending.insert(id);
    #[cfg(test)]
    OCCUPANCY_REPORTS.with(|count| count.set(count.get().strict_add(1)));
}

pub(super) fn report_new_occupancy(
    old: &BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    new: &BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    pending: &mut BTreeSet<PhysicalMapNodeId>,
) {
    for id in new.keys() {
        if !old.contains_key(id) {
            observe_vacant(pending, *id);
        }
    }
}

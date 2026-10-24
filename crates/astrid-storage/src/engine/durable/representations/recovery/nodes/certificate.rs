//! A closed admitted graph proves every present root has a complete closure.
//!
//! This is an optional acceleration: any missing referenced child discards the
//! certificate and leaves journal validation and tail repair to ordinary walks.
use super::{
    ClosureProof, DurableError, DurableFile, LocationIndexMemoryBudget, ObjectId, PagedLocations,
    PhysicalMapNode, RebuildLocations, RecoveryLimits,
};
use crate::engine::durable::locations::LocationLookup;

pub(super) struct ClosureCertificate {
    source_epoch: u64,
}

impl ClosureCertificate {
    pub(super) fn matches(&self, source: &PagedLocations) -> bool {
        self.source_epoch == source.runs_epoch()
    }

    pub(super) fn build(
        file: &DurableFile,
        source: &PagedLocations,
        limits: RecoveryLimits,
        budget: LocationIndexMemoryBudget,
    ) -> Result<Option<Self>, DurableError> {
        // The otherwise unused private staging quarter holds reference witnesses.
        // These locations identify authenticated PARENT frames, never child bodies.
        // They are private to this join and never enter the admitted node locator.
        let mut references = RebuildLocations::new(budget.durable_entries());
        for entry in source.locations() {
            let (id, location) = entry?;
            let node = super::super::super::cold::read_node(
                file,
                limits,
                super::map_node_id(*id.as_bytes()),
                location,
            )?;
            let mut child = |id: crate::storage_model::PhysicalMapNodeId| {
                references.push(
                    ObjectId::new(*id.as_bytes()),
                    location,
                    ClosureProof::Unknown,
                )
            };
            match node {
                PhysicalMapNode::Branch { zero, one, .. } => {
                    child(zero)?;
                    child(one)?;
                },
                PhysicalMapNode::Radix { children, .. } => {
                    for id in children {
                        child(id)?;
                    }
                },
                PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => {},
            }
        }
        let (references, _) = references.finish()?;
        let closed = references_present(source, &references)?;
        Ok(closed.then_some(Self {
            source_epoch: source.runs_epoch(),
        }))
    }
}

fn references_present(
    source: &PagedLocations,
    references: &PagedLocations,
) -> Result<bool, DurableError> {
    let mut admitted = source.locations();
    let mut current = admitted.next().transpose()?;
    let mut closed = true;
    for entry in references.locations() {
        let (child, _) = entry?;
        while current.is_some_and(|(id, _)| id < child) {
            current = admitted.next().transpose()?;
        }
        if current.is_none_or(|(id, _)| id != child) {
            closed = false;
        }
    }
    // Even a missing reference cannot hide later scratch damage. Drain both
    // authenticated streams completely before publishing any certificate.
    for entry in admitted {
        entry?;
    }
    Ok(closed)
}

#[cfg(test)]
mod tests;

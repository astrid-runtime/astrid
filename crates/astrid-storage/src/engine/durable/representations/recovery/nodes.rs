//! Recovery owns frame locations, never a history-sized decoded payload arena.

use super::super::super::format::frame_checksum;
use super::super::super::locations::{LocationLookup, PagedLocations};
use super::super::format::{Blake3PhysicalIdentity, METADATA_MAGIC, MetadataFrame, map_node_id};
use super::super::{
    ArenaLocation, ColdNodes, DurableError, DurableFile, LocationIndexMemoryBudget, RecoveryLimits,
    io_error,
};
use crate::storage_model::{
    CanonicalPhysicalMap, ObjectId, PhysicalMapNode, PhysicalMapNodeId, PhysicalMapNodes,
};
use std::borrow::Cow;

pub(in super::super) struct RecoveredNodes {
    file: DurableFile,
    locations: PagedLocations,
    limits: RecoveryLimits,
    budget: LocationIndexMemoryBudget,
}

impl RecoveredNodes {
    pub(super) fn new(
        file: &DurableFile,
        limits: RecoveryLimits,
        budget: LocationIndexMemoryBudget,
    ) -> Result<Self, DurableError> {
        // Frame lookups use positioned I/O. A native try_clone may share its
        // seek cursor, so no reader here is allowed to seek the scan handle.
        Ok(Self {
            file: file
                .try_clone()
                .map_err(|e| io_error("clone metadata recovery reader", e))?,
            locations: PagedLocations::new(budget.durable_entries()),
            limits,
            budget,
        })
    }

    pub(super) fn admit(
        &mut self,
        offset: u64,
        payload: &[u8],
        frame: &MetadataFrame,
    ) -> Result<(), DurableError> {
        let node = PhysicalMapNode::decode(&frame.value)?;
        let id = node.identify(&Blake3PhysicalIdentity)?;
        if id != map_node_id(frame.identity) {
            return Err(DurableError::InvalidRepresentationState(
                "metadata identity does not match canonical value",
            ));
        }
        // Newest-wins locator merging is not a collision proof: compare the
        // authenticated previous canonical body before replacing its location.
        if let Some(previous) = self.node(id)?
            && previous.as_ref() != &node
        {
            return Err(DurableError::InvalidRepresentationState(
                "physical metadata identity collision",
            ));
        }
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
        self.locations.insert(
            ObjectId::new(*id.as_bytes()),
            ArenaLocation {
                offset,
                payload_len,
                checksum: frame_checksum(METADATA_MAGIC, payload_len, payload),
            },
        )
    }

    pub(in super::super) fn into_cold(
        self,
        maps: &[&CanonicalPhysicalMap],
    ) -> Result<ColdNodes, DurableError> {
        ColdNodes::from_recovered_locations(
            self.file,
            self.locations,
            self.limits,
            self.budget,
            maps,
        )
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.locations.len()
    }

    #[cfg(test)]
    pub(super) fn resident_capacity_bytes(&self) -> usize {
        self.locations.resident_capacity_bytes()
    }
}

impl PhysicalMapNodes for RecoveredNodes {
    type Error = DurableError;
    fn node(
        &self,
        id: PhysicalMapNodeId,
    ) -> Result<Option<Cow<'_, PhysicalMapNode>>, DurableError> {
        let Some(location) = self.locations.location(ObjectId::new(*id.as_bytes()))? else {
            return Ok(None);
        };
        super::super::cold::read_node(&self.file, self.limits, id, location)
            .map(|node| Some(Cow::Owned(node)))
    }
}

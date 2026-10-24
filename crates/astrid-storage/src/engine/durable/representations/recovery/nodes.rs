//! Recovery owns frame locations, never a history-sized decoded payload arena.

use super::super::super::format::frame_checksum;
use super::super::super::locations::{
    AuthenticatedPageMemo, ClosureProof, PagedLocations, RebuildLocations,
};
use super::super::format::{Blake3PhysicalIdentity, METADATA_MAGIC, MetadataFrame, map_node_id};
use super::super::{
    ArenaLocation, ColdNodes, DurableError, DurableFile, LocationIndexMemoryBudget, RecoveryLimits,
    io_error,
};
use crate::storage_model::{
    CanonicalPhysicalMap, ObjectId, PhysicalMapNode, PhysicalMapNodeId, PhysicalMapNodes,
};
use std::borrow::Cow;
use std::cell::RefCell;

mod memo;
use memo::CompleteMemo;

pub(in super::super) struct RecoveredNodes {
    file: DurableFile,
    locations: PagedLocations,
    limits: RecoveryLimits,
    budget: LocationIndexMemoryBudget,
    // PhysicalMapNodes lends immutable access; only disposable authenticated
    // page evidence changes here. Index mutations invalidate its run epoch.
    page_memo: RefCell<AuthenticatedPageMemo>,
    complete_memo: RefCell<CompleteMemo>,
}

/// No lookup or journal authority can observe a partially admitted index.
pub(super) struct NodeAdmission {
    file: DurableFile,
    locations: RebuildLocations,
    limits: RecoveryLimits,
    budget: LocationIndexMemoryBudget,
}

impl NodeAdmission {
    pub(super) fn new(
        file: &DurableFile,
        limits: RecoveryLimits,
        budget: LocationIndexMemoryBudget,
    ) -> Result<Self, DurableError> {
        // All readers use positioned I/O: native clones may share the scan
        // handle's seek cursor, so duplicate validation must never seek it.
        let reader = file
            .try_clone()
            .map_err(|e| io_error("clone metadata recovery reader", e))?;
        let duplicate_reader = file
            .try_clone()
            .map_err(|e| io_error("clone duplicate recovery reader", e))?;
        let locations =
            RebuildLocations::checked(budget.durable_entries(), move |id, newer, older| {
                // Every superseded location is freshly authenticated before it can
                // disappear from the private merge. Equal hashes alone are not a
                // canonical-body collision proof.
                let id = map_node_id(*id.as_bytes());
                let previous = super::super::cold::read_node(&duplicate_reader, limits, id, older)?;
                let replacement =
                    super::super::cold::read_node(&duplicate_reader, limits, id, newer)?;
                if previous != replacement {
                    return Err(DurableError::InvalidRepresentationState(
                        "physical metadata identity collision",
                    ));
                }
                Ok(())
            });
        Ok(Self {
            file: reader,
            locations,
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
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
        self.locations.push(
            ObjectId::new(*id.as_bytes()),
            ArenaLocation {
                offset,
                payload_len,
                checksum: frame_checksum(METADATA_MAGIC, payload_len, payload),
            },
            ClosureProof::Unknown,
        )
    }

    pub(super) fn finish(self) -> Result<RecoveredNodes, DurableError> {
        let (locations, _) = self.locations.finish()?;
        Ok(RecoveredNodes {
            file: self.file,
            locations,
            limits: self.limits,
            budget: self.budget,
            page_memo: RefCell::default(),
            complete_memo: RefCell::new(CompleteMemo::new(self.budget)?),
        })
    }
}

impl RecoveredNodes {
    pub(in super::super) fn reset_proofs(&mut self) -> Result<(), DurableError> {
        // Phase boundaries discard journal reachability evidence and collapse
        // fragmented runs without dropping any historical location. Canonical
        // cold proofs are rebuilt independently from the recovered active maps.
        self.complete_memo.get_mut().clear();
        self.locations.clear_proofs()?;
        *self.page_memo.get_mut() = AuthenticatedPageMemo::default();
        Ok(())
    }

    pub(in super::super) fn into_cold(
        self,
        maps: &[&CanonicalPhysicalMap],
    ) -> Result<ColdNodes, DurableError> {
        // The borrowed staging partition must be free before cold mutation
        // state can use it. Journal memo entries never become canonical proofs.
        drop(self.complete_memo);
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

impl super::super::activation::CompleteNodes for RecoveredNodes {
    fn complete(&self, id: &PhysicalMapNodeId) -> Result<bool, DurableError> {
        let mut memo = self.complete_memo.borrow_mut();
        if self.locations.failed() {
            memo.clear();
            return Err(DurableError::InvalidRepresentationState(
                "failed recovery locator",
            ));
        }
        // A replacement run must be authenticated again, even for a previously
        // complete ID. Reuse never outlives the existing page-evidence epoch.
        memo.sync(self.locations.runs_epoch());
        if memo.contains(*id) {
            return Ok(true);
        }
        match self.locations.closure_proven_memo(
            ObjectId::new(*id.as_bytes()),
            &mut self.page_memo.borrow_mut(),
        ) {
            Ok(true) => {
                memo.insert(*id);
                Ok(true)
            },
            Ok(false) => Ok(false),
            Err(error) => {
                memo.clear();
                Err(error)
            },
        }
    }

    fn remember(&mut self, id: PhysicalMapNodeId) -> Result<(), DurableError> {
        // These bits prove recovery reachability only. into_cold rebuilds every
        // bit from canonically validated active maps, never from this evidence.
        let result = self
            .locations
            .mark_proven_memo(ObjectId::new(*id.as_bytes()), self.page_memo.get_mut());
        let memo = self.complete_memo.get_mut();
        memo.sync(self.locations.runs_epoch());
        if result.is_err() {
            memo.clear();
        }
        result
    }
}

impl PhysicalMapNodes for RecoveredNodes {
    type Error = DurableError;
    fn node(
        &self,
        id: PhysicalMapNodeId,
    ) -> Result<Option<Cow<'_, PhysicalMapNode>>, DurableError> {
        let Some(location) = self.locations.location_memo(
            ObjectId::new(*id.as_bytes()),
            &mut self.page_memo.borrow_mut(),
        )?
        else {
            return Ok(None);
        };
        super::super::cold::read_node(&self.file, self.limits, id, location)
            .map(|node| Some(Cow::Owned(node)))
    }
}

#[cfg(test)]
mod tests;

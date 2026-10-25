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

mod proofs;
use proofs::JournalProofs;
mod certificate;
use certificate::ClosureCertificate;

pub(in super::super) struct RecoveredNodes {
    file: DurableFile,
    locations: PagedLocations,
    limits: RecoveryLimits,
    budget: LocationIndexMemoryBudget,
    // PhysicalMapNodes lends immutable access; only disposable authenticated
    // page evidence changes here. Index mutations invalidate its run epoch.
    page_memo: RefCell<AuthenticatedPageMemo>,
    proofs: RefCell<JournalProofs>,
    certificate: Option<ClosureCertificate>,
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
        let proofs = JournalProofs::new(self.budget, locations.runs_epoch());
        Ok(RecoveredNodes {
            file: self.file,
            locations,
            limits: self.limits,
            budget: self.budget,
            page_memo: RefCell::default(),
            proofs: RefCell::new(proofs),
            certificate: None,
        })
    }
}

impl RecoveredNodes {
    pub(in super::super) fn reset_proofs(&mut self) -> Result<(), DurableError> {
        // Phase boundaries discard journal reachability evidence and collapse
        // fragmented runs without dropping any historical location. Canonical
        // cold proofs are rebuilt independently from the recovered active maps.
        self.proofs.get_mut().require_healthy(&self.locations)?;
        self.certificate = None;
        // Discard journal evidence before rebuilding the admitted locator.
        *self.proofs.get_mut() = JournalProofs::new(self.budget, self.locations.runs_epoch());
        self.locations
            .clear_proofs()
            .inspect_err(|_| self.proofs.get_mut().fence())?;
        *self.proofs.get_mut() = JournalProofs::new(self.budget, self.locations.runs_epoch());
        *self.page_memo.get_mut() = AuthenticatedPageMemo::default();
        Ok(())
    }

    pub(super) fn certify_closures(&mut self) -> Result<(), DurableError> {
        self.proofs.get_mut().require_healthy(&self.locations)?;
        self.certificate = None;
        // Release any prior journal staging loan before reference witnesses use
        // that partition. A certificate is published only after the join ends.
        *self.proofs.get_mut() = JournalProofs::new(self.budget, self.locations.runs_epoch());
        let result =
            ClosureCertificate::build(&self.file, &self.locations, self.limits, self.budget);
        if result.is_err() {
            self.proofs.get_mut().fence();
        }
        self.certificate = result?;
        Ok(())
    }

    pub(in super::super) fn into_cold(
        self,
        maps: &[&CanonicalPhysicalMap],
    ) -> Result<ColdNodes, DurableError> {
        // The borrowed staging partition must be free before cold mutation
        // state can use it. Journal memo entries never become canonical proofs.
        self.proofs.borrow().require_healthy(&self.locations)?;
        drop(self.proofs);
        ColdNodes::from_recovered_locations(
            self.file,
            self.locations,
            self.limits,
            self.budget,
            maps,
        )
    }

    #[cfg(test)]
    pub(super) fn has_matching_certificate(&self) -> bool {
        self.certificate
            .as_ref()
            .is_some_and(|proof| proof.matches(&self.locations))
    }

    pub(in super::super) fn len(&self) -> usize {
        self.locations.len()
    }

    #[cfg(test)]
    pub(super) fn resident_capacity_bytes(&self) -> usize {
        self.locations.resident_capacity_bytes()
    }
}

impl super::super::activation::CompleteNodes for RecoveredNodes {
    fn complete(&self, id: &PhysicalMapNodeId) -> Result<bool, DurableError> {
        self.proofs.borrow().require_healthy(&self.locations)?;
        if self
            .certificate
            .as_ref()
            .is_some_and(|proof| proof.matches(&self.locations))
        {
            return self
                .locations
                .location_memo(
                    ObjectId::new(*id.as_bytes()),
                    &mut self.page_memo.borrow_mut(),
                )
                .map(|location| location.is_some());
        }
        self.proofs.borrow_mut().complete(
            ObjectId::new(*id.as_bytes()),
            &self.locations,
            &mut self.page_memo.borrow_mut(),
        )
    }

    fn remember(&mut self, id: PhysicalMapNodeId) -> Result<(), DurableError> {
        // Journal reachability never modifies the admitted node locator and
        // never becomes the canonical proof table handed to cold mutation.
        self.proofs.get_mut().remember(
            ObjectId::new(*id.as_bytes()),
            &self.locations,
            self.page_memo.get_mut(),
        )
    }
}

impl PhysicalMapNodes for RecoveredNodes {
    type Error = DurableError;
    fn node(
        &self,
        id: PhysicalMapNodeId,
    ) -> Result<Option<Cow<'_, PhysicalMapNode>>, DurableError> {
        self.proofs.borrow().require_healthy(&self.locations)?;
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

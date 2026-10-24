//! Physical-node values stay in their existing canonical metadata frames.
//!
//! Three active map views share one complete paged locator. Path copying writes
//! new immutable nodes into anonymous staging under the existing mutation lock.
//! Only final reachable nodes enter metadata; authority still requires its flush
//! and the existing journal CAS. Batch intermediates never become durable junk.

use parking_lot::Mutex;
use std::borrow::Cow;
use std::sync::Arc;

use super::super::format::{frame_checksum, read_frame_at};
use super::super::locations::{
    AuthenticatedPageMemo, ClosureProof, LocationIndexMemoryBudget, LocationLookup, PagedLocations,
};
use super::super::{ArenaLocation, DurableError, File, RecoveryLimits, append_frame, io_error};
use super::format::{
    Blake3PhysicalIdentity, METADATA_FILE, METADATA_MAGIC, MetadataFrame, MetadataKind,
};
use crate::storage_model::{
    BackedPhysicalMap, CanonicalPhysicalMap, ObjectId, PhysicalMapMutNodes, PhysicalMapNode,
    PhysicalMapNodeId, PhysicalMapNodes,
};
use std::cell::RefCell;
use std::rc::Rc;

pub(super) type ColdPhysicalMap = BackedPhysicalMap<ColdNodes>;

#[derive(Clone, Debug)]
pub(super) struct ColdNodes(Arc<Mutex<NodeArena>>);

#[derive(Debug)]
struct NodeArena {
    file: File,
    locations: PagedLocations,
    limits: RecoveryLimits,
    failed: bool,
    staged: Option<StagedNodes>,
    budget: LocationIndexMemoryBudget,
}

#[derive(Debug)]
struct StagedNodes {
    file: File,
    locations: PagedLocations,
}

/// Page proofs live only for the bounded traversal that owns this provider.
/// Decoded node bodies are never retained and remain authenticated on each read.
pub(super) struct ColdMemoNodes<'a> {
    cold: &'a ColdNodes,
    memo: Rc<RefCell<AuthenticatedPageMemo>>,
}

impl ColdNodes {
    #[cfg(test)]
    pub(super) fn truncate_oldest_test_run(&self) {
        self.0.lock().locations.truncate_oldest_test_run();
    }

    #[cfg(test)]
    pub(super) fn test_spilled_run_count(&self) -> usize {
        self.0.lock().locations.test_spilled_run_count()
    }

    #[cfg(test)]
    pub(super) fn truncate_test_run(&self) {
        self.0.lock().locations.truncate_test_run();
    }

    /// Consolidate only process-local lookup machinery; durable authority stays
    /// untouched and checkpoint recovery independently verifies its replacement.
    pub(super) fn prepare_checkpoint_walk(&self) -> Result<(), DurableError> {
        let mut arena = self.0.lock();
        if arena.failed {
            return Err(DurableError::InvalidRepresentationState(
                "cannot checkpoint failed physical node arena",
            ));
        }
        let result = arena.locations.consolidate();
        if result.is_err() {
            arena.failed = true;
        }
        result
    }

    pub(super) fn memoized_nodes(&self) -> ColdMemoNodes<'_> {
        ColdMemoNodes {
            cold: self,
            memo: Rc::new(RefCell::new(AuthenticatedPageMemo::default())),
        }
    }

    #[cfg(test)]
    pub(super) fn from_metadata(
        file: &File,
        limits: RecoveryLimits,
        budget: LocationIndexMemoryBudget,
    ) -> Result<Self, DurableError> {
        Self::from_validated_maps(file, limits, budget, &[])
    }

    /// Reuse only complete active closures accepted by canonical map recovery.
    /// The final unique proof count also requires every such node on media.
    #[cfg(test)]
    pub(super) fn from_validated_maps(
        file: &File,
        limits: RecoveryLimits,
        budget: LocationIndexMemoryBudget,
        maps: &[&CanonicalPhysicalMap],
    ) -> Result<Self, DurableError> {
        let mut reader = file
            .try_clone()
            .map_err(|e| io_error("clone recovery metadata scanner", e))?;
        super::recovery::recover_metadata(&mut reader, limits, budget)?
            .into_nodes()
            .into_cold(maps)
    }

    pub(super) fn from_recovered_locations(
        file: File,
        source: PagedLocations,
        limits: RecoveryLimits,
        budget: LocationIndexMemoryBudget,
        maps: &[&CanonicalPhysicalMap],
    ) -> Result<Self, DurableError> {
        let expected_complete = maps.iter().try_fold(0_usize, |sum, map| {
            sum.checked_add(map.nodes().len())
                .ok_or(DurableError::EncodingOverflow)
        })?;
        // Publish canonical closure proofs only after full active-map validation.
        // Historical journal reachability memos never confer this stronger proof.
        let (locations, complete) = source.rebuild_proofs(budget.durable_entries(), |id| {
            if maps.iter().any(|map| {
                map.nodes()
                    .contains_key(&PhysicalMapNodeId::new(*id.as_bytes()))
            }) {
                ClosureProof::Complete
            } else {
                ClosureProof::Unknown
            }
        })?;
        drop(source);
        if complete != expected_complete {
            return Err(DurableError::InvalidRepresentationState(
                "validated physical closure is missing from metadata",
            ));
        }
        Ok(Self(Arc::new(Mutex::new(NodeArena {
            file,
            locations,
            limits,
            failed: false,
            staged: None,
            budget,
        }))))
    }

    pub(super) fn install_materialized(
        &mut self,
        map: &CanonicalPhysicalMap,
    ) -> Result<(), DurableError> {
        for (id, node) in map.nodes() {
            self.put(*id, node.clone())?;
        }
        Ok(())
    }

    pub(super) fn failed(&self) -> bool {
        let arena = self.0.lock();
        arena.failed
            || arena.locations.failed()
            || arena
                .staged
                .as_ref()
                .is_some_and(|staged| staged.locations.failed())
    }

    pub(super) fn contains(&self, id: &PhysicalMapNodeId) -> Result<bool, DurableError> {
        Ok(self
            .0
            .lock()
            .locations
            .location(ObjectId::new(*id.as_bytes()))?
            .is_some())
    }

    /// Install a locator only after its final reachable frame was appended.
    pub(super) fn promote(
        &self,
        id: PhysicalMapNodeId,
        location: ArenaLocation,
    ) -> Result<(), DurableError> {
        let mut arena = self.0.lock();
        let result = arena
            .locations
            .insert(ObjectId::new(*id.as_bytes()), location);
        if result.is_err() {
            arena.failed = true;
        }
        result
    }

    /// Every current map root now resolves through canonical metadata. Dropping
    /// the anonymous arena releases intermediate path copies and their locators.
    pub(super) fn finish_staging(&self) {
        self.0.lock().staged = None;
    }

    #[cfg(test)]
    pub(super) fn staging_capacity_bytes(&self) -> usize {
        let arena = self.0.lock();
        arena.locations.resident_capacity_bytes().saturating_add(
            arena
                .staged
                .as_ref()
                .map_or(0, |staged| staged.locations.resident_capacity_bytes()),
        )
    }

    pub(super) fn budget(&self) -> LocationIndexMemoryBudget {
        self.0.lock().budget
    }

    pub(super) fn set_memory(&self, budget: LocationIndexMemoryBudget) -> Result<(), DurableError> {
        let mut arena = self.0.lock();
        let result = (|| {
            arena.locations.set_limit(budget.durable_entries())?;
            if let Some(staged) = &mut arena.staged {
                staged.locations.set_limit(budget.durable_entries())?;
            }
            arena.budget = budget;
            Ok(())
        })();
        if result.is_err() {
            arena.failed = true;
        }
        result
    }

    pub(super) fn limits(&self) -> RecoveryLimits {
        self.0.lock().limits
    }

    pub(super) fn len(&self) -> usize {
        self.0.lock().locations.len()
    }
}

impl super::activation::CompleteNodes for ColdNodes {
    fn complete(&self, id: &PhysicalMapNodeId) -> Result<bool, DurableError> {
        self.0
            .lock()
            .locations
            .closure_proven(ObjectId::new(*id.as_bytes()))
    }

    fn remember(&mut self, id: PhysicalMapNodeId) -> Result<(), DurableError> {
        let mut arena = self.0.lock();
        let result = arena.locations.mark_proven(ObjectId::new(*id.as_bytes()));
        if result.is_err() {
            arena.failed = true;
        }
        result
    }
}

/// Shared operation-scoped page memo for one closure walk.
///
/// Guards are acquired only around locator lookups/updates. Callers must not
/// hold a `NodeArena` mutex across `map.view_node`, which re-enters the same
/// arena through `ColdNodes`.
pub(super) struct ColdMemoPresence<'a> {
    cold: &'a ColdNodes,
    memo: Rc<RefCell<AuthenticatedPageMemo>>,
}

pub(super) struct ColdMemoComplete<'a> {
    cold: &'a ColdNodes,
    memo: Rc<RefCell<AuthenticatedPageMemo>>,
}

pub(super) fn memoized_closure_handles(
    cold: &ColdNodes,
) -> (ColdMemoPresence<'_>, ColdMemoComplete<'_>) {
    cold.memoized_nodes().closure_handles()
}

impl<'a> ColdMemoNodes<'a> {
    pub(super) fn closure_handles(&self) -> (ColdMemoPresence<'a>, ColdMemoComplete<'a>) {
        (
            ColdMemoPresence {
                cold: self.cold,
                memo: Rc::clone(&self.memo),
            },
            ColdMemoComplete {
                cold: self.cold,
                memo: Rc::clone(&self.memo),
            },
        )
    }
}

impl super::activation::NodePresence for ColdMemoPresence<'_> {
    fn has_node(&self, id: &PhysicalMapNodeId) -> Result<bool, DurableError> {
        let mut memo = self.memo.borrow_mut();
        let arena = self.cold.0.lock();
        Ok(arena
            .locations
            .location_memo(ObjectId::new(*id.as_bytes()), &mut memo)?
            .is_some())
    }
}

impl super::activation::CompleteNodes for ColdMemoComplete<'_> {
    fn complete(&self, id: &PhysicalMapNodeId) -> Result<bool, DurableError> {
        let mut memo = self.memo.borrow_mut();
        let arena = self.cold.0.lock();
        arena
            .locations
            .closure_proven_memo(ObjectId::new(*id.as_bytes()), &mut memo)
    }

    fn remember(&mut self, id: PhysicalMapNodeId) -> Result<(), DurableError> {
        let mut memo = self.memo.borrow_mut();
        let mut arena = self.cold.0.lock();
        let result = arena
            .locations
            .mark_proven_memo(ObjectId::new(*id.as_bytes()), &mut memo);
        if result.is_err() {
            arena.failed = true;
        }
        result
    }
}

impl NodeArena {
    fn node(&self, id: PhysicalMapNodeId) -> Result<Option<PhysicalMapNode>, DurableError> {
        self.node_memo(id, &mut AuthenticatedPageMemo::default())
    }

    fn node_memo(
        &self,
        id: PhysicalMapNodeId,
        memo: &mut AuthenticatedPageMemo,
    ) -> Result<Option<PhysicalMapNode>, DurableError> {
        let key = ObjectId::new(*id.as_bytes());
        if let Some(staged) = &self.staged
            && let Some(location) = staged.locations.location(key)?
        {
            return read_node(&staged.file, self.limits, id, location).map(Some);
        }
        let Some(location) = self.locations.location_memo(key, memo)? else {
            return Ok(None);
        };
        read_node(&self.file, self.limits, id, location).map(Some)
    }
}

impl PhysicalMapNodes for ColdNodes {
    type Error = DurableError;
    fn note_read_failure(&self) {
        self.0.lock().failed = true;
    }
    fn node(
        &self,
        id: PhysicalMapNodeId,
    ) -> Result<Option<Cow<'_, PhysicalMapNode>>, DurableError> {
        let mut arena = self.0.lock();
        let result = arena.node(id).map(|node| node.map(Cow::Owned));
        if result.is_err() {
            arena.failed = true;
        }
        result
    }
}

impl PhysicalMapNodes for ColdMemoNodes<'_> {
    type Error = DurableError;

    fn note_read_failure(&self) {
        self.cold.note_read_failure();
    }

    fn node(
        &self,
        id: PhysicalMapNodeId,
    ) -> Result<Option<Cow<'_, PhysicalMapNode>>, DurableError> {
        let mut arena = self.cold.0.lock();
        let result = arena
            .node_memo(id, &mut self.memo.borrow_mut())
            .map(|node| node.map(Cow::Owned));
        if result.is_err() {
            arena.failed = true;
        }
        result
    }
}

impl ColdNodes {
    fn put_memo(
        &self,
        id: PhysicalMapNodeId,
        node: &PhysicalMapNode,
        memo: &mut AuthenticatedPageMemo,
    ) -> Result<(), DurableError> {
        let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, node)?;
        if frame.identity != *id.as_bytes() {
            return Err(DurableError::InvalidRepresentationState(
                "physical node write identity mismatch",
            ));
        }
        let payload = frame.encode()?;
        let mut arena = self.0.lock();
        super::super::ensure_payload_limit(METADATA_FILE, 0, payload.len(), arena.limits)?;
        let existing = arena.node_memo(id, memo);
        if existing.is_err() {
            arena.failed = true;
        }
        if let Some(existing) = existing? {
            if existing != *node {
                return Err(DurableError::InvalidRepresentationState(
                    "physical node identity collision",
                ));
            }
            return Ok(());
        }
        let result = (|| {
            if arena.staged.is_none() {
                arena.staged =
                    Some(StagedNodes {
                        file: File::native(tempfile::tempfile().map_err(|error| {
                            io_error("create physical node staging arena", error)
                        })?),
                        locations: PagedLocations::new(arena.budget.durable_entries()),
                    });
            }
            let staged = arena
                .staged
                .as_mut()
                .ok_or(DurableError::InvalidRepresentationState(
                    "physical node staging arena disappeared",
                ))?;
            let location = append_frame(&mut staged.file, METADATA_MAGIC, &payload)?;
            staged
                .locations
                .insert(ObjectId::new(*id.as_bytes()), location)
        })();
        if result.is_err() {
            arena.failed = true;
        }
        result
    }
}

impl PhysicalMapMutNodes for ColdNodes {
    fn put(&mut self, id: PhysicalMapNodeId, node: PhysicalMapNode) -> Result<(), DurableError> {
        self.put_memo(id, &node, &mut AuthenticatedPageMemo::default())
    }
}

impl PhysicalMapMutNodes for ColdMemoNodes<'_> {
    fn put(&mut self, id: PhysicalMapNodeId, node: PhysicalMapNode) -> Result<(), DurableError> {
        self.cold.put_memo(id, &node, &mut self.memo.borrow_mut())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod engine_tests;

pub(super) fn read_node(
    file: &File,
    limits: RecoveryLimits,
    id: PhysicalMapNodeId,
    location: ArenaLocation,
) -> Result<PhysicalMapNode, DurableError> {
    let payload = read_frame_at(file, METADATA_FILE, METADATA_MAGIC, location.offset, limits)?;
    if u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?
        != location.payload_len
        || frame_checksum(METADATA_MAGIC, location.payload_len, &payload) != location.checksum
    {
        return Err(DurableError::InvalidRepresentationState(
            "physical node locator no longer matches frame",
        ));
    }
    let frame = MetadataFrame::decode(&payload)?;
    if frame.kind != MetadataKind::MapNode || frame.identity != *id.as_bytes() {
        return Err(DurableError::InvalidRepresentationState(
            "physical node locator names a different identity",
        ));
    }
    frame.verify(&Blake3PhysicalIdentity)?;
    Ok(PhysicalMapNode::decode(&frame.value)?)
}

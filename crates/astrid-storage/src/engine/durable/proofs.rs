//! Closure evidence shares the complete locator instead of retaining another tree.
//!
//! A positive bit is installed only after the complete immutable owning closure
//! has been checked. Root publication does not create evidence. Missing bits
//! require the ordinary traversal; scratch errors require recovery.

use std::collections::BTreeSet;

use super::{
    DurableError, DurableInner, ObjectId, locations::PagedLocations, wal::PendingWalOverlay,
};

pub(super) trait ClosureProofLookup {
    fn proven(&self, id: &ObjectId) -> Result<bool, DurableError>;
}

impl ClosureProofLookup for BTreeSet<ObjectId> {
    fn proven(&self, id: &ObjectId) -> Result<bool, DurableError> {
        Ok(self.contains(id))
    }
}

pub(super) struct ProvenObjects<'a, P: Ord> {
    index: &'a PagedLocations,
    pending: &'a PendingWalOverlay<P>,
}

impl<'a, P: Ord> ProvenObjects<'a, P> {
    pub(super) const fn new(index: &'a PagedLocations, pending: &'a PendingWalOverlay<P>) -> Self {
        Self { index, pending }
    }
}

impl<P: Ord> ClosureProofLookup for ProvenObjects<'_, P> {
    fn proven(&self, id: &ObjectId) -> Result<bool, DurableError> {
        if self.pending.closure_proven(id) {
            return Ok(true);
        }
        self.index.closure_proven(*id)
    }
}

impl<P: Ord> DurableInner<P> {
    pub(super) fn proofs(&self) -> ProvenObjects<'_, P> {
        ProvenObjects::new(&self.index, &self.pending_wal)
    }

    pub(super) fn mark_proven(&mut self, id: ObjectId) -> Result<(), DurableError> {
        if self.pending_wal.mark_proven(id) {
            return Ok(());
        }
        self.index.mark_proven(id)
    }

    pub(super) fn mark_proven_all(
        &mut self,
        ids: impl IntoIterator<Item = ObjectId>,
    ) -> Result<(), DurableError> {
        for id in ids {
            self.mark_proven(id)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn clear_proofs(&mut self) {
        self.index.clear_proofs().unwrap();
        self.pending_wal.clear_proofs();
    }
}

impl<P, I, C> super::DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: super::PersistentObjectIdentity,
    C: super::PrincipalCodec<P>,
{
    /// Scratch proof errors fence even lock-free cached-read paths immediately.
    pub(super) fn proof_result<T>(
        &self,
        inner: &mut DurableInner<P>,
        result: Result<T, DurableError>,
    ) -> Result<T, DurableError> {
        if result.is_err() {
            self.mark_requires_recovery(inner);
        }
        result
    }

    pub(super) fn remember_proofs(
        &self,
        inner: &mut DurableInner<P>,
        ids: impl IntoIterator<Item = ObjectId>,
    ) -> Result<(), DurableError> {
        let result = inner.mark_proven_all(ids);
        self.proof_result(inner, result)
    }
}

//! Disposable checkpoint validation published at native root admission.

use std::fmt;
use std::panic::{AssertUnwindSafe, RefUnwindSafe, UnwindSafe};
use std::sync::Arc;

use super::{KvValidationCache, Projection, TreeValidation};
use crate::storage_model::{ObjectId, RootState};

/// A closed, process-local cache update, never an arbitrary engine callback.
/// The native consumer must match the transaction's identity authority and
/// successfully publish its root before invoking this update under its writer.
pub(crate) struct KvCheckpointPublication(Box<dyn PublishCheckpoint>);

/// Evicted value buffers must be released after the engine writer is dropped.
pub(crate) struct RetiredKvProjection {
    _projection: Projection,
}

// Only this module can implement the erased operation or construct its token.
// Erasure keeps RootTransaction's public principal bounds unchanged.
trait PublishCheckpoint: Send + Sync + UnwindSafe + RefUnwindSafe {
    fn try_publish(self: Box<Self>, root: RootState) -> Option<RetiredKvProjection>;
}

struct CheckpointPublication<P: Ord> {
    cache: Arc<KvValidationCache<P>>,
    owner: P,
    checkpoint_owner: P,
    commit: ObjectId,
    projection: Projection,
    validation: TreeValidation,
}

impl fmt::Debug for KvCheckpointPublication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KvCheckpointPublication")
            .finish_non_exhaustive()
    }
}

impl KvCheckpointPublication {
    pub(super) fn new<P: Clone + Ord + Send + Sync + 'static>(
        cache: Arc<KvValidationCache<P>>,
        owner: P,
        commit: ObjectId,
        projection: Projection,
        validation: TreeValidation,
    ) -> Self {
        // This closed operation updates only disposable validation metadata;
        // unwinding cannot invalidate the admitted root or its immutable bytes.
        // Keep RootTransaction's original unwind auto-traits; its principal
        // and record fields still impose their own ordinary marker bounds.
        Self(Box::new(AssertUnwindSafe(CheckpointPublication {
            cache,
            checkpoint_owner: owner.clone(),
            owner,
            commit,
            projection,
            validation,
        })))
    }

    pub(crate) fn try_publish(self, root: RootState) -> Option<RetiredKvProjection> {
        self.0.try_publish(root)
    }
}

impl<P: Ord + Send + Sync> PublishCheckpoint for AssertUnwindSafe<CheckpointPublication<P>> {
    fn try_publish(self: Box<Self>, root: RootState) -> Option<RetiredKvProjection> {
        let AssertUnwindSafe(publication) = *self;
        if root.commit != publication.commit
            || publication.validation.root() != publication.projection.tree
            || publication.projection.boundary != Some(publication.validation.certificate())
        {
            return None;
        }
        // Existing fallback publishers acquire projections before querying
        // the engine. Never wait on either cache while holding its writer:
        // contention leaves publication to the ordinary post-commit path.
        let mut projections = publication.cache.projections.try_lock()?;
        let mut trees = publication.cache.trees.try_lock()?;
        trees.insert(publication.checkpoint_owner, publication.validation);
        projections
            .insert(publication.owner, publication.projection)
            .map(|projection| RetiredKvProjection {
                _projection: projection,
            })
    }
}

#[cfg(test)]
mod tests;

//! Reuse published immutable bytes without retaining a second prepared record.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::storage_model::{ObjectIdentity, RootState};

use super::super::format::{decode_object_frame, frame_checksum};
use super::super::{
    ARENA_MAGIC, ArenaLocation, DurableEngine, LIFECYCLE_USABLE, PersistentObjectIdentity,
    PrincipalCodec, ensure_usable,
};

/// Created only after the batch's durable frontier and root publication.
/// The payload is moved from `Prepared`, never copied or kept decoded there.
pub(super) struct PublishedCommitPayload {
    pub(super) root: RootState,
    pub(super) arena_generation: u64,
    pub(super) location: ArenaLocation,
    pub(super) payload: Arc<[u8]>,
}

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    pub(super) fn warm_published_commits(&self, published: BTreeMap<P, PublishedCommitPayload>) {
        for (principal, commit) in published {
            // This accelerator cannot change an already-published receipt or
            // poison the engine if an external cache-budget callback unwinds.
            if catch_unwind(AssertUnwindSafe(|| {
                self.warm_published_commit(&principal, &commit);
            }))
            .is_err()
            {
                tracing::error!("published-commit cache admission panicked");
            }
        }
    }

    fn warm_published_commit(&self, principal: &P, commit: &PublishedCommitPayload) {
        let Ok(length) = u64::try_from(commit.payload.len()) else {
            return;
        };
        if self.lifecycle.load(Ordering::Acquire) != LIFECYCLE_USABLE
            || !self.object_cache.may_retain(principal, length)
        {
            return;
        }
        if length != commit.location.payload_len
            || frame_checksum(ARENA_MAGIC, length, &commit.payload) != commit.location.checksum
        {
            return;
        }
        let Ok((id, record)) = decode_object_frame(&commit.payload, self.identity.scheme()) else {
            return;
        };
        if id != commit.root.commit || self.identity.identify(&record) != id {
            return;
        }
        // Match ordinary read admission's writer -> cache order. The original
        // publication writer/fence is already released; never wait for a writer
        // or enter recovery here. A miss after any skipped admission uses the authoritative path.
        let Some(inner) = self.inner.try_lock() else {
            return;
        };
        if self.lifecycle.load(Ordering::Acquire) != LIFECYCLE_USABLE
            || ensure_usable(&inner).is_err()
            || inner.arena_generation != commit.arena_generation
            || inner.roots_by_principal.get(principal) != Some(&commit.root)
            || inner.index.get(&id) != Some(&commit.location)
        {
            return;
        }
        let _ = self.object_cache.insert(principal, id, record);
    }
}

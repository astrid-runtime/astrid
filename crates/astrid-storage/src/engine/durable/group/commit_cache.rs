//! Reuse published immutable bytes without retaining a second prepared record.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::Ordering;

use super::super::format::{frame_checksum, published_record};
use super::super::{
    ARENA_MAGIC, DurableEngine, LIFECYCLE_USABLE, PersistentObjectIdentity, PrincipalCodec,
    ensure_usable,
};

pub(super) use super::super::read_admission::PublishedCommitPayload;

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
        let Some(candidate) = commit.prepare(
            |len, bytes| frame_checksum(ARENA_MAGIC, len, bytes),
            |bytes, id| published_record(bytes, id, &self.identity),
        ) else {
            return;
        };
        // Match ordinary read admission's writer -> cache order. The original
        // publication writer/fence is already released; never wait for a writer
        // or enter recovery here. A miss after any skipped admission uses the authoritative path.
        let Some(inner) = self.inner.try_lock() else {
            return;
        };
        if self.lifecycle.load(Ordering::Acquire) != LIFECYCLE_USABLE
            || ensure_usable(&inner).is_err()
        {
            return;
        }
        let _ = candidate.warm(
            principal,
            inner.arena_generation,
            &inner.roots_by_principal,
            &inner.index,
            |owner, key, loaded| self.object_cache.insert(owner, key, loaded),
        );
    }
}

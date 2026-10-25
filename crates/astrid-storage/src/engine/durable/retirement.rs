//! Move verified durable ownership without reopening or reviving old handles.

use super::wal::PendingWalOverlay;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use parking_lot::{Mutex, RwLock};

use super::{
    CommitGroup, DurableEngine, DurableError, DurableInner, LIFECYCLE_CLOSED, LIFECYCLE_USABLE,
    PersistentObjectIdentity, PrincipalCodec, PublishedRoots, io_error,
};

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Transfer a quiesced engine to a distinct finalization owner.
    /// Old projections remain permanently closed; prepared transactions cannot
    /// cross the fresh preparation authority. Files and locks move without an
    /// unlock/reopen gap. The caller must already have joined its producers.
    pub(crate) fn handoff_for_retirement(&self) -> Result<Self, DurableError> {
        // Exclude queued or executing commit groups and stop new queueing
        // until the old engine has its permanent closed fence.
        let group = self.commit_group.try_lock().ok_or_else(busy)?;
        if !group.is_idle() {
            return Err(busy());
        }
        // Never wait for a stager while holding the commit queue. A caller
        // that has not actually quiesced must retry after joining its writers.
        let mut inner = self.inner.try_lock().ok_or_else(busy)?;
        super::ensure_usable(&inner)?;
        if inner.lock.is_none() || self.arena_reader.read().is_none() {
            return Err(DurableError::Closed);
        }
        self.flush_for_retirement(&mut inner)?;
        let mut reader = self.arena_reader.write();
        self.lifecycle.store(LIFECYCLE_CLOSED, Ordering::Release);
        let transferred = std::mem::replace(&mut *inner, empty_inner());
        let published_roots = PublishedRoots::new(&transferred.roots_by_principal);
        self.published_roots.replace(&inner.roots_by_principal);
        self.object_cache.clear();
        Ok(Self {
            directory: self.directory.clone(),
            directory_capability: self.directory_capability.clone(),
            volume: RwLock::new(self.volume.write().take()),
            identity: self.identity.clone(),
            principal_codec: self.principal_codec.clone(),
            limits: self.limits,
            faults: Arc::clone(&self.faults),
            group_policy: self.group_policy,
            commit_group: Mutex::new(CommitGroup::default()),
            transaction_wal: self.transaction_wal,
            wal: Mutex::new(self.wal.lock().take()),
            lifecycle: AtomicU8::new(LIFECYCLE_USABLE),
            arena_reader: RwLock::new(reader.take()),
            object_cache: self.object_cache.empty_peer(),
            recovery_policy: self.recovery_policy,
            preparation_authority: Arc::new(()),
            inner: Mutex::new(transferred),
            published_roots,
        })
    }
}

fn busy() -> DurableError {
    io_error(
        "transfer durable ownership with active writers",
        std::io::Error::from(std::io::ErrorKind::WouldBlock),
    )
}

fn empty_inner<P: Ord>() -> DurableInner<P> {
    DurableInner {
        roots_by_principal: BTreeMap::new(),
        index: BTreeMap::new(),
        pending_wal: PendingWalOverlay::default(),
        pending_index_locations: Vec::new(),
        pending_direct_objects: BTreeMap::new(),
        validated: BTreeSet::new(),
        files: None,
        representations: None,
        lock: None,
        poisoned: false,
        arena_generation: 0,
    }
}

#[cfg(test)]
mod tests;

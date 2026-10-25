//! Checkpoint work owns its cache-cleanup obligation until every retry ends.
use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::Arc;

use parking_lot::Mutex;

use super::{BlockingTreeStore, KvProjectionEngine, projection_from_header, should_checkpoint};

pub(super) type Checkpointing<P> = Arc<Mutex<BTreeMap<P, CheckpointState>>>;

pub(super) struct CheckpointState {
    retention: CacheRetention,
    requested: bool,
}

pub(super) enum CacheRetention {
    Keep,
    ForgetAfterCompletion,
}

struct CheckpointRegistration<P: Ord, E> {
    store: BlockingTreeStore<P, E>,
    owner: P,
    registered: bool,
}

impl<P: Clone + Ord, E> CheckpointRegistration<P, E> {
    fn acquire(store: BlockingTreeStore<P, E>, owner: P) -> Option<Self> {
        {
            let mut active = store.checkpointing.lock();
            match active.entry(owner.clone()) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().requested = true;
                    return None;
                },
                Entry::Vacant(entry) => {
                    entry.insert(CheckpointState {
                        retention: CacheRetention::Keep,
                        requested: false,
                    });
                },
            }
        }
        Some(Self {
            store,
            owner,
            registered: true,
        })
    }
}

impl<P: Ord, E> CheckpointRegistration<P, E> {
    fn finish_or_retry(&mut self) -> bool {
        // Publish completion atomically with deciding whether a writer requested
        // another pass. A request after removal queues a distinct registration.
        let mut active = self.store.checkpointing.lock();
        if let Some(state) = active.get_mut(&self.owner)
            && state.requested
        {
            state.requested = false;
            return false;
        }
        release_owner(&self.store, &self.owner, &mut active);
        self.registered = false;
        true
    }
}

impl<P: Ord, E> Drop for CheckpointRegistration<P, E> {
    fn drop(&mut self) {
        if self.registered {
            release_owner(
                &self.store,
                &self.owner,
                &mut self.store.checkpointing.lock(),
            );
        }
    }
}

fn release_owner<P: Ord, E>(
    store: &BlockingTreeStore<P, E>,
    owner: &P,
    active: &mut BTreeMap<P, CheckpointState>,
) {
    // Purge marks the registration before clearing caches under this same lock.
    if active
        .get(owner)
        .is_some_and(|state| matches!(state.retention, CacheRetention::ForgetAfterCompletion))
    {
        store.validation.forget_owner(owner);
        store.validated_content.lock().remove(owner);
    }
    active.remove(owner);
}

impl<P, E> BlockingTreeStore<P, E>
where
    P: Clone + Ord + Send + Sync + 'static,
    E: KvProjectionEngine<P> + 'static,
{
    pub(super) fn forget_owner_projection_state(&self, owner: &P) {
        let mut active = self.checkpointing.lock();
        if let Some(state) = active.get_mut(owner) {
            state.retention = CacheRetention::ForgetAfterCompletion;
        }
        self.validation.forget_owner(owner);
        self.validated_content.lock().remove(owner);
    }

    pub(super) fn schedule_checkpoint(&self, owner: P) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Some(mut registration) = CheckpointRegistration::acquire(self.clone(), owner) else {
            return;
        };
        // A dropped or panicking task also releases its registration. Keep one
        // registration for the complete retry chain, with no untracked gap.
        let _task = runtime.spawn_blocking(move || {
            let store = registration.store.clone();
            loop {
                let outcome = store.checkpoint_once(registration.owner.clone(), false);
                let retry = if matches!(outcome.as_ref(), Ok(false)) {
                    match store.header(registration.owner.clone()) {
                        Ok(header) => should_checkpoint(&projection_from_header(&header)),
                        Err(error) => {
                            tracing::warn!(%error, "principal KV checkpoint retry check failed");
                            false
                        },
                    }
                } else {
                    false
                };
                if let Err(error) = outcome {
                    tracing::warn!(%error, "principal KV checkpoint failed");
                }
                if !retry && registration.finish_or_retry() {
                    break;
                }
                std::thread::yield_now();
            }
        });
    }
}

#[cfg(test)]
mod tests;

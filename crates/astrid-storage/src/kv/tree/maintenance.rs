//! One scoped admission and publication ticket spans every checkpoint retry.
use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::Arc;

use parking_lot::Mutex;

use super::{
    BlockingTreeStore, KvProjectionEngine, MemoEpoch, projection_from_header, should_checkpoint,
};

pub(super) type Checkpointing<P> = Arc<Mutex<BTreeMap<P, CheckpointState>>>;

pub(super) struct CheckpointState {
    requested: bool,
}

struct CheckpointRegistration<P: Ord, E> {
    store: BlockingTreeStore<P, E>,
    owner: P,
    registered: bool,
    epoch: MemoEpoch,
}

impl<P: Clone + Ord, E> CheckpointRegistration<P, E> {
    fn acquire(store: BlockingTreeStore<P, E>, owner: P) -> Option<Self> {
        let epoch = store.validation.memo_epoch();
        {
            let mut active = store.checkpointing.lock();
            match active.entry(owner.clone()) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().requested = true;
                    return None;
                },
                Entry::Vacant(entry) => {
                    entry.insert(CheckpointState { requested: false });
                },
            }
        }
        Some(Self {
            store,
            owner,
            registered: true,
            epoch,
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
        active.remove(&self.owner);
        self.registered = false;
        true
    }
}

impl<P: Ord, E> Drop for CheckpointRegistration<P, E> {
    fn drop(&mut self) {
        if self.registered {
            self.store.checkpointing.lock().remove(&self.owner);
        }
    }
}

impl<P, E> CheckpointRegistration<P, E>
where
    P: Clone + Ord + Send + Sync + 'static,
    E: KvProjectionEngine<P> + 'static,
{
    fn checkpoint_once(&self) -> crate::StorageResult<bool> {
        self.store
            .checkpoint_once_after(self.owner.clone(), false, self.epoch, || Ok(()))
    }
}

impl<P, E> BlockingTreeStore<P, E>
where
    P: Clone + Ord + Send + Sync + 'static,
    E: KvProjectionEngine<P> + 'static,
{
    pub(super) fn forget_owner_projection_state(&self, owner: &P) {
        self.validation.forget_owner(owner, &self.validated_content);
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
                let outcome = registration.checkpoint_once();
                let retry = if matches!(outcome.as_ref(), Ok(false)) {
                    match store.header_at_epoch(registration.owner.clone(), registration.epoch) {
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

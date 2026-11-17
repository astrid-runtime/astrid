//! Amortized representation-generation checkpoint after commit frontier.
//!
//! Invoked from the existing commit-group leader after the current batch's
//! durable frontier and receipts are published. Ordinary `RuntimeEngine` writes
//! remain the automatic path; there is no separate background maintenance task.
//! Clean close drains an in-flight job; with no job it stays flush-only and
//! does not call this helper.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;

#[cfg(test)]
use super::super::checkpoint_worker::SharedCheckpointArbiter;
use super::super::checkpoint_worker::{self, SharedRepresentationStore};
use super::super::representations::{CapturedCheckpoint, CheckpointControl, CheckpointMedia};
use super::super::{
    DurableEngine, DurableError, LIFECYCLE_USABLE, PersistentObjectIdentity, PrincipalCodec,
};

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    pub(super) fn maintain_representations_after_commit(&self) {
        if let Err(error) = self.maybe_schedule_representation_checkpoint() {
            tracing::error!(error = %error, "representation checkpoint requires recovery");
            // Never call lock_usable from post-commit maintenance: poll/join
            // errors already require recovery, and lock_usable would recover
            // then let mark_requires_recovery poison the freshly recovered
            // engine. Poison the lifecycle immediately; mark inner only if the
            // writer lock is free. The next ordinary lock_usable recovers once.
            checkpoint_worker::poison_lifecycle(self.lifecycle.as_ref());
            if let Some(mut inner) = self.inner.try_lock() {
                self.mark_requires_recovery(&mut inner);
            }
        }
    }

    /// Schedule at most one off-writer checkpoint job after a successful frontier.
    ///
    /// Uses `try_lock` on the arbiter so the commit leader never blocks behind
    /// exclusive close/compaction/recovery. Capture runs under the physical
    /// store mutex; prepare/publish/reclaim run on the worker thread.
    pub(in crate::engine::durable) fn maybe_schedule_representation_checkpoint(
        &self,
    ) -> Result<(), DurableError> {
        checkpoint_worker::poll_finished_checkpoint_worker(
            self.checkpoint_arbiter.as_ref(),
            self.lifecycle.as_ref(),
        )?;
        let Some(mut arbiter) = self.checkpoint_arbiter.try_lock() else {
            return Ok(());
        };
        if !matches!(
            arbiter.worker,
            checkpoint_worker::CheckpointWorkerSlot::Idle
        ) {
            return Ok(());
        }
        if self.lifecycle.load(Ordering::Acquire) != LIFECYCLE_USABLE {
            return Ok(());
        }
        let Some(media) = self.checkpoint_media() else {
            return Ok(());
        };
        let Some(shared) = self.shared_representations() else {
            return Ok(());
        };
        let capture = {
            let mut store = shared.lock();
            // Declared after the physical guard so capture failure/panic poisons
            // before the store mutex is released.
            let mut poison = checkpoint_worker::PublicationPoison::armed(self.lifecycle.as_ref());
            if self.lifecycle.load(Ordering::Acquire) != LIFECYCLE_USABLE {
                poison.disarm();
                return Ok(());
            }
            if !media.should_prepare(&store)? {
                poison.disarm();
                return Ok(());
            }
            match CapturedCheckpoint::capture_from_media(&mut store, media) {
                Ok(capture) => {
                    poison.disarm();
                    capture
                },
                Err(error) => return Err(error),
            }
        };
        let control = Arc::new(CheckpointControl::running());
        let worker_control = Arc::clone(&control);
        let worker_shared = Arc::clone(&shared);
        let worker_arbiter = Arc::clone(&self.checkpoint_arbiter);
        let worker_lifecycle = Arc::clone(&self.lifecycle);
        let generation = arbiter.custody_generation;
        let limits = self.limits;
        let join = thread::Builder::new()
            .name("astrid-rep-checkpoint".to_owned())
            .spawn(move || {
                checkpoint_worker::run_checkpoint_worker(
                    &worker_shared,
                    &worker_arbiter,
                    capture,
                    limits,
                    worker_control.as_ref(),
                    &worker_lifecycle,
                    generation,
                )
            })
            .map_err(|source| {
                super::super::io_error("spawn representation checkpoint worker", source)
            })?;
        checkpoint_worker::install_preparing_worker(&mut arbiter, control, join);
        Ok(())
    }

    fn checkpoint_media(&self) -> Option<CheckpointMedia> {
        if let Some(volume) = self.volume.read().as_ref().cloned() {
            return Some(CheckpointMedia::Volume(volume));
        }
        self.directory_capability
            .as_ref()
            .map(|directory| CheckpointMedia::Directory(Arc::clone(directory)))
    }

    fn shared_representations(&self) -> Option<SharedRepresentationStore> {
        let inner = self.inner.lock();
        inner.representations.clone()
    }
}

/// Test-only access to the shared arbiter for exclusive/cancel races.
#[cfg(test)]
impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    pub(in crate::engine::durable) fn checkpoint_arbiter_for_test(
        &self,
    ) -> SharedCheckpointArbiter {
        Arc::clone(&self.checkpoint_arbiter)
    }

    pub(in crate::engine::durable) fn shared_representations_for_test(
        &self,
    ) -> Option<SharedRepresentationStore> {
        self.shared_representations()
    }

    pub(in crate::engine::durable) fn lifecycle_for_test(
        &self,
    ) -> Arc<std::sync::atomic::AtomicU8> {
        Arc::clone(&self.lifecycle)
    }
}

//! Amortized representation-generation checkpoint after commit frontier.
//!
//! Invoked from the existing commit-group leader after the current batch's
//! durable frontier and receipts are published. Ordinary `RuntimeEngine` writes
//! remain the automatic path; there is no separate background maintenance task.
//! Clean close stays flush-only and does not call this helper.

use super::super::{
    DurableEngine, DurableError, DurableInner, PersistentObjectIdentity, PrincipalCodec,
};

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    pub(super) fn maintain_representations_after_commit(&self) {
        if let Ok(mut inner) = self.lock_usable()
            && let Err(error) = self.maybe_checkpoint_representations(&mut inner)
        {
            tracing::error!(error = %error, "representation checkpoint requires recovery");
            self.mark_requires_recovery(&mut inner);
        }
    }

    /// Checkpoint when obsolete frames provably reach the resident map size.
    ///
    /// Must run under `lock_usable` / `inner` already held. Never acquires
    /// `commit_group`. On hard failure the caller poisons the engine.
    pub(super) fn maybe_checkpoint_representations(
        &self,
        inner: &mut DurableInner<P>,
    ) -> Result<(), DurableError> {
        let Some(store) = inner.representations.as_mut() else {
            return Ok(());
        };
        if let Some(volume) = self.volume.read().as_ref().cloned() {
            store.maybe_checkpoint_volume(&volume, self.limits)?;
            return Ok(());
        }
        if let Some(directory) = self.directory_capability.as_ref() {
            store.maybe_checkpoint_native(directory, self.limits)?;
            return Ok(());
        }
        Ok(())
    }
}

//! Physical bookkeeping maintenance after ordinary durable publication.

use super::super::{
    DurableEngine, DurableError, DurableInner, PersistentObjectIdentity, PrincipalCodec,
};

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    pub(in crate::engine::durable) fn checkpoint_physical_history(
        &self,
        inner: &mut DurableInner<P>,
    ) -> Result<(), DurableError> {
        let Some(store) = inner.representations.as_mut() else {
            return Ok(());
        };
        if !store.checkpoint_required() {
            return Ok(());
        }
        // Only ordinary published frontiers call this helper. Compaction's
        // private rebasing must publish its pointer together with its arena.
        // A physical checkpoint retains every logical object and authority ID.
        let result = if let Some(volume) = self.volume.read().as_ref().cloned() {
            store.checkpoint_volume(&volume, self.limits)
        } else {
            store.checkpoint_native(self.hosted_directory()?, self.limits)
        };
        if result.is_err() {
            // Namespace publication can precede a failed durability barrier.
            // Reopen before using any old handles after an ambiguous failure.
            self.mark_requires_recovery(inner);
        }
        result
    }
}

#[cfg(test)]
mod tests;

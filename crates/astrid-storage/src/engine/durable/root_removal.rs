//! Exact root retirement, serialized with ordinary commit publication.

use super::roots::encode_root_removal;
use super::{
    DurableEngine, DurableError, DurableInner, FaultPoint, ModelError, PersistentObjectIdentity,
    PrincipalCodec, ROOT_FILE, ROOT_MAGIC, RootState, append_frame, ensure_payload_limit, io_error,
    live_files_mut,
};

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Atomically remove a principal root using exact compare-and-swap.
    ///
    /// This is a storage mechanism; callers must fence the retired identity's
    /// writers before invoking it. Objects remain until compaction proves
    /// that no surviving root or explicit retention lease needs them.
    ///
    /// # Errors
    ///
    /// Returns a root conflict for stale or absent roots. An uncertain durable
    /// mutation requires authoritative recovery before further operations.
    pub fn remove_root(
        &self,
        principal: &P,
        expected: RootState,
    ) -> Result<RootState, DurableError> {
        let payload = encode_root_removal(
            self.identity.scheme(),
            &self.principal_codec.encode(principal),
            expected,
        )?;
        ensure_payload_limit(ROOT_FILE, 0, payload.len(), self.limits)?;
        let mut inner = self.lock_usable()?;
        let actual = inner.roots_by_principal.get(principal).copied();
        if actual != Some(expected) {
            return Err(ModelError::RootConflict {
                expected: Some(expected),
                actual,
            }
            .into());
        }
        // The WAL only encodes replacement roots. Fold every pending replacement
        // before appending a deletion, so neither later folding nor replay can
        // resurrect a root which this deletion has durably removed.
        if let Err(error) = self
            .flush_authority(&mut inner)
            .and_then(|()| self.persist_root_removal(&mut inner, &payload))
        {
            self.mark_requires_recovery(&mut inner);
            return Err(error);
        }
        inner.roots_by_principal.remove(principal);
        self.published_roots.remove(principal);
        self.object_cache.discard_principal(principal);
        Ok(expected)
    }

    fn persist_root_removal(
        &self,
        inner: &mut DurableInner<P>,
        payload: &[u8],
    ) -> Result<(), DurableError> {
        self.fail_if(FaultPoint::BeforeRootCas)?;
        let files = live_files_mut(&mut inner.files)?;
        append_frame(&mut files.roots, ROOT_MAGIC, payload)?;
        files
            .roots
            .sync_data()
            .map_err(|source| io_error("flush root removal", source))?;
        self.sync_volume()?;
        self.checkpoint_physical_history(inner)?;
        self.fail_if(FaultPoint::AfterRootCas)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod publication_scale_tests;

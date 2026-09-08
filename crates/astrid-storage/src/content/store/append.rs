use super::{
    ContentName, EngineIdentity, EngineSource, PrincipalContentError, PrincipalContentStore,
    PrincipalProjectionEngine, map_read_error,
};

impl<P, E> PrincipalContentStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Append using a cached canonical proof, or leave the file untouched.
    ///
    /// A cold/unverified source returns false so the caller can use its validating
    /// streaming path. The read handle pins the old closure through root publication.
    pub(crate) fn try_append(
        &self,
        principal: &P,
        name: &ContentName,
        expected_length: u64,
        bytes: &[u8],
    ) -> Result<bool, PrincipalContentError> {
        let Some(handle) = self.open_read(principal, name)? else {
            return Err(PrincipalContentError::BatchPreconditionFailed);
        };
        if handle.descriptor().logical_bytes() != expected_length {
            return Err(PrincipalContentError::BatchPreconditionFailed);
        }
        let Some(verified) = handle.verified() else {
            return Ok(false);
        };
        let appended = crate::content_dag::append_verified_content(
            &EngineIdentity::<P, E>::new(self.engine.as_ref()),
            &EngineSource::<P, E>::new(self.engine.as_ref(), principal),
            verified,
            bytes,
        )
        .map_err(map_read_error)?;
        self.publish_deferred_expected(
            principal,
            name,
            appended.verified,
            &appended.records,
            Some(verified.descriptor().file()),
        )?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests;

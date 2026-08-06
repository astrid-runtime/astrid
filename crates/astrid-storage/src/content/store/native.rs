//! Native composition hooks kept outside the public content-store surface.

use std::sync::Arc;

use astrid_storage_content::VerifiedContent;
use astrid_storage_engine::PrincipalProjectionEngine;

use super::super::{ContentName, ContentWriteOutcome, PrincipalContentError};
use super::PrincipalContentStore;

impl<P: Ord, E> PrincipalContentStore<P, E> {
    /// Construct without a principal-specific quota.
    #[must_use]
    pub fn from_engine(engine: Arc<E>) -> Self {
        Self {
            engine,
            quota: None,
            validated_catalogs: Arc::new(
                parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            ),
            validated_kv: Arc::new(crate::kv::KvValidationCache::default()),
        }
    }

    pub(crate) fn engine(&self) -> Arc<E> {
        Arc::clone(&self.engine)
    }
}

impl<P, E> PrincipalContentStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    pub(crate) fn publish_verified_content(
        &self,
        principal: &P,
        name: &ContentName,
        verified: VerifiedContent,
        staged_objects_inserted: u64,
    ) -> Result<ContentWriteOutcome, PrincipalContentError> {
        self.publish(principal, name, verified, None, staged_objects_inserted)
    }
}

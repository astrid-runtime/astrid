//! Authenticated content-catalog memo transfer across retirement handoff.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::content::PrincipalContentError;
use crate::content::catalog::{
    CONTENT_COMPONENT_LABEL, CatalogSummary, CatalogValidation, root_from_record,
};
use crate::engine::PrincipalProjectionEngine;
use crate::storage_model::{ObjectId, ObjectKind, ReferenceKind, ReferenceLabel, RootState};

use super::{
    PRINCIPAL_GRAPH_VERSION, PrincipalContentStore, STATE_LABEL, invalid, owned_target,
    require_structural,
};

impl<P, E> PrincipalContentStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Shared catalog validation memos for this content projection.
    pub(crate) fn validated_catalogs(&self) -> &Arc<Mutex<BTreeMap<P, CatalogValidation>>> {
        &self.validated_catalogs
    }

    /// Seed one owner catalog memo from `source` when it matches this store's live root.
    pub(crate) fn seed_catalog_owner_from(
        &self,
        source: &Mutex<BTreeMap<P, CatalogValidation>>,
        owner: P,
    ) -> bool {
        let Some(memo) = source.lock().get(&owner).copied() else {
            return false;
        };
        let Ok(live_root) = self.engine.current_root(&owner) else {
            return false;
        };
        let Ok(live) = self.live_content_catalog(&owner, live_root) else {
            return false;
        };
        match (live, memo.root) {
            (None, None) => {
                if memo.summary != CatalogSummary::default() {
                    return false;
                }
            },
            (Some((object, summary)), Some(memo_root))
                if memo_root == object && memo.summary == summary => {},
            _ => return false,
        }
        let Ok(current) = self.engine.current_root(&owner) else {
            return false;
        };
        if current != live_root {
            return false;
        }
        self.validated_catalogs.lock().insert(owner, memo);
        true
    }

    fn live_content_catalog(
        &self,
        owner: &P,
        root: Option<RootState>,
    ) -> Result<Option<(ObjectId, CatalogSummary)>, PrincipalContentError> {
        let Some(root) = root else {
            return Ok(None);
        };
        let commit = self.load_typed(
            owner,
            root.commit,
            ObjectKind::Commit,
            PRINCIPAL_GRAPH_VERSION,
        )?;
        require_structural(root.commit, &commit)?;
        let state_id = owned_target(root.commit, &commit, STATE_LABEL)?;
        let state = self.load_typed(
            owner,
            state_id,
            ObjectKind::PrincipalState,
            PRINCIPAL_GRAPH_VERSION,
        )?;
        require_structural(state_id, &state)?;
        let Some(reference) = state.reference(&ReferenceLabel::new(CONTENT_COMPONENT_LABEL)) else {
            return Ok(None);
        };
        if reference.kind() != ReferenceKind::Owns {
            return Err(invalid(
                state_id,
                "principal content component is not owning",
            ));
        }
        let record = self.load_required_for(owner, reference.target())?;
        let catalog = root_from_record(reference.target(), &record)?;
        Ok(Some((catalog.object, catalog.summary)))
    }

    #[cfg(test)]
    pub(crate) fn validated_kv_cache(&self) -> &Arc<crate::kv::KvValidationCache<P>> {
        &self.validated_kv
    }

    #[cfg(test)]
    pub(crate) fn snapshot_catalog_owner(&self, owner: &P) -> Option<CatalogValidation> {
        self.validated_catalogs.lock().get(owner).copied()
    }

    #[cfg(test)]
    pub(crate) fn insert_catalog_unchecked_for_test(&self, owner: P, memo: CatalogValidation) {
        self.validated_catalogs.lock().insert(owner, memo);
    }

    #[cfg(test)]
    pub(crate) fn cached_catalog_owners_for_test(&self) -> Vec<P> {
        self.validated_catalogs.lock().keys().cloned().collect()
    }

    #[cfg(test)]
    pub(crate) fn catalog_validation_invocations(&self) -> u64 {
        self.catalog_validation_invocations
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn kv_tree_validation_invocations(&self) -> u64 {
        self.validated_kv.tree_validation_invocations_for_test()
    }
}

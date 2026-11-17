//! Transfer existing verified storage custody without reviving former handles.

use super::{PendingRuntimeFinalization, RuntimeFinalization};
use crate::principal_state::{
    NativePrincipalContentStore, RuntimePrincipalStore, RuntimeStore, StateOwner,
    StateOwnerResolver,
};
use crate::{StorageError, StorageResult};
use astrid_core::dirs::AstridHome;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

impl RuntimePrincipalStore {
    /// Retain open custody for deferred handoff after task-runtime teardown.
    ///
    /// Does not close the engine or revoke live handles. Callers must keep this
    /// token across the original runtime drop, then
    /// [`PendingRuntimeFinalization::handoff_for_finalization`].
    ///
    /// # Errors
    /// Fails when the volume binding or retirement home is invalid.
    pub fn retain_for_finalization(
        &self,
        home: &AstridHome,
    ) -> StorageResult<PendingRuntimeFinalization> {
        self.require_volume_binding(home)?;
        crate::principal_state::runtime_tree_active::validate_retirement_home(home, self)?;
        Ok(PendingRuntimeFinalization {
            store: Some(self.clone()),
            home: home.clone(),
            shutdown_error: None,
        })
    }

    /// Close old runtime handles and move authority into a finalization owner.
    ///
    /// All producers must already be quiesced. Keep the returned owner across
    /// task-runtime teardown and pass it to the lifecycle guard for packing.
    ///
    /// # Errors
    /// Fails on a wrong home, active commits, or a durable flush failure.
    pub fn handoff_for_finalization(
        &self,
        home: &AstridHome,
    ) -> StorageResult<RuntimeFinalization> {
        self.require_volume_binding(home)?;
        crate::principal_state::runtime_tree_active::validate_retirement_home(home, self)?;
        // Reserve old staging before engine transfer. Idle facade clones do not
        // block; live writer/publish leases do. Token Drop restores Open if the
        // engine handoff fails.
        let staging_close = match self.staging.get() {
            Some(area) => Some(area.reserve_for_close()?),
            None => None,
        };
        let engine = Arc::new(self.engine.handoff_for_retirement().map_err(|error| {
            StorageError::Connection(format!("transfer runtime store: {error}"))
        })?);
        if let Some(token) = staging_close {
            token.commit();
        }
        // Keep the live quota policy while creating fresh projections: old
        // handles and their mutable caches cannot cross the handoff. System
        // validation memos may be rebound into new containers against the live
        // transferred root; agent overlays and disposable caches stay cold.
        let quota = Arc::clone(&self.quota);
        let source_kv = self.runtime_kv.validation_cache();
        let source_catalogs = self.content.validated_catalogs();
        let catalogs = Arc::new(Mutex::new(BTreeMap::new()));
        let kv_validation = Arc::new(crate::kv::KvValidationCache::default());
        let runtime_kv = Arc::new(
            RuntimeStore::from_engine_with_quota_and_content_validation(
                Arc::clone(&engine),
                StateOwnerResolver::new(self.principals.clone()),
                Arc::clone(&quota),
                Arc::clone(&kv_validation),
                Arc::clone(&catalogs),
            )
            .with_read_cache(super::super::store_open::runtime_read_cache_config()),
        );
        let kv: Arc<dyn crate::KvStore> = runtime_kv.clone();
        let content = Arc::new(
            NativePrincipalContentStore::from_engine_with_quota_and_validation(
                Arc::clone(&engine),
                Arc::clone(&quota),
                catalogs,
                kv_validation,
            ),
        );
        // Best-effort System memo rebind into the fresh containers. Misses stay
        // cold; optional cache failure must not affect transferred custody.
        let system_kv_memo_rebound = crate::kv::seed_owner_memo_if_live(
            engine.as_ref(),
            source_kv.as_ref(),
            runtime_kv.validation_cache(),
            StateOwner::System,
        );
        let system_catalog_memo_rebound =
            content.seed_catalog_owner_from(source_catalogs.as_ref(), StateOwner::System);
        tracing::debug!(
            system_kv_memo_rebound,
            system_catalog_memo_rebound,
            "Rebound finalization validation memos"
        );
        let store = Self {
            quota: Arc::clone(&quota),
            volume_binding: self.volume_binding.clone(),
            engine,
            directory_cutover_receipt: Arc::clone(&self.directory_cutover_receipt),
            runtime_kv,
            kv,
            content,
            staging: Arc::new(OnceLock::new()),
            principals: self.principals.clone(),
        };
        Ok(RuntimeFinalization {
            store,
            shutdown_error: None,
        })
    }
}

#[cfg(test)]
mod drain_gate;
#[cfg(test)]
mod tests;

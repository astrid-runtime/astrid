//! Transfer existing verified storage custody without reviving former handles.

use super::{PendingRuntimeFinalization, RuntimeFinalization};
use crate::principal_state::{
    NativePrincipalContentStore, RuntimePrincipalStore, RuntimeStore, StateOwnerResolver,
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
        let engine = Arc::new(self.engine.handoff_for_retirement().map_err(|error| {
            StorageError::Connection(format!("transfer runtime store: {error}"))
        })?);
        // Keep the live quota policy while creating fresh projections: old
        // handles and their validation/read caches cannot cross the handoff.
        let quota = Arc::clone(&self.quota);
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
mod tests;

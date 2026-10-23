//! Exclusive finalization ownership after runtime projections have closed.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use astrid_core::dirs::AstridHome;
use parking_lot::Mutex;

use super::{
    NativePrincipalContentStore, RuntimePrincipalStore, RuntimeStore, StateOwner,
    StateOwnerResolver,
};
use crate::{KvQuotaResolver, StorageError, StorageResult};

/// A separate durable owner for final packing after task-runtime teardown.
///
/// The former runtime engine is permanently closed, including retained KV and
/// content handles. This non-cloneable owner keeps the same files and exclusive
/// locks; it never reopens the volume or recovers historical indexes.
pub struct RuntimeRetirement {
    home: AstridHome,
    store: RuntimePrincipalStore,
    shutdown_error: Option<StorageError>,
}

impl RuntimePrincipalStore {
    /// Close old runtime handles and move authority into a finalization owner.
    ///
    /// All producers must already be quiesced. Keep the returned owner across
    /// task-runtime teardown and pass it to the lifecycle guard for packing.
    ///
    /// # Errors
    /// Fails on a wrong home, active commits, or a durable flush failure.
    pub fn handoff_for_retirement(&self, home: &AstridHome) -> StorageResult<RuntimeRetirement> {
        super::runtime_tree::validate_retirement_home(home, self)?;
        let engine = Arc::new(self.engine.handoff_for_retirement().map_err(|error| {
            StorageError::Connection(format!("transfer runtime store: {error}"))
        })?);
        // Retirement only writes system-owned projection content. It must not
        // inherit callable old views or their mutable validation/read caches.
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
        let catalogs = Arc::new(Mutex::new(BTreeMap::new()));
        let kv_validation = Arc::new(crate::kv::KvValidationCache::default());
        let runtime_kv = Arc::new(RuntimeStore::from_engine_with_quota_and_content_validation(
            Arc::clone(&engine),
            StateOwnerResolver::new(self.principals.clone()),
            Arc::clone(&quota),
            Arc::clone(&kv_validation),
            Arc::clone(&catalogs),
        ));
        let kv: Arc<dyn crate::KvStore> = runtime_kv.clone();
        let content = Arc::new(
            NativePrincipalContentStore::from_engine_with_quota_and_validation(
                Arc::clone(&engine),
                quota,
                catalogs,
                kv_validation,
            ),
        );
        let store = Self {
            engine,
            directory_cutover_receipt: Arc::clone(&self.directory_cutover_receipt),
            runtime_kv,
            kv,
            content,
            staging: Arc::new(OnceLock::new()),
            principals: self.principals.clone(),
        };
        Ok(RuntimeRetirement {
            home: home.clone(),
            store,
            shutdown_error: None,
        })
    }
}

impl RuntimeRetirement {
    /// Preserve an earlier shutdown error while retaining exclusive packing
    /// ownership. Finalization still packs and closes before returning it.
    pub fn record_shutdown_error(&mut self, error: StorageError) {
        self.shutdown_error.get_or_insert(error);
    }

    pub(super) fn finish(&mut self, home: &AstridHome) -> StorageResult<()> {
        if home.root() != self.home.root() {
            return Err(StorageError::Connection(
                "retirement belongs to a different home".into(),
            ));
        }
        let packed = self.store.pack_and_retire_runtime_projection(home);
        let closed = self.store.engine.close().map_err(|error| {
            StorageError::Connection(format!("close finalization store: {error}"))
        });
        packed.and(closed)?;
        // An audit/KV close error is not proven harmless merely because the
        // host projection packed. Preserve failed overall shutdown, while
        // distinguishing successful retirement from an incomplete pack.
        if let Some(error) = self.shutdown_error.take() {
            return Err(StorageError::Internal(format!(
                "durable home packed and closed; earlier shutdown failed: {error}"
            )));
        }
        Ok(())
    }
}

impl Drop for RuntimeRetirement {
    fn drop(&mut self) {
        if let Err(error) = self.store.engine.close() {
            tracing::error!(%error, "failed to close abandoned finalization owner");
        }
    }
}

#[cfg(test)]
mod tests;

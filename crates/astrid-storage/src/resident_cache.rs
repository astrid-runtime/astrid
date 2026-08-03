//! Resident-memory authority adapter for the decoded-object cache.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Arc;

use astrid_resources::{
    ElasticLogicalMemoryPool, ElasticPhysicalMemoryPool, MemoryClass, MemorySubsystem,
    ResidentMemoryAuthority,
};
use astrid_storage_engine::{
    ObjectCacheCapacity, ObjectCacheConfig, ObjectCacheController, ObjectCacheMemoryBudget,
    PrincipalObjectCacheBudget,
};
use parking_lot::Mutex;

use crate::StateOwner;

struct GovernedObjectCacheInner {
    authority: ResidentMemoryAuthority<StateOwner>,
    physical: ElasticPhysicalMemoryPool<StateOwner>,
    logical: Mutex<BTreeMap<StateOwner, ElasticLogicalMemoryPool<StateOwner>>>,
}

/// Coarse resident-memory leases backing one decoded-object cache.
///
/// The embedding runtime owns principal registration and limits in the shared
/// [`ResidentMemoryAuthority`]. This adapter creates one physical slab for
/// shared immutable bytes and one logical slab per principal. Slabs grow
/// geometrically, so ordinary cache hits never acquire the authority lock.
/// Admission refusal disables only retention; authoritative reads continue.
#[derive(Clone)]
pub struct GovernedObjectCache {
    inner: Arc<GovernedObjectCacheInner>,
}

impl GovernedObjectCache {
    /// Bind the storage cache to the process-wide memory authority.
    #[must_use]
    pub fn new(authority: ResidentMemoryAuthority<StateOwner>) -> Self {
        Self {
            inner: Arc::new(GovernedObjectCacheInner {
                physical: ElasticPhysicalMemoryPool::new(
                    authority.clone(),
                    None,
                    MemorySubsystem::StorageCache,
                    MemoryClass::Evictable,
                ),
                authority,
                logical: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// Build the engine cache policy using this adapter for both ledgers.
    #[must_use]
    pub fn config(&self) -> ObjectCacheConfig<StateOwner> {
        ObjectCacheConfig::new(
            ObjectCacheController::governed(Arc::new(self.clone())),
            Arc::new(self.clone()),
        )
    }

    fn logical_pool(&self, principal: &StateOwner) -> ElasticLogicalMemoryPool<StateOwner> {
        self.inner
            .logical
            .lock()
            .entry(*principal)
            .or_insert_with(|| {
                ElasticLogicalMemoryPool::new(
                    self.inner.authority.clone(),
                    *principal,
                    MemorySubsystem::StorageCache,
                    MemoryClass::Evictable,
                )
            })
            .clone()
    }
}

impl ObjectCacheMemoryBudget for GovernedObjectCache {
    fn capacity(&self) -> ObjectCacheCapacity {
        capacity(self.inner.physical.requested_capacity())
    }

    fn ensure_capacity(&self, required: u64) -> ObjectCacheCapacity {
        let bytes = self
            .inner
            .physical
            .ensure_capacity(required)
            .unwrap_or_else(|_| self.inner.physical.requested_capacity());
        capacity(bytes)
    }

    fn reconcile(&self, resident_bytes: u64) {
        let _ = self.inner.physical.reconcile_usage(resident_bytes);
    }

    fn release_unused(&self, resident_bytes: u64) {
        let _ = self.inner.physical.trim_to_usage(resident_bytes);
    }
}

impl PrincipalObjectCacheBudget<StateOwner> for GovernedObjectCache {
    fn capacity(&self, principal: &StateOwner) -> ObjectCacheCapacity {
        capacity(self.logical_pool(principal).requested_capacity())
    }

    fn ensure_capacity(&self, principal: &StateOwner, required: u64) -> ObjectCacheCapacity {
        let pool = self.logical_pool(principal);
        let bytes = pool
            .ensure_capacity(required)
            .unwrap_or_else(|_| pool.requested_capacity());
        capacity(bytes)
    }

    fn reconcile(&self, principal: &StateOwner, charged_bytes: u64) {
        let _ = self.logical_pool(principal).reconcile_usage(charged_bytes);
    }

    fn release_unused(&self, principal: &StateOwner, charged_bytes: u64) {
        let _ = self.logical_pool(principal).trim_to_usage(charged_bytes);
    }
}

fn capacity(bytes: u64) -> ObjectCacheCapacity {
    NonZeroU64::new(bytes).map_or(ObjectCacheCapacity::Disabled, ObjectCacheCapacity::Bounded)
}

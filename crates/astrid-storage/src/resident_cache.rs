//! Resident-memory authority adapter for the decoded-object cache.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Arc;

use crate::engine::{
    ObjectCacheCapacity, ObjectCacheConfig, ObjectCacheController, ObjectCacheMemoryBudget,
    PrincipalObjectCacheBudget,
};
use crate::resources::{
    ElasticLogicalMemoryPool, ElasticPhysicalMemoryPool, MemoryClass, MemorySubsystem,
    ResidentMemoryAuthority,
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

    fn logical_pool(&self, principal: &StateOwner) -> Option<ElasticLogicalMemoryPool<StateOwner>> {
        self.inner.logical.lock().get(principal).cloned()
    }

    fn ensure_logical_capacity(&self, principal: &StateOwner, required: u64) -> u64 {
        let mut logical = self.inner.logical.lock();
        if let Some(pool) = logical.get(principal) {
            return pool
                .ensure_capacity(required)
                .unwrap_or_else(|_| pool.requested_capacity());
        }
        let pool = ElasticLogicalMemoryPool::new(
            self.inner.authority.clone(),
            *principal,
            MemorySubsystem::StorageCache,
            MemoryClass::Evictable,
        );
        let Ok(bytes) = pool.ensure_capacity(required) else {
            return 0;
        };
        logical.insert(*principal, pool);
        bytes
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
        self.logical_pool(principal)
            .map_or(ObjectCacheCapacity::Disabled, |pool| {
                capacity(pool.requested_capacity())
            })
    }

    fn ensure_capacity(&self, principal: &StateOwner, required: u64) -> ObjectCacheCapacity {
        capacity(self.ensure_logical_capacity(principal, required))
    }

    fn reconcile(&self, principal: &StateOwner, charged_bytes: u64) {
        if let Some(pool) = self.logical_pool(principal) {
            let _ = pool.reconcile_usage(charged_bytes);
        }
    }

    fn release_unused(&self, principal: &StateOwner, charged_bytes: u64) {
        if let Some(pool) = self.logical_pool(principal) {
            let _ = pool.trim_to_usage(charged_bytes);
        }
    }

    fn release_unused_all(&self, charged_bytes: &BTreeMap<StateOwner, u64>) {
        self.inner.logical.lock().retain(|principal, pool| {
            let used = charged_bytes.get(principal).copied().unwrap_or(0);
            pool.trim_to_usage(used).is_err() || used != 0
        });
    }
}

fn capacity(bytes: u64) -> ObjectCacheCapacity {
    NonZeroU64::new(bytes).map_or(ObjectCacheCapacity::Disabled, ObjectCacheCapacity::Bounded)
}

#[cfg(test)]
mod tests {
    use astrid_core::identity::PrincipalUid;

    use super::*;

    #[test]
    fn unknown_principal_does_not_leave_an_empty_pool() {
        let authority = ResidentMemoryAuthority::new(1024);
        authority
            .register_principal(StateOwner::System, None, 1024)
            .unwrap();
        let cache = GovernedObjectCache::new(authority.clone());
        let unknown = StateOwner::Principal(PrincipalUid::from_bytes([7; 32]));

        assert_eq!(
            PrincipalObjectCacheBudget::capacity(&cache, &unknown),
            ObjectCacheCapacity::Disabled
        );
        assert_eq!(
            PrincipalObjectCacheBudget::ensure_capacity(&cache, &unknown, 64),
            ObjectCacheCapacity::Disabled
        );
        assert!(cache.inner.logical.lock().is_empty());
        assert!(authority.snapshot().logical_leases.is_empty());
    }

    #[test]
    fn complete_reclaim_releases_pools_without_live_partitions() {
        let authority = ResidentMemoryAuthority::new(1024);
        let owner = StateOwner::Principal(PrincipalUid::from_bytes([9; 32]));
        authority.register_principal(owner, None, 1024).unwrap();
        let cache = GovernedObjectCache::new(authority.clone());

        assert_eq!(
            PrincipalObjectCacheBudget::ensure_capacity(&cache, &owner, 64),
            ObjectCacheCapacity::Bounded(NonZeroU64::new(64).unwrap())
        );
        assert_eq!(authority.snapshot().logical_leases.len(), 1);

        PrincipalObjectCacheBudget::release_unused_all(&cache, &BTreeMap::new());

        assert!(cache.inner.logical.lock().is_empty());
        assert!(authority.snapshot().logical_leases.is_empty());
        authority.remove_principal(&owner).unwrap();
    }
}

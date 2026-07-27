//! Resource-accounted cache for verified immutable arena objects.
//!
//! Physical records are shared by `ObjectId`, while every principal that uses
//! one is charged its full cache weight. Charging does not vary with sharing,
//! so principal-visible resource accounting cannot reveal a deduplication hit.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use astrid_storage_model::{ObjectId, ObjectRecord};
use parking_lot::Mutex;

#[path = "durable_cache/policy.rs"]
mod policy;

pub use policy::{
    ObjectCacheCapacity, ObjectCacheConfig, ObjectCacheController, ObjectCacheStats,
    PrincipalObjectCacheBudget,
};

struct CachedObject<P: Ord> {
    record: Arc<ObjectRecord>,
    weight: u64,
    last_access: u64,
    principals: BTreeSet<P>,
}

#[derive(Default)]
struct PrincipalPartition {
    entries: BTreeMap<ObjectId, u64>,
    charged_bytes: u64,
}

struct CacheState<P: Ord> {
    entries: BTreeMap<ObjectId, CachedObject<P>>,
    principals: BTreeMap<P, PrincipalPartition>,
    resident_bytes: u64,
    clock: u64,
    hits: u64,
    misses: u64,
    bypasses: u64,
    insertions: u64,
    evictions: u64,
}

impl<P: Ord> Default for CacheState<P> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            principals: BTreeMap::new(),
            resident_bytes: 0,
            clock: 0,
            hits: 0,
            misses: 0,
            bypasses: 0,
            insertions: 0,
            evictions: 0,
        }
    }
}

pub(super) struct ObjectCache<P: Ord> {
    controller: ObjectCacheController,
    principal_budget: Arc<dyn PrincipalObjectCacheBudget<P>>,
    state: Mutex<CacheState<P>>,
}

impl<P> ObjectCache<P>
where
    P: Clone + Ord,
{
    pub(super) fn new(config: ObjectCacheConfig<P>) -> Self {
        Self {
            controller: config.controller,
            principal_budget: config.principal_budget,
            state: Mutex::new(CacheState::default()),
        }
    }

    pub(super) fn get(&self, principal: &P, object: ObjectId) -> Option<Arc<ObjectRecord>> {
        let global_capacity = self.controller.capacity();
        let principal_capacity = self.principal_budget.capacity(principal);
        if global_capacity == ObjectCacheCapacity::Disabled
            || principal_capacity == ObjectCacheCapacity::Disabled
        {
            let mut state = self.state.lock();
            state.bypasses = state.bypasses.saturating_add(1);
            return None;
        }

        let mut state = self.state.lock();
        state.trim_global(global_capacity);
        state.trim_principal(principal, principal_capacity);
        let Some(weight) = state.entries.get(&object).map(|entry| entry.weight) else {
            state.misses = state.misses.saturating_add(1);
            return None;
        };
        if !principal_capacity.accepts(weight) {
            state.bypasses = state.bypasses.saturating_add(1);
            return None;
        }
        state.attach_principal(principal, object, weight, principal_capacity);
        let tick = state.tick();
        let record = {
            let entry = state.entries.get_mut(&object)?;
            entry.last_access = tick;
            entry.principals.insert(principal.clone());
            Arc::clone(&entry.record)
        };
        if let Some(partition) = state.principals.get_mut(principal) {
            partition.entries.insert(object, tick);
        }
        state.hits = state.hits.saturating_add(1);
        Some(record)
    }

    pub(super) fn insert(
        &self,
        principal: &P,
        object: ObjectId,
        record: ObjectRecord,
    ) -> Arc<ObjectRecord> {
        let record = Arc::new(record);
        let weight = cache_weight(&record);
        let global_capacity = self.controller.capacity();
        let principal_capacity = self.principal_budget.capacity(principal);
        if !global_capacity.accepts(weight) || !principal_capacity.accepts(weight) {
            return record;
        }

        let mut state = self.state.lock();
        state.trim_global(global_capacity);
        state.trim_principal(principal, principal_capacity);
        if state.entries.contains_key(&object) {
            state.attach_principal(principal, object, weight, principal_capacity);
            let tick = state.tick();
            let cached = state.entries.get_mut(&object).map(|entry| {
                entry.last_access = tick;
                entry.principals.insert(principal.clone());
                Arc::clone(&entry.record)
            });
            if let Some(partition) = state.principals.get_mut(principal) {
                partition.entries.insert(object, tick);
            }
            return cached.unwrap_or(record);
        }

        state.evict_principal_until_fits(principal, weight, principal_capacity);
        state.evict_global_until_fits(weight, global_capacity);
        if !state.can_fit_principal(principal, weight, principal_capacity)
            || !state.can_fit_global(weight, global_capacity)
        {
            return record;
        }

        let tick = state.tick();
        let mut principals = BTreeSet::new();
        principals.insert(principal.clone());
        state.entries.insert(
            object,
            CachedObject {
                record: Arc::clone(&record),
                weight,
                last_access: tick,
                principals,
            },
        );
        let partition = state.principals.entry(principal.clone()).or_default();
        partition.entries.insert(object, tick);
        partition.charged_bytes = partition.charged_bytes.saturating_add(weight);
        state.resident_bytes = state.resident_bytes.saturating_add(weight);
        state.insertions = state.insertions.saturating_add(1);
        record
    }

    pub(super) fn stats(&self) -> ObjectCacheStats {
        let state = self.state.lock();
        ObjectCacheStats {
            hits: state.hits,
            misses: state.misses,
            bypasses: state.bypasses,
            insertions: state.insertions,
            evictions: state.evictions,
            resident_objects: u64::try_from(state.entries.len()).unwrap_or(u64::MAX),
            resident_bytes: state.resident_bytes,
        }
    }

    pub(super) fn principal_charge(&self, principal: &P) -> u64 {
        self.state
            .lock()
            .principals
            .get(principal)
            .map_or(0, |partition| partition.charged_bytes)
    }
}

impl<P> CacheState<P>
where
    P: Clone + Ord,
{
    fn tick(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }

    fn attach_principal(
        &mut self,
        principal: &P,
        object: ObjectId,
        weight: u64,
        capacity: ObjectCacheCapacity,
    ) {
        if self
            .principals
            .get(principal)
            .is_some_and(|partition| partition.entries.contains_key(&object))
        {
            return;
        }
        self.evict_principal_until_fits(principal, weight, capacity);
        if !self.can_fit_principal(principal, weight, capacity) {
            return;
        }
        let partition = self.principals.entry(principal.clone()).or_default();
        partition.charged_bytes = partition.charged_bytes.saturating_add(weight);
    }

    fn can_fit_principal(&self, principal: &P, weight: u64, capacity: ObjectCacheCapacity) -> bool {
        let charged = self
            .principals
            .get(principal)
            .map_or(0, |partition| partition.charged_bytes);
        capacity.limit().is_none_or(|limit| {
            charged
                .checked_add(weight)
                .is_some_and(|total| total <= limit)
        })
    }

    fn can_fit_global(&self, weight: u64, capacity: ObjectCacheCapacity) -> bool {
        capacity.limit().is_none_or(|limit| {
            self.resident_bytes
                .checked_add(weight)
                .is_some_and(|total| total <= limit)
        })
    }

    fn evict_principal_until_fits(
        &mut self,
        principal: &P,
        weight: u64,
        capacity: ObjectCacheCapacity,
    ) {
        while !self.can_fit_principal(principal, weight, capacity) {
            let victim = self.principals.get(principal).and_then(|partition| {
                partition
                    .entries
                    .iter()
                    .min_by_key(|(_, tick)| *tick)
                    .map(|(object, _)| *object)
            });
            let Some(victim) = victim else {
                break;
            };
            self.detach_principal(principal, victim);
        }
    }

    fn trim_principal(&mut self, principal: &P, capacity: ObjectCacheCapacity) {
        while capacity.limit().is_some_and(|limit| {
            self.principals
                .get(principal)
                .is_some_and(|partition| partition.charged_bytes > limit)
        }) {
            let victim = self.principals.get(principal).and_then(|partition| {
                partition
                    .entries
                    .iter()
                    .min_by_key(|(_, tick)| *tick)
                    .map(|(object, _)| *object)
            });
            let Some(victim) = victim else {
                break;
            };
            self.detach_principal(principal, victim);
        }
    }

    fn evict_global_until_fits(&mut self, weight: u64, capacity: ObjectCacheCapacity) {
        while !self.can_fit_global(weight, capacity) {
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_access)
                .map(|(object, _)| *object);
            let Some(victim) = victim else {
                break;
            };
            self.remove_physical(victim);
        }
    }

    fn trim_global(&mut self, capacity: ObjectCacheCapacity) {
        while capacity
            .limit()
            .is_some_and(|limit| self.resident_bytes > limit)
        {
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_access)
                .map(|(object, _)| *object);
            let Some(victim) = victim else {
                break;
            };
            self.remove_physical(victim);
        }
    }

    fn detach_principal(&mut self, principal: &P, object: ObjectId) {
        let weight = self.entries.get(&object).map(|entry| entry.weight);
        let Some(weight) = weight else {
            return;
        };
        if let Some(partition) = self.principals.get_mut(principal)
            && partition.entries.remove(&object).is_some()
        {
            partition.charged_bytes = partition.charged_bytes.saturating_sub(weight);
        }
        if self
            .principals
            .get(principal)
            .is_some_and(|partition| partition.entries.is_empty())
        {
            self.principals.remove(principal);
        }
        let remove_physical = self.entries.get_mut(&object).is_some_and(|entry| {
            entry.principals.remove(principal);
            entry.principals.is_empty()
        });
        if remove_physical {
            self.remove_physical(object);
        }
    }

    fn remove_physical(&mut self, object: ObjectId) {
        let Some(entry) = self.entries.remove(&object) else {
            return;
        };
        for principal in entry.principals {
            if let Some(partition) = self.principals.get_mut(&principal)
                && partition.entries.remove(&object).is_some()
            {
                partition.charged_bytes = partition.charged_bytes.saturating_sub(entry.weight);
            }
            if self
                .principals
                .get(&principal)
                .is_some_and(|partition| partition.entries.is_empty())
            {
                self.principals.remove(&principal);
            }
        }
        self.resident_bytes = self.resident_bytes.saturating_sub(entry.weight);
        self.evictions = self.evictions.saturating_add(1);
    }
}

fn cache_weight(record: &ObjectRecord) -> u64 {
    let record_struct = u64::try_from(std::mem::size_of::<ObjectRecord>()).unwrap_or(u64::MAX);
    record
        .retained_bytes()
        .unwrap_or(u64::MAX)
        .saturating_add(record_struct)
}

#[cfg(test)]
#[path = "durable_cache/tests.rs"]
mod tests;

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
    lru: BTreeSet<(u64, ObjectId)>,
    charged_bytes: u64,
}

struct CacheState<P: Ord> {
    entries: BTreeMap<ObjectId, CachedObject<P>>,
    lru: BTreeSet<(u64, ObjectId)>,
    principals: BTreeMap<P, PrincipalPartition>,
    resident_record_bytes: u64,
    resident_association_bytes: u64,
    resident_associations: u64,
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
            lru: BTreeSet::new(),
            principals: BTreeMap::new(),
            resident_record_bytes: 0,
            resident_association_bytes: 0,
            resident_associations: 0,
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
        if !state.is_attached(principal, object) {
            let association_weight = association_weight::<P>();
            state.evict_global_until_fits(association_weight, global_capacity, Some(object));
            if !state.can_fit_global(association_weight, global_capacity)
                || !state.attach_principal(principal, object, weight, principal_capacity)
            {
                state.bypasses = state.bypasses.saturating_add(1);
                return None;
            }
        }
        let record = state.touch(principal, object)?;
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
        let association_weight = association_weight::<P>();
        let global_capacity = self.controller.capacity();
        let principal_capacity = self.principal_budget.capacity(principal);
        let initial_weight = weight.saturating_add(association_weight);
        if !global_capacity.accepts(initial_weight) || !principal_capacity.accepts(weight) {
            return record;
        }

        let mut state = self.state.lock();
        state.trim_global(global_capacity);
        state.trim_principal(principal, principal_capacity);
        if state.entries.contains_key(&object) {
            if !state.is_attached(principal, object) {
                state.evict_global_until_fits(association_weight, global_capacity, Some(object));
                if !state.can_fit_global(association_weight, global_capacity)
                    || !state.attach_principal(principal, object, weight, principal_capacity)
                {
                    return record;
                }
            }
            return state.touch(principal, object).unwrap_or(record);
        }

        state.evict_principal_until_fits(principal, weight, principal_capacity);
        state.evict_global_until_fits(initial_weight, global_capacity, None);
        if !state.can_fit_principal(principal, weight, principal_capacity)
            || !state.can_fit_global(initial_weight, global_capacity)
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
        state.lru.insert((tick, object));
        let partition = state.principals.entry(principal.clone()).or_default();
        partition.entries.insert(object, tick);
        partition.lru.insert((tick, object));
        partition.charged_bytes = partition.charged_bytes.saturating_add(weight);
        state.resident_record_bytes = state.resident_record_bytes.saturating_add(weight);
        state.resident_association_bytes = state
            .resident_association_bytes
            .saturating_add(association_weight);
        state.resident_associations = state.resident_associations.saturating_add(1);
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
            resident_bytes: state.resident_bytes(),
            resident_record_bytes: state.resident_record_bytes,
            resident_association_bytes: state.resident_association_bytes,
            resident_associations: state.resident_associations,
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

    fn touch(&mut self, principal: &P, object: ObjectId) -> Option<Arc<ObjectRecord>> {
        if !self.entries.contains_key(&object) || !self.principals.contains_key(principal) {
            return None;
        }
        let tick = self.tick();
        let (previous_tick, record) = {
            let entry = self.entries.get_mut(&object)?;
            let previous_tick = entry.last_access;
            entry.last_access = tick;
            entry.principals.insert(principal.clone());
            (previous_tick, Arc::clone(&entry.record))
        };
        self.lru.remove(&(previous_tick, object));
        self.lru.insert((tick, object));
        let partition = self.principals.get_mut(principal)?;
        if let Some(previous_tick) = partition.entries.insert(object, tick) {
            partition.lru.remove(&(previous_tick, object));
        }
        partition.lru.insert((tick, object));
        Some(record)
    }

    fn is_attached(&self, principal: &P, object: ObjectId) -> bool {
        self.principals
            .get(principal)
            .is_some_and(|partition| partition.entries.contains_key(&object))
    }

    fn attach_principal(
        &mut self,
        principal: &P,
        object: ObjectId,
        weight: u64,
        capacity: ObjectCacheCapacity,
    ) -> bool {
        if self.is_attached(principal, object) {
            return true;
        }
        self.evict_principal_until_fits(principal, weight, capacity);
        if !self.can_fit_principal(principal, weight, capacity) {
            return false;
        }
        let partition = self.principals.entry(principal.clone()).or_default();
        partition.charged_bytes = partition.charged_bytes.saturating_add(weight);
        self.resident_association_bytes = self
            .resident_association_bytes
            .saturating_add(association_weight::<P>());
        self.resident_associations = self.resident_associations.saturating_add(1);
        true
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
            self.resident_bytes()
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
            let victim = self
                .principals
                .get(principal)
                .and_then(|partition| partition.lru.first().map(|(_, object)| *object));
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
            let victim = self
                .principals
                .get(principal)
                .and_then(|partition| partition.lru.first().map(|(_, object)| *object));
            let Some(victim) = victim else {
                break;
            };
            self.detach_principal(principal, victim);
        }
    }

    fn evict_global_until_fits(
        &mut self,
        weight: u64,
        capacity: ObjectCacheCapacity,
        protected: Option<ObjectId>,
    ) {
        while !self.can_fit_global(weight, capacity) {
            let victim = self
                .lru
                .iter()
                .find(|(_, object)| Some(*object) != protected)
                .map(|(_, object)| *object);
            let Some(victim) = victim else {
                break;
            };
            self.remove_physical(victim);
        }
    }

    fn trim_global(&mut self, capacity: ObjectCacheCapacity) {
        while capacity
            .limit()
            .is_some_and(|limit| self.resident_bytes() > limit)
        {
            let victim = self.lru.first().map(|(_, object)| *object);
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
            && let Some(tick) = partition.entries.remove(&object)
        {
            partition.lru.remove(&(tick, object));
            partition.charged_bytes = partition.charged_bytes.saturating_sub(weight);
            self.resident_association_bytes = self
                .resident_association_bytes
                .saturating_sub(association_weight::<P>());
            self.resident_associations = self.resident_associations.saturating_sub(1);
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
        self.lru.remove(&(entry.last_access, object));
        for principal in entry.principals {
            if let Some(partition) = self.principals.get_mut(&principal)
                && let Some(tick) = partition.entries.remove(&object)
            {
                partition.lru.remove(&(tick, object));
                partition.charged_bytes = partition.charged_bytes.saturating_sub(entry.weight);
                self.resident_association_bytes = self
                    .resident_association_bytes
                    .saturating_sub(association_weight::<P>());
                self.resident_associations = self.resident_associations.saturating_sub(1);
            }
            if self
                .principals
                .get(&principal)
                .is_some_and(|partition| partition.entries.is_empty())
            {
                self.principals.remove(&principal);
            }
        }
        self.resident_record_bytes = self.resident_record_bytes.saturating_sub(entry.weight);
        self.evictions = self.evictions.saturating_add(1);
    }

    fn resident_bytes(&self) -> u64 {
        self.resident_record_bytes
            .saturating_add(self.resident_association_bytes)
    }
}

fn cache_weight(record: &ObjectRecord) -> u64 {
    let resident_metadata = std::mem::size_of::<ObjectRecord>()
        .saturating_add(std::mem::size_of::<Arc<ObjectRecord>>())
        .saturating_add(std::mem::size_of::<ObjectId>())
        .saturating_add(std::mem::size_of::<u64>());
    record
        .retained_bytes()
        .unwrap_or(u64::MAX)
        .saturating_add(u64::try_from(resident_metadata).unwrap_or(u64::MAX))
}

fn association_weight<P>() -> u64 {
    u64::try_from(
        std::mem::size_of::<P>()
            .saturating_add(std::mem::size_of::<ObjectId>())
            .saturating_add(std::mem::size_of::<u64>())
            .saturating_add(std::mem::size_of::<ObjectId>())
            .saturating_add(std::mem::size_of::<u64>()),
    )
    .unwrap_or(u64::MAX)
}

#[cfg(test)]
#[path = "durable_cache/tests.rs"]
mod tests;

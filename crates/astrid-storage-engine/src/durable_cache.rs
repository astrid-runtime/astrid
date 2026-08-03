//! Resource-accounted cache for verified immutable arena objects and
//! projection-owned accelerators.
//!
//! Physical records are shared by `ObjectId`, while every principal that uses
//! one is charged its full cache weight. Charging does not vary with sharing,
//! so principal-visible resource accounting cannot reveal a deduplication hit.
//! Type-erased projection values remain principal-local and are charged to the
//! same injected total and per-principal budgets.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::{ProjectionCacheEntry, ProjectionCacheKey};
use astrid_storage_model::{ObjectId, ObjectRecord};
use parking_lot::Mutex;

#[path = "durable_cache/policy.rs"]
mod policy;

pub use policy::{
    ObjectCacheCapacity, ObjectCacheConfig, ObjectCacheController, ObjectCacheMemoryBudget,
    ObjectCacheStats, PrincipalObjectCacheBudget,
};

struct CachedObject<P: Ord> {
    record: Arc<ObjectRecord>,
    weight: u64,
    last_access: u64,
    principals: BTreeSet<P>,
}

struct CachedProjection {
    value: Arc<dyn Any + Send + Sync>,
    weight: u64,
}

#[derive(Clone, Copy)]
struct CacheAdmission {
    global: ObjectCacheCapacity,
    principal: ObjectCacheCapacity,
}

struct PrincipalEntry {
    last_access: u64,
    projections: BTreeMap<ProjectionCacheKey, CachedProjection>,
}

#[derive(Default)]
struct PrincipalPartition {
    entries: BTreeMap<ObjectId, PrincipalEntry>,
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
    resident_projection_bytes: u64,
    resident_projection_entries: u64,
    clock: u64,
    hits: u64,
    misses: u64,
    bypasses: u64,
    insertions: u64,
    evictions: u64,
    projection_hits: u64,
    projection_misses: u64,
    projection_insertions: u64,
    projection_evictions: u64,
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
            resident_projection_bytes: 0,
            resident_projection_entries: 0,
            clock: 0,
            hits: 0,
            misses: 0,
            bypasses: 0,
            insertions: 0,
            evictions: 0,
            projection_hits: 0,
            projection_misses: 0,
            projection_insertions: 0,
            projection_evictions: 0,
        }
    }
}

pub(super) struct ObjectCache<P: Ord> {
    controller: ObjectCacheController,
    principal_budget: Arc<dyn PrincipalObjectCacheBudget<P>>,
    accounting: Mutex<()>,
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
            accounting: Mutex::new(()),
            state: Mutex::new(CacheState::default()),
        }
    }

    pub(super) fn get(&self, principal: &P, object: ObjectId) -> Option<Arc<ObjectRecord>> {
        let _accounting = self.accounting.lock();
        let (global_required, principal_required) = {
            let state = self.state.lock();
            let weight = state.entries.get(&object).map_or(0, |entry| entry.weight);
            if weight == 0 || state.is_attached(principal, object) {
                (state.resident_bytes(), state.principal_charge(principal))
            } else {
                (
                    state
                        .resident_bytes()
                        .saturating_add(association_weight::<P>()),
                    state.principal_charge(principal).saturating_add(weight),
                )
            }
        };
        let global_capacity = self.controller.ensure_capacity(global_required);
        let principal_capacity = if global_capacity == ObjectCacheCapacity::Disabled {
            ObjectCacheCapacity::Disabled
        } else {
            self.principal_budget
                .ensure_capacity(principal, principal_required)
        };
        let mut state = self.state.lock();
        let global_capacity = global_capacity.min(self.controller.capacity());
        let principal_capacity = principal_capacity.min(self.principal_budget.capacity(principal));
        state.trim_global(global_capacity);
        state.trim_principal(principal, principal_capacity);
        let result = 'cache: {
            if global_capacity == ObjectCacheCapacity::Disabled
                || principal_capacity == ObjectCacheCapacity::Disabled
            {
                state.bypasses = state.bypasses.saturating_add(1);
                break 'cache None;
            }

            let Some(weight) = state.entries.get(&object).map(|entry| entry.weight) else {
                state.misses = state.misses.saturating_add(1);
                break 'cache None;
            };
            if !principal_capacity.accepts(weight) {
                state.bypasses = state.bypasses.saturating_add(1);
                break 'cache None;
            }
            if !state.is_attached(principal, object) {
                let association_weight = association_weight::<P>();
                state.evict_global_until_fits(association_weight, global_capacity, Some(object));
                if !state.can_fit_global(association_weight, global_capacity)
                    || !state.attach_principal(principal, object, weight, principal_capacity)
                {
                    state.bypasses = state.bypasses.saturating_add(1);
                    break 'cache None;
                }
            }
            let Some(record) = state.touch(principal, object) else {
                break 'cache None;
            };
            state.hits = state.hits.saturating_add(1);
            Some(record)
        };
        let resident = state.resident_bytes();
        let charged = state.principal_charge(principal);
        drop(state);
        // Reconciliation may acknowledge an authority pressure target and
        // shrink a slab. The accounting guard keeps this byte count ordered
        // with every admission and explicit release without invoking an
        // external policy while the cache-state lock is held.
        self.controller.reconcile(resident);
        self.principal_budget.reconcile(principal, charged);
        result
    }

    pub(super) fn insert(
        &self,
        principal: &P,
        object: ObjectId,
        record: ObjectRecord,
    ) -> Arc<ObjectRecord> {
        let _accounting = self.accounting.lock();
        let record = Arc::new(record);
        let weight = cache_weight(&record);
        let association_weight = association_weight::<P>();
        let initial_weight = weight.saturating_add(association_weight);
        let (global_required, principal_required) = {
            let state = self.state.lock();
            if state.entries.contains_key(&object) {
                if state.is_attached(principal, object) {
                    (state.resident_bytes(), state.principal_charge(principal))
                } else {
                    (
                        state.resident_bytes().saturating_add(association_weight),
                        state.principal_charge(principal).saturating_add(weight),
                    )
                }
            } else {
                (
                    state.resident_bytes().saturating_add(initial_weight),
                    state.principal_charge(principal).saturating_add(weight),
                )
            }
        };
        let global_capacity = self.controller.ensure_capacity(global_required);
        let principal_capacity = if global_capacity == ObjectCacheCapacity::Disabled {
            ObjectCacheCapacity::Disabled
        } else {
            self.principal_budget
                .ensure_capacity(principal, principal_required)
        };
        let mut state = self.state.lock();
        let global_capacity = global_capacity.min(self.controller.capacity());
        let principal_capacity = principal_capacity.min(self.principal_budget.capacity(principal));
        state.trim_global(global_capacity);
        state.trim_principal(principal, principal_capacity);
        let result = 'cache: {
            if !global_capacity.accepts(initial_weight) || !principal_capacity.accepts(weight) {
                break 'cache Arc::clone(&record);
            }

            if state.entries.contains_key(&object) {
                if !state.is_attached(principal, object) {
                    state.evict_global_until_fits(
                        association_weight,
                        global_capacity,
                        Some(object),
                    );
                    if !state.can_fit_global(association_weight, global_capacity)
                        || !state.attach_principal(principal, object, weight, principal_capacity)
                    {
                        break 'cache Arc::clone(&record);
                    }
                }
                break 'cache state
                    .touch(principal, object)
                    .unwrap_or_else(|| Arc::clone(&record));
            }

            state.evict_principal_until_fits(principal, weight, principal_capacity);
            state.evict_global_until_fits(initial_weight, global_capacity, None);
            if !state.can_fit_principal(principal, weight, principal_capacity)
                || !state.can_fit_global(initial_weight, global_capacity)
            {
                break 'cache Arc::clone(&record);
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
            partition.entries.insert(
                object,
                PrincipalEntry {
                    last_access: tick,
                    projections: BTreeMap::new(),
                },
            );
            partition.lru.insert((tick, object));
            partition.charged_bytes = partition.charged_bytes.saturating_add(weight);
            state.resident_record_bytes = state.resident_record_bytes.saturating_add(weight);
            state.resident_association_bytes = state
                .resident_association_bytes
                .saturating_add(association_weight);
            state.resident_associations = state.resident_associations.saturating_add(1);
            state.insertions = state.insertions.saturating_add(1);
            Arc::clone(&record)
        };
        let resident = state.resident_bytes();
        let charged = state.principal_charge(principal);
        drop(state);
        self.controller.reconcile(resident);
        self.principal_budget.reconcile(principal, charged);
        result
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
            projection_hits: state.projection_hits,
            projection_misses: state.projection_misses,
            projection_insertions: state.projection_insertions,
            projection_evictions: state.projection_evictions,
            resident_projection_bytes: state.resident_projection_bytes,
            resident_projection_entries: state.resident_projection_entries,
        }
    }

    pub(super) fn principal_charge(&self, principal: &P) -> u64 {
        self.state
            .lock()
            .principals
            .get(principal)
            .map_or(0, |partition| partition.charged_bytes)
    }

    pub(super) fn projection(
        &self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
    ) -> Option<ProjectionCacheEntry> {
        let global_capacity = self.controller.capacity();
        let principal_capacity = self.principal_budget.capacity(principal);
        let mut state = self.state.lock();
        state.trim_global(global_capacity);
        state.trim_principal(principal, principal_capacity);
        if global_capacity == ObjectCacheCapacity::Disabled
            || principal_capacity == ObjectCacheCapacity::Disabled
        {
            state.projection_misses = state.projection_misses.saturating_add(1);
            return None;
        }
        let value = state
            .principals
            .get(principal)
            .and_then(|partition| partition.entries.get(&object))
            .and_then(|entry| entry.projections.get(&key))
            .map(|entry| Arc::clone(&entry.value));
        let Some(value) = value else {
            state.projection_misses = state.projection_misses.saturating_add(1);
            return None;
        };
        let weight = state
            .principals
            .get(principal)
            .and_then(|partition| partition.entries.get(&object))
            .and_then(|entry| entry.projections.get(&key))
            .map_or(0, |entry| entry.weight);
        if state.touch(principal, object).is_none() {
            state.projection_misses = state.projection_misses.saturating_add(1);
            return None;
        }
        state.projection_hits = state.projection_hits.saturating_add(1);
        Some(ProjectionCacheEntry::from_parts(value, weight))
    }

    pub(super) fn retain_projection(
        &self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
        value: ProjectionCacheEntry,
    ) -> bool {
        let _accounting = self.accounting.lock();
        let (value, payload_weight) = value.into_parts();
        let weight = projection_cache_weight(payload_weight);
        let (global_required, principal_required) = {
            let state = self.state.lock();
            let replaced = state
                .principals
                .get(principal)
                .and_then(|partition| partition.entries.get(&object))
                .and_then(|entry| entry.projections.get(&key))
                .map_or(0, |entry| entry.weight);
            (
                state
                    .resident_bytes()
                    .saturating_sub(replaced)
                    .saturating_add(weight),
                state
                    .principal_charge(principal)
                    .saturating_sub(replaced)
                    .saturating_add(weight),
            )
        };
        let global_capacity = self.controller.ensure_capacity(global_required);
        let principal_capacity = if global_capacity == ObjectCacheCapacity::Disabled {
            ObjectCacheCapacity::Disabled
        } else {
            self.principal_budget
                .ensure_capacity(principal, principal_required)
        };
        let mut state = self.state.lock();
        let global_capacity = global_capacity.min(self.controller.capacity());
        let principal_capacity = principal_capacity.min(self.principal_budget.capacity(principal));
        state.trim_global(global_capacity);
        state.trim_principal(principal, principal_capacity);
        let retained = state.insert_projection(
            principal,
            object,
            key,
            value,
            weight,
            CacheAdmission {
                global: global_capacity,
                principal: principal_capacity,
            },
        );
        let resident = state.resident_bytes();
        let charged = state.principal_charge(principal);
        drop(state);
        self.controller.reconcile(resident);
        self.principal_budget.reconcile(principal, charged);
        retained
    }

    pub(super) fn discard_projection(
        &self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
    ) -> bool {
        self.state.lock().remove_projection(principal, object, key)
    }

    /// Discard cached objects absent from a newly installed authoritative
    /// object set.
    ///
    /// Compaction is the only operation that removes objects from the arena.
    /// Reconciling at installation keeps cache hits observationally identical
    /// to uncached index lookups while preserving entries whose immutable
    /// identities remain live at their new physical locations.
    pub(super) fn retain_objects(&self, mut retain: impl FnMut(ObjectId) -> bool) {
        let mut state = self.state.lock();
        let discarded = state
            .entries
            .keys()
            .copied()
            .filter(|object| !retain(*object))
            .collect::<Vec<_>>();
        for object in discarded {
            state.remove_physical(object);
        }
    }

    pub(super) fn clear(&self) {
        let _accounting = self.accounting.lock();
        let mut state = self.state.lock();
        let objects = state.entries.keys().copied().collect::<Vec<_>>();
        for object in objects {
            state.remove_physical(object);
        }
        drop(state);
        self.controller.release_unused(0);
        self.principal_budget.release_unused_all(&BTreeMap::new());
    }

    /// Honor the latest external pressure targets and return released slabs.
    pub(super) fn reclaim(&self) {
        let _accounting = self.accounting.lock();
        let mut state = self.state.lock();
        let principals = state.principals.keys().cloned().collect::<Vec<_>>();
        let capacities = principals
            .iter()
            .map(|principal| (principal.clone(), self.principal_budget.capacity(principal)))
            .collect::<Vec<_>>();
        let global_capacity = self.controller.capacity();
        state.trim_global(global_capacity);
        for (principal, capacity) in &capacities {
            state.trim_principal(principal, *capacity);
        }
        let resident = state.resident_bytes();
        let charges = state
            .principals
            .iter()
            .map(|(principal, partition)| (principal.clone(), partition.charged_bytes))
            .collect::<BTreeMap<_, _>>();

        drop(state);
        // The accounting guard prevents an admission from committing between
        // the live-byte snapshot and release. Admission also revalidates the
        // authority target after acquiring the cache-state lock.
        self.controller.release_unused(resident);
        self.principal_budget.release_unused_all(&charges);
    }
}

impl<P> CacheState<P>
where
    P: Clone + Ord,
{
    fn principal_charge(&self, principal: &P) -> u64 {
        self.principals
            .get(principal)
            .map_or(0, |partition| partition.charged_bytes)
    }

    fn tick(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }

    fn insert_projection(
        &mut self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
        value: Arc<dyn Any + Send + Sync>,
        weight: u64,
        capacity: CacheAdmission,
    ) -> bool {
        if weight == u64::MAX
            || capacity.global == ObjectCacheCapacity::Disabled
            || capacity.principal == ObjectCacheCapacity::Disabled
            || !self.is_attached(principal, object)
        {
            return false;
        }
        let replaced_weight = self
            .principals
            .get(principal)
            .and_then(|partition| partition.entries.get(&object))
            .and_then(|entry| entry.projections.get(&key))
            .map_or(0, |entry| entry.weight);
        self.evict_principal_until_fits_with_credit(
            principal,
            weight,
            replaced_weight,
            capacity.principal,
            object,
        );
        self.evict_global_until_fits_with_credit(weight, replaced_weight, capacity.global, object);
        if !self.can_fit_principal_with_credit(
            principal,
            weight,
            replaced_weight,
            capacity.principal,
        ) || !self.can_fit_global_with_credit(weight, replaced_weight, capacity.global)
            || !self.is_attached(principal, object)
        {
            return false;
        }

        let Some(partition) = self.principals.get_mut(principal) else {
            return false;
        };
        let Some(entry) = partition.entries.get_mut(&object) else {
            return false;
        };
        let replaced = entry
            .projections
            .insert(key, CachedProjection { value, weight });
        partition.charged_bytes = partition
            .charged_bytes
            .saturating_sub(replaced_weight)
            .saturating_add(weight);
        self.resident_projection_bytes = self
            .resident_projection_bytes
            .saturating_sub(replaced_weight)
            .saturating_add(weight);
        if replaced.is_some() {
            self.projection_evictions = self.projection_evictions.saturating_add(1);
        } else {
            self.resident_projection_entries = self.resident_projection_entries.saturating_add(1);
        }
        self.projection_insertions = self.projection_insertions.saturating_add(1);
        self.touch(principal, object).is_some()
    }

    fn remove_projection(
        &mut self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
    ) -> bool {
        let removed = self
            .principals
            .get_mut(principal)
            .and_then(|partition| partition.entries.get_mut(&object))
            .and_then(|entry| entry.projections.remove(&key));
        let Some(removed) = removed else {
            return false;
        };
        if let Some(partition) = self.principals.get_mut(principal) {
            partition.charged_bytes = partition.charged_bytes.saturating_sub(removed.weight);
        }
        self.resident_projection_bytes = self
            .resident_projection_bytes
            .saturating_sub(removed.weight);
        self.resident_projection_entries = self.resident_projection_entries.saturating_sub(1);
        self.projection_evictions = self.projection_evictions.saturating_add(1);
        true
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
        let entry = partition.entries.get_mut(&object)?;
        let previous_tick = entry.last_access;
        entry.last_access = tick;
        partition.lru.remove(&(previous_tick, object));
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
        partition.entries.insert(
            object,
            PrincipalEntry {
                last_access: self
                    .entries
                    .get(&object)
                    .map_or(self.clock, |entry| entry.last_access),
                projections: BTreeMap::new(),
            },
        );
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

    fn can_fit_principal_with_credit(
        &self,
        principal: &P,
        weight: u64,
        credit: u64,
        capacity: ObjectCacheCapacity,
    ) -> bool {
        let charged = self
            .principals
            .get(principal)
            .map_or(0, |partition| partition.charged_bytes);
        capacity.limit().is_none_or(|limit| {
            charged
                .saturating_sub(credit)
                .checked_add(weight)
                .is_some_and(|total| total <= limit)
        })
    }

    fn can_fit_global_with_credit(
        &self,
        weight: u64,
        credit: u64,
        capacity: ObjectCacheCapacity,
    ) -> bool {
        capacity.limit().is_none_or(|limit| {
            self.resident_bytes()
                .saturating_sub(credit)
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

    fn evict_principal_until_fits_with_credit(
        &mut self,
        principal: &P,
        weight: u64,
        credit: u64,
        capacity: ObjectCacheCapacity,
        protected: ObjectId,
    ) {
        while !self.can_fit_principal_with_credit(principal, weight, credit, capacity) {
            let victim = self.principals.get(principal).and_then(|partition| {
                partition
                    .lru
                    .iter()
                    .find(|(_, object)| *object != protected)
                    .map(|(_, object)| *object)
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

    fn evict_global_until_fits_with_credit(
        &mut self,
        weight: u64,
        credit: u64,
        capacity: ObjectCacheCapacity,
        protected: ObjectId,
    ) {
        while !self.can_fit_global_with_credit(weight, credit, capacity) {
            let victim = self
                .lru
                .iter()
                .find(|(_, object)| *object != protected)
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
            && let Some(entry) = partition.entries.remove(&object)
        {
            let projection = projection_weight(&entry);
            partition.lru.remove(&(entry.last_access, object));
            partition.charged_bytes = partition
                .charged_bytes
                .saturating_sub(weight)
                .saturating_sub(projection);
            self.resident_association_bytes = self
                .resident_association_bytes
                .saturating_sub(association_weight::<P>());
            self.resident_associations = self.resident_associations.saturating_sub(1);
            self.resident_projection_bytes =
                self.resident_projection_bytes.saturating_sub(projection);
            let projection_count = u64::try_from(entry.projections.len()).unwrap_or(u64::MAX);
            self.resident_projection_entries = self
                .resident_projection_entries
                .saturating_sub(projection_count);
            self.projection_evictions = self.projection_evictions.saturating_add(projection_count);
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
                && let Some(principal_entry) = partition.entries.remove(&object)
            {
                let projection = projection_weight(&principal_entry);
                partition.lru.remove(&(principal_entry.last_access, object));
                partition.charged_bytes = partition
                    .charged_bytes
                    .saturating_sub(entry.weight)
                    .saturating_sub(projection);
                self.resident_association_bytes = self
                    .resident_association_bytes
                    .saturating_sub(association_weight::<P>());
                self.resident_associations = self.resident_associations.saturating_sub(1);
                self.resident_projection_bytes =
                    self.resident_projection_bytes.saturating_sub(projection);
                let projection_count =
                    u64::try_from(principal_entry.projections.len()).unwrap_or(u64::MAX);
                self.resident_projection_entries = self
                    .resident_projection_entries
                    .saturating_sub(projection_count);
                self.projection_evictions =
                    self.projection_evictions.saturating_add(projection_count);
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
            .saturating_add(self.resident_projection_bytes)
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

fn projection_weight(entry: &PrincipalEntry) -> u64 {
    entry.projections.values().fold(0_u64, |total, projection| {
        total.saturating_add(projection.weight)
    })
}

fn projection_cache_weight(payload: u64) -> u64 {
    let metadata = std::mem::size_of::<ProjectionCacheKey>()
        .saturating_add(std::mem::size_of::<CachedProjection>())
        .saturating_add(std::mem::size_of::<usize>().saturating_mul(3));
    payload.saturating_add(u64::try_from(metadata).unwrap_or(u64::MAX))
}

#[cfg(test)]
#[path = "durable_cache/tests.rs"]
mod tests;

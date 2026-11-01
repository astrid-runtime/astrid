//! Admission is serialized with explicit owner/cache release.
//!
//! The engine's root-liveness predicate runs under the existing accounting
//! gate, before any capacity reservation or association. Root removal publishes
//! absence before acquiring that gate to discard the owner. An admission that
//! wins the gate is therefore subsequently discarded; one that follows the
//! discard cannot recreate the retired partition. Ordinary cache hits need no
//! durable-engine lock, and no retired-owner tombstone is retained.
use super::*;

impl<P: Clone + Ord> ObjectCache<P> {
    pub(in crate::engine) fn get_if_current(
        &self,
        principal: &P,
        object: ObjectId,
        admitted: impl FnOnce() -> bool,
    ) -> Option<Arc<ObjectRecord>> {
        let _accounting = self.accounting.lock();
        if !admitted() {
            // A retained immutable read may reuse shared physical bytes, but
            // it must not recreate a retired owner's association or lease.
            let mut state = self.state.lock();
            state.bypasses = state.bypasses.saturating_add(1);
            return state
                .entries
                .get(&object)
                .map(|entry| Arc::clone(&entry.record));
        }
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

    pub(in crate::engine) fn insert_if_current(
        &self,
        principal: &P,
        object: ObjectId,
        record: ObjectRecord,
        admitted: impl FnOnce() -> bool,
    ) -> Arc<ObjectRecord> {
        let _accounting = self.accounting.lock();
        if !admitted() {
            return Arc::new(record);
        }
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

    pub(in crate::engine) fn retain_projection_if_current(
        &self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
        value: ProjectionCacheEntry,
        admitted: impl FnOnce() -> bool,
    ) -> bool {
        let _accounting = self.accounting.lock();
        if !admitted() {
            return false;
        }
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
}

//! Admission and LRU access under the cache-state lock.

use super::principals::CachedPrincipals;
use super::{CacheState, PrincipalEntry, association_weight, resident};
use crate::storage_model::{ObjectId, ObjectRecord};
use std::collections::BTreeMap;
use std::sync::Arc;

impl<P: Clone + Ord> CacheState<P> {
    // The caller has checked both live budgets under the state lock. Publish
    // physical custody, both membership directions and their charges together.
    pub(super) fn admit_record(
        &mut self,
        principal: &P,
        object: ObjectId,
        record: Arc<ObjectRecord>,
        weight: u64,
    ) {
        let association_weight = association_weight::<P>();
        let tick = self.tick();
        let principal_key = self.principal_key(principal);
        let principals = CachedPrincipals::new(Arc::clone(&principal_key));
        resident::install(&mut self.entries, object, record, weight, tick, principals);
        self.lru.insert((tick, object));
        let partition = self.principals.entry(principal_key).or_default();
        partition.entries.insert(
            object,
            PrincipalEntry {
                last_access: tick,
                projections: BTreeMap::new(),
            },
        );
        partition.lru.insert((tick, object));
        partition.charged_bytes = partition.charged_bytes.saturating_add(weight);
        self.resident_record_bytes = self.resident_record_bytes.saturating_add(weight);
        self.resident_association_bytes = self
            .resident_association_bytes
            .saturating_add(association_weight);
        self.resident_associations = self.resident_associations.saturating_add(1);
        self.insertions = self.insertions.saturating_add(1);
    }

    pub(super) fn principal_key(&self, principal: &P) -> Arc<P> {
        self.principals
            .get_key_value(principal)
            .map_or_else(|| Arc::new(principal.clone()), |(key, _)| Arc::clone(key))
    }

    pub(super) fn touch(&mut self, principal: &P, object: ObjectId) -> Option<Arc<ObjectRecord>> {
        #[cfg(debug_assertions)]
        let membership = Arc::clone(self.principals.get_key_value(principal)?.0);
        // Resolve both directions before mutating either LRU. Admission owns
        // membership registration; hits only update these existing entries.
        resident::visit(
            principal,
            object,
            &mut self.principals,
            &mut self.entries,
            &mut self.clock,
            &mut self.lru,
            |members| {
                #[cfg(not(debug_assertions))]
                let _ = members;
                #[cfg(debug_assertions)]
                debug_assert!(members.contains(&membership));
            },
        )
    }
}

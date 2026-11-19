//! Whole-cache eviction without rebuilding indexes that are being discarded.

use super::{CacheState, association_weight, projection_weight};

impl<P: Ord> CacheState<P> {
    pub(super) fn clear(&mut self) {
        self.evictions = self
            .evictions
            .saturating_add(u64::try_from(self.entries.len()).unwrap_or(u64::MAX));
        self.projection_evictions = self
            .projection_evictions
            .saturating_add(self.resident_projection_entries);
        // The caller holds both accounting and state locks. Drop every owned
        // reference before returning its leases, preserving ordinary eviction
        // metrics without allocating an ID list or rebalancing each index.
        self.entries.clear();
        self.lru.clear();
        self.principals.clear();
        self.resident_record_bytes = 0;
        self.resident_association_bytes = 0;
        self.resident_associations = 0;
        self.resident_projection_bytes = 0;
        self.resident_projection_entries = 0;
    }
}

impl<P: Clone + Ord> CacheState<P> {
    pub(super) fn clear_principal(&mut self, principal: &P) {
        let Some((principal, partition)) = self.principals.remove_entry(principal) else {
            return;
        };
        let membership = principal;
        let association = association_weight::<P>();
        // Take this partition once. Its forward entries and LRU are discarded,
        // so only surviving physical records need inverse-index maintenance.
        // Owned canonical identity remains alive until all its links are gone.
        for (object, principal_entry) in partition.entries {
            let projection = projection_weight(&principal_entry);
            self.resident_association_bytes =
                self.resident_association_bytes.saturating_sub(association);
            self.resident_associations = self.resident_associations.saturating_sub(1);
            self.resident_projection_bytes =
                self.resident_projection_bytes.saturating_sub(projection);
            let projections = u64::try_from(principal_entry.projections.len()).unwrap_or(u64::MAX);
            self.resident_projection_entries =
                self.resident_projection_entries.saturating_sub(projections);
            self.projection_evictions = self.projection_evictions.saturating_add(projections);
            let remove_physical = self.entries.get_mut(&object).is_some_and(|entry| {
                entry.principals.remove(&membership);
                entry.principals.is_empty()
            });
            if remove_physical {
                self.remove_physical(object);
            }
        }
        // All payloads, the discarded LRU and canonical identity are dropped
        // before the caller releases physical and principal leases.
    }
}

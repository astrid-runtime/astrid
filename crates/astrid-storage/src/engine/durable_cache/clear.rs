//! Whole-cache eviction without rebuilding indexes that are being discarded.

use super::CacheState;

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

//! LRU access and inverse membership registration under the cache-state lock.

use std::sync::Arc;

use crate::storage_model::{ObjectId, ObjectRecord};

use super::CacheState;

impl<P: Clone + Ord> CacheState<P> {
    // A true registration follows successful forward attachment under the same
    // lock. Existing reads/projections already have exact inverse membership.
    pub(super) fn touch(
        &mut self,
        principal: &P,
        object: ObjectId,
        register_membership: bool,
    ) -> Option<Arc<ObjectRecord>> {
        if !self.entries.contains_key(&object) || !self.principals.contains_key(principal) {
            return None;
        }
        let tick = self.tick();
        let (previous_tick, record) = {
            let entry = self.entries.get_mut(&object)?;
            let previous_tick = entry.last_access;
            entry.last_access = tick;
            if register_membership {
                entry.principals.insert(principal.clone());
            } else {
                debug_assert!(entry.principals.contains(principal));
            }
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
}

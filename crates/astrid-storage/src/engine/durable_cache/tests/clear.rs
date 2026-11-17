use std::cmp::Ordering as Comparison;

use super::*;

#[derive(Clone)]
struct CountedPrincipal(u8, Arc<AtomicU64>);

impl PartialEq for CountedPrincipal {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for CountedPrincipal {}

impl Ord for CountedPrincipal {
    fn cmp(&self, other: &Self) -> Comparison {
        self.1.fetch_add(1, Ordering::Relaxed);
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for CountedPrincipal {
    fn partial_cmp(&self, other: &Self) -> Option<Comparison> {
        Some(self.cmp(other))
    }
}

#[test]
fn whole_cache_clear_does_not_rebalance_principal_indexes() {
    let comparisons = Arc::new(AtomicU64::new(0));
    let cache = ObjectCache::new(ObjectCacheConfig::new(
        ObjectCacheController::new(ObjectCacheCapacity::Unbounded),
        Arc::new(|_: &CountedPrincipal| ObjectCacheCapacity::Unbounded),
    ));
    for index in 0..64 {
        let principal = CountedPrincipal(index, Arc::clone(&comparisons));
        cache.insert(&principal, object(index), record(index));
    }
    comparisons.store(0, Ordering::Relaxed);

    cache.clear();

    assert_eq!(comparisons.load(Ordering::Relaxed), 0);
    assert_eq!(cache.stats().evictions, 64);
    assert_eq!(cache.stats().resident_bytes, 0);
}

#[derive(Debug)]
struct DroppedProjection(Arc<AtomicU64>);

impl ProjectionCachePayload for DroppedProjection {
    fn retained_bytes(&self) -> u64 {
        u64::try_from(size_of::<Self>()).unwrap()
    }
}

impl Drop for DroppedProjection {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct ReleaseOrderBudget {
    dropped: Arc<AtomicU64>,
    physical_released: AtomicBool,
    principal_released: AtomicBool,
}

impl ObjectCacheMemoryBudget for ReleaseOrderBudget {
    fn capacity(&self) -> ObjectCacheCapacity {
        ObjectCacheCapacity::Unbounded
    }

    fn release_unused(&self, bytes: u64) {
        assert_eq!(bytes, 0);
        assert_eq!(self.dropped.load(Ordering::Relaxed), 3);
        self.physical_released.store(true, Ordering::Relaxed);
    }
}

impl PrincipalObjectCacheBudget<String> for ReleaseOrderBudget {
    fn capacity(&self, _: &String) -> ObjectCacheCapacity {
        ObjectCacheCapacity::Unbounded
    }

    fn release_unused_all(&self, charges: &BTreeMap<String, u64>) {
        assert!(charges.is_empty());
        assert_eq!(self.dropped.load(Ordering::Relaxed), 3);
        self.principal_released.store(true, Ordering::Relaxed);
    }
}

#[test]
fn whole_cache_clear_drops_payloads_before_releasing_leases_and_preserves_metrics() {
    let budget = Arc::new(ReleaseOrderBudget::default());
    let cache = ObjectCache::new(ObjectCacheConfig::new(
        ObjectCacheController::governed(budget.clone()),
        budget.clone(),
    ));
    let mut records = Vec::new();
    for (owner, index) in [("alice", 1), ("alice", 2), ("bob", 1)] {
        let owner = owner.to_owned();
        cache.insert(&owner, object(index), record(index));
        records.push(Arc::downgrade(&cache.get(&owner, object(index)).unwrap()));
        assert!(cache.retain_projection(
            &owner,
            object(index),
            ProjectionCacheKey::new(9),
            ProjectionCacheEntry::new(DroppedProjection(Arc::clone(&budget.dropped))),
        ));
    }
    assert!(cache.get(&"alice".to_owned(), object(99)).is_none());
    let before = cache.stats();
    assert_eq!(before.resident_objects, 2);
    assert_eq!(before.resident_associations, 3);
    assert_eq!(before.resident_projection_entries, 3);

    cache.clear();

    let after = cache.stats();
    assert!(records.iter().all(|record| record.upgrade().is_none()));
    assert!(budget.physical_released.load(Ordering::Relaxed));
    assert!(budget.principal_released.load(Ordering::Relaxed));
    assert_eq!(after.evictions, before.evictions + before.resident_objects);
    assert_eq!(
        after.projection_evictions,
        before.projection_evictions + before.resident_projection_entries
    );
    assert_eq!(after.hits, before.hits);
    assert_eq!(after.misses, before.misses);
    assert_eq!(after.insertions, before.insertions);
    assert_eq!(after.projection_insertions, before.projection_insertions);
    assert_eq!(after.resident_objects, 0);
    assert_eq!(after.resident_bytes, 0);
    assert_eq!(after.resident_record_bytes, 0);
    assert_eq!(after.resident_association_bytes, 0);
    assert_eq!(after.resident_associations, 0);
    assert_eq!(after.resident_projection_bytes, 0);
    assert_eq!(after.resident_projection_entries, 0);
    assert_eq!(cache.principal_charge(&"alice".to_owned()), 0);
    assert_eq!(cache.principal_charge(&"bob".to_owned()), 0);
    cache.clear();
    assert_eq!(cache.stats().evictions, after.evictions);
    cache.insert(&"alice".to_owned(), object(3), record(3));
    assert!(cache.get(&"alice".to_owned(), object(3)).is_some());
}

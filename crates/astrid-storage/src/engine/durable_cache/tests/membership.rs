use std::cell::Cell;

use super::*;

thread_local! {
    static CLONES: Cell<usize> = const { Cell::new(0) };
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Principal(u8);

impl Clone for Principal {
    fn clone(&self) -> Self {
        CLONES.set(CLONES.get().saturating_add(1));
        Self(self.0)
    }
}

#[test]
fn hits_do_not_clone_or_reregister_existing_membership() {
    let cache = ObjectCache::new(ObjectCacheConfig::new(
        ObjectCacheController::new(ObjectCacheCapacity::Unbounded),
        Arc::new(|_: &Principal| ObjectCacheCapacity::Unbounded),
    ));
    let first = Principal(1);
    let second = Principal(2);
    let id = object(1);
    cache.insert(&first, id, record(1));
    assert!(cache.get(&second, id).is_some());
    CLONES.set(0);
    for _ in 0..64 {
        assert!(cache.get(&first, id).is_some());
        assert!(cache.get(&second, id).is_some());
    }
    assert_eq!(
        CLONES.get(),
        0,
        "hits must not repeat membership registration"
    );
    let stats = cache.stats();
    assert_eq!(stats.resident_objects, 1);
    assert_eq!(stats.resident_associations, 2);
    assert_eq!(
        cache.principal_charge(&first),
        cache.principal_charge(&second)
    );
}

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

#[test]
fn retirement_releases_canonical_identity_before_same_principal_returns() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let retired = Arc::new(AtomicBool::new(false));
    let pressure = Arc::clone(&retired);
    let cache = ObjectCache::new(ObjectCacheConfig::new(
        ObjectCacheController::new(ObjectCacheCapacity::Unbounded),
        Arc::new(move |principal: &Principal| {
            if principal.0 == 2 && pressure.load(Ordering::SeqCst) {
                ObjectCacheCapacity::Disabled
            } else {
                ObjectCacheCapacity::Unbounded
            }
        }),
    ));
    let first = Principal(1);
    let second = Principal(2);
    for index in 1..=2 {
        cache.insert(&first, object(index), record(index));
        assert!(cache.get(&second, object(index)).is_some());
    }
    let (old_identity, first_identity) = {
        let state = cache.state.lock();
        (
            Arc::downgrade(state.principals.get_key_value(&second).unwrap().0),
            Arc::downgrade(state.principals.get_key_value(&first).unwrap().0),
        )
    };
    let original = cache.get(&first, object(1)).unwrap();
    let charge = cache.principal_charge(&first);
    retired.store(true, Ordering::SeqCst);
    cache.reclaim();
    assert!(old_identity.upgrade().is_none(), "retired identity leaked");
    assert_eq!(cache.principal_charge(&second), 0);
    assert_eq!(cache.principal_charge(&first), charge);
    assert_eq!(cache.stats().resident_associations, 2);
    assert!(Arc::ptr_eq(
        &original,
        &cache.get(&first, object(1)).unwrap()
    ));
    retired.store(false, Ordering::SeqCst);
    for index in 1..=2 {
        assert!(cache.get(&second, object(index)).is_some());
    }
    let replacement = {
        let state = cache.state.lock();
        Arc::downgrade(state.principals.get_key_value(&second).unwrap().0)
    };
    assert!(!std::sync::Weak::ptr_eq(&old_identity, &replacement));
    assert_eq!(cache.stats().resident_associations, 4);
    cache.set_capacity(ObjectCacheCapacity::Disabled);
    assert!(replacement.upgrade().is_none());
    assert!(first_identity.upgrade().is_none());
    assert_eq!(cache.stats().resident_objects, 0);
}

use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ProjectionCachePayload;
use astrid_storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceKind, ReferenceLabel,
};

use super::*;

fn record(byte: u8) -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        vec![byte; 4096],
        Vec::new(),
        4096,
        ObjectClass::Data,
    )
    .unwrap()
}

fn object(byte: u8) -> ObjectId {
    ObjectId::new([byte; 32])
}

fn cache(controller: ObjectCacheController, principal_bytes: u64) -> ObjectCache<String> {
    let principal_bytes = NonZeroU64::new(principal_bytes).unwrap();
    ObjectCache::new(ObjectCacheConfig::new(
        controller,
        Arc::new(move |_: &String| ObjectCacheCapacity::Bounded(principal_bytes)),
    ))
}

fn assert_lru_indexes(cache: &ObjectCache<String>) {
    let state = cache.state.lock();
    let expected_global: BTreeSet<_> = state
        .entries
        .iter()
        .map(|(object, entry)| (entry.last_access, *object))
        .collect();
    assert_eq!(state.lru, expected_global);
    for partition in state.principals.values() {
        let expected: BTreeSet<_> = partition
            .entries
            .iter()
            .map(|(object, entry)| (entry.last_access, *object))
            .collect();
        assert_eq!(partition.lru, expected);
    }
}

#[test]
fn shares_one_physical_record_but_charges_each_principal_fully() {
    let controller = ObjectCacheController::new(ObjectCacheCapacity::Unbounded);
    let cache = cache(controller, 1024 * 1024);
    let id = object(7);
    let expected = record(7);
    let weight = cache_weight(&expected);

    cache.insert(&"alice".to_owned(), id, expected.clone());
    assert_eq!(
        cache.get(&"alice".to_owned(), id).as_deref(),
        Some(&expected)
    );
    assert_eq!(cache.get(&"bob".to_owned(), id).as_deref(), Some(&expected));

    let stats = cache.stats();
    assert_eq!(stats.resident_objects, 1);
    assert_eq!(stats.resident_record_bytes, weight);
    assert_eq!(stats.resident_associations, 2);
    assert_eq!(
        stats.resident_association_bytes,
        association_weight::<String>().saturating_mul(2)
    );
    assert_eq!(
        stats.resident_bytes,
        stats
            .resident_record_bytes
            .saturating_add(stats.resident_association_bytes)
    );
    assert_eq!(cache.principal_charge(&"alice".to_owned()), weight);
    assert_eq!(cache.principal_charge(&"bob".to_owned()), weight);
    assert_lru_indexes(&cache);
}

#[test]
fn live_budget_reduction_evicts_without_failing_reads() {
    let first = record(1);
    let weight = cache_weight(&first);
    let association = association_weight::<String>();
    let capacity = NonZeroU64::new(weight.saturating_add(association).saturating_mul(2)).unwrap();
    let controller = ObjectCacheController::new(ObjectCacheCapacity::Bounded(capacity));
    let cache = cache(controller.clone(), capacity.get());
    cache.insert(&"alice".to_owned(), object(1), first);
    cache.insert(&"alice".to_owned(), object(2), record(2));
    assert_eq!(cache.stats().resident_objects, 2);

    controller.set_capacity(ObjectCacheCapacity::Bounded(
        NonZeroU64::new(weight.saturating_add(association)).unwrap(),
    ));
    assert!(cache.get(&"alice".to_owned(), object(2)).is_some());
    assert_eq!(cache.stats().resident_objects, 1);
    assert!(cache.stats().evictions >= 1);
    assert_lru_indexes(&cache);
}

#[test]
fn disabling_the_global_budget_evicts_on_the_next_operation() {
    let controller = ObjectCacheController::new(ObjectCacheCapacity::Unbounded);
    let cache = cache(controller.clone(), 1024 * 1024);
    let alice = "alice".to_owned();
    let id = object(1);
    cache.insert(&alice, id, record(1));
    assert_eq!(cache.stats().resident_objects, 1);

    controller.set_capacity(ObjectCacheCapacity::Disabled);
    assert!(cache.get(&alice, id).is_none());

    let stats = cache.stats();
    assert_eq!(stats.resident_objects, 0);
    assert_eq!(stats.resident_bytes, 0);
    assert_eq!(cache.principal_charge(&alice), 0);
}

#[test]
fn disabling_one_principal_evicts_only_that_principals_partition() {
    let alice_enabled = Arc::new(AtomicBool::new(true));
    let enabled = Arc::clone(&alice_enabled);
    let principal_limit = NonZeroU64::new(1024 * 1024).unwrap();
    let cache = ObjectCache::new(ObjectCacheConfig::new(
        ObjectCacheController::new(ObjectCacheCapacity::Unbounded),
        Arc::new(move |principal: &String| {
            if principal == "alice" && !enabled.load(Ordering::Relaxed) {
                ObjectCacheCapacity::Disabled
            } else {
                ObjectCacheCapacity::Bounded(principal_limit)
            }
        }),
    ));
    let alice = "alice".to_owned();
    let bob = "bob".to_owned();
    let id = object(2);
    cache.insert(&alice, id, record(2));
    assert!(cache.get(&bob, id).is_some());

    alice_enabled.store(false, Ordering::Relaxed);
    assert!(cache.get(&alice, id).is_none());

    let stats = cache.stats();
    assert_eq!(stats.resident_objects, 1);
    assert_eq!(stats.resident_associations, 1);
    assert_eq!(cache.principal_charge(&alice), 0);
    assert!(cache.principal_charge(&bob) > 0);
    assert!(cache.get(&bob, id).is_some());
}

#[test]
fn shared_object_associations_are_bounded_by_the_global_pool() {
    let value = record(3);
    let record_weight = cache_weight(&value);
    let association = association_weight::<String>();
    let capacity =
        NonZeroU64::new(record_weight.saturating_add(association.saturating_mul(2))).unwrap();
    let controller = ObjectCacheController::new(ObjectCacheCapacity::Bounded(capacity));
    let cache = cache(controller, 1024 * 1024);
    let id = object(3);

    cache.insert(&"alice".to_owned(), id, value);
    assert!(cache.get(&"bob".to_owned(), id).is_some());
    assert!(cache.get(&"charlie".to_owned(), id).is_none());

    let stats = cache.stats();
    assert_eq!(stats.resident_objects, 1);
    assert_eq!(stats.resident_associations, 2);
    assert!(stats.resident_bytes <= capacity.get());
    assert_eq!(cache.principal_charge(&"charlie".to_owned()), 0);
    assert_lru_indexes(&cache);
}

#[test]
fn ordered_indexes_evict_the_least_recently_used_object() {
    let value = record(1);
    let record_weight = cache_weight(&value);
    let association = association_weight::<String>();
    let capacity =
        NonZeroU64::new(record_weight.saturating_add(association).saturating_mul(2)).unwrap();
    let controller = ObjectCacheController::new(ObjectCacheCapacity::Bounded(capacity));
    let cache = cache(controller, record_weight.saturating_mul(2));
    let alice = "alice".to_owned();

    cache.insert(&alice, object(1), value);
    cache.insert(&alice, object(2), record(2));
    assert!(cache.get(&alice, object(1)).is_some());
    cache.insert(&alice, object(3), record(3));

    assert!(cache.get(&alice, object(1)).is_some());
    assert!(cache.get(&alice, object(2)).is_none());
    assert!(cache.get(&alice, object(3)).is_some());
    assert_eq!(cache.stats().resident_objects, 2);
    assert_lru_indexes(&cache);
}

#[test]
fn weight_covers_reference_payloads() {
    let target = object(9);
    let record = ObjectRecord::new(
        ObjectKind::Directory,
        ObjectFormatVersion::V1,
        b"entry".to_vec(),
        vec![ObjectReference::new(
            ReferenceLabel::new(b"child".to_vec()),
            target,
            ReferenceKind::Owns,
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    assert!(cache_weight(&record) > u64::try_from(record.canonical_bytes().len()).unwrap());
}

#[derive(Debug, PartialEq, Eq)]
struct TestProjection(Vec<u8>);

impl ProjectionCachePayload for TestProjection {
    fn retained_bytes(&self) -> u64 {
        u64::try_from(std::mem::size_of::<Self>().saturating_add(self.0.capacity()))
            .unwrap_or(u64::MAX)
    }
}

#[test]
fn projection_values_share_the_object_cache_budget_and_principal_partition() {
    let value = record(5);
    let record_weight = cache_weight(&value);
    let association = association_weight::<String>();
    let projection = TestProjection(vec![7; 4096]);
    let projection_weight = projection_cache_weight(projection.retained_bytes());
    let capacity = NonZeroU64::new(
        record_weight
            .saturating_add(association)
            .saturating_add(projection_weight),
    )
    .unwrap();
    let controller = ObjectCacheController::new(ObjectCacheCapacity::Bounded(capacity));
    let cache = cache(controller.clone(), capacity.get());
    let alice = "alice".to_owned();
    let bob = "bob".to_owned();
    let id = object(5);
    let key = ProjectionCacheKey::new(1);

    cache.insert(&alice, id, value);
    assert!(cache.retain_projection(&alice, id, key, ProjectionCacheEntry::new(projection)));
    assert_eq!(
        cache
            .projection(&alice, id, key)
            .and_then(|value| value.downcast::<TestProjection>())
            .as_deref(),
        Some(&TestProjection(vec![7; 4096]))
    );
    assert!(
        cache
            .projection(&bob, id, key)
            .and_then(|value| value.downcast::<TestProjection>())
            .is_none()
    );

    let stats = cache.stats();
    assert_eq!(stats.resident_projection_entries, 1);
    assert_eq!(stats.resident_projection_bytes, projection_weight);
    assert_eq!(stats.resident_association_bytes, association);
    assert_eq!(
        stats.resident_bytes,
        stats
            .resident_record_bytes
            .saturating_add(stats.resident_association_bytes)
            .saturating_add(stats.resident_projection_bytes)
    );
    assert_eq!(
        cache.principal_charge(&alice),
        record_weight.saturating_add(projection_weight)
    );
    assert_eq!(cache.principal_charge(&bob), 0);
    assert!(stats.resident_bytes <= capacity.get());

    controller.set_capacity(ObjectCacheCapacity::Bounded(
        NonZeroU64::new(record_weight.saturating_add(association)).unwrap(),
    ));
    assert!(
        cache
            .projection(&alice, id, key)
            .and_then(|value| value.downcast::<TestProjection>())
            .is_none()
    );
    let stats = cache.stats();
    assert_eq!(stats.resident_projection_entries, 0);
    assert_eq!(stats.resident_projection_bytes, 0);
}

use std::num::NonZeroU64;
use std::sync::Arc;

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
    assert_eq!(stats.resident_bytes, weight);
    assert_eq!(cache.principal_charge(&"alice".to_owned()), weight);
    assert_eq!(cache.principal_charge(&"bob".to_owned()), weight);
}

#[test]
fn live_budget_reduction_evicts_without_failing_reads() {
    let first = record(1);
    let weight = cache_weight(&first);
    let capacity = NonZeroU64::new(weight.saturating_mul(2)).unwrap();
    let controller = ObjectCacheController::new(ObjectCacheCapacity::Bounded(capacity));
    let cache = cache(controller.clone(), capacity.get());
    cache.insert(&"alice".to_owned(), object(1), first);
    cache.insert(&"alice".to_owned(), object(2), record(2));
    assert_eq!(cache.stats().resident_objects, 2);

    controller.set_capacity(ObjectCacheCapacity::Bounded(
        NonZeroU64::new(weight).unwrap(),
    ));
    assert!(cache.get(&"alice".to_owned(), object(2)).is_some());
    assert_eq!(cache.stats().resident_objects, 1);
    assert!(cache.stats().evictions >= 1);
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

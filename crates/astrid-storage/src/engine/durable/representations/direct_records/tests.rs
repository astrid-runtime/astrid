use super::*;
use crate::engine::durable::DurableIo;
use crate::engine::durable::representations::DirectArenaObject;
use crate::engine::durable::{ArenaLocation, LocationIndexMemoryBudget, RecoveryLimits};
use std::num::NonZeroU64;

fn fixture() -> (tempfile::TempDir, RepresentationStore, Vec<ObjectId>) {
    let directory = tempfile::tempdir().unwrap();
    let specification = ObjectId::new([1; 32]);
    let profile = RepresentationStore::direct_profile_for(specification).unwrap();
    let ids = (0_u32..512)
        .map(|i| ObjectId::new(*blake3::hash(&i.to_le_bytes()).as_bytes()))
        .collect::<Vec<_>>();
    let objects = ids.iter().enumerate().map(|(i, id)| {
        DirectArenaObject::identify(
            profile,
            *id,
            &i.to_le_bytes(),
            ArenaLocation {
                offset: i as u64,
                payload_len: 8,
                checksum: [3; 32],
            },
        )
    });
    let budget = LocationIndexMemoryBudget::new(NonZeroU64::new(4096).unwrap()).unwrap();
    let root = crate::engine::durable::representations::open_store_root(directory.path()).unwrap();
    let store = RepresentationStore::activate(
        &root,
        RecoveryLimits::process_addressable(),
        specification,
        objects,
        budget,
    )
    .unwrap();
    (directory, store, ids)
}

#[test]
fn immutable_direct_scan_reuses_page_authentication_with_exact_membership() {
    let (_directory, store, ids) = fixture();
    crate::engine::durable::locations::test_take_page_auth_count();
    for id in &ids {
        assert!(store.direct_record(*id).unwrap().is_some());
    }
    let ordinary = crate::engine::durable::locations::test_take_page_auth_count();
    let mut records = store.direct_records();
    for id in &ids {
        assert!(records.record(*id).unwrap().is_some());
    }
    let memoized = crate::engine::durable::locations::test_take_page_auth_count();
    assert!(
        memoized < ordinary,
        "shared page evidence: {memoized} versus {ordinary}"
    );
    assert!(records.record(ObjectId::new([255; 32])).unwrap().is_none());
    for id in &ids {
        assert!(records.record(*id).unwrap().is_some());
    }
}

#[test]
fn warm_direct_scan_freshly_authenticates_metadata_bodies() {
    let (_directory, store, ids) = fixture();
    let media = store.metadata.try_clone().unwrap();
    let mut records = store.direct_records();
    assert!(records.record(ids[0]).unwrap().is_some());
    media.durable_set_len(0).unwrap();
    assert!(records.record(ids[0]).is_err());
    assert!(records.record(ObjectId::new([255; 32])).is_err());
}

#[test]
fn warm_direct_scan_rejects_replaced_locator_and_keeps_absence_separate() {
    let (_directory, store, ids) = fixture();
    let mut records = store.direct_records();
    assert!(records.record(ObjectId::new([255; 32])).unwrap().is_none());
    assert!(records.record(ids[0]).unwrap().is_some());
    store.reverse.truncate_test_run();
    assert!(records.record(ids[0]).is_err());
    assert!(records.record(ObjectId::new([255; 32])).is_err());
}

#[test]
fn batched_direct_scan_preserves_exact_selection_and_reduces_shared_path_reads() {
    let (_directory, store, ids) = fixture();
    let mut objects: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(at, id)| {
            (
                *id,
                ArenaLocation {
                    offset: at as u64,
                    payload_len: 8,
                    checksum: [3; 32],
                },
            )
        })
        .collect();
    let absent = (
        ObjectId::new([255; 32]),
        ArenaLocation {
            offset: 999,
            payload_len: 8,
            checksum: [7; 32],
        },
    );
    objects.push(absent);
    let mut records = store.direct_records();
    crate::engine::durable::locations::test_take_page_auth_count();
    for &(id, _) in &objects {
        records.record(id).unwrap();
    }
    let ordinary = crate::engine::durable::locations::test_take_page_auth_count();
    let mut records = store.direct_records();
    let mut missing = Vec::new();
    records
        .visit_missing(&objects, |id, location| missing.push((id, location)))
        .unwrap();
    let batched = crate::engine::durable::locations::test_take_page_auth_count();
    assert_eq!(missing, vec![absent]);
    assert!(
        batched < ordinary,
        "batch {batched} versus point {ordinary}"
    );
    missing.clear();
    for object in &objects {
        records
            .visit_missing(core::slice::from_ref(object), |id, location| {
                missing.push((id, location));
            })
            .unwrap();
    }
    assert_eq!(missing, vec![absent]);
}

#[test]
fn successive_direct_batches_freshly_reject_metadata_and_reverse_damage() {
    for damage_metadata in [false, true] {
        let (_directory, store, ids) = fixture();
        let objects: Vec<_> = ids
            .iter()
            .map(|id| {
                (
                    *id,
                    ArenaLocation {
                        offset: 0,
                        payload_len: 8,
                        checksum: [3; 32],
                    },
                )
            })
            .collect();
        let mut records = store.direct_records();
        records
            .visit_missing(&objects, |_, _| panic!("present object missing"))
            .unwrap();
        if damage_metadata {
            store
                .metadata
                .try_clone()
                .unwrap()
                .durable_set_len(0)
                .unwrap();
        } else {
            store.reverse.truncate_test_run();
        }
        assert!(records.visit_missing(&objects, |_, _| {}).is_err());
        assert!(records.visit_missing(&[], |_, _| {}).is_err());
    }
}

#[test]
fn bounded_coverage_scan_keeps_missing_and_excluded_objects_across_tiny_batches() {
    let (_directory, store, ids) = fixture();
    let mut locations = std::collections::BTreeMap::new();
    let absent = ObjectId::new([255; 32]);
    for id in ids.iter().copied().chain([absent]) {
        locations.insert(
            id,
            ArenaLocation {
                offset: 777,
                payload_len: 8,
                checksum: [7; 32],
            },
        );
    }
    for bytes in [LocationIndexMemoryBudget::MIN_BYTES, 4096, 1_048_576] {
        let budget = LocationIndexMemoryBudget::new(NonZeroU64::new(bytes).unwrap()).unwrap();
        let excluded = std::collections::BTreeSet::from([ids[0]]);
        assert_eq!(
            store
                .missing_direct_records(&locations, &excluded, budget)
                .unwrap(),
            vec![(absent, locations[&absent])]
        );
        let excluded = std::collections::BTreeSet::from([absent]);
        assert!(
            store
                .missing_direct_records(&locations, &excluded, budget)
                .unwrap()
                .is_empty()
        );
    }
}

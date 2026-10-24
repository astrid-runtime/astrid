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

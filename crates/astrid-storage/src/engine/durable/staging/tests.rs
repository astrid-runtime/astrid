//! Batch admission must reuse scratch pages while freshly checking object bodies.
use super::super::locations::{PagedLocations, test_take_page_auth_count};
use super::super::proofs::ClosureProofLookup as _;
use super::super::tests::{TestIdentity, Utf8Codec, flip_byte, limits};
use super::*;
use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectIdentity, ObjectKind};
use std::num::NonZeroUsize;

type TestEngine = DurableEngine<String, TestIdentity, Utf8Codec>;

fn records() -> Vec<ObjectRecord> {
    (0..1024_u64)
        .map(|index| {
            ObjectRecord::new(
                ObjectKind::Chunk,
                ObjectFormatVersion::V1,
                index.to_le_bytes().to_vec(),
                Vec::new(),
                8,
                ObjectClass::Data,
            )
            .unwrap()
        })
        .collect()
}

fn spilled_engine(path: &std::path::Path, records: &[ObjectRecord]) -> TestEngine {
    let engine = TestEngine::open(path, TestIdentity, Utf8Codec, limits()).unwrap();
    engine.stage_objects(records.to_vec()).unwrap();
    let mut inner = engine.lock_usable().unwrap();
    let locations = inner
        .index
        .locations()
        .collect::<Result<BTreeMap<_, _>, _>>()
        .unwrap();
    let proven = locations.keys().copied().collect();
    inner.index =
        PagedLocations::from_map_with_proofs(locations, &proven, NonZeroUsize::new(32).unwrap())
            .unwrap();
    drop(inner);
    engine
}

#[test]
fn existing_staging_batch_reuses_scoped_locator_pages() {
    let directory = tempfile::tempdir().unwrap();
    let records = records();
    let engine = spilled_engine(directory.path(), &records);
    test_take_page_auth_count();
    {
        let inner = engine.lock_usable().unwrap();
        for record in &records {
            assert!(
                inner
                    .index
                    .location(TestIdentity.identify(record))
                    .unwrap()
                    .is_some()
            );
        }
    }
    let uncached = test_take_page_auth_count();
    let results = engine.stage_objects(records.clone()).unwrap();
    let staged = test_take_page_auth_count();
    eprintln!("staging locator pages: batched={staged}, one uncached pass={uncached}");
    assert!(
        staged < uncached,
        "locked batch passes must share authenticated ancestors"
    );
    assert_eq!(results.len(), records.len());
    assert!(
        results
            .iter()
            .all(|(_, outcome)| *outcome == InsertOutcome::AlreadyPresent)
    );
    assert_eq!(engine.object_count().unwrap(), records.len());
}

#[test]
fn prepared_staging_rereads_existing_bodies_after_unlocked_preparation() {
    let directory = tempfile::tempdir().unwrap();
    let records = records();
    let engine = spilled_engine(directory.path(), &records);
    let prepared = engine.prepare_staging_batch(records.clone(), None).unwrap();
    let location = engine
        .lock_usable()
        .unwrap()
        .index
        .location(TestIdentity.identify(&records[0]))
        .unwrap()
        .unwrap();
    flip_byte(
        &directory.path().join(ARENA_FILE),
        location.offset.strict_add(super::super::FRAME_HEADER_LEN),
    );
    assert!(
        engine
            .stage_prepared_batch_with_appender(prepared, append_prepared_frames, None)
            .is_err()
    );
}

#[test]
fn prepared_staging_reauthenticates_locator_after_unlocked_preparation() {
    let directory = tempfile::tempdir().unwrap();
    let records = records();
    let engine = spilled_engine(directory.path(), &records);
    let prepared = engine.prepare_staging_batch(records, None).unwrap();
    engine.lock_usable().unwrap().index.truncate_test_run();
    assert!(
        engine
            .stage_prepared_batch_with_appender(prepared, append_prepared_frames, None)
            .is_err()
    );
    assert!(engine.inner.lock().index.failed());
}

#[test]
fn closure_proof_batch_reuses_pages_without_losing_any_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let records = records();
    let engine = spilled_engine(directory.path(), &records);
    let mut inner = engine.lock_usable().unwrap();
    inner.clear_proofs();
    let ids = inner
        .index
        .locations()
        .take(16)
        .map(|entry| entry.unwrap().0)
        .collect::<Vec<_>>();
    test_take_page_auth_count();
    for id in &ids {
        assert!(!inner.index.closure_proven(*id).unwrap());
    }
    let uncached = test_take_page_auth_count();
    inner.mark_proven_all(ids.iter().copied()).unwrap();
    let marked = test_take_page_auth_count();
    eprintln!("proof installation pages: batched={marked}, uncached={uncached}");
    assert!(marked < uncached);
    for id in ids {
        assert!(inner.proofs().proven(&id).unwrap());
    }
}

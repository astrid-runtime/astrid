//! Live disposable-cache loss must use one complete checkpoint publication.
use super::*;
use crate::engine::durable::tests::{TestEngine, Utf8Codec, limits};
use crate::volume::{AstridVolume, HostedFileVolume, VolumeRegion};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Default)]
struct TripPublication(AtomicBool);
impl FaultInjector for TripPublication {
    fn should_fail(&self, point: FaultPoint) -> bool {
        point == FaultPoint::BeforeIndexCachePublication && self.0.swap(false, Ordering::SeqCst)
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    volume: Option<Arc<HostedFileVolume>>,
}
impl Fixture {
    fn new(volume_backed: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let volume = volume_backed
            .then(|| HostedFileVolume::open(directory.path().join("store.volume")).unwrap());
        Self { directory, volume }
    }
    fn open(&self, faults: Arc<TripPublication>) -> TestEngine {
        match &self.volume {
            Some(volume) => DurableEngine::open_volume_with_faults(
                volume.clone(),
                TestIdentity,
                Utf8Codec,
                limits(),
                DurableEnginePolicy::default(),
                faults,
            )
            .unwrap(),
            None => DurableEngine::open_with_faults(
                self.directory.path(),
                TestIdentity,
                Utf8Codec,
                limits(),
                faults,
            )
            .unwrap(),
        }
    }
    fn capture_persisted(&self) -> Self {
        // Freeze bytes before source recovery or close can repair publication.
        // A fresh hosted backend must recover its catalogue from this copy.
        let mut captured = Self::new(false);
        if let Some(volume) = &self.volume {
            let path = captured.directory.path().join("store.volume");
            volume.copy_container_for_test(&path);
            captured.volume = Some(HostedFileVolume::open(path).unwrap());
        } else {
            for entry in std::fs::read_dir(self.directory.path()).unwrap() {
                let entry = entry.unwrap();
                // Lock ownership is not persisted authority. A fresh native
                // engine creates its own lock without reading the held one.
                if entry.file_name() != std::ffi::OsStr::new(LOCK_FILE) {
                    std::fs::copy(
                        entry.path(),
                        captured.directory.path().join(entry.file_name()),
                    )
                    .unwrap();
                }
            }
        }
        captured
    }
    fn truncate_cache(&self) {
        // Simulate cache loss while THIS synthetic engine remains open.
        // The authoritative arena and root journal are never modified.
        if let Some(volume) = &self.volume {
            volume
                .set_region_len(&VolumeRegion::new(INDEX_FILE).unwrap(), 0)
                .unwrap();
            volume.sync().unwrap();
        } else {
            let cache = std::fs::OpenOptions::new()
                .write(true)
                .open(self.directory.path().join(INDEX_FILE))
                .unwrap();
            cache.set_len(0).unwrap();
            cache.sync_data().unwrap();
        }
    }

    fn native_cache_reader(&self) -> Option<std::fs::File> {
        self.volume
            .is_none()
            .then(|| std::fs::File::open(self.directory.path().join(INDEX_FILE)).unwrap())
    }

    fn assert_native_cache_reused(&self, reader: Option<std::fs::File>) {
        if let Some(mut reader) = reader {
            // Empty-cache repair must reuse the existing file, avoiding a
            // temporary file, rename, directory flush, and reopen.
            let mut original = Vec::new();
            std::io::Read::read_to_end(&mut reader, &mut original).unwrap();
            let current = std::fs::read(self.directory.path().join(INDEX_FILE)).unwrap();
            assert!(!current.is_empty());
            assert_eq!(
                original, current,
                "empty-cache repair replaced the live file"
            );
        }
    }
}

fn record(index: u64) -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        index.to_le_bytes().to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}

fn seed(engine: &TestEngine) -> (RootState, Vec<(ObjectId, ObjectRecord)>) {
    let (_, transaction) = transaction("alice", None, b"rooted checkpoint seed");
    let mut known = transaction.records().to_vec();
    let root = engine.commit(transaction).unwrap().root();
    let records = (0..32).map(record).collect::<Vec<_>>();
    let outcomes = engine.stage_objects(records.clone()).unwrap();
    known.extend(
        outcomes
            .into_iter()
            .zip(records)
            .map(|((id, _), record)| (id, record)),
    );
    engine.flush().unwrap();
    (root, known)
}

fn exact_readback(engine: &TestEngine, root: RootState, known: &[(ObjectId, ObjectRecord)]) {
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(root));
    assert_eq!(engine.object_count().unwrap(), known.len());
    for (id, expected) in known {
        assert_eq!(engine.object(*id).unwrap().as_ref(), Some(expected));
    }
}

fn assert_single_snapshot(engine: &TestEngine) {
    let mut inner = engine.inner.lock();
    let file = inner.files.as_mut().unwrap().index_cache.as_mut().unwrap();
    let mut kinds = Vec::new();
    // Use production frame validation, not a second test-only decoder.
    scan_frames(file, INDEX_FILE, INDEX_MAGIC, limits(), |_, payload| {
        kinds.push(payload[0]);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        kinds,
        vec![1],
        "an empty cache should publish the complete current snapshot without a redundant prefix plus delta"
    );
}

#[test]
fn volume_flush_reports_checkpoint_failure_and_recovers_staged_objects() {
    let fixture = Fixture::new(true);
    let faults = Arc::new(TripPublication::default());
    let engine = fixture.open(Arc::clone(&faults));
    let (root, mut known) = seed(&engine);
    let next = record(32);
    let outcomes = engine.stage_objects(vec![next.clone()]).unwrap();
    known.push((outcomes[0].0, next));
    faults.0.store(true, Ordering::SeqCst);
    assert!(matches!(
        engine.flush(),
        Err(DurableError::FaultInjected(
            FaultPoint::BeforeIndexCachePublication
        ))
    ));
    assert!(
        engine.inner.lock().poisoned,
        "failed flush must require recovery"
    );
    // Authority was flushed before checkpoint publication. Freeze that boundary
    // before either live recovery or close can rebuild the disposable cache.
    let persisted = fixture.capture_persisted();
    exact_readback(&engine, root, &known);
    engine.flush().unwrap();
    engine.close().unwrap();
    let recovered = persisted.open(faults);
    exact_readback(&recovered, root, &known);
    recovered.close().unwrap();
}

#[test]
fn live_empty_cache_rebuilds_one_snapshot_and_preserves_history() {
    for volume_backed in [false, true] {
        let fixture = Fixture::new(volume_backed);
        let faults = Arc::new(TripPublication::default());
        let engine = fixture.open(Arc::clone(&faults));
        let (root, mut known) = seed(&engine);
        fixture.truncate_cache();
        let cache_reader = fixture.native_cache_reader();
        let next = record(32);
        let (id, _) = engine.persist_standalone_object(&next).unwrap();
        known.push((id, next));
        fixture.assert_native_cache_reused(cache_reader);
        let persisted = fixture.capture_persisted();
        assert_single_snapshot(&engine);
        exact_readback(&engine, root, &known);
        engine.close().unwrap();
        drop(engine);
        let recovered = persisted.open(faults);
        exact_readback(&recovered, root, &known);
        recovered.close().unwrap();
    }
}

#[test]
fn live_empty_cache_publication_failure_is_observable_and_recovers() {
    for volume_backed in [false, true] {
        let fixture = Fixture::new(volume_backed);
        let faults = Arc::new(TripPublication::default());
        let engine = fixture.open(Arc::clone(&faults));
        let (root, mut known) = seed(&engine);
        let acknowledged = known.clone();
        fixture.truncate_cache();
        faults.0.store(true, Ordering::SeqCst);
        let next = record(32);
        let id = engine.identify(&next);
        assert!(matches!(
            engine.persist_standalone_object(&next),
            Err(DurableError::FaultInjected(
                FaultPoint::BeforeIndexCachePublication
            ))
        ));
        known.push((id, next));
        let persisted = fixture.capture_persisted();
        // The live backend can recover the appended bytes. Cold volume
        // recovery below is bounded by its last acknowledged container commit.
        exact_readback(&engine, root, &known);
        assert_single_snapshot(&engine);
        engine.close().unwrap();
        drop(engine);
        let recovered = persisted.open(faults);
        // The error precedes the volume commit barrier. Native arena bytes
        // were already flushed; the cold volume retains the acknowledged seed.
        let durable = if volume_backed { &acknowledged } else { &known };
        exact_readback(&recovered, root, durable);
        recovered.close().unwrap();
    }
}

#[test]
fn live_empty_cache_root_publication_preserves_new_and_historical_objects() {
    for volume_backed in [false, true] {
        let fixture = Fixture::new(volume_backed);
        let faults = Arc::new(TripPublication::default());
        let engine = fixture.open(Arc::clone(&faults));
        let (previous, mut known) = seed(&engine);
        fixture.truncate_cache();
        let cache_reader = fixture.native_cache_reader();
        let (_, transaction) = transaction(
            "alice",
            Some(previous),
            b"new rooted state after live cache loss",
        );
        known.extend_from_slice(transaction.records());
        let root = engine.commit(transaction).unwrap().root();
        fixture.assert_native_cache_reused(cache_reader);
        let persisted = fixture.capture_persisted();
        assert_single_snapshot(&engine);
        exact_readback(&engine, root, &known);
        engine.close().unwrap();
        drop(engine);
        let recovered = persisted.open(faults);
        exact_readback(&recovered, root, &known);
        recovered.close().unwrap();
    }
}

#[test]
fn live_empty_cache_root_publication_fault_preserves_acknowledged_state() {
    for volume_backed in [false, true] {
        let fixture = Fixture::new(volume_backed);
        let faults = Arc::new(TripPublication::default());
        let engine = fixture.open(Arc::clone(&faults));
        let (previous, mut known) = seed(&engine);
        let acknowledged = known.clone();
        fixture.truncate_cache();
        let (_, transaction) = transaction(
            "alice",
            Some(previous),
            b"root append before failed cache publication",
        );
        let expected = RootState {
            generation: previous.generation.checked_next().unwrap(),
            commit: transaction.commit(),
        };
        known.extend_from_slice(transaction.records());
        faults.0.store(true, Ordering::SeqCst);
        assert!(matches!(
            engine.commit(transaction),
            Err(DurableError::FaultInjected(
                FaultPoint::BeforeIndexCachePublication
            ))
        ));
        let persisted = fixture.capture_persisted();
        // Native roots have crossed their flush; the volume barrier has not.
        // Live recovery must still preserve the complete appended transaction.
        exact_readback(&engine, expected, &known);
        assert_single_snapshot(&engine);
        engine.close().unwrap();
        drop(engine);
        let recovered = persisted.open(faults);
        // Cold recovery must never lose an acknowledged root or expose a
        // partial transaction. The failed volume transaction was not committed.
        let (durable_root, durable) = if volume_backed {
            (previous, &acknowledged)
        } else {
            (expected, &known)
        };
        exact_readback(&recovered, durable_root, durable);
        recovered.close().unwrap();
    }
}

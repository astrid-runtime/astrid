use std::io;

use crate::volume::{AstridVolume, HostedFileVolume, VolumeMetadataMutation, VolumeRegion};

#[derive(Debug)]
pub(super) struct RecordingVolume {
    inner: Arc<HostedFileVolume>,
    syncs: AtomicUsize,
    remaining_failures: AtomicUsize,
}

impl RecordingVolume {
    pub(super) fn wrap(inner: Arc<HostedFileVolume>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            syncs: AtomicUsize::new(0),
            remaining_failures: AtomicUsize::new(0),
        })
    }

    pub(super) fn sync_count(&self) -> usize {
        self.syncs.load(Ordering::SeqCst)
    }

    pub(super) fn fail_next_syncs(&self, count: usize) {
        self.remaining_failures.store(count, Ordering::SeqCst);
    }
}

impl AstridVolume for RecordingVolume {
    fn create_region(&self, region: &VolumeRegion, create_new: bool) -> io::Result<()> {
        self.inner.create_region(region, create_new)
    }

    fn region_exists(&self, region: &VolumeRegion) -> io::Result<bool> {
        self.inner.region_exists(region)
    }

    fn region_len(&self, region: &VolumeRegion) -> io::Result<u64> {
        self.inner.region_len(region)
    }

    fn read_region_at(
        &self,
        region: &VolumeRegion,
        offset: u64,
        buffer: &mut [u8],
    ) -> io::Result<usize> {
        self.inner.read_region_at(region, offset, buffer)
    }

    fn write_region_from(
        &self,
        region: &VolumeRegion,
        offset: u64,
        payload_len: u64,
        payload: &mut dyn Read,
    ) -> io::Result<()> {
        self.inner
            .write_region_from(region, offset, payload_len, payload)
    }

    fn set_region_len(&self, region: &VolumeRegion, length: u64) -> io::Result<()> {
        self.inner.set_region_len(region, length)
    }

    fn remove_region(&self, region: &VolumeRegion) -> io::Result<()> {
        self.inner.remove_region(region)
    }

    fn rename_region(&self, source: &VolumeRegion, destination: &VolumeRegion) -> io::Result<()> {
        self.inner.rename_region(source, destination)
    }

    fn replace_region(&self, source: &VolumeRegion, destination: &VolumeRegion) -> io::Result<()> {
        self.inner.replace_region(source, destination)
    }

    fn commit_metadata(&self, mutations: &[VolumeMetadataMutation]) -> io::Result<()> {
        self.inner.commit_metadata(mutations)
    }

    fn list_regions(&self, prefix: &str) -> io::Result<Vec<VolumeRegion>> {
        self.inner.list_regions(prefix)
    }

    fn available_space(&self) -> io::Result<Option<u64>> {
        self.inner.available_space()
    }

    fn reclaim(&self) -> io::Result<()> {
        self.inner.reclaim()
    }

    fn sync(&self) -> io::Result<()> {
        self.syncs.fetch_add(1, Ordering::SeqCst);
        let remaining = self.remaining_failures.load(Ordering::SeqCst);
        if remaining > 0 {
            self.remaining_failures
                .store(remaining.saturating_sub(1), Ordering::SeqCst);
            return Err(io::Error::other("injected volume sync failure"));
        }
        self.inner.sync()
    }
}

fn evidence_record(bytes: &[u8]) -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        bytes.to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}

fn open_recording_engine(
    directory: &tempfile::TempDir,
) -> (PathBuf, Arc<RecordingVolume>, TestEngine) {
    let path = directory.path().join("astrid.volume");
    let volume = RecordingVolume::wrap(HostedFileVolume::open(&path).unwrap());
    let engine = TestEngine::open_volume(
        Arc::clone(&volume) as Arc<dyn AstridVolume>,
        TestIdentity,
        Utf8Codec,
        limits(),
        DurableEnginePolicy::default(),
    )
    .unwrap();
    (path, volume, engine)
}

fn copy_volume_while_live(source: &Path, directory: &tempfile::TempDir) -> TestEngine {
    let copy = directory.path().join("copied.volume");
    std::fs::copy(source, &copy).unwrap();
    TestEngine::open_volume(
        HostedFileVolume::open(&copy).unwrap(),
        TestIdentity,
        Utf8Codec,
        limits(),
        DurableEnginePolicy::default(),
    )
    .unwrap()
}

fn rewind_indexed_arena_len(engine: &TestEngine, id: ObjectId) {
    let mut inner = engine.inner.lock();
    let location = *inner
        .index
        .get(&id)
        .expect("standalone object remains indexed");
    inner
        .files
        .as_mut()
        .expect("durable files remain open")
        .arena_len = location.offset;
}

#[test]
fn hosted_standalone_persist_crosses_volume_fence_before_drop() {
    let directory = tempfile::tempdir().unwrap();
    let (path, volume, engine) = open_recording_engine(&directory);
    let record = evidence_record(b"format specification");
    let before = volume.sync_count();
    let (id, inserted) = engine.persist_standalone_object(&record).unwrap();
    assert_eq!(inserted, InsertOutcome::Inserted);
    let copied = copy_volume_while_live(&path, &directory);
    assert_eq!(copied.object(id).unwrap(), Some(record.clone()));
    assert_eq!(volume.sync_count() - before, 1);

    let before_retry = volume.sync_count();
    let (_, repeated) = engine.persist_standalone_object(&record).unwrap();
    assert_eq!(repeated, InsertOutcome::AlreadyPresent);
    assert_eq!(volume.sync_count(), before_retry);

    rewind_indexed_arena_len(&engine, id);
    let before_flush = volume.sync_count();
    let (_, flushed) = engine.persist_standalone_object(&record).unwrap();
    assert_eq!(flushed, InsertOutcome::AlreadyPresent);
    assert_eq!(volume.sync_count() - before_flush, 1);
}

#[test]
fn hosted_standalone_sync_failure_is_not_an_ack() {
    let directory = tempfile::tempdir().unwrap();
    let (path, volume, engine) = open_recording_engine(&directory);
    let record = evidence_record(b"unsynced specification");
    let id = engine.identify(&record);
    volume.fail_next_syncs(1);
    let error = engine.persist_standalone_object(&record).unwrap_err();
    assert!(matches!(error, DurableError::Io { .. }));
    assert!(engine.inner.lock().poisoned);
    assert_eq!(
        engine.lifecycle.load(Ordering::Acquire),
        LIFECYCLE_REQUIRES_RECOVERY
    );
    let copied = copy_volume_while_live(&path, &directory);
    assert_eq!(copied.object(id).unwrap(), None);
}

#[test]
fn volume_tail_repair_flushes_the_container_and_propagates_failure() {
    for fail_sync in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let volume = RecordingVolume::wrap(
            HostedFileVolume::open(directory.path().join("repair.volume")).unwrap(),
        );
        let mut arena = super::File::volume(volume.clone(), ARENA_FILE, true).unwrap();
        arena.write_all(&[0; 5]).unwrap();
        volume.sync().unwrap();
        let before = volume.sync_count();
        if fail_sync {
            volume.fail_next_syncs(1);
        }
        let recovered = super::format::recover_arena(&mut arena, &TestIdentity, limits(), 0);
        if fail_sync {
            assert!(matches!(
                recovered,
                Err(DurableError::Io {
                    operation: "flush durable tail truncation",
                    ..
                })
            ));
        } else {
            let (index, tail) = recovered.unwrap();
            assert!(index.is_empty() && tail.is_none());
        }
        assert_eq!(volume.sync_count(), before + 1);
        if !fail_sync {
            super::format::recover_arena(&mut arena, &TestIdentity, limits(), 0).unwrap();
            assert_eq!(volume.sync_count(), before + 1);
        }
    }
}

#[test]
fn reopen_after_failed_tail_sync_requires_a_successful_volume_fence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("retry.volume");
    let volume = RecordingVolume::wrap(HostedFileVolume::open(&path).unwrap());
    let mut arena = super::File::volume(volume.clone(), ARENA_FILE, true).unwrap();
    arena.write_all(&[0; 5]).unwrap();
    volume.sync().unwrap();
    volume.fail_next_syncs(1);
    let failed = super::format::recover_arena(&mut arena, &TestIdentity, limits(), 0);
    assert!(matches!(
        failed,
        Err(DurableError::Io {
            operation: "flush durable tail truncation",
            ..
        })
    ));
    assert_eq!(arena.metadata().unwrap().len(), 0);
    drop(arena);

    // The shortened region is visible in memory. Startup must still fence
    // preceding mutations even when its subsequent arena scan will be clean.
    let reopen = || {
        TestEngine::open_volume(
            volume.clone(),
            TestIdentity,
            Utf8Codec,
            limits(),
            DurableEnginePolicy::default(),
        )
    };
    volume.fail_next_syncs(1);
    assert!(matches!(
        reopen(),
        Err(DurableError::Io {
            operation: "flush Astrid volume namespace",
            ..
        })
    ));
    let engine = reopen().unwrap();
    let copy = directory.path().join("stable.volume");
    std::fs::copy(&path, &copy).unwrap();
    let stable = HostedFileVolume::open(copy).unwrap();
    assert_eq!(
        stable
            .region_len(&VolumeRegion::new(ARENA_FILE).unwrap())
            .unwrap(),
        0
    );
    drop(engine);
}

#[test]
fn cold_volume_open_persists_both_repaired_regions_and_restores_the_owner() {
    let directory = tempfile::tempdir().unwrap();
    let (path, volume, engine) = open_recording_engine(&directory);
    let (commit, tx) = transaction("alice", None, b"retained");
    let root = engine.commit(tx).unwrap().root();
    engine.close().unwrap();
    drop(engine);
    let regions = [
        VolumeRegion::new(ARENA_FILE).unwrap(),
        VolumeRegion::new(ROOT_FILE).unwrap(),
    ];
    let lengths = regions.each_ref().map(|r| volume.region_len(r).unwrap());
    for (region, len) in regions.iter().zip(lengths) {
        volume
            .write_region_from(region, len, 5, &mut &[0; 5][..])
            .unwrap();
    }
    volume.sync().unwrap();
    let recovered = TestEngine::open_volume(
        volume.clone(),
        TestIdentity,
        Utf8Codec,
        limits(),
        DurableEnginePolicy::default(),
    )
    .unwrap();
    // Inspect a second container before another engine has a chance to repair it.
    let copy = directory.path().join("both-repaired.volume");
    std::fs::copy(path, &copy).unwrap();
    let stable = HostedFileVolume::open(copy).unwrap();
    for (region, len) in regions.iter().zip(lengths) {
        assert_eq!(stable.region_len(region).unwrap(), len);
    }
    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
    assert!(recovered.object(commit).unwrap().is_some());
}

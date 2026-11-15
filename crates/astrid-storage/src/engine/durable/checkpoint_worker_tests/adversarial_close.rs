//! Public-close adversarial regressions for drain/publication fencing.

use std::collections::BTreeSet;
use std::io::{self, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;

use crate::engine::durable::tests::transaction;
use crate::engine::durable::{DurableError, checkpoint_worker};
use crate::volume::{AstridVolume, HostedFileVolume, VolumeMetadataMutation, VolumeRegion};

use super::{
    BlockNextGenerationMetadata, GATE_BOUND, PrepareGate, activated_volume_engine,
    drain_close_while_prepare_gated, grow_until_checkpoint_eligible, open_store_snapshot,
};

/// Hold the first post-CURRENT sync so the worker retains arbiter then physical.
#[derive(Debug)]
struct HoldSyncAfterCurrent {
    inner: Arc<dyn AstridVolume>,
    gate: Arc<PrepareGate>,
    arm_after_current: AtomicBool,
    hold_next_sync: AtomicBool,
}

impl HoldSyncAfterCurrent {
    fn new(inner: Arc<dyn AstridVolume>, gate: Arc<PrepareGate>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            gate,
            arm_after_current: AtomicBool::new(false),
            hold_next_sync: AtomicBool::new(false),
        })
    }

    fn arm_next_publication_hold(&self) {
        self.arm_after_current.store(true, Ordering::SeqCst);
    }
}

impl AstridVolume for HoldSyncAfterCurrent {
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
        self.inner.commit_metadata(mutations)?;
        if mutations.iter().any(|mutation| {
            matches!(
                mutation,
                VolumeMetadataMutation::Replace { destination, .. }
                    if destination.as_str() == "representations/CURRENT"
            )
        }) && self.arm_after_current.swap(false, Ordering::SeqCst)
        {
            self.hold_next_sync.store(true, Ordering::SeqCst);
        }
        Ok(())
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
        if self
            .hold_next_sync
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.gate.wait_for_release();
        }
        self.inner.sync()
    }
}

/// Fail the first post-CURRENT sync once for uncertain publication through close.
#[derive(Debug)]
struct SyncFailOnceVolume {
    inner: Arc<dyn AstridVolume>,
    fail_next_sync: AtomicBool,
    arm_after_current: AtomicBool,
}

impl SyncFailOnceVolume {
    fn new(inner: Arc<dyn AstridVolume>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            fail_next_sync: AtomicBool::new(false),
            arm_after_current: AtomicBool::new(false),
        })
    }

    fn arm_next_sync_failure(&self) {
        self.arm_after_current.store(true, Ordering::SeqCst);
    }
}

impl AstridVolume for SyncFailOnceVolume {
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
        self.inner.commit_metadata(mutations)?;
        if mutations.iter().any(|mutation| {
            matches!(
                mutation,
                VolumeMetadataMutation::Replace { destination, .. }
                    if destination.as_str() == "representations/CURRENT"
            )
        }) && self.arm_after_current.swap(false, Ordering::SeqCst)
        {
            self.fail_next_sync.store(true, Ordering::SeqCst);
        }
        Ok(())
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
        if self
            .fail_next_sync
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Err(io::Error::other("injected post-CURRENT sync failure"));
        }
        self.inner.sync()
    }
}

#[test]
fn public_close_blocks_on_arbiter_while_worker_holds_publication_fence() {
    // Valid interleaving: worker acquires arbiter before physical, so close cannot
    // hold arbiter while the worker holds physical. Close blocks on arbiter, then
    // progresses after the worker releases the publication fence.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("arbiter-block.volume");
    let gate = PrepareGate::new();
    let volume =
        HoldSyncAfterCurrent::new(HostedFileVolume::open(&path).unwrap(), Arc::clone(&gate));
    let preparation = PrepareGate::new();
    let engine = activated_volume_engine(BlockNextGenerationMetadata::wrap(
        Arc::clone(&volume) as Arc<dyn AstridVolume>,
        Arc::clone(&preparation),
    ));
    let before = {
        let inner = engine.inner.lock();
        checkpoint_worker::lock_representations(inner.representations.as_ref())
            .unwrap()
            .journal_generation_for_test()
    };
    let release_preparation = preparation.arm();
    let release_guard = gate.arm();
    volume.arm_next_publication_hold();
    grow_until_checkpoint_eligible(&engine);
    let expected = engine.root(&"alice".to_owned()).unwrap();
    let (_, txn) = transaction("alice", expected, b"hold-publication-sync");
    engine.commit(txn).unwrap();
    assert!(preparation.wait_entered(GATE_BOUND));
    drop(release_preparation);
    assert!(
        gate.wait_entered(GATE_BOUND),
        "worker must enter post-CURRENT sync while holding arbiter then physical"
    );
    let arbiter = engine.checkpoint_arbiter_for_test();
    assert!(
        arbiter.try_lock().is_none(),
        "worker must own the arbiter during the publication fence"
    );
    let (started, receive_started) = mpsc::sync_channel(0);
    let closer = thread::spawn(move || {
        started.send(()).unwrap();
        engine.close()
    });
    receive_started.recv_timeout(GATE_BOUND).unwrap();
    assert!(
        !closer.is_finished(),
        "publication still owns the close arbiter"
    );
    drop(release_guard);
    closer
        .join()
        .expect("close thread")
        .expect("close after publication hold");
    let (generation, _frames, generations) =
        open_store_snapshot(&(Arc::clone(&volume) as Arc<dyn AstridVolume>));
    assert!(generation > before);
    assert_eq!(generations, BTreeSet::from([generation]));
}

#[test]
fn stale_prepared_custody_on_public_close_fail_closes_and_reopens() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("stale-custody.volume");
    let gate = PrepareGate::new();
    let volume = BlockNextGenerationMetadata::wrap(
        HostedFileVolume::open(&path).unwrap(),
        Arc::clone(&gate),
    );
    let volume_dyn = Arc::clone(&volume) as Arc<dyn AstridVolume>;
    let engine = Arc::new(activated_volume_engine(Arc::clone(&volume_dyn)));
    let before = {
        let inner = engine.inner.lock();
        checkpoint_worker::lock_representations(inner.representations.as_ref())
            .unwrap()
            .journal_generation_for_test()
    };
    let release_guard = gate.arm();
    grow_until_checkpoint_eligible(&engine);
    let expected = engine.root(&"alice".to_owned()).unwrap();
    let (_, txn) = transaction("alice", expected, b"stale-custody");
    engine.commit(txn).unwrap();
    assert!(gate.wait_entered(GATE_BOUND));
    {
        let arbiter = engine.checkpoint_arbiter_for_test();
        arbiter.lock().bump_custody().unwrap();
    }
    let closed = drain_close_while_prepare_gated(Arc::clone(&engine), &gate, release_guard);
    assert!(
        matches!(
            closed,
            Err(crate::engine::durable::DurableError::RequiresRecovery)
        ),
        "stale Prepared custody must fail closed: {closed:?}"
    );
    assert!(matches!(
        engine.root(&"alice".to_owned()),
        Err(DurableError::Closed)
    ));
    let (generation, _frames, generations) = open_store_snapshot(&volume_dyn);
    assert_eq!(generation, before);
    assert_eq!(generations, BTreeSet::from([generation]));
    let reopened = activated_volume_engine(volume_dyn);
    let (_, txn) = transaction(
        "alice",
        reopened.root(&"alice".to_owned()).unwrap(),
        b"after-stale",
    );
    reopened.commit(txn).unwrap();
    reopened.close().unwrap();
}

#[test]
fn drained_public_close_post_current_sync_failure_teardown_and_recovers() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("post-current-sync-fail.volume");
    let failing = SyncFailOnceVolume::new(HostedFileVolume::open(&path).unwrap());
    let gate = PrepareGate::new();
    let volume = BlockNextGenerationMetadata::wrap(
        Arc::clone(&failing) as Arc<dyn AstridVolume>,
        Arc::clone(&gate),
    );
    let volume_dyn = Arc::clone(&volume) as Arc<dyn AstridVolume>;
    let engine = Arc::new(activated_volume_engine(Arc::clone(&volume_dyn)));
    let before = {
        let inner = engine.inner.lock();
        checkpoint_worker::lock_representations(inner.representations.as_ref())
            .unwrap()
            .journal_generation_for_test()
    };
    let release_guard = gate.arm();
    grow_until_checkpoint_eligible(&engine);
    let expected_root = engine.root(&"alice".to_owned()).unwrap();
    let (_, txn) = transaction("alice", expected_root, b"post-current-fail");
    let committed_root = engine.commit(txn).unwrap().root();
    assert!(gate.wait_entered(GATE_BOUND));
    failing.arm_next_sync_failure();
    let closed = drain_close_while_prepare_gated(Arc::clone(&engine), &gate, release_guard);
    assert!(
        closed.is_err(),
        "post-CURRENT sync failure through drained close must surface: {closed:?}"
    );
    assert!(matches!(
        engine.root(&"alice".to_owned()),
        Err(DurableError::Closed)
    ));
    let retained_generations = super::generation_ids(volume_dyn.as_ref());
    assert!(retained_generations.contains(&before));
    assert!(
        retained_generations
            .iter()
            .any(|generation| *generation > before)
    );
    // Release the test's own volume handles. Keep the closed engine alive to
    // distinguish its explicit teardown from Drop releasing custody.
    drop(volume_dyn);
    drop(volume);
    drop(failing);
    let reopened = activated_volume_engine(HostedFileVolume::open(&path).unwrap());
    let root = reopened.root(&"alice".to_owned()).unwrap();
    assert_eq!(root, Some(committed_root));
    let advanced = {
        let inner = reopened.inner.lock();
        checkpoint_worker::lock_representations(inner.representations.as_ref())
            .unwrap()
            .journal_generation_for_test()
    };
    assert!(
        advanced > before,
        "uncertain post-CURRENT publish must recover the new custody on reopen: before={before} after={advanced}"
    );
    let (_, txn) = transaction("alice", root, b"after-recovery");
    reopened.commit(txn).unwrap();
    reopened.close().unwrap();
}

#[test]
fn waiting_writer_rejects_post_current_checkpoint_poison_before_publication() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("waiting-writer-poison.volume");
    let failing = SyncFailOnceVolume::new(HostedFileVolume::open(&path).unwrap());
    let publication_gate = PrepareGate::new();
    let held = HoldSyncAfterCurrent::new(
        Arc::clone(&failing) as Arc<dyn AstridVolume>,
        Arc::clone(&publication_gate),
    );
    let preparation_gate = PrepareGate::new();
    let volume = BlockNextGenerationMetadata::wrap(
        Arc::clone(&held) as Arc<dyn AstridVolume>,
        Arc::clone(&preparation_gate),
    );
    let engine = Arc::new(activated_volume_engine(
        Arc::clone(&volume) as Arc<dyn AstridVolume>
    ));
    let release_preparation = preparation_gate.arm();
    let release_publication = publication_gate.arm();
    held.arm_next_publication_hold();
    failing.arm_next_sync_failure();
    grow_until_checkpoint_eligible(&engine);
    let previous = engine.root(&"alice".to_owned()).unwrap();
    let (_, txn) = transaction("alice", previous, b"before-checkpoint-failure");
    let committed = engine.commit(txn).unwrap().root();
    assert!(preparation_gate.wait_entered(GATE_BOUND));
    drop(release_preparation);
    assert!(publication_gate.wait_entered(GATE_BOUND));
    let (entered, receive_entry) = mpsc::sync_channel(0);
    let writer_engine = Arc::clone(&engine);
    let writer = thread::spawn(move || {
        checkpoint_worker::observe_next_physical_lock(entered);
        let (_, txn) = transaction("bob", None, b"must-not-publish-after-poison");
        writer_engine.commit(txn)
    });
    // The hook is inside the real physical-lock helper. This handshake proves
    // the writer already passed lock_usable while the worker still owns custody.
    receive_entry.recv_timeout(GATE_BOUND).unwrap();
    assert!(engine.inner.try_lock().is_none());
    drop(release_publication);
    let outcome = writer.join().unwrap();
    assert!(
        matches!(outcome, Err(DurableError::RequiresRecovery)),
        "waiting writer must reject worker poison before acknowledgement: {outcome:?}"
    );
    let closed = engine.close();
    assert!(
        closed.is_err(),
        "close must surface the worker failure: {closed:?}"
    );
    assert!(matches!(
        engine.root(&"bob".to_owned()),
        Err(DurableError::Closed)
    ));
    drop(volume);
    drop(held);
    drop(failing);
    let reopened = activated_volume_engine(HostedFileVolume::open(&path).unwrap());
    assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(committed));
    assert_eq!(reopened.root(&"bob".to_owned()).unwrap(), None);
    reopened.close().unwrap();
}

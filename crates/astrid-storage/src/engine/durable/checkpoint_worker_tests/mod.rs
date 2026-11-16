//! Engine-owned checkpoint worker regressions.
//!
//! These cover publication fencing against the shared physical store and the
//! single-flight arbiter. They do not claim native 8s/10k runtime acceptance.

mod adversarial_close;
mod growth;
mod wal_publication;

use growth::commit_until_generation_advances;
pub(super) use growth::grow_until_checkpoint_eligible;

use std::collections::BTreeSet;
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex as StdMutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::engine::durable::representations::{CheckpointControl, RepresentationStore};
use crate::engine::durable::tests::{TestIdentity, Utf8Codec, limits, transaction};
use crate::engine::durable::{
    DurableEngine, DurableEnginePolicy, FaultInjector, FaultPoint, RecoveryLimits,
};
use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectKind, ObjectRecord};
use crate::volume::{AstridVolume, HostedFileVolume, VolumeMetadataMutation, VolumeRegion};

pub(super) type Engine = DurableEngine<String, TestIdentity, Utf8Codec>;

pub(super) const GATE_BOUND: Duration = Duration::from_secs(5);

pub(super) fn evidence(payload: Vec<u8>) -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        payload,
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}

pub(super) fn activated_volume_engine(volume: Arc<dyn AstridVolume>) -> Engine {
    let engine = DurableEngine::open_volume(
        volume,
        TestIdentity,
        Utf8Codec,
        limits(),
        DurableEnginePolicy::default(),
    )
    .unwrap();
    // Reopen must reuse the durable catalogue. Persisting another bootstrap object
    // and calling ensure again fails with relocatable-representation rejection.
    let initialized = {
        let inner = engine.inner.lock();
        super::checkpoint_worker::lock_representations(inner.representations.as_ref()).is_some()
    };
    if initialized {
        return engine;
    }
    let specification = evidence(b"physical format specification".to_vec());
    let (id, _) = engine.persist_standalone_object(&specification).unwrap();
    engine
        .ensure_direct_representation_catalogue(id, &[id])
        .unwrap();
    engine
}

pub(super) fn generation_ids(volume: &dyn AstridVolume) -> BTreeSet<u64> {
    let mut generations = BTreeSet::new();
    for region in volume.list_regions("representations/generations/").unwrap() {
        let Some(suffix) = region.as_str().strip_prefix("representations/generations/") else {
            continue;
        };
        let Some((generation, _)) = suffix.split_once('/') else {
            continue;
        };
        if let Ok(value) = u64::from_str_radix(generation, 16) {
            generations.insert(value);
        }
    }
    generations
}

pub(super) fn open_store_snapshot(volume: &Arc<dyn AstridVolume>) -> (u64, u64, BTreeSet<u64>) {
    let store = RepresentationStore::open_volume(volume, RecoveryLimits::process_addressable())
        .unwrap()
        .unwrap();
    let generation = store.journal_generation_for_test();
    let frames = store.map_frame_count();
    drop(store);
    (generation, frames, generation_ids(volume.as_ref()))
}

#[derive(Debug, Default)]
struct PrepareGateState {
    armed: bool,
    entered: usize,
    release: bool,
}

/// Bounded enter/release gate for next-generation metadata creation.
#[derive(Debug)]
pub(super) struct PrepareGate {
    state: StdMutex<PrepareGateState>,
    cv: Condvar,
}

impl PrepareGate {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: StdMutex::new(PrepareGateState::default()),
            cv: Condvar::new(),
        })
    }

    pub(super) fn arm(self: &Arc<Self>) -> ReleaseOnDrop {
        let mut state = self.state.lock().unwrap();
        state.armed = true;
        state.entered = 0;
        state.release = false;
        drop(state);
        ReleaseOnDrop(Arc::clone(self))
    }

    pub(super) fn wait_entered(&self, timeout: Duration) -> bool {
        let mut state = self.state.lock().unwrap();
        let deadline = Instant::now().checked_add(timeout).unwrap();
        while state.entered == 0 {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (next, wait_result) = self
                .cv
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap();
            state = next;
            if wait_result.timed_out() && state.entered == 0 {
                return false;
            }
        }
        true
    }

    pub(super) fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.release = true;
        state.armed = false;
        self.cv.notify_all();
    }

    pub(super) fn entered(&self) -> usize {
        self.state.lock().unwrap().entered
    }

    pub(super) fn wait_for_release(&self) {
        let mut state = self.state.lock().unwrap();
        if !state.armed {
            return;
        }
        state.entered = state.entered.saturating_add(1);
        self.cv.notify_all();
        let deadline = Instant::now().checked_add(GATE_BOUND).unwrap();
        while !state.release {
            let now = Instant::now();
            if now >= deadline {
                // Fail closed: do not hang the volume thread if the test aborts.
                break;
            }
            let (next, wait_result) = self
                .cv
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap();
            state = next;
            if wait_result.timed_out() && !state.release {
                break;
            }
        }
    }
}

pub(super) struct ReleaseOnDrop(Arc<PrepareGate>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Blocks creation of next-generation representation metadata regions only.
#[derive(Debug)]
pub(super) struct BlockNextGenerationMetadata {
    inner: Arc<dyn AstridVolume>,
    gate: Arc<PrepareGate>,
}

impl BlockNextGenerationMetadata {
    pub(super) fn wrap(inner: Arc<dyn AstridVolume>, gate: Arc<PrepareGate>) -> Arc<Self> {
        Arc::new(Self { inner, gate })
    }

    fn is_next_generation_metadata(region: &VolumeRegion) -> bool {
        let name = region.as_str();
        let Some(rest) = name.strip_prefix("representations/generations/") else {
            return false;
        };
        let Some((generation, file)) = rest.split_once('/') else {
            return false;
        };
        file == "metadata.arena"
            && generation.len() == 16
            && u64::from_str_radix(generation, 16)
                .ok()
                .is_some_and(|g| g > 0)
    }
}

impl AstridVolume for BlockNextGenerationMetadata {
    fn create_region(&self, region: &VolumeRegion, create_new: bool) -> io::Result<()> {
        if Self::is_next_generation_metadata(region) {
            self.gate.wait_for_release();
        }
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
        self.inner.sync()
    }
}

#[test]
fn blocked_checkpoint_prepare_does_not_stall_ordinary_commits() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("liveness.volume");
    let gate = PrepareGate::new();
    let volume = BlockNextGenerationMetadata::wrap(
        HostedFileVolume::open(&path).unwrap(),
        Arc::clone(&gate),
    );
    let engine = activated_volume_engine(Arc::clone(&volume) as Arc<dyn AstridVolume>);
    // Arm before the first automatic scheduling opportunity. Arming after a
    // trigger would race the worker's next-generation file creation.
    let release_guard = gate.arm();
    let mut expected = None;
    // Grow reclaimable history until automatic maintenance wants work.
    for sequence in 0_u64..2048 {
        let mut payload = sequence.to_le_bytes().to_vec();
        payload.extend([b'y'; 256]);
        let (_, txn) = transaction("alice", expected, &payload);
        expected = Some(engine.commit(txn).unwrap().root());
        let ready = {
            let inner = engine.inner.lock();
            super::checkpoint_worker::lock_representations(inner.representations.as_ref())
                .unwrap()
                .should_checkpoint_representations_metadata()
        };
        if ready {
            break;
        }
    }
    // The trigger has scheduled a worker blocked on next-generation metadata.
    let mut payload = 9_u64.to_le_bytes().to_vec();
    payload.extend([b'z'; 256]);
    let (_, txn) = transaction("alice", expected, &payload);
    expected = Some(engine.commit(txn).unwrap().root());
    assert!(
        gate.wait_entered(GATE_BOUND),
        "checkpoint prepare must enter next-generation metadata.arena create"
    );
    assert!(gate.entered() >= 1);

    let started = Instant::now();
    let mut payload = 10_u64.to_le_bytes().to_vec();
    payload.extend([b'w'; 64]);
    let (_, txn) = transaction("alice", expected, &payload);
    engine.commit(txn).unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "ordinary commit must not wait on blocked checkpoint prepare"
    );

    drop(release_guard);
    engine.close().unwrap();
}

#[derive(Debug)]
struct PanicAtBeforeRootCas {
    armed: AtomicBool,
    holding: Arc<(StdMutex<bool>, Condvar)>,
}

impl FaultInjector for PanicAtBeforeRootCas {
    fn should_fail(&self, point: FaultPoint) -> bool {
        if point == FaultPoint::BeforeRootCas && self.armed.swap(false, Ordering::SeqCst) {
            let (lock, cv) = &*self.holding;
            let mut parked = lock.lock().unwrap();
            *parked = true;
            cv.notify_all();
            let deadline = Instant::now().checked_add(GATE_BOUND).unwrap();
            while *parked {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let (next, wait_result) = cv
                    .wait_timeout(parked, deadline.saturating_duration_since(now))
                    .unwrap();
                parked = next;
                if wait_result.timed_out() {
                    break;
                }
            }
            panic!("injected publisher panic before root frontier");
        }
        false
    }
}

#[test]
fn mid_frontier_panic_poisons_before_worker_can_capture() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("midfrontier.volume");
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&path).unwrap();
    let holding = Arc::new((StdMutex::new(false), Condvar::new()));
    let faults = Arc::new(PanicAtBeforeRootCas {
        armed: AtomicBool::new(true),
        holding: Arc::clone(&holding),
    });
    let engine = DurableEngine::open_volume_with_faults(
        Arc::clone(&volume),
        TestIdentity,
        Utf8Codec,
        limits(),
        DurableEnginePolicy::default(),
        faults,
    )
    .unwrap();
    let specification = evidence(b"physical format specification".to_vec());
    let (id, _) = engine.persist_standalone_object(&specification).unwrap();
    engine
        .ensure_direct_representation_catalogue(id, &[id])
        .unwrap();

    let shared = engine
        .shared_representations_for_test()
        .expect("activated store");
    let observer = {
        let shared = Arc::clone(&shared);
        let holding = Arc::clone(&holding);
        thread::spawn(move || {
            let (lock, cv) = &*holding;
            let mut parked = lock.lock().unwrap();
            let deadline = Instant::now().checked_add(GATE_BOUND).unwrap();
            while !*parked {
                let now = Instant::now();
                if now >= deadline {
                    return;
                }
                let (next, wait_result) = cv
                    .wait_timeout(parked, deadline.saturating_duration_since(now))
                    .unwrap();
                parked = next;
                if wait_result.timed_out() && !*parked {
                    return;
                }
            }
            // While the publisher is parked mid-frontier, the physical mutex must
            // remain held so a worker cannot capture a half-mutated tip.
            assert!(
                shared.try_lock().is_none(),
                "physical store must stay locked across BeforeRootCas"
            );
            *parked = false;
            cv.notify_all();
        })
    };

    let (_, txn) = transaction("alice", None, b"mid-frontier");
    let result = engine.commit(txn);
    observer.join().unwrap();
    assert!(
        matches!(result, Err(super::DurableError::RequiresRecovery)),
        "leader must convert mid-frontier panic into RequiresRecovery: {result:?}"
    );
    assert_eq!(
        engine.lifecycle_for_test().load(Ordering::Acquire),
        super::LIFECYCLE_REQUIRES_RECOVERY
    );
}

#[test]
fn exclusive_cancel_join_rejects_concurrent_schedule() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cancel.volume");
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&path).unwrap();
    let engine = activated_volume_engine(volume);
    let arbiter = engine.checkpoint_arbiter_for_test();
    let lifecycle = engine.lifecycle_for_test();
    let mut exclusive = super::checkpoint_worker::cancel_join_checkpoint_worker(
        arbiter.as_ref(),
        lifecycle.as_ref(),
    );
    exclusive.bump_custody().unwrap();
    // Holding the arbiter must make auto-schedule a no-op rather than starting N+1.
    assert!(engine.maybe_schedule_representation_checkpoint().is_ok());
    assert!(matches!(
        exclusive.worker,
        super::checkpoint_worker::CheckpointWorkerSlot::Idle
    ));
    drop(exclusive);
    engine.close().unwrap();
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct NotSend(String, std::rc::Rc<()>);

struct LocalCodec;

impl crate::engine::durable::PrincipalCodec<NotSend> for LocalCodec {
    fn encode(&self, principal: &NotSend) -> Vec<u8> {
        principal.0.as_bytes().to_vec()
    }
    fn decode(&self, bytes: &[u8]) -> Option<NotSend> {
        String::from_utf8(bytes.to_vec())
            .ok()
            .map(|text| NotSend(text, std::rc::Rc::new(())))
    }
}

#[test]
fn checkpoint_worker_types_are_principal_agnostic() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<super::checkpoint_worker::SharedRepresentationStore>();
    assert_send_sync::<super::checkpoint_worker::SharedCheckpointArbiter>();
    // DurableEngine remains usable with !Send principals; the worker never
    // captures P or Arc<DurableEngine>.
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("local-principal.volume")).unwrap();
    let engine = DurableEngine::open_volume(
        volume,
        TestIdentity,
        LocalCodec,
        limits(),
        DurableEnginePolicy::default(),
    )
    .unwrap();
    let principal = NotSend("alice".to_owned(), std::rc::Rc::new(()));
    let (_, template) = transaction("alice", None, b"local principal");
    let transaction = crate::engine::RootTransaction::new(
        principal.clone(),
        None,
        template.commit(),
        template.records().to_vec(),
    );
    let root = engine.commit(transaction).unwrap().root();
    assert_eq!(engine.root(&principal).unwrap(), Some(root));
    engine.close().unwrap();
}

#[test]
fn atomic_checkpoint_poison_recovers_through_recover_if_required() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("atomic-recover.volume");
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&path).unwrap();
    let engine = activated_volume_engine(volume);
    let lifecycle = engine.lifecycle_for_test();
    // Worker-only atomic poison: inner.poisoned stays false until reconcile.
    lifecycle.store(super::LIFECYCLE_REQUIRES_RECOVERY, Ordering::Release);
    assert!(engine.recover_if_required().unwrap());
    assert_eq!(lifecycle.load(Ordering::Acquire), super::LIFECYCLE_USABLE);
    let (_, txn) = transaction("alice", None, b"after-heal");
    engine.commit(txn).unwrap();
    engine.close().unwrap();
}

#[test]
fn failed_checkpoint_worker_close_releases_store_for_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("worker-fail-close.volume");
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&path).unwrap();
    let engine = activated_volume_engine(Arc::clone(&volume));
    let (_, txn) = transaction("alice", None, b"committed before failure");
    let root = engine.commit(txn).unwrap().root();

    let arbiter = engine.checkpoint_arbiter_for_test();
    {
        let mut state = arbiter.lock();
        let join = thread::Builder::new()
            .name("astrid-rep-checkpoint-fail".to_owned())
            .spawn(|| Err(super::DurableError::RequiresRecovery))
            .unwrap();
        super::checkpoint_worker::install_preparing_worker(
            &mut state,
            Arc::new(CheckpointControl::running()),
            join,
        );
    }

    let closed = engine.close();
    assert!(
        matches!(closed, Err(super::DurableError::RequiresRecovery)),
        "close must surface recovery after a failed worker: {closed:?}"
    );
    drop(engine);

    let reopened = DurableEngine::open_volume(
        volume,
        TestIdentity,
        Utf8Codec,
        limits(),
        DurableEnginePolicy::default(),
    )
    .unwrap();
    assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(root));
    let (_, txn) = transaction("alice", Some(root), b"after reopen");
    reopened.commit(txn).unwrap();
    reopened.close().unwrap();
}

pub(super) fn wait_control_draining(control: &CheckpointControl) {
    let deadline = Instant::now().checked_add(GATE_BOUND).unwrap();
    while !control.is_draining() {
        assert!(
            Instant::now() < deadline,
            "clean close must request drain while prepare remains gated"
        );
        thread::yield_now();
    }
}

pub(super) fn drain_close_while_prepare_gated(
    engine: impl Into<Arc<Engine>>,
    gate: &Arc<PrepareGate>,
    release_guard: ReleaseOnDrop,
) -> Result<(), super::DurableError> {
    let engine = engine.into();
    let arbiter = engine.checkpoint_arbiter_for_test();
    assert!(
        gate.wait_entered(GATE_BOUND),
        "checkpoint prepare must enter next-generation metadata.arena create"
    );
    let control = {
        let state = arbiter.lock();
        match &state.worker {
            super::checkpoint_worker::CheckpointWorkerSlot::Preparing { control, .. } => {
                Arc::clone(control)
            },
            super::checkpoint_worker::CheckpointWorkerSlot::Idle => {
                panic!("gated prepare must leave the arbiter in Preparing")
            },
        }
    };
    assert!(
        !control.is_draining() && !control.is_cancelled(),
        "control must stay Running until exclusive clean close"
    );
    let closer = thread::spawn(move || engine.close());
    wait_control_draining(control.as_ref());
    drop(release_guard);
    closer.join().expect("close thread")
}

fn measure_ungated_baseline(path: &std::path::Path) -> (u64, u64) {
    let mut baseline_generation = None;
    let mut baseline_frames = None;
    for cycle in 0_u32..3 {
        let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(path).unwrap();
        let engine = activated_volume_engine(Arc::clone(&volume));
        let before = {
            let inner = engine.inner.lock();
            super::checkpoint_worker::lock_representations(inner.representations.as_ref())
                .unwrap()
                .journal_generation_for_test()
        };
        grow_until_checkpoint_eligible(&engine);
        let advanced = commit_until_generation_advances(
            &engine,
            before,
            b'n'.strict_add(u8::try_from(cycle).unwrap()),
        );
        engine.close().unwrap();
        drop(engine);
        let (generation, frames, generations) = open_store_snapshot(&volume);
        assert_eq!(generations, BTreeSet::from([generation]));
        baseline_generation = Some(generation);
        baseline_frames = Some(frames);
        if advanced > before {
            assert!(
                generation > before,
                "ungated short cycle must publish CURRENT when the worker finishes: before={before} current={generation} frames={frames}"
            );
            break;
        }
    }
    (
        baseline_generation.expect("baseline cycle must open a durable store"),
        baseline_frames.unwrap(),
    )
}

fn run_drained_close_cycles(path: &std::path::Path, baseline_generation: u64) -> (u64, u64) {
    let mut drain_generation = baseline_generation;
    let mut drain_frames = 0_u64;
    for cycle in 0_u32..3 {
        let gate = PrepareGate::new();
        let volume = BlockNextGenerationMetadata::wrap(
            HostedFileVolume::open(path).unwrap(),
            Arc::clone(&gate),
        );
        let volume_dyn = Arc::clone(&volume) as Arc<dyn AstridVolume>;
        let engine = activated_volume_engine(Arc::clone(&volume_dyn));
        let before = {
            let inner = engine.inner.lock();
            let store =
                super::checkpoint_worker::lock_representations(inner.representations.as_ref())
                    .unwrap();
            store.journal_generation_for_test()
        };
        let release_guard = gate.arm();
        grow_until_checkpoint_eligible(&engine);
        let expected = engine.root(&"alice".to_owned()).unwrap();
        let mut payload = u64::from(cycle).to_le_bytes().to_vec();
        payload.extend([b'c'; 256]);
        let (_, txn) = transaction("alice", expected, &payload);
        engine.commit(txn).unwrap();
        // Compare the same logical workload on both sides of the checkpoint,
        // not the smaller live state before this session added new objects.
        let dirty_frames = {
            let inner = engine.inner.lock();
            super::checkpoint_worker::lock_representations(inner.representations.as_ref())
                .unwrap()
                .map_frame_count()
        };
        let closed = drain_close_while_prepare_gated(engine, &gate, release_guard);
        assert!(
            closed.is_ok(),
            "drained clean close must complete without poison: {closed:?}"
        );
        let (generation, frames, generations) = open_store_snapshot(&volume_dyn);
        assert!(
            generation > before,
            "drained clean close must advance CURRENT: before={before:?} after={generation} frames={frames} gens={generations:?}"
        );
        assert_eq!(
            generations,
            BTreeSet::from([generation]),
            "drained publish must reclaim toward CURRENT-only: gens={generations:?}"
        );
        assert!(
            frames <= dirty_frames,
            "drained publish must reclaim obsolete frames: dirty={dirty_frames} sealed={frames}"
        );
        drain_generation = generation;
        drain_frames = frames;
    }
    (drain_generation, drain_frames)
}

#[test]
fn rapid_close_reopen_drains_eligible_checkpoint_progress() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("close-reopen-drain.volume");
    let (baseline_generation, _baseline_frames) = measure_ungated_baseline(&path);
    let (drain_generation, drain_frames) = run_drained_close_cycles(&path, baseline_generation);
    assert!(
        drain_generation >= baseline_generation,
        "drain cycles must preserve or advance CURRENT: baseline={baseline_generation} drain={drain_generation}"
    );

    // Follow-up ungated session continues to make progress after drained closes.
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&path).unwrap();
    let engine = activated_volume_engine(Arc::clone(&volume));
    let before = {
        let inner = engine.inner.lock();
        super::checkpoint_worker::lock_representations(inner.representations.as_ref())
            .unwrap()
            .journal_generation_for_test()
    };
    assert_eq!(before, drain_generation);
    grow_until_checkpoint_eligible(&engine);
    let advanced = commit_until_generation_advances(&engine, before, b'p');
    engine.close().unwrap();
    drop(engine);
    let (generation, frames, generations) = open_store_snapshot(&volume);
    assert!(
        advanced > before && generation > before,
        "after drained closes, ungated reopen must still publish: before={before} advanced={advanced} durable={generation} frames={frames}"
    );
    assert_eq!(
        generation, advanced,
        "close must remain flush-only after ordinary publication"
    );
    assert_eq!(generations, BTreeSet::from([generation]));
    let _ = (drain_frames, frames);
}

#[test]
fn exclusive_cancel_discards_prepared_without_publishing_current() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cancel-cleanup.volume");
    let gate = PrepareGate::new();
    let volume = BlockNextGenerationMetadata::wrap(
        HostedFileVolume::open(&path).unwrap(),
        Arc::clone(&gate),
    );
    let volume_dyn = Arc::clone(&volume) as Arc<dyn AstridVolume>;
    let engine = activated_volume_engine(Arc::clone(&volume_dyn));
    let before = {
        let inner = engine.inner.lock();
        super::checkpoint_worker::lock_representations(inner.representations.as_ref())
            .unwrap()
            .journal_generation_for_test()
    };
    let release_guard = gate.arm();
    grow_until_checkpoint_eligible(&engine);
    let expected = engine.root(&"alice".to_owned()).unwrap();
    let (_, txn) = transaction("alice", expected, b"cancel-cleanup");
    engine.commit(txn).unwrap();
    assert!(gate.wait_entered(GATE_BOUND));
    let arbiter = engine.checkpoint_arbiter_for_test();
    let lifecycle = engine.lifecycle_for_test();
    let control = {
        let state = arbiter.lock();
        match &state.worker {
            super::checkpoint_worker::CheckpointWorkerSlot::Preparing { control, .. } => {
                Arc::clone(control)
            },
            super::checkpoint_worker::CheckpointWorkerSlot::Idle => {
                panic!("gated prepare must be Preparing before cancel")
            },
        }
    };
    let canceler = thread::spawn(move || {
        drop(super::checkpoint_worker::cancel_join_checkpoint_worker(
            arbiter.as_ref(),
            lifecycle.as_ref(),
        ));
    });
    let deadline = Instant::now().checked_add(GATE_BOUND).unwrap();
    while !control.is_cancelled() {
        assert!(
            Instant::now() < deadline,
            "exclusive cancel must publish Cancel while prepare is gated"
        );
        thread::yield_now();
    }
    drop(release_guard);
    canceler.join().expect("cancel join thread");
    engine.close().unwrap();
    let (generation, _frames, generations) = open_store_snapshot(&volume_dyn);
    assert_eq!(
        generation, before,
        "Cancel must not publish CURRENT: before={before} after={generation}"
    );
    assert_eq!(
        generations,
        BTreeSet::from([generation]),
        "Cancel must not leak unpublished next-generation regions: {generations:?}"
    );
}

#[test]
fn drain_join_maps_published_without_prepared_handoff() {
    let arbiter = Arc::new(parking_lot::Mutex::new(
        super::checkpoint_worker::CheckpointArbiterState::default(),
    ));
    let lifecycle = Arc::new(std::sync::atomic::AtomicU8::new(super::LIFECYCLE_USABLE));
    {
        let mut state = arbiter.lock();
        let join = thread::Builder::new()
            .name("astrid-rep-checkpoint-published".to_owned())
            .spawn(|| Ok(super::checkpoint_worker::CheckpointOutcome::Published))
            .unwrap();
        super::checkpoint_worker::install_preparing_worker(
            &mut state,
            Arc::new(CheckpointControl::running()),
            join,
        );
    }
    let mut state = arbiter.lock();
    let drained = super::checkpoint_worker::drain_join_slot(&mut state, lifecycle.as_ref())
        .expect("Published worker must join cleanly");
    assert!(
        matches!(drained, super::checkpoint_worker::DrainedWorker::Published),
        "clean close must treat worker-won publication as flush-only"
    );
    assert!(matches!(
        state.worker,
        super::checkpoint_worker::CheckpointWorkerSlot::Idle
    ));
}

#[test]
fn close_after_worker_published_stays_flush_only() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("worker-published-close.volume");
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&path).unwrap();
    let engine = activated_volume_engine(Arc::clone(&volume));
    let before = {
        let inner = engine.inner.lock();
        super::checkpoint_worker::lock_representations(inner.representations.as_ref())
            .unwrap()
            .journal_generation_for_test()
    };
    grow_until_checkpoint_eligible(&engine);
    let advanced = commit_until_generation_advances(&engine, before, b'w');
    assert!(
        advanced > before,
        "fixture must let the worker publish before close: before={before} advanced={advanced}"
    );
    // Wait until the finished worker is either still joinable or already polled Idle.
    let arbiter = engine.checkpoint_arbiter_for_test();
    let deadline = Instant::now().checked_add(GATE_BOUND).unwrap();
    loop {
        let state = arbiter.lock();
        match &state.worker {
            super::checkpoint_worker::CheckpointWorkerSlot::Idle => break,
            super::checkpoint_worker::CheckpointWorkerSlot::Preparing { join, .. }
                if join.is_finished() =>
            {
                break;
            },
            super::checkpoint_worker::CheckpointWorkerSlot::Preparing { .. } => {
                drop(state);
                assert!(
                    Instant::now() < deadline,
                    "worker must finish publishing before close observes Published/Idle"
                );
                thread::yield_now();
            },
        }
    }
    let live_generation = {
        let inner = engine.inner.lock();
        super::checkpoint_worker::lock_representations(inner.representations.as_ref())
            .unwrap()
            .journal_generation_for_test()
    };
    assert_eq!(live_generation, advanced);
    engine.close().unwrap();
    drop(engine);
    let (generation, _frames, generations) = open_store_snapshot(&volume);
    assert_eq!(
        generation, advanced,
        "close after worker publication must not start a duplicate checkpoint"
    );
    assert_eq!(
        generations,
        BTreeSet::from([generation]),
        "flush-only close must keep a single CURRENT generation"
    );
}

//! Exhaustive byte-prefix replay against the production durable reader.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use crate::engine::crash_replay::{
    ConservativeDataSync, CrashImage, CrashTrace, CrashTraceRecorder, ReplayLimits, TraceEffect,
    TraceFileId,
};

use super::tests::{
    TEST_IDENTITY_SCHEME, TestEngine, TestIdentity, Utf8Codec, limits, open, transaction,
};
use super::*;

#[derive(Clone, Debug)]
struct RecordedFrame {
    file: TraceFileId,
    offset: usize,
    bytes: Vec<u8>,
}

impl RecordedFrame {
    fn is_exact_in(&self, image: &CrashImage) -> bool {
        let end = self.offset.checked_add(self.bytes.len()).unwrap();
        image.files()[&self.file].get(self.offset..end) == Some(self.bytes.as_slice())
    }

    fn payload(&self) -> &[u8] {
        &self.bytes[FRAME_HEADER_LEN_USIZE..]
    }
}

#[derive(Clone, Debug)]
struct ExpectedRootFrame {
    root: RootState,
    frame: RecordedFrame,
}

fn recorded_frames(trace: &CrashTrace) -> Vec<RecordedFrame> {
    let mut frames = Vec::new();
    for effect in trace.effects() {
        let TraceEffect::Append {
            file,
            pre_len,
            bytes,
        } = effect
        else {
            continue;
        };
        let magic = match file.as_str() {
            ARENA_FILE => ARENA_MAGIC,
            ROOT_FILE => ROOT_MAGIC,
            other => panic!("unexpected framed trace file {other}"),
        };
        let mut cursor = 0_usize;
        while cursor < bytes.len() {
            let header_end = cursor.checked_add(FRAME_HEADER_LEN_USIZE).unwrap();
            let header = bytes
                .get(cursor..header_end)
                .expect("recorded append contains a complete frame header");
            assert_eq!(&header[..8], &magic);
            let payload_len =
                usize::try_from(u64::from_le_bytes(header[12..20].try_into().unwrap())).unwrap();
            let frame_end = header_end.checked_add(payload_len).unwrap();
            let frame = bytes
                .get(cursor..frame_end)
                .expect("recorded append contains a complete frame");
            frames.push(RecordedFrame {
                file: file.clone(),
                offset: usize::try_from(*pre_len)
                    .unwrap()
                    .checked_add(cursor)
                    .unwrap(),
                bytes: frame.to_vec(),
            });
            cursor = frame_end;
        }
    }
    frames
}

fn expected_root_frame(
    frames: &[RecordedFrame],
    principal: &str,
    expected: Option<RootState>,
    root: RootState,
) -> ExpectedRootFrame {
    let payload =
        encode_root_record(TEST_IDENTITY_SCHEME, principal.as_bytes(), expected, root).unwrap();
    let frame = frames
        .iter()
        .find(|frame| frame.file.as_str() == ROOT_FILE && frame.payload() == payload)
        .expect("recorded trace contains expected canonical root frame")
        .clone();
    ExpectedRootFrame { root, frame }
}

fn has_invalid_interior(image: &CrashImage, frames: &[RecordedFrame]) -> bool {
    frames.iter().enumerate().any(|(position, frame)| {
        !frame.is_exact_in(image)
            && frames.iter().skip(position).skip(1).any(|later| {
                later.file == frame.file && later.offset > frame.offset && later.is_exact_in(image)
            })
    })
}

fn acknowledged_bytes_are_quiescent(trace: &CrashTrace, image: &CrashImage) -> bool {
    let effects = &trace.effects()[..image.operation_prefix()];
    let latest_acknowledgement = effects
        .iter()
        .rposition(|effect| matches!(effect, TraceEffect::AcknowledgedCommit { .. }));
    let after_acknowledgement = latest_acknowledgement.map_or(effects, |position| {
        &effects[position.checked_add(1).unwrap()..]
    });
    let has_acknowledgement =
        latest_acknowledgement.is_some() || !trace.initial_acknowledgements().is_empty();
    has_acknowledgement
        && !after_acknowledgement.iter().any(|effect| {
            matches!(
                effect,
                TraceEffect::Append { .. }
                    | TraceEffect::Write { .. }
                    | TraceEffect::Truncate { .. }
            )
        })
}

#[derive(Debug)]
struct EngineTraceFaults {
    recorder: CrashTraceRecorder,
    arena: (TraceFileId, PathBuf),
    roots: (TraceFileId, PathBuf),
    root_len: Mutex<u64>,
}

impl EngineTraceFaults {
    fn new(directory: &Path, initial_acknowledgements: &[&str]) -> Self {
        let arena = TraceFileId::new(ARENA_FILE).unwrap();
        let roots = TraceFileId::new(ROOT_FILE).unwrap();
        let arena_path = directory.join(ARENA_FILE);
        let roots_path = directory.join(ROOT_FILE);
        let root_len = std::fs::metadata(&roots_path).unwrap().len();
        let recorder = CrashTraceRecorder::from_paths(
            [
                (arena.clone(), arena_path.clone()),
                (roots.clone(), roots_path.clone()),
            ],
            initial_acknowledgements
                .iter()
                .map(|label| (*label).to_owned()),
        )
        .unwrap();
        Self {
            recorder,
            arena: (arena, arena_path),
            roots: (roots, roots_path),
            root_len: Mutex::new(root_len),
        }
    }

    fn capture(&self, file: &(TraceFileId, PathBuf)) {
        self.recorder.capture(&file.0, &file.1).unwrap();
    }
}

impl FaultInjector for EngineTraceFaults {
    fn should_fail(&self, point: FaultPoint) -> bool {
        match point {
            FaultPoint::AfterObjectAppend | FaultPoint::AfterCommitAppend => {
                self.capture(&self.arena);
            },
            FaultPoint::AfterObjectFlush => {
                self.capture(&self.arena);
                self.recorder.barrier(&self.arena.0).unwrap();
            },
            FaultPoint::AfterRootCas => {
                self.capture(&self.roots);
                self.recorder.barrier(&self.roots.0).unwrap();
                let current = std::fs::metadata(&self.roots.1).unwrap().len();
                let mut previous = self.root_len.lock();
                let len = current.checked_sub(*previous).unwrap();
                self.recorder
                    .root_publication(&self.roots.0, *previous, len)
                    .unwrap();
                *previous = current;
            },
            FaultPoint::AfterCommitFlush
            | FaultPoint::AfterWalPublication
            | FaultPoint::BeforeRootCas
            | FaultPoint::AfterCompactionFilesFlush
            | FaultPoint::AfterCompactionEvidencePrepare
            | FaultPoint::AfterCompactionIntentFlush
            | FaultPoint::AfterCompactionArenaBackup
            | FaultPoint::AfterCompactionArenaPromote
            | FaultPoint::AfterCompactionRootsBackup
            | FaultPoint::AfterCompactionRootsPromote
            | FaultPoint::AfterCompactionDirectoryFlush
            | FaultPoint::AfterCompactionEvidenceReady
            | FaultPoint::BeforeCompactionIntentRemoval
            | FaultPoint::BeforeInProcessRecoveryOpen
            | FaultPoint::BeforeInProcessRecoveryArenaFlush
            | FaultPoint::BeforeInProcessRecoveryRootFlush
            | FaultPoint::AfterCompactionRepresentationRebase => {},
        }
        false
    }
}

fn open_traced(directory: &Path, faults: Arc<EngineTraceFaults>) -> TestEngine {
    DurableEngine::open_with_faults(directory, TestIdentity, Utf8Codec, limits(), faults).unwrap()
}

fn open_traced_group(directory: &Path, faults: Arc<EngineTraceFaults>) -> TestEngine {
    DurableEngine::open_with_options(
        directory,
        TestIdentity,
        Utf8Codec,
        limits(),
        EngineOpenOptions {
            policy: DurableEnginePolicy::new(
                GroupCommitPolicy::immediate(),
                RecoveryRetryPolicy::default(),
                ObjectCacheConfig::disabled(),
            ),
            faults,
        },
    )
    .unwrap()
}

fn wait_for_queued_commits(engine: &TestEngine, expected: usize) {
    let started = Instant::now();
    while engine.queued_commit_count() < expected {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed out waiting for {expected} traced commits"
        );
        thread::yield_now();
    }
}

fn authoritative_bytes(directory: &Path) -> (Vec<u8>, Vec<u8>) {
    (
        std::fs::read(directory.join(ARENA_FILE)).unwrap(),
        std::fs::read(directory.join(ROOT_FILE)).unwrap(),
    )
}

fn materialize_replay_image(image: &CrashImage, directory: &Path) {
    image.materialize(directory).unwrap();
}

fn retain_failure(image: &CrashImage, test: &str) -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"),
        PathBuf::from,
    );
    let directory = target.join("crash-replay-failures").join(format!(
        "{test}-prefix-{}-image-{}",
        image.operation_prefix(),
        image.ordinal()
    ));
    image.materialize(&directory).unwrap();
    std::fs::write(
        directory.join("replay.txt"),
        format!(
            "model={}\noperation-prefix={}\nimage={}\nacknowledged={:?}\npublications={:?}\n",
            image.model(),
            image.operation_prefix(),
            image.ordinal(),
            image.acknowledged_commits(),
            image.root_publications(),
        ),
    )
    .unwrap();
    directory
}

fn with_retained_failure<T>(image: &CrashImage, test: &str, operation: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(payload) => {
            let retained = retain_failure(image, test);
            eprintln!(
                "retained failed crash image for prefix {} image {} at {}",
                image.operation_prefix(),
                image.ordinal(),
                retained.display()
            );
            resume_unwind(payload);
        },
    }
}

fn replay_image(
    image: &CrashImage,
    directory: &Path,
    trace: &CrashTrace,
    frames: &[RecordedFrame],
    initial_root: RootState,
    root_frames: &[ExpectedRootFrame],
    acknowledgement_floor: &BTreeMap<&str, RootGeneration>,
) -> bool {
    materialize_replay_image(image, directory);
    let invalid_interior = has_invalid_interior(image, frames);
    let opened = DurableEngine::open(directory, TestIdentity, Utf8Codec, limits());
    let engine = match opened {
        Ok(engine) => {
            assert!(
                !invalid_interior,
                "recovery accepted invalid interior at prefix {} image {}",
                image.operation_prefix(),
                image.ordinal()
            );
            engine
        },
        Err(DurableError::Corrupt { .. }) => {
            assert!(
                invalid_interior,
                "recovery rejected a repairable image at prefix {} image {}",
                image.operation_prefix(),
                image.ordinal()
            );
            assert!(
                !acknowledged_bytes_are_quiescent(trace, image),
                "recovery rejected quiescent acknowledged bytes at prefix {} image {}",
                image.operation_prefix(),
                image.ordinal()
            );
            return false;
        },
        Err(error) => {
            panic!(
                "unexpected recovery result at prefix {} image {}: {error}",
                image.operation_prefix(),
                image.ordinal()
            );
        },
    };
    let recovered = engine.root(&"alice".to_owned()).unwrap().unwrap();
    let root_is_present = recovered == initial_root
        || root_frames
            .iter()
            .any(|expected| expected.root == recovered && expected.frame.is_exact_in(image));
    assert!(
        root_is_present,
        "recovery invented root {recovered:?} at prefix {} image {}",
        image.operation_prefix(),
        image.ordinal()
    );
    let minimum = image
        .acknowledged_commits()
        .iter()
        .filter_map(|label| acknowledgement_floor.get(label.as_str()))
        .max()
        .copied()
        .unwrap();
    assert!(
        recovered.generation >= minimum,
        "acknowledged root rolled back at prefix {} image {}",
        image.operation_prefix(),
        image.ordinal()
    );
    assert!(engine.snapshot(&"alice".to_owned()).unwrap().is_some());
    drop(engine);

    let repaired_once = authoritative_bytes(directory);
    drop(open(directory));
    let repaired_twice = authoritative_bytes(directory);
    assert_eq!(
        repaired_once,
        repaired_twice,
        "repair was not idempotent at prefix {} image {}",
        image.operation_prefix(),
        image.ordinal()
    );
    true
}

#[test]
fn production_recovery_accepts_every_single_and_multi_commit_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let initial_engine = open(directory.path());
    let (_, initial_transaction) = transaction("alice", None, b"initial");
    let initial = initial_engine.commit(initial_transaction).unwrap().root();
    drop(initial_engine);

    let faults = Arc::new(EngineTraceFaults::new(directory.path(), &["initial"]));
    let engine = open_traced(directory.path(), Arc::clone(&faults));
    let (_, middle_transaction) = transaction("alice", Some(initial), b"middle");
    let middle = engine.commit(middle_transaction).unwrap().root();
    faults.recorder.acknowledge("middle").unwrap();
    let (_, final_transaction) = transaction("alice", Some(middle), b"final");
    let final_root = engine.commit(final_transaction).unwrap().root();
    faults.recorder.acknowledge("final").unwrap();
    drop(engine);

    let trace = faults.recorder.trace().unwrap();
    assert!(trace.effects().iter().any(
        |effect| matches!(effect, TraceEffect::AcknowledgedCommit { label } if label == "final")
    ));
    let frames = recorded_frames(&trace);
    let root_frames = [
        expected_root_frame(&frames, "alice", Some(initial), middle),
        expected_root_frame(&frames, "alice", Some(middle), final_root),
    ];
    let images = trace
        .replay(
            &ConservativeDataSync::new(NonZeroUsize::new(4096).unwrap()),
            ReplayLimits::ci(),
        )
        .unwrap();
    let floors = BTreeMap::from([
        ("initial", initial.generation),
        ("middle", middle.generation),
        ("final", final_root.generation),
    ]);
    let mut recovered = 0_usize;
    let replay = tempfile::tempdir().unwrap();
    for image in images.images() {
        let did_recover = with_retained_failure(image, "single-multi-commit", || {
            replay_image(
                image,
                replay.path(),
                &trace,
                &frames,
                initial,
                &root_frames,
                &floors,
            )
        });
        if did_recover {
            recovered = recovered.checked_add(1).unwrap();
        }
    }
    assert!(recovered > 0);
}

#[test]
fn crash_replay_generates_an_interior_corruption_rejected_by_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let initial_engine = open(directory.path());
    let (_, initial_transaction) = transaction("alice", None, b"initial");
    let initial = initial_engine.commit(initial_transaction).unwrap().root();
    drop(initial_engine);

    let faults = Arc::new(EngineTraceFaults::new(directory.path(), &["initial"]));
    let engine = open_traced(directory.path(), Arc::clone(&faults));
    let (_, transaction) = transaction("alice", Some(initial), b"next");
    engine.commit(transaction).unwrap();
    drop(engine);

    let trace = faults.recorder.trace().unwrap();
    let frames = recorded_frames(&trace);
    let images = trace
        .replay(
            &ConservativeDataSync::new(NonZeroUsize::new(128).unwrap()),
            ReplayLimits::ci(),
        )
        .unwrap();
    let image = images
        .images()
        .iter()
        .find(|image| has_invalid_interior(image, &frames))
        .expect("small-block replay did not generate invalid interior data");
    let replay = tempfile::tempdir().unwrap();
    image.materialize(replay.path()).unwrap();

    assert!(matches!(
        DurableEngine::open(replay.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::Corrupt { .. })
    ));
}

#[test]
fn complete_length_zero_tail_is_generated_and_repaired() {
    let directory = tempfile::tempdir().unwrap();
    let initial_engine = open(directory.path());
    let (_, initial_transaction) = transaction("alice", None, b"initial");
    let initial = initial_engine.commit(initial_transaction).unwrap().root();
    drop(initial_engine);
    let initial_arena = std::fs::read(directory.path().join(ARENA_FILE)).unwrap();

    let faults = Arc::new(EngineTraceFaults::new(directory.path(), &["initial"]));
    let engine = open_traced(directory.path(), Arc::clone(&faults));
    let (_, transaction) = transaction("alice", Some(initial), b"uncommitted");
    engine.commit(transaction).unwrap();
    drop(engine);
    let full_arena = std::fs::read(directory.path().join(ARENA_FILE)).unwrap();
    let arena_id = TraceFileId::new(ARENA_FILE).unwrap();
    let images = faults
        .recorder
        .trace()
        .unwrap()
        .replay(
            &ConservativeDataSync::new(NonZeroUsize::new(4096).unwrap()),
            ReplayLimits::ci(),
        )
        .unwrap();
    let zero_tail = images
        .images()
        .iter()
        .find(|image| {
            let arena = &image.files()[&arena_id];
            arena.len() == full_arena.len()
                && arena.starts_with(&initial_arena)
                && arena[initial_arena.len()..].iter().all(|byte| *byte == 0)
        })
        .expect("complete-length zero tail was not generated");
    let replay = tempfile::tempdir().unwrap();
    zero_tail.materialize(replay.path()).unwrap();
    let recovered = open(replay.path());
    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(initial));
    drop(recovered);
    assert_eq!(
        std::fs::read(replay.path().join(ARENA_FILE)).unwrap(),
        initial_arena
    );
}

fn record_multi_principal_group_commit(
    directory: &Path,
) -> (CrashTrace, BTreeMap<String, RootState>) {
    drop(open(directory));
    let faults = Arc::new(EngineTraceFaults::new(directory, &[]));
    let engine = Arc::new(open_traced_group(directory, Arc::clone(&faults)));
    let drain_reached = Arc::new(Barrier::new(2));
    let drain_release = Arc::new(Barrier::new(2));
    engine.gate_next_group_drain(Arc::clone(&drain_reached), Arc::clone(&drain_release));
    let mut handles = Vec::new();
    {
        let engine = Arc::clone(&engine);
        handles.push(thread::spawn(move || {
            let (_, transaction) = transaction("alice", None, b"alice");
            ("alice", engine.commit(transaction).unwrap().root())
        }));
    }
    drain_reached.wait();
    {
        let engine = Arc::clone(&engine);
        handles.push(thread::spawn(move || {
            let (_, transaction) = transaction("bob", None, b"bob");
            ("bob", engine.commit(transaction).unwrap().root())
        }));
    }
    wait_for_queued_commits(&engine, 2);
    drain_release.wait();
    let mut expected = BTreeMap::new();
    for handle in handles {
        let (principal, root) = handle.join().unwrap();
        expected.insert(principal.to_owned(), root);
    }
    for principal in expected.keys() {
        faults.recorder.acknowledge(principal.clone()).unwrap();
    }
    drop(engine);

    (faults.recorder.trace().unwrap(), expected)
}

fn assert_one_group_flush_pair(trace: &CrashTrace) {
    let barriers = trace
        .effects()
        .iter()
        .filter(|effect| matches!(effect, TraceEffect::Barrier { .. }))
        .count();
    assert_eq!(
        barriers, 2,
        "one group must share one arena/root flush pair"
    );
}

fn replay_group_image(
    image: &CrashImage,
    directory: &Path,
    trace: &CrashTrace,
    frames: &[RecordedFrame],
    expected: &BTreeMap<String, RootState>,
    root_frames: &BTreeMap<String, ExpectedRootFrame>,
) -> Option<usize> {
    materialize_replay_image(image, directory);
    let invalid_interior = has_invalid_interior(image, frames);
    let recovered = match DurableEngine::open(directory, TestIdentity, Utf8Codec, limits()) {
        Ok(engine) => {
            assert!(
                !invalid_interior,
                "group recovery accepted invalid interior at prefix {} image {}",
                image.operation_prefix(),
                image.ordinal()
            );
            engine
        },
        Err(DurableError::Corrupt { .. }) => {
            assert!(
                invalid_interior,
                "group recovery rejected a repairable image at prefix {} image {}",
                image.operation_prefix(),
                image.ordinal()
            );
            assert!(
                !acknowledged_bytes_are_quiescent(trace, image),
                "group recovery rejected quiescent acknowledged bytes at prefix {} image {}",
                image.operation_prefix(),
                image.ordinal()
            );
            return None;
        },
        Err(error) => {
            panic!(
                "unexpected grouped recovery at prefix {} image {}: {error}",
                image.operation_prefix(),
                image.ordinal()
            );
        },
    };
    let mut visible = 0_usize;
    for (principal, root) in expected {
        let actual = recovered.root(principal).unwrap();
        let root_frame = &root_frames[principal];
        let allowed = root_frame.frame.is_exact_in(image).then_some(*root);
        assert_eq!(
            actual,
            allowed,
            "group recovery root did not match exact journal evidence for {principal} at prefix {} image {}",
            image.operation_prefix(),
            image.ordinal()
        );
        if actual.is_some() {
            visible = visible.checked_add(1).unwrap();
            assert!(recovered.snapshot(principal).unwrap().is_some());
        }
    }
    if image.acknowledged_commits().len() == expected.len() {
        assert_eq!(visible, expected.len(), "acknowledged group rolled back");
    }
    drop(recovered);
    let repaired_once = authoritative_bytes(directory);
    drop(open(directory));
    assert_eq!(repaired_once, authoritative_bytes(directory));
    Some(visible)
}

#[test]
fn multi_principal_group_commit_uses_the_same_prefix_replayer() {
    let directory = tempfile::tempdir().unwrap();
    let (trace, expected) = record_multi_principal_group_commit(directory.path());

    let frames = recorded_frames(&trace);
    let root_frames: BTreeMap<_, _> = expected
        .iter()
        .map(|(principal, root)| {
            (
                principal.clone(),
                expected_root_frame(&frames, principal, None, *root),
            )
        })
        .collect();
    assert_one_group_flush_pair(&trace);
    let images = trace
        .replay(
            &ConservativeDataSync::new(NonZeroUsize::new(4096).unwrap()),
            ReplayLimits::ci(),
        )
        .unwrap();
    let mut partial_group = false;
    let replay = tempfile::tempdir().unwrap();
    for image in images.images() {
        let visible = with_retained_failure(image, "group-commit", || {
            replay_group_image(
                image,
                replay.path(),
                &trace,
                &frames,
                &expected,
                &root_frames,
            )
        });
        let Some(visible) = visible else {
            continue;
        };
        partial_group |= visible == 1;
    }
    assert!(
        partial_group,
        "no pre-barrier partial group image recovered"
    );
}

//! Exhaustive byte-prefix replay against the production durable reader.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use crate::crash_replay::{
    ConservativeDataSync, CrashImage, CrashTraceRecorder, ReplayLimits, TraceEffect, TraceFileId,
};

use super::tests::{TestEngine, TestIdentity, Utf8Codec, limits, open, transaction};
use super::*;

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
            | FaultPoint::BeforeInProcessRecoveryRootFlush => {},
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

fn replay_image(
    image: &CrashImage,
    roots: &[RootState],
    acknowledgement_floor: &BTreeMap<&str, RootGeneration>,
) -> bool {
    let directory = tempfile::tempdir().unwrap();
    image.materialize(directory.path()).unwrap();
    let opened = DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits());
    let engine = match opened {
        Ok(engine) => engine,
        Err(DurableError::Corrupt { .. }) => return false,
        Err(error) => {
            let retained = retain_failure(image, "single-multi-commit");
            panic!(
                "unexpected recovery result at prefix {} image {}: {error}; retained {}",
                image.operation_prefix(),
                image.ordinal(),
                retained.display()
            );
        },
    };
    let recovered = engine.root(&"alice".to_owned()).unwrap().unwrap();
    assert!(
        roots.contains(&recovered),
        "recovery invented root {recovered:?}"
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

    let repaired_once = authoritative_bytes(directory.path());
    drop(open(directory.path()));
    let repaired_twice = authoritative_bytes(directory.path());
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
    let first_arena_appends: Vec<_> = trace
        .effects()
        .iter()
        .filter_map(|effect| match effect {
            TraceEffect::Append {
                file,
                pre_len,
                bytes,
            } if file.as_str() == ARENA_FILE => Some((*pre_len, bytes.as_slice())),
            _ => None,
        })
        .take(2)
        .collect();
    assert_eq!(first_arena_appends.len(), 2);
    let images = trace
        .replay(
            &ConservativeDataSync::new(NonZeroUsize::new(128).unwrap()),
            ReplayLimits::ci(),
        )
        .unwrap();
    let known_roots = [initial, middle, final_root];
    let floors = BTreeMap::from([
        ("initial", initial.generation),
        ("middle", middle.generation),
        ("final", final_root.generation),
    ]);
    let mut recovered = 0_usize;
    let mut refused = 0_usize;
    let mut invalid_followed_by_valid_was_refused = false;
    let arena_id = TraceFileId::new(ARENA_FILE).unwrap();
    for image in images.images() {
        let arena = &image.files()[&arena_id];
        let [(first_offset, first), (second_offset, second)] = first_arena_appends.as_slice()
        else {
            unreachable!();
        };
        let first_offset = usize::try_from(*first_offset).unwrap();
        let second_offset = usize::try_from(*second_offset).unwrap();
        let first_end = first_offset.checked_add(first.len()).unwrap();
        let second_end = second_offset.checked_add(second.len()).unwrap();
        let has_invalid_interior = arena.get(first_offset..first_end) != Some(*first)
            && arena.get(second_offset..second_end) == Some(*second);
        if replay_image(image, &known_roots, &floors) {
            recovered = recovered.checked_add(1).unwrap();
        } else {
            refused = refused.checked_add(1).unwrap();
            invalid_followed_by_valid_was_refused |= has_invalid_interior;
        }
    }
    assert!(recovered > 0);
    assert!(refused > 0, "no invalid-interior crash image was generated");
    assert!(
        invalid_followed_by_valid_was_refused,
        "no invalid frame followed by a valid frame was refused"
    );
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

#[test]
fn multi_principal_group_commit_uses_the_same_prefix_replayer() {
    let directory = tempfile::tempdir().unwrap();
    drop(open(directory.path()));
    let faults = Arc::new(EngineTraceFaults::new(directory.path(), &[]));
    let engine = Arc::new(open_traced_group(directory.path(), Arc::clone(&faults)));
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

    let trace = faults.recorder.trace().unwrap();
    assert_eq!(
        trace
            .effects()
            .iter()
            .filter(|effect| matches!(effect, TraceEffect::Barrier { .. }))
            .count(),
        2,
        "one grouped transaction must share one arena/root flush pair"
    );
    let images = trace
        .replay(
            &ConservativeDataSync::new(NonZeroUsize::new(128).unwrap()),
            ReplayLimits::ci(),
        )
        .unwrap();
    let mut partial_group = false;
    let mut refused = 0_usize;
    for image in images.images() {
        let replay = tempfile::tempdir().unwrap();
        image.materialize(replay.path()).unwrap();
        let recovered = match DurableEngine::open(replay.path(), TestIdentity, Utf8Codec, limits())
        {
            Ok(engine) => engine,
            Err(DurableError::Corrupt { .. }) => {
                refused = refused.checked_add(1).unwrap();
                continue;
            },
            Err(error) => {
                let retained = retain_failure(image, "group-commit");
                panic!(
                    "unexpected grouped recovery at prefix {} image {}: {error}; retained {}",
                    image.operation_prefix(),
                    image.ordinal(),
                    retained.display()
                );
            },
        };
        let mut visible = 0_usize;
        for (principal, root) in &expected {
            let actual = recovered.root(principal).unwrap();
            assert!(actual.is_none() || actual == Some(*root));
            if actual.is_some() {
                visible = visible.checked_add(1).unwrap();
                assert!(recovered.snapshot(principal).unwrap().is_some());
            }
        }
        partial_group |= visible == 1;
        if image.acknowledged_commits().len() == expected.len() {
            assert_eq!(visible, expected.len(), "acknowledged group rolled back");
        }
        drop(recovered);
        let repaired_once = authoritative_bytes(replay.path());
        drop(open(replay.path()));
        assert_eq!(repaired_once, authoritative_bytes(replay.path()));
    }
    assert!(
        partial_group,
        "no pre-barrier partial group image recovered"
    );
    assert!(refused > 0, "no grouped interior corruption was refused");
}

//! Concurrency, failure-isolation, and recovery tests for group commit.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use super::tests::{TestIdentity, Utf8Codec, limits, transaction};
use super::*;

#[derive(Default)]
struct RecordingProjectionObserver {
    phases: Mutex<BTreeSet<crate::ProjectionPhase>>,
}

impl crate::ProjectionObserver for RecordingProjectionObserver {
    fn record(&self, phase: crate::ProjectionPhase, _elapsed: Duration) {
        self.phases.lock().insert(phase);
    }
}

#[test]
fn observed_staging_and_publication_report_the_durable_phases() {
    let directory = tempfile::tempdir().unwrap();
    let engine = DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()).unwrap();
    let observer = Arc::new(RecordingProjectionObserver::default());
    let (commit, transaction) = transaction("alice", None, b"observed");

    let prepared = engine
        .prepare_objects_for_projection(
            transaction
                .records()
                .iter()
                .map(|(_, record)| record.clone())
                .collect(),
            Some(observer.as_ref()),
        )
        .unwrap();
    engine
        .stage_prepared_for_projection(prepared, Some(observer.as_ref()))
        .unwrap();
    engine
        .commit_observed(
            RootTransaction::new("alice".to_owned(), None, commit, Vec::new()),
            Arc::clone(&observer) as Arc<dyn crate::ProjectionObserver>,
        )
        .unwrap();

    let phases = observer.phases.lock();
    for expected in [
        crate::ProjectionPhase::ObjectPreparation,
        crate::ProjectionPhase::AdmissionProbe,
        crate::ProjectionPhase::ArenaAppend,
        crate::ProjectionPhase::PhysicalMapUpdate,
        crate::ProjectionPhase::ClosureValidation,
        crate::ProjectionPhase::RootPublication,
        crate::ProjectionPhase::Flush,
    ] {
        assert!(phases.contains(&expected), "missing phase {expected:?}");
    }
}

#[test]
fn prepared_projection_batches_are_bound_to_the_preparing_engine() {
    let first_directory = tempfile::tempdir().unwrap();
    let second_directory = tempfile::tempdir().unwrap();
    let first =
        DurableEngine::open(first_directory.path(), TestIdentity, Utf8Codec, limits()).unwrap();
    let second =
        DurableEngine::open(second_directory.path(), TestIdentity, Utf8Codec, limits()).unwrap();
    let (_, transaction) = transaction("alice", None, b"engine-bound");
    let records = transaction
        .records()
        .iter()
        .map(|(_, record)| record.clone())
        .collect();

    let prepared = first.prepare_objects_for_projection(records, None).unwrap();
    let error = second
        .stage_prepared_for_projection(prepared, None)
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("prepared object batch does not belong to this engine")
    );
    assert_eq!(second.object_count().unwrap(), 0);
}

#[derive(Debug, Default)]
struct CountFlushes {
    arena: AtomicUsize,
    roots: AtomicUsize,
}

impl FaultInjector for CountFlushes {
    fn should_fail(&self, point: FaultPoint) -> bool {
        match point {
            FaultPoint::AfterObjectFlush => {
                self.arena.fetch_add(1, Ordering::Relaxed);
            },
            FaultPoint::AfterRootCas => {
                self.roots.fetch_add(1, Ordering::Relaxed);
            },
            _ => {},
        }
        false
    }
}

#[derive(Debug)]
struct FailAt(FaultPoint);

impl FaultInjector for FailAt {
    fn should_fail(&self, point: FaultPoint) -> bool {
        point == self.0
    }
}

#[derive(Debug)]
struct PauseAfterRootFlush {
    reached: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl FaultInjector for PauseAfterRootFlush {
    fn should_fail(&self, point: FaultPoint) -> bool {
        if point == FaultPoint::AfterRootCas {
            self.reached.wait();
            self.release.wait();
        }
        false
    }
}

#[derive(Debug)]
struct PauseFirstAfterRootFlush {
    calls: AtomicUsize,
    reached: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl FaultInjector for PauseFirstAfterRootFlush {
    fn should_fail(&self, point: FaultPoint) -> bool {
        if point == FaultPoint::AfterRootCas && self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
            self.reached.wait();
            self.release.wait();
        }
        false
    }
}

type TestEngine = DurableEngine<String, TestIdentity, Utf8Codec>;

fn open_grouped(
    path: &Path,
    faults: Arc<dyn FaultInjector>,
    policy: GroupCommitPolicy,
) -> TestEngine {
    DurableEngine::open_with_options(
        path,
        TestIdentity,
        Utf8Codec,
        limits(),
        EngineOpenOptions {
            policy: DurableEnginePolicy::new(
                policy,
                RecoveryRetryPolicy::default(),
                ObjectCacheConfig::disabled(),
            ),
            faults,
        },
    )
    .unwrap()
}

fn open(path: &Path) -> TestEngine {
    DurableEngine::open(path, TestIdentity, Utf8Codec, limits()).unwrap()
}

fn wait_for_queued_commits(engine: &TestEngine, expected: usize) {
    let started = Instant::now();
    while engine.queued_commit_count() < expected {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed out waiting for {expected} queued commits"
        );
        thread::yield_now();
    }
}

#[test]
fn independent_principals_share_one_durability_pair() {
    let directory = tempfile::tempdir().unwrap();
    let flushes = Arc::new(CountFlushes::default());
    let faults: Arc<dyn FaultInjector> = flushes.clone();
    let drain_reached = Arc::new(Barrier::new(2));
    let drain_release = Arc::new(Barrier::new(2));
    let engine = Arc::new(open_grouped(
        directory.path(),
        faults,
        GroupCommitPolicy::immediate(),
    ));
    engine.gate_next_group_drain(Arc::clone(&drain_reached), Arc::clone(&drain_release));
    let barrier = Arc::new(Barrier::new(9));
    let mut handles = Vec::new();
    for value in 0_u8..8 {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let principal = format!("principal-{value}");
            let (_, transaction) = transaction(&principal, None, &[value]);
            barrier.wait();
            (principal, engine.commit(transaction))
        }));
    }
    barrier.wait();
    drain_reached.wait();
    wait_for_queued_commits(&engine, 8);
    drain_release.wait();

    let mut roots = Vec::new();
    for handle in handles {
        let (principal, outcome) = handle.join().unwrap();
        roots.push((principal, outcome.unwrap().root()));
    }
    assert_eq!(flushes.arena.load(Ordering::Relaxed), 1);
    assert_eq!(flushes.roots.load(Ordering::Relaxed), 1);
    drop(engine);

    let recovered = open(directory.path());
    for (principal, root) in roots {
        assert_eq!(recovered.root(&principal).unwrap(), Some(root));
    }
}

#[test]
fn invalid_group_member_does_not_cancel_an_independent_commit() {
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(open_grouped(
        directory.path(),
        Arc::new(NoFaults),
        GroupCommitPolicy::new(Duration::from_millis(50)),
    ));
    let (_, good) = transaction("alice", None, b"good");
    let (_, bad_source) = transaction("mallory", None, b"bad");
    let mut bad_records = bad_source.records().to_vec();
    bad_records[0].0 = ObjectId::new([99; 32]);
    let bad = RootTransaction::new("mallory".to_owned(), None, bad_source.commit(), bad_records);
    let barrier = Arc::new(Barrier::new(3));
    let good_handle = {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            engine.commit(good)
        })
    };
    let bad_handle = {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            engine.commit(bad)
        })
    };
    barrier.wait();

    let installed = good_handle.join().unwrap().unwrap().root();
    assert!(matches!(
        bad_handle.join().unwrap(),
        Err(DurableError::Model(
            ModelError::ObjectIdentityMismatch { .. }
        ))
    ));
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(installed));
    assert_eq!(engine.root(&"mallory".to_owned()).unwrap(), None);
}

#[test]
fn same_principal_group_has_one_cas_winner() {
    let directory = tempfile::tempdir().unwrap();
    let flushes = Arc::new(CountFlushes::default());
    let faults: Arc<dyn FaultInjector> = flushes.clone();
    let engine = Arc::new(open_grouped(
        directory.path(),
        faults,
        GroupCommitPolicy::new(Duration::from_millis(50)),
    ));
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for payload in [b"first".as_slice(), b"second".as_slice()] {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        let (_, transaction) = transaction("alice", None, payload);
        handles.push(thread::spawn(move || {
            barrier.wait();
            engine.commit(transaction)
        }));
    }
    barrier.wait();

    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                Err(DurableError::Model(ModelError::RootConflict {
                    expected: None,
                    actual: Some(_),
                }))
            ))
            .count(),
        1
    );
    assert_eq!(flushes.arena.load(Ordering::Relaxed), 1);
    assert_eq!(flushes.roots.load(Ordering::Relaxed), 1);
}

#[test]
fn same_principal_successors_follow_queue_order_in_one_group() {
    let directory = tempfile::tempdir().unwrap();
    let flushes = Arc::new(CountFlushes::default());
    let faults: Arc<dyn FaultInjector> = flushes.clone();
    let engine = Arc::new(open_grouped(
        directory.path(),
        faults,
        GroupCommitPolicy::new(Duration::from_millis(250)),
    ));
    let (first_commit, first) = transaction("alice", None, b"first");
    let first_root = RootState {
        generation: RootGeneration::INITIAL,
        commit: first_commit,
    };
    let (_, second) = transaction("alice", Some(first_root), b"second");

    let first_handle = {
        let engine = Arc::clone(&engine);
        thread::spawn(move || engine.commit(first))
    };
    wait_for_queued_commits(&engine, 1);
    let second_handle = {
        let engine = Arc::clone(&engine);
        thread::spawn(move || engine.commit(second))
    };
    wait_for_queued_commits(&engine, 2);

    assert_eq!(first_handle.join().unwrap().unwrap().root(), first_root);
    let second_root = second_handle.join().unwrap().unwrap().root();
    assert_eq!(second_root.generation.get(), 1);
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(second_root));
    assert_eq!(flushes.arena.load(Ordering::Relaxed), 1);
    assert_eq!(flushes.roots.load(Ordering::Relaxed), 1);
}

#[test]
fn grouped_commit_acknowledges_only_after_root_flush() {
    let directory = tempfile::tempdir().unwrap();
    let reached = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let faults: Arc<dyn FaultInjector> = Arc::new(PauseAfterRootFlush {
        reached: Arc::clone(&reached),
        release: Arc::clone(&release),
    });
    let engine = Arc::new(open_grouped(
        directory.path(),
        faults,
        GroupCommitPolicy::immediate(),
    ));
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let handle = {
        let engine = Arc::clone(&engine);
        thread::spawn(move || {
            let (_, transaction) = transaction("alice", None, b"durable");
            sender.send(engine.commit(transaction)).unwrap();
        })
    };

    reached.wait();
    assert!(matches!(
        receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    release.wait();
    assert!(receiver.recv().unwrap().is_ok());
    handle.join().unwrap();
}

#[test]
fn commits_queued_during_a_flush_form_the_next_group() {
    let directory = tempfile::tempdir().unwrap();
    let reached = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let pause = Arc::new(PauseFirstAfterRootFlush {
        calls: AtomicUsize::new(0),
        reached: Arc::clone(&reached),
        release: Arc::clone(&release),
    });
    let faults: Arc<dyn FaultInjector> = pause.clone();
    let engine = Arc::new(open_grouped(
        directory.path(),
        faults,
        GroupCommitPolicy::immediate(),
    ));
    let first = {
        let engine = Arc::clone(&engine);
        thread::spawn(move || {
            let (_, transaction) = transaction("first", None, b"first");
            engine.commit(transaction)
        })
    };

    reached.wait();
    let mut next = Vec::new();
    for value in 0_u8..4 {
        let engine = Arc::clone(&engine);
        next.push(thread::spawn(move || {
            let principal = format!("next-{value}");
            let (_, transaction) = transaction(&principal, None, &[value]);
            (principal, engine.commit(transaction))
        }));
    }
    wait_for_queued_commits(&engine, 4);
    release.wait();

    assert!(first.join().unwrap().is_ok());
    for handle in next {
        let (principal, result) = handle.join().unwrap();
        let root = result.unwrap().root();
        assert_eq!(engine.root(&principal).unwrap(), Some(root));
    }
    assert_eq!(pause.calls.load(Ordering::Relaxed), 2);
}

#[test]
fn every_group_member_observes_a_closed_engine_as_closed() {
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(open_grouped(
        directory.path(),
        Arc::new(NoFaults),
        GroupCommitPolicy::immediate(),
    ));
    engine.close().unwrap();
    let drain_reached = Arc::new(Barrier::new(2));
    let drain_release = Arc::new(Barrier::new(2));
    engine.gate_next_group_drain(Arc::clone(&drain_reached), Arc::clone(&drain_release));
    let barrier = Arc::new(Barrier::new(5));
    let mut handles = Vec::new();
    for value in 0_u8..4 {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let principal = format!("principal-{value}");
            let (_, transaction) = transaction(&principal, None, &[value]);
            barrier.wait();
            engine.commit(transaction)
        }));
    }
    barrier.wait();
    drain_reached.wait();
    wait_for_queued_commits(&engine, 4);
    drain_release.wait();

    for handle in handles {
        assert!(matches!(handle.join().unwrap(), Err(DurableError::Closed)));
    }
}

#[test]
fn grouped_faults_recover_only_complete_principal_roots() {
    for point in [
        FaultPoint::AfterObjectAppend,
        FaultPoint::AfterObjectFlush,
        FaultPoint::AfterCommitAppend,
        FaultPoint::AfterCommitFlush,
        FaultPoint::BeforeRootCas,
        FaultPoint::AfterRootCas,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let drain_reached = Arc::new(Barrier::new(2));
        let drain_release = Arc::new(Barrier::new(2));
        let engine = Arc::new(open_grouped(
            directory.path(),
            Arc::new(FailAt(point)),
            GroupCommitPolicy::immediate(),
        ));
        engine.gate_next_group_drain(Arc::clone(&drain_reached), Arc::clone(&drain_release));
        let barrier = Arc::new(Barrier::new(5));
        let mut handles = Vec::new();
        for value in 0_u8..4 {
            let engine = Arc::clone(&engine);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let principal = format!("principal-{value}");
                let (_, transaction) = transaction(&principal, None, &[value]);
                barrier.wait();
                engine.commit(transaction)
            }));
        }
        barrier.wait();
        drain_reached.wait();
        wait_for_queued_commits(&engine, 4);
        drain_release.wait();

        let mut precise = 0;
        let mut recovery = 0;
        for handle in handles {
            match handle.join().unwrap() {
                Err(DurableError::FaultInjected(actual)) if actual == point => precise += 1,
                Err(DurableError::RequiresRecovery) => recovery += 1,
                result => panic!("unexpected grouped fault result at {point:?}: {result:?}"),
            }
        }
        assert_eq!(precise, 1);
        assert_eq!(recovery, 3);

        for value in 0_u8..4 {
            let principal = format!("principal-{value}");
            let visible = engine.root(&principal).unwrap();
            if point == FaultPoint::AfterRootCas {
                assert!(visible.is_some(), "missing durable root for {principal}");
            } else {
                assert_eq!(visible, None, "unexpected root for {principal}");
            }
        }
    }
}

#[test]
fn grouped_commit_indexes_every_preceding_staged_frame() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open_grouped(
        directory.path(),
        Arc::new(NoFaults),
        GroupCommitPolicy::immediate(),
    );
    let staged = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"staged before group publication".to_vec(),
        Vec::new(),
        31,
        ObjectClass::Data,
    )
    .unwrap();
    let (staged_id, outcome) = engine.stage_object(&staged).unwrap();
    assert_eq!(outcome, InsertOutcome::Inserted);
    let (_, transaction) = transaction("alice", None, b"published");
    engine.commit(transaction).unwrap();
    drop(engine);

    let recovered = open(directory.path());
    assert_eq!(recovered.object(staged_id).unwrap(), Some(staged));
}

#[test]
#[ignore = "explicit durable group-commit throughput probe"]
fn group_commit_scale_probe() {
    const COMMITS_PER_WRITER: u8 = 128;

    for writers in [1_u8, 2, 4, 8] {
        let directory = tempfile::tempdir().unwrap();
        let flushes = Arc::new(CountFlushes::default());
        let faults: Arc<dyn FaultInjector> = flushes.clone();
        let engine = Arc::new(open_grouped(
            directory.path(),
            faults,
            GroupCommitPolicy::default(),
        ));
        let barrier = Arc::new(Barrier::new(usize::from(writers) + 1));
        let mut handles = Vec::new();
        for writer in 0..writers {
            let engine = Arc::clone(&engine);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let principal = format!("principal-{writer}");
                let mut expected = None;
                let mut latencies = Vec::new();
                barrier.wait();
                for sequence in 0..COMMITS_PER_WRITER {
                    let (_, transaction) = transaction(&principal, expected, &[writer, sequence]);
                    let started = Instant::now();
                    let outcome = engine.commit(transaction).unwrap();
                    latencies.push(started.elapsed());
                    expected = Some(outcome.root());
                }
                latencies
            }));
        }
        barrier.wait();
        let started = Instant::now();
        let mut writer_latencies = Vec::new();
        for handle in handles {
            writer_latencies.push(handle.join().unwrap());
        }
        let elapsed = started.elapsed();
        let mut latencies: Vec<_> = writer_latencies.iter().flatten().copied().collect();
        latencies.sort_unstable();
        let operations = u32::from(writers) * u32::from(COMMITS_PER_WRITER);
        let p50 = latencies[latencies.len() / 2];
        let p95 = latencies[(latencies.len() * 95 / 100).min(latencies.len() - 1)];
        let per_writer_p95: Vec<_> = writer_latencies
            .iter_mut()
            .map(|latencies| {
                latencies.sort_unstable();
                latencies[(latencies.len() * 95 / 100).min(latencies.len() - 1)].as_micros()
            })
            .collect();
        let per_writer_max: Vec<_> = writer_latencies
            .iter()
            .map(|latencies| latencies.last().unwrap().as_micros())
            .collect();
        println!(
            "group_commit_probe writers={writers} operations={operations} batches={} ops_per_second={:.1} p50_us={} p95_us={} per_writer_p95_us={per_writer_p95:?} per_writer_max_us={per_writer_max:?} wall_ms={}",
            flushes.roots.load(Ordering::Relaxed),
            f64::from(operations) / elapsed.as_secs_f64(),
            p50.as_micros(),
            p95.as_micros(),
            elapsed.as_millis(),
        );
    }
}

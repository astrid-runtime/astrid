//! Concurrency, durability, and recovery tests for group commit.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use astrid_storage_model::{ModelError, ObjectId};

use super::tests::{
    TEST_IDENTITY_SCHEME, TestEngine, TestIdentity, Utf8Codec, limits, open, transaction,
};
use super::*;

#[derive(Debug)]
struct FailAt(FaultPoint);

impl FaultInjector for FailAt {
    fn should_fail(&self, point: FaultPoint) -> bool {
        point == self.0
    }
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
        policy,
        faults,
        ObjectCacheConfig::disabled(),
    )
    .unwrap()
}

#[test]
fn independent_principals_share_one_durability_pair() {
    let directory = tempfile::tempdir().unwrap();
    let flushes = Arc::new(CountFlushes::default());
    let faults: Arc<dyn FaultInjector> = flushes.clone();
    let engine = Arc::new(open_grouped(
        directory.path(),
        faults,
        GroupCommitPolicy::new(Duration::from_millis(50)),
    ));
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
fn identical_group_frames_are_appended_once() {
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(open_grouped(
        directory.path(),
        Arc::new(NoFaults),
        GroupCommitPolicy::new(Duration::from_millis(50)),
    ));
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for principal in ["alice", "bob"] {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        let (_, transaction) = transaction(principal, None, b"shared");
        handles.push(thread::spawn(move || {
            barrier.wait();
            engine.commit(transaction).unwrap()
        }));
    }
    barrier.wait();

    let mut inserted = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().objects_inserted())
        .collect::<Vec<_>>();
    inserted.sort_unstable();
    assert_eq!(inserted, [0, 2]);
    assert_eq!(engine.object_count().unwrap(), 2);
    assert!(engine.root(&"alice".to_owned()).unwrap().is_some());
    assert!(engine.root(&"bob".to_owned()).unwrap().is_some());
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
        let engine = Arc::new(open_grouped(
            directory.path(),
            Arc::new(FailAt(point)),
            GroupCommitPolicy::new(Duration::from_millis(50)),
        ));
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
        drop(engine);

        let recovered = open(directory.path());
        for value in 0_u8..4 {
            let principal = format!("principal-{value}");
            let visible = recovered.root(&principal).unwrap();
            if point == FaultPoint::AfterRootCas {
                assert!(visible.is_some(), "missing durable root for {principal}");
            } else {
                assert_eq!(visible, None, "unexpected root for {principal}");
            }
        }
    }
}

#[test]
fn grouped_commit_advances_the_persistent_index_frontier() {
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(open_grouped(
        directory.path(),
        Arc::new(NoFaults),
        GroupCommitPolicy::new(Duration::from_millis(50)),
    ));
    let barrier = Arc::new(Barrier::new(5));
    let mut handles = Vec::new();
    for value in 0_u8..4 {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let principal = format!("principal-{value}");
            let (_, transaction) = transaction(&principal, None, &[value]);
            barrier.wait();
            engine.commit(transaction).unwrap();
        }));
    }
    barrier.wait();
    for handle in handles {
        handle.join().unwrap();
    }

    {
        let mut arena = open_rw(&directory.path().join(ARENA_FILE)).unwrap();
        let mut index = open_rw(&directory.path().join(INDEX_FILE)).unwrap();
        let arena_len = arena.metadata().unwrap().len();
        let recovered = recover_index(
            &mut index,
            &mut arena,
            TEST_IDENTITY_SCHEME,
            limits(),
            arena_len,
        )
        .expect("grouped commit must append a replayable index delta before close");
        assert_eq!(recovered.objects.len(), 8);
        assert_eq!(recovered.arena_len, arena_len);
    }
    engine.close().unwrap();
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

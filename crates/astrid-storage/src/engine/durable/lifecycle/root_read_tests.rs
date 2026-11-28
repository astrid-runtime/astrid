//! A root fast-path read overlapping close must observe the terminal fence.

use std::cmp::Ordering;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use crate::engine::RootTransaction;
use crate::engine::durable::tests::{TestIdentity, limits, transaction};
use crate::engine::durable::{
    DurableEngine, FaultInjector, FaultPoint, LIFECYCLE_CLOSED, PrincipalCodec,
};

#[derive(Debug)]
enum ReadEvent {
    Entered,
    Returned,
}

struct ReadGate {
    armed: AtomicBool,
    entered: mpsc::SyncSender<ReadEvent>,
    release: Mutex<Option<mpsc::Receiver<()>>>,
    on_drop: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

#[derive(Clone)]
struct GatedPrincipal {
    name: String,
    gate: Arc<ReadGate>,
}

impl Drop for GatedPrincipal {
    fn drop(&mut self) {
        if let Some(probe) = self.gate.on_drop.lock().unwrap().as_ref() {
            probe();
        }
    }
}

impl PartialEq for GatedPrincipal {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for GatedPrincipal {}

impl PartialOrd for GatedPrincipal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GatedPrincipal {
    fn cmp(&self, other: &Self) -> Ordering {
        if std::thread::current().name() == Some("ready-root-reader")
            && self.gate.armed.swap(false, AtomicOrdering::AcqRel)
        {
            self.gate.entered.send(ReadEvent::Entered).unwrap();
            self.gate
                .release
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .recv_timeout(Duration::from_secs(30))
                .unwrap();
        }
        self.name.cmp(&other.name)
    }
}

struct GatedCodec(Arc<ReadGate>);

impl PrincipalCodec<GatedPrincipal> for GatedCodec {
    fn encode(&self, principal: &GatedPrincipal) -> Vec<u8> {
        principal.name.as_bytes().to_vec()
    }

    fn decode(&self, bytes: &[u8]) -> Option<GatedPrincipal> {
        Some(GatedPrincipal {
            name: std::str::from_utf8(bytes).ok()?.to_owned(),
            gate: Arc::clone(&self.0),
        })
    }
}

#[test]
fn close_fences_a_reader_already_inside_the_published_root_lookup() {
    let directory = tempfile::tempdir().unwrap();
    let (entered, receive) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let gate = Arc::new(ReadGate {
        armed: AtomicBool::new(true),
        entered,
        release: Mutex::new(Some(released)),
        on_drop: Mutex::new(None),
    });
    let principal = GatedPrincipal {
        name: "alice".to_owned(),
        gate: Arc::clone(&gate),
    };
    let engine = Arc::new(
        DurableEngine::open(
            directory.path(),
            TestIdentity,
            GatedCodec(Arc::clone(&gate)),
            limits(),
        )
        .unwrap(),
    );
    let (commit, source) = transaction("alice", None, b"close/read interleaving");
    engine
        .commit(RootTransaction::new(
            principal.clone(),
            None,
            commit,
            source.records().to_vec(),
        ))
        .unwrap();
    let reader_engine = Arc::clone(&engine);
    let reader_gate = Arc::clone(&gate);
    let reader = std::thread::Builder::new()
        .name("ready-root-reader".to_owned())
        .spawn(move || {
            let ready = reader_engine.root_if_ready(&principal);
            let _ = reader_gate.entered.send(ReadEvent::Returned);
            ready
        })
        .unwrap();

    // Ord runs after the immutable root map load. Retain
    // that old map guard while close publishes CLOSED and clears its view.
    let entered = receive.recv_timeout(Duration::from_secs(30));
    let closed = engine.close();
    let released = engine.published_roots.entries.load().is_empty();
    let _ = release.send(());
    let ready = reader.join().unwrap();
    assert!(matches!(entered.unwrap(), ReadEvent::Entered));
    closed.unwrap();
    assert!(ready.is_none(), "closed root fast path remained usable");
    assert!(released);
}

#[test]
fn refused_slot_replacement_preserves_the_published_snapshot() {
    use crate::engine::durable::{DurableError, PublishedRoots};
    use crate::storage_model::{RootGeneration, RootState};
    use std::collections::BTreeMap;

    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    struct Key(u8);

    impl Clone for Key {
        fn clone(&self) -> Self {
            // Exercise an embedding that produces a different principal while building slots.
            Self(if self.0 == 2 { 3 } else { self.0 })
        }
    }

    let (commit, _) = transaction("alice", None, b"admitted");
    let root = RootState {
        generation: RootGeneration::INITIAL,
        commit,
    };
    let published = PublishedRoots::new(&BTreeMap::from([(Key(1), root)])).unwrap();
    let candidate = BTreeMap::from([(Key(2), root)]);
    assert!(matches!(
        PublishedRoots::new(&candidate),
        Err(DurableError::InvalidRootProjection)
    ));
    assert!(matches!(
        published.replace(&candidate),
        Err(DurableError::InvalidRootProjection)
    ));
    assert_eq!(published.get(&Key(1)), Some(root));
    assert_eq!(published.get(&Key(2)), None);
    assert_eq!(published.get(&Key(3)), None);
}

struct FailAfterRoot(AtomicBool);
impl FaultInjector for FailAfterRoot {
    fn should_fail(&self, point: FaultPoint) -> bool {
        point == FaultPoint::AfterRootCas && self.0.swap(false, AtomicOrdering::AcqRel)
    }
}

#[test]
fn a_read_started_during_poison_cannot_serve_the_pre_recovery_root() {
    let directory = tempfile::tempdir().unwrap();
    let (entered, receive) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let gate = Arc::new(ReadGate {
        armed: AtomicBool::new(true),
        entered,
        release: Mutex::new(Some(released)),
        on_drop: Mutex::new(None),
    });
    let principal = GatedPrincipal {
        name: "alice".to_owned(),
        gate: Arc::clone(&gate),
    };
    let fault = Arc::new(FailAfterRoot(AtomicBool::new(false)));
    let engine = Arc::new(
        DurableEngine::open_with_faults(
            directory.path(),
            TestIdentity,
            GatedCodec(Arc::clone(&gate)),
            limits(),
            Arc::clone(&fault) as Arc<dyn FaultInjector>,
        )
        .unwrap(),
    );
    let (old_commit, source) = transaction("alice", None, b"old");
    let old = engine
        .commit(RootTransaction::new(
            principal.clone(),
            None,
            old_commit,
            source.records().to_vec(),
        ))
        .unwrap()
        .root();
    let (new_commit, source) = transaction("alice", Some(old), b"new durable root");
    fault.0.store(true, AtomicOrdering::Release);
    assert!(
        engine
            .commit(RootTransaction::new(
                principal.clone(),
                Some(old),
                new_commit,
                source.records().to_vec()
            ))
            .is_err()
    );
    assert_eq!(
        engine.lifecycle.load(AtomicOrdering::Acquire),
        super::super::LIFECYCLE_REQUIRES_RECOVERY
    );
    assert_eq!(engine.published_roots.get(&principal), Some(old));

    let reader_engine = Arc::clone(&engine);
    let reading = principal.clone();
    let reader_gate = Arc::clone(&gate);
    let reader = std::thread::Builder::new()
        .name("ready-root-reader".to_owned())
        .spawn(move || {
            let ready = reader_engine.root_if_ready(&reading);
            let _ = reader_gate.entered.send(ReadEvent::Returned);
            ready
        })
        .unwrap();
    // Either an entry fence rejects immediately, or the bad implementation
    // pauses on its stale snapshot while real recovery republishes the root.
    let progress = receive.recv_timeout(Duration::from_secs(30));
    let recovered = engine.root(&principal);
    let _ = release.send(());
    let ready = reader.join().unwrap();
    progress.unwrap();
    let recovered = recovered.unwrap().unwrap();
    assert_eq!(recovered.commit, new_commit);
    assert_ne!(recovered, old);
    assert!(
        ready.is_none_or(|ready| ready.get() == Some(recovered)),
        "a read begun while poisoned returned the pre-recovery root"
    );
    engine.close().unwrap();
}

#[test]
fn retired_principal_destructors_run_after_the_engine_guards_are_released() {
    assert_destructors_run_unlocked(false);
}

#[test]
fn cached_principal_destructors_observe_closed_without_engine_guards() {
    assert_destructors_run_unlocked(true);
}

fn assert_destructors_run_unlocked(warm_cache: bool) {
    let directory = tempfile::tempdir().unwrap();
    let (entered, _receive) = mpsc::sync_channel(1);
    let (_release, released) = mpsc::sync_channel(1);
    let gate = Arc::new(ReadGate {
        armed: AtomicBool::new(false),
        entered,
        release: Mutex::new(Some(released)),
        on_drop: Mutex::new(None),
    });
    let principal = GatedPrincipal {
        name: "alice".to_owned(),
        gate: Arc::clone(&gate),
    };
    let engine = Arc::new(
        DurableEngine::open_with_object_cache(
            directory.path(),
            TestIdentity,
            GatedCodec(Arc::clone(&gate)),
            limits(),
            if warm_cache {
                crate::engine::ObjectCacheConfig::bounded(
                    std::num::NonZeroU64::new(512 * 1024).unwrap(),
                )
            } else {
                crate::engine::ObjectCacheConfig::disabled()
            },
        )
        .unwrap(),
    );
    let (commit, source) = transaction("alice", None, b"principal cleanup");
    engine
        .commit(RootTransaction::new(
            principal.clone(),
            None,
            commit,
            source.records().to_vec(),
        ))
        .unwrap();
    if warm_cache {
        assert!(engine.object_for(&principal, commit).unwrap().is_some());
        assert!(engine.object_cache_stats().resident_associations > 0);
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let locked = Arc::new(AtomicBool::new(false));
    let bad_reentry = Arc::new(AtomicBool::new(false));
    let bad = Arc::clone(&bad_reentry);
    let weak = Arc::downgrade(&engine);
    let count = Arc::clone(&drops);
    let observed = Arc::clone(&locked);
    let closing_thread = std::thread::current().id();
    *gate.on_drop.lock().unwrap() = Some(Box::new(move || {
        if std::thread::current().id() == closing_thread
            && let Some(engine) = weak.upgrade()
            && (warm_cache || engine.lifecycle.load(AtomicOrdering::Acquire) == LIFECYCLE_CLOSED)
        {
            count.fetch_add(1, AtomicOrdering::Relaxed);
            // A normal destructor may query its now-closed engine. Probe the
            // locks without blocking so a regression fails instead of hangs.
            let writer_locked = engine.inner.try_lock().is_none();
            let arbiter_locked = engine.checkpoint_arbiter.try_lock().is_none();
            if engine.lifecycle.load(AtomicOrdering::Acquire) != LIFECYCLE_CLOSED {
                bad.store(true, AtomicOrdering::Relaxed);
            }
            if writer_locked || arbiter_locked {
                observed.store(true, AtomicOrdering::Relaxed);
            } else if !matches!(
                engine.object_count(),
                Err(super::super::DurableError::Closed)
            ) {
                bad.store(true, AtomicOrdering::Relaxed);
            }
        }
    }));
    engine.close().unwrap();
    assert!(drops.load(AtomicOrdering::Relaxed) > 0);
    assert!(!bad_reentry.load(AtomicOrdering::Relaxed));
    assert!(
        !locked.load(AtomicOrdering::Relaxed),
        "metadata destructors ran under engine guards"
    );
}

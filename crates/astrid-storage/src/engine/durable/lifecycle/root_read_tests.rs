//! A root fast-path read overlapping close must observe the terminal fence.

use std::cmp::Ordering;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use crate::engine::RootTransaction;
use crate::engine::durable::tests::{TestIdentity, limits, transaction};
use crate::engine::durable::{DurableEngine, PrincipalCodec};

#[derive(Debug)]
struct ReadGate {
    armed: AtomicBool,
    entered: mpsc::SyncSender<()>,
    release: Mutex<Option<mpsc::Receiver<()>>>,
}

#[derive(Clone, Debug)]
struct GatedPrincipal {
    name: String,
    gate: Arc<ReadGate>,
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
            self.gate.entered.send(()).unwrap();
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
    let reader = std::thread::Builder::new()
        .name("ready-root-reader".to_owned())
        .spawn(move || reader_engine.root_if_ready(&principal))
        .unwrap();

    // Ord runs after the immutable root map load. Retain
    // that old map guard while close publishes CLOSED and clears its view.
    let entered = receive.recv_timeout(Duration::from_secs(30));
    let closed = engine.close();
    let released = engine.published_roots.entries.load().is_empty();
    let _ = release.send(());
    let ready = reader.join().unwrap();
    entered.unwrap();
    closed.unwrap();
    assert!(ready.is_none(), "closed root fast path remained usable");
    assert!(released);
}

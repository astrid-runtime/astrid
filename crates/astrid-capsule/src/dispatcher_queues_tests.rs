//! Tests for [`crate::dispatcher`]'s per-(capsule, principal) queue/consumer
//! machinery (in the sibling `queues` module). Kept here so they can reach the
//! module-private internals — `dispatch_single`, `InterceptorWork`,
//! `acquire_chain_lock`, the idle-grace override — directly via `use super::*`,
//! while the dispatcher's matching/enforcement tests live in
//! `dispatcher_tests.rs`.

use super::*;

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;

use crate::capsule::{Capsule, CapsuleId, CapsuleState, InterceptResult, ReadyStatus};
use crate::context::CapsuleContext;
use crate::error::CapsuleResult;
use crate::manifest::{CapabilitiesDef, CapsuleManifest, PackageDef};

/// A minimal mock capsule that counts `invoke_interceptor` calls. Self-
/// contained (no manifest interceptors needed — these tests drive
/// `dispatch_single` directly, bypassing matching).
struct CountingCapsule {
    id: CapsuleId,
    manifest: CapsuleManifest,
    invoke_counter: Arc<AtomicUsize>,
}

impl CountingCapsule {
    fn new(name: &str) -> (Self, Arc<AtomicUsize>) {
        let invoke_counter = Arc::new(AtomicUsize::new(0));
        let manifest = CapsuleManifest {
            package: PackageDef {
                name: name.to_string(),
                version: "0.0.1".to_string(),
                description: None,
                authors: Vec::new(),
                repository: None,
                homepage: None,
                documentation: None,
                license: None,
                license_file: None,
                readme: None,
                keywords: Vec::new(),
                categories: Vec::new(),
                astrid_version: None,
                publish: None,
                include: None,
                exclude: None,
                metadata: None,
            },
            components: Vec::new(),
            imports: std::collections::HashMap::new(),
            exports: std::collections::HashMap::new(),
            capabilities: CapabilitiesDef::default(),
            env: std::collections::HashMap::new(),
            context_files: Vec::new(),
            commands: Vec::new(),
            mcp_servers: Vec::new(),
            skills: Vec::new(),
            uplinks: Vec::new(),
            publishes: std::collections::HashMap::new(),
            subscribes: std::collections::HashMap::new(),
            tools: Vec::new(),
        };
        (
            Self {
                id: CapsuleId::from_static(name),
                manifest,
                invoke_counter: Arc::clone(&invoke_counter),
            },
            invoke_counter,
        )
    }
}

#[async_trait]
impl Capsule for CountingCapsule {
    fn id(&self) -> &CapsuleId {
        &self.id
    }
    fn manifest(&self) -> &CapsuleManifest {
        &self.manifest
    }
    fn state(&self) -> CapsuleState {
        CapsuleState::Ready
    }
    async fn load(&mut self, _ctx: &CapsuleContext) -> CapsuleResult<()> {
        Ok(())
    }
    async fn unload(&mut self) -> CapsuleResult<()> {
        Ok(())
    }
    async fn wait_ready(&self, _timeout: Duration) -> ReadyStatus {
        ReadyStatus::Ready
    }
    async fn invoke_interceptor(
        &self,
        _action: &str,
        _payload: &[u8],
        _caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> CapsuleResult<InterceptResult> {
        self.invoke_counter.fetch_add(1, Ordering::SeqCst);
        Ok(InterceptResult::Continue(Vec::new()))
    }
    fn check_health(&self) -> CapsuleState {
        CapsuleState::Ready
    }
    fn source_dir(&self) -> Option<&Path> {
        None
    }
}

#[tokio::test]
async fn dispatch_respawns_when_mapped_consumer_is_closed() {
    // Regression for the burst-induced `user.v1.prompt` stall: a stale CLOSED
    // sender left in the queue map (its consumer gone — idle-evict race or an
    // abnormally-ended task) must NOT make every later dispatch fail `Closed`
    // and drop forever. `get_or_spawn_consumer` skips a closed entry and
    // re-spawns; the event is delivered, not dropped.
    let (capsule, counter) = CountingCapsule::new("respawn-cap");
    let capsule: Arc<dyn Capsule> = Arc::new(capsule);

    // Pre-seed the queue map with a CLOSED sender for the key (receiver dropped).
    let queues: CapsuleQueues = Arc::new(parking_lot::Mutex::new(HashMap::new()));
    let key = (capsule.id().clone(), Some("alice".to_string()));
    let (dead_tx, dead_rx) = mpsc::channel::<InterceptorWork>(CAPSULE_EVENT_QUEUE_CAPACITY);
    drop(dead_rx);
    assert!(
        dead_tx.is_closed(),
        "precondition: the seeded sender is closed"
    );
    queues.lock().insert(key.clone(), dead_tx);

    // Dispatch through the closed entry — must re-spawn a live consumer and
    // deliver rather than hand back the dead sender and drop.
    dispatch_single(
        &queues,
        Arc::clone(&capsule),
        "test_action".to_string(),
        Arc::new("respawn.topic".to_string()),
        Arc::new(Vec::new()),
        None,
        Some("alice".to_string()),
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while counter.load(Ordering::SeqCst) < 1 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "a dispatch through a closed mapped sender must re-spawn and deliver, not drop"
    );
}

// ── Chain-lock map bounding (#828) ──────────────────────────────

#[tokio::test]
async fn chain_lock_prunes_entry_when_last_referrer_drops() {
    // Each distinct (capsule, principal) chain key inserts a mutex on
    // first use. Without RAII pruning the map grows one entry per
    // principal forever (ephemeral sub-agent churn). Acquire+drop a lock
    // for many distinct principals and assert the map sheds every entry.
    let chain_locks: ChainLocks = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let cap = CapsuleId::from_static("chainmap-cap");

    for i in 0..256 {
        let key = (cap.clone(), Some(format!("user-{i}")));
        let guard = acquire_chain_lock(&chain_locks, key).await;
        // While the guard is alive the entry exists.
        assert_eq!(chain_locks.read().len(), 1, "entry present while held");
        drop(guard);
        // Dropping the sole referrer prunes it.
        assert!(
            chain_locks.read().is_empty(),
            "map must shed the entry once the last referrer drops"
        );
    }

    assert!(
        chain_locks.read().is_empty(),
        "chain_locks must not retain one entry per principal"
    );
}

#[tokio::test]
async fn chain_lock_retained_while_another_holder_exists() {
    // Two acquirers of the SAME key share one map entry; the entry
    // survives until BOTH guards drop. This proves the prune only fires
    // for the last referrer — a held sibling chain is never stranded
    // without its serialization mutex.
    let chain_locks: ChainLocks = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let cap = CapsuleId::from_static("shared-cap");
    let key = (cap.clone(), Some("alice".to_string()));

    let g1 = acquire_chain_lock(&chain_locks, key.clone()).await;
    assert_eq!(chain_locks.read().len(), 1);

    // A second acquirer for the same key blocks on the mutex (g1 holds
    // it). Acquire it on a task; it shares the same map Arc, so the
    // entry must NOT be pruned while g1 lives.
    let cl = Arc::clone(&chain_locks);
    let k2 = key.clone();
    let task = tokio::spawn(async move {
        let g2 = acquire_chain_lock(&cl, k2).await;
        tokio::task::yield_now().await;
        drop(g2);
    });

    // g1 still alive → entry present regardless of the racing acquirer.
    assert_eq!(
        chain_locks.read().len(),
        1,
        "entry must persist while g1 holds it"
    );
    drop(g1);
    task.await.unwrap();

    // Both guards gone → entry pruned.
    assert!(
        chain_locks.read().is_empty(),
        "entry pruned once both holders drop"
    );
}

#[tokio::test]
async fn idle_evicts_then_respawns_after_grace() {
    // A consumer spawned for a key self-evicts after the (collapsed) idle
    // grace, then re-spawns on the next dispatch — the event still lands.
    set_idle_consumer_grace_for_test(100);
    struct ResetGrace;
    impl Drop for ResetGrace {
        fn drop(&mut self) {
            set_idle_consumer_grace_for_test(DEFAULT_IDLE_CONSUMER_GRACE_MS);
        }
    }
    let _reset = ResetGrace;

    let (capsule, counter) = CountingCapsule::new("evict-cap");
    let capsule: Arc<dyn Capsule> = Arc::new(capsule);
    let queues: CapsuleQueues = Arc::new(parking_lot::Mutex::new(HashMap::new()));

    dispatch_single(
        &queues,
        Arc::clone(&capsule),
        "test_action".to_string(),
        Arc::new("evict.topic".to_string()),
        Arc::new(Vec::new()),
        None,
        Some("alice".to_string()),
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while counter.load(Ordering::SeqCst) < 1 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(counter.load(Ordering::SeqCst), 1, "first event should land");

    // Sleep past the collapsed grace so the consumer idle-evicts.
    tokio::time::sleep(Duration::from_millis(400)).await;

    dispatch_single(
        &queues,
        Arc::clone(&capsule),
        "test_action".to_string(),
        Arc::new("evict.topic".to_string()),
        Arc::new(Vec::new()),
        None,
        Some("alice".to_string()),
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while counter.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "second event must re-spawn the consumer and land"
    );
}

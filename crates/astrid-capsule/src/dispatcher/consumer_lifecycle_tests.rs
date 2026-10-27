use super::*;
use crate::dispatcher::consumer::{evict_idle, run_consumer};

fn work() -> InterceptorWork {
    InterceptorWork {
        action: "test_action".into(),
        payload: Arc::new(Vec::new()),
        topic: Arc::new("fixture".into()),
        ipc_message: None,
        failure: None,
    }
}

fn key() -> (RuntimeId, PrincipalKey) {
    (
        RuntimeId::for_test(CapsuleId::from_static("fixture"), 1),
        None,
    )
}

#[test]
fn idle_probe_preserves_work_queued_after_timeout() {
    let queues: CapsuleQueues = Arc::default();
    let (tx, mut rx) = mpsc::channel(2);
    let identity = tx.downgrade();
    tx.try_send(work()).unwrap();
    queues.lock().insert(key(), tx);
    assert!(!evict_idle(&rx, &queues, &key(), &identity));
    assert!(
        rx.try_recv().is_ok(),
        "idle probe must not consume queued work"
    );
    assert!(evict_idle(&rx, &queues, &key(), &identity));
}

#[test]
fn stale_idle_consumer_cannot_remove_a_replacement_channel() {
    let queues: CapsuleQueues = Arc::default();
    let (old_tx, old_rx) = mpsc::channel(2);
    let identity = old_tx.downgrade();
    let (new_tx, _new_rx) = mpsc::channel(2);
    queues.lock().insert(key(), new_tx);
    assert_eq!(old_rx.sender_strong_count(), 1);
    assert!(!evict_idle(&old_rx, &queues, &key(), &identity));
    assert_eq!(queues.lock().len(), 1);
}

#[tokio::test]
async fn retired_idle_consumer_releases_capsule_without_idle_grace() {
    let (capsule, _) = MockCapsule::new("fixture", "fixture");
    let mut capsule: Arc<dyn Capsule> = Arc::new(capsule);
    let queues: CapsuleQueues = Arc::default();
    let (tx, rx) = mpsc::channel(2);
    let identity = tx.downgrade();
    // Hold an external sender so ordinary idle eviction cannot make this
    // pass, even while another test shortens the global idle grace.
    let keepalive = tx.clone();
    queues.lock().insert(key(), tx);
    let handle = tokio::spawn(run_consumer(
        rx,
        capsule.clone(),
        queues.clone(),
        key(),
        identity,
    ));
    tokio::task::yield_now().await;
    capsule.retire();
    tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .unwrap()
        .unwrap();
    drop(keepalive);
    assert!(queues.lock().is_empty());
    assert!(
        Arc::get_mut(&mut capsule).is_some(),
        "unload must acquire exclusive ownership"
    );
}

#[tokio::test]
async fn retirement_waits_for_active_invoke_and_outstanding_reserved_work() {
    verify_active_drain(false).await;
}

#[tokio::test]
async fn global_stop_waits_for_active_invoke_and_outstanding_reserved_work() {
    verify_active_drain(true).await;
}

async fn verify_active_drain(global_stop: bool) {
    let (mut capsule, _) = MockCapsule::new("fixture", "fixture");
    let blocker = Arc::new(tokio::sync::Semaphore::new(0));
    capsule.blocked_principal = Some(("alice".into(), blocker.clone()));
    let counter = Arc::new(AtomicUsize::new(0));
    capsule.invoke_counter = Some(counter.clone());
    let gate = capsule.delivery_gate.clone();
    let capsule: Arc<dyn Capsule> = Arc::new(capsule);
    let queues: CapsuleQueues = Arc::default();
    let (tx, rx) = mpsc::channel(3);
    let identity = tx.downgrade();
    let permit = tx.clone().reserve_owned().await.unwrap();
    let mut first = work();
    first.ipc_message = Some(Arc::new(
        astrid_events::IpcMessage::new(
            Topic::from_raw("fixture"),
            IpcPayload::RawJson(serde_json::json!({})),
            uuid::Uuid::nil(),
        )
        .with_principal("alice"),
    ));
    tx.try_send(first).unwrap();
    queues.lock().insert(key(), tx);
    let mut handle = tokio::spawn(run_consumer(rx, capsule, queues.clone(), key(), identity));
    tokio::task::yield_now().await;
    if global_stop {
        super::super::queues::DispatcherControl::new(queues.clone()).stop();
    } else {
        gate.retire();
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut handle)
            .await
            .is_err()
    );
    blocker.add_permits(1);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut handle)
            .await
            .is_err()
    );
    permit.send(work());
    tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(counter.load(Ordering::SeqCst), 2);
    assert!(queues.lock().is_empty());
}

/// A custom capsule may omit an admission gate; global stop must still wake it.
struct GatelessCapsule(MockCapsule);

#[async_trait]
impl Capsule for GatelessCapsule {
    fn id(&self) -> &CapsuleId {
        self.0.id()
    }
    fn manifest(&self) -> &CapsuleManifest {
        self.0.manifest()
    }
    fn state(&self) -> CapsuleState {
        self.0.state()
    }
    async fn load(&mut self, ctx: &CapsuleContext) -> CapsuleResult<()> {
        self.0.load(ctx).await
    }
    async fn unload(&mut self) -> CapsuleResult<()> {
        self.0.unload().await
    }
    async fn invoke_interceptor(
        &self,
        action: &str,
        payload: &[u8],
        caller: Option<&astrid_events::IpcMessage>,
    ) -> CapsuleResult<InterceptResult> {
        self.0.invoke_interceptor(action, payload, caller).await
    }
}

#[tokio::test]
async fn global_stop_wakes_gateless_consumers_and_refuses_resurrection() {
    let (mock, _) = MockCapsule::new("fixture", "fixture");
    let mut capsule: Arc<dyn Capsule> = Arc::new(GatelessCapsule(mock));
    let queues: CapsuleQueues = Arc::default();
    let control = super::super::queues::DispatcherControl::new(queues.clone());
    let (_, keepalive) = get_or_spawn_consumer(&queues, &capsule, key());
    tokio::task::yield_now().await;
    assert_eq!(Arc::strong_count(&capsule), 2);
    control.stop();
    tokio::time::timeout(Duration::from_secs(1), async {
        while Arc::strong_count(&capsule) > 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (_, refused) = get_or_spawn_consumer(&queues, &capsule, key());
    assert!(refused.is_closed());
    assert!(queues.lock().is_empty());
    drop(keepalive);
    assert!(Arc::get_mut(&mut capsule).is_some());
}

#[derive(Clone)]
struct WarningCounter(Arc<AtomicUsize>);

impl tracing::Subscriber for WarningCounter {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() == tracing::Level::WARN {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn post_stop_unreserved_delivery_does_not_report_an_invariant_violation() {
    let queues: CapsuleQueues = Arc::default();
    super::super::queues::DispatcherControl::new(queues.clone()).stop();
    let (capsule, _) = MockCapsule::new("fixture", "fixture");
    let warnings = Arc::new(AtomicUsize::new(0));
    tracing::subscriber::with_default(WarningCounter(warnings.clone()), || {
        dispatch_single(&queues, key(), Arc::new(capsule), work());
    });
    assert_eq!(warnings.load(Ordering::SeqCst), 0);
    assert!(queues.lock().is_empty());
}

//! Ordering, restart-gap and fail-closed behaviour of the host-audit lane.

use std::sync::atomic::AtomicU64;

use super::*;

fn marker_store() -> ScopedKvStore {
    ScopedKvStore::new(
        Arc::new(astrid_storage::MemoryKvStore::new()),
        "system:control:audit-lane",
    )
    .expect("marker scope")
}

/// Wait until the writer has made at least `calls` calls durable.
fn wait_persisted(sink: &KernelAuditSink, calls: u64) {
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(10))
        .expect("deadline");
    while sink.health().persisted < calls {
        assert!(std::time::Instant::now() < deadline, "writer stalled");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Concurrent producers across several principals, with small batches and
/// a short window so many batches interleave with production: every chain
/// lists its calls in exactly the order they were accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chain_order_equals_call_order_under_concurrency() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09b1));
    let sink = Arc::new(KernelAuditSink::with_policy(
        Arc::clone(&log),
        session.clone(),
        policy(10, 8, 4096),
    ));
    let principals: Vec<_> = ["alice", "bob", "carol"]
        .iter()
        .map(|name| PrincipalId::new(*name).expect("principal"))
        .collect();
    // The sequence number is drawn in the same critical section as the
    // report, so it is the call order the lane must preserve.
    let order = Arc::new(Mutex::new(()));
    let sequence = Arc::new(AtomicU64::new(0));
    let mut threads = Vec::new();
    for worker in 0..6_usize {
        let sink = Arc::clone(&sink);
        let order = Arc::clone(&order);
        let sequence = Arc::clone(&sequence);
        let principal = principals[worker % principals.len()].clone();
        threads.push(std::thread::spawn(move || {
            for _ in 0..150 {
                let _serial = order.lock().expect("order lock");
                let n = sequence.fetch_add(1, Ordering::SeqCst);
                let path = format!("/seq/{n:06}");
                // Denials are exact entries; every third call is an allowed
                // read between them, recorded as its own one-call run.
                let outcome = if n.is_multiple_of(3) {
                    HostAuditOutcome::Allowed
                } else {
                    HostAuditOutcome::Denied("not in host_fs allowlist")
                };
                sink.record(
                    &principal,
                    HostAuditEvent::FileRead { path: &path },
                    outcome,
                );
            }
        }));
    }
    for thread in threads {
        thread.join().expect("producer");
    }
    sink.shutdown();

    let mut total = 0;
    for principal in &principals {
        let entries = log
            .get_principal_entries(&session, Some(principal))
            .await
            .expect("entries");
        let paths: Vec<String> = entries
            .iter()
            .map(|entry| match &entry.action {
                AuditAction::FileRead { actor: None, path } => path.clone(),
                AuditAction::HostCallRun { calls } => match &calls.tally[0].first {
                    AuditAction::FileRead { actor: None, path } => path.clone(),
                    other => panic!("unexpected run sample {other:?}"),
                },
                other => panic!("unexpected action {other:?}"),
            })
            .collect();
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted, "{principal}: chain order must be call order");
        total += entries.len();
        let verification = log
            .verify_principal_chain(&session, Some(principal))
            .await
            .expect("verify");
        assert!(verification.valid, "{verification:?}");
    }
    assert!(total > 0);
    assert_eq!(sink.health().accepted, 900);
    assert_eq!(sink.health().queue_depth, 0);
}

/// A lane run that dies with calls still queued leaves a signed gap entry in
/// every chain it wrote to, and in the system chain, at the next start. A
/// clean shutdown leaves none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unclean_stop_is_recorded_as_a_gap_at_next_start() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09b2));
    let marker = marker_store();
    let alice = PrincipalId::new("alice").expect("alice");
    let bob = PrincipalId::new("bob").expect("bob");

    let first = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(10, 128, 4096),
        marker.clone(),
    );
    for principal in [&alice, &bob] {
        first.record(
            principal,
            HostAuditEvent::FileRead { path: "/durable" },
            HostAuditOutcome::Allowed,
        );
    }
    wait_persisted(&first, 2);
    // This call is still queued when the lane run dies.
    first.record(
        &alice,
        HostAuditEvent::FileDelete { path: "/lost" },
        HostAuditOutcome::Denied("not in host_fs allowlist"),
    );
    first.abandon_for_test();
    let before = log.count_session(&session).await.expect("count");

    let second = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(10, 128, 4096),
        marker.clone(),
    );
    second.shutdown();
    assert_eq!(
        second.health().gaps_recorded,
        3,
        "alice, bob and the system chain"
    );
    for principal in [Some(&alice), Some(&bob), None] {
        let entries = log
            .get_principal_entries(&session, principal)
            .await
            .expect("entries");
        let last = entries.last().expect("gap entry");
        assert!(
            matches!(
                &last.action,
                AuditAction::HostCallGap { reason, .. } if reason == "unclean_shutdown"
            ),
            "{principal:?}: {:?}",
            last.action
        );
    }
    assert_eq!(
        log.count_session(&session).await.expect("count"),
        before + 3
    );
    assert!(log.verify_chain(&session).await.expect("verify").valid);

    // The second run closed cleanly: a third run records no gap.
    let third = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(10, 128, 4096),
        marker,
    );
    third.shutdown();
    assert_eq!(third.health().gaps_recorded, 0);
    assert_eq!(
        log.count_session(&session).await.expect("count"),
        before + 3
    );
}

/// A marker that cannot be parsed says nothing about the previous run: it is
/// recorded as a gap of an unknown run in the system chain and replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreadable_marker_is_recorded_as_a_gap_and_replaced() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09b6));
    let marker = marker_store();
    marker
        .set("lane", b"not a marker".to_vec())
        .await
        .expect("corrupt marker");

    let first = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(10, 128, 4096),
        marker.clone(),
    );
    first.shutdown();
    assert_eq!(first.health().gaps_recorded, 1);
    let system = log
        .get_principal_entries(&session, None)
        .await
        .expect("system entries");
    assert!(
        matches!(
            &system[..],
            [entry] if matches!(
                &entry.action,
                AuditAction::HostCallGap { epoch, reason, .. }
                    if epoch == "unknown" && reason == "lane_marker_unreadable"
            )
        ),
        "{system:?}"
    );

    let second = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(10, 128, 4096),
        marker,
    );
    second.shutdown();
    assert_eq!(second.health().gaps_recorded, 0, "the marker was replaced");
}

/// A gap owed only to the system chain is written when the lane starts, not
/// held until the next host call or shutdown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn system_only_gap_is_recorded_without_a_host_call() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09b9));
    let marker = marker_store();
    marker
        .set("lane", b"not a marker".to_vec())
        .await
        .expect("corrupt marker");

    let sink = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(10, 128, 4096),
        marker,
    );
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(10))
        .expect("deadline");
    while sink.health().gaps_recorded < 1 {
        assert!(
            std::time::Instant::now() < deadline,
            "gap not recorded while idle"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(
        log.get_principal_entries(&session, None)
            .await
            .expect("system entries")
            .len(),
        1
    );
    sink.shutdown();
}

/// A system-chain gap entry the log refuses at start is retried while the
/// lane is idle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_system_gap_is_retried_while_idle() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09ba));
    log.set_global_retention_caps(1, u64::MAX)
        .await
        .expect("caps");
    log.append(
        session.clone(),
        AuditAction::FileRead {
            actor: None,
            path: "/fills-the-log".into(),
        },
        AuthorizationProof::System {
            reason: "test".into(),
        },
        AuditOutcome::success(),
    )
    .await
    .expect("first entry");
    let marker = marker_store();
    marker
        .set("lane", b"not a marker".to_vec())
        .await
        .expect("corrupt marker");

    let sink = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(10, 128, 4096),
        marker,
    );
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(15))
        .expect("deadline");
    while !sink
        .health()
        .last_error
        .is_some_and(|error| error.contains("system-chain gap entry failed"))
    {
        assert!(std::time::Instant::now() < deadline, "no failed attempt");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(sink.health().gaps_recorded, 0);
    log.set_global_retention_caps(1_000, u64::MAX)
        .await
        .expect("raise caps");
    while sink.health().gaps_recorded < 1 {
        assert!(
            std::time::Instant::now() < deadline,
            "gap not retried while idle"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    sink.shutdown();
}

/// A batch the log refuses is kept and retried, in order and without loss,
/// until the log accepts it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_batch_is_retried_in_order_once_the_log_recovers() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09b7));
    let p = principal();
    log.set_global_retention_caps(1, u64::MAX)
        .await
        .expect("caps");
    log.append_with_principal(
        session.clone(),
        p.clone(),
        AuditAction::FileRead {
            actor: None,
            path: "/fills-the-log".into(),
        },
        AuthorizationProof::System {
            reason: "test".into(),
        },
        AuditOutcome::success(),
    )
    .await
    .expect("first entry");
    let sink =
        KernelAuditSink::with_policy(Arc::clone(&log), session.clone(), policy(10, 128, 4096));
    for index in 0..3 {
        let path = format!("/retry-{index}");
        sink.record(
            &p,
            HostAuditEvent::FileRead { path: &path },
            HostAuditOutcome::Denied("not in host_fs allowlist"),
        );
    }
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(10))
        .expect("deadline");
    while sink.health().failed == 0 {
        assert!(std::time::Instant::now() < deadline, "no failed attempt");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(sink.health().persisted, 0);
    log.set_global_retention_caps(1_000, u64::MAX)
        .await
        .expect("raise caps");
    wait_persisted(&sink, 3);
    sink.shutdown();

    let paths: Vec<_> = log
        .get_principal_entries(&session, Some(&p))
        .await
        .expect("entries")
        .into_iter()
        .map(|entry| match entry.action {
            AuditAction::FileRead { actor: None, path } => path,
            other => panic!("unexpected action {other:?}"),
        })
        .collect();
    assert_eq!(
        paths,
        ["/fills-the-log", "/retry-0", "/retry-1", "/retry-2"]
    );
    let health = sink.health();
    assert_eq!((health.lost, health.queue_depth), (0, 0));
    assert!(log.verify_chain(&session).await.expect("verify").valid);
}

/// Gap duties survive a second unclean stop before they were recorded.
#[test]
fn unrecorded_gap_duties_carry_over_to_the_next_run() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let store = marker_store();
    let first = marker::LaneMarker::open(&runtime, store.clone(), "run-1".into(), Timestamp::now());
    assert!(first.duties.is_empty() && first.errors.is_empty());
    let mut second =
        marker::LaneMarker::open(&runtime, store.clone(), "run-2".into(), Timestamp::now());
    assert_eq!(second.duties.len(), 1);
    assert_eq!(second.duties[0].epoch, "run-1");
    second
        .marker
        .register(&runtime, &[PrincipalId::new("alice").expect("alice")])
        .expect("register");
    // Run 2 dies before recording run 1's gap.
    let third = marker::LaneMarker::open(&runtime, store, "run-3".into(), Timestamp::now());
    let epochs: Vec<_> = third
        .duties
        .iter()
        .map(|duty| duty.epoch.as_str())
        .collect();
    assert_eq!(epochs, ["run-1", "run-2"]);
    assert_eq!(third.duties[1].chains, ["alice"]);
}

/// Memory store whose every operation fails while `failing` is set.
struct FlakyKv {
    inner: astrid_storage::MemoryKvStore,
    failing: std::sync::atomic::AtomicBool,
}

impl FlakyKv {
    fn check(&self) -> astrid_storage::StorageResult<()> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(astrid_storage::StorageError::Connection(
                "marker store offline".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl astrid_storage::KvStore for FlakyKv {
    async fn get(
        &self,
        namespace: &str,
        key: &str,
    ) -> astrid_storage::StorageResult<Option<Vec<u8>>> {
        self.check()?;
        self.inner.get(namespace, key).await
    }
    async fn set(
        &self,
        namespace: &str,
        key: &str,
        value: Vec<u8>,
    ) -> astrid_storage::StorageResult<()> {
        self.check()?;
        self.inner.set(namespace, key, value).await
    }
    async fn delete(&self, namespace: &str, key: &str) -> astrid_storage::StorageResult<bool> {
        self.check()?;
        self.inner.delete(namespace, key).await
    }
    async fn exists(&self, namespace: &str, key: &str) -> astrid_storage::StorageResult<bool> {
        self.check()?;
        self.inner.exists(namespace, key).await
    }
    async fn list_keys(&self, namespace: &str) -> astrid_storage::StorageResult<Vec<String>> {
        self.check()?;
        self.inner.list_keys(namespace).await
    }
    async fn list_keys_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> astrid_storage::StorageResult<Vec<String>> {
        self.check()?;
        self.inner.list_keys_with_prefix(namespace, prefix).await
    }
    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> astrid_storage::StorageResult<bool> {
        self.check()?;
        self.inner
            .compare_and_swap(namespace, key, expected, new)
            .await
    }
    async fn clear_namespace(&self, namespace: &str) -> astrid_storage::StorageResult<u64> {
        self.check()?;
        self.inner.clear_namespace(namespace).await
    }
}

/// A marker store that cannot be read or written leaves signed gap entries
/// for both the unknown previous run and the current, unprotected run; once
/// the store works again the marker is written and a clean stop leaves no
/// gap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_marker_store_is_recorded_as_gaps() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09b8));
    let kv = Arc::new(FlakyKv {
        inner: astrid_storage::MemoryKvStore::new(),
        failing: std::sync::atomic::AtomicBool::new(true),
    });
    let marker = ScopedKvStore::new(
        Arc::clone(&kv) as Arc<dyn astrid_storage::KvStore>,
        "system:control:audit-lane",
    )
    .expect("marker scope");
    let alice = PrincipalId::new("alice").expect("alice");
    let bob = PrincipalId::new("bob").expect("bob");

    let first = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(10, 128, 4096),
        marker.clone(),
    );
    first.record(
        &alice,
        HostAuditEvent::FileRead { path: "/a" },
        HostAuditOutcome::Allowed,
    );
    wait_persisted(&first, 1);
    let reasons: Vec<String> = log
        .get_principal_entries(&session, None)
        .await
        .expect("system entries")
        .into_iter()
        .filter_map(|entry| match entry.action {
            AuditAction::HostCallGap { reason, .. } => Some(reason),
            _ => None,
        })
        .collect();
    assert_eq!(
        reasons,
        ["lane_marker_unreadable", "lane_marker_unavailable"]
    );
    assert!(first.health().degraded);

    kv.failing.store(false, Ordering::SeqCst);
    first.record(
        &bob,
        HostAuditEvent::FileRead { path: "/b" },
        HostAuditOutcome::Allowed,
    );
    wait_persisted(&first, 2);
    first.shutdown();

    let second = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(10, 128, 4096),
        marker,
    );
    second.shutdown();
    assert_eq!(second.health().gaps_recorded, 0);
}

/// The gap a run owes for its own unwritable marker stays owed after the
/// store recovers: a crash before the gap entry is durable leaves it to the
/// next run.
#[test]
fn unavailable_marker_duty_survives_a_later_marker_write() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let kv = Arc::new(FlakyKv {
        inner: astrid_storage::MemoryKvStore::new(),
        failing: std::sync::atomic::AtomicBool::new(true),
    });
    let store = ScopedKvStore::new(
        Arc::clone(&kv) as Arc<dyn astrid_storage::KvStore>,
        "system:control:audit-lane",
    )
    .expect("marker scope");
    let mut first =
        marker::LaneMarker::open(&runtime, store.clone(), "run-1".into(), Timestamp::now());
    assert_eq!(first.errors.len(), 2);
    kv.failing.store(false, Ordering::SeqCst);
    first
        .marker
        .register(&runtime, &[PrincipalId::new("alice").expect("alice")])
        .expect("register");
    // Run 1 dies before recording its gaps.
    let second = marker::LaneMarker::open(&runtime, store, "run-2".into(), Timestamp::now());
    let owed: Vec<_> = second
        .duties
        .iter()
        .map(|duty| (duty.epoch.as_str(), duty.reason.as_str()))
        .collect();
    assert_eq!(
        owed,
        [
            ("unknown", "lane_marker_unreadable"),
            ("run-1", "lane_marker_unavailable"),
            ("run-1", "unclean_shutdown"),
        ]
    );
}

fn fail_closed_policy(classes: &[&str]) -> HostAuditPolicy {
    HostAuditPolicy::from(&AuditConfig {
        host_coalesce_ms: 60_000,
        host_fail_closed: classes.iter().map(|class| (*class).to_owned()).collect(),
        ..AuditConfig::default()
    })
}

/// A fail-closed call is admitted only once its write-ahead entry is
/// durable, behind everything queued before it; other classes are not held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fail_closed_call_waits_for_a_durable_write_ahead_entry() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09b3));
    let sink = KernelAuditSink::with_policy(
        Arc::clone(&log),
        session.clone(),
        fail_closed_policy(&["file_write"]),
    );
    let p = principal();
    sink.record(
        &p,
        HostAuditEvent::FileRead { path: "/before" },
        HostAuditOutcome::Allowed,
    );
    sink.admit(&p, HostAuditEvent::FileRead { path: "/not-held" })
        .expect("best-effort class");
    assert_eq!(log.count_session(&session).await.expect("count"), 0);

    sink.admit(
        &p,
        HostAuditEvent::FileWrite {
            content_hash: None,
            path: "/held",
        },
    )
    .expect("durable admission");
    let entries = log
        .get_principal_entries(&session, Some(&p))
        .await
        .expect("entries");
    assert_eq!(
        entries.len(),
        2,
        "the earlier call is written first: {entries:?}"
    );
    assert!(
        matches!(&entries[0].action, AuditAction::FileRead { actor: None, path } if path == "/before")
    );
    assert!(matches!(
        &entries[1].action,
        AuditAction::HostCallAdmitted { call }
            if matches!(call.as_ref(), AuditAction::FileWrite { path, .. } if path == "/held")
    ));

    sink.record(
        &p,
        HostAuditEvent::FileWrite {
            content_hash: None,
            path: "/held",
        },
        HostAuditOutcome::Allowed,
    );
    sink.shutdown();
    let entries = log
        .get_principal_entries(&session, Some(&p))
        .await
        .expect("entries");
    assert!(matches!(&entries[2].action, AuditAction::FileWrite { path, .. } if path == "/held"));
    assert!(log.verify_chain(&session).await.expect("verify").valid);
}

/// When the write-ahead entry cannot be made durable, the call is refused
/// and the refusal is queued as a denial.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fail_closed_call_is_refused_when_the_log_cannot_record_it() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09b4));
    let p = principal();
    // A one-entry retention cap with no sealed segment to prune makes every
    // further append fail.
    log.set_global_retention_caps(1, u64::MAX)
        .await
        .expect("caps");
    log.append_with_principal(
        session.clone(),
        p.clone(),
        AuditAction::FileRead {
            actor: None,
            path: "/fills-the-log".into(),
        },
        AuthorizationProof::System {
            reason: "test".into(),
        },
        AuditOutcome::success(),
    )
    .await
    .expect("first entry");
    let sink = KernelAuditSink::with_policy(
        Arc::clone(&log),
        session.clone(),
        fail_closed_policy(&["process_spawn"]),
    );

    let refusal = sink
        .admit(&p, HostAuditEvent::ProcessSpawn { command: "rm" })
        .expect_err("no durable entry, no effect");
    assert!(refusal.reason().contains("retention cap"), "{refusal}");
    let health = sink.health();
    assert_eq!(health.fail_closed_refused, 1);
    assert!(health.degraded);
    assert_eq!(health.queue_depth, 1, "the refusal is queued as a denial");
    sink.shutdown();
    assert_eq!(log.count_session(&session).await.expect("count"), 1);
}

/// After shutdown a fail-closed call is refused and a best-effort call is
/// counted as dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn calls_after_shutdown_are_refused_or_counted() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09b5));
    let sink = KernelAuditSink::with_policy(
        Arc::clone(&log),
        session,
        fail_closed_policy(&["net_connect"]),
    );
    let p = principal();
    sink.shutdown();
    assert!(
        sink.admit(
            &p,
            HostAuditEvent::NetConnect {
                host: "example.com",
                port: 443
            }
        )
        .is_err()
    );
    sink.record(
        &p,
        HostAuditEvent::FileRead { path: "/late" },
        HostAuditOutcome::Allowed,
    );
    let health = sink.health();
    assert_eq!(
        health.dropped_after_shutdown, 2,
        "the refusal and the late call"
    );
    assert_eq!(health.fail_closed_refused, 1);
}

/// The configuration and the audit records spell host-call classes alike.
#[test]
fn fail_closed_classes_match_the_record_classes() {
    for class in astrid_config::validate::HOST_AUDIT_FAIL_CLOSED_CLASSES {
        assert!(HOST_CALL_CLASSES.contains(&class), "{class}");
    }
    let policy = fail_closed_policy(&astrid_config::validate::HOST_AUDIT_FAIL_CLOSED_CLASSES);
    for event in [
        HostAuditEvent::FileRead { path: "/p" },
        HostAuditEvent::FileWrite {
            content_hash: None,
            path: "/p",
        },
        HostAuditEvent::FileDelete { path: "/p" },
        HostAuditEvent::NetConnect { host: "h", port: 1 },
        HostAuditEvent::NetBind { addr: "a" },
        HostAuditEvent::ProcessSpawn { command: "c" },
    ] {
        assert!(policy.fails_closed(&event), "{event:?}");
    }
    assert!(!policy.fails_closed(&HostAuditEvent::FileProbe { path: "/p" }));
    assert!(
        !HostAuditPolicy::default().fails_closed(&HostAuditEvent::FileWrite {
            content_hash: None,
            path: "/p"
        })
    );
}

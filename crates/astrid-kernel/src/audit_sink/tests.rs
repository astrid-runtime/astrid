use std::sync::Arc;

use super::*;

use astrid_audit::host_call::{HostCallRef, HostCallSummary};
use astrid_audit::{AuditEntry, AuditOutcome, AuthorizationProof};
use astrid_crypto::KeyPair;

#[path = "bench_tests.rs"]
mod bench;
#[path = "lane_behaviour_tests.rs"]
mod lane_behaviour;

fn principal() -> PrincipalId {
    PrincipalId::new("alice").expect("valid principal")
}

fn policy(coalesce_ms: u64, batch: u64, capacity: u64) -> HostAuditPolicy {
    HostAuditPolicy::from(&AuditConfig {
        host_coalesce_ms: coalesce_ms,
        host_batch_max: batch,
        host_queue_capacity: capacity,
        host_path_probes: false,
        ..AuditConfig::default()
    })
}

fn test_policy() -> HostAuditPolicy {
    policy(10, 128, 4096)
}

fn test_sink(log: Arc<AuditLog>, session: SessionId) -> KernelAuditSink {
    KernelAuditSink::with_policy(log, session, test_policy())
}

fn run_summary(entry: &AuditEntry) -> &HostCallSummary {
    match &entry.action {
        AuditAction::HostCallRun { calls } => calls,
        other => panic!("expected a host-call run, got {other:?}"),
    }
}

fn record_event_kinds(sink: &KernelAuditSink, principal: &PrincipalId) {
    sink.record(
        principal,
        HostAuditEvent::FileRead { path: "/w/r" },
        HostAuditOutcome::Allowed,
    );
    sink.record(
        principal,
        HostAuditEvent::FileWrite { path: "/w/w" },
        HostAuditOutcome::Failed("disk full"),
    );
    sink.record(
        principal,
        HostAuditEvent::FileDelete { path: "/w/d" },
        HostAuditOutcome::Allowed,
    );
    sink.record(
        principal,
        HostAuditEvent::NetConnect {
            host: "example.com",
            port: 443,
        },
        HostAuditOutcome::Allowed,
    );
    sink.record(
        principal,
        HostAuditEvent::NetBind {
            addr: "127.0.0.1:0",
        },
        HostAuditOutcome::Allowed,
    );
    sink.record(
        principal,
        HostAuditEvent::NetAccept {
            local_addr: "127.0.0.1:8788",
            peer_addr: "127.0.0.1:49152",
        },
        HostAuditOutcome::Allowed,
    );
    sink.record(
        principal,
        HostAuditEvent::ProcessSpawn { command: "ls" },
        HostAuditOutcome::Denied("not in host_process allowlist"),
    );
}

/// Every event kind reaches the signed chain: the six gated calls as one
/// run whose tally keeps each class's first call, the denial as its own
/// entry after them, and the chain still verifies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn records_each_event_kind_onto_the_signed_chain() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    // Fixed, non-nil session id (nil is reserved for system/daemon
    // messages); deterministic so the test stays reproducible.
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0994));
    let sink =
        KernelAuditSink::with_policy(Arc::clone(&log), session.clone(), policy(60_000, 128, 4096));
    let p = principal();

    record_event_kinds(&sink, &p);
    sink.shutdown();

    let entries = log
        .get_principal_entries(&session, Some(&p))
        .await
        .expect("read principal entries");
    assert_eq!(entries.len(), 2, "one run and one denial: {entries:?}");
    for e in &entries {
        assert_eq!(e.principal.as_ref(), Some(&p), "principal must be stamped");
    }

    let run = run_summary(&entries[0]);
    assert_eq!(run.count, 6);
    assert!(
        matches!(&entries[0].outcome, AuditOutcome::Failure { error } if error == "1 of 6 host calls failed")
    );
    let classes: Vec<_> = run
        .tally
        .iter()
        .map(|tally| (tally.class.as_str(), tally.outcome, tally.count))
        .collect();
    assert_eq!(
        classes,
        [
            ("file_read", HostCallOutcome::Ok, 1),
            ("file_write", HostCallOutcome::Failed, 1),
            ("file_delete", HostCallOutcome::Ok, 1),
            ("net_connect", HostCallOutcome::Ok, 1),
            ("net_bind", HostCallOutcome::Ok, 1),
            ("net_accept", HostCallOutcome::Ok, 1),
        ]
    );
    assert!(matches!(
        &run.tally[1].first,
        AuditAction::FileWrite { path, content_hash }
            if path == "/w/w" && *content_hash == ContentHash::zero()
    ));
    assert_eq!(run.tally[1].first_detail.as_deref(), Some("disk full"));
    assert!(matches!(
        &run.tally[3].first,
        AuditAction::NetConnect { host, port } if host == "example.com" && *port == 443
    ));
    assert!(matches!(
        &run.tally[5].first,
        AuditAction::NetAccept { local_addr, peer_addr }
            if local_addr == "127.0.0.1:8788" && peer_addr == "127.0.0.1:49152"
    ));
    assert!(matches!(
        (&entries[1].action, &entries[1].authorization, &entries[1].outcome),
        (
            AuditAction::ProcessSpawn { command },
            AuthorizationProof::Denied { .. },
            AuditOutcome::Failure { .. }
        ) if command == "ls"
    ));

    let verification = log.verify_chain(&session).await.expect("verify chain");
    assert!(
        verification.valid,
        "chain must remain valid: {verification:?}"
    );
}

/// A multi-megabyte guest string is capped to [`MAX_AUDIT_STR_BYTES`] before
/// it is signed and persisted, and the stored form is still valid UTF-8.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_guest_strings_are_truncated_at_the_sink() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0995));
    let sink = test_sink(Arc::clone(&log), session.clone());
    let p = principal();

    // 4 MiB of a multi-byte code point: exercises both the size cap and the
    // char-boundary snap (the naive byte cut could land mid-'é').
    let huge = "é".repeat(4 * 1024 * 1024);
    assert!(huge.len() > MAX_AUDIT_STR_BYTES);

    sink.record(
        &p,
        HostAuditEvent::ProcessSpawn { command: &huge },
        // Even a denied call from a zero-capability capsule must not persist
        // the unbounded string — that is the amplification vector.
        HostAuditOutcome::Denied(&huge),
    );
    sink.record(
        &p,
        HostAuditEvent::FileRead { path: &huge },
        HostAuditOutcome::Allowed,
    );
    sink.shutdown();

    let entries = log
        .get_principal_entries(&session, Some(&p))
        .await
        .expect("read principal entries");
    assert_eq!(entries.len(), 2);

    for e in &entries {
        let stored = match &e.action {
            AuditAction::ProcessSpawn { command } => command,
            AuditAction::FileRead { path } => path,
            other => panic!("unexpected action: {other:?}"),
        };
        assert!(
            stored.len() <= MAX_AUDIT_STR_BYTES,
            "stored string must be capped: {} bytes",
            stored.len()
        );
        // `str` is UTF-8 by construction; assert the snap preserved whole
        // code points (no trailing partial 'é').
        assert!(
            stored.chars().all(|c| c == 'é'),
            "truncation must not split a multi-byte code point"
        );
    }
    assert!(
        matches!(&entries[0].authorization, AuthorizationProof::Denied { reason } if reason.len() <= MAX_AUDIT_STR_BYTES),
        "the denial reason is bounded too"
    );

    // Bounding the field must not break the signed chain.
    let verification = log.verify_chain(&session).await.expect("verify chain");
    assert!(
        verification.valid,
        "chain must remain valid: {verification:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_record_is_enqueue_only_and_shutdown_is_the_durable_barrier() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0997));
    let sink = test_sink(Arc::clone(&log), session.clone());
    let p = principal();
    let started = std::time::Instant::now();
    sink.record(
        &p,
        HostAuditEvent::FileRead { path: "/enqueue" },
        HostAuditOutcome::Allowed,
    );
    // This call must not wait for the writer's append/fync path. The
    // bounded queue records acceptance immediately; shutdown below is the
    // explicit point at which a caller asks for durable completion.
    assert!(started.elapsed() < std::time::Duration::from_millis(100));
    assert_eq!(sink.health().accepted, 1);
    sink.shutdown();
    let health = sink.health();
    assert_eq!(health.persisted, 1);
    assert_eq!(health.queue_depth, 0);
    assert_eq!(log.count_session(&session).await.unwrap_or_default(), 1);
}

/// The truncation helper snaps to a char boundary and is a no-op under the
/// cap.
#[test]
fn truncate_guest_str_snaps_to_char_boundary() {
    // Under the cap: identity.
    assert_eq!(truncate_guest_str("hello"), "hello");

    // 'é' is 2 bytes; a string that ends exactly one byte past the cap must
    // snap DOWN to the last whole code point, never mid-'é'.
    let s = "é".repeat(MAX_AUDIT_STR_BYTES); // 2 * cap bytes
    let out = truncate_guest_str(&s);
    assert!(out.len() <= MAX_AUDIT_STR_BYTES);
    assert!(out.is_char_boundary(out.len()));
    assert!(out.chars().all(|c| c == 'é'));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_writer_durably_acks_concurrent_reports() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0996));
    let sink = Arc::new(test_sink(Arc::clone(&log), session.clone()));
    let p = principal();
    let mut threads = Vec::new();
    for worker in 0..4 {
        let sink = Arc::clone(&sink);
        let p = p.clone();
        threads.push(std::thread::spawn(move || {
            for index in 0..64 {
                let path = format!("/bounded/{worker}/{index}");
                sink.record(
                    &p,
                    HostAuditEvent::FileRead { path: &path },
                    HostAuditOutcome::Allowed,
                );
            }
        }));
    }
    for thread in threads {
        thread.join().expect("reporting thread");
    }
    sink.shutdown();
    let health = sink.health();
    assert_eq!(health.accepted, 256);
    assert_eq!(health.failed, 0);
    assert_eq!(health.persisted, 256, "every call is counted by an entry");
    let entries = log.get_principal_entries(&session, Some(&p)).await.unwrap();
    let counted: u64 = entries
        .iter()
        .map(|entry| match &entry.action {
            AuditAction::HostCallRun { calls } => calls.count,
            _ => 1,
        })
        .sum();
    assert_eq!(counted, 256);
    assert_eq!(
        health.collapsed_repeats,
        256 - u64::try_from(entries.len()).unwrap()
    );
    assert!(log.verify_chain(&session).await.unwrap().valid);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identical_host_reads_collapse_to_one_signed_row() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0998));
    let sink =
        KernelAuditSink::with_policy(Arc::clone(&log), session.clone(), policy(60_000, 128, 4096));
    let p = principal();
    for _ in 0..32 {
        sink.record(
            &p,
            HostAuditEvent::FileRead { path: "/same" },
            HostAuditOutcome::Allowed,
        );
    }
    sink.shutdown();
    let entries = log
        .get_principal_entries(&session, Some(&p))
        .await
        .expect("read");
    assert_eq!(entries.len(), 1, "identical reads share one signed row");
    let run = run_summary(&entries[0]);
    assert_eq!(run.count, 32, "the count is signed evidence, not a drop");
    assert_eq!(sink.health().collapsed_repeats, 31);
    assert!(log.verify_chain(&session).await.unwrap().valid);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allowed_path_probes_are_omitted_denied_probes_persist() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0999));
    let sink = test_sink(Arc::clone(&log), session.clone());
    let p = principal();
    sink.record(
        &p,
        HostAuditEvent::FileProbe { path: "/w/stat" },
        HostAuditOutcome::Allowed,
    );
    sink.record(
        &p,
        HostAuditEvent::FileProbe {
            path: "/etc/shadow",
        },
        HostAuditOutcome::Denied("not in host_fs allowlist"),
    );
    sink.shutdown();
    let entries = log
        .get_principal_entries(&session, Some(&p))
        .await
        .expect("read");
    assert_eq!(entries.len(), 1, "only the denial is signed");
    assert_eq!(sink.health().omitted_path_probes, 1);
    assert!(matches!(
        (&entries[0].action, &entries[0].authorization),
        (
            AuditAction::FileRead { path },
            AuthorizationProof::Denied { .. }
        ) if path == "/etc/shadow"
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn collapse_keeps_principals_and_exact_denials() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09a2));
    let sink = test_sink(Arc::clone(&log), session.clone());
    let alice = PrincipalId::new("alice").expect("alice");
    let bob = PrincipalId::new("bob").expect("bob");
    sink.record(
        &alice,
        HostAuditEvent::FileRead { path: "/a" },
        HostAuditOutcome::Allowed,
    );
    sink.record(
        &bob,
        HostAuditEvent::FileRead { path: "/b" },
        HostAuditOutcome::Allowed,
    );
    sink.record(
        &alice,
        HostAuditEvent::FileProbe {
            path: "/etc/shadow",
        },
        HostAuditOutcome::Denied("not in host_fs allowlist"),
    );
    sink.record(
        &alice,
        HostAuditEvent::FileProbe {
            path: "/etc/passwd",
        },
        HostAuditOutcome::Denied("not in host_fs allowlist"),
    );
    sink.shutdown();
    let entries = log.get_session_entries(&session).await.expect("read");
    let principals: Vec<_> = entries
        .iter()
        .filter_map(|e| e.principal.as_ref().map(astrid_core::PrincipalId::as_str))
        .collect();
    assert!(principals.contains(&"alice"), "{principals:?}");
    assert!(principals.contains(&"bob"), "{principals:?}");
    let denied_paths: Vec<_> = entries
        .iter()
        .filter_map(|e| match (&e.action, &e.authorization) {
            (AuditAction::FileRead { path }, AuthorizationProof::Denied { .. }) => {
                Some(path.as_str())
            },
            _ => None,
        })
        .collect();
    assert_eq!(denied_paths, ["/etc/shadow", "/etc/passwd"]);
}

/// The coalesced entry commits to every call it counts: the fold, count and
/// time range recompute from the individual calls, and the tally keeps each
/// class's first call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn coalesced_run_is_lossless() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09a3));
    let sink =
        KernelAuditSink::with_policy(Arc::clone(&log), session.clone(), policy(60_000, 128, 4096));
    let p = principal();
    let base = chrono::Utc::now();
    let mut calls = Vec::new();
    for index in 0..40_i64 {
        let at = Timestamp::from_datetime(base + chrono::Duration::microseconds(index));
        let path = format!("/run/{index}");
        let (event, outcome, action, kind, detail) = if index % 5 == 4 {
            (
                HostAuditEvent::FileWrite { path: &path },
                HostAuditOutcome::Failed("disk full"),
                AuditAction::FileWrite {
                    path: path.clone(),
                    content_hash: ContentHash::zero(),
                },
                HostCallOutcome::Failed,
                "disk full",
            )
        } else {
            (
                HostAuditEvent::FileRead { path: &path },
                HostAuditOutcome::Allowed,
                AuditAction::FileRead { path: path.clone() },
                HostCallOutcome::Ok,
                "",
            )
        };
        sink.record_at(&p, event, outcome, at);
        calls.push((action, kind, detail, at));
    }
    sink.shutdown();

    let entries = log.get_principal_entries(&session, Some(&p)).await.unwrap();
    assert_eq!(entries.len(), 1);
    let run = run_summary(&entries[0]);
    let refs: Vec<_> = calls
        .iter()
        .map(|(action, outcome, detail, at)| HostCallRef {
            action,
            outcome: *outcome,
            detail,
            at,
        })
        .collect();
    assert!(run.matches_calls(&refs), "fold must commit to every call");
    assert!(!run.matches_calls(&refs[1..]), "a dropped call is detected");
    let mut swapped = refs.clone();
    swapped.swap(3, 4);
    assert!(!run.matches_calls(&swapped), "reordering is detected");
    assert_eq!(run.tally.len(), 2);
    assert_eq!(
        (run.tally[0].class.as_str(), run.tally[0].count),
        ("file_read", 32)
    );
    assert_eq!(
        (run.tally[1].class.as_str(), run.tally[1].count),
        ("file_write", 8)
    );
    assert!(matches!(&run.tally[1].first, AuditAction::FileWrite { path, .. } if path == "/run/4"));
    assert!(log.verify_chain(&session).await.unwrap().valid);
}

/// A full queue never drops a call silently: the overflow becomes one signed
/// loss entry at its place in the chain, counting and committing to every
/// lost call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queue_overflow_is_recorded_as_a_signed_loss_entry() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09a1));
    // A long window keeps the writer idle, so the queue fills
    // deterministically; capacity clamps to 64.
    let sink =
        KernelAuditSink::with_policy(Arc::clone(&log), session.clone(), policy(60_000, 128, 64));
    let p = principal();
    let base = chrono::Utc::now();
    let mut lost = Vec::new();
    for index in 0..80_i64 {
        let at = Timestamp::from_datetime(base + chrono::Duration::microseconds(index));
        let path = format!("/denied-{index}");
        sink.record_at(
            &p,
            HostAuditEvent::FileProbe { path: &path },
            HostAuditOutcome::Denied("not in host_fs allowlist"),
            at,
        );
        if index >= 64 {
            lost.push((AuditAction::FileRead { path }, at));
        }
    }
    let health = sink.health();
    assert_eq!(health.accepted, 80);
    assert_eq!(health.queue_full, 16);
    sink.shutdown();

    let entries = log.get_principal_entries(&session, Some(&p)).await.unwrap();
    assert_eq!(entries.len(), 65, "64 denials and one loss entry");
    for (index, entry) in entries[..64].iter().enumerate() {
        assert!(
            matches!(&entry.action, AuditAction::FileRead { path } if *path == format!("/denied-{index}")),
            "denials stay in call order: {:?}",
            entry.action
        );
    }
    let AuditAction::HostCallLoss { calls, reason } = &entries[64].action else {
        panic!("expected a loss entry, got {:?}", entries[64].action);
    };
    assert_eq!(reason, "queue_full");
    assert_eq!(calls.count, 16);
    assert_eq!(calls.tally[0].class, "file_read");
    assert_eq!(calls.tally[0].outcome, HostCallOutcome::Denied);
    let refs: Vec<_> = lost
        .iter()
        .map(|(action, at)| HostCallRef {
            action,
            outcome: HostCallOutcome::Denied,
            detail: "not in host_fs allowlist",
            at,
        })
        .collect();
    assert!(
        calls.matches_calls(&refs),
        "the loss entry commits to the lost calls"
    );
    let health = sink.health();
    assert_eq!(
        (health.persisted, health.lost, health.queue_depth),
        (64, 16, 0)
    );
    assert!(log.verify_chain(&session).await.unwrap().valid);
}

use std::sync::Arc;

use super::*;

use astrid_crypto::KeyPair;

fn principal() -> PrincipalId {
    PrincipalId::new("alice").expect("valid principal")
}

fn test_policy() -> HostAuditPolicy {
    HostAuditPolicy::from(&astrid_config::types::AuditConfig {
        host_coalesce_ms: 10,
        host_batch_max: 128,
        host_queue_capacity: 4096,
        host_path_probes: false,
        ..astrid_config::types::AuditConfig::default()
    })
}

fn test_sink(log: Arc<AuditLog>, session: SessionId) -> KernelAuditSink {
    KernelAuditSink::with_policy(log, session, test_policy())
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

/// Every event kind, including a denial, lands a principal-stamped,
/// correctly-mapped entry, and the resulting chain still verifies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn records_each_event_kind_onto_the_signed_chain() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    // Fixed, non-nil session id (nil is reserved for system/daemon
    // messages); deterministic so the test stays reproducible.
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0994));
    let sink = test_sink(Arc::clone(&log), session.clone());
    let p = principal();

    record_event_kinds(&sink, &p);
    sink.shutdown();

    let entries = log
        .get_principal_entries(&session, Some(&p))
        .await
        .expect("read principal entries");
    assert_eq!(entries.len(), 7, "all seven events must persist");

    // Every entry is stamped with the acting principal.
    for e in &entries {
        assert_eq!(e.principal.as_ref(), Some(&p), "principal must be stamped");
    }

    assert!(entries.iter().any(|e| matches!(
        (&e.action, &e.outcome),
        (AuditAction::FileRead { path }, AuditOutcome::Success { .. }) if path == "/w/r"
    )));
    assert!(entries.iter().any(|e| matches!(
        (&e.action, &e.outcome),
        (AuditAction::FileWrite { path, content_hash }, AuditOutcome::Failure { .. })
            if path == "/w/w" && *content_hash == ContentHash::zero()
    )));
    assert!(entries.iter().any(|e| matches!(
        &e.action,
        AuditAction::FileDelete { path } if path == "/w/d"
    )));
    assert!(entries.iter().any(|e| matches!(
        &e.action,
        AuditAction::NetConnect { host, port } if host == "example.com" && *port == 443
    )));
    assert!(entries.iter().any(|e| matches!(
        &e.action,
        AuditAction::NetBind { addr } if addr == "127.0.0.1:0"
    )));
    assert!(entries.iter().any(|e| matches!(
        &e.action,
        AuditAction::NetAccept {
            local_addr,
            peer_addr,
        } if local_addr == "127.0.0.1:8788" && peer_addr == "127.0.0.1:49152"
    )));
    assert!(entries.iter().any(|e| matches!(
        (&e.action, &e.authorization, &e.outcome),
        (
            AuditAction::ProcessSpawn { command },
            AuthorizationProof::Denied { .. },
            AuditOutcome::Failure { .. }
        ) if command == "ls"
    )));

    // The signed hash chain remains valid after the high-frequency
    // appends.
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
        HostAuditOutcome::Denied("not in host_process allowlist"),
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
    assert_eq!(sink.health().persisted, 1);
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
    // Distinct allowed FileRead paths collapse per writer window (may be
    // more than one window under concurrent producers).
    assert!(
        (1..=4).contains(&health.persisted),
        "persisted rows {} should be a handful of collapsed windows",
        health.persisted
    );
    assert_eq!(u64::try_from(log.count_session(&session).await.unwrap()).unwrap(), health.persisted);
    assert!(health.collapsed_repeats >= 250);
    assert!(log.verify_chain(&session).await.unwrap().valid);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identical_host_reads_collapse_to_one_signed_row() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0998));
    let sink = test_sink(Arc::clone(&log), session.clone());
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
    assert!(
        matches!(
            &entries[0].outcome,
            AuditOutcome::Success {
                details: Some(d)
            } if d.contains("repeats=32")
        ),
        "repeat count must be evidence, not a silent drop: {:?}",
        entries[0].outcome
    );
    assert!(sink.health().collapsed_repeats >= 31);
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

//! Host-call recording overhead, run on demand:
//!
//! ```text
//! cargo test -p astrid-kernel --lib audit_sink::tests::bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Uses only the sink's public surface, so the same file measures earlier
//! implementations too. The log is in memory: the numbers cover the host-call
//! path, signing and serialization, not volume I/O.

use std::sync::Arc;
use std::time::Instant;

use astrid_audit::AuditLog;
use astrid_capsule::{HostAuditEvent, HostAuditOutcome, HostAuditSink};
use astrid_config::types::AuditConfig;
use astrid_core::{PrincipalId, SessionId};
use astrid_crypto::KeyPair;

use super::super::{HostAuditPolicy, KernelAuditSink};

fn sink(log: &Arc<AuditLog>, session: &SessionId) -> KernelAuditSink {
    KernelAuditSink::with_policy(
        Arc::clone(log),
        session.clone(),
        HostAuditPolicy::from(&AuditConfig {
            host_coalesce_ms: 50,
            ..AuditConfig::default()
        }),
    )
}

/// Record `per_thread` calls from each of `threads` producers and report
/// the producer-side cost per call and the resulting entries.
async fn measure(
    name: &str,
    threads: usize,
    per_thread: usize,
    shared_principal: bool,
    call: fn(&KernelAuditSink, &PrincipalId, usize),
) {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::new_v4());
    let sink = Arc::new(sink(&log, &session));
    let started = Instant::now();
    let producers: Vec<_> = (0..threads)
        .map(|worker| {
            let sink = Arc::clone(&sink);
            let principal = if shared_principal {
                PrincipalId::new("bench").expect("principal")
            } else {
                PrincipalId::new(format!("bench-{worker}")).expect("principal")
            };
            std::thread::spawn(move || {
                let started = Instant::now();
                for index in 0..per_thread {
                    call(&sink, &principal, index);
                }
                started.elapsed()
            })
        })
        .collect();
    let busy: std::time::Duration = producers
        .into_iter()
        .map(|producer| producer.join().expect("producer"))
        .sum();
    let produced = started.elapsed();
    sink.shutdown();
    let drained = started.elapsed();
    let health = sink.health();
    let calls = u32::try_from(threads.saturating_mul(per_thread)).unwrap_or(u32::MAX);
    let entries = log.count_session(&session).await.expect("count");
    println!(
        "{name}: calls={calls} ns/call={} produce_ms={} drain_ms={} entries={entries} accepted={} persisted={} queue_full={}",
        busy.checked_div(calls).unwrap_or_default().as_nanos(),
        produced.as_millis(),
        drained.as_millis(),
        health.accepted,
        health.persisted,
        health.queue_full,
    );
}

fn mixed_allowed(sink: &KernelAuditSink, principal: &PrincipalId, index: usize) {
    let path = format!("/bench/{index}");
    let event = match index % 3 {
        0 => HostAuditEvent::FileRead { path: &path },
        1 => HostAuditEvent::FileWrite {
            content_hash: None,
            path: &path,
        },
        _ => HostAuditEvent::NetConnect {
            host: "example.com",
            port: 443,
        },
    };
    sink.record(principal, event, HostAuditOutcome::Allowed);
}

fn distinct_denials(sink: &KernelAuditSink, principal: &PrincipalId, index: usize) {
    let path = format!("/denied/{index}");
    sink.record(
        principal,
        HostAuditEvent::FileRead { path: &path },
        HostAuditOutcome::Denied("not in host_fs allowlist"),
    );
}

fn reads_with_occasional_denial(sink: &KernelAuditSink, principal: &PrincipalId, index: usize) {
    let path = format!("/mixed/{index}");
    let outcome = if index % 50 == 49 {
        HostAuditOutcome::Denied("not in host_fs allowlist")
    } else {
        HostAuditOutcome::Allowed
    };
    sink.record(principal, HostAuditEvent::FileRead { path: &path }, outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "throughput measurement; run with --ignored --nocapture"]
async fn host_audit_recording_overhead() {
    for round in 0..3 {
        println!("round {round}");
        measure("mixed_allowed_1x1", 1, 100_000, false, mixed_allowed).await;
        measure("mixed_allowed_8x8", 8, 25_000, false, mixed_allowed).await;
        measure("mixed_allowed_shared_8x1", 8, 25_000, true, mixed_allowed).await;
        measure(
            "reads_2pct_denials_4x4",
            4,
            25_000,
            false,
            reads_with_occasional_denial,
        )
        .await;
        measure("distinct_denials_1x1", 1, 20_000, false, distinct_denials).await;
    }
}

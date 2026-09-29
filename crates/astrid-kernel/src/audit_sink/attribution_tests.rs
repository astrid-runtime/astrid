//! Attribution of host-call entries to the capsule that acted, and content
//! hashes on file writes.

use std::sync::Arc;

use astrid_audit::{AuditAction, AuditLog, CapsuleActor};
use astrid_capsule::{HostAuditActor, HostAuditEvent, HostAuditOutcome, HostAuditSink};
use astrid_config::types::AuditConfig;
use astrid_core::{PrincipalId, SessionId};
use astrid_crypto::{ContentHash, KeyPair};

use super::{HostAuditPolicy, KernelAuditSink};

fn sink(log: &Arc<AuditLog>, session: &SessionId) -> KernelAuditSink {
    KernelAuditSink::with_policy(
        Arc::clone(log),
        session.clone(),
        HostAuditPolicy::from(&AuditConfig {
            host_coalesce_ms: 10,
            ..AuditConfig::default()
        }),
    )
}

fn host_actor(capsule_id: &str) -> HostAuditActor {
    HostAuditActor {
        capsule_id: capsule_id.to_owned(),
        wasm_hash: Some(ContentHash::hash(capsule_id.as_bytes())),
    }
}

fn actor_of(action: &AuditAction) -> Option<&CapsuleActor> {
    match action {
        AuditAction::FileRead { actor, .. } | AuditAction::FileWrite { actor, .. } => {
            actor.as_ref()
        },
        _ => None,
    }
}

/// A handle obtained through `attributed` stamps the capsule id and wasm hash
/// on its entries; the kernel's own handle stays unattributed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attributed_handle_stamps_capsule_identity() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0a01));
    let kernel_sink = sink(&log, &session);
    let fetcher = kernel_sink
        .attributed(host_actor("fetcher"))
        .expect("kernel sink supports attribution");
    let alice = PrincipalId::new("alice").expect("principal");

    fetcher.record(
        &alice,
        HostAuditEvent::FileRead { path: "/w/a" },
        HostAuditOutcome::Allowed,
    );
    kernel_sink.record(
        &alice,
        HostAuditEvent::FileRead { path: "/w/b" },
        HostAuditOutcome::Denied("not in host_fs allowlist"),
    );
    kernel_sink.shutdown();

    let entries = log.get_session_entries(&session).await.expect("entries");
    assert_eq!(entries.len(), 2);
    for entry in &entries {
        let AuditAction::FileRead { path, actor } = &entry.action else {
            panic!("unexpected action {:?}", entry.action);
        };
        if path == "/w/a" {
            assert_eq!(
                actor.as_ref(),
                Some(&CapsuleActor {
                    capsule_id: "fetcher".to_owned(),
                    wasm_hash: Some(ContentHash::hash(b"fetcher")),
                })
            );
        } else {
            assert!(actor.is_none(), "kernel handle must not attribute");
        }
    }
    assert!(log.verify_chain(&session).await.expect("verify").valid);
}

/// Alternating capsules close each other's runs: attribution and FIFO order
/// must both survive coalescing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn folding_never_merges_capsules() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0a02));
    let kernel_sink = sink(&log, &session);
    let one = kernel_sink.attributed(host_actor("one")).expect("attr");
    let two = kernel_sink.attributed(host_actor("two")).expect("attr");
    let alice = PrincipalId::new("alice").expect("principal");

    for path in ["/w/1", "/w/2"] {
        one.record(
            &alice,
            HostAuditEvent::FileRead { path },
            HostAuditOutcome::Allowed,
        );
        two.record(
            &alice,
            HostAuditEvent::FileRead { path },
            HostAuditOutcome::Allowed,
        );
    }
    kernel_sink.shutdown();

    let entries = log.get_session_entries(&session).await.expect("entries");
    let capsules: Vec<_> = entries
        .iter()
        .filter_map(|e| actor_of(&e.action).map(|a| a.capsule_id.clone()))
        .collect();
    assert_eq!(capsules, ["one", "two", "one", "two"]);
    assert!(log.verify_chain(&session).await.expect("verify").valid);
}

/// A write that carried content records the BLAKE3 of those bytes; a
/// directory creation keeps the zero hash.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_write_records_the_content_hash() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0a03));
    let kernel_sink = sink(&log, &session);
    let alice = PrincipalId::new("alice").expect("principal");
    let written = ContentHash::hash(b"hello");

    kernel_sink.record(
        &alice,
        HostAuditEvent::FileWrite {
            path: "/w/file",
            content_hash: Some(written),
        },
        HostAuditOutcome::Allowed,
    );
    kernel_sink.record(
        &alice,
        HostAuditEvent::FileWrite {
            path: "/w/dir",
            content_hash: None,
        },
        HostAuditOutcome::Denied("not in host_fs allowlist"),
    );
    kernel_sink.shutdown();

    let entries = log.get_session_entries(&session).await.expect("entries");
    let hash_for = |wanted: &str| {
        entries.iter().find_map(|e| match &e.action {
            AuditAction::FileWrite {
                path, content_hash, ..
            } if path == wanted => Some(*content_hash),
            _ => None,
        })
    };
    assert_eq!(hash_for("/w/file"), Some(written));
    assert_eq!(hash_for("/w/dir"), Some(ContentHash::zero()));
}

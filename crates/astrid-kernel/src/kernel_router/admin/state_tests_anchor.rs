//! `audit.anchor_mark` and `audit.anchor_status`, the prune refusal they
//! drive, and the receipt history in `audit.export`.

use std::sync::Arc;

use astrid_audit::{AuditAction, AuditOutcome, AuditRetentionPolicy, AuthorizationProof};
use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_crypto::ContentHash;
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use astrid_events::kernel_api::{
    AdminKernelRequest, AdminRequestKind, AdminResponseBody, AuditAnchorEvidence,
    AuditAnchorMarkChain, AuditAnchorMarkRequest, AuditAnchorMarkResult, AuditAnchorMarkStatus,
    AuditAnchorStatusReport, AuditExportRequest,
};
use tempfile::TempDir;

use super::handlers;
use crate::Kernel;

async fn fixture() -> (TempDir, Arc<Kernel>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(dir.path())).await;
    (dir, kernel)
}

fn pid(name: &str) -> PrincipalId {
    PrincipalId::new(name).unwrap()
}

/// Append `count` entries to a principal chain, in batches of up to 128 so
/// a sealed 1,024-entry segment takes a few commits.
async fn append(kernel: &Kernel, principal: &str, count: usize) {
    let entries: Vec<_> = (0..count)
        .map(|index| {
            (
                kernel.session_id.clone(),
                pid(principal),
                AuditAction::McpToolCall {
                    server: "anchor-test".to_owned(),
                    tool: format!("tool_{index}"),
                    args_hash: ContentHash::zero(),
                },
                AuthorizationProof::NotRequired {
                    reason: "test".to_owned(),
                },
                AuditOutcome::success(),
            )
        })
        .collect();
    for batch in entries.chunks(128) {
        for result in kernel
            .audit_log
            .append_batch_with_principal(batch.to_vec())
            .await
        {
            result.expect("append audit entry");
        }
    }
}

/// Content hash of the entry at retained index `index` of a principal chain.
async fn hash_at(kernel: &Kernel, principal: &str, index: usize) -> String {
    kernel
        .audit_log
        .chain_entries_page(&kernel.session_id, Some(&pid(principal)), None, 10_000)
        .await
        .unwrap()[index]
        .1
        .content_hash()
        .to_hex()
}

fn evidence() -> AuditAnchorEvidence {
    AuditAnchorEvidence {
        network: "unicity:test".to_owned(),
        checkpoint_digest_hex: "ab".repeat(32),
        link_position: 3,
        certifying_round: Some(77),
        seal_digest_hex: Some("cd".repeat(32)),
    }
}

fn chain(kernel: &Kernel, principal: &str, position: u64, hash: String) -> AuditAnchorMarkChain {
    AuditAnchorMarkChain {
        session: kernel.session_id.clone(),
        principal: Some(pid(principal)),
        position,
        head_hash_hex: hash,
    }
}

async fn dispatch(kernel: &Arc<Kernel>, request: AdminRequestKind) -> AdminResponseBody {
    handlers::dispatch(kernel, &PrincipalId::default(), request).await
}

async fn mark(kernel: &Arc<Kernel>, chains: Vec<AuditAnchorMarkChain>) -> AuditAnchorMarkResult {
    let request = AdminRequestKind::AuditAnchorMark(AuditAnchorMarkRequest {
        evidence: evidence(),
        chains,
    });
    match dispatch(kernel, request).await {
        AdminResponseBody::AuditAnchorMarked(result) => *result,
        other => panic!("expected AuditAnchorMarked, got {other:?}"),
    }
}

async fn status(kernel: &Arc<Kernel>) -> AuditAnchorStatusReport {
    match dispatch(kernel, AdminRequestKind::AuditAnchorStatus).await {
        AdminResponseBody::AuditAnchorStatus(report) => *report,
        other => panic!("expected AuditAnchorStatus, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn anchor_mark_records_each_chain_independently() {
    let (_dir, kernel) = fixture().await;
    append(&kernel, "alice", 4).await;
    append(&kernel, "bob", 3).await;
    let alice_head = hash_at(&kernel, "alice", 3).await;
    let bob_second = hash_at(&kernel, "bob", 1).await;

    let result = mark(
        &kernel,
        vec![
            chain(&kernel, "alice", 4, alice_head.clone()),
            chain(&kernel, "bob", 3, bob_second),
        ],
    )
    .await;
    assert_eq!(result.chains.len(), 2);
    assert_eq!(result.chains[0].status, AuditAnchorMarkStatus::Advanced);
    assert_eq!(result.chains[0].anchored_position, 4);
    assert_eq!(result.chains[1].status, AuditAnchorMarkStatus::Rejected);
    assert_eq!(result.chains[1].anchored_position, 0);
    let error = result.chains[1].error.as_deref().unwrap();
    assert!(
        error.contains("does not match the entry at position 2"),
        "{error}"
    );

    let again = mark(
        &kernel,
        vec![chain(&kernel, "alice", 4, alice_head.clone())],
    )
    .await;
    assert_eq!(again.chains[0].status, AuditAnchorMarkStatus::Unchanged);
    let lower = mark(&kernel, vec![chain(&kernel, "alice", 2, alice_head)]).await;
    assert_eq!(lower.chains[0].status, AuditAnchorMarkStatus::Rejected);
    assert_eq!(lower.chains[0].anchored_position, 4);

    let report = status(&kernel).await;
    assert!(!report.require_anchor_before_prune);
    assert!(report.retention_hold.is_none());
    let alice = report
        .chains
        .iter()
        .find(|chain| chain.principal == Some(pid("alice")))
        .unwrap();
    assert_eq!((alice.anchored_position, alice.lag()), (Some(4), Some(0)));
    assert_eq!(alice.evidence.as_ref().unwrap()["certifying_round"], 77);
    assert!(alice.anchored_at.is_some());
    let bob = report
        .chains
        .iter()
        .find(|chain| chain.principal == Some(pid("bob")))
        .unwrap();
    assert_eq!((bob.anchored_position, bob.lag()), (None, Some(3)));
}

#[tokio::test(flavor = "multi_thread")]
async fn anchor_mark_rejects_malformed_requests_whole() {
    let (_dir, kernel) = fixture().await;
    append(&kernel, "alice", 2).await;
    let head = hash_at(&kernel, "alice", 1).await;
    let requests = [
        (
            AuditAnchorMarkRequest {
                evidence: AuditAnchorEvidence {
                    checkpoint_digest_hex: "not hex".to_owned(),
                    ..evidence()
                },
                chains: vec![chain(&kernel, "alice", 2, head.clone())],
            },
            "checkpoint_digest_hex",
        ),
        (
            AuditAnchorMarkRequest {
                evidence: evidence(),
                chains: Vec::new(),
            },
            "no chains",
        ),
        (
            AuditAnchorMarkRequest {
                evidence: evidence(),
                chains: vec![
                    chain(&kernel, "alice", 2, head.clone()),
                    chain(&kernel, "alice", 2, head.clone()),
                ],
            },
            "more than once",
        ),
    ];
    for (request, needle) in requests {
        match dispatch(&kernel, AdminRequestKind::AuditAnchorMark(request)).await {
            AdminResponseBody::Error(error) => assert!(error.contains(needle), "{error}"),
            other => panic!("expected an error containing {needle:?}, got {other:?}"),
        }
    }
    let bad_hash = mark(&kernel, vec![chain(&kernel, "alice", 2, "zz".to_owned())]).await;
    assert!(
        bad_hash.chains[0]
            .error
            .as_deref()
            .unwrap()
            .contains("32 bytes of hex")
    );
    assert!(
        kernel
            .audit_log
            .anchor_watermark(&kernel.session_id, Some(&pid("alice")))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_prune_is_refused_past_the_watermark() {
    let (_dir, kernel) = fixture().await;
    kernel.audit_log.set_require_anchor_before_prune(true);
    append(&kernel, "carol", 1_030).await;
    let prune = || AdminRequestKind::AuditPrune {
        retain_entries: 1,
        retain_bytes: None,
    };
    match dispatch(&kernel, prune()).await {
        AdminResponseBody::Error(error) => {
            assert!(error.starts_with("audit prune refused: "), "{error}");
            assert!(error.contains("no anchored watermark"), "{error}");
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(status(&kernel).await.require_anchor_before_prune);

    // A watermark inside the sealed segment still refuses it, and says how
    // far the chain is anchored. (Deleting a whole segment is covered in
    // the audit crate; the kernel test store is slow to delete that many.)
    let middle = hash_at(&kernel, "carol", 511).await;
    mark(&kernel, vec![chain(&kernel, "carol", 512, middle)]).await;
    match dispatch(&kernel, prune()).await {
        AdminResponseBody::Error(error) => assert!(
            error.contains(
                "anchored through its first 512 entries, but the prune would remove its first 1024"
            ),
            "{error}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
    let stats = kernel
        .audit_log
        .chain_stats(&kernel.session_id, Some(&pid("carol")))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stats.count, 1_030);
}

#[tokio::test(flavor = "multi_thread")]
async fn export_pages_carry_the_receipt_history_on_request() {
    let (_dir, kernel) = fixture().await;
    append(&kernel, "dave", 12).await;
    for keep in [9, 6, 3] {
        kernel
            .audit_log
            .prune_chain(
                &kernel.session_id,
                Some(&pid("dave")),
                AuditRetentionPolicy {
                    retain_entries: keep,
                    retain_bytes: None,
                },
            )
            .await
            .unwrap();
    }
    let export = |receipts_from| {
        AdminRequestKind::AuditExport(AuditExportRequest {
            session: kernel.session_id.clone(),
            principal: Some(pid("dave")),
            from: 0,
            cursor: None,
            limit: None,
            receipts_from,
        })
    };
    let AdminResponseBody::AuditExport(plain) = dispatch(&kernel, export(None)).await else {
        panic!("expected AuditExport");
    };
    assert!(plain.prune_receipts.is_empty());
    assert_eq!(plain.prune_receipt.as_ref().unwrap()["generation"], 2);

    let AdminResponseBody::AuditExport(page) = dispatch(&kernel, export(Some(1))).await else {
        panic!("expected AuditExport");
    };
    let generations: Vec<_> = page
        .prune_receipts
        .iter()
        .map(|receipt| receipt.generation)
        .collect();
    assert_eq!(generations, vec![1, 2]);
    assert!(page.next_receipts_from.is_none());
    let latest = page.prune_receipts.last().unwrap();
    assert_eq!(
        Some(&latest.receipt_hash_hex),
        page.prune_receipt_hash_hex.as_ref()
    );
    assert_eq!(
        page.prune_receipts[1].receipt["prior_receipt_hash"],
        page.prune_receipts[0].receipt_hash_hex
    );
    let signing_data = hex::decode(&latest.signing_data_hex).unwrap();
    let receipt: astrid_audit::AuditPruneReceipt =
        serde_json::from_value(latest.receipt.clone()).unwrap();
    receipt
        .signature
        .verify(&signing_data, receipt.public_key.as_bytes())
        .unwrap();
}

async fn send_admin(
    kernel: &Arc<Kernel>,
    caller: &PrincipalId,
    suffix: &str,
    kind: AdminRequestKind,
) -> serde_json::Value {
    let response_topic = Topic::admin_response(suffix);
    let mut rx = kernel.event_bus.subscribe_topic(response_topic.as_str());
    let payload = serde_json::to_value(AdminKernelRequest::from(kind)).unwrap();
    let mut message = IpcMessage::new(
        Topic::admin_request(suffix),
        IpcPayload::RawJson(payload),
        kernel.session_id.0,
    );
    message.principal = Some(caller.to_string());
    let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("test"),
        message,
    });
    astrid_runtime::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let event = rx.recv().await.expect("admin response");
            if let astrid_events::AstridEvent::Ipc { message, .. } = &*event
                && let IpcPayload::RawJson(value) = &message.payload
            {
                return value.clone();
            }
        }
    })
    .await
    .expect("admin response within 30s")
}

/// Outcomes of the `admin.audit.anchor_mark` rows `principal` produced.
async fn mark_rows(kernel: &Kernel, principal: &PrincipalId) -> Vec<bool> {
    kernel
        .audit_log
        .get_session_entries(&kernel.session_id)
        .await
        .unwrap()
        .into_iter()
        .filter(|entry| entry.principal.as_ref() == Some(principal))
        .filter_map(|entry| match entry.action {
            AuditAction::AdminRequest { method, .. } if method == "admin.audit.anchor_mark" => {
                Some(matches!(entry.outcome, AuditOutcome::Success { .. }))
            },
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn anchor_marks_skip_the_success_row_but_rejections_and_denials_are_recorded() {
    let (_dir, kernel) = fixture().await;
    let admin = PrincipalId::default();
    let restricted = pid("restricted");
    for (principal, group) in [(&admin, "admin"), (&restricted, "restricted")] {
        let profile = PrincipalProfile {
            groups: vec![group.to_owned()],
            ..Default::default()
        };
        profile
            .save_to_path(&PrincipalProfile::path_for(&kernel.astrid_home, principal))
            .unwrap();
        kernel.profile_cache.invalidate(principal);
    }
    append(&kernel, "erin", 2).await;
    let head = hash_at(&kernel, "erin", 1).await;
    let request = |position, hash: &str| {
        AdminRequestKind::AuditAnchorMark(AuditAnchorMarkRequest {
            evidence: evidence(),
            chains: vec![chain(&kernel, "erin", position, hash.to_owned())],
        })
    };

    for _ in 0..3 {
        let marked = send_admin(&kernel, &admin, "audit.anchor_mark", request(2, &head)).await;
        assert_eq!(marked["status"], "AuditAnchorMarked", "{marked}");
    }
    assert!(mark_rows(&kernel, &admin).await.is_empty());

    let rejected = send_admin(
        &kernel,
        &admin,
        "audit.anchor_mark",
        request(2, &"00".repeat(32)),
    )
    .await;
    assert_eq!(rejected["status"], "AuditAnchorMarked", "{rejected}");
    assert_eq!(mark_rows(&kernel, &admin).await, vec![false]);

    let denied = send_admin(&kernel, &restricted, "audit.anchor_mark", request(2, &head)).await;
    assert_eq!(denied["status"], "Error", "{denied}");
    assert_eq!(mark_rows(&kernel, &restricted).await, vec![false]);
}

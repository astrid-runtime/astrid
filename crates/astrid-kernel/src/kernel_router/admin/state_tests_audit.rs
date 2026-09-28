//! `audit.heads` and `audit.export`: the runtime-key-signed head snapshot,
//! the paged raw export, and their exemption from the generic success row.

use std::sync::Arc;

use astrid_audit::{
    AuditAction, AuditOutcome, AuditPruneReceipt, AuditRetentionPolicy, AuthorizationProof,
};
use astrid_core::SessionId;
use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_crypto::{ContentHash, PublicKey, Signature};
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use astrid_events::kernel_api::{
    AUDIT_HEADS_DOMAIN_V1, AdminKernelRequest, AdminRequestKind, AdminResponseBody,
    AuditExportEntry, AuditExportPage, AuditExportRequest, AuditHeadsSnapshot,
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

async fn append(kernel: &Kernel, session: &SessionId, principal: Option<&str>, count: usize) {
    for index in 0..count {
        let action = AuditAction::McpToolCall {
            server: "anchor-test".to_owned(),
            tool: format!("tool_{index}"),
            args_hash: ContentHash::zero(),
        };
        let proof = AuthorizationProof::NotRequired {
            reason: "test".to_owned(),
        };
        let appended = match principal {
            Some(alias) => {
                kernel
                    .audit_log
                    .append_with_principal(
                        session.clone(),
                        pid(alias),
                        action,
                        proof,
                        AuditOutcome::success(),
                    )
                    .await
            },
            None => {
                kernel
                    .audit_log
                    .append(session.clone(), action, proof, AuditOutcome::success())
                    .await
            },
        };
        appended.expect("append audit entry");
    }
}

async fn prune(kernel: &Kernel, session: &SessionId, principal: &str, retain_entries: usize) {
    kernel
        .audit_log
        .prune_chain(
            session,
            Some(&pid(principal)),
            AuditRetentionPolicy {
                retain_entries,
                retain_bytes: None,
            },
        )
        .await
        .expect("prune audit chain");
}

async fn heads(kernel: &Arc<Kernel>) -> AuditHeadsSnapshot {
    match handlers::dispatch(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::AuditHeads,
    )
    .await
    {
        AdminResponseBody::AuditHeads(snapshot) => *snapshot,
        other => panic!("expected AuditHeads, got {other:?}"),
    }
}

async fn export(kernel: &Arc<Kernel>, request: AuditExportRequest) -> AdminResponseBody {
    handlers::dispatch(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::AuditExport(request),
    )
    .await
}

async fn export_page(kernel: &Arc<Kernel>, request: AuditExportRequest) -> AuditExportPage {
    match export(kernel, request).await {
        AdminResponseBody::AuditExport(page) => *page,
        other => panic!("expected AuditExport, got {other:?}"),
    }
}

fn request(session: &SessionId, principal: &str) -> AuditExportRequest {
    AuditExportRequest {
        session: session.clone(),
        principal: Some(pid(principal)),
        from: 0,
        cursor: None,
        limit: None,
    }
}

fn verify_ed25519(public_key_hex: &str, signature_hex: &str, message: &[u8]) -> bool {
    let public_key = PublicKey::from_hex(public_key_hex).unwrap();
    Signature::from_hex(signature_hex)
        .unwrap()
        .verify(message, public_key.as_bytes())
        .is_ok()
}

/// Check the external-verifier contract of one exported entry: the content
/// hash is `BLAKE3(signing_data)` and the signature covers `signing_data`.
fn assert_entry_verifies(entry: &AuditExportEntry) {
    let signing_data = hex::decode(&entry.signing_data_hex).unwrap();
    assert_eq!(
        ContentHash::hash(&signing_data).to_hex(),
        entry.content_hash_hex
    );
    assert!(verify_ed25519(
        &entry.public_key_hex,
        &entry.signature_hex,
        &signing_data
    ));
    assert_eq!(entry.entry["id"], entry.id);
    assert_eq!(entry.entry["previous_hash"], entry.previous_hash_hex);
}

#[tokio::test(flavor = "multi_thread")]
async fn heads_lists_every_chain_and_signs_the_encoding() {
    let (_dir, kernel) = fixture().await;
    let other = SessionId::new();
    append(&kernel, &kernel.session_id, None, 2).await;
    append(&kernel, &kernel.session_id, Some("alice"), 3).await;
    append(&kernel, &kernel.session_id, Some("bob"), 1).await;
    append(&kernel, &other, Some("carol"), 2).await;

    let snapshot = heads(&kernel).await;
    for (session, principal, count) in [
        (&kernel.session_id, Some("alice"), 3),
        (&kernel.session_id, Some("bob"), 1),
        (&other, Some("carol"), 2),
    ] {
        let chain = snapshot
            .chains
            .iter()
            .find(|chain| {
                chain.session == session.0.to_string()
                    && chain.principal.as_ref().map(PrincipalId::as_str) == principal
            })
            .expect("chain listed");
        assert_eq!(chain.count, count);
    }
    assert!(
        snapshot
            .chains
            .iter()
            .any(|chain| chain.principal.is_none())
    );
    for chain in &snapshot.chains {
        let session = SessionId::from_uuid(chain.session.parse().unwrap());
        let stats = kernel
            .audit_log
            .chain_stats(&session, chain.principal.as_ref())
            .await
            .unwrap()
            .expect("chain metadata");
        assert_eq!(chain.count, stats.count);
        assert_eq!(chain.head_hash_hex, stats.head_hash.to_hex());
        assert_eq!(chain.head_id, stats.head.map(|id| id.0.to_string()));
        assert_eq!(chain.omitted_total, 0);
    }

    let signed = hex::decode(&snapshot.signed_bytes_hex).unwrap();
    assert_eq!(signed, snapshot.signed_bytes_v1().unwrap());
    let domain = AUDIT_HEADS_DOMAIN_V1.as_bytes();
    assert_eq!(
        signed[..4],
        u32::try_from(domain.len()).unwrap().to_be_bytes()
    );
    assert_eq!(&signed[4..4 + domain.len()], domain);
    assert_eq!(
        snapshot.runtime_public_key_hex,
        kernel.runtime_key.export_public_key().to_hex()
    );
    assert!(verify_ed25519(
        &snapshot.runtime_public_key_hex,
        &snapshot.signature_hex,
        &signed
    ));
    let mut tampered = signed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(!verify_ed25519(
        &snapshot.runtime_public_key_hex,
        &snapshot.signature_hex,
        &tampered
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn export_pages_resume_and_entries_chain_and_verify() {
    let (_dir, kernel) = fixture().await;
    let session = kernel.session_id.clone();
    append(&kernel, &session, Some("alice"), 4).await;
    append(&kernel, &session, Some("bob"), 2).await;
    append(&kernel, &session, Some("alice"), 3).await;

    let mut entries = Vec::new();
    let mut cursor = None;
    loop {
        let page = export_page(
            &kernel,
            AuditExportRequest {
                cursor: cursor.clone(),
                limit: Some(3),
                ..request(&session, "alice")
            },
        )
        .await;
        assert_eq!(page.from, u64::try_from(entries.len()).unwrap());
        assert_eq!(page.chain_count, 7);
        assert!(page.prune_receipt.is_none());
        cursor.clone_from(&page.next_cursor);
        let complete = page.complete;
        entries.extend(page.entries);
        assert_eq!(page.next_index, u64::try_from(entries.len()).unwrap());
        if complete {
            break;
        }
    }
    assert_eq!(entries.len(), 7);
    assert_eq!(entries[0].previous_hash_hex, ContentHash::zero().to_hex());
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.index, u64::try_from(index).unwrap());
        assert_eq!(entry.entry["principal"], "alice");
        assert_entry_verifies(entry);
    }
    for pair in entries.windows(2) {
        assert_eq!(pair[1].previous_hash_hex, pair[0].content_hash_hex);
    }
    let snapshot = heads(&kernel).await;
    let alice = snapshot
        .chains
        .iter()
        .find(|chain| chain.principal == Some(pid("alice")))
        .unwrap();
    assert_eq!(
        alice.head_hash_hex,
        entries.last().unwrap().content_hash_hex
    );

    let middle = export_page(
        &kernel,
        AuditExportRequest {
            from: 2,
            limit: Some(2),
            ..request(&session, "alice")
        },
    )
    .await;
    let ids: Vec<_> = middle.entries.iter().map(|entry| &entry.id).collect();
    assert_eq!(ids, vec![&entries[2].id, &entries[3].id]);
    assert_eq!((middle.from, middle.next_index), (2, 4));

    append(&kernel, &session, Some("alice"), 1).await;
    let tail = export_page(
        &kernel,
        AuditExportRequest {
            cursor,
            ..request(&session, "alice")
        },
    )
    .await;
    assert_eq!(tail.entries.len(), 1);
    assert_eq!(tail.entries[0].index, 7);
    assert_eq!(
        tail.entries[0].previous_hash_hex,
        entries.last().unwrap().content_hash_hex
    );
    assert!(tail.complete);
}

#[tokio::test(flavor = "multi_thread")]
async fn export_rejects_unknown_chains_and_foreign_cursors() {
    let (_dir, kernel) = fixture().await;
    let session = kernel.session_id.clone();
    append(&kernel, &session, Some("alice"), 2).await;
    append(&kernel, &session, Some("bob"), 1).await;
    let missing = export(&kernel, request(&session, "nobody")).await;
    assert!(matches!(missing, AdminResponseBody::Error(ref error) if error.contains("not found")));

    let bob_cursor = export_page(&kernel, request(&session, "bob"))
        .await
        .next_cursor
        .unwrap();
    let alice_cursor = export_page(&kernel, request(&session, "alice"))
        .await
        .next_cursor
        .unwrap();
    let (_, alice_key) = alice_cursor.split_once(':').unwrap();
    let beyond_count = format!("3:{alice_key}");
    // Keep the entry id but move the sequence past the rest of the chain.
    let (prefix, entry_id) = alice_key.rsplit_once(':').unwrap();
    let (session_key, sequence) = prefix.rsplit_once(':').unwrap();
    let forged_sequence = format!(
        "2:{session_key}:{:020}:{entry_id}",
        sequence.parse::<u64>().unwrap() + 100
    );
    for cursor in [
        "garbage",
        "1:00000000-0000-0000-0000-00000000abcd:x",
        bob_cursor.as_str(),
        beyond_count.as_str(),
        forged_sequence.as_str(),
    ] {
        let response = export(
            &kernel,
            AuditExportRequest {
                cursor: Some(cursor.to_owned()),
                ..request(&session, "alice")
            },
        )
        .await;
        assert!(
            matches!(response, AdminResponseBody::Error(_)),
            "{cursor}: {response:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn export_after_prune_links_first_retained_entry_to_the_receipt() {
    let (_dir, kernel) = fixture().await;
    let session = kernel.session_id.clone();
    append(&kernel, &session, Some("dave"), 6).await;
    prune(&kernel, &session, "dave", 2).await;

    let page = export_page(&kernel, request(&session, "dave")).await;
    assert_eq!(page.entries.len(), 2);
    let receipt: AuditPruneReceipt =
        serde_json::from_value(page.prune_receipt.clone().unwrap()).unwrap();
    assert_eq!(
        page.entries[0].previous_hash_hex,
        receipt.omitted_terminal_hash
    );
    let signing_data = hex::decode(page.prune_receipt_signing_data_hex.unwrap()).unwrap();
    receipt
        .signature
        .verify(&signing_data, receipt.public_key.as_bytes())
        .unwrap();
    let stored = serde_json::to_vec(&receipt).unwrap();
    assert_eq!(
        page.prune_receipt_hash_hex.unwrap(),
        ContentHash::hash(&stored).to_hex()
    );

    let snapshot = heads(&kernel).await;
    let dave = snapshot
        .chains
        .iter()
        .find(|chain| chain.principal == Some(pid("dave")))
        .unwrap();
    assert_eq!((dave.count, dave.omitted_total), (2, 4));
    assert_eq!(dave.prune.as_ref().unwrap().generation, 0);
}

/// The signed v1 block of one principal chain: `lp(session) || 1 ||
/// lp(principal) || count || omitted_total || head_hash`.
fn signed_chain_block(
    session: &SessionId,
    principal: &str,
    count: u64,
    omitted_total: u64,
    head_hash_hex: &str,
) -> Vec<u8> {
    let session = session.0.to_string();
    let mut block = Vec::new();
    block.extend_from_slice(&u32::try_from(session.len()).unwrap().to_be_bytes());
    block.extend_from_slice(session.as_bytes());
    block.push(1);
    block.extend_from_slice(&u32::try_from(principal.len()).unwrap().to_be_bytes());
    block.extend_from_slice(principal.as_bytes());
    block.extend_from_slice(&count.to_be_bytes());
    block.extend_from_slice(&omitted_total.to_be_bytes());
    block.extend_from_slice(&hex::decode(head_hash_hex).unwrap());
    block
}

#[tokio::test(flavor = "multi_thread")]
async fn heads_sign_the_omitted_total_accumulated_across_prunes() {
    let (_dir, kernel) = fixture().await;
    let session = kernel.session_id.clone();
    append(&kernel, &session, Some("erin"), 9).await;
    prune(&kernel, &session, "erin", 6).await;
    prune(&kernel, &session, "erin", 4).await;
    append(&kernel, &session, Some("erin"), 2).await;
    prune(&kernel, &session, "erin", 1).await;

    let snapshot = heads(&kernel).await;
    let erin = snapshot
        .chains
        .iter()
        .find(|chain| chain.principal == Some(pid("erin")))
        .unwrap();
    assert_eq!((erin.count, erin.omitted_total), (1, 10));
    assert_eq!(erin.prune.as_ref().unwrap().generation, 2);
    let signed = hex::decode(&snapshot.signed_bytes_hex).unwrap();
    assert!(verify_ed25519(
        &snapshot.runtime_public_key_hex,
        &snapshot.signature_hex,
        &signed
    ));
    let block = signed_chain_block(&session, "erin", 1, 10, &erin.head_hash_hex);
    assert!(signed.windows(block.len()).any(|window| window == block));
}

#[tokio::test(flavor = "multi_thread")]
async fn export_pages_span_several_storage_batches() {
    let (_dir, kernel) = fixture().await;
    let session = kernel.session_id.clone();
    append(&kernel, &session, Some("grace"), 70).await;

    let whole = export_page(&kernel, request(&session, "grace")).await;
    assert_eq!((whole.entries.len(), whole.complete), (70, true));
    for pair in whole.entries.windows(2) {
        assert_eq!(pair[1].previous_hash_hex, pair[0].content_hash_hex);
    }
    for (limit, expected, complete) in [(64, 64, false), (70, 70, true)] {
        let page = export_page(
            &kernel,
            AuditExportRequest {
                limit: Some(limit),
                ..request(&session, "grace")
            },
        )
        .await;
        assert_eq!(page.entries.len(), expected, "limit {limit}");
        assert_eq!(page.complete, complete, "limit {limit}");
    }
    let first = export_page(
        &kernel,
        AuditExportRequest {
            limit: Some(64),
            ..request(&session, "grace")
        },
    )
    .await;
    let rest = export_page(
        &kernel,
        AuditExportRequest {
            cursor: first.next_cursor,
            ..request(&session, "grace")
        },
    )
    .await;
    assert_eq!(
        (rest.from, rest.entries.len(), rest.complete),
        (64, 6, true)
    );
    assert_eq!(rest.entries[0].id, whole.entries[64].id);
}

/// Append an entry whose action carries `padding` bytes of parameters.
async fn append_padded(kernel: &Kernel, session: &SessionId, principal: &str, padding: usize) {
    kernel
        .audit_log
        .append_with_principal(
            session.clone(),
            pid(principal),
            AuditAction::AdminRequest {
                method: "admin.test.padded".to_owned(),
                required_capability: "test:padded".to_owned(),
                target_principal: None,
                params: Some(serde_json::json!({ "padding": "x".repeat(padding) })),
                device_key_id: None,
            },
            AuthorizationProof::System {
                reason: "test".to_owned(),
            },
            AuditOutcome::success(),
        )
        .await
        .expect("append padded audit entry");
}

#[tokio::test(flavor = "multi_thread")]
async fn export_returns_a_large_entry_alone_and_rejects_one_above_the_limit() {
    let (_dir, kernel) = fixture().await;
    let session = kernel.session_id.clone();
    append(&kernel, &session, Some("frank"), 1).await;
    // The action is serialized into the entry and, hex-encoded, into its
    // signing data, so these export as roughly 1.1 MiB and 1.6 MiB: above
    // the 1 MiB page budget, and above the 1.5 MiB single-entry limit.
    append_padded(&kernel, &session, "frank", 370 * 1024).await;
    append(&kernel, &session, Some("frank"), 1).await;
    append_padded(&kernel, &session, "frank", 540 * 1024).await;

    let mut cursor = None;
    for (index, oversized) in [(0, false), (1, true), (2, false)] {
        let page = export_page(
            &kernel,
            AuditExportRequest {
                cursor: cursor.clone(),
                ..request(&session, "frank")
            },
        )
        .await;
        assert_eq!(page.entries.len(), 1, "page at {index}");
        assert_eq!(page.entries[0].index, index);
        assert!(!page.complete);
        let size = serde_json::to_vec(&page.entries[0]).unwrap().len();
        assert_eq!(
            size > 1024 * 1024,
            oversized,
            "entry {index} is {size} bytes"
        );
        cursor = page.next_cursor;
    }
    let rejected = export(
        &kernel,
        AuditExportRequest {
            cursor,
            ..request(&session, "frank")
        },
    )
    .await;
    assert!(
        matches!(rejected, AdminResponseBody::Error(ref error) if error.contains("at index 3")),
        "{rejected:?}"
    );
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

async fn admin_rows(kernel: &Kernel, principal: &PrincipalId, method: &str) -> Vec<bool> {
    kernel
        .audit_log
        .get_session_entries(&kernel.session_id)
        .await
        .unwrap()
        .into_iter()
        .filter(|entry| entry.principal.as_ref() == Some(principal))
        .filter_map(|entry| match entry.action {
            AuditAction::AdminRequest { method: name, .. } if name == method => {
                Some(matches!(entry.outcome, AuditOutcome::Success { .. }))
            },
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn anchoring_reads_skip_the_success_row_but_failures_and_denials_are_recorded() {
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
    append(&kernel, &kernel.session_id, Some("alice"), 1).await;

    for _ in 0..3 {
        let heads = send_admin(&kernel, &admin, "audit.heads", AdminRequestKind::AuditHeads).await;
        assert_eq!(heads["status"], "AuditHeads", "{heads}");
        let page = send_admin(
            &kernel,
            &admin,
            "audit.export",
            AdminRequestKind::AuditExport(request(&kernel.session_id, "alice")),
        )
        .await;
        assert_eq!(page["status"], "AuditExport", "{page}");
    }
    assert!(
        admin_rows(&kernel, &admin, "admin.audit.heads")
            .await
            .is_empty()
    );
    assert!(
        admin_rows(&kernel, &admin, "admin.audit.export")
            .await
            .is_empty()
    );

    // An authorized read that its handler rejects is recorded as a failure.
    let rejected = send_admin(
        &kernel,
        &admin,
        "audit.export",
        AdminRequestKind::AuditExport(AuditExportRequest {
            cursor: Some("garbage".to_owned()),
            ..request(&kernel.session_id, "alice")
        }),
    )
    .await;
    assert_eq!(rejected["status"], "Error", "{rejected}");
    assert_eq!(
        admin_rows(&kernel, &admin, "admin.audit.export").await,
        vec![false]
    );

    let denied = send_admin(
        &kernel,
        &restricted,
        "audit.heads",
        AdminRequestKind::AuditHeads,
    )
    .await;
    assert_eq!(denied["status"], "Error", "{denied}");
    assert_eq!(
        admin_rows(&kernel, &restricted, "admin.audit.heads").await,
        vec![false]
    );

    let stats = send_admin(&kernel, &admin, "audit.stats", AdminRequestKind::AuditStats).await;
    assert_eq!(stats["status"], "AuditStats", "{stats}");
    assert_eq!(
        admin_rows(&kernel, &admin, "admin.audit.stats").await,
        vec![true]
    );
}

use super::*;

/// Append `count` test entries to the log, returning their IDs.
fn append_test_entries(log: &AuditLog, session_id: &SessionId, count: u32) -> Vec<AuditEntryId> {
    (0..count)
        .map(|i| {
            log.append(
                session_id.clone(),
                AuditAction::McpToolCall {
                    server: "test".to_string(),
                    tool: format!("tool_{i}"),
                    args_hash: ContentHash::zero(),
                },
                AuthorizationProof::NotRequired {
                    reason: "test".to_string(),
                },
                AuditOutcome::success(),
            )
            .unwrap()
        })
        .collect()
}

#[test]
fn test_append_and_retrieve() {
    let keypair = KeyPair::generate();
    let user_id = keypair.key_id();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();

    let entry_id = log
        .append(
            session_id.clone(),
            AuditAction::SessionStarted {
                user_id,
                platform: "cli".to_string(),
            },
            AuthorizationProof::System {
                reason: "test".to_string(),
            },
            AuditOutcome::success(),
        )
        .unwrap();

    let entry = log.get(&entry_id).unwrap().unwrap();
    assert_eq!(entry.id, entry_id);
}

#[test]
fn test_chain_verification() {
    let keypair = KeyPair::generate();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();

    append_test_entries(&log, &session_id, 5);

    let result = log.verify_chain(&session_id).unwrap();
    assert!(result.valid);
    assert_eq!(result.entries_verified, 5);
}

#[test]
fn test_audit_builder() {
    let keypair = KeyPair::generate();
    let user_id = keypair.key_id();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();

    let entry_id = AuditBuilder::new(&log, session_id.clone())
        .action(AuditAction::SessionStarted {
            user_id,
            platform: "cli".to_string(),
        })
        .authorization(AuthorizationProof::System {
            reason: "test".to_string(),
        })
        .success()
        .unwrap();

    assert!(log.get(&entry_id).unwrap().is_some());

    // Also verify success_with and failure builders to prevent dead code.
    let entry_id2 = AuditBuilder::new(&log, session_id.clone())
        .action(AuditAction::ConfigReloaded)
        .success_with("custom-details")
        .unwrap();
    assert!(log.get(&entry_id2).unwrap().is_some());

    let entry_id3 = AuditBuilder::new(&log, session_id)
        .action(AuditAction::ConfigReloaded)
        .failure("custom-error")
        .unwrap();
    assert!(log.get(&entry_id3).unwrap().is_some());
}

#[test]
fn test_verify_detects_tampered_signature() {
    let keypair = KeyPair::generate();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();
    let ids = append_test_entries(&log, &session_id, 3);

    // Tamper: corrupt the signature of the second entry.
    let mut entry = log.get(&ids[1]).unwrap().unwrap();
    let mut bad_sig = *entry.signature.as_bytes();
    bad_sig[0] ^= 0xFF;
    entry.signature = astrid_crypto::Signature::from_bytes(bad_sig);
    log.storage.store(&entry).unwrap();

    let result = log.verify_chain(&session_id).unwrap();
    assert!(!result.valid);
    assert!(result.issues.iter().any(|issue| matches!(
        issue,
        ChainIssue::InvalidSignature { entry_id } if *entry_id == ids[1]
    )));
}

#[test]
fn test_verify_detects_broken_link() {
    let keypair = KeyPair::generate();
    // Keep secret bytes to reconstruct the key for re-signing tampered entries.
    let secret = keypair.secret_key_bytes();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();
    let ids = append_test_entries(&log, &session_id, 3);

    // Tamper: change the previous_hash of the third entry to break the link.
    let mut entry = log.get(&ids[2]).unwrap().unwrap();
    entry.previous_hash = ContentHash::from_bytes([0xAB; 32]);
    // Re-sign so the signature is valid - only the link is broken.
    let signer = KeyPair::from_secret_key(&secret).unwrap();
    let signing_data = entry.signing_data();
    entry.signature = signer.sign(&signing_data);
    log.storage.store(&entry).unwrap();

    let result = log.verify_chain(&session_id).unwrap();
    assert!(!result.valid);
    // The re-sign must succeed - no InvalidSignature, only BrokenLink.
    assert!(
        !result
            .issues
            .iter()
            .any(|issue| matches!(issue, ChainIssue::InvalidSignature { .. })),
        "re-signed entry should not trigger InvalidSignature"
    );
    assert!(result.issues.iter().any(|issue| matches!(
        issue,
        ChainIssue::BrokenLink { entry_id, .. } if *entry_id == ids[2]
    )));
}

#[test]
fn test_verify_detects_invalid_genesis() {
    let keypair = KeyPair::generate();
    let secret = keypair.secret_key_bytes();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();

    // Create one entry then tamper its previous_hash to be non-zero.
    let id = log
        .append(
            session_id.clone(),
            AuditAction::McpToolCall {
                server: "test".to_string(),
                tool: "tool_0".to_string(),
                args_hash: ContentHash::zero(),
            },
            AuthorizationProof::NotRequired {
                reason: "test".to_string(),
            },
            AuditOutcome::success(),
        )
        .unwrap();

    let mut entry = log.get(&id).unwrap().unwrap();
    entry.previous_hash = ContentHash::from_bytes([0x01; 32]);
    // Re-sign with the tampered previous_hash.
    let signer = KeyPair::from_secret_key(&secret).unwrap();
    let signing_data = entry.signing_data();
    entry.signature = signer.sign(&signing_data);
    log.storage.store(&entry).unwrap();

    let result = log.verify_chain(&session_id).unwrap();
    assert!(!result.valid);
    // The re-sign must succeed - no InvalidSignature, only InvalidGenesis.
    assert!(
        !result
            .issues
            .iter()
            .any(|issue| matches!(issue, ChainIssue::InvalidSignature { .. })),
        "re-signed entry should not trigger InvalidSignature"
    );
    assert!(result.issues.iter().any(|issue| matches!(
        issue,
        ChainIssue::InvalidGenesis { entry_id } if *entry_id == id
    )));
}

#[test]
fn test_verify_all_detects_tampered_session() {
    let keypair = KeyPair::generate();
    let log = AuditLog::in_memory(keypair);

    // Session A: valid chain.
    let session_a = SessionId::new();
    append_test_entries(&log, &session_a, 3);

    // Session B: tampered chain (single entry).
    let session_b = SessionId::new();
    let tampered_ids = append_test_entries(&log, &session_b, 1);
    let tampered_id = tampered_ids[0].clone();

    // Corrupt session B's entry signature.
    let mut entry = log.get(&tampered_id).unwrap().unwrap();
    let mut bad_sig = *entry.signature.as_bytes();
    bad_sig[0] ^= 0xFF;
    entry.signature = astrid_crypto::Signature::from_bytes(bad_sig);
    log.storage.store(&entry).unwrap();

    let results = log.verify_all().unwrap();
    assert_eq!(results.len(), 2);

    let a_result = results.iter().find(|(sid, _)| *sid == session_a).unwrap();
    assert!(a_result.1.valid);

    let b_result = results.iter().find(|(sid, _)| *sid == session_b).unwrap();
    assert!(!b_result.1.valid);
}

#[test]
fn test_verify_empty_log_is_valid() {
    let keypair = KeyPair::generate();
    let log = AuditLog::in_memory(keypair);

    let results = log.verify_all().unwrap();
    assert!(results.is_empty());

    // Also verify an empty session.
    let session_id = SessionId::new();
    let result = log.verify_chain(&session_id).unwrap();
    assert!(result.valid);
    assert_eq!(result.entries_verified, 0);
}

#[test]
fn test_key_rotation_entries_verify_via_embedded_pubkey() {
    // Entries embed the public key they were signed with, so verification
    // works even when the log's runtime key has changed (key rotation).
    let keypair_a = KeyPair::generate();
    let log_a = AuditLog::in_memory(keypair_a);
    let session_id = SessionId::new();

    // Write entries signed by key A.
    append_test_entries(&log_a, &session_id, 3);

    // Extract the entries and replay them into a log with key B.
    let entries = log_a.get_session_entries(&session_id).unwrap();
    let keypair_b = KeyPair::generate();
    let log_b = AuditLog::in_memory(keypair_b);

    for entry in &entries {
        log_b.storage.store(entry).unwrap();
    }

    // Key B log should still verify entries signed by key A because
    // verify_signature uses the entry's embedded public key.
    let result = log_b.verify_chain(&session_id).unwrap();
    assert!(
        result.valid,
        "entries signed by key A should verify in key B log, issues: {:?}",
        result.issues
    );
    assert_eq!(result.entries_verified, 3);
}

// ── Per-principal chain tests ────────────────────────────────

#[test]
fn test_principal_chains_are_independent() {
    let keypair = KeyPair::generate();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();
    let alice = astrid_core::PrincipalId::new("alice").unwrap();
    let bob = astrid_core::PrincipalId::new("bob").unwrap();

    // Alice: 2 entries
    log.append_with_principal(
        session_id.clone(),
        alice.clone(),
        AuditAction::McpToolCall {
            server: "test".into(),
            tool: "alice_tool_1".into(),
            args_hash: ContentHash::zero(),
        },
        AuthorizationProof::NotRequired {
            reason: "test".into(),
        },
        AuditOutcome::success(),
    )
    .unwrap();
    log.append_with_principal(
        session_id.clone(),
        alice.clone(),
        AuditAction::McpToolCall {
            server: "test".into(),
            tool: "alice_tool_2".into(),
            args_hash: ContentHash::zero(),
        },
        AuthorizationProof::NotRequired {
            reason: "test".into(),
        },
        AuditOutcome::success(),
    )
    .unwrap();

    // Bob: 1 entry
    log.append_with_principal(
        session_id.clone(),
        bob.clone(),
        AuditAction::McpToolCall {
            server: "test".into(),
            tool: "bob_tool_1".into(),
            args_hash: ContentHash::zero(),
        },
        AuthorizationProof::NotRequired {
            reason: "test".into(),
        },
        AuditOutcome::success(),
    )
    .unwrap();

    // System: 1 entry
    log.append(
        session_id.clone(),
        AuditAction::SessionStarted {
            user_id: [0; 8],
            platform: "test".into(),
        },
        AuthorizationProof::System {
            reason: "test".into(),
        },
        AuditOutcome::success(),
    )
    .unwrap();

    // Each chain verifies independently.
    let alice_result = log
        .verify_principal_chain(&session_id, Some(&alice))
        .unwrap();
    assert!(alice_result.valid, "alice chain: {:?}", alice_result.issues);
    assert_eq!(alice_result.entries_verified, 2);

    let bob_result = log.verify_principal_chain(&session_id, Some(&bob)).unwrap();
    assert!(bob_result.valid, "bob chain: {:?}", bob_result.issues);
    assert_eq!(bob_result.entries_verified, 1);

    let system_result = log.verify_principal_chain(&session_id, None).unwrap();
    assert!(
        system_result.valid,
        "system chain: {:?}",
        system_result.issues
    );
    assert_eq!(system_result.entries_verified, 1);

    // Full session verification covers all 4 entries.
    let full = log.verify_chain(&session_id).unwrap();
    assert!(full.valid, "full session: {:?}", full.issues);
    assert_eq!(full.entries_verified, 4);
}

#[test]
fn test_get_principal_entries_filters_correctly() {
    let keypair = KeyPair::generate();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();
    let alice = astrid_core::PrincipalId::new("alice").unwrap();

    // 2 alice entries + 1 system entry
    log.append_with_principal(
        session_id.clone(),
        alice.clone(),
        AuditAction::FileRead {
            path: "a.txt".into(),
        },
        AuthorizationProof::NotRequired { reason: "t".into() },
        AuditOutcome::success(),
    )
    .unwrap();
    log.append(
        session_id.clone(),
        AuditAction::ConfigReloaded,
        AuthorizationProof::System { reason: "t".into() },
        AuditOutcome::success(),
    )
    .unwrap();
    log.append_with_principal(
        session_id.clone(),
        alice.clone(),
        AuditAction::FileRead {
            path: "b.txt".into(),
        },
        AuthorizationProof::NotRequired { reason: "t".into() },
        AuditOutcome::success(),
    )
    .unwrap();

    let alice_entries = log
        .get_principal_entries(&session_id, Some(&alice))
        .unwrap();
    assert_eq!(alice_entries.len(), 2);

    let system_entries = log.get_principal_entries(&session_id, None).unwrap();
    assert_eq!(system_entries.len(), 1);

    // Total session still has 3
    let all = log.get_session_entries(&session_id).unwrap();
    assert_eq!(all.len(), 3);
}

#[test]
fn test_mixed_session_verify_chain_passes() {
    // A session with interleaved principal and system entries
    // should verify cleanly — each chain is independent.
    let keypair = KeyPair::generate();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();
    let alice = astrid_core::PrincipalId::new("alice").unwrap();

    // Interleave: system, alice, system, alice
    log.append(
        session_id.clone(),
        AuditAction::ConfigReloaded,
        AuthorizationProof::System { reason: "t".into() },
        AuditOutcome::success(),
    )
    .unwrap();
    log.append_with_principal(
        session_id.clone(),
        alice.clone(),
        AuditAction::FileRead {
            path: "a.txt".into(),
        },
        AuthorizationProof::NotRequired { reason: "t".into() },
        AuditOutcome::success(),
    )
    .unwrap();
    log.append(
        session_id.clone(),
        AuditAction::ConfigReloaded,
        AuthorizationProof::System { reason: "t".into() },
        AuditOutcome::success(),
    )
    .unwrap();
    log.append_with_principal(
        session_id.clone(),
        alice.clone(),
        AuditAction::FileRead {
            path: "b.txt".into(),
        },
        AuthorizationProof::NotRequired { reason: "t".into() },
        AuditOutcome::success(),
    )
    .unwrap();

    let result = log.verify_chain(&session_id).unwrap();
    assert!(result.valid, "mixed chain: {:?}", result.issues);
    assert_eq!(result.entries_verified, 4);
}

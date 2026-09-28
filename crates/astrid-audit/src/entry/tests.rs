//! Entry signing, chain-linking and serialization-compatibility tests.

use super::*;
use astrid_crypto::KeyPair;

fn test_keypair() -> KeyPair {
    KeyPair::generate()
}

#[test]
fn test_entry_creation() {
    let keypair = test_keypair();
    let session_id = SessionId::new();

    let entry = AuditEntry::create(
        session_id,
        AuditAction::SessionStarted {
            user_id: keypair.key_id(),
            platform: "cli".to_string(),
        },
        AuthorizationProof::System {
            reason: "session start".to_string(),
        },
        AuditOutcome::success(),
        ContentHash::zero(),
        &keypair,
    );

    assert!(entry.verify_signature().is_ok());
}

#[test]
fn test_chain_linking() {
    let keypair = test_keypair();
    let session_id = SessionId::new();

    let entry1 = AuditEntry::create(
        session_id.clone(),
        AuditAction::SessionStarted {
            user_id: keypair.key_id(),
            platform: "cli".to_string(),
        },
        AuthorizationProof::System {
            reason: "session start".to_string(),
        },
        AuditOutcome::success(),
        ContentHash::zero(),
        &keypair,
    );

    let entry2 = AuditEntry::create(
        session_id,
        AuditAction::McpToolCall {
            server: "test".to_string(),
            tool: "tool".to_string(),
            args_hash: ContentHash::hash(b"args"),
        },
        AuthorizationProof::NotRequired {
            reason: "test".to_string(),
        },
        AuditOutcome::success(),
        entry1.content_hash(),
        &keypair,
    );

    assert!(entry2.follows(&entry1));
    assert!(!entry1.follows(&entry2));
}

#[test]
fn test_signature_tampering() {
    let keypair = test_keypair();
    let session_id = SessionId::new();

    let mut entry = AuditEntry::create(
        session_id,
        AuditAction::SessionStarted {
            user_id: keypair.key_id(),
            platform: "cli".to_string(),
        },
        AuthorizationProof::System {
            reason: "session start".to_string(),
        },
        AuditOutcome::success(),
        ContentHash::zero(),
        &keypair,
    );

    // Valid signature
    assert!(entry.verify_signature().is_ok());

    // Tamper with the entry
    entry.action = AuditAction::SessionEnded {
        reason: "tampered".to_string(),
        duration_secs: 0,
    };

    // Signature should now fail
    assert!(entry.verify_signature().is_err());
}

#[test]
fn test_action_description() {
    let action = AuditAction::McpToolCall {
        server: "filesystem".to_string(),
        tool: "read_file".to_string(),
        args_hash: ContentHash::zero(),
    };

    assert!(action.description().contains("filesystem:read_file"));
}

fn actor() -> CapsuleActor {
    CapsuleActor {
        capsule_id: "fetcher".to_string(),
        wasm_hash: Some(ContentHash::hash(b"component")),
    }
}

/// Entries written before the coverage fields existed carry none of them.
/// Serializing a variant with the new optional fields unset must reproduce
/// the legacy action JSON byte for byte, or those entries would stop
/// verifying after a read/re-serialize round trip.
#[test]
fn unset_coverage_fields_keep_the_legacy_action_encoding() {
    let content_hash = ContentHash::hash(b"content");
    let cases = [
        (
            AuditAction::FileWrite {
                path: "/w/f".to_string(),
                content_hash,
                actor: None,
            },
            format!(r#"{{"type":"file_write","path":"/w/f","content_hash":"{content_hash}"}}"#),
        ),
        (
            AuditAction::NetConnect {
                host: "example.com".to_string(),
                port: 443,
                actor: None,
            },
            r#"{"type":"net_connect","host":"example.com","port":443}"#.to_string(),
        ),
        (
            AuditAction::CapsuleToolCall {
                capsule_id: "c".to_string(),
                tool: "t".to_string(),
                args_hash: content_hash,
                call_id: None,
                result_hash: None,
                actor: None,
            },
            format!(
                r#"{{"type":"capsule_tool_call","capsule_id":"c","tool":"t","args_hash":"{content_hash}"}}"#
            ),
        ),
        (
            AuditAction::ApprovalDenied {
                action: "a".to_string(),
                reason: None,
                request_id: None,
                request_entry_id: None,
                actor: None,
            },
            r#"{"type":"approval_denied","action":"a","reason":null}"#.to_string(),
        ),
    ];
    for (action, legacy) in cases {
        assert_eq!(serde_json::to_string(&action).unwrap(), legacy);
        let parsed: AuditAction = serde_json::from_str(&legacy).unwrap();
        assert_eq!(serde_json::to_string(&parsed).unwrap(), legacy);
    }
}

/// A legacy-format entry still verifies after it is parsed by this version
/// and re-serialized, which is what reading a stored chain does.
#[test]
fn legacy_entry_verifies_after_round_trip() {
    let keypair = test_keypair();
    let entry = AuditEntry::create(
        SessionId::new(),
        AuditAction::FileRead {
            path: "/w/r".to_string(),
            actor: None,
        },
        AuthorizationProof::System {
            reason: "manifest-gated host call".to_string(),
        },
        AuditOutcome::success(),
        ContentHash::zero(),
        &keypair,
    );
    let stored = serde_json::to_string(&entry).unwrap();
    assert!(!stored.contains("actor"), "unset actor must not be written");
    let reread: AuditEntry = serde_json::from_str(&stored).unwrap();
    assert!(reread.verify_signature().is_ok());
    assert_eq!(reread.content_hash(), entry.content_hash());
}

/// The coverage fields are part of the signed action JSON: changing the
/// attributed capsule or a committed hash invalidates the signature.
#[test]
fn coverage_fields_are_signed() {
    let keypair = test_keypair();
    let mut entry = AuditEntry::create(
        SessionId::new(),
        AuditAction::HttpRequest {
            sequence: 1,
            run_id: "run".to_string(),
            method: "POST".to_string(),
            host: "api.example.com".to_string(),
            port: 443,
            path_hash: ContentHash::hash(b"/v1/chat"),
            headers_hash: ContentHash::hash(b"headers"),
            body_hash: ContentHash::hash(b"body"),
            body_len: 4,
            redirect_hop: 0,
            injected_secrets: vec!["api_key".to_string()],
            actor: Some(actor()),
        },
        AuthorizationProof::System {
            reason: "manifest-gated host call".to_string(),
        },
        AuditOutcome::success(),
        ContentHash::zero(),
        &keypair,
    );
    assert!(entry.verify_signature().is_ok());

    let AuditAction::HttpRequest {
        actor: Some(actor), ..
    } = &mut entry.action
    else {
        panic!("unexpected action");
    };
    actor.capsule_id = "someone-else".to_string();
    assert!(entry.verify_signature().is_err());
}

#[test]
fn new_actions_round_trip_and_describe() {
    let actions = [
        AuditAction::HttpResponse {
            sequence: 7,
            run_id: "run".to_string(),
            request_entry_id: Some(AuditEntryId::new()),
            status: Some(200),
            body_hash: Some(ContentHash::hash(b"resp")),
            body_len: 4,
            complete: true,
            provider_request_ids: vec![ProviderRequestId {
                header: "x-request-id".to_string(),
                value: "req_123".to_string(),
            }],
            actor: Some(actor()),
        },
        AuditAction::CapabilityChanged {
            target_principal: PrincipalId::new("alice").unwrap(),
            kind: "capability".to_string(),
            granted: vec!["fs:read".to_string()],
            revoked: Vec::new(),
            via: "admin.caps.grant".to_string(),
        },
        AuditAction::CapsuleInstalled {
            capsule_id: "fetcher".to_string(),
            version: "1.0.0".to_string(),
            target_principal: None,
            wasm_hash: Some(ContentHash::hash(b"component")),
            manifest_hash: Some(ContentHash::hash(b"manifest")),
        },
        AuditAction::CapsuleLoaded {
            capsule_id: "fetcher".to_string(),
            version: "1.0.0".to_string(),
            wasm_hash: Some(ContentHash::hash(b"component")),
            manifest_hash: Some(ContentHash::hash(b"manifest")),
            engine_profile: "profile".to_string(),
            trigger: "load".to_string(),
        },
    ];
    for action in actions {
        let json = serde_json::to_string(&action).unwrap();
        let parsed: AuditAction = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
        assert!(!action.description().is_empty());
    }
}

use super::*;
use crate::AllowancePattern;
use astrid_core::principal::PrincipalId;
use astrid_core::types::Timestamp;
use astrid_crypto::KeyPair;

/// Deterministic default principal used by single-tenant tests.
fn default_principal() -> PrincipalId {
    PrincipalId::default()
}

/// Deterministic named principals for multi-tenant tests.
fn alice() -> PrincipalId {
    PrincipalId::new("alice").expect("valid principal")
}

fn bob() -> PrincipalId {
    PrincipalId::new("bob").expect("valid principal")
}

/// Create a test allowance with the given pattern.
fn make_allowance(pattern: AllowancePattern, session_only: bool) -> Allowance {
    make_allowance_for(default_principal(), pattern, session_only)
}

/// Create a test allowance owned by a specific principal.
fn make_allowance_for(
    principal: PrincipalId,
    pattern: AllowancePattern,
    session_only: bool,
) -> Allowance {
    let keypair = KeyPair::generate();
    Allowance {
        id: AllowanceId::new(),
        principal,
        action_pattern: pattern,
        created_at: Timestamp::now(),
        expires_at: None,
        max_uses: None,
        uses_remaining: None,
        session_only,
        workspace_root: None,
        signature: keypair.sign(b"test-allowance"),
    }
}

/// Create a limited-use test allowance.
fn make_limited_allowance(pattern: AllowancePattern, max_uses: u32) -> Allowance {
    let keypair = KeyPair::generate();
    Allowance {
        id: AllowanceId::new(),
        principal: default_principal(),
        action_pattern: pattern,
        created_at: Timestamp::now(),
        expires_at: None,
        max_uses: Some(max_uses),
        uses_remaining: Some(max_uses),
        session_only: true,
        workspace_root: None,
        signature: keypair.sign(b"test-allowance"),
    }
}

#[test]
fn test_store_add_and_count() {
    let store = AllowanceStore::new();
    assert_eq!(store.count(), 0);

    let allowance = make_allowance(
        AllowancePattern::ServerTools {
            server: "fs".to_string(),
        },
        true,
    );
    store.add_allowance(allowance).unwrap();
    assert_eq!(store.count(), 1);
    assert_eq!(store.count_for(&default_principal()), 1);
}

#[test]
fn test_store_find_matching() {
    let store = AllowanceStore::new();

    let allowance = make_allowance(
        AllowancePattern::ExactTool {
            server: "filesystem".to_string(),
            tool: "read_file".to_string(),
        },
        true,
    );
    let expected_id = allowance.id.clone();
    store.add_allowance(allowance).unwrap();

    let action = SensitiveAction::McpToolCall {
        server: "filesystem".to_string(),
        tool: "read_file".to_string(),
    };
    let found = store.find_matching(&default_principal(), &action, None);
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, expected_id);
}

#[test]
fn test_store_find_matching_no_match() {
    let store = AllowanceStore::new();

    let allowance = make_allowance(
        AllowancePattern::ExactTool {
            server: "filesystem".to_string(),
            tool: "read_file".to_string(),
        },
        true,
    );
    store.add_allowance(allowance).unwrap();

    let action = SensitiveAction::McpToolCall {
        server: "github".to_string(),
        tool: "create_issue".to_string(),
    };
    assert!(
        store
            .find_matching(&default_principal(), &action, None)
            .is_none()
    );
}

#[test]
fn test_store_find_matching_skips_expired() {
    let store = AllowanceStore::new();

    let keypair = KeyPair::generate();
    let expired = Allowance {
        id: AllowanceId::new(),
        principal: default_principal(),
        action_pattern: AllowancePattern::ServerTools {
            server: "filesystem".to_string(),
        },
        created_at: Timestamp::from_datetime(chrono::Utc::now() - chrono::Duration::hours(2)),
        expires_at: Some(Timestamp::from_datetime(
            chrono::Utc::now() - chrono::Duration::hours(1),
        )),
        max_uses: None,
        uses_remaining: None,
        session_only: true,
        workspace_root: None,
        signature: keypair.sign(b"test"),
    };
    store.add_allowance(expired).unwrap();

    let action = SensitiveAction::McpToolCall {
        server: "filesystem".to_string(),
        tool: "read_file".to_string(),
    };
    assert!(
        store
            .find_matching(&default_principal(), &action, None)
            .is_none()
    );
}

#[test]
fn test_store_find_matching_skips_exhausted() {
    let store = AllowanceStore::new();

    let mut allowance = make_limited_allowance(
        AllowancePattern::ServerTools {
            server: "filesystem".to_string(),
        },
        1,
    );
    let id = allowance.id.clone();
    // Pre-exhaust the uses
    allowance.uses_remaining = Some(0);
    store.add_allowance(allowance).unwrap();

    let action = SensitiveAction::McpToolCall {
        server: "filesystem".to_string(),
        tool: "read_file".to_string(),
    };
    assert!(
        store
            .find_matching(&default_principal(), &action, None)
            .is_none()
    );

    // Verify it's still in the store (not removed, just skipped)
    assert_eq!(store.count(), 1);
    // But consume_use on it still works (it's found by ID)
    assert!(store.consume_use(&default_principal(), &id).is_ok());
}

#[test]
fn test_store_consume_use_limited() {
    let store = AllowanceStore::new();

    let allowance = make_limited_allowance(
        AllowancePattern::ServerTools {
            server: "fs".to_string(),
        },
        3,
    );
    let id = allowance.id.clone();
    store.add_allowance(allowance).unwrap();

    let p = default_principal();
    // 3 uses: consume down to 2, 1, 0
    assert!(store.consume_use(&p, &id).unwrap()); // 2 remaining
    assert!(store.consume_use(&p, &id).unwrap()); // 1 remaining
    assert!(!store.consume_use(&p, &id).unwrap()); // 0 remaining (last use)

    // Saturates at 0
    assert!(!store.consume_use(&p, &id).unwrap());
}

#[test]
fn test_store_consume_use_unlimited() {
    let store = AllowanceStore::new();

    let allowance = make_allowance(
        AllowancePattern::ServerTools {
            server: "fs".to_string(),
        },
        true,
    );
    let id = allowance.id.clone();
    store.add_allowance(allowance).unwrap();

    let p = default_principal();
    // Unlimited: always returns true
    assert!(store.consume_use(&p, &id).unwrap());
    assert!(store.consume_use(&p, &id).unwrap());
}

#[test]
fn test_store_consume_use_not_found() {
    let store = AllowanceStore::new();
    let result = store.consume_use(&default_principal(), &AllowanceId::new());
    assert!(result.is_err());
}

#[test]
fn test_store_cleanup_expired() {
    let store = AllowanceStore::new();

    let keypair = KeyPair::generate();

    // Add an expired allowance
    let expired = Allowance {
        id: AllowanceId::new(),
        principal: default_principal(),
        action_pattern: AllowancePattern::ServerTools {
            server: "old".to_string(),
        },
        created_at: Timestamp::from_datetime(chrono::Utc::now() - chrono::Duration::hours(2)),
        expires_at: Some(Timestamp::from_datetime(
            chrono::Utc::now() - chrono::Duration::hours(1),
        )),
        max_uses: None,
        uses_remaining: None,
        session_only: true,
        workspace_root: None,
        signature: keypair.sign(b"expired"),
    };
    store.add_allowance(expired).unwrap();

    // Add a valid allowance
    let valid = make_allowance(
        AllowancePattern::ServerTools {
            server: "current".to_string(),
        },
        true,
    );
    store.add_allowance(valid).unwrap();

    assert_eq!(store.count(), 2);
    let removed = store.cleanup_expired();
    assert_eq!(removed, 1);
    assert_eq!(store.count(), 1);
}

#[test]
fn test_store_clear_session_allowances_scoped_to_principal() {
    let store = AllowanceStore::new();

    // Alice: one session, one persistent.
    store
        .add_allowance(make_allowance_for(
            alice(),
            AllowancePattern::ServerTools {
                server: "alice-session".to_string(),
            },
            true,
        ))
        .unwrap();
    store
        .add_allowance(make_allowance_for(
            alice(),
            AllowancePattern::ServerTools {
                server: "alice-persistent".to_string(),
            },
            false,
        ))
        .unwrap();

    // Bob: one session (must NOT be cleared by alice disconnecting).
    store
        .add_allowance(make_allowance_for(
            bob(),
            AllowancePattern::ServerTools {
                server: "bob-session".to_string(),
            },
            true,
        ))
        .unwrap();

    assert_eq!(store.count(), 3);

    // Alice disconnects.
    store.clear_session_allowances(&alice());

    // Alice's session gone, alice's persistent survives, bob's session untouched.
    assert_eq!(store.count(), 2);
    assert_eq!(store.count_for(&alice()), 1);
    assert_eq!(store.count_for(&bob()), 1);

    let alice_persistent = SensitiveAction::McpToolCall {
        server: "alice-persistent".to_string(),
        tool: "any_tool".to_string(),
    };
    assert!(
        store
            .find_matching(&alice(), &alice_persistent, None)
            .is_some()
    );

    let alice_session_action = SensitiveAction::McpToolCall {
        server: "alice-session".to_string(),
        tool: "any_tool".to_string(),
    };
    assert!(
        store
            .find_matching(&alice(), &alice_session_action, None)
            .is_none()
    );

    let bob_session_action = SensitiveAction::McpToolCall {
        server: "bob-session".to_string(),
        tool: "any_tool".to_string(),
    };
    assert!(
        store
            .find_matching(&bob(), &bob_session_action, None)
            .is_some()
    );
}

#[test]
fn test_store_clear_all_session_allowances() {
    let store = AllowanceStore::new();

    store
        .add_allowance(make_allowance_for(
            alice(),
            AllowancePattern::ServerTools {
                server: "s1".to_string(),
            },
            true,
        ))
        .unwrap();
    store
        .add_allowance(make_allowance_for(
            bob(),
            AllowancePattern::ServerTools {
                server: "s2".to_string(),
            },
            true,
        ))
        .unwrap();
    store
        .add_allowance(make_allowance_for(
            bob(),
            AllowancePattern::ServerTools {
                server: "s3".to_string(),
            },
            false,
        ))
        .unwrap();

    assert_eq!(store.count(), 3);

    store.clear_all_session_allowances();

    // Only the persistent allowance survives.
    assert_eq!(store.count(), 1);
    assert_eq!(store.count_for(&alice()), 0);
    assert_eq!(store.count_for(&bob()), 1);
}

#[test]
fn test_store_find_matching_does_not_cross_principals() {
    let store = AllowanceStore::new();

    // Alice has an allowance for the `fs` server.
    store
        .add_allowance(make_allowance_for(
            alice(),
            AllowancePattern::ServerTools {
                server: "fs".to_string(),
            },
            true,
        ))
        .unwrap();

    let action = SensitiveAction::McpToolCall {
        server: "fs".to_string(),
        tool: "read_file".to_string(),
    };

    // Alice can see her allowance.
    assert!(store.find_matching(&alice(), &action, None).is_some());

    // Bob cannot — even though the pattern matches the action, Bob has no
    // allowance here.
    assert!(store.find_matching(&bob(), &action, None).is_none());
    assert!(
        store
            .find_matching_and_consume(&bob(), &action, None)
            .is_none()
    );

    // Alice's uses are untouched by Bob's attempt.
    assert_eq!(store.count_for(&alice()), 1);
}

#[test]
fn test_store_export_is_principal_scoped() {
    let store = AllowanceStore::new();
    store
        .add_allowance(make_allowance_for(
            alice(),
            AllowancePattern::ServerTools {
                server: "alice-s".to_string(),
            },
            true,
        ))
        .unwrap();
    store
        .add_allowance(make_allowance_for(
            bob(),
            AllowancePattern::ServerTools {
                server: "bob-s".to_string(),
            },
            true,
        ))
        .unwrap();

    let alice_exported = store.export_session_allowances(&alice());
    let bob_exported = store.export_session_allowances(&bob());
    assert_eq!(alice_exported.len(), 1);
    assert_eq!(bob_exported.len(), 1);
    assert_eq!(alice_exported[0].principal, alice());
    assert_eq!(bob_exported[0].principal, bob());
}

#[test]
fn clear_for_principal_removes_every_scope_without_touching_peers() {
    let store = AllowanceStore::new();
    for session_only in [true, false] {
        store
            .add_allowance(make_allowance_for(
                alice(),
                AllowancePattern::ServerTools {
                    server: format!("alice-{session_only}"),
                },
                session_only,
            ))
            .unwrap();
    }
    store
        .add_allowance(make_allowance_for(
            bob(),
            AllowancePattern::ServerTools {
                server: "bob".to_string(),
            },
            false,
        ))
        .unwrap();

    store.clear_for_principal(&alice());

    assert_eq!(store.count_for(&alice()), 0);
    assert_eq!(store.count_for(&bob()), 1);
}

#[test]
fn retirement_fences_allowance_creation_and_authorization_until_finished() {
    let store = AllowanceStore::new();
    let action = SensitiveAction::McpToolCall {
        server: "retired".to_string(),
        tool: "run".to_string(),
    };
    let allowance = make_allowance_for(
        alice(),
        AllowancePattern::ServerTools {
            server: "retired".to_string(),
        },
        false,
    );
    store.add_allowance(allowance.clone()).unwrap();

    store.begin_principal_retirement(&alice()).unwrap();
    assert!(store.find_matching(&alice(), &action, None).is_none());
    assert!(store.add_allowance(allowance.clone()).is_err());

    store.finish_principal_retirement(&alice());
    store.add_allowance(allowance).unwrap();
    assert!(store.find_matching(&alice(), &action, None).is_some());
}

#[test]
fn test_store_add_trusts_allowance_principal() {
    // Adversarial case: the Allowance's principal is the only source of
    // truth. An allowance for bob is inserted under bob — not under any
    // caller-supplied context.
    let store = AllowanceStore::new();
    store
        .add_allowance(make_allowance_for(
            bob(),
            AllowancePattern::ServerTools {
                server: "bob-only".to_string(),
            },
            true,
        ))
        .unwrap();

    let action = SensitiveAction::McpToolCall {
        server: "bob-only".to_string(),
        tool: "any".to_string(),
    };

    // Alice (who did NOT grant this) cannot find it.
    assert!(store.find_matching(&alice(), &action, None).is_none());
    // Bob can.
    assert!(store.find_matching(&bob(), &action, None).is_some());
}

#[test]
fn test_store_default() {
    let store = AllowanceStore::default();
    assert_eq!(store.count(), 0);
}

#[test]
fn test_store_debug() {
    let store = AllowanceStore::new();
    let debug = format!("{store:?}");
    assert!(debug.contains("AllowanceStore"));
    assert!(debug.contains("count"));
}

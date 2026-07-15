use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

use astrid_audit::{AuditLog, AuthorizationProof};
use astrid_core::{SessionId, Timestamp};
use astrid_crypto::KeyPair;
use chrono::TimeZone;

fn admin_action(method: &str, target: Option<&str>) -> AuditAction {
    AuditAction::AdminRequest {
        method: method.into(),
        required_capability: "*".into(),
        target_principal: target.map(|s| PrincipalId::new(s).unwrap()),
        params: None,
        device_key_id: None,
    }
}

#[tokio::test]
async fn render_drops_non_admin_actions() {
    // Non-admin entries (MCP tool calls, capsule events) belong
    // to a different audit feed; they must not surface in the
    // historical-admin view.
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::from_uuid(uuid::Uuid::nil());
    log.append(
        session.clone(),
        AuditAction::McpToolCall {
            server: "x".into(),
            tool: "y".into(),
            args_hash: astrid_crypto::ContentHash::from_bytes([0u8; 32]),
        },
        AuthorizationProof::System {
            reason: "test".into(),
        },
        AuditOutcome::Success { details: None },
    )
    .await
    .expect("append");
    let entries = log.get_session_entries(&session).await.expect("read");
    assert_eq!(entries.len(), 1);
    assert!(
        render_entry(&entries[0]).is_none(),
        "McpToolCall must not render into the admin-history view"
    );
}

#[tokio::test]
async fn render_admin_request_round_trips() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::from_uuid(uuid::Uuid::nil());
    log.append_with_principal(
        session.clone(),
        PrincipalId::new("admin").unwrap(),
        admin_action("AgentDelete", Some("alice")),
        AuthorizationProof::System {
            reason: "test".into(),
        },
        AuditOutcome::Success { details: None },
    )
    .await
    .expect("append");
    let entries = log.get_session_entries(&session).await.expect("read");
    let view = render_entry(&entries[0]).expect("admin entry must render");
    assert_eq!(view.method.as_deref(), Some("AgentDelete"));
    assert_eq!(view.principal.as_deref(), Some("admin"));
    assert_eq!(view.target_principal.as_deref(), Some("alice"));
    assert_eq!(view.outcome, "success");
}

#[tokio::test]
async fn pagination_narrows_live_without_hiding_the_callers_records() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::from_uuid(uuid::Uuid::nil());
    for (principal, method) in [
        ("alice", "AliceOwnAfterNarrowing"),
        ("bob", "BobHiddenAfterNarrowing"),
        ("bob", "BobVisibleBeforeNarrowing"),
    ] {
        log.append_with_principal(
            session.clone(),
            PrincipalId::new(principal).unwrap(),
            admin_action(method, None),
            AuthorizationProof::System {
                reason: "test".into(),
            },
            AuditOutcome::Success { details: None },
        )
        .await
        .expect("append");
    }
    let mut entries = log.get_session_entries(&session).await.expect("read");
    entries.reverse();

    let checks = Arc::new(AtomicUsize::new(0));
    let checks_for_probe = Arc::clone(&checks);
    let capability_probe = super::super::events::CapabilityProbe::new(move |_, _, _| {
        matches!(checks_for_probe.fetch_add(1, Ordering::SeqCst), 0 | 1)
    });
    let caller = PrincipalId::new("alice").unwrap();
    let access = AuditAccess {
        capability_probe: &capability_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };

    let (page, _) = paginate_page(
        entries,
        &AuditQuery::default(),
        &access,
        AuditCursor::default(),
        DEFAULT_LIMIT,
    )
    .expect("pagination");
    let methods: Vec<_> = page
        .iter()
        .filter_map(|entry| entry.method.as_deref())
        .collect();

    assert_eq!(
        methods,
        vec!["BobVisibleBeforeNarrowing", "AliceOwnAfterNarrowing"]
    );
    assert!(!methods.contains(&"BobHiddenAfterNarrowing"));
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn pagination_cursor_survives_live_narrowing_with_same_second_batch() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::from_uuid(uuid::Uuid::nil());
    for (principal, method) in [
        ("alice", "AliceOlder"),
        ("alice", "AliceVisibleAfterNarrowing"),
        ("bob", "BobHiddenAfterNarrowing"),
        ("bob", "BobVisibleBeforeNarrowing"),
    ] {
        log.append_with_principal(
            session.clone(),
            PrincipalId::new(principal).unwrap(),
            admin_action(method, None),
            AuthorizationProof::System {
                reason: "test".into(),
            },
            AuditOutcome::Success { details: None },
        )
        .await
        .expect("append");
    }
    let mut entries = log.get_session_entries(&session).await.expect("read");
    entries.reverse();
    let same_second = Timestamp::from_datetime(
        chrono::Utc
            .timestamp_opt(1_700_000_000, 0)
            .single()
            .unwrap(),
    );
    let next_second = Timestamp::from_datetime(
        chrono::Utc
            .timestamp_opt(1_699_999_999, 0)
            .single()
            .unwrap(),
    );
    for entry in &mut entries[..3] {
        entry.timestamp = same_second;
    }
    entries[3].timestamp = next_second;

    let firehose_probe = super::super::events::CapabilityProbe::new(|_, _, _| true);
    let self_only_probe = super::super::events::CapabilityProbe::new(|_, _, _| false);
    let caller = PrincipalId::new("alice").unwrap();
    let firehose_access = AuditAccess {
        capability_probe: &firehose_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };
    let self_only_access = AuditAccess {
        capability_probe: &self_only_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };

    let (page_one, next_cursor) = paginate_page(
        entries.clone(),
        &AuditQuery::default(),
        &firehose_access,
        AuditCursor::default(),
        1,
    )
    .expect("page one");
    assert_eq!(
        page_one[0].method.as_deref(),
        Some("BobVisibleBeforeNarrowing")
    );
    let mut cursor = parse_cursor(next_cursor.as_deref()).expect("page-one cursor parses");
    assert_eq!(cursor.timestamp, Some(1_700_000_000));
    assert_eq!(cursor.same_second_offset, 1);
    assert_eq!(cursor.scope, Some(CursorScope::All));
    assert_eq!(cursor.anchor_entry_id, Some(entries[0].id.0));
    cursor.scope = validate_cursor_scope(
        cursor.timestamp,
        cursor.scope.as_ref(),
        &AuditQuery::default(),
        &self_only_access,
    )
    .expect("all-scope cursor may narrow to self-only");
    let (page_two, next_cursor) = paginate_page(
        entries.clone(),
        &AuditQuery::default(),
        &self_only_access,
        cursor,
        1,
    )
    .expect("page two");
    assert_eq!(
        page_two[0].method.as_deref(),
        Some("AliceVisibleAfterNarrowing")
    );
    let mut cursor = parse_cursor(next_cursor.as_deref()).expect("page-two cursor parses");
    assert_eq!(cursor.timestamp, Some(1_700_000_000));
    assert_eq!(cursor.same_second_offset, 3);
    assert_eq!(cursor.scope, Some(CursorScope::Principal(caller.clone())));
    assert_eq!(cursor.anchor_entry_id, Some(entries[2].id.0));
    cursor.scope = validate_cursor_scope(
        cursor.timestamp,
        cursor.scope.as_ref(),
        &AuditQuery::default(),
        &self_only_access,
    )
    .expect("self-only cursor continues under same scope");
    let (page_three, next_cursor) = paginate_page(
        entries.clone(),
        &AuditQuery::default(),
        &self_only_access,
        cursor,
        1,
    )
    .expect("page three");
    assert_eq!(page_three[0].method.as_deref(), Some("AliceOlder"));
    assert_eq!(next_cursor.as_deref(), None);
}

#[tokio::test]
async fn identity_cursor_survives_same_second_append_between_pages() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::from_uuid(uuid::Uuid::nil());
    for method in ["Older", "PageOne"] {
        log.append_with_principal(
            session.clone(),
            PrincipalId::new("alice").unwrap(),
            admin_action(method, None),
            AuthorizationProof::System {
                reason: "test".into(),
            },
            AuditOutcome::Success { details: None },
        )
        .await
        .expect("append");
    }
    let timestamp = Timestamp::from_datetime(
        chrono::Utc
            .timestamp_opt(1_700_000_000, 0)
            .single()
            .unwrap(),
    );
    let mut first_snapshot = log.get_session_entries(&session).await.expect("read");
    first_snapshot.reverse();
    for entry in &mut first_snapshot {
        entry.timestamp = timestamp;
    }

    let self_only_probe = super::super::events::CapabilityProbe::new(|_, _, _| false);
    let caller = PrincipalId::new("alice").unwrap();
    let access = AuditAccess {
        capability_probe: &self_only_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };

    let (page_one, next_cursor) = paginate_page(
        first_snapshot.clone(),
        &AuditQuery::default(),
        &access,
        AuditCursor::default(),
        1,
    )
    .expect("page one");
    assert_eq!(page_one[0].method.as_deref(), Some("PageOne"));

    let mut cursor = parse_cursor(next_cursor.as_deref()).expect("identity cursor");
    assert_eq!(cursor.anchor_entry_id, Some(first_snapshot[0].id.0));
    cursor.scope = validate_cursor_scope(
        cursor.timestamp,
        cursor.scope.as_ref(),
        &AuditQuery::default(),
        &access,
    )
    .expect("self scope continues");

    log.append_with_principal(
        session.clone(),
        caller.clone(),
        admin_action("AppendedAfterPageOne", None),
        AuthorizationProof::System {
            reason: "test".into(),
        },
        AuditOutcome::Success { details: None },
    )
    .await
    .expect("append between pages");
    let mut second_snapshot = log.get_session_entries(&session).await.expect("read");
    second_snapshot.reverse();
    for entry in &mut second_snapshot {
        entry.timestamp = timestamp;
    }

    let (page_two, next_cursor) =
        paginate_page(second_snapshot, &AuditQuery::default(), &access, cursor, 2)
            .expect("page two");
    let methods: Vec<_> = page_two
        .iter()
        .filter_map(|entry| entry.method.as_deref())
        .collect();
    assert_eq!(methods, vec!["Older"]);
    assert_eq!(next_cursor, None);
}

#[tokio::test]
async fn identity_cursor_missing_anchor_requires_restart() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::from_uuid(uuid::Uuid::nil());
    log.append_with_principal(
        session.clone(),
        PrincipalId::new("alice").unwrap(),
        admin_action("OnlyEntry", None),
        AuthorizationProof::System {
            reason: "test".into(),
        },
        AuditOutcome::Success { details: None },
    )
    .await
    .expect("append");
    let mut entries = log.get_session_entries(&session).await.expect("read");
    entries.reverse();

    let self_only_probe = super::super::events::CapabilityProbe::new(|_, _, _| false);
    let caller = PrincipalId::new("alice").unwrap();
    let access = AuditAccess {
        capability_probe: &self_only_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };
    let cursor = AuditCursor {
        timestamp: Some(1_700_000_000),
        same_second_offset: 1,
        scope: Some(CursorScope::Principal(caller.clone())),
        anchor_entry_id: Some(uuid::Uuid::new_v4()),
    };

    let err = paginate_page(entries, &AuditQuery::default(), &access, cursor, 1)
        .expect_err("missing anchor must restart pagination");
    assert!(err.to_string().contains(CURSOR_ANCHOR_MISSING));
}

#[tokio::test]
async fn exact_limit_page_preserves_scope_cursor_after_hidden_row() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::from_uuid(uuid::Uuid::nil());
    for (principal, method) in [
        ("alice", "AliceTerminal"),
        ("bob", "BobHiddenBeforeTerminal"),
    ] {
        log.append_with_principal(
            session.clone(),
            PrincipalId::new(principal).unwrap(),
            admin_action(method, None),
            AuthorizationProof::System {
                reason: "test".into(),
            },
            AuditOutcome::Success { details: None },
        )
        .await
        .expect("append");
    }
    let mut entries = log.get_session_entries(&session).await.expect("read");
    entries.reverse();

    let self_only_probe = super::super::events::CapabilityProbe::new(|_, _, _| false);
    let firehose_probe = super::super::events::CapabilityProbe::new(|_, _, _| true);
    let caller = PrincipalId::new("alice").unwrap();
    let access = AuditAccess {
        capability_probe: &self_only_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };
    let widened_access = AuditAccess {
        capability_probe: &firehose_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };

    let (page, next_cursor) = paginate_page(
        entries,
        &AuditQuery::default(),
        &access,
        AuditCursor::default(),
        1,
    )
    .expect("terminal page");

    assert_eq!(page.len(), 1);
    assert_eq!(page[0].method.as_deref(), Some("AliceTerminal"));
    let cursor = parse_cursor(next_cursor.as_deref()).expect("scope-bound cursor");
    let err = validate_cursor_scope(
        cursor.timestamp,
        cursor.scope.as_ref(),
        &AuditQuery::default(),
        &widened_access,
    )
    .expect_err("widening after a hidden row must restart pagination");
    assert!(err.to_string().contains(CURSOR_SCOPE_CHANGED));
}

#[tokio::test]
async fn exact_limit_physical_eof_has_no_continuation_cursor() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::from_uuid(uuid::Uuid::nil());
    log.append_with_principal(
        session.clone(),
        PrincipalId::new("alice").unwrap(),
        admin_action("AliceTerminal", None),
        AuthorizationProof::System {
            reason: "test".into(),
        },
        AuditOutcome::Success { details: None },
    )
    .await
    .expect("append");
    let mut entries = log.get_session_entries(&session).await.expect("read");
    entries.reverse();

    let self_only_probe = super::super::events::CapabilityProbe::new(|_, _, _| false);
    let caller = PrincipalId::new("alice").unwrap();
    let access = AuditAccess {
        capability_probe: &self_only_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };

    let (page, next_cursor) = paginate_page(
        entries,
        &AuditQuery::default(),
        &access,
        AuditCursor::default(),
        1,
    )
    .expect("terminal page");

    assert_eq!(page.len(), 1);
    assert_eq!(page[0].method.as_deref(), Some("AliceTerminal"));
    assert_eq!(next_cursor, None);
}

#[test]
fn parse_cursor_handles_legacy_and_identity_anchored_shapes() {
    // v1 (legacy): bare integer, no underscore — offset
    // defaults to 0. Validation later accepts this shape only
    // for an unambiguous default self-view continuation.
    let cursor = parse_cursor(Some("1700000000")).expect("bare ts parses");
    assert_eq!(cursor.timestamp, Some(1_700_000_000));
    assert_eq!(cursor.same_second_offset, 0);
    assert_eq!(cursor.scope, None);
    assert_eq!(cursor.anchor_entry_id, None);

    // v2: `<ts>_<offset>` — same-second batches resume cleanly
    // without losing or duplicating entries across the page
    // boundary.
    let cursor = parse_cursor(Some("1700000000_3")).expect("v2 cursor parses");
    assert_eq!(cursor.timestamp, Some(1_700_000_000));
    assert_eq!(cursor.same_second_offset, 3);
    assert_eq!(cursor.scope, None);
    assert_eq!(cursor.anchor_entry_id, None);

    // New cursors carry both the effective scope and immutable entry anchor.
    let entry_id = uuid::Uuid::from_u128(1);
    let cursor = parse_cursor(Some(
        "1700000000_3_p616c696365_00000000-0000-0000-0000-000000000001",
    ))
    .expect("identity-anchored cursor parses");
    assert_eq!(cursor.timestamp, Some(1_700_000_000));
    assert_eq!(cursor.same_second_offset, 3);
    assert_eq!(
        cursor.scope,
        Some(CursorScope::Principal(PrincipalId::new("alice").unwrap()))
    );
    assert_eq!(cursor.anchor_entry_id, Some(entry_id));

    // None: no cursor → no positioning, start from newest.
    assert_eq!(
        parse_cursor(None).expect("None passes"),
        AuditCursor::default()
    );

    // Garbage rejected with `BadRequest`.
    assert!(parse_cursor(Some("not-a-number")).is_err());
    assert!(parse_cursor(Some("123_not-a-number")).is_err());
    assert!(parse_cursor(Some("not-a-number_4")).is_err());
    assert!(parse_cursor(Some("1700000000_3_p616c696365")).is_err());
    assert!(parse_cursor(Some("1700000000_3_all_not-a-uuid")).is_err());
}

#[tokio::test]
async fn pagination_cursor_rejects_scope_widening_after_self_only_page() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::from_uuid(uuid::Uuid::nil());
    for (principal, method) in [
        ("alice", "AliceVisibleWhileScoped"),
        ("bob", "BobNewlyVisibleAfterWidening"),
    ] {
        log.append_with_principal(
            session.clone(),
            PrincipalId::new(principal).unwrap(),
            admin_action(method, None),
            AuthorizationProof::System {
                reason: "test".into(),
            },
            AuditOutcome::Success { details: None },
        )
        .await
        .expect("append");
    }
    let mut entries = log.get_session_entries(&session).await.expect("read");
    entries.reverse();
    let same_second = Timestamp::from_datetime(
        chrono::Utc
            .timestamp_opt(1_700_000_000, 0)
            .single()
            .unwrap(),
    );
    for entry in &mut entries {
        entry.timestamp = same_second;
    }

    let self_only_probe = super::super::events::CapabilityProbe::new(|_, _, _| false);
    let firehose_probe = super::super::events::CapabilityProbe::new(|_, _, _| true);
    let caller = PrincipalId::new("alice").unwrap();
    let self_only_access = AuditAccess {
        capability_probe: &self_only_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };
    let firehose_access = AuditAccess {
        capability_probe: &firehose_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };

    let (page_one, next_cursor) = paginate_page(
        entries,
        &AuditQuery::default(),
        &self_only_access,
        AuditCursor::default(),
        1,
    )
    .expect("page one");
    assert_eq!(
        page_one[0].method.as_deref(),
        Some("AliceVisibleWhileScoped")
    );
    let cursor = parse_cursor(next_cursor.as_deref()).expect("cursor parses");
    let err = validate_cursor_scope(
        cursor.timestamp,
        cursor.scope.as_ref(),
        &AuditQuery::default(),
        &firehose_access,
    )
    .expect_err("widening must fail closed");
    assert!(
        err.to_string()
            .contains("restart pagination without a cursor"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn pagination_rejects_mid_page_scope_widening_after_visible_rows() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::from_uuid(uuid::Uuid::nil());
    for (principal, method) in [
        ("bob", "BobVisibleAfterRewidening"),
        ("alice", "AliceVisibleWhileScoped"),
        ("bob", "BobHiddenWhileScoped"),
        ("bob", "BobVisibleBeforeNarrowing"),
    ] {
        log.append_with_principal(
            session.clone(),
            PrincipalId::new(principal).unwrap(),
            admin_action(method, None),
            AuthorizationProof::System {
                reason: "test".into(),
            },
            AuditOutcome::Success { details: None },
        )
        .await
        .expect("append");
    }
    let mut entries = log.get_session_entries(&session).await.expect("read");
    entries.reverse();

    let checks = Arc::new(AtomicUsize::new(0));
    let checks_for_probe = Arc::clone(&checks);
    let capability_probe = super::super::events::CapabilityProbe::new(move |_, _, _| {
        matches!(checks_for_probe.fetch_add(1, Ordering::SeqCst), 0 | 1 | 4)
    });
    let caller = PrincipalId::new("alice").unwrap();
    let access = AuditAccess {
        capability_probe: &capability_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };

    let err = paginate_page(
        entries,
        &AuditQuery::default(),
        &access,
        AuditCursor::default(),
        3,
    )
    .expect_err("mid-page widening must restart pagination");
    assert!(
        err.to_string().contains(CURSOR_SCOPE_CHANGED),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn pagination_rejects_scope_widening_before_first_visible_row() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::from_uuid(uuid::Uuid::nil());
    for (principal, method) in [
        ("alice", "AliceVisibleAfterWidening"),
        ("bob", "BobHiddenWhileScoped"),
    ] {
        log.append_with_principal(
            session.clone(),
            PrincipalId::new(principal).unwrap(),
            admin_action(method, None),
            AuthorizationProof::System {
                reason: "test".into(),
            },
            AuditOutcome::Success { details: None },
        )
        .await
        .expect("append");
    }
    let mut entries = log.get_session_entries(&session).await.expect("read");
    entries.reverse();

    let checks = Arc::new(AtomicUsize::new(0));
    let checks_for_probe = Arc::clone(&checks);
    let capability_probe = super::super::events::CapabilityProbe::new(move |_, _, _| {
        checks_for_probe.fetch_add(1, Ordering::SeqCst) == 2
    });
    let caller = PrincipalId::new("alice").unwrap();
    let access = AuditAccess {
        capability_probe: &capability_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };

    let err = paginate_page(
        entries,
        &AuditQuery::default(),
        &access,
        AuditCursor::default(),
        3,
    )
    .expect_err("widening before the first visible row must not signal EOF");
    assert!(
        err.to_string().contains(CURSOR_SCOPE_CHANGED),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn identity_cursor_rejects_widening_while_seeking_anchor() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::from_uuid(uuid::Uuid::nil());
    for (principal, method) in [
        ("alice", "PriorPageAnchor"),
        ("bob", "AppendedBeforeAnchor"),
    ] {
        log.append_with_principal(
            session.clone(),
            PrincipalId::new(principal).unwrap(),
            admin_action(method, None),
            AuthorizationProof::System {
                reason: "test".into(),
            },
            AuditOutcome::Success { details: None },
        )
        .await
        .expect("append");
    }
    let mut entries = log.get_session_entries(&session).await.expect("read");
    entries.reverse();
    let cursor_ts = 1_700_000_000_u64;
    let timestamp = Timestamp::from_datetime(
        chrono::Utc
            .timestamp_opt(i64::try_from(cursor_ts).unwrap(), 0)
            .single()
            .unwrap(),
    );
    for entry in &mut entries {
        entry.timestamp = timestamp;
    }

    let checks = Arc::new(AtomicUsize::new(0));
    let checks_for_probe = Arc::clone(&checks);
    let capability_probe = super::super::events::CapabilityProbe::new(move |_, _, _| {
        checks_for_probe.fetch_add(1, Ordering::SeqCst) >= 2
    });
    let caller = PrincipalId::new("alice").unwrap();
    let access = AuditAccess {
        capability_probe: &capability_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };
    let mut cursor = AuditCursor {
        timestamp: Some(cursor_ts),
        same_second_offset: 1,
        scope: Some(CursorScope::Principal(caller.clone())),
        anchor_entry_id: Some(entries[1].id.0),
    };

    cursor.scope = validate_cursor_scope(
        cursor.timestamp,
        cursor.scope.as_ref(),
        &AuditQuery::default(),
        &access,
    )
    .expect("principal cursor initially matches principal visibility");
    let err = paginate_page(entries, &AuditQuery::default(), &access, cursor, 1)
        .expect_err("widening while seeking the identity anchor must restart pagination");
    assert!(
        err.to_string().contains(CURSOR_SCOPE_CHANGED),
        "unexpected error: {err}"
    );
}

#[test]
fn legacy_cursor_self_view_stays_compatible() {
    let self_only_probe = super::super::events::CapabilityProbe::new(|_, _, _| false);
    let caller = PrincipalId::new("alice").unwrap();
    let access = AuditAccess {
        capability_probe: &self_only_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };
    let cursor = parse_cursor(Some("1700000000_3")).expect("legacy cursor parses");

    let bound_scope = validate_cursor_scope(
        cursor.timestamp,
        cursor.scope.as_ref(),
        &AuditQuery::default(),
        &access,
    )
    .expect("legacy self-view cursor remains compatible");
    assert_eq!(bound_scope, Some(CursorScope::Principal(caller)));
}

#[test]
fn legacy_cursor_rejects_widening_between_validation_and_pagination() {
    let checks = Arc::new(AtomicUsize::new(0));
    let checks_for_probe = Arc::clone(&checks);
    let capability_probe = super::super::events::CapabilityProbe::new(move |_, _, _| {
        checks_for_probe.fetch_add(1, Ordering::SeqCst) >= 1
    });
    let caller = PrincipalId::new("alice").unwrap();
    let access = AuditAccess {
        capability_probe: &capability_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };
    let mut cursor = parse_cursor(Some("1700000000_3")).expect("legacy cursor parses");

    cursor.scope = validate_cursor_scope(
        cursor.timestamp,
        cursor.scope.as_ref(),
        &AuditQuery::default(),
        &access,
    )
    .expect("legacy cursor validates while authority is self-only");
    let err = paginate_page(Vec::new(), &AuditQuery::default(), &access, cursor, 1)
        .expect_err("widening after legacy validation must restart pagination");

    assert!(
        err.to_string().contains(CURSOR_SCOPE_CHANGED),
        "unexpected error: {err}"
    );
}

#[test]
fn legacy_cursor_rejects_firehose_resume() {
    let firehose_probe = super::super::events::CapabilityProbe::new(|_, _, _| true);
    let caller = PrincipalId::new("alice").unwrap();
    let access = AuditAccess {
        capability_probe: &firehose_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: None,
    };
    let cursor = parse_cursor(Some("1700000000_3")).expect("legacy cursor parses");
    let err = validate_cursor_scope(
        cursor.timestamp,
        cursor.scope.as_ref(),
        &AuditQuery::default(),
        &access,
    )
    .expect_err("legacy firehose resume must restart pagination");

    assert!(
        err.to_string().contains(CURSOR_SCOPE_CHANGED),
        "unexpected error: {err}"
    );
}

#[test]
fn legacy_cursor_rejects_explicit_principal_resume() {
    let firehose_probe = super::super::events::CapabilityProbe::new(|_, _, _| true);
    let caller = PrincipalId::new("alice").unwrap();
    let requested = PrincipalId::new("bob").unwrap();
    let access = AuditAccess {
        capability_probe: &firehose_probe,
        caller_principal: &caller,
        device_key_id: Some("0123456789abcdef"),
        requested_principal: Some(&requested),
    };
    let cursor = parse_cursor(Some("1700000000_3")).expect("legacy cursor parses");
    let query = AuditQuery {
        principal: Some("bob".into()),
        ..AuditQuery::default()
    };
    let err = validate_cursor_scope(cursor.timestamp, cursor.scope.as_ref(), &query, &access)
        .expect_err("legacy explicit-principal resume must restart pagination");

    assert!(
        err.to_string().contains(CURSOR_SCOPE_CHANGED),
        "unexpected error: {err}"
    );
}

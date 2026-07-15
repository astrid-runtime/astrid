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
        (None, 0, None),
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
        (None, 0, None),
        1,
    )
    .expect("page one");
    assert_eq!(
        page_one[0].method.as_deref(),
        Some("BobVisibleBeforeNarrowing")
    );
    assert_eq!(next_cursor.as_deref(), Some("1700000000_1_all"));

    let (cursor_ts, cursor_offset, cursor_scope) =
        parse_cursor(next_cursor.as_deref()).expect("page-one cursor parses");
    validate_cursor_scope(
        cursor_ts,
        cursor_scope.as_ref(),
        &AuditQuery::default(),
        &self_only_access,
    )
    .expect("all-scope cursor may narrow to self-only");
    let (page_two, next_cursor) = paginate_page(
        entries.clone(),
        &AuditQuery::default(),
        &self_only_access,
        (cursor_ts, cursor_offset, cursor_scope),
        1,
    )
    .expect("page two");
    assert_eq!(
        page_two[0].method.as_deref(),
        Some("AliceVisibleAfterNarrowing")
    );
    assert_eq!(next_cursor.as_deref(), Some("1700000000_3_p616c696365"));

    let (cursor_ts, cursor_offset, cursor_scope) =
        parse_cursor(next_cursor.as_deref()).expect("page-two cursor parses");
    validate_cursor_scope(
        cursor_ts,
        cursor_scope.as_ref(),
        &AuditQuery::default(),
        &self_only_access,
    )
    .expect("self-only cursor continues under same scope");
    let (page_three, next_cursor) = paginate_page(
        entries.clone(),
        &AuditQuery::default(),
        &self_only_access,
        (cursor_ts, cursor_offset, cursor_scope),
        1,
    )
    .expect("page three");
    assert_eq!(page_three[0].method.as_deref(), Some("AliceOlder"));
    assert_eq!(next_cursor.as_deref(), None);
}

#[test]
fn parse_cursor_handles_v1_v2_and_v3_shapes() {
    // v1 (legacy): bare integer, no underscore — offset
    // defaults to 0. We accept this shape so v0.7.0 cursors
    // already in flight don't fail the next paginated fetch.
    let (ts, off, scope) = parse_cursor(Some("1700000000")).expect("bare ts parses");
    assert_eq!(ts, Some(1_700_000_000));
    assert_eq!(off, 0);
    assert_eq!(scope, None);

    // v2: `<ts>_<offset>` — same-second batches resume cleanly
    // without losing or duplicating entries across the page
    // boundary.
    let (ts, off, scope) = parse_cursor(Some("1700000000_3")).expect("v2 cursor parses");
    assert_eq!(ts, Some(1_700_000_000));
    assert_eq!(off, 3);
    assert_eq!(scope, None);

    // v3: `<ts>_<offset>_<scope>` — carries the last page's
    // effective scope so incompatible widens fail closed.
    let (ts, off, scope) =
        parse_cursor(Some("1700000000_3_p616c696365")).expect("v3 cursor parses");
    assert_eq!(ts, Some(1_700_000_000));
    assert_eq!(off, 3);
    assert_eq!(
        scope,
        Some(CursorScope::Principal(PrincipalId::new("alice").unwrap()))
    );

    // None: no cursor → no positioning, start from newest.
    let (ts, off, scope) = parse_cursor(None).expect("None passes");
    assert_eq!(ts, None);
    assert_eq!(off, 0);
    assert_eq!(scope, None);

    // Garbage rejected with `BadRequest`.
    assert!(parse_cursor(Some("not-a-number")).is_err());
    assert!(parse_cursor(Some("123_not-a-number")).is_err());
    assert!(parse_cursor(Some("not-a-number_4")).is_err());
}

#[tokio::test]
async fn pagination_cursor_rejects_scope_widening_after_self_only_page() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::from_uuid(uuid::Uuid::nil());
    for (principal, method) in [
        ("alice", "AliceOlder"),
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
    let next_second = Timestamp::from_datetime(
        chrono::Utc
            .timestamp_opt(1_699_999_999, 0)
            .single()
            .unwrap(),
    );
    for entry in &mut entries[..2] {
        entry.timestamp = same_second;
    }
    entries[2].timestamp = next_second;

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
        (None, 0, None),
        1,
    )
    .expect("page one");
    assert_eq!(
        page_one[0].method.as_deref(),
        Some("AliceVisibleWhileScoped")
    );
    let (cursor_ts, _, cursor_scope) = parse_cursor(next_cursor.as_deref()).expect("cursor parses");
    let err = validate_cursor_scope(
        cursor_ts,
        cursor_scope.as_ref(),
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

    let err = paginate_page(entries, &AuditQuery::default(), &access, (None, 0, None), 3)
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

    let err = paginate_page(entries, &AuditQuery::default(), &access, (None, 0, None), 3)
        .expect_err("widening before the first visible row must not signal EOF");
    assert!(
        err.to_string().contains(CURSOR_SCOPE_CHANGED),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn principal_cursor_rejects_widening_during_skipped_rows() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::from_uuid(uuid::Uuid::nil());
    for (principal, method) in [
        ("alice", "AliceEligibleAfterCursor"),
        ("bob", "BobSkippedByCursor"),
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
    let cursor = (
        Some(cursor_ts),
        1,
        Some(CursorScope::Principal(caller.clone())),
    );

    validate_cursor_scope(cursor.0, cursor.2.as_ref(), &AuditQuery::default(), &access)
        .expect("principal cursor initially matches principal visibility");
    let err = paginate_page(entries, &AuditQuery::default(), &access, cursor, 1)
        .expect_err("widening while skipping cursor rows must restart pagination");
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

    validate_cursor_scope(cursor.0, cursor.2.as_ref(), &AuditQuery::default(), &access)
        .expect("legacy self-view cursor remains compatible");
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
    let err = validate_cursor_scope(cursor.0, cursor.2.as_ref(), &AuditQuery::default(), &access)
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
    let err = validate_cursor_scope(cursor.0, cursor.2.as_ref(), &query, &access)
        .expect_err("legacy explicit-principal resume must restart pagination");

    assert!(
        err.to_string().contains(CURSOR_SCOPE_CHANGED),
        "unexpected error: {err}"
    );
}

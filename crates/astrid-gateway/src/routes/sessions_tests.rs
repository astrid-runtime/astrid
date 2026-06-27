use super::*;

#[test]
fn resolve_limit_defaults_and_caps() {
    // Absent → default.
    assert_eq!(resolve_limit(None).unwrap(), DEFAULT_LIMIT);
    // Zero is "unset" → default (mirrors the audit endpoint).
    assert_eq!(resolve_limit(Some(0)).unwrap(), DEFAULT_LIMIT);
    // A sane value passes through unchanged.
    assert_eq!(resolve_limit(Some(25)).unwrap(), 25);
    // Exactly at the cap is allowed.
    assert_eq!(resolve_limit(Some(MAX_LIMIT)).unwrap(), MAX_LIMIT);
    // Over the cap is rejected as a client error.
    let err = resolve_limit(Some(MAX_LIMIT + 1)).unwrap_err();
    assert!(
        matches!(err, GatewayError::BadRequest(_)),
        "over-cap must be BadRequest"
    );
}

#[test]
fn validate_session_id_accepts_normal_ids() {
    // A UUID, the implicit default thread, and a dotted id all pass —
    // dots are explicitly allowed (the id never becomes a topic segment).
    validate_session_id("default").expect("default is valid");
    validate_session_id("550e8400-e29b-41d4-a716-446655440000").expect("uuid is valid");
    validate_session_id("a.b.c").expect("dotted id is valid");
}

#[test]
fn validate_session_id_rejects_abuse() {
    // Empty.
    assert!(matches!(
        validate_session_id("").unwrap_err(),
        GatewayError::BadRequest(_)
    ));
    // Too long.
    let too_long = "x".repeat(MAX_SESSION_ID_LEN + 1);
    assert!(matches!(
        validate_session_id(&too_long).unwrap_err(),
        GatewayError::BadRequest(_)
    ));
    // Exactly at the limit is fine.
    let at_limit = "x".repeat(MAX_SESSION_ID_LEN);
    validate_session_id(&at_limit).expect("max-length id is valid");
    // Control characters (newline, NUL, tab).
    for bad in ["a\nb", "a\0b", "a\tb"] {
        assert!(
            matches!(
                validate_session_id(bad).unwrap_err(),
                GatewayError::BadRequest(_)
            ),
            "control-char id {bad:?} must be rejected"
        );
    }
}

#[test]
fn build_list_payload_matches_frozen_contract() {
    // With cursor, limit, and include_archived present.
    let p = build_list_payload("corr-1", Some("opaque-cursor"), 50, true);
    assert_eq!(p["correlation_id"], "corr-1");
    assert_eq!(p["cursor"], "opaque-cursor");
    assert_eq!(p["limit"], 50);
    assert_eq!(p["include_archived"], true);
    // Absent cursor serializes as JSON null, not omitted — the frozen
    // contract is `"cursor": <string> | null`. include_archived defaults
    // to false at the handler.
    let p = build_list_payload("corr-2", None, 10, false);
    assert_eq!(p["cursor"], Value::Null);
    assert!(
        p.get("cursor").is_some(),
        "cursor key must be present as null"
    );
    assert_eq!(p["limit"], 10);
    assert_eq!(p["include_archived"], false);
}

#[test]
fn build_messages_payload_reuses_existing_verb() {
    let p = build_messages_payload("sess-7", "corr-9");
    assert_eq!(p["session_id"], "sess-7");
    assert_eq!(p["correlation_id"], "corr-9");
    // No extra fields leak into the existing capsule verb's payload.
    let obj = p.as_object().expect("payload is an object");
    assert_eq!(
        obj.len(),
        2,
        "get_messages payload must carry only session_id + correlation_id"
    );
}

#[test]
fn parse_list_response_round_trips_frozen_shape() {
    // A sample body matching the frozen `session.v1.response.list`
    // contract, including a fully-populated and a mostly-null element.
    let body = serde_json::json!({
        "correlation_id": "corr-1",
        "sessions": [
            {
                "session_id": "default",
                "message_count": 12,
                "created_at": 1_719_000_000_i64,
                "updated_at": 1_719_000_100_i64,
                "parent_session_id": "old-id",
                "preview": "first user message, truncated"
            },
            {
                "session_id": "fresh",
                "message_count": 0,
                "created_at": null,
                "updated_at": null,
                "parent_session_id": null,
                "preview": null
            }
        ],
        "next_cursor": "page-2",
        "total": 2
    });
    let parsed = parse_list_response(body).expect("frozen list shape must deserialize");
    assert_eq!(parsed.sessions.len(), 2);
    assert_eq!(parsed.next_cursor.as_deref(), Some("page-2"));
    assert_eq!(
        parsed.total,
        Some(2),
        "total is surfaced from the capsule reply"
    );

    let first = &parsed.sessions[0];
    assert_eq!(first.session_id, "default");
    assert_eq!(first.message_count, 12);
    assert_eq!(first.created_at, Some(1_719_000_000));
    assert_eq!(first.updated_at, Some(1_719_000_100));
    assert_eq!(first.parent_session_id.as_deref(), Some("old-id"));
    assert_eq!(
        first.preview.as_deref(),
        Some("first user message, truncated")
    );

    let second = &parsed.sessions[1];
    assert_eq!(second.session_id, "fresh");
    assert_eq!(second.message_count, 0);
    assert!(second.created_at.is_none());
    assert!(second.preview.is_none());
}

#[test]
fn parse_list_response_null_next_cursor_is_last_page() {
    let body = serde_json::json!({
        "correlation_id": "corr-1",
        "sessions": [],
        "next_cursor": null
    });
    let parsed = parse_list_response(body).expect("empty page must deserialize");
    assert!(parsed.sessions.is_empty());
    assert!(parsed.next_cursor.is_none());
}

#[test]
fn parse_list_response_rejects_garbage() {
    // A body the capsule never agreed to (sessions is a string) is an
    // upstream-shape error, surfaced as Kernel-class (502), not a 500.
    let body = serde_json::json!({ "sessions": "not-an-array" });
    let err = parse_list_response(body).unwrap_err();
    assert!(
        matches!(err, GatewayError::Kernel(_)),
        "bad upstream shape → Kernel"
    );
}

#[test]
fn parse_messages_response_passes_through_array() {
    let body = serde_json::json!({
        "correlation_id": "corr-1",
        "messages": [
            { "role": "user", "content": "hi" },
            { "role": "assistant", "content": "hello" }
        ]
    });
    let messages = parse_messages_response(&body).expect("messages must extract");
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["role"], "user");
    assert_eq!(messages[1]["content"], "hello");
}

#[test]
fn parse_messages_response_missing_field_is_empty_not_error() {
    // The capsule cannot distinguish "never existed" from "empty"; a
    // reply with no `messages` field maps to an empty transcript so we
    // never 404 / leak thread existence.
    let body = serde_json::json!({ "correlation_id": "corr-1" });
    let messages = parse_messages_response(&body).expect("missing messages → empty");
    assert!(messages.is_empty());
    // Explicit null is treated the same way.
    let body = serde_json::json!({ "correlation_id": "corr-1", "messages": null });
    assert!(parse_messages_response(&body).unwrap().is_empty());
}

#[test]
fn parse_messages_response_rejects_non_array() {
    let body = serde_json::json!({ "messages": "nope" });
    let err = parse_messages_response(&body).unwrap_err();
    assert!(
        matches!(err, GatewayError::Kernel(_)),
        "non-array messages → Kernel"
    );
}

/// Live round-trip over a real `EventBus`: publish a canned reply on
/// the scoped response topic and assert the helper returns it. Proves
/// the subscribe-first/publish/await loop and the correlation check
/// against the actual bus wiring, not a mock.
#[tokio::test]
async fn request_capsule_round_trips_scoped_reply() {
    let bus = Arc::new(EventBus::new());
    let principal = PrincipalId::new("alice").expect("valid principal");
    let correlation_id = "corr-rt-1";
    let response_topic = format!("{TOPIC_LIST_RESPONSE_PREFIX}.{correlation_id}");

    // Subscribe the stand-in capsule to the REQUEST topic HERE, before
    // anything publishes — broadcast channels don't replay history to a
    // late subscriber, so subscribing inside the spawned task would race
    // `request_capsule`'s publish and the request could be missed. The
    // capsule task then awaits on the already-live receiver and echoes a
    // frozen-shape reply on the scoped RESPONSE topic.
    let mut req_rx = bus.subscribe_topic(TOPIC_LIST_REQUEST.to_string());
    let bus_capsule = Arc::clone(&bus);
    let resp_topic = response_topic.clone();
    let cid = correlation_id.to_string();
    let capsule = tokio::spawn(async move {
        let event = req_rx.recv().await.expect("request arrives");
        // The stand-in capsule sees the request principal-stamped.
        if let AstridEvent::Ipc { message, .. } = &*event {
            assert_eq!(message.principal.as_deref(), Some("alice"));
            assert_ne!(message.source_id, Uuid::nil());
            assert_eq!(message.origin, MessageOrigin::RemoteGateway);
        } else {
            panic!("expected an IPC request event");
        }
        let reply = serde_json::json!({
            "correlation_id": cid,
            "sessions": [],
            "next_cursor": null
        });
        let mut msg = IpcMessage::new(
            Topic::from_raw(resp_topic.clone()),
            IpcPayload::RawJson(reply),
            session_capsule_source_id(),
        );
        if let AstridEvent::Ipc { message, .. } = &*event
            && let Some(principal) = &message.principal
        {
            msg = msg.with_principal(principal.clone());
        }
        bus_capsule.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test::capsule"),
            message: msg,
        });
    });

    let payload = build_list_payload(correlation_id, None, DEFAULT_LIMIT, false);
    let value = request_capsule(
        &bus,
        TOPIC_LIST_REQUEST,
        &response_topic,
        payload,
        correlation_id,
        &principal,
        None,
        CAPSULE_TIMEOUT,
    )
    .await
    .expect("helper returns the scoped reply");

    capsule.await.expect("stand-in capsule task joins");
    let parsed = parse_list_response(value).expect("reply deserializes");
    assert!(parsed.sessions.is_empty());
    assert!(parsed.next_cursor.is_none());
}

/// Real WASM capsule `publish_json` replies arrive at the gateway as
/// `IpcPayload::Custom { data }`. The gateway must unwrap the guest-visible
/// JSON body before checking correlation, not inspect the enum wrapper.
#[tokio::test]
async fn request_capsule_round_trips_custom_json_reply() {
    let bus = Arc::new(EventBus::new());
    let principal = PrincipalId::new("alice").expect("valid principal");
    let correlation_id = "corr-custom-1";
    let response_topic = format!("{TOPIC_LIST_RESPONSE_PREFIX}.{correlation_id}");

    let mut req_rx = bus.subscribe_topic(TOPIC_LIST_REQUEST.to_string());
    let bus_capsule = Arc::clone(&bus);
    let resp_topic = response_topic.clone();
    let cid = correlation_id.to_string();
    let capsule = tokio::spawn(async move {
        let event = req_rx.recv().await.expect("request arrives");
        let reply = serde_json::json!({
            "correlation_id": cid,
            "sessions": [],
            "next_cursor": null
        });
        let mut msg = IpcMessage::new(
            Topic::from_raw(resp_topic.clone()),
            IpcPayload::Custom { data: reply },
            session_capsule_source_id(),
        );
        if let AstridEvent::Ipc { message, .. } = &*event
            && let Some(principal) = &message.principal
        {
            msg = msg.with_principal(principal.clone());
        }
        bus_capsule.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test::capsule"),
            message: msg,
        });
    });

    let payload = build_list_payload(correlation_id, None, DEFAULT_LIMIT, false);
    let value = request_capsule(
        &bus,
        TOPIC_LIST_REQUEST,
        &response_topic,
        payload,
        correlation_id,
        &principal,
        None,
        CAPSULE_TIMEOUT,
    )
    .await
    .expect("helper returns the capsule publish_json reply");

    capsule.await.expect("stand-in capsule task joins");
    let parsed = parse_list_response(value).expect("reply deserializes");
    assert!(parsed.sessions.is_empty());
    assert!(parsed.next_cursor.is_none());
}

#[test]
fn resolve_search_limit_defaults_and_caps() {
    assert_eq!(resolve_search_limit(None).unwrap(), DEFAULT_SEARCH_LIMIT);
    assert_eq!(resolve_search_limit(Some(0)).unwrap(), DEFAULT_SEARCH_LIMIT);
    assert_eq!(resolve_search_limit(Some(50)).unwrap(), 50);
    assert_eq!(
        resolve_search_limit(Some(MAX_SEARCH_LIMIT)).unwrap(),
        MAX_SEARCH_LIMIT
    );
    assert!(matches!(
        resolve_search_limit(Some(MAX_SEARCH_LIMIT + 1)).unwrap_err(),
        GatewayError::BadRequest(_)
    ));
}

#[test]
fn validate_search_query_rejects_empty_and_trims() {
    // Empty / whitespace-only → 400.
    assert!(matches!(
        validate_search_query("").unwrap_err(),
        GatewayError::BadRequest(_)
    ));
    assert!(matches!(
        validate_search_query("   ").unwrap_err(),
        GatewayError::BadRequest(_)
    ));
    // A real query is trimmed and returned.
    assert_eq!(validate_search_query("  hello  ").unwrap(), "hello");
}

#[test]
fn build_update_payload_forwards_only_present_keys() {
    // Only `title` present → the patch carries `correlation_id`,
    // `session_id`, and `title`, but NOT `archived`/`meta` (absent =
    // unchanged, so the gateway must not synthesise them).
    let body = serde_json::json!({ "title": "renamed" });
    let p = build_update_payload("corr-1", "sess-1", &body).unwrap();
    let obj = p.as_object().unwrap();
    assert_eq!(obj["correlation_id"], "corr-1");
    assert_eq!(obj["session_id"], "sess-1");
    assert_eq!(obj["title"], "renamed");
    assert!(
        !obj.contains_key("archived"),
        "absent key must not be forwarded"
    );
    assert!(
        !obj.contains_key("meta"),
        "absent key must not be forwarded"
    );
}

#[test]
fn build_update_payload_preserves_clear_and_explicit_null() {
    // Present-and-`""` (clear) and present-and-archived=false must be
    // forwarded verbatim — they are distinct from absence.
    let body = serde_json::json!({ "title": "", "archived": false, "meta": "{}" });
    let p = build_update_payload("c", "s", &body).unwrap();
    let obj = p.as_object().unwrap();
    assert_eq!(obj["title"], "");
    assert_eq!(obj["archived"], false);
    assert_eq!(obj["meta"], "{}");
}

#[test]
fn build_update_payload_empty_body_is_correlation_and_session_only() {
    // `{}` body → an empty patch: only the gateway-set keys. The capsule
    // sees a no-op update (nothing changes), never a clobber.
    let body = serde_json::json!({});
    let p = build_update_payload("c", "s", &body).unwrap();
    let obj = p.as_object().unwrap();
    assert_eq!(
        obj.len(),
        2,
        "empty patch carries only correlation_id + session_id"
    );
    assert!(obj.contains_key("correlation_id"));
    assert!(obj.contains_key("session_id"));
}

#[test]
fn build_update_payload_ignores_unknown_keys() {
    // A client must not be able to smuggle arbitrary fields (e.g. another
    // principal's session_id override, or capsule-internal keys) into the
    // capsule's update via extra body keys. Only the three recognised keys
    // are forwarded; `session_id` is always the gateway's path value.
    let body = serde_json::json!({
        "title": "ok",
        "session_id": "attacker-controlled",
        "owner": "someone-else",
        "deleted": true
    });
    let p = build_update_payload("c", "path-session", &body).unwrap();
    let obj = p.as_object().unwrap();
    assert_eq!(
        obj["session_id"], "path-session",
        "path id wins, never the body"
    );
    assert!(!obj.contains_key("owner"));
    assert!(!obj.contains_key("deleted"));
    assert_eq!(obj.len(), 3, "only correlation_id + session_id + title");
}

#[test]
fn build_update_payload_rejects_non_object_body() {
    let body = serde_json::json!("not-an-object");
    assert!(matches!(
        build_update_payload("c", "s", &body).unwrap_err(),
        GatewayError::BadRequest(_)
    ));
}

#[test]
fn build_search_payload_matches_frozen_contract() {
    let p = build_search_payload("corr-1", "needle", 20, Some("cur"), true);
    assert_eq!(p["correlation_id"], "corr-1");
    assert_eq!(p["query"], "needle");
    assert_eq!(p["limit"], 20);
    assert_eq!(p["cursor"], "cur");
    assert_eq!(p["include_archived"], true);
    // Absent cursor serializes as null (key present), matching the frozen
    // `cursor: <string>|null` shape.
    let p = build_search_payload("c", "q", 5, None, false);
    assert_eq!(p["cursor"], Value::Null);
    assert!(p.get("cursor").is_some());
    assert_eq!(p["include_archived"], false);
}

#[test]
fn session_summary_round_trips_frozen_summary() {
    // The frozen SUMMARY shape, fully populated, then mostly-null.
    let full = serde_json::json!({
        "session_id": "default",
        "title": "Planning",
        "preview": "first user message",
        "last_message_preview": "latest line",
        "message_count": 12,
        "created_at": 1_719_000_000_i64,
        "updated_at": 1_719_000_100_i64,
        "archived": false,
        "parent_session_id": "old-id",
        "meta": "{\"k\":1}"
    });
    let s: SessionSummary = serde_json::from_value(full).expect("frozen SUMMARY deserializes");
    assert_eq!(s.session_id, "default");
    assert_eq!(s.title.as_deref(), Some("Planning"));
    assert_eq!(s.last_message_preview.as_deref(), Some("latest line"));
    assert!(!s.archived);
    assert_eq!(s.meta.as_deref(), Some("{\"k\":1}"));

    // Minimal/sparse element: only the always-present fields.
    let sparse = serde_json::json!({
        "session_id": "fresh",
        "message_count": 0,
        "archived": true
    });
    let s: SessionSummary = serde_json::from_value(sparse).expect("sparse SUMMARY deserializes");
    assert!(s.title.is_none());
    assert!(s.preview.is_none());
    assert!(s.last_message_preview.is_none());
    assert!(s.created_at.is_none());
    assert!(s.meta.is_none());
    assert!(s.archived);
}

#[test]
fn parse_session_field_null_is_none_for_404() {
    // Explicit null → None (the handler maps None to a 404).
    let null_reply = serde_json::json!({ "correlation_id": "c", "session": null });
    assert!(parse_session_field(&null_reply).unwrap().is_none());
    // Absent `session` → None too.
    let absent = serde_json::json!({ "correlation_id": "c" });
    assert!(parse_session_field(&absent).unwrap().is_none());
}

#[test]
fn parse_session_field_present_summary_deserializes() {
    let reply = serde_json::json!({
        "correlation_id": "c",
        "session": {
            "session_id": "s1",
            "title": "T",
            "message_count": 3,
            "archived": false
        }
    });
    let s = parse_session_field(&reply)
        .unwrap()
        .expect("present session");
    assert_eq!(s.session_id, "s1");
    assert_eq!(s.title.as_deref(), Some("T"));
    assert_eq!(s.message_count, 3);
}

#[test]
fn parse_session_field_rejects_garbage_session() {
    // `session` present but not an object the SUMMARY agrees to → Kernel.
    let reply = serde_json::json!({ "session": { "session_id": 42 } });
    assert!(matches!(
        parse_session_field(&reply).unwrap_err(),
        GatewayError::Kernel(_)
    ));
}

#[test]
fn parse_deleted_field_reads_bool_defaults_false() {
    assert!(parse_deleted_field(&serde_json::json!({ "deleted": true })));
    assert!(!parse_deleted_field(
        &serde_json::json!({ "deleted": false })
    ));
    // Missing / non-bool → false (idempotent no-op outcome).
    assert!(!parse_deleted_field(
        &serde_json::json!({ "correlation_id": "c" })
    ));
    assert!(!parse_deleted_field(
        &serde_json::json!({ "deleted": "yes" })
    ));
}

#[test]
fn parse_search_response_round_trips_frozen_shape() {
    let body = serde_json::json!({
        "correlation_id": "c",
        "results": [
            {
                "session_id": "s1",
                "title": "Trip planning",
                "snippet": "…book the flight…",
                "match_count": 2,
                "updated_at": 1_719_000_000_i64
            },
            { "session_id": "s2", "match_count": 1 }
        ],
        "next_cursor": "page-2"
    });
    let parsed = parse_search_response(body).expect("frozen search shape deserializes");
    assert_eq!(parsed.results.len(), 2);
    assert_eq!(parsed.next_cursor.as_deref(), Some("page-2"));
    let first = &parsed.results[0];
    assert_eq!(first.session_id, "s1");
    assert_eq!(first.title.as_deref(), Some("Trip planning"));
    assert_eq!(first.match_count, 2);
    assert_eq!(first.updated_at, Some(1_719_000_000));
    let second = &parsed.results[1];
    assert!(second.title.is_none());
    assert!(second.snippet.is_none());
    assert!(second.updated_at.is_none());
    assert_eq!(second.match_count, 1);
}

#[test]
fn parse_search_response_null_next_cursor_is_last_page() {
    let body = serde_json::json!({ "results": [], "next_cursor": null });
    let parsed = parse_search_response(body).expect("empty page deserializes");
    assert!(parsed.results.is_empty());
    assert!(parsed.next_cursor.is_none());
    // Absent next_cursor is also fine (defaults to None).
    let body = serde_json::json!({ "results": [] });
    assert!(parse_search_response(body).unwrap().next_cursor.is_none());
}

#[test]
fn parse_search_response_rejects_garbage() {
    let body = serde_json::json!({ "results": "not-an-array" });
    assert!(matches!(
        parse_search_response(body).unwrap_err(),
        GatewayError::Kernel(_)
    ));
}

/// Live round-trip over a real `EventBus` for the `update` verb: the
/// stand-in capsule receives the principal-stamped, present-keys-only
/// patch and replies with an updated SUMMARY on the scoped topic.
#[tokio::test]
async fn request_capsule_round_trips_update_reply() {
    let bus = Arc::new(EventBus::new());
    let principal = PrincipalId::new("alice").expect("valid principal");
    let correlation_id = "corr-upd-1";
    let response_topic = format!("{TOPIC_UPDATE_RESPONSE_PREFIX}.{correlation_id}");

    let mut req_rx = bus.subscribe_topic(TOPIC_UPDATE_REQUEST.to_string());
    let bus_capsule = Arc::clone(&bus);
    let resp_topic = response_topic.clone();
    let cid = correlation_id.to_string();
    let capsule = tokio::spawn(async move {
        let event = req_rx.recv().await.expect("request arrives");
        let AstridEvent::Ipc { message, .. } = &*event else {
            panic!("expected IPC request");
        };
        // Principal-stamped, and the patch carries only the sent key.
        assert_eq!(message.principal.as_deref(), Some("alice"));
        assert_ne!(message.source_id, Uuid::nil());
        assert_eq!(message.origin, MessageOrigin::RemoteGateway);
        if let IpcPayload::RawJson(v) = &message.payload {
            assert_eq!(v["title"], "renamed");
            assert!(v.get("archived").is_none(), "absent key not forwarded");
        } else {
            panic!("expected RawJson payload");
        }
        let reply = serde_json::json!({
            "correlation_id": cid,
            "session": {
                "session_id": "sess-1",
                "title": "renamed",
                "message_count": 4,
                "archived": false
            }
        });
        let mut msg = IpcMessage::new(
            Topic::from_raw(resp_topic),
            IpcPayload::RawJson(reply),
            session_capsule_source_id(),
        );
        if let Some(principal) = &message.principal {
            msg = msg.with_principal(principal.clone());
        }
        bus_capsule.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test::capsule"),
            message: msg,
        });
    });

    let body = serde_json::json!({ "title": "renamed" });
    let payload = build_update_payload(correlation_id, "sess-1", &body).unwrap();
    let value = request_capsule(
        &bus,
        TOPIC_UPDATE_REQUEST,
        &response_topic,
        payload,
        correlation_id,
        &principal,
        None,
        CAPSULE_TIMEOUT,
    )
    .await
    .expect("helper returns the scoped reply");

    capsule.await.expect("stand-in capsule joins");
    let summary = parse_session_field(&value)
        .unwrap()
        .expect("present session");
    assert_eq!(summary.session_id, "sess-1");
    assert_eq!(summary.title.as_deref(), Some("renamed"));
}

/// A reply stamped for a different principal is ignored. This protects a
/// same-topic reply from satisfying another caller's request.
#[tokio::test]
async fn request_capsule_ignores_wrong_principal_reply() {
    let bus = Arc::new(EventBus::new());
    let principal = PrincipalId::new("alice").expect("valid principal");
    let correlation_id = "corr-want-principal";
    let response_topic = format!("{TOPIC_LIST_RESPONSE_PREFIX}.{correlation_id}");

    let bus_bg = Arc::clone(&bus);
    let resp_topic = response_topic.clone();
    tokio::spawn(async move {
        tokio::task::yield_now().await;
        let reply = serde_json::json!({
            "correlation_id": "corr-want-principal",
            "sessions": [],
            "next_cursor": null
        });
        let msg = IpcMessage::new(
            Topic::from_raw(resp_topic),
            IpcPayload::RawJson(reply),
            session_capsule_source_id(),
        )
        .with_principal("mallory".to_string());
        bus_bg.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test::foreign"),
            message: msg,
        });
    });

    let payload = build_list_payload(correlation_id, None, DEFAULT_LIMIT, false);
    let err = request_capsule(
        &bus,
        TOPIC_LIST_REQUEST,
        &response_topic,
        payload,
        correlation_id,
        &principal,
        None,
        Duration::from_millis(150),
    )
    .await
    .expect_err("foreign-principal reply must not satisfy the request");
    assert!(matches!(err, GatewayError::Kernel(_)));
}

/// A same-principal, same-correlation reply from another capsule is ignored.
/// Principal and correlation are necessary but not sufficient: the response
/// must also come from the session capsule's kernel-stamped source id.
#[tokio::test]
async fn request_capsule_ignores_wrong_capsule_source_reply() {
    let bus = Arc::new(EventBus::new());
    let principal = PrincipalId::new("alice").expect("valid principal");
    let correlation_id = "corr-want-source";
    let response_topic = format!("{TOPIC_LIST_RESPONSE_PREFIX}.{correlation_id}");

    let bus_bg = Arc::clone(&bus);
    let resp_topic = response_topic.clone();
    tokio::spawn(async move {
        tokio::task::yield_now().await;
        let reply = serde_json::json!({
            "correlation_id": "corr-want-source",
            "sessions": [{
                "session_id": "ASTRID_ADVERSARIAL_POISON_SESSION",
                "message_count": 1
            }],
            "next_cursor": null
        });
        let wrong_source = Uuid::new_v5(&CAPSULE_ID_NAMESPACE, b"astrid-capsule-adversarial");
        let msg = IpcMessage::new(
            Topic::from_raw(resp_topic),
            IpcPayload::RawJson(reply),
            wrong_source,
        )
        .with_principal("alice".to_string());
        bus_bg.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test::adversarial-capsule"),
            message: msg,
        });
    });

    let payload = build_list_payload(correlation_id, None, DEFAULT_LIMIT, false);
    let err = request_capsule(
        &bus,
        TOPIC_LIST_REQUEST,
        &response_topic,
        payload,
        correlation_id,
        &principal,
        None,
        Duration::from_millis(150),
    )
    .await
    .expect_err("wrong-source reply must not satisfy the request");
    assert!(matches!(err, GatewayError::Kernel(_)));
}

/// A reply whose `correlation_id` does NOT match is skipped; the
/// helper keeps waiting and ultimately times out rather than
/// returning a foreign body. Proves the defensive correlation check.
#[tokio::test]
async fn request_capsule_ignores_mismatched_correlation() {
    let bus = Arc::new(EventBus::new());
    let principal = PrincipalId::new("alice").expect("valid principal");
    let correlation_id = "corr-want";
    let response_topic = format!("{TOPIC_LIST_RESPONSE_PREFIX}.{correlation_id}");

    // Publish a mismatched reply on the same scoped topic before the
    // helper's short timeout elapses.
    let bus_bg = Arc::clone(&bus);
    let resp_topic = response_topic.clone();
    tokio::spawn(async move {
        // Let the helper subscribe first.
        tokio::task::yield_now().await;
        let reply = serde_json::json!({
            "correlation_id": "corr-other",
            "sessions": [],
            "next_cursor": null
        });
        let msg = IpcMessage::new(
            Topic::from_raw(resp_topic),
            IpcPayload::RawJson(reply),
            session_capsule_source_id(),
        )
        .with_principal("alice".to_string());
        bus_bg.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test::foreign"),
            message: msg,
        });
    });

    let payload = build_list_payload(correlation_id, None, DEFAULT_LIMIT, false);
    let err = request_capsule(
        &bus,
        TOPIC_LIST_REQUEST,
        &response_topic,
        payload,
        correlation_id,
        &principal,
        None,
        // Short timeout — we expect the mismatched reply to be skipped
        // and the call to time out rather than return a foreign body.
        Duration::from_millis(150),
    )
    .await
    .expect_err("mismatched correlation must not satisfy the request");
    assert!(
        matches!(err, GatewayError::Kernel(_)),
        "timeout after skipping a foreign reply maps to Kernel-class"
    );
}

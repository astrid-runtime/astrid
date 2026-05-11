use super::*;
use astrid_events::EventBus;
use astrid_events::ipc::IpcPayload;

/// Publish N IPC messages to a bus and return a receiver subscribed to them.
fn publish_ipc_messages(bus: &EventBus, topic: &str, count: usize) {
    for i in 0..count {
        let msg = IpcMessage::new(
            topic,
            IpcPayload::Custom {
                data: serde_json::json!({"i": i}),
            },
            uuid::Uuid::new_v4(),
        );
        bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: msg,
        });
    }
}

#[test]
fn drain_receiver_collects_all_available_messages() {
    let bus = EventBus::new();
    let mut receiver = bus.subscribe_topic("test.topic");

    publish_ipc_messages(&bus, "test.topic", 5);

    let result = drain_receiver(&mut receiver, 10 * 1024 * 1024);
    assert_eq!(result.messages.len(), 5);
    assert_eq!(result.dropped, 0);
    assert_eq!(result.lagged, 0);
}

#[test]
fn drain_receiver_returns_empty_when_no_messages() {
    let bus = EventBus::new();
    let mut receiver = bus.subscribe_topic("test.topic");

    let result = drain_receiver(&mut receiver, 10 * 1024 * 1024);
    assert!(result.messages.is_empty());
    assert_eq!(result.dropped, 0);
    assert_eq!(result.lagged, 0);
}

#[test]
fn drain_receiver_drops_on_buffer_overflow() {
    let bus = EventBus::new();
    let mut receiver = bus.subscribe_topic("test.topic");

    // Publish messages — each has a small JSON payload.
    publish_ipc_messages(&bus, "test.topic", 10);

    // Use a tiny buffer limit so the drain hits the overflow.
    // Each message payload `{"i":0}` serializes to ~20+ bytes as IpcPayload.
    let result = drain_receiver(&mut receiver, 50);
    assert!(
        result.messages.len() < 10,
        "should not have drained all 10 with 50-byte limit, got {}",
        result.messages.len()
    );
    assert_eq!(
        result.dropped, 1,
        "one message should be dropped on overflow"
    );
}

#[test]
fn drain_receiver_surfaces_lag_from_broadcast_overflow() {
    // Tiny channel capacity to force lag.
    let bus = EventBus::with_capacity(2);
    let mut receiver = bus.subscribe_topic("test.topic");

    // Publish 5 messages into a capacity-2 channel — the receiver will lag.
    publish_ipc_messages(&bus, "test.topic", 5);

    let result = drain_receiver(&mut receiver, 10 * 1024 * 1024);
    assert!(
        result.lagged > 0,
        "expected lag from broadcast overflow, got 0"
    );
    // Should still receive the messages that weren't lost.
    assert!(
        !result.messages.is_empty(),
        "should still get some messages after lag"
    );
}

#[tokio::test]
async fn subscription_lifecycle_remove_and_reinsert() {
    // Tests the Mutex-drop-before-blocking pattern used by recv_impl:
    // remove receiver from subscriptions, use it, re-insert it.
    let bus = EventBus::new();
    let receiver = bus.subscribe_topic("test.*");

    let mut subscriptions = std::collections::HashMap::new();
    let handle_id: u64 = 42;
    subscriptions.insert(handle_id, receiver);

    // Remove (simulates the lock-drop pattern in recv_impl).
    let mut removed = subscriptions
        .remove(&handle_id)
        .expect("should find handle");
    assert!(
        !subscriptions.contains_key(&handle_id),
        "handle should be gone after remove"
    );

    // Publish while receiver is outside the map.
    publish_ipc_messages(&bus, "test.foo", 3);

    // Drain from the removed receiver — should still work.
    let result = drain_receiver(&mut removed, 10 * 1024 * 1024);
    assert_eq!(result.messages.len(), 3, "receiver should work outside map");

    // Re-insert.
    subscriptions.insert(handle_id, removed);
    assert!(
        subscriptions.contains_key(&handle_id),
        "handle should be back after re-insert"
    );

    // Publish more and verify the re-inserted receiver still works.
    publish_ipc_messages(&bus, "test.bar", 2);
    let receiver = subscriptions.get_mut(&handle_id).unwrap();
    let result = drain_receiver(receiver, 10 * 1024 * 1024);
    assert_eq!(
        result.messages.len(),
        2,
        "receiver should work after re-insert"
    );
}

#[tokio::test]
async fn recv_blocking_wake_plus_drain_burst() {
    // Simulates what recv_impl does: block on recv(), then drain remaining.
    let bus = EventBus::new();
    let mut receiver = bus.subscribe_topic("burst.*");

    let bus_clone = bus.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        // Publish 5 messages in a burst.
        publish_ipc_messages(&bus_clone, "burst.test", 5);
    });

    // Block until first message arrives.
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv())
        .await
        .expect("should not timeout")
        .expect("should get a message");

    // Small delay to let remaining messages arrive in the channel.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Drain remaining (simulates recv_impl's post-wake drain).
    let drain = drain_receiver(&mut receiver, 10 * 1024 * 1024);

    // The first message was consumed by recv(), drain gets the rest.
    let mut total = drain.messages.len() + 1; // +1 for the recv() message
    if let AstridEvent::Ipc { .. } = &*first {
        // first was a matching IPC message, count is correct.
    } else {
        total -= 1;
    }

    assert_eq!(
        total, 5,
        "should get all 5 messages (1 from recv + rest from drain)"
    );
}

/// Thin wrapper around the production deserialization path so we can
/// test it without a full WASM plugin context.
fn deserialize_publish_payload(payload_bytes: &[u8]) -> Result<IpcPayload, String> {
    serde_json::from_slice::<serde_json::Value>(payload_bytes)
        .map(IpcPayload::from_json_value)
        .map_err(|_| "IPC payload is not valid JSON".into())
}

#[test]
fn publish_unknown_type_tag_produces_custom() {
    let input = serde_json::json!({"type": "my_plugin_msg", "foo": 1});
    let bytes = serde_json::to_vec(&input).unwrap();
    let payload = deserialize_publish_payload(&bytes).unwrap();

    match payload {
        IpcPayload::Custom { data } => {
            assert_eq!(data["type"], "my_plugin_msg");
            assert_eq!(data["foo"], 1);
        },
        other => panic!("expected Custom, got {other:?}"),
    }
}

#[test]
fn publish_missing_type_tag_produces_custom() {
    let input = serde_json::json!({"foo": 1, "bar": "baz"});
    let bytes = serde_json::to_vec(&input).unwrap();
    let payload = deserialize_publish_payload(&bytes).unwrap();

    match payload {
        IpcPayload::Custom { data } => {
            assert_eq!(data["foo"], 1);
        },
        other => panic!("expected Custom, got {other:?}"),
    }
}

#[test]
fn publish_non_object_payload_produces_custom() {
    // A bare JSON string has no `type` field.
    let bytes = br#""hello""#;
    let payload = deserialize_publish_payload(bytes).unwrap();

    match payload {
        IpcPayload::Custom { data } => {
            assert_eq!(data, "hello");
        },
        other => panic!("expected Custom, got {other:?}"),
    }
}

#[test]
fn publish_known_type_tag_deserializes_correctly() {
    let input = serde_json::json!({"type": "connect"});
    let bytes = serde_json::to_vec(&input).unwrap();
    let payload = deserialize_publish_payload(&bytes).unwrap();

    assert_eq!(payload, IpcPayload::Connect);
}

#[test]
fn publish_known_tag_with_malformed_fields_falls_to_custom() {
    // `user_input` requires a `text` field. Without it, deserialization
    // fails and the .unwrap_or path produces Custom.
    let input = serde_json::json!({"type": "user_input"});
    let bytes = serde_json::to_vec(&input).unwrap();
    let payload = deserialize_publish_payload(&bytes).unwrap();

    match payload {
        IpcPayload::Custom { data } => {
            assert_eq!(data["type"], "user_input");
        },
        other => panic!("expected Custom (malformed known tag), got {other:?}"),
    }
}

#[test]
fn publish_custom_tag_with_data_unwraps_inner_value() {
    // A well-formed {"type": "custom", "data": {...}} should deserialize
    // via serde so that `data` is the inner value, not the outer wrapper.
    let input = serde_json::json!({"type": "custom", "data": {"foo": 1}});
    let bytes = serde_json::to_vec(&input).unwrap();
    let payload = deserialize_publish_payload(&bytes).unwrap();

    match payload {
        IpcPayload::Custom { data } => {
            assert_eq!(data, serde_json::json!({"foo": 1}));
        },
        other => panic!("expected Custom with inner data, got {other:?}"),
    }
}

#[test]
fn publish_invalid_json_is_error() {
    let result = deserialize_publish_payload(b"not json at all");
    assert!(result.is_err());
}

#[tokio::test]
async fn cancellation_token_unblocks_recv() {
    let bus = EventBus::new();
    let mut receiver = bus.subscribe_topic("cancel.test");
    let cancel_token = tokio_util::sync::CancellationToken::new();

    let token = cancel_token.clone();

    // Cancel after 50ms.
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        token.cancel();
    });

    // Block on recv with a long timeout. Cancellation should unblock it
    // well before the 60-second timeout.
    let start = std::time::Instant::now();
    let event = tokio::select! {
        result = tokio::time::timeout(
            std::time::Duration::from_millis(60_000),
            receiver.recv(),
        ) => result.ok().flatten(),
        () = cancel_token.cancelled() => None,
    };

    let elapsed = start.elapsed();
    assert!(event.is_none(), "should return None on cancellation");
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "should unblock promptly, took {elapsed:?}"
    );
}

#[test]
fn protected_interceptor_handle_rejects_unsubscribe() {
    // Simulate post-auto-subscribe state: handle 1 is in subscriptions
    // and flagged as protected (runtime-owned interceptor).
    let bus = EventBus::new();
    let receiver = bus.subscribe_topic("interceptor.topic");

    let mut subscriptions = std::collections::HashMap::new();
    let handle_id: u64 = 1;
    subscriptions.insert(handle_id, receiver);

    // The production function must reject protected handles.
    let result = remove_subscription(&mut subscriptions, true, handle_id);
    assert!(
        result.is_err(),
        "should reject unsubscribe on protected handle",
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("runtime-owned interceptor handle"),
        "error should mention interceptor handle",
    );

    // Subscription must still exist.
    assert!(
        subscriptions.contains_key(&handle_id),
        "protected subscription must survive unsubscribe attempt",
    );
}

#[test]
fn guest_handle_allows_unsubscribe() {
    // Guest-created handle (not protected) can be removed.
    let bus = EventBus::new();
    let receiver = bus.subscribe_topic("guest.topic");

    let mut subscriptions = std::collections::HashMap::new();
    let handle_id: u64 = 99;
    subscriptions.insert(handle_id, receiver);

    // The production function must allow unprotected handles.
    let result = remove_subscription(&mut subscriptions, false, handle_id);
    assert!(result.is_ok(), "should allow unsubscribe on guest handle");
    assert!(
        !subscriptions.contains_key(&handle_id),
        "subscription should be gone after removal",
    );
}

#[test]
fn unsubscribe_nonexistent_handle_returns_not_found() {
    let mut subscriptions = std::collections::HashMap::new();

    let result = remove_subscription(&mut subscriptions, false, 42);
    assert!(result.is_err(), "should reject nonexistent handle");
    assert!(
        result.unwrap_err().to_string().contains("not found"),
        "error should mention not found",
    );
}

// ── subscribe ACL tests ────────────────────────────────────────

#[test]
fn subscribe_acl_empty_patterns_denies() {
    let err = check_subscribe_acl("test-capsule", "any.topic", &[]).unwrap_err();
    assert!(err.contains("no ipc_subscribe declarations"));
}

#[test]
fn subscribe_acl_exact_match_allows() {
    let patterns = vec!["agent.v1.response".into()];
    assert!(check_subscribe_acl("test", "agent.v1.response", &patterns).is_ok());
}

#[test]
fn subscribe_acl_wildcard_matches_concrete() {
    let patterns = vec!["registry.v1.*".into()];
    assert!(check_subscribe_acl("test", "registry.v1.providers", &patterns).is_ok());
}

#[test]
fn subscribe_acl_segment_count_mismatch_denies() {
    // ACL has 3 segments, subscription has 4 - topic_matches requires equal count.
    let patterns = vec!["registry.v1.*".into()];
    let err = check_subscribe_acl("test", "registry.v1.selection.callback", &patterns).unwrap_err();
    assert!(err.contains("not allowed to subscribe"));
}

#[test]
fn subscribe_acl_wildcard_subscription_matches_wildcard_acl() {
    // A capsule with ACL "foo.*" is explicitly authorizing a "foo.*" subscription
    // (same pattern). The ACL check gates the subscription string, not individual
    // messages.
    let patterns = vec!["foo.*".into()];
    assert!(check_subscribe_acl("test", "foo.*", &patterns).is_ok());
}

#[test]
fn subscribe_acl_wildcard_subscription_denied_by_exact_acl() {
    // A capsule with ACL ["foo.bar"] must NOT be able to subscribe to "foo.*"
    // which would receive all foo.* events, not just foo.bar. This is the
    // primary scope-escalation prevention invariant.
    let patterns = vec!["foo.bar".into()];
    let result = check_subscribe_acl("test", "foo.*", &patterns);
    assert!(
        result.is_err(),
        "wildcard subscription must be denied by exact ACL"
    );
}

#[test]
fn subscribe_acl_unrelated_topic_denies() {
    let patterns = vec!["agent.v1.*".into()];
    let err = check_subscribe_acl("test", "session.v1.clear", &patterns).unwrap_err();
    assert!(err.contains("not allowed to subscribe"));
}

#[test]
fn subscribe_acl_multiple_patterns_second_matches() {
    let patterns = vec!["agent.v1.*".into(), "session.v1.response.*".into()];
    assert!(check_subscribe_acl("test", "session.v1.response.abc", &patterns).is_ok());
}

#[test]
fn subscribe_acl_malformed_pattern_silently_denies() {
    // A malformed ACL pattern (empty segments) causes topic_matches to
    // return false via has_valid_segments, resulting in a silent deny.
    // This is safe (fail-closed) but the error message is misleading.
    // See #374 for load-time validation of ipc_subscribe patterns.
    let patterns = vec!["foo..bar".into()];
    let result = check_subscribe_acl("test", "foo.x.bar", &patterns);
    assert!(
        result.is_err(),
        "malformed ACL pattern must not allow subscriptions"
    );
}

#[test]
fn publish_inner_quota_bucket_is_keyed_by_passed_principal() {
    // Regression: `publish_inner` used `state.effective_principal()` for the
    // quota bucket key, which for an uplink relaying via `ipc_publish_as`
    // resolves to the uplink's own principal — every relayed principal ends
    // up sharing one bucket, so one tenant can starve another's budget.
    // The fix uses the validated `principal_str` parameter as the key.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let mut state = crate::engine::wasm::test_fixtures::minimal_host_state(rt.handle().clone());
    state.has_uplink_capability = true;
    state.ipc_publish_patterns = vec!["uplink.*".into()];

    // Tight cap so two saturating sends to the SAME bucket would trip the
    // limiter on the second. Set on a custom invocation profile so the
    // host reads it via `effective_profile()`.
    let mut profile = astrid_core::profile::PrincipalProfile::default();
    profile.quotas.max_ipc_throughput_bytes = 200;
    state.invocation_profile = Some(std::sync::Arc::new(profile));

    // Valid JSON; the body is irrelevant — only the byte length is.
    let payload = format!("\"{}\"", "x".repeat(148)); // adds 2 for quotes → 150 bytes
    let topic = "uplink.relay".to_string();

    // First message charged to alice — fits her 200-byte bucket (uses 150).
    super::publish_inner(&mut state, topic.clone(), payload.clone(), "alice".into())
        .expect("alice first send fits her bucket");

    // Second message charged to bob — would fail if they shared a bucket
    // (150 + 150 = 300 > 200) but succeeds with separate buckets.
    super::publish_inner(&mut state, topic.clone(), payload.clone(), "bob".into())
        .expect("bob has his own bucket");

    // Third message back to alice's bucket — must now fail because alice
    // is at 150/200 and 150 more would bust the cap.
    let err = super::publish_inner(&mut state, topic, payload, "alice".into())
        .expect_err("alice's bucket should be saturated now");
    assert!(
        err.contains("Rate limit exceeded"),
        "expected rate-limit error, got: {err}"
    );
}

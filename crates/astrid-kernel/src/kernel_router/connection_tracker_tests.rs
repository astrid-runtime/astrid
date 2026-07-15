//! Unit tests for [`super::connection_signal`] — the classifier that lets the
//! connection tracker recognise both typed `IpcPayload::Connect`/`Disconnect`
//! (native producers) and the `client.v1.connect`/`client.v1.disconnect`
//! topics (uplink capsules, which can only publish JSON via the SDK).

use std::sync::Arc;

use astrid_events::AstridEvent;
use astrid_events::EventMetadata;
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};

use super::{
    CallerResolutionError, ConnectionSignal, connection_signal, resolve_connection_principal,
};

#[test]
fn typed_connect_payload_opens() {
    assert_eq!(
        connection_signal("client.v1.connect", &IpcPayload::Connect),
        Some(ConnectionSignal::Opened)
    );
}

#[test]
fn typed_disconnect_payload_closes() {
    let payload = IpcPayload::Disconnect {
        reason: Some("quit".to_string()),
    };
    assert_eq!(
        connection_signal("client.v1.disconnect", &payload),
        Some(ConnectionSignal::Closed {
            reason: Some("quit".to_string())
        })
    );
}

#[test]
fn typed_disconnect_without_reason_closes() {
    let payload = IpcPayload::Disconnect { reason: None };
    assert_eq!(
        connection_signal("client.v1.disconnect", &payload),
        Some(ConnectionSignal::Closed { reason: None })
    );
}

#[test]
fn connected_topic_with_json_payload_opens() {
    // The capsule path: the CLI proxy can only publish JSON, so the typed
    // variant is never present — the topic is the sole signal.
    let payload = IpcPayload::RawJson(serde_json::json!({ "principal": "alice" }));
    assert_eq!(
        connection_signal("client.v1.connect", &payload),
        Some(ConnectionSignal::Opened)
    );
}

#[test]
fn disconnect_topic_with_json_payload_closes_and_extracts_reason() {
    let payload = IpcPayload::RawJson(serde_json::json!({ "reason": "quit" }));
    assert_eq!(
        connection_signal("client.v1.disconnect", &payload),
        Some(ConnectionSignal::Closed {
            reason: Some("quit".to_string())
        })
    );
}

#[test]
fn disconnect_topic_with_json_payload_without_reason_closes() {
    // Reason is optional — a JSON disconnect with no `reason` key still closes.
    let payload = IpcPayload::RawJson(serde_json::json!({ "principal": "alice" }));
    assert_eq!(
        connection_signal("client.v1.disconnect", &payload),
        Some(ConnectionSignal::Closed { reason: None })
    );
}

#[test]
fn unrelated_client_topic_is_ignored() {
    // Other `client.v1.*` traffic (the tracker subscribes to the whole prefix)
    // must not move the connection counter.
    let payload = IpcPayload::RawJson(serde_json::json!({ "hello": "world" }));
    assert_eq!(connection_signal("client.v1.heartbeat", &payload), None);
    assert_eq!(connection_signal("client.v1.prompt", &payload), None);
}

#[test]
fn typed_payload_wins_even_on_an_unrelated_topic() {
    // A native producer's typed payload is honoured regardless of topic, so a
    // mismatched topic never suppresses a real connection event.
    assert_eq!(
        connection_signal("some.other.topic", &IpcPayload::Connect),
        Some(ConnectionSignal::Opened)
    );
    assert_eq!(
        connection_signal("some.other.topic", &IpcPayload::Disconnect { reason: None }),
        Some(ConnectionSignal::Closed { reason: None })
    );
}

#[test]
fn missing_connection_principal_maps_to_anonymous_not_default() {
    let message = IpcMessage::new(
        Topic::client_connect(),
        IpcPayload::Connect,
        uuid::Uuid::nil(),
    );
    let principal = resolve_connection_principal(&message).expect("anonymous identity");
    assert_eq!(principal, astrid_core::PrincipalId::anonymous());
    assert_ne!(principal, astrid_core::PrincipalId::default());
}

#[test]
fn malformed_connection_principal_is_ignored_not_defaulted() {
    let message = IpcMessage::new(
        Topic::client_connect(),
        IpcPayload::Connect,
        uuid::Uuid::nil(),
    )
    .with_principal("alice@evil.example");
    assert_eq!(
        resolve_connection_principal(&message),
        Err(CallerResolutionError::Invalid)
    );
}

// ── End-to-end counter balance through the live tracker ──────────────────
//
// The classifier tests above are pure. These drive the real
// `spawn_connection_tracker` task against a live `Kernel` event bus,
// publishing the exact `client.v1.connect` / `client.v1.disconnect` shape the
// HOST now emits (it used to come from the capsule-cli proxy). They guard the
// connection-tracker leak fix: connect and disconnect for one connection carry
// the IDENTICAL principal, so the per-principal counter returns to baseline.
//
// The leak this regresses: the proxy published `client.v1.disconnect` AFTER
// the connection closed, so the host stamped it `anonymous` instead of the
// real principal — connect incremented `default` and disconnect decremented
// `anonymous` (a saturating no-op), leaking `+1` per connection. Moving
// emission into the host pairs both events on one verified principal.

/// Publish a host-shaped `client.v1.connect` for `principal` onto the bus.
fn publish_connect(kernel: &crate::Kernel, principal: &str) {
    let message = IpcMessage::new(
        Topic::client_connect(),
        IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::nil(),
    )
    .with_principal(principal);
    kernel.event_bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("test").with_session_id(uuid::Uuid::nil()),
        message,
    });
}

/// Publish a host-shaped `client.v1.disconnect` for `principal` onto the bus.
fn publish_disconnect(kernel: &crate::Kernel, principal: &str) {
    let message = IpcMessage::new(
        Topic::client_disconnect(),
        IpcPayload::RawJson(serde_json::json!({ "reason": "socket closed" })),
        uuid::Uuid::nil(),
    )
    .with_principal(principal);
    kernel.event_bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("test").with_session_id(uuid::Uuid::nil()),
        message,
    });
}

/// Poll `cond` until it holds or the attempt budget is exhausted. The tracker
/// processes events on a spawned task, so the counter updates asynchronously
/// after a publish; this yields between checks rather than sleeping a fixed
/// duration.
async fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..2000 {
        if cond() {
            return true;
        }
        tokio::task::yield_now().await;
        astrid_runtime::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    cond()
}

/// N matched connect+disconnect cycles for one verified principal return the
/// global AND per-principal counts to baseline (zero). This is the leak
/// regression: a disconnect that lost its principal would decrement a DIFFERENT
/// key, leaving this principal's count stuck at N.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matched_cycles_balance_to_baseline_for_verified_principal() {
    /// Matched connect/disconnect cycles to drive through the tracker.
    const CYCLES: usize = 5;

    let dir = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    drop(super::spawn_connection_tracker(Arc::clone(&kernel)));

    let principal = astrid_core::PrincipalId::new("claude-code").unwrap();
    assert_eq!(kernel.total_connection_count(), 0, "baseline");

    for _ in 0..CYCLES {
        publish_connect(&kernel, principal.as_str());
        assert!(
            wait_until(|| kernel.total_connection_count() == 1).await,
            "connect should raise the count to 1"
        );

        publish_disconnect(&kernel, principal.as_str());
        assert!(
            wait_until(|| kernel.total_connection_count() == 0).await,
            "disconnect must return the count to 0 — a leak leaves it at 1"
        );
    }

    assert_eq!(
        kernel.total_connection_count(),
        0,
        "after {CYCLES} matched cycles the global count is back to baseline"
    );
    assert!(
        kernel
            .connections_by_principal()
            .iter()
            .all(|(p, _)| *p != principal),
        "the verified principal must hold no residual connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_principal_lifecycle_balances_under_anonymous() {
    let dir = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    drop(super::spawn_connection_tracker(Arc::clone(&kernel)));

    for (topic, expected) in [
        (Topic::client_connect(), 1),
        (Topic::client_disconnect(), 0),
    ] {
        let message = IpcMessage::new(
            topic,
            IpcPayload::RawJson(serde_json::json!({})),
            uuid::Uuid::nil(),
        );
        let _ = kernel.event_bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test").with_session_id(uuid::Uuid::nil()),
            message,
        });
        assert!(
            wait_until(|| kernel.total_connection_count() == expected).await,
            "anonymous lifecycle count should become {expected}"
        );
    }

    assert!(
        kernel
            .connections_by_principal()
            .iter()
            .all(|(principal, _)| *principal != astrid_core::PrincipalId::default()),
        "missing lifecycle identity must never touch the bootstrap principal"
    );
}

/// The historical leak, reproduced as a guard: a connect stamped with the real
/// principal but a disconnect stamped `anonymous` (what the proxy produced
/// post-close) does NOT balance — the real principal stays at 1 while
/// `anonymous` saturates at 0. This asserts the buggy pairing is detectably
/// broken, so the fix (identical-principal pairing) is load-bearing, not
/// incidental.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mismatched_principal_pairing_leaks_as_the_original_bug_did() {
    let dir = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    drop(super::spawn_connection_tracker(Arc::clone(&kernel)));

    publish_connect(&kernel, "claude-code");
    assert!(
        wait_until(|| kernel.total_connection_count() == 1).await,
        "connect raises the count"
    );

    // Disconnect stamped with the WRONG principal (the old anonymous-stamp
    // bug). It decrements `anonymous` (saturating no-op), not `claude-code`.
    let anon = astrid_core::PrincipalId::anonymous();
    publish_disconnect(&kernel, anon.as_str());
    // Give the tracker ample opportunity to process before asserting the leak.
    let _ = wait_until(|| false).await;

    assert_eq!(
        kernel.total_connection_count(),
        1,
        "a principal-mismatched disconnect leaks — claude-code stays at 1"
    );
    assert!(
        kernel
            .connections_by_principal()
            .iter()
            .any(|(p, c)| p.as_str() == "claude-code" && *c == 1),
        "the leak lands on the original (connect) principal"
    );
}

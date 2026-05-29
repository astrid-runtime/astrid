//! Unit tests for [`super::connection_signal`] — the classifier that lets the
//! connection tracker recognise both typed `IpcPayload::Connect`/`Disconnect`
//! (native producers) and the `client.v1.connected`/`client.v1.disconnect`
//! topics (uplink capsules, which can only publish JSON via the SDK).

use astrid_events::ipc::IpcPayload;

use super::{ConnectionSignal, connection_signal};

#[test]
fn typed_connect_payload_opens() {
    assert_eq!(
        connection_signal("client.v1.connected", &IpcPayload::Connect),
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
        Some(ConnectionSignal::Closed)
    );
}

#[test]
fn typed_disconnect_without_reason_closes() {
    let payload = IpcPayload::Disconnect { reason: None };
    assert_eq!(
        connection_signal("client.v1.disconnect", &payload),
        Some(ConnectionSignal::Closed)
    );
}

#[test]
fn connected_topic_with_json_payload_opens() {
    // The capsule path: the CLI proxy can only publish JSON, so the typed
    // variant is never present — the topic is the sole signal.
    let payload = IpcPayload::RawJson(serde_json::json!({ "principal": "alice" }));
    assert_eq!(
        connection_signal("client.v1.connected", &payload),
        Some(ConnectionSignal::Opened)
    );
}

#[test]
fn disconnect_topic_with_json_payload_closes() {
    let payload = IpcPayload::RawJson(serde_json::json!({ "reason": "quit" }));
    assert_eq!(
        connection_signal("client.v1.disconnect", &payload),
        Some(ConnectionSignal::Closed)
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
        Some(ConnectionSignal::Closed)
    );
}

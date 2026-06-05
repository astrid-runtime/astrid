//! Integration-level tests for `AstridClientHandler`.
//!
//! These tests exercise `handle_inbound_message` and the full inbound
//! message pipeline, including size limits, plugin-ID anti-spoofing,
//! channel resolution, and uplink fallback behaviour.

use std::sync::{Arc, Mutex, PoisonError};

use astrid_core::{
    InboundMessage, UplinkCapabilities, UplinkDescriptor, UplinkId, UplinkProfile, UplinkSource,
};
use tokio::sync::mpsc;

use super::super::handler::CapabilitiesHandler;
use super::bridge::{MAX_CHANNEL_NAME_LEN, MAX_CHANNELS_PER_CAPSULE};
use super::handler::AstridClientHandler;
use super::notice::{
    MAX_CONTEXT_BYTES, MAX_NOTIFICATION_PAYLOAD_BYTES, MAX_PLATFORM_USER_ID_BYTES,
};

// ─── Test helpers ─────────────────────────────────────────────────────────────

/// Build a handler wired to inbound channel + shared uplinks.
fn test_handler(
    capsule_id: &str,
) -> (
    AstridClientHandler,
    mpsc::Receiver<InboundMessage>,
    Arc<Mutex<Vec<UplinkDescriptor>>>,
) {
    let (inbound_tx, inbound_rx) = mpsc::channel(256);
    let shared = Arc::new(Mutex::new(Vec::new()));
    let handler = AstridClientHandler::new("test-server", Arc::new(CapabilitiesHandler::new()))
        .with_capsule_id(capsule_id)
        .with_inbound_tx(inbound_tx)
        .with_shared_uplinks(Arc::clone(&shared));
    (handler, inbound_rx, shared)
}

/// Register a uplink in `shared_uplinks` for inbound message tests.
///
/// This simulates what `register_channels_locally` does during
/// `on_custom_notification`.
fn register_test_uplink(
    shared: &Arc<Mutex<Vec<UplinkDescriptor>>>,
    name: &str,
    platform: &str,
    capsule_id: &str,
) -> UplinkId {
    let source = UplinkSource::new_bridge(capsule_id).expect("valid capsule_id");
    let descriptor = UplinkDescriptor::builder(name, platform)
        .source(source)
        .profile(UplinkProfile::Bridge)
        .capabilities(UplinkCapabilities::receive_only())
        .build();
    let id = descriptor.id;
    shared
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(descriptor);
    id
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn test_inbound_message_notification() {
    let (handler, mut inbound_rx, shared) = test_handler("test-plugin");

    let expected_id = register_test_uplink(&shared, "telegram", "telegram", "test-plugin");

    let msg_params = serde_json::json!({
        "capsuleId": "test-plugin",
        "content": "Hello from Telegram",
        "context": {
            "channel": "telegram",
            "from": { "id": "user-123" }
        }
    });
    handler.handle_inbound_message(Some(msg_params));

    let msg = inbound_rx.try_recv().expect("should receive message");
    assert_eq!(msg.uplink_id, expected_id);
    assert_eq!(msg.platform, "telegram");
    assert_eq!(msg.platform_user_id, "user-123");
    assert_eq!(msg.content, "Hello from Telegram");
}

#[test]
fn test_inbound_message_oversized_rejected() {
    let (handler, mut rx, _) = test_handler("test-plugin");

    let big_content = "x".repeat(MAX_NOTIFICATION_PAYLOAD_BYTES + 100);
    let params = serde_json::json!({
        "capsuleId": "test-plugin",
        "content": big_content,
        "context": {}
    });

    handler.handle_inbound_message(Some(params));
    assert!(
        rx.try_recv().is_err(),
        "oversized message should be rejected"
    );
}

#[test]
fn test_inbound_message_full_channel_drops() {
    let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
    let handler = AstridClientHandler::new("test-server", Arc::new(CapabilitiesHandler::new()))
        .with_capsule_id("test-plugin")
        .with_inbound_tx(inbound_tx);

    let make_params = || {
        serde_json::json!({
            "capsuleId": "test-plugin",
            "content": "msg",
            "context": {}
        })
    };

    handler.handle_inbound_message(Some(make_params()));
    handler.handle_inbound_message(Some(make_params()));

    assert!(
        inbound_rx.try_recv().is_ok(),
        "first message should be present"
    );
    assert!(
        inbound_rx.try_recv().is_err(),
        "second message should have been dropped"
    );
}

#[test]
fn test_inbound_message_capsule_id_mismatch() {
    let (handler, mut rx, _) = test_handler("test-plugin");

    let params = serde_json::json!({
        "capsuleId": "evil-plugin",
        "content": "hijack",
        "context": {}
    });

    handler.handle_inbound_message(Some(params));
    assert!(
        rx.try_recv().is_err(),
        "mismatched capsule_id should be rejected"
    );
}

#[test]
fn test_inbound_message_no_uplinks_fallback() {
    let (handler, mut inbound_rx, _) = test_handler("test-plugin");

    let params = serde_json::json!({
        "capsuleId": "test-plugin",
        "content": "orphan message",
        "context": { "from": { "id": "user-1" } }
    });
    handler.handle_inbound_message(Some(params));

    let msg = inbound_rx.try_recv().expect("should receive message");
    assert_eq!(msg.content, "orphan message");
    assert!(!msg.platform.is_empty());
}

#[test]
fn test_inbound_message_non_matching_channel() {
    let (handler, mut inbound_rx, shared) = test_handler("test-plugin");

    register_test_uplink(&shared, "telegram", "telegram", "test-plugin");

    let msg_params = serde_json::json!({
        "capsuleId": "test-plugin",
        "content": "wrong channel",
        "context": { "channel": "discord" }
    });
    handler.handle_inbound_message(Some(msg_params));

    let msg = inbound_rx.try_recv().expect("should receive message");
    assert_eq!(msg.platform, "telegram");
}

#[test]
fn test_inbound_message_empty_capsule_id_rejected() {
    let (inbound_tx, mut inbound_rx) = mpsc::channel(256);
    let handler = AstridClientHandler::new("test-server", Arc::new(CapabilitiesHandler::new()))
        .with_capsule_id("")
        .with_inbound_tx(inbound_tx);

    let params = serde_json::json!({
        "capsuleId": "",
        "content": "sneaky",
        "context": {}
    });
    handler.handle_inbound_message(Some(params));
    assert!(
        inbound_rx.try_recv().is_err(),
        "empty capsule_id should be rejected"
    );
}

#[test]
fn test_inbound_message_non_string_content() {
    let (handler, mut inbound_rx, _) = test_handler("test-plugin");

    let params = serde_json::json!({
        "capsuleId": "test-plugin",
        "content": { "type": "image", "url": "https://example.com/pic.png" },
        "context": {}
    });
    handler.handle_inbound_message(Some(params));

    let msg = inbound_rx.try_recv().expect("should receive message");
    let parsed: serde_json::Value =
        serde_json::from_str(&msg.content).expect("content should be valid JSON");
    assert_eq!(parsed["type"], "image");
    assert_eq!(parsed["url"], "https://example.com/pic.png");
}

#[test]
fn test_inbound_message_oversized_context_rejected() {
    let (handler, mut inbound_rx, _) = test_handler("test-plugin");

    let big_context = "x".repeat(MAX_CONTEXT_BYTES + 100);
    let params = serde_json::json!({
        "capsuleId": "test-plugin",
        "content": "msg",
        "context": { "data": big_context }
    });
    handler.handle_inbound_message(Some(params));
    assert!(
        inbound_rx.try_recv().is_err(),
        "oversized context should be rejected"
    );
}

#[test]
fn test_handlers_reject_missing_params() {
    let (handler, mut inbound_rx, _) = test_handler("test-plugin");
    handler.handle_inbound_message(None);
    assert!(inbound_rx.try_recv().is_err());
}

#[test]
fn test_inbound_message_channel_name_fallback_key() {
    let (handler, mut inbound_rx, shared) = test_handler("test-plugin");

    let expected_id = register_test_uplink(&shared, "telegram", "telegram", "test-plugin");

    let msg_params = serde_json::json!({
        "capsuleId": "test-plugin",
        "content": "via channelName",
        "context": {
            "channelName": "telegram",
            "from": { "id": "user-1" }
        }
    });
    handler.handle_inbound_message(Some(msg_params));

    let msg = inbound_rx.try_recv().expect("should receive message");
    assert_eq!(msg.uplink_id, expected_id);
    assert_eq!(msg.content, "via channelName");
}

#[test]
fn test_inbound_message_null_content_rejected() {
    let (handler, mut inbound_rx, _) = test_handler("test-plugin");

    let params = serde_json::json!({
        "capsuleId": "test-plugin",
        "content": null,
        "context": {}
    });
    handler.handle_inbound_message(Some(params));

    assert!(
        inbound_rx.try_recv().is_err(),
        "null content should be rejected"
    );
}

#[test]
fn test_handlers_accept_valid_payloads() {
    let (handler, mut inbound_rx, _) = test_handler("test-plugin");

    let msg_params = serde_json::json!({
        "capsuleId": "test-plugin",
        "content": "dispatch test",
        "context": {}
    });
    handler.handle_inbound_message(Some(msg_params));
    assert!(
        inbound_rx.try_recv().is_ok(),
        "inboundMessage should dispatch"
    );
}

#[test]
fn test_handlers_no_channels_configured() {
    let handler = AstridClientHandler::new("test-server", Arc::new(CapabilitiesHandler::new()));

    // Should not panic — simply logs and returns
    handler.handle_inbound_message(Some(serde_json::json!({
        "capsuleId": "test",
        "content": "msg",
        "context": {}
    })));
}

#[test]
fn test_inbound_message_empty_string_content_rejected() {
    let (handler, mut inbound_rx, _) = test_handler("test-plugin");

    let params = serde_json::json!({
        "capsuleId": "test-plugin",
        "content": "",
        "context": {}
    });
    handler.handle_inbound_message(Some(params));

    assert!(
        inbound_rx.try_recv().is_err(),
        "empty string content should be rejected"
    );
}

#[test]
fn test_inbound_message_missing_capsule_id_field() {
    let (handler, mut rx, _) = test_handler("test-plugin");
    let params = serde_json::json!({
        "content": "msg",
        "context": {}
    });
    handler.handle_inbound_message(Some(params));
    assert!(
        rx.try_recv().is_err(),
        "missing pluginId field should be rejected"
    );
}

#[test]
fn test_inbound_message_oversized_non_string_content_rejected() {
    let (handler, mut inbound_rx, _) = test_handler("test-plugin");
    let big_array: Vec<String> = (0..50_000).map(|i| format!("item-{i:020}")).collect();
    let params = serde_json::json!({
        "capsuleId": "test-plugin",
        "content": big_array,
        "context": {}
    });
    handler.handle_inbound_message(Some(params));
    assert!(
        inbound_rx.try_recv().is_err(),
        "oversized serialized content should be rejected"
    );
}

#[test]
fn test_inbound_message_non_string_capsule_id_rejected() {
    let (handler, mut rx, _) = test_handler("test-plugin");
    let params = serde_json::json!({
        "capsuleId": 42,
        "content": "msg",
        "context": {}
    });
    handler.handle_inbound_message(Some(params));
    assert!(
        rx.try_recv().is_err(),
        "non-string pluginId should be rejected"
    );
}

#[test]
fn test_inbound_message_null_context() {
    let (handler, mut inbound_rx, _) = test_handler("test-plugin");

    let params = serde_json::json!({
        "capsuleId": "test-plugin",
        "content": "hello",
        "context": null
    });
    handler.handle_inbound_message(Some(params));

    let msg = inbound_rx.try_recv().expect("should handle null context");
    assert_eq!(msg.content, "hello");
    assert_eq!(msg.platform_user_id, "unknown");
}

#[test]
fn test_inbound_message_absent_context() {
    let (handler, mut inbound_rx, _) = test_handler("test-plugin");

    let params = serde_json::json!({
        "capsuleId": "test-plugin",
        "content": "hello"
    });
    handler.handle_inbound_message(Some(params));

    let msg = inbound_rx.try_recv().expect("should handle absent context");
    assert_eq!(msg.content, "hello");
    assert_eq!(msg.platform_user_id, "unknown");
}

#[test]
fn test_inbound_message_string_content_size_limit() {
    let (handler, mut inbound_rx, _) = test_handler("test-plugin");

    let huge_string = "x".repeat(MAX_NOTIFICATION_PAYLOAD_BYTES + 1);
    let params = serde_json::json!({
        "capsuleId": "test-plugin",
        "content": huge_string,
        "context": {}
    });
    handler.handle_inbound_message(Some(params));

    assert!(
        inbound_rx.try_recv().is_err(),
        "oversized string content should be rejected"
    );
}

#[test]
fn test_inbound_message_missing_content() {
    let (handler, mut inbound_rx, _) = test_handler("test-plugin");

    let params = serde_json::json!({
        "capsuleId": "test-plugin",
        "context": { "from": { "id": "user-1" } }
    });
    handler.handle_inbound_message(Some(params));

    assert!(
        inbound_rx.try_recv().is_err(),
        "missing content field should be rejected"
    );
}

// ─── Constant value regression guards ─────────────────────────────────────────

#[test]
fn test_size_constants_have_expected_values() {
    // Regression guard: accidental changes to these limits would silently
    // weaken security bounds or break wire compatibility.
    assert_eq!(MAX_NOTIFICATION_PAYLOAD_BYTES, 1_024 * 1_024); // 1 MB
    assert_eq!(MAX_CONTEXT_BYTES, 64 * 1024); // 64 KB
    assert_eq!(MAX_PLATFORM_USER_ID_BYTES, 512);
    assert_eq!(MAX_CHANNEL_NAME_LEN, 128);
    assert_eq!(
        MAX_CHANNELS_PER_CAPSULE,
        astrid_core::MAX_UPLINKS_PER_CAPSULE
    );
}

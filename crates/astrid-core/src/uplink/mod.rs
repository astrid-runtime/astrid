//! Uplink abstraction - unified types for platforms, capsules, and bridges.
//!
//! A **uplink** is any component that can send or receive messages on behalf
//! of the Astrid runtime. The three current flavours are:
//!
//! | Source | Example |
//! |--------|---------|
//! | [`UplinkSource::Native`] | CLI capsule uplink |
//! | [`UplinkSource::Wasm`] | WASM capsule providing a tool |
//! | [`UplinkSource::Bridge`] | Protocol-bridged capsule |

// ---------------------------------------------------------------------------

/// Error types for uplinks.
pub(crate) mod error;
/// Core types for uplinks.
pub(crate) mod types;

pub use error::{UplinkError, UplinkResult};
pub use types::*;

// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use uuid::Uuid;

    // -- UplinkId --

    #[test]
    fn uplink_id_uniqueness() {
        let a = UplinkId::new();
        let b = UplinkId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn uplink_id_display_matches_uuid() {
        let uuid = Uuid::new_v4();
        let id = UplinkId::from_uuid(uuid);
        assert_eq!(id.to_string(), uuid.to_string());
    }

    #[test]
    fn uplink_id_roundtrip_serde() {
        let id = UplinkId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: UplinkId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // -- UplinkCapabilities --

    #[test]
    fn capabilities_full() {
        let c = UplinkCapabilities::full();
        assert!(c.can_receive);
        assert!(c.can_send);
        assert!(c.can_approve);
        assert!(c.can_elicit);
        assert!(c.supports_rich_media);
        assert!(c.supports_threads);
        assert!(c.supports_buttons);
    }

    #[test]
    fn capabilities_notify_only() {
        let c = UplinkCapabilities::notify_only();
        assert!(!c.can_receive);
        assert!(c.can_send);
        assert!(!c.can_approve);
    }

    #[test]
    fn capabilities_receive_only() {
        let c = UplinkCapabilities::receive_only();
        assert!(c.can_receive);
        assert!(!c.can_send);
        assert!(!c.can_approve);
    }

    #[test]
    fn capabilities_default_all_false() {
        let c = UplinkCapabilities::default();
        assert!(!c.can_receive);
        assert!(!c.can_send);
        assert!(!c.can_approve);
        assert!(!c.can_elicit);
        assert!(!c.supports_rich_media);
        assert!(!c.supports_threads);
        assert!(!c.supports_buttons);
    }

    #[test]
    fn capabilities_serde_roundtrip() {
        let c = UplinkCapabilities::full();
        let json = serde_json::to_string(&c).unwrap();
        let back: UplinkCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // -- UplinkProfile --

    #[test]
    fn profile_display() {
        assert_eq!(UplinkProfile::Chat.to_string(), "chat");
        assert_eq!(UplinkProfile::Interactive.to_string(), "interactive");
        assert_eq!(UplinkProfile::Notify.to_string(), "notify");
        assert_eq!(UplinkProfile::Bridge.to_string(), "bridge");
    }

    // -- UplinkSource --

    #[test]
    fn source_display() {
        assert_eq!(UplinkSource::Native.to_string(), "native");
        assert_eq!(
            UplinkSource::Wasm {
                capsule_id: "foo".into()
            }
            .to_string(),
            "wasm(foo)"
        );
        assert_eq!(
            UplinkSource::Bridge {
                capsule_id: "bar".into()
            }
            .to_string(),
            "bridge(bar)"
        );
    }

    #[test]
    fn source_display_truncates_long_capsule_id() {
        let long_id = "a".repeat(128);
        let src = UplinkSource::Wasm {
            capsule_id: long_id,
        };
        let display = src.to_string();
        // 64 chars of 'a' + "wasm(" + ")" = 70
        assert_eq!(display.len(), 70);
    }

    #[test]
    fn source_new_wasm_valid() {
        let src = UplinkSource::new_wasm("my-plugin-1").unwrap();
        assert_eq!(
            src,
            UplinkSource::Wasm {
                capsule_id: "my-plugin-1".into()
            }
        );
    }

    #[test]
    fn source_new_bridge_valid() {
        let src = UplinkSource::new_bridge("bridge-42").unwrap();
        assert_eq!(
            src,
            UplinkSource::Bridge {
                capsule_id: "bridge-42".into()
            }
        );
    }

    #[test]
    fn source_new_wasm_rejects_empty() {
        let err = UplinkSource::new_wasm("").unwrap_err();
        assert!(matches!(err, UplinkError::InvalidCapsuleId(_)));
    }

    #[test]
    fn source_new_wasm_rejects_uppercase() {
        let err = UplinkSource::new_wasm("MyPlugin").unwrap_err();
        assert!(matches!(err, UplinkError::InvalidCapsuleId(_)));
    }

    #[test]
    fn source_new_wasm_rejects_leading_hyphen() {
        let err = UplinkSource::new_wasm("-bad").unwrap_err();
        assert!(matches!(err, UplinkError::InvalidCapsuleId(_)));
    }

    #[test]
    fn source_new_wasm_rejects_trailing_hyphen() {
        let err = UplinkSource::new_wasm("bad-").unwrap_err();
        assert!(matches!(err, UplinkError::InvalidCapsuleId(_)));
    }

    #[test]
    fn source_new_wasm_rejects_special_chars() {
        let err = UplinkSource::new_wasm("path/../traversal").unwrap_err();
        assert!(matches!(err, UplinkError::InvalidCapsuleId(_)));
    }

    #[test]
    fn source_serde_roundtrip_native() {
        let src = UplinkSource::Native;
        let json = serde_json::to_string(&src).unwrap();
        let back: UplinkSource = serde_json::from_str(&json).unwrap();
        assert_eq!(src, back);
    }

    #[test]
    fn source_serde_roundtrip_wasm() {
        let src = UplinkSource::new_wasm("test-plugin").unwrap();
        let json = serde_json::to_string(&src).unwrap();
        let back: UplinkSource = serde_json::from_str(&json).unwrap();
        assert_eq!(src, back);
    }

    #[test]
    fn source_serde_roundtrip_bridge() {
        let src = UplinkSource::new_bridge("bridge-1").unwrap();
        let json = serde_json::to_string(&src).unwrap();
        let back: UplinkSource = serde_json::from_str(&json).unwrap();
        assert_eq!(src, back);
    }

    #[test]
    fn source_deserializes_legacy_open_claw_tag_as_bridge() {
        // Back-compat: `UplinkSource::OpenClaw` was renamed to `Bridge`
        // (serde tag `open_claw` -> `bridge`). A persisted `UplinkDescriptor`
        // row written before the rename still carries the `open_claw` tag,
        // so `#[serde(alias = "open_claw")]` must accept it on deserialize.
        let legacy = r#"{"open_claw":{"capsule_id":"telegram-bridge"}}"#;
        let back: UplinkSource = serde_json::from_str(legacy).unwrap();
        assert_eq!(back, UplinkSource::new_bridge("telegram-bridge").unwrap());

        // New writes must serialize under the current tag, never the legacy one.
        let json = serde_json::to_string(&back).unwrap();
        assert!(
            json.contains("\"bridge\""),
            "must serialize as bridge: {json}"
        );
        assert!(
            !json.contains("open_claw"),
            "must not re-emit legacy tag: {json}"
        );
    }

    // -- UplinkDescriptor --

    #[test]
    fn descriptor_builder() {
        let desc = UplinkDescriptor::builder("discord-bot", "discord")
            .source(UplinkSource::Native)
            .capabilities(UplinkCapabilities::full())
            .profile(UplinkProfile::Chat)
            .metadata("version", "1.0")
            .build();

        assert_eq!(desc.name, "discord-bot");
        assert_eq!(desc.platform, "discord");
        assert_eq!(desc.source, UplinkSource::Native);
        assert_eq!(desc.capabilities, UplinkCapabilities::full());
        assert_eq!(desc.profile, UplinkProfile::Chat);
        assert_eq!(desc.metadata.get("version").unwrap(), "1.0");
    }

    #[test]
    fn descriptor_serde_roundtrip() {
        let desc = UplinkDescriptor::builder("cli", "cli")
            .capabilities(UplinkCapabilities::full())
            .build();

        let json = serde_json::to_string(&desc).unwrap();
        let back: UplinkDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(desc, back);
    }

    #[test]
    fn descriptor_builder_defaults() {
        let desc = UplinkDescriptor::builder("minimal", "cli").build();
        assert_eq!(desc.profile, UplinkProfile::Chat);
        assert_eq!(desc.capabilities, UplinkCapabilities::default());
        assert_eq!(desc.source, UplinkSource::Native);
        assert!(desc.metadata.is_empty());
    }

    // -- InboundMessage --

    #[test]
    fn inbound_message_builder() {
        let id = UplinkId::new();
        let msg = InboundMessage::builder(id, "discord", "user123", "hello")
            .context(serde_json::json!({"key": "value"}))
            .thread_id("thread-1")
            .build();

        assert_eq!(msg.uplink_id, id);
        assert_eq!(msg.platform_user_id, "user123");
        assert_eq!(msg.content, "hello");
        assert_eq!(msg.context["key"], "value");
        assert_eq!(msg.thread_id.as_deref(), Some("thread-1"));
    }

    #[test]
    fn inbound_message_serde_roundtrip() {
        let id = UplinkId::new();
        let msg = InboundMessage::builder(id, "discord", "user1", "test")
            .context(serde_json::json!({"nested": {"deep": [1, 2, 3]}}))
            .build();

        let json = serde_json::to_string(&msg).unwrap();
        let back: InboundMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uplink_id, id);
        assert_eq!(back.context["nested"]["deep"][1], 2);
    }

    #[test]
    fn inbound_message_empty_content() {
        let id = UplinkId::new();
        let msg = InboundMessage::builder(id, "cli", "", "").build();
        assert!(msg.platform_user_id.is_empty());
        assert!(msg.content.is_empty());
    }

    // -- UplinkError --

    #[test]
    fn error_display() {
        let e = UplinkError::NotConnected;
        assert_eq!(e.to_string(), "uplink not connected");

        let e = UplinkError::SendFailed("timeout".into());
        assert_eq!(e.to_string(), "send failed: timeout");

        let e = UplinkError::UnsupportedOperation("rich_media".into());
        assert_eq!(e.to_string(), "unsupported operation: rich_media");

        let e = UplinkError::InvalidCapsuleId("bad".into());
        assert_eq!(e.to_string(), "invalid capsule id: bad");
    }

    // --- UplinkProfile::FromStr ---

    #[test]
    fn profile_from_str_all_variants() {
        assert_eq!(
            UplinkProfile::from_str("chat").unwrap(),
            UplinkProfile::Chat
        );
        assert_eq!(
            UplinkProfile::from_str("interactive").unwrap(),
            UplinkProfile::Interactive
        );
        assert_eq!(
            UplinkProfile::from_str("notify").unwrap(),
            UplinkProfile::Notify
        );
        assert_eq!(
            UplinkProfile::from_str("bridge").unwrap(),
            UplinkProfile::Bridge
        );
    }

    #[test]
    fn profile_from_str_case_insensitive() {
        assert_eq!(
            UplinkProfile::from_str("Chat").unwrap(),
            UplinkProfile::Chat
        );
        assert_eq!(
            UplinkProfile::from_str("NOTIFY").unwrap(),
            UplinkProfile::Notify
        );
    }

    #[test]
    fn profile_from_str_unknown_returns_error() {
        let err = UplinkProfile::from_str("bogus").unwrap_err();
        assert!(err.contains("unknown uplink profile"));
    }
}

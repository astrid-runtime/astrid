//! `AstridClientHandler` — bridges astrid capability handlers with rmcp.

use std::sync::{Arc, Mutex, PoisonError};

use astrid_core::{
    InboundMessage, UplinkCapabilities, UplinkDescriptor, UplinkId, UplinkProfile, UplinkSource,
};
use serde_json::Value;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::super::handler::CapabilitiesHandler;
use super::bridge::BridgeChannelInfo;
use super::helpers::{
    estimate_json_size, extract_inbound_content, extract_platform_user_id, normalize_platform_name,
};
use super::notice::{
    MAX_CONTEXT_BYTES, MAX_NOTIFICATION_PAYLOAD_BYTES, MAX_PLATFORM_USER_ID_BYTES, ServerNotice,
};

/// Bridge between astrid capability handlers and the rmcp `ClientHandler` trait.
///
/// This is the handler passed to `rmcp::ServiceExt::serve()` when connecting
/// to an MCP server. It delegates server-initiated requests (sampling, roots,
/// elicitation) to the configured `CapabilitiesHandler`.
pub(crate) struct AstridClientHandler {
    pub(super) server_name: String,
    pub(super) inner: Arc<CapabilitiesHandler>,
    /// Channel for pushing notifications (tools changed, etc.) back to the
    /// `McpClient`. `None` if the caller does not care about notifications.
    pub(super) notice_tx: Option<mpsc::UnboundedSender<ServerNotice>>,
    /// Capsule ID for anti-spoofing validation on inbound notifications.
    pub(super) capsule_id: String,
    /// Channel for inbound messages from the bridge.
    /// Bounded to 256 (set by caller in `McpPlugin::load()`).
    pub(super) inbound_tx: Option<mpsc::Sender<InboundMessage>>,
    /// Shared registered uplinks for uplink ID lookups on inbound messages.
    ///
    /// Uses `std::sync::Mutex` (not `tokio::sync::Mutex`) because this is only
    /// accessed in non-async notification handlers and updated during uplink
    /// registration. The lock is never held across an `.await` point, so a
    /// blocking mutex is correct and avoids the overhead of an async-aware mutex.
    pub(super) registered_uplinks: Arc<Mutex<Vec<UplinkDescriptor>>>,
}

impl AstridClientHandler {
    /// Create a new handler for a specific server connection.
    pub(crate) fn new(server_name: impl Into<String>, inner: Arc<CapabilitiesHandler>) -> Self {
        Self {
            server_name: server_name.into(),
            inner,
            notice_tx: None,
            capsule_id: String::new(),
            inbound_tx: None,
            registered_uplinks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Attach a notice sender so that notifications (tool refreshes,
    /// uplink registrations) can be forwarded to the caller.
    #[must_use]
    pub(crate) fn with_notice_tx(mut self, tx: mpsc::UnboundedSender<ServerNotice>) -> Self {
        self.notice_tx = Some(tx);
        self
    }

    /// Set the capsule ID for anti-spoofing validation on inbound notifications.
    ///
    /// **Required** when inbound message channels are configured — an empty capsule ID
    /// causes the inbound message handler to reject all messages.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_capsule_id(mut self, capsule_id: &str) -> Self {
        self.capsule_id = capsule_id.to_string();
        self
    }

    /// Set the channel for inbound messages from the bridge.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_inbound_tx(mut self, tx: mpsc::Sender<InboundMessage>) -> Self {
        self.inbound_tx = Some(tx);
        self
    }

    /// Share the registered uplinks state for uplink ID lookups.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_shared_uplinks(
        mut self,
        uplinks: Arc<Mutex<Vec<UplinkDescriptor>>>,
    ) -> Self {
        self.registered_uplinks = uplinks;
        self
    }

    /// Handle a `notifications/astrid.inboundMessage` notification.
    pub(super) fn handle_inbound_message(&self, params: Option<Value>) {
        let Some(ref tx) = self.inbound_tx else {
            debug!("Ignoring inboundMessage: no inbound_tx configured");
            return;
        };

        // Reject if no capsule_id is configured (prevents empty-string bypass)
        if self.capsule_id.is_empty() {
            warn!("inboundMessage: no capsule_id configured, rejecting");
            return;
        }

        let Some(params) = params else {
            warn!("inboundMessage: missing params");
            return;
        };

        // Validate payload size (best-effort post-parse check)
        if estimate_json_size(&params) > MAX_NOTIFICATION_PAYLOAD_BYTES {
            warn!(
                max = MAX_NOTIFICATION_PAYLOAD_BYTES,
                "inboundMessage: payload too large, rejecting"
            );
            return;
        }

        // Extract and validate capsule_id BEFORE any content allocation (anti-spoofing)
        let Some(capsule_id) = params.get("capsuleId").and_then(Value::as_str) else {
            warn!("inboundMessage: missing capsuleId");
            return;
        };
        if capsule_id != self.capsule_id {
            warn!(
                got = %capsule_id,
                "inboundMessage: capsuleId mismatch, rejecting"
            );
            return;
        }

        let Some(content) = extract_inbound_content(&params, MAX_NOTIFICATION_PAYLOAD_BYTES) else {
            return;
        };

        let msg_context = params.get("context").cloned().unwrap_or(Value::Null);

        // Post-serialization context size check guards against escape-amplification
        // (control chars can expand up to 6x as \uNNNN when serialized).
        let ctx_size = if msg_context.is_null() {
            4
        } else {
            msg_context.to_string().len()
        };
        if ctx_size > MAX_CONTEXT_BYTES {
            warn!(
                max = MAX_CONTEXT_BYTES,
                actual = ctx_size,
                "inboundMessage: context payload too large, rejecting"
            );
            return;
        }

        // Extract platform_user_id with fallback chain
        let platform_user_id = extract_platform_user_id(&msg_context, MAX_PLATFORM_USER_ID_BYTES);

        // Extract channel name from context for uplink lookup
        let channel_name = msg_context
            .get("channel")
            .or_else(|| msg_context.get("channelName"))
            .and_then(Value::as_str);

        // Resolve uplink_id and platform from registered uplinks
        let (uplink_id, platform) = {
            let uplinks = self
                .registered_uplinks
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(desc) = channel_name.and_then(|ch| uplinks.iter().find(|d| d.name == ch)) {
                (desc.id, desc.platform.clone())
            } else if let Some(desc) = uplinks.first() {
                warn!(
                    capsule_id = %capsule_id,
                    channel = ?channel_name,
                    fallback_uplink = %desc.name,
                    "inboundMessage: channel not found, falling back to first uplink"
                );
                (desc.id, desc.platform.clone())
            } else {
                warn!(
                    capsule_id = %capsule_id,
                    channel = ?channel_name,
                    "inboundMessage: no uplinks registered, using ephemeral ID"
                );
                (UplinkId::new(), capsule_id.to_string())
            }
        };

        // Build inbound message
        let message = InboundMessage::builder(uplink_id, platform, platform_user_id, content)
            .context(msg_context)
            .build();

        // Send via bounded channel
        if let Err(e) = tx.try_send(message) {
            warn!(
                error = %e,
                "inboundMessage: inbound channel full or closed, dropping"
            );
        }
    }

    /// Process validated channels from a `uplinkRegistered` notification
    /// and populate `registered_uplinks` for inbound message lookups.
    pub(super) fn register_channels_locally(
        &self,
        capsule_id: &str,
        channels: &[BridgeChannelInfo],
    ) {
        let source = match UplinkSource::new_bridge(capsule_id) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "register_channels_locally: invalid capsule_id for UplinkSource");
                return;
            },
        };

        let mut shared = self
            .registered_uplinks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        for ch in channels {
            // Skip duplicates
            if shared.iter().any(|d| d.name == ch.name) {
                continue;
            }

            // Map platform from channel name (best effort)
            let platform = normalize_platform_name(&ch.name);

            // Map capabilities from typed definition
            let capabilities = ch
                .definition
                .as_ref()
                .and_then(|d| d.capabilities.as_ref())
                .map_or_else(UplinkCapabilities::receive_only, |caps| {
                    UplinkCapabilities {
                        can_receive: caps.can_receive,
                        can_send: caps.can_send,
                        can_approve: caps.can_approve,
                        ..UplinkCapabilities::default()
                    }
                });

            let descriptor = UplinkDescriptor::builder(&ch.name, platform)
                .source(source.clone())
                .profile(UplinkProfile::Bridge)
                .capabilities(capabilities)
                .build();

            shared.push(descriptor);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, PoisonError};

    use super::super::super::handler::CapabilitiesHandler;
    use super::super::bridge::{
        BridgeChannelCapabilities, BridgeChannelDefinition, BridgeChannelInfo,
    };
    use super::AstridClientHandler;

    #[test]
    fn test_register_channels_locally() {
        let handler =
            AstridClientHandler::new("capsule:test-plugin", Arc::new(CapabilitiesHandler::new()));

        let channels = vec![
            BridgeChannelInfo {
                name: "telegram".to_string(),
                definition: Some(BridgeChannelDefinition {
                    capabilities: Some(BridgeChannelCapabilities {
                        can_receive: true,
                        can_send: true,
                        ..Default::default()
                    }),
                }),
            },
            BridgeChannelInfo {
                name: "discord".to_string(),
                definition: None,
            },
        ];

        handler.register_channels_locally("test-plugin", &channels);

        let shared = handler
            .registered_uplinks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert_eq!(shared.len(), 2);
        assert_eq!(shared[0].name, "telegram");
        assert_eq!(shared[1].name, "discord");
    }

    #[test]
    fn test_register_channels_locally_deduplicates() {
        let handler =
            AstridClientHandler::new("capsule:test-plugin", Arc::new(CapabilitiesHandler::new()));

        let channels = vec![BridgeChannelInfo {
            name: "telegram".to_string(),
            definition: None,
        }];

        handler.register_channels_locally("test-plugin", &channels);
        handler.register_channels_locally("test-plugin", &channels);

        let shared = handler
            .registered_uplinks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert_eq!(shared.len(), 1, "duplicate channel should be deduplicated");
    }
}

//! Opt-in terminal delivery failures for guest publishers, independent of payload schemas.
//!
//! The host captures `_astrid_delivery_id` before converting a guest payload.
//! The receipt is scoped to its host-stamped publisher and principal; it grants
//! no authority to publish a response or replay an invocation. Successful calls
//! continue using their existing response topics. Independent fan-out has no
//! single terminal owner and therefore produces no receipt.

use super::IpcMessage;
#[cfg(feature = "clock")]
use super::{IpcPayload, RequestOwnerId};
use crate::Topic;
use uuid::Uuid;

/// Guest subscription alias; the host appends its own publisher identity.
pub const FAILURE_NAMESPACE: &str = "astrid.v1.delivery.failure";
const FAILURE_PREFIX: &str = "astrid.v1.delivery.failure.";
/// Optional publication metadata, consumed by the host before payload decoding.
pub const DELIVERY_ID_FIELD: &str = "_astrid_delivery_id";

/// Validated, single-segment publication correlation chosen by its publisher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryId(Uuid);

impl DeliveryId {
    /// Only canonical non-nil simple UUIDs are valid topic components.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let id = Uuid::parse_str(value).ok()?;
        (!id.is_nil() && id.simple().to_string() == value).then_some(Self(id))
    }
}

impl std::fmt::Display for DeliveryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.simple().fmt(f)
    }
}

/// A host-captured guest publication; no guest can replace the publisher.
#[cfg(feature = "clock")]
#[derive(Debug, Clone)]
pub struct DeliveryFailureBinding {
    publisher: Uuid,
    request_topic: Topic,
    principal: String,
    owner: Option<RequestOwnerId>,
    device_key_id: Option<String>,
    delivery_id: DeliveryId,
}

#[cfg(feature = "clock")]
impl DeliveryFailureBinding {
    /// Capture only opt-in, host-attributed guest publications.
    #[must_use]
    pub fn capture(request: &IpcMessage) -> Option<Self> {
        if request.source_id.is_nil() || request.principal.is_none() {
            return None;
        }
        Some(Self {
            publisher: request.source_id,
            request_topic: request.topic.clone(),
            principal: request.principal.clone()?,
            owner: request.request_owner,
            device_key_id: request.device_key_id.clone(),
            delivery_id: request.delivery_id?,
        })
    }

    /// A kernel-attributed receipt, with no original arguments or successful reply.
    #[must_use]
    pub fn message(&self, reason: &str) -> IpcMessage {
        let mut reply = IpcMessage::new(
            failure_topic(self.publisher, self.delivery_id),
            IpcPayload::RawJson(serde_json::json!({
                "delivery_id": self.delivery_id.to_string(),
                "request_topic": self.request_topic.as_str(),
                "reason": reason,
            })),
            Uuid::nil(),
        );
        reply.principal = Some(self.principal.clone());
        reply.request_owner = self.owner;
        reply.device_key_id.clone_from(&self.device_key_id);
        reply
    }
}

/// Internal receipt topic, never selected by a publishing guest.
#[must_use]
pub fn failure_topic(publisher: Uuid, delivery_id: DeliveryId) -> Topic {
    Topic::from_raw(format!(
        "{FAILURE_NAMESPACE}.{}.{delivery_id}",
        publisher.simple()
    ))
}

/// Receipt topics are transport notifications, never interceptor requests.
#[must_use]
pub fn is_failure_topic(topic: &str) -> bool {
    topic == FAILURE_NAMESPACE || topic.starts_with(FAILURE_PREFIX)
}

/// Broad resource subscriptions cannot disclose another publisher's receipt.
#[must_use]
pub fn visible_to(message: &IpcMessage, publisher: Uuid) -> bool {
    if !is_failure_topic(message.topic.as_str()) {
        return true;
    }
    let prefix = format!("{FAILURE_NAMESPACE}.{}.", publisher.simple());
    message.source_id.is_nil()
        && message
            .topic
            .as_str()
            .strip_prefix(&prefix)
            .and_then(DeliveryId::parse)
            .is_some()
}

/// Resolve an opt-in guest subscription alias to the host's own publisher scope.
/// Returns `None` for peer scopes, malformed identifiers and reserved roots.
#[must_use]
pub fn subscription_topic(pattern: &str, publisher: Uuid) -> Option<String> {
    if !is_failure_topic(pattern) {
        return Some(pattern.to_owned());
    }
    let suffix = pattern.strip_prefix(FAILURE_PREFIX)?;
    if suffix != "*" && DeliveryId::parse(suffix).is_none() {
        return None;
    }
    Some(format!(
        "{FAILURE_NAMESPACE}.{}.{suffix}",
        publisher.simple()
    ))
}

#[cfg(test)]
mod tests;

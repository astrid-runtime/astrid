//! Correlated terminal failures for authenticated native request/reply ingress.
//!
//! This is transport bookkeeping, not tool policy. Only host-stamped local
//! requests with a canonical `req_id` participate. A separate topic preserves
//! older readers: they must not mistake a new error payload for an empty reply.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{IpcMessage, IpcPayload};
#[cfg(feature = "clock")]
use super::{MessageOrigin, RequestOwnerId};
use crate::Topic;

/// A host-captured reply address; guest output cannot replace its owner.
#[derive(Debug, Clone)]
#[cfg(feature = "clock")]
pub struct RequestFailureBinding {
    correlation: Uuid,
    principal: String,
    owner: RequestOwnerId,
    device_key_id: Option<String>,
}

/// A terminal invocation failure, not a guarantee that no side effects occurred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestFailure {
    /// Canonical, single-segment request identifier supplied at native ingress.
    pub req_id: String,
    /// Actionable failure explanation; callers must not automatically replay.
    pub reason: String,
}

#[cfg(feature = "clock")]
impl RequestFailureBinding {
    /// Capture only authenticated, host-stamped native request envelopes.
    ///
    /// Call this only when one consumer owns the terminal outcome (a sole
    /// subscriber or a short-circuiting ordered chain). Independent fan-out
    /// subscribers cannot declare the whole request failed.
    #[must_use]
    pub fn capture(request: &IpcMessage) -> Option<Self> {
        if request.origin != MessageOrigin::LocalSocket
            || !request.source_id.is_nil()
            || !request.topic.as_str().starts_with("astrid.v1.request.")
        {
            return None;
        }
        let IpcPayload::RawJson(payload) = &request.payload else {
            return None;
        };
        let correlation = parse_correlation(payload.get("req_id")?.as_str()?)?;
        Some(Self {
            correlation,
            principal: request.principal.clone()?,
            owner: request.request_owner?,
            device_key_id: request.device_key_id.clone(),
        })
    }

    /// Produce a kernel-attributed failure using the captured routing identity.
    #[cfg(feature = "clock")]
    #[must_use]
    pub fn message(&self, reason: &str) -> IpcMessage {
        let req_id = self.correlation.simple().to_string();
        let mut message = IpcMessage::new(
            failure_topic(&req_id),
            IpcPayload::RawJson(serde_json::json!({
                "req_id": req_id,
                "reason": reason,
            })),
            Uuid::nil(),
        )
        .with_principal(self.principal.clone())
        .with_request_owner(self.owner);
        message.device_key_id.clone_from(&self.device_key_id);
        message
    }
}

impl RequestFailure {
    /// Accept only the host's failure for this request and principal.
    ///
    /// Native egress additionally enforces the captured connection owner. A
    /// guest can publish JSON resembling this payload but cannot obtain nil
    /// source attribution from the kernel.
    #[must_use]
    pub fn from_message(message: &IpcMessage, req_id: &str, principal: &str) -> Option<Self> {
        parse_correlation(req_id)?;
        if !message.source_id.is_nil()
            || message.request_owner.is_none()
            || message.principal.as_deref() != Some(principal)
            || message.topic != failure_topic(req_id)
        {
            return None;
        }
        let IpcPayload::RawJson(payload) = &message.payload else {
            return None;
        };
        let failure: Self = serde_json::from_value(payload.clone()).ok()?;
        (failure.req_id == req_id).then_some(failure)
    }
}

fn parse_correlation(value: &str) -> Option<Uuid> {
    let id = Uuid::parse_str(value).ok()?;
    (!id.is_nil() && id.simple().to_string() == value).then_some(id)
}

/// Separate from successful reply topics for compatibility with older readers.
#[must_use]
pub fn failure_topic(req_id: &str) -> Topic {
    Topic::from_raw(format!("astrid.v1.response.failure.{req_id}"))
}

#[cfg(all(test, feature = "clock"))]
mod tests {
    use super::*;

    fn request() -> IpcMessage {
        IpcMessage::new(
            Topic::from_raw("astrid.v1.request.example"),
            IpcPayload::RawJson(serde_json::json!({
                "req_id": "1234567890abcdef1234567890abcdef",
            })),
            Uuid::nil(),
        )
        .with_principal("alice")
        .with_request_owner(RequestOwnerId::generate())
        .with_origin(MessageOrigin::LocalSocket)
    }

    #[test]
    fn failure_preserves_owner_and_does_not_shadow_success_topic() {
        let mut request = request();
        request.device_key_id = Some("device-a".into());
        let binding = RequestFailureBinding::capture(&request).expect("native request");
        let reply = binding.message("invocation deadline exceeded");
        assert_eq!(reply.request_owner, request.request_owner);
        assert_eq!(reply.device_key_id, request.device_key_id);
        let req_id = "1234567890abcdef1234567890abcdef";
        assert_ne!(reply.topic, Topic::kernel_response(req_id));
        let failure = RequestFailure::from_message(&reply, req_id, "alice").expect("host failure");
        assert_eq!(failure.reason, "invocation deadline exceeded");
        assert!(RequestFailure::from_message(&reply, req_id, "bob").is_none());
        assert!(
            RequestFailure::from_message(&reply, "2234567890abcdef1234567890abcdef", "alice")
                .is_none()
        );
    }

    #[test]
    fn untrusted_and_uncorrelated_requests_do_not_acquire_reply_authority() {
        let original = request();
        for change in 0..6 {
            let mut request = original.clone();
            match change {
                0 => request.source_id = Uuid::new_v4(),
                1 => request.origin = MessageOrigin::RemoteGateway,
                2 => request.request_owner = None,
                3 => request.principal = None,
                4 => request.topic = Topic::from_raw("astrid.v1.requestevil"),
                _ => {
                    request.payload = IpcPayload::RawJson(serde_json::json!({"req_id":"../other"}));
                },
            }
            assert!(RequestFailureBinding::capture(&request).is_none());
        }
    }

    #[test]
    fn forged_source_and_mismatched_payload_are_not_terminal_failures() {
        let binding = RequestFailureBinding::capture(&request()).expect("native request");
        let mut reply = binding.message("failure");
        let req_id = "1234567890abcdef1234567890abcdef";
        reply.source_id = Uuid::new_v4();
        assert!(RequestFailure::from_message(&reply, req_id, "alice").is_none());
        reply.source_id = Uuid::nil();
        reply.payload = IpcPayload::RawJson(serde_json::json!({
            "req_id":"2234567890abcdef1234567890abcdef", "reason":"failure",
        }));
        assert!(RequestFailure::from_message(&reply, req_id, "alice").is_none());
    }
}

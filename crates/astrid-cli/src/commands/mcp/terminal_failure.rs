//! Validate host terminal failures without replaying the failed request.

use astrid_types::ipc::{IpcMessage, IpcPayload, RequestOwnerId, request_failure::RequestFailure};
use rmcp::ErrorData as McpError;
use serde_json::Value;

fn failure(raw: &Value, req_id: &str, principal: &str) -> Option<RequestFailure> {
    let topic = astrid_types::ipc::request_failure::failure_topic(req_id);
    if raw.get("topic").and_then(Value::as_str) != Some(topic.as_str()) {
        return None;
    }
    // Native egress flattens the payload to guest JSON; it does not serialize
    // the tagged IpcPayload representation used on the internal event bus.
    // Reconstruct only after validating the host attribution and owner fields.
    let source = serde_json::from_value::<uuid::Uuid>(raw.get("source_id")?.clone()).ok()?;
    let owner = serde_json::from_value::<RequestOwnerId>(raw.get("request_owner")?.clone()).ok()?;
    let routed_principal = raw.get("principal")?.as_str()?;
    let message = IpcMessage::new(
        topic,
        IpcPayload::RawJson(raw.get("payload")?.clone()),
        source,
    )
    .with_principal(routed_principal)
    .with_request_owner(owner);
    RequestFailure::from_message(&message, req_id, principal)
}

pub(super) fn accepts(raw: &Value, reply_topic: &str, req_id: &str, principal: &str) -> bool {
    raw.get("topic").and_then(Value::as_str) == Some(reply_topic)
        || failure(raw, req_id, principal).is_some()
}

pub(super) fn reply(raw: &Value, req_id: &str, principal: &str) -> Result<Value, McpError> {
    if let Some(failure) = failure(raw, req_id, principal) {
        // A terminal error does not prove that no effect occurred before the
        // interruption. Never reuse the connection-loss automatic retry path.
        return Err(McpError::internal_error(
            format!("runtime invocation failed: {}", failure.reason),
            None,
        ));
    }
    Ok(super::server::unwrap_reply_payload(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_types::{
        Topic,
        ipc::{IpcPayload, MessageOrigin, RequestOwnerId, request_failure::RequestFailureBinding},
    };

    const REQ_ID: &str = "1234567890abcdef1234567890abcdef";

    fn host_failure() -> IpcMessage {
        let request = IpcMessage::new(
            Topic::from_raw("astrid.v1.request.mcp.tool.call"),
            IpcPayload::RawJson(serde_json::json!({"req_id": REQ_ID})),
            uuid::Uuid::nil(),
        )
        .with_principal("alice")
        .with_request_owner(RequestOwnerId::generate())
        .with_origin(MessageOrigin::LocalSocket);
        RequestFailureBinding::capture(&request)
            .unwrap()
            .message("invocation deadline exceeded")
    }

    fn local_frame(message: &IpcMessage) -> Value {
        let IpcPayload::RawJson(payload) = &message.payload else {
            panic!("raw failure payload")
        };
        serde_json::json!({
            "topic": message.topic,
            "payload": payload,
            "source_id": message.source_id,
            "principal": message.principal,
            "request_owner": message.request_owner,
        })
    }

    #[test]
    fn terminal_failure_is_an_error_not_empty_tool_success() {
        let raw = local_frame(&host_failure());
        assert!(serde_json::from_value::<IpcMessage>(raw.clone()).is_err());
        let topic = Topic::kernel_response(REQ_ID);
        assert!(accepts(&raw, topic.as_str(), REQ_ID, "alice"));
        let error = reply(&raw, REQ_ID, "alice").unwrap_err();
        assert!(error.message.contains("invocation deadline exceeded"));
    }

    #[test]
    fn unrelated_or_forged_failures_are_ignored() {
        let topic = Topic::kernel_response(REQ_ID);
        let original = host_failure();
        for change in 0..3 {
            let mut message = original.clone();
            match change {
                0 => message.source_id = uuid::Uuid::new_v4(),
                1 => message.principal = Some("bob".into()),
                _ => message.topic = Topic::from_raw("astrid.v1.response.failure.other"),
            }
            let raw = local_frame(&message);
            assert!(!accepts(&raw, topic.as_str(), REQ_ID, "alice"));
        }
    }

    #[test]
    fn malformed_local_attribution_is_ignored() {
        let topic = Topic::kernel_response(REQ_ID);
        let frame = local_frame(&host_failure());
        for field in ["source_id", "principal", "request_owner"] {
            let mut missing = frame.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(!accepts(&missing, topic.as_str(), REQ_ID, "alice"));
        }
        let mut invalid = frame;
        invalid["request_owner"] = Value::String("not-an-owner".into());
        assert!(!accepts(&invalid, topic.as_str(), REQ_ID, "alice"));
    }

    #[test]
    fn normal_broker_reply_is_unchanged() {
        let topic = Topic::kernel_response(REQ_ID);
        let payload = serde_json::json!({"kind":"tool.call", "isError":false, "content":[]});
        let raw = serde_json::json!({"topic":topic.as_str(), "payload":{"type":"raw_json", "value":payload}});
        assert!(accepts(&raw, topic.as_str(), REQ_ID, "alice"));
        assert_eq!(reply(&raw, REQ_ID, "alice").unwrap(), payload);
    }
}

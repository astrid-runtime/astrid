//! Wire-topic policy and per-connection response demultiplexing.

use std::collections::HashMap;

use astrid_types::ipc::{IpcMessage, IpcPayload};

pub(super) const CHAT_REQUEST_TOPIC: &str = "user.v1.prompt";
const CHAT_RESPONSE_TOPIC: &str = "agent.v1.response";
const CHAT_DELTA_TOPIC: &str = "agent.v1.stream.delta";
const MAX_STREAM_SESSIONS: usize = 64;
const MAX_STREAM_BYTES: usize = super::MAX_PAYLOAD_BYTES;

const ALLOWED_INGRESS_EXACT: &[&str] = &["user.v1.prompt", "cli.v1.command.execute"];
const ALLOWED_INGRESS_PREFIXES: &[&str] = &[
    "astrid.v1.request.",
    "astrid.v1.admin.",
    "astrid.v1.elicit.response.",
    "astrid.v1.approval.response.",
    "registry.v1.selection.",
    "session.v1.request.",
    "cli.v1.command.run.",
    "sage.v1.hook.",
];
const BLOCKED_INGRESS_PREFIXES: &[&str] = &["astrid.v1.admin.response."];

const ALLOWED_EGRESS_EXACT: &[&str] = &[
    CHAT_DELTA_TOPIC,
    CHAT_RESPONSE_TOPIC,
    "astrid.v1.elicit",
    "astrid.v1.onboarding.required",
    "astrid.v1.approval",
    "astrid.v1.capsules_loaded",
    "registry.v1.active_model_changed",
];
const ALLOWED_EGRESS_PREFIXES: &[&str] = &[
    "astrid.v1.response.",
    "astrid.v1.admin.response.",
    "registry.v1.response.",
    "registry.v1.selection.",
    "session.v1.response.",
    "cli.v1.command.result.",
];

const SYSTEM_BROADCAST_EXACT: &[&str] = &["registry.v1.active_model_changed"];

pub(super) fn ingress_allowed(topic: &str) -> bool {
    if BLOCKED_INGRESS_PREFIXES
        .iter()
        .any(|prefix| topic.starts_with(prefix))
    {
        return false;
    }
    ALLOWED_INGRESS_EXACT.contains(&topic)
        || ALLOWED_INGRESS_PREFIXES
            .iter()
            .any(|prefix| topic.starts_with(prefix))
}

pub(super) fn egress_allowed(topic: &str) -> bool {
    ALLOWED_EGRESS_EXACT.contains(&topic)
        || ALLOWED_EGRESS_PREFIXES
            .iter()
            .any(|prefix| topic.starts_with(prefix))
}

pub(super) fn payload_session_id(payload: &IpcPayload) -> Option<&str> {
    match payload {
        IpcPayload::UserInput { session_id, .. } | IpcPayload::AgentResponse { session_id, .. } => {
            Some(session_id)
        },
        IpcPayload::RawJson(value) => value.get("session_id").and_then(|value| value.as_str()),
        _ => None,
    }
}

pub(super) fn outbound_session(message: &IpcMessage) -> Option<&str> {
    matches!(
        message.topic.as_str(),
        CHAT_RESPONSE_TOPIC | CHAT_DELTA_TOPIC
    )
    .then(|| payload_session_id(&message.payload))
    .flatten()
}

pub(super) fn is_cancel_turn(payload: &IpcPayload) -> bool {
    matches!(
        payload,
        IpcPayload::UserInput {
            context: Some(context),
            ..
        } if context.get("action").and_then(serde_json::Value::as_str) == Some("cancel_turn")
    )
}

pub(super) fn should_deliver(
    message: &IpcMessage,
    principal: &str,
    device_key_id: Option<&str>,
    session: Option<&str>,
) -> bool {
    if !egress_allowed(message.topic.as_str()) {
        return false;
    }
    match message.principal.as_deref() {
        Some(target) if target != principal => return false,
        None if !SYSTEM_BROADCAST_EXACT.contains(&message.topic.as_str()) => return false,
        Some(_) | None => {},
    }
    if let Some(target) = message.device_key_id.as_deref()
        && device_key_id != Some(target)
    {
        return false;
    }
    match outbound_session(message) {
        Some(target) => session == Some(target),
        None => true,
    }
}

pub(super) fn completed_chat_session(message: &IpcMessage) -> Option<&str> {
    (message.topic.as_str() == CHAT_RESPONSE_TOPIC && response_is_final(&message.payload))
        .then(|| payload_session_id(&message.payload))
        .flatten()
}

/// Prevent the terminal chat frame from replaying text already emitted as
/// stream deltas. This preserves the CLI's append-then-flush wire behavior.
pub(super) fn reconcile_stream(
    message: &mut IpcMessage,
    accumulators: &mut HashMap<String, Option<String>>,
) {
    let topic = message.topic.as_str();
    let Some(session) = payload_session_id(&message.payload).map(str::to_owned) else {
        return;
    };
    if topic == CHAT_DELTA_TOPIC {
        let Some(text) = delta_text(&message.payload) else {
            return;
        };
        if accumulators.len() >= MAX_STREAM_SESSIONS
            && !accumulators.contains_key(&session)
            && let Some(stale) = accumulators.keys().next().cloned()
        {
            accumulators.remove(&stale);
        }
        let state = accumulators
            .entry(session)
            .or_insert_with(|| Some(String::new()));
        let Some(streamed) = state.as_mut() else {
            return;
        };
        if streamed.len().saturating_add(text.len()) > MAX_STREAM_BYTES {
            // Keep an overflow tombstone until the terminal frame so later
            // deltas cannot recreate an unbounded accumulator.
            *state = None;
        } else {
            streamed.push_str(text);
        }
        return;
    }
    if topic != CHAT_RESPONSE_TOPIC || !response_is_final(&message.payload) {
        return;
    }
    let Some(state) = accumulators.remove(&session) else {
        return;
    };
    let Some(streamed) = state else {
        return;
    };
    let full = response_text(&message.payload).unwrap_or_default();
    let remainder = full.strip_prefix(&streamed).unwrap_or(full).to_owned();
    set_response_text(&mut message.payload, remainder);
}

fn delta_text(payload: &IpcPayload) -> Option<&str> {
    match payload {
        IpcPayload::AgentResponse { text, .. } => Some(text),
        IpcPayload::RawJson(value) => value
            .get("delta")
            .or_else(|| value.get("text"))
            .and_then(|value| value.as_str()),
        _ => None,
    }
}

fn response_text(payload: &IpcPayload) -> Option<&str> {
    match payload {
        IpcPayload::AgentResponse { text, .. } => Some(text),
        IpcPayload::RawJson(value) => value.get("text").and_then(|value| value.as_str()),
        _ => None,
    }
}

fn response_is_final(payload: &IpcPayload) -> bool {
    match payload {
        IpcPayload::AgentResponse { is_final, .. } => *is_final,
        IpcPayload::RawJson(value) => value
            .get("is_final")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        _ => false,
    }
}

fn set_response_text(payload: &mut IpcPayload, text: String) {
    match payload {
        IpcPayload::AgentResponse {
            text: response_text,
            ..
        } => *response_text = text,
        IpcPayload::RawJson(value) => {
            if let Some(object) = value.as_object_mut() {
                object.insert("text".to_owned(), serde_json::Value::String(text));
            }
        },
        _ => {},
    }
}

#[cfg(test)]
mod tests {
    use astrid_types::Topic;
    use uuid::Uuid;

    use super::*;

    fn message(topic: &str, principal: Option<&str>, session: &str) -> IpcMessage {
        let mut message = IpcMessage::new(
            Topic::from_raw(topic),
            IpcPayload::AgentResponse {
                text: "hello".to_owned(),
                session_id: session.to_owned(),
                is_final: true,
            },
            Uuid::nil(),
        );
        message.principal = principal.map(str::to_owned);
        message
    }

    #[test]
    fn blocks_spoofed_admin_responses_on_ingress() {
        assert!(!ingress_allowed("astrid.v1.admin.response.status.fake"));
        assert!(ingress_allowed("astrid.v1.admin.status.fake"));
        assert!(ingress_allowed("sage.v1.hook.before_tool_call"));
    }

    #[test]
    fn recognizes_only_explicit_cancel_turn_control_payload() {
        let cancel = IpcPayload::UserInput {
            text: String::new(),
            session_id: "session-1".to_owned(),
            context: Some(serde_json::json!({"action": "cancel_turn"})),
        };
        let ordinary = IpcPayload::UserInput {
            text: "hello".to_owned(),
            session_id: "session-1".to_owned(),
            context: None,
        };
        assert!(is_cancel_turn(&cancel));
        assert!(!is_cancel_turn(&ordinary));
    }

    #[test]
    fn routes_elicit_requests_but_not_client_responses_on_egress() {
        assert!(egress_allowed("astrid.v1.elicit"));
        assert!(!egress_allowed("astrid.v1.elicit.response.fake"));
    }

    #[test]
    fn principal_less_management_responses_never_broadcast() {
        let response = message("astrid.v1.admin.response.status", None, "one");
        assert!(!should_deliver(&response, "alice", None, None));

        let onboarding = message("astrid.v1.onboarding.required", None, "one");
        assert!(!should_deliver(&onboarding, "alice", None, None));

        let onboarding = message("astrid.v1.onboarding.required", Some("alice"), "one");
        assert!(should_deliver(&onboarding, "alice", None, None));
        assert!(!should_deliver(&onboarding, "bob", None, None));
    }

    #[test]
    fn demuxes_by_principal_and_chat_session() {
        let message = message(CHAT_RESPONSE_TOPIC, Some("alice"), "one");
        assert!(should_deliver(&message, "alice", None, Some("one")));
        assert!(!should_deliver(&message, "bob", None, Some("one")));
        assert!(!should_deliver(&message, "alice", None, Some("two")));
    }

    #[test]
    fn device_scoped_response_reaches_only_the_authenticated_device() {
        let mut response = message(
            "astrid.v1.admin.response.auth.pair.issue",
            Some("alice"),
            "one",
        );
        response.device_key_id = Some("full-device".to_owned());

        assert!(should_deliver(
            &response,
            "alice",
            Some("full-device"),
            None
        ));
        assert!(!should_deliver(
            &response,
            "alice",
            Some("use-only-device"),
            None
        ));
        assert!(!should_deliver(&response, "alice", None, None));
    }

    #[test]
    fn reconciles_terminal_after_delta() {
        let mut accum = HashMap::from([("one".to_owned(), Some("hel".to_owned()))]);
        let mut message = message(CHAT_RESPONSE_TOPIC, Some("alice"), "one");
        reconcile_stream(&mut message, &mut accum);
        assert_eq!(response_text(&message.payload), Some("lo"));
        assert!(accum.is_empty());
    }

    #[test]
    fn reconciles_raw_json_delta_before_terminal_response() {
        let mut accum = HashMap::new();
        let mut delta = IpcMessage::new(
            Topic::from_raw(CHAT_DELTA_TOPIC),
            IpcPayload::RawJson(serde_json::json!({
                "session_id": "one",
                "delta": "hel"
            })),
            Uuid::nil(),
        )
        .with_principal("alice");
        reconcile_stream(&mut delta, &mut accum);

        let mut terminal = IpcMessage::new(
            Topic::from_raw(CHAT_RESPONSE_TOPIC),
            IpcPayload::RawJson(serde_json::json!({
                "session_id": "one",
                "text": "hello",
                "is_final": true
            })),
            Uuid::nil(),
        )
        .with_principal("alice");
        reconcile_stream(&mut terminal, &mut accum);

        assert_eq!(response_text(&terminal.payload), Some("lo"));
        assert!(accum.is_empty());
    }

    #[test]
    fn preserves_terminal_text_when_stream_prefix_does_not_match() {
        let mut accum = HashMap::from([("one".to_owned(), Some("draft".to_owned()))]);
        let mut message = message(CHAT_RESPONSE_TOPIC, Some("alice"), "one");
        reconcile_stream(&mut message, &mut accum);
        assert_eq!(response_text(&message.payload), Some("hello"));
        assert!(accum.is_empty());
    }

    #[test]
    fn stream_overflow_remains_tombstoned_until_terminal() {
        let mut accum = HashMap::new();
        let mut delta = message(CHAT_DELTA_TOPIC, Some("alice"), "one");
        set_response_text(&mut delta.payload, "x".repeat(MAX_STREAM_BYTES + 1));
        reconcile_stream(&mut delta, &mut accum);
        assert_eq!(accum.get("one"), Some(&None));

        set_response_text(&mut delta.payload, "late".to_owned());
        reconcile_stream(&mut delta, &mut accum);
        assert_eq!(accum.get("one"), Some(&None));

        let mut terminal = message(CHAT_RESPONSE_TOPIC, Some("alice"), "one");
        reconcile_stream(&mut terminal, &mut accum);
        assert_eq!(response_text(&terminal.payload), Some("hello"));
        assert!(accum.is_empty());
    }
}

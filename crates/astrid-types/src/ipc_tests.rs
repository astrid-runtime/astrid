//! Unit tests for IPC message schemas, payload variants, and the
//! host-stamped [`MessageOrigin`](super::MessageOrigin) transport marker.
//!
//! Split out of `ipc.rs` to keep that module under the 1000-line CI cap;
//! included via `#[cfg(test)] #[path = "ipc_tests.rs"] mod tests;`.

use super::*;

#[test]
fn ipc_message_signature() {
    let msg = IpcMessage::new(
        "test.topic",
        IpcPayload::AgentResponse {
            text: "hello".into(),
            is_final: true,
            session_id: "default".into(),
        },
        Uuid::new_v4(),
    );
    assert!(msg.signature.is_none());

    let signed = msg.with_signature(vec![1, 2, 3]);
    assert_eq!(signed.signature, Some(vec![1, 2, 3]));
}

#[test]
fn ipc_message_principal() {
    let msg = IpcMessage::new(
        "test.topic",
        IpcPayload::Custom {
            data: serde_json::json!({}),
        },
        Uuid::new_v4(),
    );
    assert!(msg.principal.is_none());

    let with_principal = msg.with_principal("alice");
    assert_eq!(with_principal.principal.as_deref(), Some("alice"));
}

#[test]
fn ipc_message_principal_serde_roundtrip() {
    let msg = IpcMessage::new(
        "test.topic",
        IpcPayload::Custom {
            data: serde_json::json!({}),
        },
        Uuid::nil(),
    )
    .with_principal("bob");
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains(r#""principal":"bob""#));

    let parsed: IpcMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.principal.as_deref(), Some("bob"));
}

#[test]
fn ipc_message_principal_absent_in_json() {
    // Messages without principal should deserialize with None.
    let json = r#"{"topic":"t","payload":{"type":"connect"},"source_id":"00000000-0000-0000-0000-000000000000","timestamp":"2024-01-01T00:00:00Z","seq":0}"#;
    let msg: IpcMessage = serde_json::from_str(json).unwrap();
    assert!(msg.principal.is_none());
}

#[test]
fn ipc_message_principal_not_serialized_when_none() {
    let msg = IpcMessage::new("test.topic", IpcPayload::Connect, Uuid::nil());
    let json = serde_json::to_string(&msg).unwrap();
    assert!(!json.contains("principal"));
}

#[test]
fn ipc_message_device_key_id_builder() {
    let msg = IpcMessage::new(
        "test.topic",
        IpcPayload::Custom {
            data: serde_json::json!({}),
        },
        Uuid::new_v4(),
    );
    assert!(msg.device_key_id.is_none());

    let with_key = msg.with_device_key_id("abcdef0123456789");
    assert_eq!(with_key.device_key_id.as_deref(), Some("abcdef0123456789"));
}

#[test]
fn ipc_message_device_key_id_serde_roundtrip() {
    let msg = IpcMessage::new(
        "test.topic",
        IpcPayload::Custom {
            data: serde_json::json!({}),
        },
        Uuid::nil(),
    )
    .with_device_key_id("abcdef0123456789");
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains(r#""device_key_id":"abcdef0123456789""#));

    let parsed: IpcMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.device_key_id.as_deref(), Some("abcdef0123456789"));
}

#[test]
fn ipc_message_device_key_id_absent_in_json() {
    // A message constructed without a device key must not serialize the
    // key at all (legacy wire compatibility), and must round-trip to None.
    let msg = IpcMessage::new("test.topic", IpcPayload::Connect, Uuid::nil());
    let json = serde_json::to_string(&msg).unwrap();
    assert!(!json.contains("device_key_id"));

    let parsed: IpcMessage = serde_json::from_str(&json).unwrap();
    assert!(parsed.device_key_id.is_none());
}

#[test]
fn ipc_message_device_key_id_defaults_when_missing() {
    // A frame from a peer that predates the field deserializes with None.
    let json = r#"{"topic":"t","payload":{"type":"connect"},"source_id":"00000000-0000-0000-0000-000000000000","timestamp":"2024-01-01T00:00:00Z","seq":0}"#;
    let msg: IpcMessage = serde_json::from_str(json).unwrap();
    assert!(msg.device_key_id.is_none());
}

#[test]
fn message_origin_defaults_to_system() {
    // A freshly constructed message is System-origin (the fail-closed,
    // non-local floor) until the host stamps a transport origin.
    let msg = IpcMessage::new("t", IpcPayload::Connect, Uuid::nil());
    assert_eq!(msg.origin, MessageOrigin::System);
    assert!(msg.origin.is_system());
}

#[test]
fn message_origin_builder_sets_and_serde_roundtrips() {
    let msg = IpcMessage::new("t", IpcPayload::Connect, Uuid::nil())
        .with_origin(MessageOrigin::LocalSocket);
    assert_eq!(msg.origin, MessageOrigin::LocalSocket);

    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains(r#""origin":"local_socket""#), "json: {json}");
    let parsed: IpcMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.origin, MessageOrigin::LocalSocket);
}

#[test]
fn message_origin_system_not_serialized() {
    // System is the legacy/default origin: it must NOT appear on the wire,
    // so a system-origin message keeps the pre-origin frame shape.
    let msg = IpcMessage::new("t", IpcPayload::Connect, Uuid::nil());
    let json = serde_json::to_string(&msg).unwrap();
    assert!(!json.contains("origin"), "json: {json}");
}

#[test]
fn message_origin_absent_in_json_decodes_to_system() {
    // A frame from a peer that predates the field — and the CLI-proxy wire
    // format `{topic, payload, source_id}` which never carries it — must
    // deserialize to System (fail-closed, NON-local), never accidentally
    // local.
    let legacy = r#"{"topic":"t","payload":{"type":"connect"},"source_id":"00000000-0000-0000-0000-000000000000","timestamp":"2024-01-01T00:00:00Z","seq":0}"#;
    let msg: IpcMessage = serde_json::from_str(legacy).unwrap();
    assert_eq!(msg.origin, MessageOrigin::System);

    let cli_proxy = r#"{"topic":"agent.v1.response","payload":{"type":"connect"},"source_id":"00000000-0000-0000-0000-000000000000"}"#;
    let msg: IpcMessage = serde_json::from_str(cli_proxy).unwrap();
    assert_eq!(msg.origin, MessageOrigin::System);
}

#[test]
fn message_origin_unknown_variant_decodes_to_system() {
    // A future/unknown origin variant from a newer peer must fall back to
    // System (fail-closed), NOT be silently treated as local. This is the
    // `#[serde(other)]` floor — a remote peer cannot smuggle local
    // privilege by sending an origin string the host does not recognise.
    let v: MessageOrigin = serde_json::from_str(r#""future_listener""#).unwrap();
    assert_eq!(v, MessageOrigin::System);

    let frame = r#"{"topic":"t","payload":{"type":"connect"},"source_id":"00000000-0000-0000-0000-000000000000","origin":"future_listener"}"#;
    let msg: IpcMessage = serde_json::from_str(frame).unwrap();
    assert_eq!(msg.origin, MessageOrigin::System);
}

#[test]
fn message_origin_remote_gateway_roundtrips() {
    let v: MessageOrigin = serde_json::from_str(r#""remote_gateway""#).unwrap();
    assert_eq!(v, MessageOrigin::RemoteGateway);
    assert!(!v.is_system());
    assert_eq!(
        serde_json::to_string(&MessageOrigin::RemoteGateway).unwrap(),
        r#""remote_gateway""#
    );
}

#[test]
fn unknown_type_tag_deserializes_to_unknown() {
    let json = r#"{"type":"future_variant","some_data":42}"#;
    let payload: IpcPayload = serde_json::from_str(json).unwrap();
    assert_eq!(payload, IpcPayload::Unknown);
}

#[test]
fn ipc_message_parses_cli_proxy_wire_format() {
    // The CLI proxy capsule (capsules/astrid-capsule-cli) forwards bus
    // messages to socket clients using only the fields exposed by the
    // SDK's `ipc::Message`: {topic, payload, source_id}. The SDK does
    // not surface the original timestamp or signature, so the wire
    // format omits them. Without serde defaults on those fields the
    // headless client's `from_slice::<IpcMessage>` silently fails on
    // every frame and the response never reaches the user.
    let wire = r#"{"topic":"agent.v1.response","payload":{"type":"agent_response","text":"hi","is_final":true,"session_id":"00000000-0000-0000-0000-000000000000"},"source_id":"00000000-0000-0000-0000-000000000000"}"#;
    let msg: IpcMessage = serde_json::from_str(wire).expect("cli proxy frame must parse");
    assert_eq!(msg.topic, "agent.v1.response");
    assert!(msg.signature.is_none());
    assert_eq!(msg.seq, 0);
    match msg.payload {
        IpcPayload::AgentResponse { text, is_final, .. } => {
            assert_eq!(text, "hi");
            assert!(is_final);
        },
        other => panic!("unexpected payload variant: {other:?}"),
    }
}

#[test]
fn known_variants_unaffected_by_unknown() {
    let payload = IpcPayload::AgentResponse {
        text: "hello".into(),
        is_final: true,
        session_id: "s1".into(),
    };
    let json = serde_json::to_string(&payload).unwrap();
    let parsed: IpcPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, payload);
}

#[test]
fn unknown_variant_serializes_as_type_unknown() {
    let json = serde_json::to_string(&IpcPayload::Unknown).unwrap();
    assert_eq!(json, r#"{"type":"unknown"}"#);
}

/// Every variant's serialized `type` tag must be recognised by
/// `is_known_tag`. If a new variant is added without updating the
/// match arm *and* the representatives list below, this test fails.
#[test]
#[allow(clippy::too_many_lines, reason = "exhaustive variant table")]
fn is_known_tag_covers_all_variants() {
    const EXPECTED_VARIANT_COUNT: usize = 18;

    let representatives: Vec<IpcPayload> = vec![
        IpcPayload::RawJson(serde_json::json!({"key": "val"})),
        IpcPayload::UserInput {
            text: String::new(),
            session_id: "s".into(),
            context: None,
        },
        IpcPayload::AgentResponse {
            text: String::new(),
            is_final: false,
            session_id: "s".into(),
        },
        IpcPayload::ApprovalRequired {
            request_id: "req-1".into(),
            action: String::new(),
            resource: String::new(),
            reason: String::new(),
        },
        IpcPayload::ApprovalResponse {
            request_id: "req-1".into(),
            decision: "approve".into(),
            reason: None,
        },
        IpcPayload::GrantRequired {
            request_id: "req-1".into(),
            principal: "alice".into(),
            capsule_id: "cap".into(),
        },
        IpcPayload::OnboardingRequired {
            capsule_id: String::new(),
            fields: vec![],
        },
        IpcPayload::LlmRequest {
            request_id: Uuid::nil(),
            model: String::new(),
            messages: vec![],
            tools: vec![],
            system: String::new(),
        },
        IpcPayload::LlmStreamEvent {
            request_id: Uuid::nil(),
            event: crate::llm::StreamEvent::TextDelta(String::new()),
        },
        IpcPayload::LlmResponse {
            request_id: Uuid::nil(),
            response: crate::llm::LlmResponse {
                message: crate::llm::Message {
                    role: crate::llm::MessageRole::Assistant,
                    content: crate::llm::MessageContent::Text(String::new()),
                },
                has_tool_calls: false,
                stop_reason: crate::llm::StopReason::EndTurn,
                usage: crate::llm::Usage {
                    input_tokens: 0,
                    output_tokens: 0,
                },
            },
        },
        IpcPayload::ToolExecuteRequest {
            call_id: String::new(),
            tool_name: String::new(),
            arguments: Value::Null,
        },
        IpcPayload::ToolExecuteResult {
            call_id: String::new(),
            result: crate::llm::ToolCallResult {
                call_id: String::new(),
                content: String::new(),
                is_error: false,
            },
        },
        IpcPayload::SelectionRequired {
            request_id: String::new(),
            title: String::new(),
            options: vec![],
            callback_topic: String::new(),
        },
        IpcPayload::ElicitRequest {
            request_id: Uuid::nil(),
            capsule_id: String::new(),
            field: OnboardingField {
                key: String::new(),
                prompt: String::new(),
                description: None,
                field_type: OnboardingFieldType::Text,
                default: None,
                placeholder: None,
            },
        },
        IpcPayload::ElicitResponse {
            request_id: Uuid::nil(),
            value: None,
            values: None,
        },
        IpcPayload::Connect,
        IpcPayload::Disconnect { reason: None },
        IpcPayload::Custom {
            data: Value::Object(serde_json::Map::new()),
        },
    ];

    assert_eq!(
        representatives.len(),
        EXPECTED_VARIANT_COUNT,
        "IpcPayload variant count changed. Update the representatives list \
         and bump EXPECTED_VARIANT_COUNT."
    );

    for variant in &representatives {
        let json = serde_json::to_value(variant).unwrap();
        let tag = json["type"]
            .as_str()
            .unwrap_or_else(|| panic!("variant {variant:?} has no `type` tag"));
        assert!(
            IpcPayload::is_known_tag(tag),
            "is_known_tag does not recognise tag '{tag}' from variant {variant:?}"
        );
    }
}

#[test]
fn is_known_tag_rejects_unknown_tags() {
    assert!(!IpcPayload::is_known_tag("my_plugin_msg"));
    assert!(!IpcPayload::is_known_tag("unknown"));
    assert!(!IpcPayload::is_known_tag(""));
    assert!(!IpcPayload::is_known_tag("Raw_Json"));
}

#[test]
fn grant_required_roundtrips_with_tag() {
    let payload = IpcPayload::GrantRequired {
        request_id: "req-1".into(),
        principal: "alice".into(),
        capsule_id: "secret-tool".into(),
    };
    let json = serde_json::to_value(&payload).unwrap();
    assert_eq!(json["type"].as_str(), Some("grant_required"));
    assert!(IpcPayload::is_known_tag("grant_required"));

    let parsed: IpcPayload = serde_json::from_value(json).unwrap();
    assert_eq!(parsed, payload);
}

#[test]
fn onboarding_field_roundtrip() {
    let field = OnboardingField {
        key: "apiKey".into(),
        prompt: "Enter API key".into(),
        description: None,
        field_type: OnboardingFieldType::Secret,
        default: None,
        placeholder: None,
    };
    let json = serde_json::to_string(&field).unwrap();
    let parsed: OnboardingField = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, field);
}

#[test]
fn onboarding_field_roundtrip_array() {
    let field = OnboardingField {
        key: "relays".into(),
        prompt: "Enter relay URLs".into(),
        description: Some("Nostr relay endpoints".into()),
        field_type: OnboardingFieldType::Array,
        default: None,
        placeholder: None,
    };
    let json = serde_json::to_string(&field).unwrap();
    let parsed: OnboardingField = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, field);
}

#[test]
fn onboarding_required_payload_roundtrip() {
    let payload = IpcPayload::OnboardingRequired {
        capsule_id: "test-capsule".into(),
        fields: vec![
            OnboardingField {
                key: "network".into(),
                prompt: "Select network".into(),
                description: Some("Choose the target network".into()),
                field_type: OnboardingFieldType::Enum(vec!["testnet".into(), "mainnet".into()]),
                default: Some("testnet".into()),
                placeholder: None,
            },
            OnboardingField {
                key: "apiKey".into(),
                prompt: "Enter API key".into(),
                description: None,
                field_type: OnboardingFieldType::Secret,
                default: None,
                placeholder: None,
            },
        ],
    };
    let json = serde_json::to_string(&payload).unwrap();
    let parsed: IpcPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, payload);
}

#[test]
fn elicit_request_roundtrip() {
    let payload = IpcPayload::ElicitRequest {
        request_id: Uuid::nil(),
        capsule_id: "my-capsule".into(),
        field: OnboardingField {
            key: "api_url".into(),
            prompt: "Enter API URL".into(),
            description: Some("The backend endpoint".into()),
            field_type: OnboardingFieldType::Text,
            default: Some("https://example.com".into()),
            placeholder: None,
        },
    };
    let json = serde_json::to_string(&payload).unwrap();
    let parsed: IpcPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, payload);
}

#[test]
fn elicit_response_roundtrip() {
    let payload = IpcPayload::ElicitResponse {
        request_id: Uuid::nil(),
        value: Some("hello".into()),
        values: None,
    };
    let json = serde_json::to_string(&payload).unwrap();
    let parsed: IpcPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, payload);
}

#[test]
fn disconnect_with_reason_roundtrip() {
    let payload = IpcPayload::Disconnect {
        reason: Some("quit".into()),
    };
    let json = serde_json::to_string(&payload).unwrap();
    let parsed: IpcPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, payload);
    assert!(json.contains(r#""type":"disconnect""#), "json: {json}");
}

#[test]
fn disconnect_without_reason_roundtrip() {
    let payload = IpcPayload::Disconnect { reason: None };
    let json = serde_json::to_string(&payload).unwrap();
    let parsed: IpcPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, payload);
    assert!(!json.contains("reason"), "json: {json}");
}

#[test]
fn to_guest_bytes_custom_returns_inner_data() {
    let data = serde_json::json!({"session_id": "abc", "messages": []});
    let payload = IpcPayload::Custom { data: data.clone() };
    let bytes = payload.to_guest_bytes().unwrap();
    let roundtrip: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(roundtrip, data);
    assert!(roundtrip.get("type").is_none());
}

#[test]
fn to_guest_bytes_structured_preserves_type_tag() {
    let payload = IpcPayload::UserInput {
        text: "hello".into(),
        session_id: "default".into(),
        context: None,
    };
    let bytes = payload.to_guest_bytes().unwrap();
    let roundtrip: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        roundtrip.get("type").and_then(|v| v.as_str()),
        Some("user_input")
    );
}

#[test]
fn to_guest_bytes_raw_json_unwraps() {
    let inner = serde_json::json!({"key": "value"});
    let payload = IpcPayload::RawJson(inner.clone());
    let bytes = payload.to_guest_bytes().unwrap();
    let roundtrip: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(roundtrip, inner);
    assert!(roundtrip.get("type").is_none());
}

#[test]
fn to_guest_bytes_connect_unit_variant() {
    let payload = IpcPayload::Connect;
    let bytes = payload.to_guest_bytes().unwrap();
    let roundtrip: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        roundtrip.get("type").and_then(|v| v.as_str()),
        Some("connect")
    );
}

#[test]
fn from_json_value_unknown_tag_becomes_custom() {
    let data = serde_json::json!({"type": "my_plugin_msg", "foo": 42});
    let payload = IpcPayload::from_json_value(data.clone());
    assert_eq!(payload, IpcPayload::Custom { data });
}

#[test]
fn from_json_value_known_tag_parses() {
    let data = serde_json::json!({
        "type": "user_input",
        "text": "hi",
        "session_id": "s1"
    });
    let payload = IpcPayload::from_json_value(data);
    assert!(matches!(payload, IpcPayload::UserInput { .. }));
}

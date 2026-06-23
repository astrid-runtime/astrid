//! Cross-boundary IPC message schemas and payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// A cross-boundary message sent over the event bus between WASM guests and the host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IpcMessage {
    /// Topic pattern or exact match (e.g., `astrid.cli.input`).
    pub topic: String,
    /// Standardized payload structure.
    pub payload: IpcPayload,
    /// Optional cryptographic signature for stateless verification across a distributed swarm.
    #[serde(default)]
    pub signature: Option<Vec<u8>>,
    /// Identifier of the sender plugin or agent.
    pub source_id: Uuid,
    /// Timestamp when the message was dispatched. Defaults to now on
    /// deserialization so capsules forwarding bus messages over the wire
    /// (e.g. the CLI proxy) don't need to fabricate a timestamp the SDK
    /// doesn't expose to them. Only filled in by the `clock` feature
    /// path (kernel-side); when the feature is off (capsule SDK
    /// consumption on `wasm32-unknown-unknown`), missing timestamps
    /// fall back to the Unix epoch — capsules read timestamps from
    /// kernel-published messages, they never construct fresh ones.
    #[cfg_attr(feature = "clock", serde(default = "Utc::now"))]
    #[cfg_attr(not(feature = "clock"), serde(default = "default_unix_epoch"))]
    pub timestamp: DateTime<Utc>,
    /// Monotonic sequence number assigned by the event bus at publish time.
    /// Used by the dispatcher to guarantee in-order delivery per capsule.
    #[serde(default)]
    pub seq: u64,
    /// The principal (user identity) this message is acting on behalf of.
    ///
    /// `String` rather than `PrincipalId` because `astrid-types` must not
    /// depend on `astrid-core`. Validation to `PrincipalId` happens at the
    /// kernel boundary. `None` for system events (boot, lifecycle).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,

    /// The device key that authenticated this message, if any.
    ///
    /// Identifies which registered `DeviceKey` on the acting principal's
    /// `AuthConfig` this message was authenticated with, so the cap-gate can
    /// apply that device's scope as an attenuation floor on the principal's
    /// effective capabilities. `None` means an unattenuated (full-principal)
    /// message — the legacy behaviour for every existing connection.
    ///
    /// This is **host-derived** internal bus metadata, NOT a client-settable
    /// hint: it is stamped from the per-connection registry on the socket
    /// path (or the gateway-signed bearer on the HTTP path), never read off a
    /// client-controlled field. Like `principal`, it is a `String` because
    /// `astrid-types` must not depend on `astrid-core`; resolution to a live
    /// `DeviceKey` happens at the kernel boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_key_id: Option<String>,
}

/// `DateTime<Utc>` at the Unix epoch — used as the serde default for
/// `timestamp` fields when the `clock` feature is off and a message
/// arrives without one. Capsule-side code never inspects this value;
/// kernel-side code always sets a real timestamp before publish.
#[cfg(not(feature = "clock"))]
fn default_unix_epoch() -> DateTime<Utc> {
    // chrono guarantees epoch is representable; the `unwrap_or`
    // branch is unreachable. `MIN_UTC` is the safe fallback if that
    // contract ever changes.
    DateTime::<Utc>::from_timestamp(0, 0).unwrap_or(DateTime::<Utc>::MIN_UTC)
}

impl IpcMessage {
    /// Create a new IPC message stamped with the current wall-clock
    /// time. Only available when the `clock` feature is enabled
    /// (kernel-side); capsule code constructs `IpcMessage` from
    /// payloads it receives, never from scratch.
    #[cfg(feature = "clock")]
    #[must_use]
    pub fn new(topic: impl Into<String>, payload: IpcPayload, source_id: Uuid) -> Self {
        Self {
            topic: topic.into(),
            payload,
            signature: None,
            source_id,
            timestamp: Utc::now(),
            seq: 0,
            principal: None,
            device_key_id: None,
        }
    }

    /// Attach a signature for swarm verification.
    #[must_use]
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Set the acting principal for this message.
    #[must_use]
    pub fn with_principal(mut self, principal: impl Into<String>) -> Self {
        self.principal = Some(principal.into());
        self
    }

    /// Set the authenticating device key id for this message.
    ///
    /// Host-derived metadata used by the cap-gate to apply per-device scope
    /// attenuation. Callers on the host paths stamp this from the
    /// per-connection registry / signed bearer; it is never sourced from a
    /// client-controlled field.
    #[must_use]
    pub fn with_device_key_id(mut self, id: impl Into<String>) -> Self {
        self.device_key_id = Some(id.into());
        self
    }
}

/// Default session ID for conversations.
fn default_session_id() -> String {
    "default".into()
}

/// Standardized cross-boundary payload schemas.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcPayload {
    /// Raw, arbitrary JSON.
    RawJson(Value),
    /// User input provided via a frontend (CLI, Telegram).
    UserInput {
        /// The raw text input.
        text: String,
        /// Session ID for conversation continuity. Defaults to `"default"`.
        #[serde(default = "default_session_id")]
        session_id: String,
        /// Optional extra context.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context: Option<Value>,
    },
    /// A response generated by an agent.
    AgentResponse {
        /// The text output.
        text: String,
        /// True if this is the final response in a chain.
        is_final: bool,
        /// Session ID for multi-session attribution.
        #[serde(default = "default_session_id")]
        session_id: String,
    },
    /// An interceptor or capsule request for capability approval.
    ApprovalRequired {
        /// Opaque correlation ID.
        request_id: String,
        /// The action being requested (e.g. "git push").
        action: String,
        /// The resource target (e.g. full command string).
        resource: String,
        /// Justification.
        reason: String,
    },
    /// Response to an [`ApprovalRequired`](IpcPayload::ApprovalRequired).
    ApprovalResponse {
        /// Must match the `request_id` from the originating request.
        request_id: String,
        /// The user's decision.
        decision: String,
        /// Optional reason for the decision.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// A grant-on-first-use signal: principal `principal` invoked a tool from
    /// capsule `capsule_id` that they do not currently hold. The broker/shim
    /// elicits consent and, on approve, the kernel grants the capsule.
    /// Distinct from [`ApprovalRequired`](IpcPayload::ApprovalRequired) so the
    /// broker can tell a grant-on-use from a plain capability approval.
    GrantRequired {
        /// Unguessable correlation id (a UUID) the response is keyed on, used
        /// to build `astrid.v1.approval.response.<request_id>`.
        request_id: String,
        /// The kernel-stamped caller principal that hit the access-gate miss.
        principal: String,
        /// The capsule id the principal needs granted.
        capsule_id: String,
    },
    /// A capsule needs environment variables to be provided by the user.
    OnboardingRequired {
        /// The ID of the capsule requiring onboarding.
        capsule_id: String,
        /// Rich field descriptors for each missing env var.
        fields: Vec<OnboardingField>,
    },
    /// Request an LLM provider capsule to generate a response.
    LlmRequest {
        /// The unique ID of the request, used for routing the response stream back.
        request_id: Uuid,
        /// The requested model name (e.g. "claude-3-5-sonnet").
        model: String,
        /// The conversation history.
        messages: Vec<crate::llm::Message>,
        /// The tools available to the model.
        tools: Vec<crate::llm::LlmToolDefinition>,
        /// The system prompt.
        system: String,
    },
    /// A stream event from an LLM provider capsule.
    LlmStreamEvent {
        /// The unique ID of the request this stream belongs to.
        request_id: Uuid,
        /// The actual stream event (`TokenDelta`, `ToolCallStart`, etc).
        event: crate::llm::StreamEvent,
    },
    /// The final, non-streaming LLM response.
    LlmResponse {
        /// The unique ID of the request this response belongs to.
        request_id: Uuid,
        /// The final response object.
        response: crate::llm::LlmResponse,
    },
    /// Request the Tool Router capsule to execute a tool.
    ToolExecuteRequest {
        /// The unique ID of the tool call.
        call_id: String,
        /// The name of the tool to execute.
        tool_name: String,
        /// The JSON arguments.
        arguments: Value,
    },
    /// The result of a tool execution.
    ToolExecuteResult {
        /// The unique ID of the tool call.
        call_id: String,
        /// The result of the execution.
        result: crate::llm::ToolCallResult,
    },
    /// Request cancellation of in-flight tool executions.
    ToolCancelRequest {
        /// The call IDs of the tool invocations to cancel.
        call_ids: Vec<String>,
    },
    /// A capsule is requesting the user to select from a list of options.
    SelectionRequired {
        /// Opaque ID so the capsule can correlate the response.
        request_id: String,
        /// Title/prompt shown above the list.
        title: String,
        /// The selectable options.
        options: Vec<SelectionOption>,
        /// IPC topic to publish the user's choice back on.
        callback_topic: String,
    },
    /// A lifecycle hook is requesting user input via the `elicit` API.
    ElicitRequest {
        /// Correlation ID.
        request_id: Uuid,
        /// The capsule requesting input.
        capsule_id: String,
        /// Field descriptor reusing the onboarding schema.
        field: OnboardingField,
    },
    /// Response to an [`ElicitRequest`](IpcPayload::ElicitRequest).
    ElicitResponse {
        /// Must match the `request_id` from the originating request.
        request_id: Uuid,
        /// The user's input. `None` if the user cancelled.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        /// For `Array`-type fields, the collected items.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        values: Option<Vec<String>>,
    },
    /// A client has connected.
    Connect,
    /// A client is disconnecting gracefully.
    Disconnect {
        /// Optional reason for disconnection (e.g. "quit", "timeout").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Arbitrary JSON data for unstructured plugins.
    Custom {
        /// Raw data.
        data: Value,
    },
    /// Unrecognized payload type from a newer protocol version.
    #[serde(other)]
    Unknown,
}

impl IpcPayload {
    /// Returns `true` if `tag` matches a known serde variant name.
    #[must_use]
    pub fn is_known_tag(tag: &str) -> bool {
        matches!(
            tag,
            "raw_json"
                | "user_input"
                | "agent_response"
                | "approval_required"
                | "approval_response"
                | "grant_required"
                | "onboarding_required"
                | "llm_request"
                | "llm_stream_event"
                | "llm_response"
                | "tool_execute_request"
                | "tool_execute_result"
                | "tool_cancel_request"
                | "selection_required"
                | "elicit_request"
                | "elicit_response"
                | "connect"
                | "disconnect"
                | "custom"
        )
    }

    /// Deserialize a JSON [`Value`] into an `IpcPayload`, falling back to
    /// [`Custom`](Self::Custom) for unrecognised or missing type tags.
    pub fn from_json_value(data: Value) -> Self {
        let is_known = data
            .get("type")
            .and_then(|v| v.as_str())
            .is_some_and(Self::is_known_tag);

        if is_known {
            serde_json::from_value::<Self>(data.clone()).unwrap_or(Self::Custom { data })
        } else {
            Self::Custom { data }
        }
    }

    /// Serialize only the guest-facing payload data.
    ///
    /// [`Custom`](Self::Custom) and [`RawJson`](Self::RawJson) payloads return
    /// the inner data value directly (no `type` wrapper). Structured variants
    /// return the full tagged serialization.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if serialization fails.
    pub fn to_guest_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        match self {
            Self::Custom { data } | Self::RawJson(data) => serde_json::to_vec(data),
            other => serde_json::to_vec(other),
        }
    }
}

/// A single option in a `SelectionRequired` picker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SelectionOption {
    /// Machine-readable identifier sent back to the capsule.
    pub id: String,
    /// Human-readable label shown in the picker.
    pub label: String,
    /// Optional description shown alongside the label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A field descriptor for capsule onboarding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OnboardingField {
    /// The environment variable key.
    pub key: String,
    /// The prompt shown to the user.
    pub prompt: String,
    /// Optional description for additional context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The input type for this field.
    pub field_type: OnboardingFieldType,
    /// Optional default value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Placeholder hint text shown when the input is empty (e.g. `"sk-..."`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
}

/// The type of input expected for an onboarding field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OnboardingFieldType {
    /// Free-form text input.
    Text,
    /// Masked secret input.
    Secret,
    /// Selection from a fixed set of choices.
    Enum(Vec<String>),
    /// Multi-value array input (user adds items one at a time).
    Array,
}

#[cfg(test)]
mod tests {
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
}

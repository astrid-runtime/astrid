//! Cross-boundary IPC message schemas and payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Where a routed [`IpcMessage`] entered the system — the **transport
/// origin** of the request, host-stamped at the listener ingress.
///
/// This is the provenance an egress site (e.g. the `astrid:http` SSRF airlock)
/// uses to tell a *local operator* request (arrived over the kernel-verified
/// Unix socket) from a *remote API caller* request (arrived over the gateway
/// HTTP listener). Like [`IpcMessage::device_key_id`] it is **host-derived
/// internal-bus metadata, never a client-settable hint**: the kernel stamps it
/// at each listener ingress and propagates the *originating* request's value
/// through fan-out / publish-as, so a guest can neither set nor elevate it.
///
/// # Fail-closed default
///
/// An absent field (a legacy peer that predates it, the CLI-proxy wire format
/// that omits it) and an unknown/future variant both resolve to [`System`] via
/// `#[serde(default)]` + `#[serde(other)]`. [`System`] is the **non-local**
/// floor: an egress site that grants local-operator privilege only to
/// [`LocalSocket`] therefore treats every unattributed message as remote and
/// fails closed.
///
/// [`System`]: MessageOrigin::System
/// [`LocalSocket`]: MessageOrigin::LocalSocket
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MessageOrigin {
    /// The request entered over the **local Unix socket** on a connection the
    /// kernel verified at the handshake (a bound [`ConnectionIdentity`]). This
    /// is the positive "local operator" signal — the only origin that may earn
    /// runtime local-egress consent. An unbound (unauthenticated) local
    /// connection does NOT earn this; it stays [`System`](Self::System),
    /// parallel to how an unbound principal stamps the reserved `anonymous`
    /// identity.
    ///
    /// [`ConnectionIdentity`]: ../../astrid_capsule/index.html
    LocalSocket,
    /// The request entered over the **gateway HTTP listener** (a remote API
    /// caller, even one bearing a valid signed bearer). Stamped at the gateway
    /// bus-publish sites. A remote request is never a local operator, so this
    /// origin never earns runtime local-egress consent — it is as non-local as
    /// [`System`](Self::System) for that decision, but named distinctly so the
    /// provenance is explicit in audit.
    RemoteGateway,
    /// System / internal origin: a kernel-originated event (boot, lifecycle), a
    /// capsule-to-capsule mesh publish with no inbound request behind it, an
    /// UNBOUND local socket connection (no verified handshake identity), or any
    /// frame that predates / does not carry the marker. This is the
    /// **fail-closed, non-local** default — it earns no local-operator
    /// privilege at an egress site.
    ///
    /// Declared LAST because `#[serde(other)]` (the unknown-variant fallback)
    /// must sit on the final variant: a future / unknown origin string from a
    /// newer peer deserializes here, so a remote peer cannot smuggle local
    /// privilege via an unrecognised value.
    #[default]
    #[serde(other)]
    System,
}

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

    /// The transport origin this message entered the system on — see
    /// [`MessageOrigin`].
    ///
    /// **Host-derived internal-bus metadata, never a client-settable hint**,
    /// exactly like [`device_key_id`](Self::device_key_id): the kernel stamps it
    /// at each listener ingress and propagates the *originating* request's value
    /// through fan-out / publish-as. A guest can neither set it on a `publish`
    /// nor elevate it. Absent on the wire (legacy peers, the CLI-proxy frame)
    /// resolves to [`MessageOrigin::System`] — the fail-closed, non-local floor
    /// — and is skipped on serialization so it stays off the wire for the
    /// common system-origin case (legacy compatibility, parallel to `seq` /
    /// `device_key_id`).
    #[serde(default, skip_serializing_if = "MessageOrigin::is_system")]
    pub origin: MessageOrigin,
}

impl MessageOrigin {
    /// `true` for the fail-closed [`System`](Self::System) default. Used as the
    /// `skip_serializing_if` predicate so a system-origin message keeps the
    /// legacy wire shape (no `origin` key).
    #[must_use]
    pub fn is_system(&self) -> bool {
        matches!(self, Self::System)
    }
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
            origin: MessageOrigin::System,
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

    /// Set the host-stamped transport [`origin`](Self::origin) for this message.
    ///
    /// Host-derived metadata stamped at a listener ingress (socket / gateway) or
    /// carried forward from the originating in-flight request through fan-out /
    /// publish-as. It is **never** sourced from a guest argument: a guest
    /// `publish` always inherits its caller-context's origin, never names one.
    #[must_use]
    pub fn with_origin(mut self, origin: MessageOrigin) -> Self {
        self.origin = origin;
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
#[path = "ipc_tests.rs"]
mod tests;

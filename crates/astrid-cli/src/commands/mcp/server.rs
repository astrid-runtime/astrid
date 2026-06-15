//! The rmcp [`ServerHandler`] shim over the daemon broker surface.
//!
//! [`AstridMcpServer`] implements just three MCP request handlers:
//!
//! * [`get_info`](AstridMcpServer::get_info) — advertises a tools-only
//!   server with `tools.listChanged = true`.
//! * [`list_tools`](ServerHandler::list_tools) — bridges to
//!   `astrid.v1.request.mcp.tools.list`.
//! * [`call_tool`](ServerHandler::call_tool) — bridges to
//!   `astrid.v1.request.mcp.tool.call`.
//!
//! Every other MCP method falls through to rmcp's `method_not_found`
//! defaults — this is a pure tool broker.
//!
//! ## Correlation contract
//!
//! Each bridged request mints a fresh `req_id` (a dashless UUID, so it
//! is a single charset-clean topic segment the broker's egress gate
//! accepts), mirrors it into the request body, publishes on the request
//! topic, then awaits the single-segment reply topic
//! `astrid.v1.response.<req_id>` for up to [`REQUEST_DEADLINE`]. The
//! broker echoes `req_id` in the body, but the shim correlates purely on
//! the response topic (unique per request); the body copy exists for the
//! broker's own logging and is not read back here. Concurrent calls never
//! collide because each holds a distinct response topic.
//!
//! ## Connection lifetime
//!
//! The shim holds ONE [`SocketClient`] for its whole lifetime, behind a
//! [`Mutex`] so the `&self` handlers can take exclusive read/write
//! access for the publish-then-await round trip. Holding the lock across
//! the await serializes round trips — acceptable here because a single
//! MCP stdio client issues requests sequentially, and it guarantees a
//! reply frame is never consumed by the wrong waiter.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use rmcp::ErrorData as McpError;
use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, Implementation, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::socket_client::SocketClient;

use super::elicit;
use super::ingress;

/// Request topic for the broker `tools/list` front door.
pub(super) const TOOLS_LIST_TOPIC: &str = "astrid.v1.request.mcp.tools.list";
/// Request topic for the broker `tools/call` front door.
const TOOL_CALL_TOPIC: &str = "astrid.v1.request.mcp.tool.call";
/// Egress topic prefix the broker replies on (`<prefix><req_id>`).
pub(super) const RESPONSE_PREFIX: &str = "astrid.v1.response.";

/// Shim-side deadline for a single broker round trip. The broker bounds
/// its own tool drain at 50 s; this sits just above that so a slow tool
/// surfaces as a broker-side `isError` reply rather than a shim timeout.
const REQUEST_DEADLINE: Duration = Duration::from_secs(55);

/// MCP server shim bridging a stdio client to the daemon tool broker.
pub(crate) struct AstridMcpServer {
    /// The single long-lived uplink, shared across `&self` handlers.
    client: Arc<Mutex<SocketClient>>,
    /// Principal stamped on every outbound IPC message.
    principal: String,
}

impl AstridMcpServer {
    /// Build a new shim over an established uplink and resolved principal.
    pub(crate) fn new(client: Arc<Mutex<SocketClient>>, principal: String) -> Self {
        Self { client, principal }
    }

    /// Publish `body` on `request_topic` and await the broker reply on
    /// `astrid.v1.response.<req_id>`, returning the inner reply object.
    ///
    /// `req_id` must already be a charset-clean single segment (it is —
    /// see [`new_req_id`]). The reply body is unwrapped from its IPC
    /// payload envelope before being returned.
    async fn round_trip(
        &self,
        request_topic: &str,
        req_id: &str,
        body: Value,
    ) -> Result<Value, McpError> {
        let reply_topic = format!("{RESPONSE_PREFIX}{req_id}");

        let msg = astrid_types::ipc::IpcMessage::new(
            request_topic,
            astrid_types::ipc::IpcPayload::RawJson(body),
            // Source attribution is set by the kernel from the
            // authenticated connection, not this field; match the other
            // CLI uplink verbs and send nil.
            Uuid::nil(),
        )
        .with_principal(self.principal.clone());

        let mut client = self.client.lock().await;

        // Survive a daemon restart. If the publish fails — e.g. the daemon
        // rebound `system.sock` under us and our socket is now a dead fd
        // (`Broken pipe`) — re-dial the live daemon once and retry. Retrying
        // is safe precisely because the *send* failed: the request never
        // reached the broker, so no tool ran and there is no double-execution
        // risk. A failure *after* a successful send is surfaced (below), not
        // retried, since the routed tool may already have executed.
        if let Err(first) = client.send_message(msg.clone()).await {
            warn!(topic = request_topic, error = %first, "MCP shim: broker publish failed; reconnecting to daemon and retrying once");
            client.reconnect().await.map_err(|e| {
                warn!(error = %e, "MCP shim: reconnect to daemon failed");
                McpError::internal_error(format!("reconnect to daemon failed: {e}"), None)
            })?;
            client.send_message(msg).await.map_err(|e| {
                warn!(topic = request_topic, error = %e, "MCP shim: failed to publish broker request after reconnect");
                McpError::internal_error(format!("failed to publish broker request after reconnect: {e}"), None)
            })?;
        }

        let raw = client
            .read_until_topic(&reply_topic, REQUEST_DEADLINE)
            .await
            .map_err(|e| {
                warn!(topic = %reply_topic, error = %e, "MCP shim: broker reply not received");
                McpError::internal_error(format!("broker reply not received: {e}"), None)
            })?;

        Ok(unwrap_reply_payload(&raw))
    }
}

impl ServerHandler for AstridMcpServer {
    fn get_info(&self) -> ServerInfo {
        // Tools-only server. `listChanged = true` tells the client the
        // tool surface can change at runtime (capsules load/unload), so
        // it should honour `notifications/tools/list_changed`.
        let mut capabilities = ServerCapabilities::default();
        capabilities.tools = Some(rmcp::model::ToolsCapability {
            list_changed: Some(true),
        });

        // `ServerInfo` (`InitializeResult`) is `#[non_exhaustive]`, so it
        // must be built through its constructor + setters rather than a
        // struct literal.
        ServerInfo::new(capabilities)
            .with_server_info(Implementation::new("astrid", env!("CARGO_PKG_VERSION")))
            // Pin the advertised revision to exactly the one this server is
            // built and verified against, rather than `ProtocolVersion::LATEST`
            // (which would silently advance on a future rmcp bump to a spec we
            // have not yet implemented). Bump deliberately when adopting a newer
            // revision. rmcp negotiates older clients down at `initialize`.
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_instructions("Astrid secure agent runtime — capsule tools bridged over MCP.")
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let req_id = new_req_id();
        let body = json!({ "req_id": req_id });

        let reply = self.round_trip(TOOLS_LIST_TOPIC, &req_id, body).await?;

        let tools = reply
            .get("tools")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(tool_from_descriptor).collect())
            .unwrap_or_default();

        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let arguments = request.arguments.map_or(Value::Null, Value::Object);

        // Build the broker `tool.call` body for a fresh `req_id`. The same
        // (name, arguments) may be sent twice — once that trips the ingress
        // consent gate, then once more after consent is recorded — each with
        // its own correlation id so their replies never collide.
        let call_body = |req_id: &str| {
            json!({
                "req_id": req_id,
                "name": request.name,
                "arguments": arguments,
            })
        };

        let req_id = new_req_id();
        let reply = self
            .round_trip(TOOL_CALL_TOPIC, &req_id, call_body(&req_id))
            .await?;

        // If the broker gated the call on an untrusted ingress, it replies an
        // `ingress_approval_required` signal (NOT a result). Elicit the user's
        // consent; on accept, record trust via the broker and RE-SEND the
        // original call (now passing the gate). On deny / no-capability /
        // error, fail secure with an MCP error.
        let reply = if let Some(ingress) = ingress::IngressRequest::from_reply(&reply) {
            let granted = self.resolve_ingress(&context.peer, &ingress).await?;
            if !granted {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Astrid tool calls were not authorized for this session.",
                )]));
            }
            // Re-send the original call now that the ingress is trusted.
            let retry_id = new_req_id();
            self.round_trip(TOOL_CALL_TOPIC, &retry_id, call_body(&retry_id))
                .await?
        } else {
            reply
        };

        // If the routed tool parked on a capability approval, the broker
        // surfaces an `approval_required` flag instead of a terminal result.
        // Elicit the choice from the client, forward the decision to the
        // broker, and use the broker's resumed/denied reply as the terminal
        // result. The non-parked path skips this entirely.
        let reply = if let Some(approval) = elicit::ApprovalRequest::from_reply(&reply) {
            self.resolve_approval(&context.peer, &approval).await?
        } else {
            reply
        };

        Ok(call_tool_result_from_reply(&reply))
    }
}

impl AstridMcpServer {
    /// Drive the approval bridge for a parked `tools/call`: elicit a decision
    /// from the client, forward it on the broker's
    /// [`APPROVAL_RESPOND_TOPIC`](elicit::APPROVAL_RESPOND_TOPIC) front door,
    /// and return the broker's terminal `tool.call` reply (the resumed
    /// result on approve, or the `isError` result on deny).
    ///
    /// A fresh `req_id` keys the terminal reply on its own response topic so
    /// it never collides with the original parked round trip. Fail-secure:
    /// the decision defaults to `deny` when the client cannot or will not
    /// elicit (see [`elicit::resolve_decision`]), so an unanswered approval
    /// retires the tool cleanly rather than hanging on the host timeout.
    async fn resolve_approval(
        &self,
        peer: &rmcp::service::Peer<RoleServer>,
        approval: &elicit::ApprovalRequest,
    ) -> Result<Value, McpError> {
        let respond_req_id = new_req_id();
        let (_decision, respond_body) =
            elicit::resolve_decision(peer, approval, &respond_req_id).await;

        self.round_trip(
            elicit::APPROVAL_RESPOND_TOPIC,
            &respond_req_id,
            respond_body,
        )
        .await
    }

    /// Drive the ingress-consent bridge for a `tools/call` the broker gated on
    /// an untrusted ingress: elicit the user's decision and, on accept,
    /// forward it on the broker's
    /// [`INGRESS_RESPOND_TOPIC`](ingress::INGRESS_RESPOND_TOPIC) front door so
    /// the broker records trust (keyed on the kernel-stamped caller, never a
    /// body field). Returns whether the ingress is now trusted — `true` only
    /// when the user accepted AND the broker confirmed it persisted the grant.
    ///
    /// Fail-secure: a decline / no-capability / elicit error never sends a
    /// respond and returns `false`. An accept that the broker could not
    /// persist (ack `granted:false`) also returns `false` so the caller does
    /// not re-send a call that would just trip the gate again.
    async fn resolve_ingress(
        &self,
        peer: &rmcp::service::Peer<RoleServer>,
        request: &ingress::IngressRequest,
    ) -> Result<bool, McpError> {
        if !ingress::elicit_consent(peer, request).await {
            return Ok(false);
        }

        // The respond body carries NO source_id — the broker trusts the
        // kernel-stamped caller of this message. A fresh req_id keys the ack.
        let respond_req_id = new_req_id();
        let respond_body = json!({ "req_id": respond_req_id, "accept": true });

        let ack = self
            .round_trip(
                ingress::INGRESS_RESPOND_TOPIC,
                &respond_req_id,
                respond_body,
            )
            .await?;

        let granted = ack.get("granted").and_then(Value::as_bool).unwrap_or(false);
        if !granted {
            warn!("MCP shim: broker did not confirm ingress trust grant; not retrying call");
        }
        Ok(granted)
    }
}

/// Reshape a broker terminal `tool.call` reply
/// (`{ content, isError }`) into an rmcp [`CallToolResult`]. Shared by the
/// non-parked path and the post-approval path because the broker delivers an
/// identical shape on both.
fn call_tool_result_from_reply(reply: &Value) -> CallToolResult {
    let content = reply
        .get("content")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(content_from_block).collect())
        .unwrap_or_default();

    let is_error = reply
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // `CallToolResult` is `#[non_exhaustive]`; use the success/error
    // constructors, which set `is_error` for us.
    if is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    }
}

/// Mint a fresh correlation id: a dashless UUID is exactly one
/// charset-clean topic segment, which the broker's egress gate accepts
/// and which `read_until_topic` can match verbatim.
pub(super) fn new_req_id() -> String {
    Uuid::new_v4().simple().to_string()
}

/// Unwrap the broker reply object from its IPC payload envelope.
///
/// A `RawJson` payload serializes on the wire as
/// `{ "type": "raw_json", "value": <inner> }`. Mirror
/// [`SocketClient::extract_kernel_response`]'s unwrap so a future change
/// to the payload wrapper only needs touching in one place's logic.
/// Falls back to the bare `payload` (and finally an empty object) when
/// the shape is unexpected, so a malformed frame degrades to an empty
/// reply rather than panicking.
pub(super) fn unwrap_reply_payload(raw: &Value) -> Value {
    let Some(payload) = raw.get("payload") else {
        return Value::Object(Map::new());
    };
    if payload
        .as_object()
        .is_some_and(|m| m.contains_key("type") && m.contains_key("value"))
    {
        return payload
            .get("value")
            .cloned()
            .unwrap_or_else(|| payload.clone());
    }
    payload.clone()
}

/// Translate one broker MCP descriptor
/// (`{ name, title?, description, inputSchema, capabilities? }`) into an
/// rmcp [`Tool`]. Descriptors missing a name or schema object are
/// skipped — the broker already charset-gates names, so this is a
/// shape, not a trust, check.
fn tool_from_descriptor(desc: &Value) -> Option<Tool> {
    let name = desc.get("name").and_then(Value::as_str)?.to_string();

    // `Tool::input_schema` is a JSON object; default to an empty schema
    // when the descriptor omits or malforms it rather than dropping the
    // tool entirely.
    let input_schema = desc
        .get("inputSchema")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let description = desc
        .get("description")
        .and_then(Value::as_str)
        .map(|s| Cow::Owned(s.to_string()));

    let mut tool = Tool::new_with_raw(name, description, Arc::new(input_schema));
    if let Some(title) = desc.get("title").and_then(Value::as_str) {
        tool = tool.with_title(title);
    }
    Some(tool)
}

/// Translate one broker content block into rmcp [`Content`].
///
/// The broker emits `{ "type": "text", "text": "..." }` blocks. Anything
/// that is not a recognized text block is serialized to JSON text so the
/// payload always reaches the MCP client as valid content.
fn content_from_block(block: &Value) -> Content {
    if block.get("type").and_then(Value::as_str) == Some("text")
        && let Some(text) = block.get("text").and_then(Value::as_str)
    {
        return Content::text(text.to_string());
    }
    debug!("MCP shim: non-text broker content block, serializing to text");
    Content::text(block.to_string())
}

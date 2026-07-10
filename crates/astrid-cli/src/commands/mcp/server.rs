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
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use astrid_uplink::socket_client::ReadError;
use rmcp::ErrorData as McpError;
use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, Implementation, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::socket_client::SocketClient;

use super::elicit;
use super::grant;
use super::ingress;

/// Request topic for the broker `tools/list` front door.
pub(super) const TOOLS_LIST_TOPIC: &str = "astrid.v1.request.mcp.tools.list";
/// Request topic for the broker `tools/call` front door.
const TOOL_CALL_TOPIC: &str = "astrid.v1.request.mcp.tool.call";

/// Shim-side deadline for a single broker round trip. The broker bounds
/// its own tool drain at 50 s; this sits just above that so a slow tool
/// surfaces as a broker-side `isError` reply rather than a shim timeout.
const REQUEST_DEADLINE: Duration = Duration::from_secs(55);

/// Upper bound on grant-on-use resolutions the shim will drive within a
/// SINGLE `tools/call` before failing the call with a terminal error.
///
/// A fresh principal can be missing several view capsules at once (#1113): each
/// re-sent call trips the access gate on the NEXT ungranted capsule, so one
/// user-issued call may legitimately require a short sequence of grant prompts.
/// This bounds that sequence so a broker that keeps replying `grant_required`
/// (a bug, or an adversarial surface) can never spin the shim forever. Each
/// prompt still requires an explicit user accept, so the bound is a backstop,
/// not the consent mechanism. Sized for a whole distro's worth of capsules
/// resolving on one call; exceeding it yields an honest `isError`
/// ([`GRANT_BOUND_EXCEEDED_MESSAGE`]), never a fabricated empty success.
const MAX_GRANT_RESOLUTIONS: usize = 8;

/// Terminal error text when a `grant_required` signal is present but
/// unanswerable (malformed shape / missing routing token). Kept as a constant
/// so the loop and its unit tests stay in lockstep.
const MALFORMED_GRANT_MESSAGE: &str =
    "Astrid returned a malformed capsule-grant signal; the tool call was dropped.";

/// Terminal error text when a grant was surfaced but not granted (user
/// declined, or the broker did not persist the grant).
const GRANT_DENIED_MESSAGE: &str = "Capsule access was not granted for this tool.";

/// Terminal error text when a single `tools/call` needed more grant
/// resolutions than [`MAX_GRANT_RESOLUTIONS`]. The call is dropped rather than
/// returned as an empty success; re-running resumes granting the remainder.
const GRANT_BOUND_EXCEEDED_MESSAGE: &str = "Astrid needed to resolve more capsule grants than a single tool call allows; the tool call \
     was dropped. Re-run the tool to continue granting the remaining capsules.";

/// MCP server shim bridging a stdio client to the daemon tool broker.
pub(crate) struct AstridMcpServer {
    /// The single long-lived uplink, shared across `&self` handlers.
    client: Arc<Mutex<SocketClient>>,
    /// Principal stamped on every outbound IPC message.
    principal: String,
    /// Set when a prior round trip ended in a connection-loss condition (a
    /// failed send, or a reply read that hit EOF / reset). The NEXT round trip
    /// re-handshakes (`reconnect()`) before sending, so a request never goes
    /// out on a stale/half-open fd left behind by a daemon restart. A clean
    /// 55 s deadline against a live-but-slow broker does NOT set this — that is
    /// not a dead connection.
    ///
    /// Every access is made while the `client` mutex is held (see `forward`), so
    /// the flag is already serialized by that lock and needs no inter-thread
    /// ordering of its own — all accesses use `Ordering::Relaxed`.
    needs_reconnect: AtomicBool,
}

impl AstridMcpServer {
    /// Build a new shim over an established uplink and resolved principal.
    pub(crate) fn new(client: Arc<Mutex<SocketClient>>, principal: String) -> Self {
        Self {
            client,
            principal,
            needs_reconnect: AtomicBool::new(false),
        }
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
        let reply_topic = astrid_types::Topic::kernel_response(req_id);

        let msg = astrid_types::ipc::IpcMessage::new(
            astrid_types::Topic::from_raw(request_topic),
            astrid_types::ipc::IpcPayload::RawJson(body),
            // Source attribution is set by the kernel from the
            // authenticated connection, not this field; match the other
            // CLI uplink verbs and send nil.
            Uuid::nil(),
        )
        .with_principal(self.principal.clone());

        let mut client = self.client.lock().await;

        // Pre-heal: a PRIOR round trip may have ended in a connection-loss
        // condition (failed send, or a reply read that hit EOF / reset because
        // the daemon restarted under us). If so, the held socket is a dead fd;
        // re-handshake before sending so this request goes out on a fresh,
        // fully-authenticated connection rather than silently dropping into a
        // half-open socket. A clean deadline against a slow broker never sets
        // the flag, so a slow tool does not force a needless reconnect.
        if self.needs_reconnect.swap(false, Ordering::Relaxed) {
            warn!(
                topic = request_topic,
                "MCP shim: pre-healing a connection flagged dead by a prior round trip"
            );
            if let Err(e) = client.reconnect().await {
                // Re-arm the flag: the connection is still dead, so the next
                // attempt must try to heal again rather than assume health.
                self.needs_reconnect.store(true, Ordering::Relaxed);
                warn!(error = %e, "MCP shim: pre-heal reconnect failed");
                return Err(McpError::internal_error(
                    format!("reconnect to daemon failed: {e}"),
                    None,
                ));
            }
        }

        // Survive a daemon restart. If the publish fails — e.g. the daemon
        // rebound `system.sock` under us and our socket is now a dead fd
        // (`Broken pipe`) — re-dial the live daemon once and retry. Retrying
        // is safe precisely because the *send* failed: the request never
        // reached the broker, so no tool ran and there is no double-execution
        // risk. A failure *after* a successful send is handled below (and only
        // retried for idempotent requests).
        if let Err(first) = client.send_message(msg.clone()).await {
            warn!(topic = request_topic, error = %first, "MCP shim: broker publish failed; reconnecting to daemon and retrying once");
            client.reconnect().await.map_err(|e| {
                warn!(error = %e, "MCP shim: reconnect to daemon failed");
                McpError::internal_error(format!("reconnect to daemon failed: {e}"), None)
            })?;
            client.send_message(msg.clone()).await.map_err(|e| {
                warn!(topic = request_topic, error = %e, "MCP shim: failed to publish broker request after reconnect");
                McpError::internal_error(format!("failed to publish broker request after reconnect: {e}"), None)
            })?;
        }

        // Await the reply. The typed read lets us tell a dead connection (the
        // daemon died while we waited) apart from a legitimate slow-broker
        // deadline.
        match client
            .read_until_topic_typed(&reply_topic, REQUEST_DEADLINE)
            .await
        {
            Ok(raw) => Ok(unwrap_reply_payload(&raw)),

            // Connection died mid-wait. The held socket is now unusable, so the
            // NEXT request must reconnect first — always flag that. Whether we
            // transparently retry THIS request depends on idempotence: a
            // read-only enumeration (`tools/list`) can be safely re-issued, but
            // a `tools/call` (or a consent/approval respond) may have already
            // taken effect on the broker, so we must NOT silently re-run it.
            Err(ReadError::ConnectionLost(e)) => {
                self.needs_reconnect.store(true, Ordering::Relaxed);
                if is_request_retriable(request_topic) {
                    warn!(topic = request_topic, error = %e, "MCP shim: connection lost awaiting reply; reconnecting and retrying idempotent request once");
                    client.reconnect().await.map_err(|re| {
                        warn!(error = %re, "MCP shim: reconnect for idempotent retry failed");
                        McpError::internal_error(format!("reconnect to daemon failed: {re}"), None)
                    })?;
                    // Healed in-line; clear the flag we just set.
                    self.needs_reconnect.store(false, Ordering::Relaxed);
                    client.send_message(msg).await.map_err(|se| {
                        warn!(topic = request_topic, error = %se, "MCP shim: re-publish after reconnect failed");
                        McpError::internal_error(
                            format!("failed to re-publish broker request after reconnect: {se}"),
                            None,
                        )
                    })?;
                    let raw = client
                        .read_until_topic_typed(&reply_topic, REQUEST_DEADLINE)
                        .await
                        .map_err(|re| {
                            // Flag again — the retry's connection may also be dead.
                            if matches!(re, ReadError::ConnectionLost(_)) {
                                self.needs_reconnect.store(true, Ordering::Relaxed);
                            }
                            warn!(topic = %reply_topic, error = %re, "MCP shim: broker reply not received after idempotent retry");
                            McpError::internal_error(
                                format!("broker reply not received after retry: {re}"),
                                None,
                            )
                        })?;
                    Ok(unwrap_reply_payload(&raw))
                } else {
                    // Mutating / side-effecting request: surface the loss to the
                    // MCP client (it must decide whether to re-issue), but keep
                    // the reconnect flag set so the NEXT call is healthy.
                    warn!(topic = request_topic, error = %e, "MCP shim: connection lost awaiting reply for a non-idempotent request; not auto-retrying (a mutating call may have executed)");
                    Err(McpError::internal_error(
                        format!("connection to daemon lost while awaiting reply: {e}"),
                        None,
                    ))
                }
            },

            // Deadline against a still-open connection: the broker is slow, not
            // dead. Surface the timeout; do NOT reconnect (the request may still
            // be in flight, and a needless reconnect would drop the in-flight
            // reply on the floor).
            Err(ReadError::Timeout) => {
                warn!(topic = %reply_topic, "MCP shim: broker reply timed out (connection still live); not reconnecting");
                Err(McpError::internal_error(
                    "broker reply not received before deadline".to_string(),
                    None,
                ))
            },
        }
    }
}

/// Whether a broker round trip on `request_topic` may be transparently
/// re-issued after the connection drops mid-wait, WITHOUT risking a duplicate
/// side effect.
///
/// Pure, exhaustive allow-set so the safety rule is auditable and unit-tested:
/// only read-only / enumeration front doors are retriable. Anything that can
/// mutate state — running a tool, recording an approval or ingress-consent
/// decision — is NOT retriable, because the broker may have already applied
/// the effect before the connection died; the caller surfaces the loss instead
/// of silently re-running it. Default-deny: an unrecognized topic is treated
/// as not retriable.
fn is_request_retriable(request_topic: &str) -> bool {
    // The non-retriable arms are deliberately enumerated separately rather than
    // collapsed into the wildcard: each documents WHY a specific front door is
    // unsafe to re-issue, which is the point of an auditable allow-set. The
    // identical `false` bodies are intentional.
    #[allow(clippy::match_same_arms)]
    match request_topic {
        // Read-only enumeration of the tool surface (MCP `tools/list`). Safe to
        // re-issue: it never mutates state.
        TOOLS_LIST_TOPIC => true,
        // Running a tool (MCP `tools/call`) may have executed already.
        TOOL_CALL_TOPIC => false,
        // Recording an approval / ingress-consent / grant-on-use decision is a
        // state mutation on the broker (and, for grant, persists a capsule on
        // the principal kernel-side); re-issuing could double-apply or race a
        // stale decision.
        elicit::APPROVAL_RESPOND_TOPIC
        | ingress::INGRESS_RESPOND_TOPIC
        | grant::GRANT_RESPOND_TOPIC => false,
        // Default-deny anything not explicitly enumerated above.
        _ => false,
    }
}

/// One decision of the bounded grant-on-use loop, computed purely from the
/// current broker reply and how many grants have already been resolved on this
/// `tools/call`. Extracted from [`AstridMcpServer::call_tool`] so the loop's
/// control logic — in particular the resolution bound and the invariant that a
/// `grant_required` reply is NEVER treated as terminal — is unit-testable
/// without a live broker or MCP peer (#1117).
enum GrantStep {
    /// No grant signal — the reply is terminal with respect to grants; hand it
    /// to the approval/terminal path.
    Terminal,
    /// A well-formed grant to resolve (then re-send the original call).
    Resolve(grant::GrantRequest),
    /// Fail the `tools/call` with a terminal error carrying this text — a
    /// malformed signal, or the per-call resolution bound was exceeded. The
    /// reply itself is NEVER returned as a result.
    Fail(&'static str),
}

/// Decide the next grant-loop action for `reply`, given how many grants have
/// already been resolved on this call.
///
/// Crucially, a present grant signal never yields [`GrantStep::Terminal`]: an
/// ungranted `grant_required` reply must not masquerade as an empty success
/// (the #1117 bug). Once [`MAX_GRANT_RESOLUTIONS`] grants have been resolved, a
/// still-present signal fails the call rather than resolving unboundedly.
fn next_grant_step(reply: &Value, grants_resolved: usize) -> GrantStep {
    match grant::GrantRequest::classify(reply) {
        // Absent (or explicit null): already-granted / no gate. Terminal.
        grant::GrantSignal::Absent => GrantStep::Terminal,
        // Present but unanswerable: fail loudly, never as an empty success.
        grant::GrantSignal::Malformed => GrantStep::Fail(MALFORMED_GRANT_MESSAGE),
        grant::GrantSignal::Present(grant) => {
            if grants_resolved >= MAX_GRANT_RESOLUTIONS {
                GrantStep::Fail(GRANT_BOUND_EXCEEDED_MESSAGE)
            } else {
                GrantStep::Resolve(grant)
            }
        },
    }
}

impl ServerHandler for AstridMcpServer {
    fn get_info(&self) -> ServerInfo {
        // Tools-only server. `listChanged = true` tells the client the
        // tool surface can change at runtime (capsules load/unload), so
        // it should honour `notifications/tools/list_changed`.
        let mut capabilities = ServerCapabilities::default();
        let mut tools = rmcp::model::ToolsCapability::default();
        tools.list_changed = Some(true);
        capabilities.tools = Some(tools);

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
                return Ok(CallToolResult::error(vec![ContentBlock::text(
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

        // If the broker gated the call on a capsule the caller does not hold,
        // it replies a `grant_required` signal (NOT a result) — the kernel
        // DROPPED the original call at the access gate. Elicit the user's
        // consent; on approve the kernel persists the capsule grant and we
        // RE-SEND the original call (now passing the gate, exactly as the
        // ingress flow re-sends). On deny / no-capability / error, fail secure
        // with an MCP error. This sits AFTER the ingress block and BEFORE the
        // approval block, so a re-sent call still flows into the approval gate:
        // a tool that is both ungranted and capability-gated resolves in
        // sequence.
        //
        // LOOP, do not resolve once (#1117): a fresh principal can be missing
        // SEVERAL view capsules, and each re-sent call trips the access gate on
        // the NEXT ungranted capsule. Resolve-and-re-send until the reply is
        // grant-free, bounded by `MAX_GRANT_RESOLUTIONS` so a broker that keeps
        // replying `grant_required` cannot spin the shim. The invariant that
        // keeps an ungranted call from masquerading as an empty success lives
        // in `next_grant_step`: a present grant signal is never `Terminal`, so
        // the only ways out of this loop are a grant-free reply (`break`) or a
        // terminal error (malformed / denied / bound exceeded).
        let mut reply = reply;
        let mut grants_resolved = 0usize;
        let reply = loop {
            match next_grant_step(&reply, grants_resolved) {
                GrantStep::Terminal => break reply,
                GrantStep::Fail(message) => {
                    return Ok(CallToolResult::error(vec![ContentBlock::text(message)]));
                },
                GrantStep::Resolve(grant) => {
                    let granted = self.resolve_grant(&context.peer, &grant).await?;
                    if !granted {
                        return Ok(CallToolResult::error(vec![ContentBlock::text(
                            GRANT_DENIED_MESSAGE,
                        )]));
                    }
                    grants_resolved = grants_resolved.saturating_add(1);
                    // Re-send the original call now that this capsule is
                    // granted; the next reply may itself carry a further
                    // `grant_required` for the NEXT ungranted view capsule.
                    let retry_id = new_req_id();
                    reply = self
                        .round_trip(TOOL_CALL_TOPIC, &retry_id, call_body(&retry_id))
                        .await?;
                },
            }
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

    /// Drive the grant-on-use bridge for a `tools/call` the broker gated on a
    /// capsule the caller does not hold: elicit the user's decision and forward
    /// it on the broker's [`GRANT_RESPOND_TOPIC`](grant::GRANT_RESPOND_TOPIC)
    /// front door so the kernel persists (or declines) the capsule grant.
    /// Returns whether the capsule is now granted — `true` only when the user
    /// approved AND the broker confirmed the grant persisted.
    ///
    /// Marker discipline (the divergence from [`resolve_ingress`]): the broker
    /// holds a per-`(principal, capsule)` pending marker that is consumed on
    /// EVERY respond, so this ALWAYS responds — `approve` on accept, `deny` on
    /// decline / no-capability / elicit error — or the marker would stick and
    /// a later call would get a benign "already pending" terminal instead of a
    /// fresh prompt.
    ///
    /// Fail-secure: any non-accept path publishes `deny` and returns `false`.
    /// An accept the broker could not persist (ack `granted:false`) also
    /// returns `false`, so the caller does not re-send a call that would just
    /// trip the gate again. A respond round-trip error returns the error
    /// (caller fails the call) — the marker still clears on the broker's side
    /// only if the publish landed, so the broker treats a never-arriving
    /// respond as its own timeout concern; the shim's contract is to always
    /// attempt a respond, which it does.
    async fn resolve_grant(
        &self,
        peer: &rmcp::service::Peer<RoleServer>,
        request: &grant::GrantRequest,
    ) -> Result<bool, McpError> {
        let approved = grant::elicit_grant(peer, request).await;
        let decision = grant::grant_decision(approved);

        // A fresh req_id keys the ack. The respond body echoes the kernel-minted
        // grant `request_id` so the broker routes the decision; the grant target
        // is never a body field (the kernel derives it from its own signal).
        let respond_req_id = new_req_id();
        let respond_body = request.respond_body(&respond_req_id, decision);

        let ack = self
            .round_trip(grant::GRANT_RESPOND_TOPIC, &respond_req_id, respond_body)
            .await?;

        // On decline we still published `deny` (to clear the broker marker) but
        // never grant — short-circuit to false without reading the ack.
        if !approved {
            return Ok(false);
        }

        let granted = ack.get("granted").and_then(Value::as_bool).unwrap_or(false);
        if !granted {
            warn!("MCP shim: broker did not confirm capsule grant; not retrying call");
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
    unwrap_reply_payload_ref(raw).clone()
}

/// Borrowing form of [`unwrap_reply_payload`]: returns the inner reply value by
/// reference, without cloning.
///
/// A `capsules_loaded` payload carries every reloaded capsule's full `meta`
/// (including tool schemas), so a consumer that only needs to *read* a few
/// fields off it — e.g. the hot-reload watcher extracting tool names — must
/// borrow rather than clone the whole tree on every broadcast. A missing
/// `payload` degrades to a borrowed `Null` (which reads as "no fields present"
/// everywhere downstream) rather than an allocated empty object.
pub(super) fn unwrap_reply_payload_ref(raw: &Value) -> &Value {
    // A shared `Null` to hand back when there is no payload — lets this return
    // a borrow in every branch without allocating.
    static NULL_PAYLOAD: Value = Value::Null;
    let Some(payload) = raw.get("payload") else {
        return &NULL_PAYLOAD;
    };
    if payload
        .as_object()
        .is_some_and(|m| m.contains_key("type") && m.contains_key("value"))
    {
        return payload.get("value").unwrap_or(payload);
    }
    payload
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

/// Translate one broker content block into rmcp [`ContentBlock`].
///
/// The broker emits `{ "type": "text", "text": "..." }` blocks. Anything
/// that is not a recognized text block is serialized to JSON text so the
/// payload always reaches the MCP client as valid content.
fn content_from_block(block: &Value) -> ContentBlock {
    if block.get("type").and_then(Value::as_str) == Some("text")
        && let Some(text) = block.get("text").and_then(Value::as_str)
    {
        return ContentBlock::text(text.to_string());
    }
    debug!("MCP shim: non-text broker content block, serializing to text");
    ContentBlock::text(block.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The read-only tool-enumeration front door (MCP `tools/list`) is the only
    /// round trip safe to transparently re-issue after a mid-wait connection
    /// loss: it never mutates state.
    #[test]
    fn tools_list_is_retriable() {
        assert!(is_request_retriable(TOOLS_LIST_TOPIC));
    }

    /// Running a tool (MCP `tools/call`) may have ALREADY executed on the
    /// broker before the connection died — never auto-retry it, or a mutating
    /// tool could run twice.
    #[test]
    fn tool_call_is_not_retriable() {
        assert!(!is_request_retriable(TOOL_CALL_TOPIC));
    }

    /// Recording a capability-approval, ingress-consent, or grant-on-use
    /// decision is a state mutation on the broker (grant additionally persists
    /// a capsule on the principal); re-issuing could double-apply, so these are
    /// not retriable either.
    #[test]
    fn respond_front_doors_are_not_retriable() {
        assert!(!is_request_retriable(elicit::APPROVAL_RESPOND_TOPIC));
        assert!(!is_request_retriable(ingress::INGRESS_RESPOND_TOPIC));
        assert!(!is_request_retriable(grant::GRANT_RESPOND_TOPIC));
    }

    /// Default-deny: an unrecognized topic must never be treated as retriable.
    #[test]
    fn unknown_topic_is_not_retriable() {
        assert!(!is_request_retriable("astrid.v1.request.mcp.something.new"));
        assert!(!is_request_retriable(""));
    }

    // ── Bounded grant-on-use loop (#1117) ───────────────────────────

    /// A well-formed, still-present `grant_required` signal.
    fn grant_reply(capsule: &str) -> Value {
        json!({
            "kind": "tool.call",
            "content": [],
            "isError": false,
            "grant_required": {
                "request_id": format!("grant-{capsule}"),
                "capsule_id": capsule,
                "principal": "claude-code",
                "tool_name": "some.tool",
                "call_id": "call-1"
            }
        })
    }

    /// A grant-free reply — the terminal / already-granted shape.
    fn terminal_reply() -> Value {
        json!({ "kind": "tool.call", "content": [], "isError": false })
    }

    /// No grant signal → `Terminal`: proceed to the approval/terminal path.
    #[test]
    fn grant_step_terminal_when_no_signal() {
        assert!(matches!(
            next_grant_step(&terminal_reply(), 0),
            GrantStep::Terminal
        ));
    }

    /// A well-formed grant under the bound → `Resolve` (elicit + re-send).
    #[test]
    fn grant_step_resolves_present_signal_under_bound() {
        assert!(matches!(
            next_grant_step(&grant_reply("shell"), 0),
            GrantStep::Resolve(_)
        ));
        // Still resolvable right up to the last permitted resolution.
        assert!(matches!(
            next_grant_step(&grant_reply("shell"), MAX_GRANT_RESOLUTIONS - 1),
            GrantStep::Resolve(_)
        ));
    }

    /// At or above the bound, a still-present grant signal must `Fail` with the
    /// bound-exceeded message — never resolve again, never go `Terminal`.
    #[test]
    fn grant_step_fails_when_bound_exceeded() {
        let GrantStep::Fail(message) =
            next_grant_step(&grant_reply("shell"), MAX_GRANT_RESOLUTIONS)
        else {
            panic!("a present grant signal at the bound must Fail, not Resolve/Terminal");
        };
        assert_eq!(message, GRANT_BOUND_EXCEEDED_MESSAGE);
        // Well above the bound too.
        assert!(matches!(
            next_grant_step(&grant_reply("shell"), MAX_GRANT_RESOLUTIONS + 5),
            GrantStep::Fail(_)
        ));
    }

    /// A present-but-unanswerable (malformed) signal fails with the malformed
    /// message — it is never returned as an empty success.
    #[test]
    fn grant_step_fails_on_malformed_signal() {
        let malformed = json!({ "grant_required": { "request_id": "" } });
        let GrantStep::Fail(message) = next_grant_step(&malformed, 0) else {
            panic!("a malformed grant signal must Fail");
        };
        assert_eq!(message, MALFORMED_GRANT_MESSAGE);
    }

    /// The core #1117 invariant: as long as a grant signal is present, NO
    /// resolved-count ever yields `Terminal`. If it did, the loop would hand a
    /// `grant_required` reply to `call_tool_result_from_reply`, which would
    /// reshape it into an empty `isError:false` success — the phantom result
    /// the bug produced.
    #[test]
    fn grant_step_never_terminal_while_grant_present() {
        let reply = grant_reply("shell");
        for resolved in 0..=(MAX_GRANT_RESOLUTIONS + 2) {
            assert!(
                !matches!(next_grant_step(&reply, resolved), GrantStep::Terminal),
                "a present grant signal must never classify as Terminal (resolved={resolved})"
            );
        }
    }
}

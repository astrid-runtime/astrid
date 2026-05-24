//! Wraps `astrid-ipc-client::SocketClient` with bridge-specific
//! conveniences: typed send/receive of `IpcMessage`s with principal
//! attribution, plus a helper that builds messages stamped with the
//! connection's principal.

use std::time::Duration;

use astrid_core::SessionId;
use astrid_ipc_client::SocketClient;
use astrid_types::ipc::{IpcMessage, IpcPayload};
use astrid_types::llm::ToolCallResult;
use tokio::time::timeout;
use uuid::Uuid;

use crate::error::BridgeError;

/// A capability-approval request surfaced mid-tool-call by the kernel.
///
/// Mirrors [`IpcPayload::ApprovalRequired`](astrid_types::ipc::IpcPayload::ApprovalRequired)
/// minus the wire-level `request_id` (the daemon connection handles
/// correlation internally). Passed to the `on_approval` callback of
/// [`DaemonConnection::call_tool_round_trip`].
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// Action being requested (e.g. "git push").
    pub action: String,
    /// Resource target (e.g. the full command string).
    pub resource: String,
    /// Justification supplied by the originating interceptor/capsule.
    pub reason: String,
}

/// The user-facing decision on an [`ApprovalRequest`].
///
/// Serializes to the `decision` string on
/// [`IpcPayload::ApprovalResponse`](astrid_types::ipc::IpcPayload::ApprovalResponse)
/// — either `"approve"` or `"deny"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

impl ApprovalDecision {
    /// Wire-protocol string for the IPC `decision` field.
    #[must_use]
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

/// A connected, handshake-complete daemon session.
///
/// The bridge uses one of these per stdio run. All outbound messages
/// are stamped with the configured `principal` (v1: always "default")
/// so the kernel's `resolve_caller` sees the right scope for KV,
/// home, secrets, and quotas.
pub struct DaemonConnection {
    client: SocketClient,
    principal: String,
}

impl DaemonConnection {
    /// Connect to the daemon at `~/.astrid/run/system.sock` and
    /// complete the bearer-token handshake.
    ///
    /// # Errors
    /// Returns [`BridgeError::DaemonConnect`] if the socket is
    /// missing, the handshake is rejected, or any IO fails.
    pub async fn connect(principal: &str) -> Result<Self, BridgeError> {
        let session_id = SessionId::new();
        let client = SocketClient::connect(session_id)
            .await
            .map_err(BridgeError::DaemonConnect)?;
        Ok(Self {
            client,
            principal: principal.to_owned(),
        })
    }

    /// Build an [`IpcMessage`] with the connection's principal and a
    /// fresh source UUID. Caller picks the topic and payload.
    #[must_use]
    pub fn build_message(&self, topic: impl Into<String>, payload: IpcPayload) -> IpcMessage {
        IpcMessage::new(topic, payload, Uuid::new_v4()).with_principal(&self.principal)
    }

    /// Send a single [`IpcMessage`] to the daemon. Used for everything
    /// the bridge originates: `ToolExecuteRequest`s, `ApprovalResponse`s,
    /// future `ToolListRequest`s, etc.
    ///
    /// # Errors
    /// Returns [`BridgeError::Internal`] if serialization or IO fails.
    pub async fn send(&mut self, msg: &IpcMessage) -> Result<(), BridgeError> {
        self.client
            .send_message(msg.clone())
            .await
            .map_err(BridgeError::Internal)
    }

    /// Block until the next [`IpcMessage`] arrives. Returns `None` on
    /// graceful peer disconnect.
    ///
    /// # Errors
    /// Returns [`BridgeError::Internal`] if the underlying read fails
    /// with an unrecoverable error (over-large frame, mid-frame IO
    /// failure).
    pub async fn recv(&mut self) -> Result<Option<IpcMessage>, BridgeError> {
        self.client
            .read_message()
            .await
            .map_err(BridgeError::Internal)
    }

    /// Access the configured principal for this connection.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// Send a `ToolExecuteRequest` for `tool_name` with `args`, then
    /// block until the matching `ToolExecuteResult` arrives.
    ///
    /// Filters out messages we self-echo: `capsule-cli` re-broadcasts
    /// our own forwarded `ToolExecuteRequest` back at us (Task 1
    /// limitation: cannot subscribe to mid-segment wildcards like
    /// `tool.v1.execute.*.result`), so we discriminate by payload
    /// variant and `call_id` match rather than by topic.
    ///
    /// Any [`IpcPayload::ApprovalRequired`] that arrives mid-call is
    /// surfaced to the caller via the `on_approval` callback. The
    /// caller's returned [`ApprovalDecision`] is translated into an
    /// `ApprovalResponse` (`"approve"` or `"deny"`) on the bus, then
    /// the loop resumes waiting for the tool result. A deny does NOT
    /// short-circuit the round-trip — the capsule decides whether
    /// denial means "fail the tool call" or "fall back to a safer
    /// path"; either way we still wait for its `ToolExecuteResult`.
    ///
    /// # Errors
    /// - [`BridgeError::DaemonDisconnected`] if the peer closes mid-call.
    /// - [`BridgeError::ToolTimeout`] if `deadline` elapses without a
    ///   matching response.
    pub async fn call_tool_round_trip<F, Fut>(
        &mut self,
        tool_name: &str,
        args: serde_json::Value,
        deadline: Duration,
        on_approval: F,
    ) -> Result<ToolCallResult, BridgeError>
    where
        F: Fn(ApprovalRequest) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = ApprovalDecision> + Send,
    {
        let call_id = Uuid::new_v4().to_string();
        let topic = format!("tool.v1.execute.{tool_name}");
        let req = self.build_message(
            &topic,
            IpcPayload::ToolExecuteRequest {
                call_id: call_id.clone(),
                tool_name: tool_name.to_owned(),
                arguments: args,
            },
        );
        self.send(&req).await?;

        timeout(deadline, async {
            loop {
                let msg = self.recv().await?.ok_or(BridgeError::DaemonDisconnected)?;
                match msg.payload {
                    IpcPayload::ToolExecuteResult {
                        call_id: got,
                        result,
                    } if got == call_id => {
                        return Ok::<ToolCallResult, BridgeError>(result);
                    },
                    IpcPayload::ApprovalRequired {
                        request_id,
                        action,
                        resource,
                        reason,
                    } => {
                        let req = ApprovalRequest {
                            action,
                            resource,
                            reason,
                        };
                        let decision = on_approval(req).await;
                        let topic = format!("astrid.v1.approval.response.{request_id}");
                        let response = self.build_message(
                            &topic,
                            IpcPayload::ApprovalResponse {
                                request_id: request_id.clone(),
                                decision: decision.as_wire().to_string(),
                                reason: Some("mcp-bridge: forwarded via elicitation".to_string()),
                            },
                        );
                        self.send(&response).await?;
                    },
                    _ => {
                        // Ignore self-echoed requests and unrelated traffic.
                    },
                }
            }
        })
        .await
        .map_err(|_| BridgeError::ToolTimeout(deadline))?
    }
}

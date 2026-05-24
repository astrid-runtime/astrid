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
    /// # Errors
    /// - [`BridgeError::DaemonDisconnected`] if the peer closes mid-call.
    /// - [`BridgeError::ToolTimeout`] if `deadline` elapses without a
    ///   matching response.
    pub async fn call_tool_round_trip(
        &mut self,
        tool_name: &str,
        args: serde_json::Value,
        deadline: Duration,
    ) -> Result<ToolCallResult, BridgeError> {
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
                if let IpcPayload::ToolExecuteResult {
                    call_id: got,
                    result,
                } = msg.payload
                {
                    if got == call_id {
                        return Ok::<ToolCallResult, BridgeError>(result);
                    }
                }
                // Ignore self-echoed requests and unrelated traffic.
            }
        })
        .await
        .map_err(|_| BridgeError::ToolTimeout(deadline))?
    }
}

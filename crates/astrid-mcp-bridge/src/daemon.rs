//! Wraps `astrid-ipc-client::SocketClient` with bridge-specific
//! conveniences: typed send/receive of `IpcMessage`s with principal
//! attribution, plus a helper that builds messages stamped with the
//! connection's principal.

use astrid_core::SessionId;
use astrid_ipc_client::SocketClient;
use astrid_types::ipc::{IpcMessage, IpcPayload};
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
}

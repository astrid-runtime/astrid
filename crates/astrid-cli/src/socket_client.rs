use astrid_core::SessionId;
use astrid_core::session_token::{
    HandshakeRequest, HandshakeResponse, PROTOCOL_VERSION, SessionToken,
};
use astrid_types::ipc::{IpcMessage, IpcPayload};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::warn;

use anyhow::{Context, Result};

/// Path to the local Unix Domain Socket managed by the CLI Proxy Capsule.
#[must_use]
pub fn proxy_socket_path() -> std::path::PathBuf {
    use astrid_core::dirs::AstridHome;
    match AstridHome::resolve() {
        Ok(home) => home.socket_path(),
        Err(e) => {
            warn!(error = %e, "Failed to resolve ASTRID_HOME; falling back to /tmp/.astrid/run/system.sock");
            std::path::PathBuf::from("/tmp/.astrid/run/system.sock")
        },
    }
}

/// Path to the daemon readiness sentinel file.
///
/// The CLI polls for this file after spawning the daemon to determine when
/// it is fully initialized and accepting connections.
///
/// NOTE: This is intentionally duplicated in `astrid-kernel/src/socket.rs`
/// because the CLI cannot depend on `astrid-kernel`. The canonical path
/// definition is `AstridHome::ready_path()` in `astrid-core`.
#[must_use]
pub fn readiness_path() -> std::path::PathBuf {
    use astrid_core::dirs::AstridHome;
    match AstridHome::resolve() {
        Ok(home) => home.ready_path(),
        Err(e) => {
            warn!(
                error = %e,
                "Failed to resolve ASTRID_HOME; falling back to /tmp/.astrid/run/system.ready"
            );
            std::path::PathBuf::from("/tmp/.astrid/run/system.ready")
        },
    }
}

/// Path to the session authentication token file.
///
/// # Errors
/// Returns an error if `ASTRID_HOME` cannot be resolved. No `/tmp` fallback
/// is used because the server explicitly refuses to write tokens there.
fn token_path() -> anyhow::Result<std::path::PathBuf> {
    use astrid_core::dirs::AstridHome;
    let home = AstridHome::resolve()
        .map_err(|e| anyhow::anyhow!("Failed to resolve ASTRID_HOME for token path: {e}"))?;
    Ok(home.token_path())
}

/// A client connection to the Kernel's Unix Domain Socket.
pub struct SocketClient {
    read_half: tokio::net::unix::OwnedReadHalf,
    write_half: tokio::net::unix::OwnedWriteHalf,
    /// The unique identifier for this session.
    pub session_id: SessionId,
}

impl SocketClient {
    /// Attempt to connect to an existing session socket.
    ///
    /// Performs the authentication handshake: reads the session token from
    /// disk and sends a `HandshakeRequest` with the token and protocol
    /// version. The daemon validates the token and responds with a
    /// `HandshakeResponse`.
    ///
    /// # Errors
    /// Returns an error if the socket file does not exist, connection fails,
    /// or the handshake is rejected.
    pub async fn connect(session_id: SessionId) -> Result<Self> {
        let path = proxy_socket_path();

        if !path.exists() {
            anyhow::bail!("Global OS Socket not found at {}", path.display());
        }

        let mut stream = UnixStream::connect(&path)
            .await
            .context("Failed to connect to IPC socket")?;

        // Perform authenticated handshake before splitting the stream.
        perform_handshake(&mut stream).await?;

        let (read_half, write_half) = stream.into_split();

        Ok(Self {
            read_half,
            write_half,
            session_id,
        })
    }

    /// Read the next IPC message from the daemon.
    ///
    /// The CLI proxy capsule sends individual `IpcMessage` objects over
    /// the socket as length-prefixed JSON. Frames whose payload does
    /// not deserialize into [`IpcMessage`] (notably the kernel's
    /// `astrid.v1.capsules_loaded` broadcast, whose `IpcPayload::RawJson`
    /// inner value is emitted without the `type` discriminator) are
    /// logged at `debug` and skipped — the caller reads the next valid
    /// frame instead. Without this tolerance, every interactive client
    /// would die on the first broadcast.
    ///
    /// # Errors
    /// Returns an error if the connection is in an unrecoverable state
    /// (over-large frame, IO failure mid-read).
    pub async fn read_message(&mut self) -> Result<Option<IpcMessage>> {
        loop {
            let mut len_buf = [0u8; 4];
            if self.read_half.read_exact(&mut len_buf).await.is_err() {
                return Ok(None); // Connection closed
            }
            let len = u32::from_be_bytes(len_buf) as usize;

            if len > 50 * 1024 * 1024 {
                anyhow::bail!("Message too large from kernel: {len} bytes");
            }

            let mut payload = vec![0u8; len];
            self.read_half.read_exact(&mut payload).await?;

            if let Ok(message) = serde_json::from_slice::<IpcMessage>(&payload) {
                return Ok(Some(message));
            }
            let preview = String::from_utf8_lossy(&payload[..payload.len().min(120)]);
            tracing::debug!(
                preview = %preview,
                "skipping unparseable frame from daemon"
            );
        }
    }

    /// Read the next length-prefixed frame as raw bytes, without
    /// attempting to deserialize. Used by [`crate::admin_client`] when
    /// it needs to tolerate broadcast messages that don't deserialize
    /// cleanly into [`IpcMessage`] (e.g. the kernel's
    /// `astrid.v1.capsules_loaded` payload, which serializes without a
    /// `type` discriminator on the inner JSON).
    ///
    /// # Errors
    /// Returns an error if the frame cannot be read.
    pub async fn read_raw_frame(&mut self) -> Result<Option<Vec<u8>>> {
        let mut len_buf = [0u8; 4];
        if self.read_half.read_exact(&mut len_buf).await.is_err() {
            return Ok(None);
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 50 * 1024 * 1024 {
            anyhow::bail!("Message too large from kernel: {len} bytes");
        }
        let mut payload = vec![0u8; len];
        self.read_half.read_exact(&mut payload).await?;
        Ok(Some(payload))
    }

    /// Read frames until one arrives on `want_topic`, skipping
    /// broadcasts (e.g. `astrid.v1.capsules_loaded`) whose payload
    /// fails strict [`IpcMessage`] deserialization.
    ///
    /// Returns the parsed JSON value of the first matching frame so
    /// the caller can pull whatever shape it expects out of `payload`
    /// — useful for kernel responses (`KernelResponse`) whose inner
    /// JSON does not round-trip through the `IpcPayload` tag.
    ///
    /// # Errors
    /// Returns an error if the connection drops or the deadline
    /// elapses without a matching frame.
    /// Extract the inner kernel response from a raw frame previously
    /// returned by [`read_until_topic`](Self::read_until_topic).
    ///
    /// The kernel's IPC payload arrives in one of two on-wire shapes
    /// depending on which router branch produced it:
    ///
    /// * Bare typed payload — `{ "type": "...", ... }` (already a
    ///   `KernelResponse`-shaped object that `serde_json::from_value`
    ///   can deserialize directly).
    /// * `RawJson`-wrapped payload — `{ "type": "raw_json", "value":
    ///   { "type": "...", ... } }` (the older router branch wraps the
    ///   typed body in `IpcPayload::RawJson`).
    ///
    /// Both shapes have to be tolerated by every consumer of the bare
    /// verbs (`astrid status`, `astrid ps`, `astrid who`, `astrid
    /// doctor`). Returns `None` when the frame has no `payload` field
    /// or the deserialization fails — callers fall back to an empty
    /// display rather than crashing the surface.
    #[must_use]
    pub fn extract_kernel_response(
        raw: &serde_json::Value,
    ) -> Option<astrid_core::kernel_api::KernelResponse> {
        let payload = raw.get("payload")?.clone();
        let value = if payload
            .as_object()
            .is_some_and(|m| m.contains_key("type") && m.contains_key("value"))
        {
            payload.get("value").cloned().unwrap_or(payload)
        } else {
            payload
        };
        serde_json::from_value::<astrid_core::kernel_api::KernelResponse>(value).ok()
    }

    /// Read raw frames from the socket until one carries `want_topic`
    /// or the deadline expires. Frames that don't deserialize as JSON
    /// or carry a different topic are silently skipped, which lets
    /// the bare verbs (`astrid status`, `astrid ps`, `astrid who`,
    /// `astrid doctor`) tolerate broadcast frames like
    /// `astrid.v1.capsules_loaded` whose payload tag doesn't
    /// round-trip through `IpcPayload::RawJson`.
    ///
    /// # Errors
    /// Returns an error if the deadline elapses, the connection
    /// closes, or a read fails.
    pub async fn read_until_topic(
        &mut self,
        want_topic: &str,
        timeout: std::time::Duration,
    ) -> Result<serde_json::Value> {
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(tokio::time::Instant::now);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                anyhow::bail!("timed out waiting for {want_topic}");
            }
            let read = tokio::time::timeout(remaining, self.read_raw_frame()).await;
            let frame = match read {
                Ok(Ok(Some(bytes))) => bytes,
                Ok(Ok(None)) => anyhow::bail!("connection closed before {want_topic}"),
                Ok(Err(e)) => return Err(e),
                Err(_) => anyhow::bail!("timed out waiting for {want_topic}"),
            };
            let raw: serde_json::Value = match serde_json::from_slice(&frame) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if raw.get("topic").and_then(|t| t.as_str()) == Some(want_topic) {
                return Ok(raw);
            }
        }
    }

    /// Send a user input message to the Kernel.
    ///
    /// Stamps the outbound `IpcMessage` with the operator's active
    /// agent (set by `astrid agent switch`, queried via
    /// [`crate::context::active_agent`]), so the kernel's
    /// `resolve_caller` sees the right principal for session, KV,
    /// home, secret, and quota scoping. Trust-the-uplink model
    /// today; cryptographic per-connection auth lives in #658.
    ///
    /// # Errors
    /// Returns an error if the active agent context cannot be
    /// resolved or the message cannot be sent.
    pub async fn send_input(&mut self, text: String) -> Result<()> {
        let payload = IpcPayload::UserInput {
            text,
            session_id: self.session_id.0.to_string(),
            context: None,
        };

        let caller =
            crate::context::active_agent().context("Failed to resolve active agent context")?;
        let msg = IpcMessage::new("user.v1.prompt", payload, self.session_id.0)
            .with_principal(caller.to_string());

        self.send_message(msg).await
    }

    /// Send a raw IPC message to the Kernel.
    ///
    /// # Errors
    /// Returns an error if the message cannot be serialized or sent.
    pub async fn send_message(&mut self, msg: IpcMessage) -> Result<()> {
        let bytes = serde_json::to_vec(&msg)?;
        let len =
            u32::try_from(bytes.len()).context("IPC message too large (exceeds 4 GiB limit)")?;

        self.write_half.write_all(&len.to_be_bytes()).await?;
        self.write_half.write_all(&bytes).await?;
        self.write_half.flush().await?;
        Ok(())
    }
}

/// Timeout for individual handshake read/write operations (client-side).
/// Slightly longer than the server-side timeout to account for daemon load.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Maximum allowed size of a handshake response payload (bytes).
const MAX_HANDSHAKE_RESPONSE_SIZE: usize = 4096;

/// Send the authentication handshake to the daemon and validate the response.
async fn perform_handshake(stream: &mut UnixStream) -> Result<()> {
    // Read the session token from disk (fresh on every connect, no caching).
    let tok_path = token_path()?;
    let token = SessionToken::read_from_file(&tok_path).with_context(|| {
        format!(
            "Failed to read session token from {}. Is the daemon running?",
            tok_path.display()
        )
    })?;

    let request = HandshakeRequest {
        token: token.to_hex(),
        protocol_version: PROTOCOL_VERSION,
        client_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    // Send as length-prefixed JSON (same wire format as IpcMessage).
    // Write timeout prevents indefinite stall if the daemon stops reading.
    let request_bytes =
        serde_json::to_vec(&request).context("Failed to serialize handshake request")?;
    let len = u32::try_from(request_bytes.len()).context("Handshake request too large")?;

    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&request_bytes).await?;
        stream.flush().await?;
        Ok::<(), std::io::Error>(())
    })
    .await
    .context("Handshake request write timed out")?
    .context("Failed to send handshake request")?;

    // Read the response.
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .context("Handshake response timed out")?
        .context("Failed to read handshake response length")?;

    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > MAX_HANDSHAKE_RESPONSE_SIZE {
        anyhow::bail!("Handshake response too large: {resp_len} bytes");
    }

    let mut resp_payload = vec![0u8; resp_len];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut resp_payload))
        .await
        .context("Handshake response payload timed out")?
        .context("Failed to read handshake response payload")?;

    let response: HandshakeResponse =
        serde_json::from_slice(&resp_payload).context("Failed to parse handshake response")?;

    if !response.is_ok() {
        let reason = response
            .reason
            .unwrap_or_else(|| "unknown error".to_string());
        anyhow::bail!("Daemon rejected connection: {reason}");
    }

    Ok(())
}

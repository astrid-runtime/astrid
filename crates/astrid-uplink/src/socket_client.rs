//! Unix-domain socket client for the kernel.
//!
//! Performs the session-token handshake and exposes length-prefixed
//! JSON framing for [`IpcMessage`](astrid_types::ipc::IpcMessage).
//! The client is bound to one `principal` at [`SocketClient::connect`]
//! time — the consumer resolves it (CLI process-wide `--principal` vs
//! gateway-verified bearer vs emit `publish-as` attribution) and the
//! transport stamps it onto every outbound message that does not
//! already carry an explicit principal. This matches the uplink proxy,
//! which pins the first principal it sees on a connection and drops
//! any message stamped with a different one: a single connection
//! carries a single principal.

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use astrid_core::SessionId;
use astrid_core::session_token::{
    HandshakeRequest, HandshakeResponse, PROTOCOL_VERSION, SessionToken,
};
use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::warn;

/// Path to the kernel's Unix-domain socket. Falls back to
/// `/tmp/.astrid/run/system.sock` if `ASTRID_HOME` can't be resolved
/// — matches the pre-existing CLI behaviour so single-host development
/// continues to work without env setup.
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

/// Path to the daemon readiness sentinel.
///
/// Polled by uplinks after spawning the daemon to determine when it is
/// fully initialized. NOTE: also duplicated in
/// `astrid-kernel/src/socket.rs` because the kernel cannot depend on
/// this crate; the canonical path is `AstridHome::ready_path()`.
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

/// Path to the daemon PID file (`run/system.pid`).
///
/// The daemon records its PID here at boot (after acquiring the singleton
/// lock). `astrid stop`/`astrid restart` read it to signal a wedged daemon
/// that is unreachable over the socket but still holding the lock. Falls back
/// to the same `/tmp` location as the socket so single-host development keeps
/// working without env setup — and so the CLI looks where the daemon wrote.
#[must_use]
pub fn pid_path() -> std::path::PathBuf {
    use astrid_core::dirs::AstridHome;
    match AstridHome::resolve() {
        Ok(home) => home.pid_path(),
        Err(e) => {
            warn!(error = %e, "Failed to resolve ASTRID_HOME; falling back to /tmp/.astrid/run/system.pid");
            std::path::PathBuf::from("/tmp/.astrid/run/system.pid")
        },
    }
}

/// Path to the session-authentication token file.
///
/// # Errors
/// Returns an error if `ASTRID_HOME` cannot be resolved. No `/tmp`
/// fallback — the daemon refuses to write its token under
/// world-listable directories.
pub fn token_path() -> Result<std::path::PathBuf> {
    use astrid_core::dirs::AstridHome;
    let home = AstridHome::resolve()
        .map_err(|e| anyhow::anyhow!("Failed to resolve ASTRID_HOME for token path: {e}"))?;
    Ok(home.token_path())
}

/// Why a [`SocketClient::read_until_topic_typed`] read ended without the
/// awaited frame.
///
/// The two cases demand different recovery: a [`ConnectionLost`](Self::ConnectionLost)
/// means the socket is dead and the caller should reconnect (and, for an
/// idempotent request, retry); a [`Timeout`](Self::Timeout) means the deadline
/// elapsed while the connection was still open — the broker is merely slow, so
/// the caller must NOT reconnect (the request may still be in flight).
#[derive(Debug)]
pub enum ReadError {
    /// The socket reached EOF or a read failed (peer closed / reset / broken
    /// pipe). The connection is unusable; reconnect before the next request.
    ConnectionLost(anyhow::Error),
    /// The deadline elapsed with the connection still open. Do not reconnect.
    Timeout,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionLost(e) => write!(f, "connection lost: {e}"),
            Self::Timeout => write!(f, "timed out waiting for broker reply"),
        }
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConnectionLost(e) => Some(e.as_ref()),
            Self::Timeout => None,
        }
    }
}

// NOTE: no explicit `From<ReadError> for anyhow::Error` — `ReadError` is
// `Send + Sync + 'static` and implements `std::error::Error`, so anyhow's
// blanket `From<E>` already covers the `.map_err(Into::into)` in
// `read_until_topic`. Adding our own would conflict with that blanket impl.

/// A client connection to the kernel's Unix-domain socket.
pub struct SocketClient {
    read_half: tokio::net::unix::OwnedReadHalf,
    write_half: tokio::net::unix::OwnedWriteHalf,
    /// The unique identifier for this session.
    pub session_id: SessionId,
    /// The principal this connection acts as. Stamped onto every
    /// outbound message that does not already carry an explicit
    /// principal (see [`SocketClient::send_message`]).
    principal: PrincipalId,
    /// Whether the handshake authenticated as [`principal`](Self::principal)
    /// via the signed challenge — i.e. the daemon bound this connection to that
    /// identity — versus the legacy single-frame path the daemon stamps the
    /// no-capability `anonymous`. Lets a caller that REQUIRES a real identity
    /// (the MCP shim) refuse to serve silently as `anonymous`; see
    /// [`is_authenticated`](Self::is_authenticated).
    authenticated: bool,
}

impl SocketClient {
    /// Connect to an existing session socket and perform the
    /// authenticated handshake, binding the connection to `principal`.
    ///
    /// Every outbound message that does not already set its own
    /// principal is stamped with `principal`, so the kernel scopes
    /// session, KV, home, secret, and quota state to one consistent
    /// identity for the whole connection.
    ///
    /// # Errors
    /// Returns an error if the socket file does not exist, connection
    /// fails, or the handshake is rejected.
    pub async fn connect(session_id: SessionId, principal: PrincipalId) -> Result<Self> {
        let path = proxy_socket_path();

        if !path.exists() {
            anyhow::bail!("Global OS Socket not found at {}", path.display());
        }

        let mut stream = UnixStream::connect(&path)
            .await
            .context("Failed to connect to IPC socket")?;

        let authenticated = perform_handshake(&mut stream, &principal).await?;

        let (read_half, write_half) = stream.into_split();

        Ok(Self {
            read_half,
            write_half,
            session_id,
            principal,
            authenticated,
        })
    }

    /// Whether the handshake bound this connection to its requested
    /// [`principal`](Self::principal) via the signed challenge. `false` means
    /// the connection took the legacy single-frame path and the daemon stamped
    /// it the no-capability `anonymous`. A caller that must act as a real
    /// identity should refuse to proceed when this is `false` for a
    /// non-`anonymous` requested principal, rather than silently operating with
    /// no capabilities (the MCP shim does — see its `serve` entrypoint).
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Re-establish the connection to the (possibly restarted) daemon,
    /// re-reading the current session token and re-handshaking. The
    /// [`session_id`](Self::session_id) is preserved.
    ///
    /// A daemon restart rebinds `system.sock` and rewrites the session
    /// token; a long-lived uplink that kept its original socket is left
    /// writing into a dead fd (every send fails `Broken pipe`). Calling
    /// this swaps in a fresh connection to the live daemon. Used by the
    /// MCP shim to survive a daemon restart instead of going stale for
    /// the life of the session.
    ///
    /// # Errors
    /// Returns an error if the daemon socket is absent (daemon down) or
    /// the re-handshake is rejected — the caller should surface that
    /// rather than retry indefinitely.
    pub async fn reconnect(&mut self) -> Result<()> {
        // Re-bind to the SAME principal: a reconnect must preserve the
        // connection's identity, since the proxy pins the first principal it
        // sees per connection and a fresh one bound to a different principal
        // would have this uplink's messages dropped.
        *self = Self::connect(self.session_id.clone(), self.principal.clone()).await?;
        Ok(())
    }

    /// Read the next IPC message from the daemon.
    ///
    /// Frames that don't deserialize cleanly as
    /// [`IpcMessage`](astrid_types::ipc::IpcMessage) (notably the
    /// kernel's `astrid.v1.capsules_loaded` broadcast, whose
    /// [`IpcPayload::RawJson`] inner value is emitted without the
    /// `type` discriminator) are logged at `debug` and skipped. Without
    /// this tolerance interactive clients would die on the first
    /// broadcast.
    ///
    /// # Errors
    /// Returns an error if the connection is unrecoverable (over-large
    /// frame, IO failure mid-read).
    pub async fn read_message(&mut self) -> Result<Option<IpcMessage>> {
        loop {
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
    /// cleanly into [`IpcMessage`].
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

    /// Read frames until one arrives on `want_topic` or `timeout`
    /// elapses. Frames that fail to deserialize as JSON or carry a
    /// different topic are silently skipped.
    ///
    /// # Errors
    /// Returns an error if the deadline elapses, the connection
    /// closes, or a read fails.
    pub async fn read_until_topic(
        &mut self,
        want_topic: &str,
        timeout: std::time::Duration,
    ) -> Result<serde_json::Value> {
        // Preserve the historical `anyhow` surface for the many callers that
        // only care that *something* went wrong. The typed variant below is
        // for callers (the MCP shim) that must distinguish a dead connection
        // from a live-but-slow broker.
        self.read_until_topic_typed(want_topic, timeout)
            .await
            .map_err(Into::into)
    }

    /// Like [`read_until_topic`](Self::read_until_topic) but returns a typed
    /// [`ReadError`] so the caller can tell a connection-loss (EOF / reset)
    /// apart from a genuine deadline timeout against a live daemon.
    ///
    /// This distinction matters for reconnect logic: a dead connection should
    /// trigger a re-handshake (and, for idempotent requests, a retry), whereas
    /// a deadline against a still-alive broker must NOT reconnect — the request
    /// may still be in flight and the slow path is expected (a long-running
    /// tool).
    ///
    /// # Errors
    /// Returns [`ReadError::ConnectionLost`] if the socket reaches EOF or a
    /// read fails (reset/broken pipe); [`ReadError::Timeout`] if `timeout`
    /// elapses with the connection still open.
    pub async fn read_until_topic_typed(
        &mut self,
        want_topic: &str,
        timeout: std::time::Duration,
    ) -> std::result::Result<serde_json::Value, ReadError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(tokio::time::Instant::now);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(ReadError::Timeout);
            }
            let read = tokio::time::timeout(remaining, self.read_raw_frame()).await;
            let frame = match read {
                Ok(Ok(Some(bytes))) => bytes,
                // `read_raw_frame` maps a clean EOF mid-length-prefix to
                // `Ok(None)`: the peer closed the connection (daemon restart /
                // half-open socket), which is a connection-loss, not a timeout.
                Ok(Ok(None)) => {
                    return Err(ReadError::ConnectionLost(anyhow::anyhow!(
                        "connection closed before {want_topic}"
                    )));
                },
                // A read error (reset / broken pipe / over-large frame) is also
                // an unusable connection.
                Ok(Err(e)) => return Err(ReadError::ConnectionLost(e)),
                // The outer `tokio::time::timeout` fired: the deadline elapsed
                // with the connection still open. The broker may simply be slow.
                Err(_) => return Err(ReadError::Timeout),
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

    /// Extract the inner kernel response from a raw frame previously
    /// returned by [`read_until_topic`](Self::read_until_topic).
    ///
    /// The kernel emits one of two on-wire shapes depending on which
    /// router branch produced the response:
    ///
    /// * Bare typed payload — `{ "type": "...", ... }`, already a
    ///   `KernelResponse`-shaped object that `serde_json::from_value`
    ///   can deserialize directly.
    /// * `RawJson`-wrapped payload — `{ "type": "raw_json", "value":
    ///   { "type": "...", ... } }` (the older router branch wraps the
    ///   typed body in `IpcPayload::RawJson`).
    ///
    /// Both have to be tolerated by every consumer of the bare verbs.
    /// Returns `None` when the frame has no `payload` field or the
    /// deserialization fails — callers fall back to an empty display
    /// rather than crashing.
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

    /// Send a user-prompt message as this connection's principal.
    ///
    /// Convenience helper for chat-style uplinks. The connection's
    /// bound principal is stamped by [`send_message`](Self::send_message)
    /// so the kernel's `resolve_caller` sees the right principal for
    /// session, KV, home, secret, and quota scoping.
    ///
    /// # Errors
    /// Returns an error if the message cannot be sent.
    pub async fn send_input(&mut self, text: String) -> Result<()> {
        let payload = IpcPayload::UserInput {
            text,
            session_id: self.session_id.0.to_string(),
            context: None,
        };

        let msg = IpcMessage::new(Topic::user_prompt(), payload, self.session_id.0);

        self.send_message(msg).await
    }

    /// Send a raw IPC message to the kernel.
    ///
    /// If `msg` does not already carry an explicit principal, it is
    /// stamped with this connection's bound principal before sending —
    /// so every message on the connection attributes to one consistent
    /// identity (the uplink proxy drops mismatches). A caller that has
    /// already set `principal` (e.g. `publish-as` attribution) is left
    /// untouched.
    ///
    /// # Errors
    /// Returns an error if the message cannot be serialized or sent.
    pub async fn send_message(&mut self, mut msg: IpcMessage) -> Result<()> {
        if msg.principal.is_none() {
            msg.principal = Some(self.principal.to_string());
        }
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
/// Slightly longer than the server-side timeout to absorb daemon load.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Maximum allowed size of a handshake response payload (bytes).
const MAX_HANDSHAKE_RESPONSE_SIZE: usize = 4096;

/// Path to the per-principal signing key (`keys/<principal>.key`), if
/// `ASTRID_HOME` resolves. The daemon writes this 0600 file when the
/// principal's keypair is minted (issue #45/#852); the connecting process,
/// running as the OS user, can read it to sign a handshake challenge.
fn principal_key_path(principal: &PrincipalId) -> Option<std::path::PathBuf> {
    use astrid_core::dirs::AstridHome;
    let home = AstridHome::resolve().ok()?;
    Some(home.keys_dir().join(format!("{principal}.key")))
}

/// Read the session token from disk and execute the authentication
/// handshake, authenticating as `principal` when a per-principal key exists.
///
/// Two flows, picked by key presence:
/// - **Authenticated (two frames):** when `keys/<principal>.key` exists, the
///   first request frame carries `claimed_principal` (no signature); the
///   daemon replies with a challenge nonce; a second frame carries the
///   ed25519 signature over
///   `astrid-principal-auth:v1:{principal}:{nonce_hex}`.
/// - **Legacy (single frame):** when no key file exists, the request omits
///   `claimed_principal` and the handshake completes in one round trip,
///   preserving behaviour for callers without a key.
///
/// Returns `true` when the connection authenticated as `principal` via the
/// signed challenge (the daemon bound it to that identity), `false` when it
/// took the legacy single-frame path that the daemon stamps the no-capability
/// `anonymous`. An outright-rejected handshake (e.g. a bad signature) is an
/// `Err`, never a silent `false`.
async fn perform_handshake(stream: &mut UnixStream, principal: &PrincipalId) -> Result<bool> {
    let tok_path = token_path()?;
    let token = SessionToken::read_from_file(&tok_path).with_context(|| {
        format!(
            "Failed to read session token from {}. Is the daemon running?",
            tok_path.display()
        )
    })?;

    // Load the signing key only if it exists; absence ⇒ legacy single-frame.
    let keypair = match principal_key_path(principal) {
        Some(path) => match std::fs::read(&path) {
            Ok(bytes) => Some(
                astrid_crypto::KeyPair::from_secret_key(&bytes)
                    .with_context(|| format!("invalid principal key at {}", path.display()))?,
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("failed to read principal key at {}", path.display())
                });
            },
        },
        None => None,
    };

    let claimed_principal = keypair.as_ref().map(|_| principal.to_string());
    let request = HandshakeRequest {
        token: token.to_hex(),
        protocol_version: PROTOCOL_VERSION,
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        claimed_principal,
        // The signature rides the SECOND frame (after the challenge), never
        // the first.
        signature: None,
    };

    let response = send_request_read_response(stream, &request).await?;

    // Authenticated path: the daemon's first response carries a challenge
    // nonce. Sign it and send a second frame, then read the final response.
    let (response, authenticated) = if let (Some(keypair), Some(nonce_hex)) =
        (keypair.as_ref(), response.challenge.as_deref())
    {
        let message = astrid_core::session_token::principal_auth_challenge_message(
            principal.as_str(),
            nonce_hex,
        );
        let signature = keypair.sign(message.as_bytes()).to_hex();
        let signed = HandshakeRequest {
            token: token.to_hex(),
            protocol_version: PROTOCOL_VERSION,
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            claimed_principal: Some(principal.to_string()),
            signature: Some(signature),
        };
        (send_request_read_response(stream, &signed).await?, true)
    } else {
        (response, false)
    };

    if !response.is_ok() {
        let reason = response
            .reason
            .unwrap_or_else(|| "unknown error".to_string());
        anyhow::bail!("Daemon rejected connection: {reason}");
    }

    Ok(authenticated)
}

/// Write one length-prefixed [`HandshakeRequest`] frame and read the
/// length-prefixed [`HandshakeResponse`] frame, with per-operation timeouts.
async fn send_request_read_response(
    stream: &mut UnixStream,
    request: &HandshakeRequest,
) -> Result<HandshakeResponse> {
    let request_bytes =
        serde_json::to_vec(request).context("Failed to serialize handshake request")?;
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

    serde_json::from_slice(&resp_payload).context("Failed to parse handshake response")
}

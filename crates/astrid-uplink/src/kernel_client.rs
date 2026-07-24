//! Kernel-API IPC client.
//!
//! Mirrors [`AdminClient`](crate::admin_client::AdminClient) but for
//! the `KernelRequest` family that flows over the
//! `astrid.v1.request.*` / `astrid.v1.response.*` topic prefixes
//! instead of the `astrid.v1.admin.*` admin surface. Used by the
//! HTTP gateway's capsule + system routes (`GET /api/capsules`,
//! `GET /api/sys/status`, etc.).
//!
//! ## Why a separate client
//!
//! [`KernelRequest`](astrid_core::kernel_api::KernelRequest) and
//! [`AdminRequestKind`](astrid_core::kernel_api::AdminRequestKind)
//! are two distinct typed wire formats with two distinct topic
//! prefixes; the kernel dispatchers are sibling-but-separate. Splitting
//! the client mirror keeps the type-level boundaries clean — a route
//! handler for `/api/capsules` literally cannot accidentally publish
//! an `AdminRequestKind` and vice-versa.
//!
//! ## Concurrency safety
//!
//! Unlike `AdminClient`, the `KernelRequest` payload has no
//! `request_id` field for correlation. To make concurrent HTTP
//! requests safe on a shared bus, every outbound message gets a
//! per-request UUID embedded in the topic suffix
//! (`astrid.v1.request.<wire-name>.<uuid>`). The kernel router echoes
//! the full suffix on its response (`response_topic` does
//! `topic.strip_prefix("astrid.v1.request.")` then prepends the
//! response prefix), so the client can match a unique
//! `astrid.v1.response.<wire-name>.<uuid>` and never confuse two
//! in-flight `GetStatus` calls for each other.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{KernelRequest, KernelResponse};
use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload};
use tokio::time::Instant;
use uuid::Uuid;

use crate::socket_client::{ReadError, SocketClient};

/// Default **inactivity** timeout: the maximum silence permitted *between*
/// frames on a request's response channel, NOT a total deadline on the whole
/// request.
///
/// The kernel emits a [`KernelResponse::Working`] keepalive every 5s while a
/// slow handler (chiefly `InstallCapsule`, which loads + runs the capsule's
/// `#[install]` hook) is still in flight; each such frame resets this window.
/// So the total wait is unbounded as long as the kernel keeps pinging within
/// this interval — an install that legitimately runs 30s under load no longer
/// trips a 15s *total* deadline the way the old blanket timeout did. Runaway
/// guest execution is bounded elsewhere (fuel ledger, epoch-interrupt deadline,
/// memory ledgers), so this timeout was never the forever-loop guard.
///
/// Sized at ~3x the 5s keepalive interval so a couple of missed pings (bus lag,
/// a briefly-saturated worker) don't cause a spurious timeout. A hard overall
/// ceiling ([`MAX_TOTAL`]) still bounds a kernel that pings forever.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Absolute backstop on the total wait for one request, across all inactivity
/// windows. Even a kernel that keeps emitting [`KernelResponse::Working`]
/// keepalives forever (wedged handler, buggy pinger) cannot hang a client past
/// this — exceeding it returns a [`KernelClientError::Timeout`] with
/// [`TimeoutKind::Ceiling`]. Generous (10 min) so it never fires for a
/// legitimately slow install, only for a genuinely stuck one.
const MAX_TOTAL: Duration = Duration::from_mins(10);

/// Which deadline elapsed on a [`KernelClientError::Timeout`].
///
/// Both map to a 504 at the gateway; the distinction is diagnostic — an
/// [`Inactivity`](Self::Inactivity) timeout means no frame arrived within the
/// per-frame silence budget, a [`Ceiling`](Self::Ceiling) timeout means the
/// overall [`MAX_TOTAL`] wait was exceeded even though the kernel kept signalling
/// liveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutKind {
    /// No frame arrived within the inactivity window ([`DEFAULT_TIMEOUT`]).
    Inactivity,
    /// The overall [`MAX_TOTAL`] ceiling elapsed across all inactivity windows.
    Ceiling,
}

impl std::fmt::Display for TimeoutKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inactivity => f.write_str("inactivity"),
            Self::Ceiling => f.write_str("overall ceiling"),
        }
    }
}

/// Typed failure of [`KernelClient::request`] / `BusKernelClient::request`.
///
/// The request paths return this instead of `anyhow::Error` so an uplink (the
/// HTTP gateway) can branch on the *kind* of failure — chiefly mapping a
/// [`Timeout`](Self::Timeout) to a 504 while connection loss and other transport
/// faults stay 500 — without matching on message text. `#[source]` carries the
/// underlying transport error where one exists, so the full cause chain is
/// preserved for logging rather than flattened to a string.
#[derive(Debug, thiserror::Error)]
pub enum KernelClientError {
    /// The wait for a response frame timed out — either the inactivity window or
    /// the overall ceiling. `topic` is the response channel awaited. Maps to 504.
    #[error("kernel request timed out ({kind}) waiting on {topic}")]
    Timeout {
        /// The response topic the client was awaiting.
        topic: String,
        /// Which deadline elapsed (diagnostic; both map to 504).
        kind: TimeoutKind,
    },
    /// The socket reached EOF or a read failed (peer closed / reset / broken
    /// pipe) before a terminal response. The connection is unusable. Maps to 500.
    #[error("connection lost waiting on {topic}")]
    ConnectionLost {
        /// The response topic the client was awaiting.
        topic: String,
        /// The underlying socket read error.
        #[source]
        source: ReadError,
    },
    /// The event bus closed before a terminal response arrived (bus-direct
    /// client only). Maps to 500.
    #[error("event bus closed before response on {topic}")]
    BusClosed {
        /// The response topic the client was awaiting.
        topic: String,
    },
    /// Building or serialising the outbound request failed. Maps to 500.
    #[error("failed to build kernel request")]
    Build {
        /// The underlying serialisation / message-construction error.
        #[source]
        source: anyhow::Error,
    },
    /// A frame arrived on the response topic but did not deserialise as a
    /// [`KernelResponse`]. Maps to 500.
    #[error("kernel response on {topic} did not deserialize as KernelResponse")]
    Deserialize {
        /// The response topic the malformed frame arrived on.
        topic: String,
    },
}

impl KernelClientError {
    /// Whether this is a request timeout (inactivity or ceiling). The gateway
    /// maps a timeout to 504 and every other variant to 500.
    #[must_use]
    pub const fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout { .. })
    }
}

/// Stable wire-name component of the topic suffix for a
/// [`KernelRequest`] variant.
///
/// These names are hand-curated rather than auto-derived — they
/// match the CLI's existing conventions
/// (`crates/astrid-cli/src/commands/{who,daemon,ps,doctor}.rs`) so
/// the gateway and CLI publish on the same topics and the kernel
/// can't accidentally see two different name conventions for the
/// same payload.
#[must_use]
pub const fn topic_suffix(req: &KernelRequest) -> &'static str {
    match req {
        KernelRequest::InstallCapsule { .. } => "install_capsule",
        KernelRequest::ApproveCapability { .. } => "approve_capability",
        KernelRequest::ListCapsules => "list_capsules",
        KernelRequest::ReloadCapsules => "reload_capsules",
        KernelRequest::ReloadCapsule { .. } => "reload_capsule",
        KernelRequest::UnloadCapsule { .. } => "unload_capsule",
        KernelRequest::PromoteWorkspace { .. } => "promote_workspace",
        KernelRequest::RollbackWorkspace { .. } => "rollback_workspace",
        KernelRequest::GetCommands => "get_commands",
        KernelRequest::GetCapsuleMetadata => "metadata",
        KernelRequest::GetAgentReadiness => "agent_readiness",
        KernelRequest::Shutdown { .. } => "shutdown",
        KernelRequest::GetStatus => "status",
    }
}

/// A connected kernel-management client. One short-lived
/// `KernelClient` per HTTP request; the per-request connection (plus
/// the per-call UUID embedded in the topic) avoids cross-talk
/// between concurrent dashboard calls.
pub struct KernelClient {
    inner: SocketClient,
    caller: PrincipalId,
    timeout: Duration,
    /// The authenticating device's `key_id`, when the caller's bearer/handshake
    /// was device-scoped. Stamped on every outbound request so the kernel
    /// cap-gate applies the per-device capability scope (#999); `None` for a
    /// full-authority caller (no attenuation).
    device_key_id: Option<String>,
}

/// Build the request message and its private response topic for `req` on behalf
/// of `caller`, carrying `device_key_id` when the caller was device-scoped.
///
/// Free function (no `self`) so the principal + device-scope stamping is
/// unit-testable without a live socket. The kernel strips the
/// `astrid.v1.request.` prefix and reprefixes `astrid.v1.response.`, so the
/// per-call correlation UUID gives a response channel concurrent calls can't
/// collide on.
fn build_request_message(
    caller: &PrincipalId,
    device_key_id: Option<&str>,
    req: &KernelRequest,
) -> Result<(IpcMessage, Topic)> {
    let correlation = Uuid::new_v4().simple().to_string();
    let suffix = format!("{}.{correlation}", topic_suffix(req));
    let request_topic = Topic::kernel_request(&suffix);
    let want_response = Topic::kernel_response(&suffix);

    let payload = serde_json::to_value(req).context("serialise KernelRequest")?;
    let mut msg = IpcMessage::new(request_topic, IpcPayload::RawJson(payload), Uuid::nil())
        .with_principal(caller.to_string());
    if let Some(kid) = device_key_id {
        msg = msg.with_device_key_id(kid);
    }
    Ok((msg, want_response))
}

impl KernelClient {
    /// Connect to the running daemon, authenticate via the existing
    /// handshake, and bind the client to `caller`. Every outbound
    /// request stamps `IpcMessage.principal = caller` so the kernel's
    /// `resolve_caller` reads it for Layer 5 capability checks.
    ///
    /// # Errors
    /// Returns an error if the socket file is missing (no daemon),
    /// connection fails, or the handshake is rejected.
    pub async fn connect(caller: PrincipalId) -> Result<Self> {
        let session_id = astrid_core::SessionId::from_uuid(Uuid::new_v4());
        let inner = SocketClient::connect(session_id, caller.clone())
            .await
            .context("Failed to connect to Astrid daemon. Run `astrid start` to launch it.")?;
        Ok(Self {
            inner,
            caller,
            timeout: DEFAULT_TIMEOUT,
            device_key_id: None,
        })
    }

    /// Override the response read timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Carry the authenticating device's `key_id` so the kernel cap-gate
    /// applies the per-device capability scope (#999). Callers behind the
    /// gateway auth middleware pass the bearer's `CallerContext.device_key_id`;
    /// a full-authority bearer passes `None` (unattenuated, the prior behaviour).
    #[must_use]
    pub fn with_device_key_id(mut self, device_key_id: Option<String>) -> Self {
        self.device_key_id = device_key_id;
        self
    }

    /// Send a [`KernelRequest`] and await the matching terminal
    /// [`KernelResponse`], tolerating any number of intervening
    /// [`KernelResponse::Working`] keepalive frames.
    ///
    /// The read is an **inactivity** loop: each iteration waits up to
    /// [`self.timeout`](Self::with_timeout) for the *next* frame. A `Working`
    /// keepalive is swallowed and the loop continues with a fresh window, so a
    /// slow-but-live kernel (an `InstallCapsule` running its `#[install]` hook
    /// under load) never trips a total-deadline timeout. Any other variant is
    /// the terminal response and is returned. An overall [`MAX_TOTAL`] ceiling
    /// bounds a kernel that keeps pinging forever; each read is additionally
    /// capped to the ceiling's remaining budget so the ceiling can't be
    /// overshot by up to a full inactivity window.
    ///
    /// # Errors
    /// Returns [`KernelClientError`]: `Timeout` on the inactivity window or the
    /// overall [`MAX_TOTAL`] ceiling (the gateway maps this to 504),
    /// `ConnectionLost` on a dead socket, `Build` on serialise/send failure, and
    /// `Deserialize` on a frame that is not a [`KernelResponse`] — all 500.
    pub async fn request(
        &mut self,
        req: KernelRequest,
    ) -> std::result::Result<KernelResponse, KernelClientError> {
        self.request_with_ceiling(req, MAX_TOTAL).await
    }

    /// [`request`](Self::request) with an explicit overall ceiling.
    ///
    /// The public entrypoint passes [`MAX_TOTAL`]; a test passes a short ceiling
    /// so the "unending keepalives are bounded" path is exercisable without
    /// waiting ten minutes. Production behaviour is unchanged.
    async fn request_with_ceiling(
        &mut self,
        req: KernelRequest,
        max_total: Duration,
    ) -> std::result::Result<KernelResponse, KernelClientError> {
        let (msg, want_response) =
            build_request_message(&self.caller, self.device_key_id.as_deref(), &req)
                .map_err(|source| KernelClientError::Build { source })?;
        self.inner
            .send_message(msg)
            .await
            .map_err(|source| KernelClientError::Build { source })?;

        let topic = want_response.as_str();
        let started = Instant::now();
        loop {
            // Remaining budget under the absolute ceiling. Zero → the overall
            // wait has been exhausted even though the kernel may still be pinging.
            let Some(ceiling_left) = max_total.checked_sub(started.elapsed()) else {
                return Err(KernelClientError::Timeout {
                    topic: topic.to_string(),
                    kind: TimeoutKind::Ceiling,
                });
            };
            if ceiling_left.is_zero() {
                return Err(KernelClientError::Timeout {
                    topic: topic.to_string(),
                    kind: TimeoutKind::Ceiling,
                });
            }

            // Cap each read at min(inactivity window, ceiling remaining) so the
            // ceiling can't be overshot by up to a full `self.timeout`. When the
            // ceiling clamps the wait, a read timeout is a Ceiling timeout;
            // otherwise it is the inactivity window elapsing.
            let read_budget = self.timeout.min(ceiling_left);
            let capped_by_ceiling = ceiling_left < self.timeout;

            // Each read is a FRESH inactivity window: a `Working` keepalive
            // resets the max-silence-between-frames budget, so total wait is
            // unbounded as long as the kernel pings within `self.timeout`.
            let raw = match self.inner.read_until_topic_typed(topic, read_budget).await {
                Ok(raw) => raw,
                Err(ReadError::Timeout) => {
                    return Err(KernelClientError::Timeout {
                        topic: topic.to_string(),
                        kind: if capped_by_ceiling {
                            TimeoutKind::Ceiling
                        } else {
                            TimeoutKind::Inactivity
                        },
                    });
                },
                Err(source @ ReadError::ConnectionLost(_)) => {
                    return Err(KernelClientError::ConnectionLost {
                        topic: topic.to_string(),
                        source,
                    });
                },
            };

            let resp = SocketClient::extract_kernel_response(&raw).ok_or_else(|| {
                KernelClientError::Deserialize {
                    topic: topic.to_string(),
                }
            })?;

            // A `Working` keepalive means the handler is still alive: swallow it
            // (it never reaches an HTTP client) and loop for a fresh inactivity
            // window. A stray late `Working` racing out after the terminal is
            // harmless — this loops past it. Any other variant is terminal.
            if !matches!(resp, KernelResponse::Working) {
                return Ok(resp);
            }
        }
    }

    /// Borrow the principal this client stamps on outbound messages.
    #[must_use]
    pub const fn caller(&self) -> &PrincipalId {
        &self.caller
    }

    /// Build a `KernelClient` over an already-constructed [`SocketClient`] with
    /// an explicit inactivity `timeout`. Test-only: lets the crate's tests drive
    /// [`request`](Self::request) over a loopback socket pair with a short
    /// timeout, no live daemon.
    #[cfg(all(test, unix))]
    fn from_socket_for_test(inner: SocketClient, caller: PrincipalId, timeout: Duration) -> Self {
        Self {
            inner,
            caller,
            timeout,
            device_key_id: None,
        }
    }
}

/// Convenience: lift a [`KernelResponse::Error`] into `Err`.
///
/// # Errors
/// Returns an error wrapping the kernel's error message when the
/// response is `KernelResponse::Error`.
pub fn into_result(resp: KernelResponse) -> Result<KernelResponse> {
    match resp {
        KernelResponse::Error(msg) => Err(anyhow!("kernel rejected request: {msg}")),
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_suffixes_match_cli_conventions() {
        // Pin these to the strings the CLI's existing kernel-request
        // code already uses (who.rs, daemon.rs, ps.rs, doctor.rs).
        // Drift here means the gateway and CLI publish to different
        // topics for the same payload — silent breakage.
        assert_eq!(topic_suffix(&KernelRequest::GetStatus), "status");
        assert_eq!(topic_suffix(&KernelRequest::ListCapsules), "list_capsules");
        assert_eq!(topic_suffix(&KernelRequest::GetCommands), "get_commands");
        assert_eq!(topic_suffix(&KernelRequest::GetCapsuleMetadata), "metadata");
        assert_eq!(
            topic_suffix(&KernelRequest::GetAgentReadiness),
            "agent_readiness"
        );
        assert_eq!(
            topic_suffix(&KernelRequest::ReloadCapsules),
            "reload_capsules"
        );
        assert_eq!(
            topic_suffix(&KernelRequest::Shutdown { reason: None }),
            "shutdown"
        );
    }

    #[test]
    fn request_message_stamps_principal_and_device_key_id() {
        // A device-scoped caller's key_id MUST ride the outbound request so the
        // kernel cap-gate applies the per-device scope (#999). Regression guard:
        // without the stamp, every HTTP gateway admin call (status, readiness,
        // reload, capsule list/install) bypasses device-scope attenuation.
        let caller = PrincipalId::new("alice").unwrap();
        let (msg, want) = build_request_message(
            &caller,
            Some("abcdef0123456789"),
            &KernelRequest::GetAgentReadiness,
        )
        .expect("build message");
        assert_eq!(msg.principal.as_deref(), Some("alice"));
        assert_eq!(
            msg.device_key_id.as_deref(),
            Some("abcdef0123456789"),
            "device key id must reach the kernel cap-gate"
        );
        // Response topic carries the request suffix so the reply is correlated.
        assert!(want.starts_with("astrid.v1.response."));
        assert!(want.contains("agent_readiness"));
    }

    #[test]
    fn request_message_omits_device_key_id_for_full_authority_caller() {
        // A full-authority bearer carries no device scope — the message must
        // leave device_key_id unset so the kernel treats it as unattenuated,
        // preserving the prior single-tenant behaviour.
        let caller = PrincipalId::new("alice").unwrap();
        let (msg, _) =
            build_request_message(&caller, None, &KernelRequest::GetStatus).expect("build message");
        assert!(msg.device_key_id.is_none());
    }

    #[test]
    fn into_result_lifts_error_variant() {
        let err = KernelResponse::Error("not allowed".into());
        let res = into_result(err);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("not allowed"));
    }

    // ── inactivity / keepalive `request()` loop ──────────────────────────────
    //
    // These drive `KernelClient::request` over a loopback local-stream pair. The
    // client side is a real `KernelClient`; the "kernel" side is the raw server
    // half, onto which the test writes framed IPC responses (a length-prefixed
    // JSON `IpcMessage` carrying a `RawJson(KernelResponse)` payload) on the
    // request's correlated response topic — exactly the shape the daemon emits.

    #[cfg(unix)]
    use astrid_core::local_transport::{self, LocalReadHalf, LocalStream, LocalWriteHalf};
    #[cfg(unix)]
    use std::io::Result as IoResult;
    #[cfg(unix)]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Read one length-prefixed frame off the server half and return the
    /// `IpcMessage`-shaped JSON so the test can learn the request's response
    /// topic (the correlated `astrid.v1.response.<suffix>` the client awaits).
    #[cfg(unix)]
    async fn read_request_frame(read: &mut LocalReadHalf) -> serde_json::Value {
        let mut len_buf = [0u8; 4];
        read.read_exact(&mut len_buf)
            .await
            .expect("read len prefix");
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        read.read_exact(&mut buf).await.expect("read frame body");
        serde_json::from_slice(&buf).expect("request frame is JSON")
    }

    /// Write a `KernelResponse` on `response_topic` as the daemon would: a
    /// length-prefixed `IpcMessage` with a `RawJson` payload.
    #[cfg(unix)]
    async fn write_response(
        write: &mut LocalWriteHalf,
        response_topic: &str,
        resp: &KernelResponse,
    ) -> IoResult<()> {
        let payload = serde_json::to_value(resp).unwrap();
        let msg = IpcMessage::new(
            Topic::from_raw(response_topic),
            IpcPayload::RawJson(payload),
            Uuid::nil(),
        );
        let bytes = serde_json::to_vec(&msg).unwrap();
        let len = u32::try_from(bytes.len()).unwrap();
        write.write_all(&len.to_be_bytes()).await?;
        write.write_all(&bytes).await?;
        write.flush().await
    }

    /// Derive the response topic a client awaits from the request frame it sent.
    #[cfg(unix)]
    fn response_topic_of(req_frame: &serde_json::Value) -> String {
        let request_topic = req_frame
            .get("topic")
            .and_then(|t| t.as_str())
            .expect("request frame has a topic");
        let suffix = request_topic
            .strip_prefix("astrid.v1.request.")
            .expect("kernel request topic prefix");
        format!("astrid.v1.response.{suffix}")
    }

    #[cfg(unix)]
    fn test_client(client_stream: LocalStream, timeout: Duration) -> KernelClient {
        let caller = PrincipalId::new("alice").unwrap();
        let inner = SocketClient::from_stream_for_test(
            client_stream,
            astrid_core::SessionId::from_uuid(Uuid::new_v4()),
            caller.clone(),
        );
        KernelClient::from_socket_for_test(inner, caller, timeout)
    }

    /// (a) N `Working` keepalives followed by a terminal `Success` → `request()`
    /// returns the `Success`, proving `Working` is non-terminal and resets the
    /// window rather than being surfaced.
    #[cfg(unix)]
    #[tokio::test]
    async fn working_frames_are_swallowed_then_terminal_returned() {
        let (client_stream, server_stream) = tokio::net::UnixStream::pair().unwrap();
        let (mut srv_read, mut srv_write) = local_transport::split(server_stream);

        let server = tokio::spawn(async move {
            let req = read_request_frame(&mut srv_read).await;
            let topic = response_topic_of(&req);
            // Three keepalives, then the real answer.
            for _ in 0..3 {
                write_response(&mut srv_write, &topic, &KernelResponse::Working)
                    .await
                    .unwrap();
            }
            write_response(
                &mut srv_write,
                &topic,
                &KernelResponse::Success(serde_json::json!({ "ok": true })),
            )
            .await
            .unwrap();
        });

        let mut client = test_client(client_stream, Duration::from_secs(5));
        let resp = client.request(KernelRequest::GetStatus).await.unwrap();
        assert!(
            matches!(resp, KernelResponse::Success(v) if v == serde_json::json!({ "ok": true })),
            "terminal Success must be returned, keepalives swallowed",
        );
        server.await.unwrap();
    }

    /// (b) `Working` frames spaced under the timeout for a span LONGER than the
    /// timeout itself → still succeeds. Proves the window is per-frame
    /// inactivity, not a total deadline: with a 120ms inactivity timeout we keep
    /// the request alive for ~300ms via 40ms-spaced pings, which a total 120ms
    /// deadline would have failed.
    #[cfg(unix)]
    #[tokio::test]
    async fn keepalives_extend_beyond_total_inactivity_timeout() {
        let (client_stream, server_stream) = tokio::net::UnixStream::pair().unwrap();
        let (mut srv_read, mut srv_write) = local_transport::split(server_stream);

        let server = tokio::spawn(async move {
            let req = read_request_frame(&mut srv_read).await;
            let topic = response_topic_of(&req);
            // ~300ms of pings at 40ms spacing — well past the 120ms window,
            // but each ping resets it, so no gap ever reaches 120ms.
            for _ in 0..7 {
                tokio::time::sleep(Duration::from_millis(40)).await;
                write_response(&mut srv_write, &topic, &KernelResponse::Working)
                    .await
                    .unwrap();
            }
            write_response(
                &mut srv_write,
                &topic,
                &KernelResponse::Success(serde_json::json!("done")),
            )
            .await
            .unwrap();
        });

        let mut client = test_client(client_stream, Duration::from_millis(120));
        let resp = client.request(KernelRequest::GetStatus).await.unwrap();
        assert!(matches!(resp, KernelResponse::Success(_)));
        server.await.unwrap();
    }

    /// (c) Total silence for longer than the inactivity timeout → a typed
    /// [`KernelClientError::Timeout`] with [`TimeoutKind::Inactivity`] (the
    /// gateway maps this to 504).
    #[cfg(unix)]
    #[tokio::test]
    async fn silence_past_timeout_yields_typed_timeout() {
        let (client_stream, server_stream) = tokio::net::UnixStream::pair().unwrap();
        // Hold the server half open but silent so the client sees inactivity,
        // not a connection loss (EOF).
        let _held = server_stream;

        let mut client = test_client(client_stream, Duration::from_millis(80));
        let err = client
            .request(KernelRequest::GetStatus)
            .await
            .expect_err("silence past the inactivity window must time out");
        assert!(
            matches!(
                err,
                KernelClientError::Timeout {
                    kind: TimeoutKind::Inactivity,
                    ..
                }
            ),
            "a silence timeout must be a typed inactivity Timeout: {err:?}"
        );
    }

    /// (d) Exceeding `MAX_TOTAL` → a typed [`KernelClientError::Timeout`] with
    /// [`TimeoutKind::Ceiling`], even though the kernel keeps pinging within the
    /// inactivity window forever. Uses a short-lived override of the ceiling via
    /// a dedicated helper so the test doesn't wait 10 minutes.
    #[cfg(unix)]
    #[tokio::test]
    async fn unending_keepalives_are_bounded_by_max_total() {
        let (client_stream, server_stream) = tokio::net::UnixStream::pair().unwrap();
        let (mut srv_read, mut srv_write) = local_transport::split(server_stream);

        // Ping forever, faster than the inactivity window, so only MAX_TOTAL can
        // stop the wait.
        let server = tokio::spawn(async move {
            let req = read_request_frame(&mut srv_read).await;
            let topic = response_topic_of(&req);
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                if write_response(&mut srv_write, &topic, &KernelResponse::Working)
                    .await
                    .is_err()
                {
                    break; // client gave up; socket closed.
                }
            }
        });

        // A short overall ceiling for the test; the inactivity timeout is longer
        // than the ping spacing so inactivity never fires — only the ceiling can.
        let mut client = test_client(client_stream, Duration::from_millis(200));
        let err = client
            .request_with_ceiling(KernelRequest::GetStatus, Duration::from_millis(120))
            .await
            .expect_err("unending keepalives must be bounded by the overall ceiling");
        assert!(
            matches!(
                err,
                KernelClientError::Timeout {
                    kind: TimeoutKind::Ceiling,
                    ..
                }
            ),
            "the ceiling timeout must be a typed ceiling Timeout: {err:?}"
        );
        server.abort();
    }

    /// `ConnectionLost` preserves its underlying [`ReadError`] as a `#[source]`
    /// — after the request is sent, the peer closing yields an EOF the socket
    /// reader reports as `ConnectionLost`, and the typed error keeps that cause
    /// in the chain rather than flattening it to a string.
    #[cfg(unix)]
    #[tokio::test]
    async fn connection_loss_preserves_source() {
        let (client_stream, server_stream) = tokio::net::UnixStream::pair().unwrap();
        let (mut srv_read, srv_write) = local_transport::split(server_stream);

        // Read (and thus accept) the request so the client's send succeeds, then
        // drop BOTH server halves so the client's next read hits EOF.
        let server = tokio::spawn(async move {
            let _req = read_request_frame(&mut srv_read).await;
            drop(srv_write);
            drop(srv_read);
        });

        let mut client = test_client(client_stream, Duration::from_secs(5));
        let err = client
            .request(KernelRequest::GetStatus)
            .await
            .expect_err("a closed peer must surface a connection-loss error");
        assert!(
            matches!(err, KernelClientError::ConnectionLost { .. }),
            "a closed peer must be ConnectionLost, got: {err:?}"
        );
        // The underlying transport error is preserved as a source, not stringified.
        assert!(
            std::error::Error::source(&err).is_some(),
            "ConnectionLost must carry its ReadError source: {err:?}"
        );
        server.await.unwrap();
    }
}

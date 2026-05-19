use astrid_core::session_token::{
    HandshakeRequest, HandshakeResponse, PROTOCOL_VERSION, SessionToken,
};

use crate::engine::wasm::bindings::astrid::capsule::net;
use crate::engine::wasm::bindings::astrid::capsule::types::NetReadStatus;
use crate::engine::wasm::host::http::is_safe_ip;
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::{HostState, NetStream};

/// Bounded timeout on a `net-connect-tcp` outbound handshake.
///
/// DNS resolve + TCP `connect` together must complete within this window,
/// otherwise the host fn returns an error rather than holding the WASM
/// guest in a host call indefinitely.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Maximum concurrent socket connections per capsule.
/// Prevents resource exhaustion from malicious or runaway clients.
const MAX_ACTIVE_STREAMS: usize = 8;

/// Returns true for IO errors that represent a normal peer disconnect.
/// These should NOT trap the WASM guest — the run loop handles dead streams.
fn is_peer_disconnect(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// Read one length-prefixed frame from `stream`. Shared by UnixStream and
/// TcpStream paths — both implement [`tokio::io::AsyncRead`].
async fn read_frame<S>(stream: &mut S) -> Result<NetReadStatus, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    match tokio::time::timeout(
        std::time::Duration::from_millis(50),
        stream.read_exact(&mut len_buf),
    )
    .await
    {
        Err(_) => return Ok(NetReadStatus::Pending),
        Ok(Err(e)) if is_peer_disconnect(&e) => return Ok(NetReadStatus::Closed),
        Ok(Err(e)) => return Err(format!("socket read error: {e}")),
        Ok(Ok(_)) => {},
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 10 * 1024 * 1024 {
        return Err("Payload too large (max 10MB)".to_string());
    }

    let mut payload = vec![0u8; len];
    let timeout_ms = 5000 + (len as u64 / 1024);
    match tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        stream.read_exact(&mut payload),
    )
    .await
    {
        Err(_) => return Err("Payload read timed out".to_string()),
        Ok(Err(e)) if is_peer_disconnect(&e) => return Ok(NetReadStatus::Closed),
        Ok(Err(e)) => return Err(format!("socket payload read error: {e}")),
        Ok(Ok(_)) => {},
    }

    Ok(NetReadStatus::Data(payload))
}

/// Write one length-prefixed frame to `stream`. Shared across UnixStream
/// and TcpStream — both implement [`tokio::io::AsyncWrite`].
async fn write_frame<S>(stream: &mut S, data: &[u8]) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let len = u32::try_from(data.len())
        .map_err(|_| std::io::Error::other("write payload too large for length prefix"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Handshake helpers
// ---------------------------------------------------------------------------

/// Timeout for individual handshake read/write operations (server-side).
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum allowed size of a handshake request payload (bytes).
const MAX_HANDSHAKE_SIZE: usize = 4096;

/// Validate the client handshake: read the `HandshakeRequest`, verify the token
/// and protocol version, then send back a `HandshakeResponse`.
///
/// Returns `Ok(())` on success or `Err(reason)` with a human-readable rejection
/// reason.
async fn validate_handshake(
    stream: &mut tokio::net::UnixStream,
    expected_token: &SessionToken,
) -> Result<(), String> {
    use tokio::io::AsyncReadExt;

    // 1. Read the handshake request (length-prefixed JSON, same wire format).
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| "handshake timed out (5s)".to_string())?
        .map_err(|e| format!("handshake read error: {e}"))?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_HANDSHAKE_SIZE {
        return Err(format!("handshake too large: {len} bytes"));
    }

    let mut payload = vec![0u8; len];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut payload))
        .await
        .map_err(|_| "handshake payload timed out".to_string())?
        .map_err(|e| format!("handshake payload read error: {e}"))?;

    let request: HandshakeRequest =
        serde_json::from_slice(&payload).map_err(|e| format!("invalid handshake JSON: {e}"))?;

    // 2. Validate protocol version FIRST - this check reveals no information
    // about token validity. Checking version before token prevents an oracle
    // where a "protocol mismatch" response confirms the token was correct.
    if request.protocol_version != PROTOCOL_VERSION {
        let reason = format!(
            "Protocol version mismatch (client={}, server={}). \
             Restart the daemon with `astrid daemon restart`.",
            request.protocol_version, PROTOCOL_VERSION,
        );
        if let Err(e) =
            send_handshake_response_timed(stream, &HandshakeResponse::error(&reason)).await
        {
            tracing::warn!(error = %e, "Failed to send handshake error response for protocol mismatch");
        }
        return Err(reason);
    }

    // 3. Validate token (constant-time comparison).
    // Send a uniform error response on both malformed-hex and wrong-token
    // paths to prevent an oracle that distinguishes the two failure modes.
    let client_token = match SessionToken::from_hex(&request.token) {
        Ok(t) => t,
        Err(_) => {
            if let Err(e) = send_handshake_response_timed(
                stream,
                &HandshakeResponse::error("authentication failed"),
            )
            .await
            {
                tracing::warn!(error = %e, "Failed to send handshake error response");
            }
            return Err("invalid session token".to_string());
        },
    };

    if !expected_token.ct_eq(&client_token) {
        if let Err(e) = send_handshake_response_timed(
            stream,
            &HandshakeResponse::error("authentication failed"),
        )
        .await
        {
            tracing::warn!(error = %e, "Failed to send handshake error response");
        }
        return Err("invalid session token".to_string());
    }

    // 4. All checks passed - send success response.
    send_handshake_response_timed(stream, &HandshakeResponse::ok())
        .await
        .map_err(|e| format!("failed to send handshake response: {e}"))?;

    // Truncate client_version to prevent log injection from oversized values.
    // Use chars().take() to avoid panicking on multi-byte UTF-8 boundaries.
    let safe_version: String = request.client_version.chars().take(64).collect();
    tracing::info!(
        client_version = %safe_version,
        "Socket handshake succeeded"
    );
    Ok(())
}

/// Send a length-prefixed JSON handshake response with a 5s write timeout.
///
/// Wraps [`send_handshake_response`] with a timeout to prevent a stalled
/// client from holding the accept loop hostage during the response write.
async fn send_handshake_response_timed(
    stream: &mut tokio::net::UnixStream,
    response: &HandshakeResponse,
) -> Result<(), std::io::Error> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, send_handshake_response(stream, response))
        .await
        .map_err(|_| std::io::Error::other("handshake response write timed out (5s)"))?
}

/// Send a length-prefixed JSON handshake response.
async fn send_handshake_response(
    stream: &mut tokio::net::UnixStream,
    response: &HandshakeResponse,
) -> Result<(), std::io::Error> {
    use tokio::io::AsyncWriteExt;

    let bytes = serde_json::to_vec(response)
        .map_err(|e| std::io::Error::other(format!("serialize handshake response: {e}")))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::other("handshake response too large"))?;

    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Verify that the connecting process runs as the same UID as the daemon.
/// Returns `Err(reason)` if the UID does not match or credentials cannot
/// be retrieved.
#[cfg(unix)]
fn verify_peer_credentials(stream: &tokio::net::UnixStream) -> Result<(), String> {
    match stream.peer_cred() {
        Ok(cred) => {
            let peer_uid = cred.uid();
            let my_uid = nix::unistd::geteuid().as_raw();
            if peer_uid != my_uid {
                Err(format!(
                    "peer UID {peer_uid} does not match daemon UID {my_uid}"
                ))
            } else {
                Ok(())
            }
        },
        Err(e) => Err(format!("failed to check peer credentials: {e}")),
    }
}

impl net::Host for HostState {
    /// Gate `net_bind` capability once at bind time (session-scoped).
    ///
    /// The kernel pre-binds the socket and provides it via `HostState`. This
    /// function enforces the security gate before the capsule can use the
    /// listener - subsequent `accept()` calls do not re-check.
    fn net_bind_unix(&mut self, _listener_handle: u64) -> Result<u64, String> {
        // Security gate: only capsules with net_bind capability may bind sockets.
        if let Some(ref gate) = self.security {
            let capsule_id = self.capsule_id.as_str().to_owned();
            let gate = gate.clone();
            let handle = self.runtime_handle.clone();
            let semaphore = self.host_semaphore.clone();
            util::bounded_block_on(&handle, &semaphore, async move {
                gate.check_net_bind(&capsule_id).await
            })
            .map_err(|e| format!("security denied net_bind: {e}"))?;
        }

        // Return a dummy handle, since the socket is pre-bound.
        Ok(1)
    }

    fn net_accept(&mut self, _listener_handle: u64) -> Result<u64, String> {
        // Pre-accept cap check: fast reject without blocking on accept().
        let stream_count = self.active_streams.len();
        if stream_count >= MAX_ACTIVE_STREAMS {
            tracing::warn!(
                max = MAX_ACTIVE_STREAMS,
                current = stream_count,
                "accept: connection cap reached, rejecting"
            );
            return Err(format!(
                "connection cap reached ({stream_count}/{MAX_ACTIVE_STREAMS})"
            ));
        }

        let listener_arc = self
            .cli_socket_listener
            .clone()
            .ok_or_else(|| "No CLI Socket Listener available in HostState".to_string())?;
        let rt_handle = self.runtime_handle.clone();
        let cancel_token = self.cancel_token.clone();
        let session_token = self.session_token.clone();
        let host_semaphore = self.host_semaphore.clone();

        // Accept + authenticate loop. Authentication failures (wrong UID, bad
        // token) retry accept immediately so a malicious client cannot gate
        // legitimate connections behind the WASM-side 100ms backoff.
        let stream = loop {
            let accept_result = util::bounded_block_on_cancellable(
                &rt_handle,
                &host_semaphore,
                &cancel_token,
                async {
                    let l = listener_arc.lock().await;
                    l.accept().await
                },
            );
            let (stream, _addr) = match accept_result {
                Some(result) => result.map_err(|e| format!("accept error: {e}"))?,
                None => return Err("capsule unloading".to_string()),
            };

            // Peer credential verification - reject connections from different UIDs.
            #[cfg(unix)]
            if let Err(reason) = verify_peer_credentials(&stream) {
                tracing::warn!(
                    security_event = true,
                    reason = %reason,
                    "Rejected socket connection: peer credential check failed"
                );
                drop(stream);
                continue;
            }

            // Authenticate the connection via session token handshake.
            let mut stream = stream;
            if let Some(ref token) = session_token {
                let handshake_result = util::bounded_block_on_cancellable(
                    &rt_handle,
                    &host_semaphore,
                    &cancel_token,
                    validate_handshake(&mut stream, token),
                );
                match handshake_result {
                    None => return Err("capsule unloading".to_string()),
                    Some(Ok(())) => break stream,
                    Some(Err(reason)) => {
                        tracing::warn!(
                            security_event = true,
                            reason = %reason,
                            "Rejected socket connection: handshake failed"
                        );
                        drop(stream);
                        continue;
                    },
                }
            } else {
                // No session token configured (test/legacy mode) - accept without auth.
                break stream;
            }
        };

        // Defense-in-depth: re-check cap before insertion.
        let stream_count = self.active_streams.len();
        if stream_count >= MAX_ACTIVE_STREAMS {
            tracing::warn!(
                max = MAX_ACTIVE_STREAMS,
                current = stream_count,
                "accept: connection cap reached post-handshake, dropping authenticated stream"
            );
            drop(stream);
            return Err(format!(
                "connection cap reached ({stream_count}/{MAX_ACTIVE_STREAMS})"
            ));
        }

        // Use a monotonic counter to avoid handle ID reuse after stream removal.
        let handle_id = self.next_stream_id;
        self.next_stream_id = self
            .next_stream_id
            .checked_add(1)
            .ok_or_else(|| "stream handle ID space exhausted".to_string())?;
        debug_assert!(
            !self.active_streams.contains_key(&handle_id),
            "stream handle ID collision"
        );
        self.active_streams.insert(
            handle_id,
            NetStream::Unix(std::sync::Arc::new(tokio::sync::Mutex::new(stream))),
        );

        // The `client.v1.connected` event is intentionally NOT published
        // here. At accept time the host has no idea which principal the
        // socket will eventually claim, so an unstamped publish lands
        // under `default` and breaks `astrid who` attribution (#22). The
        // cli (uplink) capsule republishes the event with the correct
        // claimed principal once the first principal-stamped ingress
        // message arrives on the stream — at that point the principal
        // is known and the kernel's `active_connections` counter is
        // attributed correctly. A stream that connects but never sends
        // a principal-claim message therefore does not appear in the
        // per-principal roster, which matches the operator-facing
        // semantics of `who` (idle/zombie sockets shouldn't count).

        Ok(handle_id)
    }

    fn net_poll_accept(&mut self, _listener_handle: u64) -> Result<Option<u64>, String> {
        let listener_arc = self
            .cli_socket_listener
            .clone()
            .ok_or_else(|| "No CLI Socket Listener available in HostState".to_string())?;
        let rt_handle = self.runtime_handle.clone();
        let cancel_token = self.cancel_token.clone();
        let session_token = self.session_token.clone();
        let host_semaphore = self.host_semaphore.clone();
        let stream_count = self.active_streams.len();

        // Enforce connection cap at the host level.
        if stream_count >= MAX_ACTIVE_STREAMS {
            tracing::warn!(
                max = MAX_ACTIVE_STREAMS,
                current = stream_count,
                "poll_accept: connection cap reached, rejecting"
            );
            return Ok(None);
        }

        // Non-blocking accept with a short timeout. The 10ms window is long
        // enough to catch a pending connection without meaningfully stalling
        // the WASM loop.
        let accept_result =
            util::bounded_block_on_cancellable(&rt_handle, &host_semaphore, &cancel_token, async {
                let l = listener_arc.lock().await;
                tokio::time::timeout(std::time::Duration::from_millis(10), l.accept()).await
            });

        let (stream, _addr) = match accept_result {
            // Cancellation: return None (capsule unloading).
            None => return Ok(None),
            // Timeout: no pending connection.
            Some(Err(_)) => return Ok(None),
            // Accept error: propagate.
            Some(Ok(Err(e))) => return Err(format!("accept error: {e}")),
            // Success: connection pending.
            Some(Ok(Ok(pair))) => pair,
        };

        // Peer credential verification (same as accept_impl).
        #[cfg(unix)]
        if let Err(reason) = verify_peer_credentials(&stream) {
            tracing::warn!(
                security_event = true,
                reason = %reason,
                "poll_accept: rejected connection (peer credential check failed)"
            );
            drop(stream);
            return Ok(None);
        }

        // Session token handshake.
        let mut stream = stream;
        if let Some(ref token) = session_token {
            let handshake_result = util::bounded_block_on_cancellable(
                &rt_handle,
                &host_semaphore,
                &cancel_token,
                validate_handshake(&mut stream, token),
            );
            match handshake_result {
                None => return Ok(None),
                Some(Err(reason)) => {
                    tracing::warn!(
                        security_event = true,
                        reason = %reason,
                        "poll_accept: rejected connection (handshake failed)"
                    );
                    drop(stream);
                    return Ok(None);
                },
                Some(Ok(())) => {},
            }
        }

        // Store the authenticated stream. Re-check cap under lock for defense
        // in depth.
        if self.active_streams.len() >= MAX_ACTIVE_STREAMS {
            drop(stream);
            return Ok(None);
        }

        let handle_id = self.next_stream_id;
        self.next_stream_id = self
            .next_stream_id
            .checked_add(1)
            .ok_or_else(|| "stream handle ID space exhausted".to_string())?;
        debug_assert!(
            !self.active_streams.contains_key(&handle_id),
            "stream handle ID collision"
        );
        self.active_streams.insert(
            handle_id,
            NetStream::Unix(std::sync::Arc::new(tokio::sync::Mutex::new(stream))),
        );

        // See the matching comment in `net_accept` — `client.v1.connected`
        // is published by the cli capsule on the first principal-stamped
        // ingress message, not here, so the per-principal counter is
        // attributed correctly (#22).

        Ok(Some(handle_id))
    }

    fn net_read(&mut self, stream_handle: u64) -> Result<NetReadStatus, String> {
        let stream = self
            .active_streams
            .get(&stream_handle)
            .cloned()
            .ok_or_else(|| "Stream handle not found".to_string())?;

        let rt_handle = self.runtime_handle.clone();
        let cancel_token = self.cancel_token.clone();
        let host_semaphore = self.host_semaphore.clone();

        // Cancel safety: read_exact is not cancel-safe, so cancellation mid-read
        // may leave a partial frame on the socket. This is acceptable because the
        // capsule is unloading - the socket will be closed by Drop on
        // active_streams and the client will see a hard EOF / connection reset.
        let status =
            util::bounded_block_on_cancellable(&rt_handle, &host_semaphore, &cancel_token, async {
                match stream {
                    NetStream::Unix(arc) => {
                        let mut s = arc.lock().await;
                        read_frame(&mut *s).await
                    },
                    NetStream::Tcp(arc) => {
                        let mut s = arc.lock().await;
                        read_frame(&mut *s).await
                    },
                }
            });

        // Cancellation (capsule unloading) -> Pending so the guest loop exits cleanly.
        match status {
            Some(r) => r,
            None => Ok(NetReadStatus::Pending),
        }
    }

    fn net_write(&mut self, stream_handle: u64, data: Vec<u8>) -> Result<(), String> {
        let stream = self
            .active_streams
            .get(&stream_handle)
            .cloned()
            .ok_or_else(|| "Stream handle not found".to_string())?;

        let rt_handle = self.runtime_handle.clone();
        let host_semaphore = self.host_semaphore.clone();
        let cancel_token = self.cancel_token.clone();

        // Cancel safety: write_all is not cancel-safe, so cancellation mid-write
        // may leave a partial frame on the socket. This is acceptable because the
        // capsule is unloading - the socket will be closed by Drop on
        // active_streams and the client will see a hard EOF / connection reset.
        let result =
            util::bounded_block_on_cancellable(&rt_handle, &host_semaphore, &cancel_token, async {
                match stream {
                    NetStream::Unix(arc) => {
                        let mut s = arc.lock().await;
                        write_frame(&mut *s, &data).await
                    },
                    NetStream::Tcp(arc) => {
                        let mut s = arc.lock().await;
                        write_frame(&mut *s, &data).await
                    },
                }
            });
        match result {
            Some(Ok(())) => {},
            Some(Err(e)) => {
                // Write failed — client likely disconnected. Log and continue;
                // the dead stream will be cleaned up on the next read.
                tracing::debug!(error = %e, "net write failed, client likely disconnected");
            },
            None => return Err("capsule unloading".to_string()),
        }

        Ok(())
    }

    fn net_connect_tcp(&mut self, host: String, port: u16) -> Result<u64, String> {
        // 1. Capability check — literal host:port against the manifest's
        //    net_connect allowlist. DNS / SSRF run after this gate.
        if let Some(ref gate) = self.security {
            let capsule_id = self.capsule_id.as_str().to_owned();
            let host_for_check = host.clone();
            let gate = gate.clone();
            let rt = self.runtime_handle.clone();
            let semaphore = self.host_semaphore.clone();
            util::bounded_block_on(&rt, &semaphore, async move {
                gate.check_net_connect(&capsule_id, &host_for_check, port)
                    .await
            })
            .map_err(|e| format!("security denied net_connect: {e}"))?;
        }

        // 2. Pre-insert active-stream cap check.
        let stream_count = self.active_streams.len();
        if stream_count >= MAX_ACTIVE_STREAMS {
            tracing::warn!(
                max = MAX_ACTIVE_STREAMS,
                current = stream_count,
                "net_connect_tcp: connection cap reached, rejecting"
            );
            return Err(format!(
                "connection cap reached ({stream_count}/{MAX_ACTIVE_STREAMS})"
            ));
        }

        let rt_handle = self.runtime_handle.clone();
        let host_semaphore = self.host_semaphore.clone();
        let cancel_token = self.cancel_token.clone();

        // 3. DNS resolve + SSRF airlock + TCP connect, all under a bounded
        //    timeout so a stalled handshake doesn't pin the WASM guest.
        let connect_result =
            util::bounded_block_on_cancellable(&rt_handle, &host_semaphore, &cancel_token, async {
                tokio::time::timeout(CONNECT_TIMEOUT, async {
                    let addrs: Vec<std::net::SocketAddr> =
                        tokio::net::lookup_host((host.as_str(), port))
                            .await
                            .map_err(|e| format!("dns: {e}"))?
                            .collect();
                    if addrs.is_empty() {
                        return Err("dns: no addresses returned".to_string());
                    }
                    for addr in &addrs {
                        if !is_safe_ip(addr.ip()) {
                            return Err(format!(
                                "net.connect-tcp denied: resolved IP {} is in a \
                                 private/loopback/link-local range (SSRF protection)",
                                addr.ip()
                            ));
                        }
                    }
                    tokio::net::TcpStream::connect(&addrs[..])
                        .await
                        .map_err(|e| format!("connect: {e}"))
                })
                .await
                .map_err(|_| format!("connect timeout after {}s", CONNECT_TIMEOUT.as_secs()))
                .and_then(|inner| inner)
            });

        let stream = match connect_result {
            Some(Ok(s)) => s,
            Some(Err(e)) => return Err(e),
            None => return Err("capsule unloading".to_string()),
        };

        // 4. Defense in depth: re-check the cap before insertion.
        if self.active_streams.len() >= MAX_ACTIVE_STREAMS {
            drop(stream);
            return Err(format!(
                "connection cap reached ({}/{MAX_ACTIVE_STREAMS})",
                self.active_streams.len()
            ));
        }

        let handle_id = self.next_stream_id;
        self.next_stream_id = self
            .next_stream_id
            .checked_add(1)
            .ok_or_else(|| "stream handle ID space exhausted".to_string())?;
        debug_assert!(
            !self.active_streams.contains_key(&handle_id),
            "stream handle ID collision"
        );
        self.active_streams.insert(
            handle_id,
            NetStream::Tcp(std::sync::Arc::new(tokio::sync::Mutex::new(stream))),
        );
        Ok(handle_id)
    }

    fn net_close_stream(&mut self, stream_handle: u64) -> Result<(), String> {
        // Idempotent: silently ignore if the handle was already removed.
        //
        // The `client.v1.disconnect` event used to be published here, but
        // an unstamped publish lands under `default` regardless of which
        // principal owned the connection, which double-counts on the
        // kernel side (`connection_closed(default)` decrements default's
        // counter even when the stream was attributed to alice). The cli
        // capsule now publishes the disconnect stamped with the stream's
        // bound principal before calling `close()` — see issue #22.
        let _ = self.active_streams.remove(&stream_handle);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_active_streams_pinned() {
        // Changing MAX_ACTIVE_STREAMS requires explicit security review
        // (resource exhaustion surface). Update this test deliberately.
        assert_eq!(MAX_ACTIVE_STREAMS, 8);
    }
}

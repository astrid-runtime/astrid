use crate::engine::wasm::bindings::astrid::capsule::net;
use crate::engine::wasm::bindings::astrid::capsule::types::ShutdownHow;
use crate::engine::wasm::host::http::is_safe_ip;
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::{HostState, NetStream, TcpStreamSlot, UnixStreamSlot};

mod handshake;
mod stream;

use handshake::{validate_handshake, verify_peer_credentials};
use stream::{
    CONNECT_TIMEOUT, MAX_BYTES_PER_CALL, read_bytes_inner, with_tcp_slot, write_bytes_inner,
};

/// DNS hostname guards before reaching the resolver.
///
/// `lookup_host` will reject empty or null-byte input, but failing
/// early at the host-fn boundary keeps malformed guest input out of
/// the resolver / audit log / tracing spans entirely. 255 chars is
/// the RFC 1035 max-name-length.
fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("host must be non-empty".to_string());
    }
    if host.len() > 255 {
        return Err(format!(
            "host too long ({} bytes, max 255 per RFC 1035)",
            host.len()
        ));
    }
    if host.bytes().any(|b| b == 0) {
        return Err("host contains null byte".to_string());
    }
    Ok(())
}

/// Maximum concurrent socket connections per capsule.
/// Prevents resource exhaustion from malicious or runaway clients.
const MAX_ACTIVE_STREAMS: usize = 8;

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
            NetStream::Unix(UnixStreamSlot {
                stream: std::sync::Arc::new(tokio::sync::Mutex::new(stream)),
                read_timeout: None,
                write_timeout: None,
            }),
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
            NetStream::Unix(UnixStreamSlot {
                stream: std::sync::Arc::new(tokio::sync::Mutex::new(stream)),
                read_timeout: None,
                write_timeout: None,
            }),
        );

        // See the matching comment in `net_accept` — `client.v1.connected`
        // is published by the cli capsule on the first principal-stamped
        // ingress message, not here, so the per-principal counter is
        // attributed correctly (#22).

        Ok(Some(handle_id))
    }

    fn net_connect_tcp(&mut self, host: String, port: u16) -> Result<u64, String> {
        // Reject malformed host strings at the boundary — keeps unsafe
        // input out of the resolver, the audit log, and tracing spans.
        validate_host(&host)?;
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
            NetStream::Tcp(TcpStreamSlot {
                stream: std::sync::Arc::new(tokio::sync::Mutex::new(stream)),
                read_timeout: None,
                write_timeout: None,
            }),
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

    fn net_read_bytes(&mut self, stream_handle: u64, max_bytes: u32) -> Result<Vec<u8>, String> {
        let stream = self
            .active_streams
            .get(&stream_handle)
            .cloned()
            .ok_or_else(|| "Stream handle not found".to_string())?;
        let rt = self.runtime_handle.clone();
        let sem = self.host_semaphore.clone();
        let tok = self.cancel_token.clone();
        let max = max_bytes as usize;
        let result = util::bounded_block_on_cancellable(&rt, &sem, &tok, async {
            match stream {
                NetStream::Unix(slot) => {
                    let timeout = slot.read_timeout;
                    let mut s = slot.stream.lock().await;
                    read_bytes_inner(&mut *s, max, timeout).await
                },
                NetStream::Tcp(slot) => {
                    let timeout = slot.read_timeout;
                    let mut s = slot.stream.lock().await;
                    read_bytes_inner(&mut *s, max, timeout).await
                },
            }
        });
        result.unwrap_or_else(|| Ok(Vec::new()))
    }

    fn net_write_bytes(&mut self, stream_handle: u64, data: Vec<u8>) -> Result<u32, String> {
        let stream = self
            .active_streams
            .get(&stream_handle)
            .cloned()
            .ok_or_else(|| "Stream handle not found".to_string())?;
        let rt = self.runtime_handle.clone();
        let sem = self.host_semaphore.clone();
        let tok = self.cancel_token.clone();
        let result = util::bounded_block_on_cancellable(&rt, &sem, &tok, async {
            match stream {
                NetStream::Unix(slot) => {
                    let timeout = slot.write_timeout;
                    let mut s = slot.stream.lock().await;
                    write_bytes_inner(&mut *s, &data, timeout).await
                },
                NetStream::Tcp(slot) => {
                    let timeout = slot.write_timeout;
                    let mut s = slot.stream.lock().await;
                    write_bytes_inner(&mut *s, &data, timeout).await
                },
            }
        });
        match result {
            Some(r) => r,
            None => Err("capsule unloading".to_string()),
        }
    }

    fn net_peek(&mut self, stream_handle: u64, max_bytes: u32) -> Result<Vec<u8>, String> {
        // tokio's TcpStream has `peek` natively; UnixStream does not. The
        // Unix case is rare for outbound work — return an error rather
        // than emulate via a buffered wrapper that other host fns would
        // also have to learn about.
        let stream = self
            .active_streams
            .get(&stream_handle)
            .cloned()
            .ok_or_else(|| "Stream handle not found".to_string())?;
        let rt = self.runtime_handle.clone();
        let sem = self.host_semaphore.clone();
        let tok = self.cancel_token.clone();
        // Same OOM cap as read_bytes — guest can pass u32::MAX which
        // would be a 4 GB host-side allocation.
        let max = (max_bytes as usize).min(MAX_BYTES_PER_CALL);
        match stream {
            NetStream::Tcp(slot) => {
                let timeout = slot.read_timeout;
                let result = util::bounded_block_on_cancellable(&rt, &sem, &tok, async move {
                    let s = slot.stream.lock().await;
                    let mut buf = vec![0u8; max];
                    let fut = s.peek(&mut buf);
                    let n = match timeout {
                        Some(d) => match tokio::time::timeout(d, fut).await {
                            Ok(Ok(n)) => n,
                            Ok(Err(e)) => return Err(format!("peek error: {e}")),
                            Err(_) => return Err("peek would block".to_string()),
                        },
                        None => fut.await.map_err(|e| format!("peek error: {e}"))?,
                    };
                    buf.truncate(n);
                    Ok(buf)
                });
                result.unwrap_or_else(|| Ok(Vec::new()))
            },
            NetStream::Unix(_) => Err("peek not supported on Unix streams".to_string()),
        }
    }

    fn net_shutdown(&mut self, stream_handle: u64, how: ShutdownHow) -> Result<(), String> {
        let stream = self
            .active_streams
            .get(&stream_handle)
            .cloned()
            .ok_or_else(|| "Stream handle not found".to_string())?;
        let rt = self.runtime_handle.clone();
        let sem = self.host_semaphore.clone();
        let tok = self.cancel_token.clone();
        let std_how = match how {
            ShutdownHow::Read => std::net::Shutdown::Read,
            ShutdownHow::Write => std::net::Shutdown::Write,
            ShutdownHow::Both => std::net::Shutdown::Both,
        };
        let result = util::bounded_block_on_cancellable(&rt, &sem, &tok, async move {
            match stream {
                NetStream::Tcp(slot) => {
                    // Use socket2's borrowed `SockRef` for full
                    // `Shutdown::{Read,Write,Both}` support — tokio's
                    // `TcpStream` only exposes the write half via the
                    // `AsyncWrite` trait, but the OS `shutdown(2)`
                    // syscall (reached through socket2) handles every
                    // direction cleanly. Borrowed; no FD ownership
                    // transfer; safe to call repeatedly.
                    let s = slot.stream.lock().await;
                    let sock_ref = socket2::SockRef::from(&*s);
                    sock_ref
                        .shutdown(std_how)
                        .map_err(|e| format!("shutdown({how:?}): {e}"))
                },
                NetStream::Unix(_) => Err("shutdown not supported on Unix streams".to_string()),
            }
        });
        match result {
            Some(r) => r,
            None => Err("capsule unloading".to_string()),
        }
    }

    fn net_peer_addr(&mut self, stream_handle: u64) -> Result<String, String> {
        with_tcp_slot(self, stream_handle, |slot| {
            slot.peer_addr()
                .map(|a| a.to_string())
                .map_err(|e| format!("peer_addr: {e}"))
        })
    }

    fn net_local_addr(&mut self, stream_handle: u64) -> Result<String, String> {
        with_tcp_slot(self, stream_handle, |slot| {
            slot.local_addr()
                .map(|a| a.to_string())
                .map_err(|e| format!("local_addr: {e}"))
        })
    }

    fn net_set_nodelay(&mut self, stream_handle: u64, nodelay: bool) -> Result<(), String> {
        with_tcp_slot(self, stream_handle, |slot| {
            slot.set_nodelay(nodelay)
                .map_err(|e| format!("set_nodelay: {e}"))
        })
    }

    fn net_nodelay(&mut self, stream_handle: u64) -> Result<bool, String> {
        with_tcp_slot(self, stream_handle, |slot| {
            slot.nodelay().map_err(|e| format!("nodelay: {e}"))
        })
    }

    fn net_set_read_timeout(
        &mut self,
        stream_handle: u64,
        timeout_ms: Option<u64>,
    ) -> Result<(), String> {
        match self.active_streams.get_mut(&stream_handle) {
            Some(s) => {
                *s.read_timeout_mut() = timeout_ms.map(std::time::Duration::from_millis);
                Ok(())
            },
            None => Err("Stream handle not found".to_string()),
        }
    }

    fn net_read_timeout(&mut self, stream_handle: u64) -> Result<Option<u64>, String> {
        match self.active_streams.get(&stream_handle) {
            Some(s) => Ok(s
                .read_timeout()
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))),
            None => Err("Stream handle not found".to_string()),
        }
    }

    fn net_set_write_timeout(
        &mut self,
        stream_handle: u64,
        timeout_ms: Option<u64>,
    ) -> Result<(), String> {
        match self.active_streams.get_mut(&stream_handle) {
            Some(s) => {
                *s.write_timeout_mut() = timeout_ms.map(std::time::Duration::from_millis);
                Ok(())
            },
            None => Err("Stream handle not found".to_string()),
        }
    }

    fn net_write_timeout(&mut self, stream_handle: u64) -> Result<Option<u64>, String> {
        match self.active_streams.get(&stream_handle) {
            Some(s) => Ok(s
                .write_timeout()
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))),
            None => Err("Stream handle not found".to_string()),
        }
    }

    fn net_set_ttl(&mut self, stream_handle: u64, ttl: u32) -> Result<(), String> {
        with_tcp_slot(self, stream_handle, |slot| {
            slot.set_ttl(ttl).map_err(|e| format!("set_ttl: {e}"))
        })
    }

    fn net_ttl(&mut self, stream_handle: u64) -> Result<u32, String> {
        with_tcp_slot(self, stream_handle, |slot| {
            slot.ttl().map_err(|e| format!("ttl: {e}"))
        })
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

    #[tokio::test]
    async fn socket2_shutdown_supports_all_three_directions() {
        // Smoke test that socket2::SockRef::from(&tokio::net::TcpStream)
        // accepts every Shutdown direction. If a future tokio/socket2 bump
        // breaks this glue, the test fails loudly here instead of
        // surfacing as a runtime error on the first capsule that calls
        // shutdown(Read|Both).
        use std::net::Shutdown;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, _server) = tokio::join!(
            async { tokio::net::TcpStream::connect(addr).await.unwrap() },
            async { listener.accept().await.unwrap() },
        );
        let sock = socket2::SockRef::from(&client);
        sock.shutdown(Shutdown::Write).unwrap();
        // Read shutdown after write may already be effectively done; calling
        // it again must not panic. Some platforms return ENOTCONN here,
        // which is fine — the point is the FFI call resolves without
        // dropping into an "only write supported" branch.
        let _ = sock.shutdown(Shutdown::Read);
        let _ = sock.shutdown(Shutdown::Both);
    }

    #[test]
    fn validate_host_accepts_normal_names() {
        assert!(validate_host("example.com").is_ok());
        assert!(validate_host("fulcrum.unicity.network").is_ok());
        assert!(validate_host("127.0.0.1").is_ok());
        assert!(validate_host("::1").is_ok());
    }

    #[test]
    fn validate_host_rejects_empty() {
        assert!(validate_host("").is_err());
    }

    #[test]
    fn validate_host_rejects_null_bytes() {
        assert!(validate_host("evil\0.com").is_err());
    }

    #[test]
    fn validate_host_rejects_overlength() {
        let long = "a".repeat(256);
        let err = validate_host(&long).unwrap_err();
        assert!(err.contains("too long"));
    }

    #[test]
    fn validate_host_accepts_max_length() {
        let max = "a".repeat(255);
        assert!(validate_host(&max).is_ok());
    }
}

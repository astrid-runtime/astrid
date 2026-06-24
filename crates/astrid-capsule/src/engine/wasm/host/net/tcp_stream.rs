//! `HostTcpStream` impl — byte-oriented operations on Unix-domain and
//! outbound TCP streams. Stream halves (`read-stream` / `write-stream`)
//! land in a follow-up commit alongside the wasmtime-wasi-io
//! `InputStream`/`OutputStream` adapter for our `NetStream` type.

use std::time::Duration;

use wasmtime::component::Resource;
use wasmtime_wasi::p2::DynPollable;

use super::stream::{
    MAX_BYTES_PER_CALL, is_peer_disconnect, read_bytes_inner, read_frame, write_bytes_inner,
    write_frame,
};

/// Map a `write_frame` `io::Error` to a typed `net::ErrorCode`. Peer
/// disconnect on a write maps to `ConnectionReset` so the guest can
/// distinguish a closed connection from a transient error.
fn map_write_frame_err(e: &std::io::Error) -> ErrorCode {
    if is_peer_disconnect(e) {
        ErrorCode::ConnectionReset
    } else {
        ErrorCode::Unknown(format!("write: {e}"))
    }
}
use super::{
    HostState, NetStream, audit_net, map_io_err, net_stream, with_tcp_slot_mut, with_tcp_stream,
};
use crate::engine::wasm::bindings::astrid::io::streams::{InputStream, OutputStream};
use crate::engine::wasm::bindings::astrid::net::host::{
    ErrorCode, HostTcpStream, NetReadStatus, ShutdownHow, TcpStream,
};
use crate::engine::wasm::host::util;

impl HostTcpStream for HostState {
    fn read(&mut self, self_: Resource<TcpStream>) -> Result<NetReadStatus, ErrorCode> {
        let stream = net_stream(&self.resource_table, self_.rep())?;
        let rt = self.runtime_handle.clone();
        let sem = self.blocking_semaphore.clone();
        let tok = self.cancel_token.clone();
        let status = util::bounded_block_on_cancellable(&rt, &sem, &tok, async {
            match stream {
                NetStream::Unix(arc) => {
                    let mut s = arc.lock().await;
                    read_frame(&mut *s).await
                },
                NetStream::Tcp(slot) => {
                    let mut s = slot.stream.lock().await;
                    read_frame(&mut *s).await
                },
            }
        });
        let result: Result<NetReadStatus, ErrorCode> = match status {
            Some(Ok(st)) => Ok(st),
            Some(Err(e)) => Err(ErrorCode::Unknown(e)),
            // Cancellation is `Closed`, NOT `Pending`. Returning
            // Pending here would let a cancelled capsule's run loop
            // call read in a tight loop with no backpressure — the
            // sync cancel check inside `bounded_block_on_cancellable`
            // fires before any I/O, so each call returns instantly.
            // Closed terminates the read loop cleanly.
            None => Ok(NetReadStatus::Closed),
        };
        // ENFORCEMENT side of the per-connection identity registry
        // (issue #45/#852): when this framed read pulls a client frame off a
        // kernel-bound connection, record that connection's verified principal
        // AND the device key_id that authenticated it, so the uplink's
        // subsequent `publish-as` stamps THAT principal in place of the
        // capsule-supplied name (the self-stamp fix) and THAT device's key_id
        // so the kernel cap-gate can apply the device's scope. A non-data read
        // (closed / pending) clears BOTH in lockstep, so a stale principal or
        // device id can never leak onto a later forward. Gated on the uplink
        // capability: only the uplink forwards client frames, and only its
        // accept path ever binds an entry, so a non-uplink read stays inert
        // and skips the registry lookup.
        if self.has_uplink_capability {
            let bound = match &result {
                Ok(NetReadStatus::Data(_)) => self
                    .connection_principals
                    .get(&self_.rep())
                    .map(|entry| entry.clone()),
                _ => None,
            };
            match bound {
                Some(identity) => {
                    self.ingress_principal = Some(identity.principal);
                    self.ingress_device_key_id = identity.device_key_id;
                    // A data frame off a kernel-BOUND (handshake-verified)
                    // connection is the positive local-operator signal: stamp
                    // the transport origin so a `publish-as` forward carries it
                    // to the egress site. An UNBOUND connection never reaches
                    // this arm (it has no ConnectionIdentity → `bound` is None),
                    // so it stays `System` (fail-closed, non-local) — parallel
                    // to the `anonymous` principal an unbound forward earns.
                    self.ingress_origin = Some(astrid_events::ipc::MessageOrigin::LocalSocket);
                },
                None => {
                    self.ingress_principal = None;
                    self.ingress_device_key_id = None;
                    // Cleared in LOCKSTEP so a stale local origin can never leak
                    // onto a later forward off a closed/pending/unbound read.
                    self.ingress_origin = None;
                },
            }
        }
        let bytes = match &result {
            Ok(NetReadStatus::Data(d)) => d.len() as u64,
            _ => 0,
        };
        audit_net(self, "astrid:net/host.tcp-stream.read", bytes, &result);
        result
    }

    fn write(&mut self, self_: Resource<TcpStream>, data: Vec<u8>) -> Result<(), ErrorCode> {
        let bytes = data.len() as u64;
        let stream = net_stream(&self.resource_table, self_.rep())?;
        let rt = self.runtime_handle.clone();
        let sem = self.blocking_semaphore.clone();
        let tok = self.cancel_token.clone();
        let result = util::bounded_block_on_cancellable(&rt, &sem, &tok, async {
            match stream {
                NetStream::Unix(arc) => {
                    let mut s = arc.lock().await;
                    write_frame(&mut *s, &data).await
                },
                NetStream::Tcp(slot) => {
                    let mut s = slot.stream.lock().await;
                    write_frame(&mut *s, &data).await
                },
            }
        });
        let result = match result {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => {
                // Surface the failure to the guest. The legacy
                // implementation silently swallowed peer-disconnect
                // errors here on the theory "the capsule will see it
                // on the next read" — but the WIT contract for
                // `write` is fallible, and capsules using it for
                // request-response semantics need to know writes
                // failed.
                Err(map_write_frame_err(&e))
            },
            None => Err(ErrorCode::Closed),
        };
        audit_net(self, "astrid:net/host.tcp-stream.write", bytes, &result);
        result
    }

    fn read_bytes(
        &mut self,
        self_: Resource<TcpStream>,
        max_bytes: u32,
    ) -> Result<Vec<u8>, ErrorCode> {
        let stream = net_stream(&self.resource_table, self_.rep())?;
        let rt = self.runtime_handle.clone();
        let sem = self.blocking_semaphore.clone();
        let tok = self.cancel_token.clone();
        let max = (max_bytes as usize).min(MAX_BYTES_PER_CALL);
        let result = util::bounded_block_on_cancellable(&rt, &sem, &tok, async {
            match stream {
                NetStream::Unix(arc) => {
                    let mut s = arc.lock().await;
                    read_bytes_inner(&mut *s, max, None).await
                },
                NetStream::Tcp(slot) => {
                    let timeout = slot.read_timeout;
                    let mut s = slot.stream.lock().await;
                    read_bytes_inner(&mut *s, max, timeout).await
                },
            }
        });
        let result = match result {
            Some(Ok(v)) => Ok(v),
            Some(Err(e)) if e == "read would block" => Err(ErrorCode::WouldBlock),
            Some(Err(e)) => Err(ErrorCode::Unknown(e)),
            // Cancellation collapses to `Closed` rather than an empty
            // Vec, mirroring `read_frame` / `write_bytes` / `shutdown`.
            // An empty Vec is the conventional "clean EOF" signal in
            // byte-stream reads; returning that on a forced unload
            // would silently look like the peer closed gracefully and
            // cause capsules that finalize on EOF (write trailers,
            // send last-message IPC) to run those finalizers under a
            // tear-down. Closed distinguishes the two.
            None => Err(ErrorCode::Closed),
        };
        let bytes = result.as_ref().map(|v| v.len() as u64).unwrap_or(0);
        audit_net(
            self,
            "astrid:net/host.tcp-stream.read-bytes",
            bytes,
            &result,
        );
        result
    }

    fn write_bytes(&mut self, self_: Resource<TcpStream>, data: Vec<u8>) -> Result<u32, ErrorCode> {
        let stream = net_stream(&self.resource_table, self_.rep())?;
        let rt = self.runtime_handle.clone();
        let sem = self.blocking_semaphore.clone();
        let tok = self.cancel_token.clone();
        let result = util::bounded_block_on_cancellable(&rt, &sem, &tok, async {
            match stream {
                NetStream::Unix(arc) => {
                    let mut s = arc.lock().await;
                    write_bytes_inner(&mut *s, &data, None).await
                },
                NetStream::Tcp(slot) => {
                    let timeout = slot.write_timeout;
                    let mut s = slot.stream.lock().await;
                    write_bytes_inner(&mut *s, &data, timeout).await
                },
            }
        });
        let result = match result {
            Some(Ok(n)) => Ok(n),
            Some(Err(e)) if e == "write would block" => Err(ErrorCode::WouldBlock),
            Some(Err(e)) => Err(ErrorCode::Unknown(e)),
            None => Err(ErrorCode::Closed),
        };
        let bytes = result.as_ref().copied().unwrap_or(0) as u64;
        audit_net(
            self,
            "astrid:net/host.tcp-stream.write-bytes",
            bytes,
            &result,
        );
        result
    }

    fn peek(&mut self, self_: Resource<TcpStream>, max_bytes: u32) -> Result<Vec<u8>, ErrorCode> {
        let stream = net_stream(&self.resource_table, self_.rep())?;
        let rt = self.runtime_handle.clone();
        let sem = self.blocking_semaphore.clone();
        let tok = self.cancel_token.clone();
        let max = (max_bytes as usize).min(MAX_BYTES_PER_CALL);
        let result: Result<Vec<u8>, ErrorCode> = match stream {
            NetStream::Tcp(slot) => {
                let timeout = slot.read_timeout;
                let opt = util::bounded_block_on_cancellable(&rt, &sem, &tok, async move {
                    let s = slot.stream.lock().await;
                    let mut buf = vec![0u8; max];
                    let fut = s.peek(&mut buf);
                    let n = match timeout {
                        Some(d) => match tokio::time::timeout(d, fut).await {
                            Ok(Ok(n)) => n,
                            Ok(Err(e)) => return Err(map_io_err(e)),
                            Err(_) => return Err(ErrorCode::WouldBlock),
                        },
                        None => fut.await.map_err(map_io_err)?,
                    };
                    buf.truncate(n);
                    Ok(buf)
                });
                // Same reasoning as `read_bytes`: an empty Vec is "no
                // data peeked yet, peer still connected," which is
                // indistinguishable from a clean cancel. Surface Closed
                // on cancellation so capsules can distinguish.
                opt.unwrap_or(Err(ErrorCode::Closed))
            },
            NetStream::Unix(_) => Err(ErrorCode::NotTcp),
        };
        let bytes = result.as_ref().map(|v| v.len() as u64).unwrap_or(0);
        audit_net(self, "astrid:net/host.tcp-stream.peek", bytes, &result);
        result
    }

    fn shutdown(&mut self, self_: Resource<TcpStream>, how: ShutdownHow) -> Result<(), ErrorCode> {
        let stream = net_stream(&self.resource_table, self_.rep())?;
        let rt = self.runtime_handle.clone();
        let sem = self.blocking_semaphore.clone();
        let tok = self.cancel_token.clone();
        let std_how = match how {
            ShutdownHow::Receive => std::net::Shutdown::Read,
            ShutdownHow::Send => std::net::Shutdown::Write,
            ShutdownHow::Both => std::net::Shutdown::Both,
        };
        let result = util::bounded_block_on_cancellable(&rt, &sem, &tok, async move {
            match stream {
                NetStream::Tcp(slot) => {
                    let s = slot.stream.lock().await;
                    let sock_ref = socket2::SockRef::from(&*s);
                    sock_ref.shutdown(std_how).map_err(map_io_err)
                },
                NetStream::Unix(_) => Err(ErrorCode::NotTcp),
            }
        });
        result.unwrap_or(Err(ErrorCode::Closed))
    }

    fn peer_addr(&mut self, self_: Resource<TcpStream>) -> Result<String, ErrorCode> {
        with_tcp_stream(self, self_.rep(), |s| {
            s.peer_addr().map(|a| a.to_string()).map_err(map_io_err)
        })
    }

    fn local_addr(&mut self, self_: Resource<TcpStream>) -> Result<String, ErrorCode> {
        with_tcp_stream(self, self_.rep(), |s| {
            s.local_addr().map(|a| a.to_string()).map_err(map_io_err)
        })
    }

    fn set_nodelay(&mut self, self_: Resource<TcpStream>, nodelay: bool) -> Result<(), ErrorCode> {
        with_tcp_stream(self, self_.rep(), |s| {
            s.set_nodelay(nodelay).map_err(map_io_err)
        })
    }

    fn nodelay(&mut self, self_: Resource<TcpStream>) -> Result<bool, ErrorCode> {
        with_tcp_stream(self, self_.rep(), |s| s.nodelay().map_err(map_io_err))
    }

    fn set_read_timeout(
        &mut self,
        self_: Resource<TcpStream>,
        timeout_ms: Option<u64>,
    ) -> Result<(), ErrorCode> {
        with_tcp_slot_mut(&mut self.resource_table, self_.rep(), |slot| {
            slot.read_timeout = timeout_ms.map(Duration::from_millis);
        })
    }

    fn read_timeout(&mut self, self_: Resource<TcpStream>) -> Result<Option<u64>, ErrorCode> {
        let s = net_stream(&self.resource_table, self_.rep())?;
        match s {
            NetStream::Tcp(slot) => Ok(slot
                .read_timeout
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))),
            NetStream::Unix(_) => Err(ErrorCode::NotTcp),
        }
    }

    fn set_write_timeout(
        &mut self,
        self_: Resource<TcpStream>,
        timeout_ms: Option<u64>,
    ) -> Result<(), ErrorCode> {
        with_tcp_slot_mut(&mut self.resource_table, self_.rep(), |slot| {
            slot.write_timeout = timeout_ms.map(Duration::from_millis);
        })
    }

    fn write_timeout(&mut self, self_: Resource<TcpStream>) -> Result<Option<u64>, ErrorCode> {
        let s = net_stream(&self.resource_table, self_.rep())?;
        match s {
            NetStream::Tcp(slot) => Ok(slot
                .write_timeout
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))),
            NetStream::Unix(_) => Err(ErrorCode::NotTcp),
        }
    }

    fn set_hop_limit(&mut self, self_: Resource<TcpStream>, hops: u32) -> Result<(), ErrorCode> {
        with_tcp_stream(self, self_.rep(), |s| s.set_ttl(hops).map_err(map_io_err))
    }

    fn hop_limit(&mut self, self_: Resource<TcpStream>) -> Result<u32, ErrorCode> {
        with_tcp_stream(self, self_.rep(), |s| s.ttl().map_err(map_io_err))
    }

    fn set_keepalive(
        &mut self,
        self_: Resource<TcpStream>,
        keepalive_secs: Option<u64>,
    ) -> Result<(), ErrorCode> {
        with_tcp_stream(self, self_.rep(), |s| {
            let sock = socket2::SockRef::from(s);
            match keepalive_secs {
                Some(secs) => {
                    let kal = socket2::TcpKeepalive::new()
                        .with_time(Duration::from_secs(secs.max(1)))
                        .with_interval(Duration::from_secs(secs.max(1)));
                    sock.set_tcp_keepalive(&kal).map_err(map_io_err)
                },
                None => sock.set_keepalive(false).map_err(map_io_err),
            }
        })
    }

    fn keepalive(&mut self, self_: Resource<TcpStream>) -> Result<Option<u64>, ErrorCode> {
        with_tcp_stream(self, self_.rep(), |s| {
            let sock = socket2::SockRef::from(s);
            match sock.keepalive() {
                Ok(true) => Ok(Some(0)),
                Ok(false) => Ok(None),
                Err(e) => Err(map_io_err(e)),
            }
        })
    }

    fn set_linger(
        &mut self,
        self_: Resource<TcpStream>,
        linger_ms: Option<u64>,
    ) -> Result<(), ErrorCode> {
        with_tcp_stream(self, self_.rep(), |s| {
            let sock = socket2::SockRef::from(s);
            sock.set_linger(linger_ms.map(Duration::from_millis))
                .map_err(map_io_err)
        })
    }

    fn linger(&mut self, self_: Resource<TcpStream>) -> Result<Option<u64>, ErrorCode> {
        with_tcp_stream(self, self_.rep(), |s| {
            let sock = socket2::SockRef::from(s);
            sock.linger()
                .map(|d| d.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)))
                .map_err(map_io_err)
        })
    }

    fn set_reuseaddr(&mut self, self_: Resource<TcpStream>, reuse: bool) -> Result<(), ErrorCode> {
        with_tcp_stream(self, self_.rep(), |s| {
            let sock = socket2::SockRef::from(s);
            sock.set_reuse_address(reuse).map_err(map_io_err)
        })
    }

    fn reuseaddr(&mut self, self_: Resource<TcpStream>) -> Result<bool, ErrorCode> {
        with_tcp_stream(self, self_.rep(), |s| {
            let sock = socket2::SockRef::from(s);
            sock.reuse_address().map_err(map_io_err)
        })
    }

    fn subscribe_readable(&mut self, _self_: Resource<TcpStream>) -> Resource<DynPollable> {
        // Real pollable wiring (tokio AsyncRead readiness over the
        // NetStream) lands with the stream-half adapter commit.
        // Always-ready sentinel until then; guests poll then call
        // read-bytes which handles real readability internally.
        super::super::stubs::always_ready_pollable(&mut self.resource_table)
    }

    fn read_stream(&mut self, _self_: Resource<TcpStream>) -> Resource<InputStream> {
        // Real adapter (wasmtime-wasi-io InputStream impl over our
        // NetStream) lands with the stream-half commit. Closed-on-read
        // sentinel until then — capsules use read / read-bytes
        // directly.
        super::super::stubs::closed_input_stream(&mut self.resource_table)
    }

    fn write_stream(&mut self, _self_: Resource<TcpStream>) -> Resource<OutputStream> {
        // Same story as read_stream — closed-on-write sentinel.
        super::super::stubs::closed_output_stream(&mut self.resource_table)
    }

    fn drop(&mut self, rep: Resource<TcpStream>) -> wasmtime::Result<()> {
        let table_rep = rep.rep();
        if self
            .resource_table
            .delete::<NetStream>(Resource::new_own(table_rep))
            .is_ok()
        {
            self.net_stream_count = self.net_stream_count.saturating_sub(1);
        }
        // Drop any verified per-connection principal binding (issue #45/#852)
        // so the registry does not leak entries for closed connections. A
        // no-op for outbound TCP streams (never bound) and for unauthenticated
        // unix connections.
        self.unbind_connection_principal(table_rep);
        // Emit `client.v1.disconnect` for the kernel connection tracker if this
        // rep was an INBOUND uplink connection, stamped with the SAME
        // host-verified principal its `client.v1.connect` carried, and drop the
        // lifecycle entry. A no-op for outbound TCP streams and non-net
        // resources (never registered), so a capsule-dialed socket dropping
        // never moves the connection counter. Pairs connect/disconnect on one
        // identity → the per-principal count balances (connection-tracker leak
        // fix).
        super::client_lifecycle::emit_client_disconnect(self, table_rep);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Regression tests for the PR #752 `write` fix.
    //!
    //! The legacy implementation silently swallowed peer-disconnect
    //! errors as `Ok(())` on the theory "the capsule will see it on
    //! the next read". Capsules using TcpStream for request/response
    //! could not detect a half-closed connection. We now surface
    //! `ConnectionReset` for any peer-disconnect IO kind and
    //! `Unknown` for everything else.
    use super::*;
    use std::io;

    #[test]
    fn write_frame_err_brokenpipe_maps_to_connection_reset() {
        let e = io::Error::new(io::ErrorKind::BrokenPipe, "peer gone");
        assert!(matches!(
            map_write_frame_err(&e),
            ErrorCode::ConnectionReset
        ));
    }

    #[test]
    fn write_frame_err_connection_reset_maps_to_connection_reset() {
        let e = io::Error::new(io::ErrorKind::ConnectionReset, "rst");
        assert!(matches!(
            map_write_frame_err(&e),
            ErrorCode::ConnectionReset
        ));
    }

    #[test]
    fn write_frame_err_connection_aborted_maps_to_connection_reset() {
        let e = io::Error::new(io::ErrorKind::ConnectionAborted, "abort");
        assert!(matches!(
            map_write_frame_err(&e),
            ErrorCode::ConnectionReset
        ));
    }

    #[test]
    fn write_frame_err_unexpected_eof_maps_to_connection_reset() {
        let e = io::Error::new(io::ErrorKind::UnexpectedEof, "eof");
        assert!(matches!(
            map_write_frame_err(&e),
            ErrorCode::ConnectionReset
        ));
    }

    #[test]
    fn write_frame_err_other_maps_to_unknown() {
        let e = io::Error::other("weird");
        assert!(matches!(map_write_frame_err(&e), ErrorCode::Unknown(_)));
    }

    #[test]
    fn write_frame_err_timed_out_maps_to_unknown() {
        // Timeouts are NOT peer disconnect — capsule can retry.
        let e = io::Error::new(io::ErrorKind::TimedOut, "slow");
        assert!(matches!(map_write_frame_err(&e), ErrorCode::Unknown(_)));
    }

    /// ENFORCEMENT wiring for the per-connection principal registry
    /// (issue #45/#852): a framed read off a kernel-bound connection must
    /// record that connection's verified principal in
    /// [`HostState::ingress_principal`], and a non-data read must clear it.
    ///
    /// This guards the link DIRECTLY rather than via a manually-set field: the
    /// `publish-as` override in `host/ipc.rs` consumes `ingress_principal`, so
    /// if this read never populated it the override would silently fall back to
    /// the capsule-supplied (forgeable) name and the self-stamp hole would
    /// reopen — with `publish-as`-level tests still green. A socketpair stands
    /// in for an accepted client connection; it binds no filesystem path, so it
    /// works under the sandbox (unlike a named Unix socket).
    #[tokio::test(flavor = "multi_thread")]
    async fn framed_read_records_then_clears_verified_ingress_principal() {
        use tokio::io::AsyncWriteExt;

        use crate::engine::wasm::host_state::NetStream;
        use crate::engine::wasm::test_fixtures::minimal_host_state;

        let rt = tokio::runtime::Handle::current();
        let mut state = minimal_host_state(rt);
        // Only the uplink records ingress principals (and only its accept path
        // ever binds an entry).
        state.has_uplink_capability = true;

        let (host_end, mut peer) = tokio::net::UnixStream::pair().expect("socketpair");
        let net = NetStream::Unix(std::sync::Arc::new(tokio::sync::Mutex::new(host_end)));
        let rep = state.resource_table.push(net).expect("push stream").rep();

        // The handshake bound this connection to `claude` (Path 2 crypto, or a
        // Path 1 daemon spawn-binding), with the matched device key_id so the
        // cap-gate can scope it.
        let claude = astrid_core::PrincipalId::new("claude").unwrap();
        state.bind_connection_principal(rep, claude.clone(), Some("dev-abc123".to_string()));

        // Peer sends one length-prefixed frame (4-byte BE length + payload).
        let payload = br#"{"topic":"client.v1.connect","payload":{}}"#;
        peer.write_all(&(payload.len() as u32).to_be_bytes())
            .await
            .unwrap();
        peer.write_all(payload).await.unwrap();
        peer.flush().await.unwrap();

        // A data read records the connection's verified principal AND the
        // device key_id that authenticated it.
        let status = HostTcpStream::read(&mut state, Resource::new_borrow(rep))
            .expect("read should succeed");
        assert!(
            matches!(status, NetReadStatus::Data(_)),
            "expected a data frame, got {status:?}"
        );
        assert_eq!(
            state.ingress_principal,
            Some(claude),
            "a data read on a kernel-bound connection must record its verified principal"
        );
        assert_eq!(
            state.ingress_device_key_id.as_deref(),
            Some("dev-abc123"),
            "a data read must record the connection's authenticating device key_id"
        );
        assert_eq!(
            state.ingress_origin,
            Some(astrid_events::ipc::MessageOrigin::LocalSocket),
            "a data read on a kernel-BOUND connection must stamp LocalSocket origin"
        );

        // A subsequent non-data read (no more frames → pending) clears BOTH, so
        // a stale principal or device id can never leak onto a later forward.
        let status = HostTcpStream::read(&mut state, Resource::new_borrow(rep))
            .expect("read should succeed");
        assert!(
            matches!(status, NetReadStatus::Pending),
            "expected pending, got {status:?}"
        );
        assert_eq!(
            state.ingress_principal, None,
            "a non-data read must clear the in-flight ingress principal"
        );
        assert_eq!(
            state.ingress_device_key_id, None,
            "a non-data read must clear the in-flight ingress device key_id"
        );
        assert_eq!(
            state.ingress_origin, None,
            "a non-data read must clear the in-flight LocalSocket origin so a \
             stale local origin can never leak onto a later forward"
        );
    }

    /// A non-uplink capsule never records an ingress principal even when it
    /// reads a (hypothetically) bound stream — the gate keeps the registry
    /// lookup off every non-uplink framed read and prevents any cross-capsule
    /// principal bleed through `ingress_principal`.
    #[tokio::test(flavor = "multi_thread")]
    async fn framed_read_is_inert_without_uplink_capability() {
        use tokio::io::AsyncWriteExt;

        use crate::engine::wasm::host_state::NetStream;
        use crate::engine::wasm::test_fixtures::minimal_host_state;

        let rt = tokio::runtime::Handle::current();
        let mut state = minimal_host_state(rt);
        // No uplink capability — the default.
        assert!(!state.has_uplink_capability);

        let (host_end, mut peer) = tokio::net::UnixStream::pair().expect("socketpair");
        let net = NetStream::Unix(std::sync::Arc::new(tokio::sync::Mutex::new(host_end)));
        let rep = state.resource_table.push(net).expect("push stream").rep();
        state.bind_connection_principal(
            rep,
            astrid_core::PrincipalId::new("claude").unwrap(),
            Some("dev-abc123".to_string()),
        );

        let payload = br#"{"topic":"x","payload":{}}"#;
        peer.write_all(&(payload.len() as u32).to_be_bytes())
            .await
            .unwrap();
        peer.write_all(payload).await.unwrap();
        peer.flush().await.unwrap();

        let status = HostTcpStream::read(&mut state, Resource::new_borrow(rep))
            .expect("read should succeed");
        assert!(matches!(status, NetReadStatus::Data(_)));
        assert_eq!(
            state.ingress_principal, None,
            "a non-uplink read must not populate the ingress principal"
        );
        assert_eq!(
            state.ingress_device_key_id, None,
            "a non-uplink read must not populate the ingress device key_id"
        );
        assert_eq!(
            state.ingress_origin, None,
            "a non-uplink read must not stamp a transport origin"
        );
    }

    /// A framed read off an UNBOUND connection (no `ConnectionIdentity`) must
    /// NOT earn `LocalSocket` — it stays `None` (= `System`, fail-closed,
    /// non-local), parallel to the `anonymous` principal an unbound forward
    /// earns. This is the security floor that stops a peer-cred-trusted-but-
    /// unauthenticated local connection from claiming local-operator privilege.
    #[tokio::test(flavor = "multi_thread")]
    async fn framed_read_unbound_connection_does_not_earn_local_origin() {
        use tokio::io::AsyncWriteExt;

        use crate::engine::wasm::host_state::NetStream;
        use crate::engine::wasm::test_fixtures::minimal_host_state;

        let rt = tokio::runtime::Handle::current();
        let mut state = minimal_host_state(rt);
        // Uplink capability is set (so the registry lookup runs), but the
        // connection is never bound — no `bind_connection_principal` call.
        state.has_uplink_capability = true;

        let (host_end, mut peer) = tokio::net::UnixStream::pair().expect("socketpair");
        let net = NetStream::Unix(std::sync::Arc::new(tokio::sync::Mutex::new(host_end)));
        let rep = state.resource_table.push(net).expect("push stream").rep();
        // Deliberately NO bind: this is an unbound (unauthenticated) connection.

        let payload = br#"{"topic":"x","payload":{}}"#;
        peer.write_all(&(payload.len() as u32).to_be_bytes())
            .await
            .unwrap();
        peer.write_all(payload).await.unwrap();
        peer.flush().await.unwrap();

        let status = HostTcpStream::read(&mut state, Resource::new_borrow(rep))
            .expect("read should succeed");
        assert!(matches!(status, NetReadStatus::Data(_)));
        assert_eq!(
            state.ingress_principal, None,
            "an unbound connection stamps no verified principal"
        );
        assert_eq!(
            state.ingress_origin, None,
            "an unbound connection must NOT earn LocalSocket — it stays System \
             (fail-closed, non-local)"
        );
    }
}

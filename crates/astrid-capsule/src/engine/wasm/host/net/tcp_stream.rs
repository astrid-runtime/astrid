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

/// Effective deadline for a host framed / byte-stream write.
///
/// An unbounded `write_all` awaits forever when a connected client stops
/// draining its socket and the kernel send buffer fills. Because the
/// capsule-cli guest services every uplink from a single run loop, one such
/// stalled write freezes accepts, binds, and forwards for the whole uplink
/// surface while the daemon otherwise stays healthy (issue #1144). Bounding
/// the write turns a non-draining peer into a prompt write error, which the
/// guest proxy already handles by evicting the client.
///
/// Honours an explicit `write_timeout` on a Tcp slot when one is set;
/// otherwise falls back to a ceiling scaled by payload size, mirroring the
/// `read_frame` payload-read bound (`5000 + len/1024` ms). The Unix arm has no
/// per-slot timeout field, so it always uses the default ceiling.
fn write_deadline(stream: &NetStream, data_len: usize) -> Duration {
    let default_ceiling = Duration::from_millis(5000 + (data_len as u64 / 1024));
    match stream {
        NetStream::Tcp(slot) => slot.write_timeout.unwrap_or(default_ceiling),
        NetStream::Unix(_) => default_ceiling,
    }
}
use super::{
    HostState, NetStream, audit_net, map_io_err, net_stream, record_net_stream_metrics,
    with_tcp_slot_mut, with_tcp_stream,
};
use crate::engine::wasm::bindings::astrid::io::streams::{InputStream, OutputStream};
use crate::engine::wasm::bindings::astrid::net::host::{
    ErrorCode, HostTcpStream, NetReadStatus, ShutdownHow, TcpStream,
};
use crate::engine::wasm::host::util;

impl HostTcpStream for HostState {
    fn read(&mut self, self_: Resource<TcpStream>) -> Result<NetReadStatus, ErrorCode> {
        let rep = self_.rep();
        let stream = net_stream(&self.resource_table, rep)?;
        let rt = self.runtime_handle.clone();
        let sem = self.blocking_semaphore.clone();
        let tok = self.effective_cancel_token();
        let frame_state = self.net_frame_states.entry(rep).or_default();
        let status = util::bounded_block_on_cancellable(&rt, &sem, &tok, async {
            match stream {
                NetStream::Unix(arc) => {
                    let mut s = arc.lock().await;
                    read_frame(&mut *s, frame_state).await
                },
                NetStream::Tcp(slot) => {
                    let mut s = slot.stream.lock().await;
                    read_frame(&mut *s, frame_state).await
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
                    // Record which capsule earned the LocalSocket stamp. The
                    // downstream egress-consent gate trusts LocalSocket as "the
                    // local operator"; that trust holds ONLY while this stamp is
                    // reachable solely from the uplink capsule (the
                    // `has_uplink_capability` gate above). Surfacing the
                    // capsule_id here makes an unexpected stamper — a non-uplink
                    // capsule that somehow earned the capability — observable in
                    // the audit trail rather than silent. Emit before the move
                    // below so the verified principal is still borrowable.
                    tracing::debug!(
                        target: "astrid.audit.net",
                        capsule_id = %self.capsule_id.as_str(),
                        principal = %identity.principal,
                        "tcp-stream.read stamped LocalSocket origin (uplink-gated)"
                    );
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
        let tok = self.effective_cancel_token();
        // Bound the whole write — lock acquisition included, since a stuck
        // write holds the per-stream mutex and a second write would otherwise
        // block unbounded on the lock itself — so a peer that stops draining
        // its socket becomes a write error within a deadline instead of
        // freezing the single-threaded proxy run loop forever (issue #1144).
        // The cancel token still races ahead of the deadline so a capsule
        // teardown aborts the write promptly.
        let deadline = write_deadline(&stream, data.len());
        let result = util::bounded_block_on_cancellable(&rt, &sem, &tok, async {
            let write_fut = async {
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
            };
            match tokio::time::timeout(deadline, write_fut).await {
                // Surface any write failure to the guest. The legacy
                // implementation silently swallowed peer-disconnect errors
                // here on the theory "the capsule will see it on the next
                // read" — but the WIT contract for `write` is fallible, and
                // capsules using it for request-response semantics need to
                // know writes failed.
                Ok(res) => res.map_err(|e| map_write_frame_err(&e)),
                Err(_elapsed) => Err(ErrorCode::Unknown(
                    "write timed out: peer not draining".to_string(),
                )),
            }
        });
        let result = match result {
            Some(inner) => inner,
            // Cancellation (capsule teardown) collapses to `Closed`.
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
        let tok = self.effective_cancel_token();
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
        let tok = self.effective_cancel_token();
        // Same unbounded-write hazard as framed `write` (issue #1144): bound
        // the whole call — lock acquisition included — so a non-draining peer
        // yields `WouldBlock` within a deadline rather than pinning the host
        // worker. The deadline subsumes the per-call timeout previously
        // applied only inside `write_bytes_inner` (Tcp arm only, and only
        // around the write, not the lock), so pass `None` there and let the
        // outer bound own the duration for both transport arms.
        let deadline = write_deadline(&stream, data.len());
        let result = util::bounded_block_on_cancellable(&rt, &sem, &tok, async {
            let write_fut = async {
                match stream {
                    NetStream::Unix(arc) => {
                        let mut s = arc.lock().await;
                        write_bytes_inner(&mut *s, &data, None).await
                    },
                    NetStream::Tcp(slot) => {
                        let mut s = slot.stream.lock().await;
                        write_bytes_inner(&mut *s, &data, None).await
                    },
                }
            };
            match tokio::time::timeout(deadline, write_fut).await {
                Ok(res) => res,
                // A byte-stream write that makes no progress before the
                // deadline is a `WouldBlock` — matching the retry semantics
                // `write_bytes_inner` already surfaces on its own timeout — so
                // the capsule can back off rather than treat it as fatal.
                Err(_elapsed) => Err("write would block".to_string()),
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
        let tok = self.effective_cancel_token();
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
        let tok = self.effective_cancel_token();
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

    fn subscribe_readable(&mut self, self_: Resource<TcpStream>) -> Resource<DynPollable> {
        wasmtime_wasi::p2::subscribe(
            &mut self.resource_table,
            Resource::<NetStream>::new_borrow(self_.rep()),
        )
        .unwrap_or_else(|_| Resource::new_own(0))
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
            self.net_stream_leases.remove(&table_rep);
            self.net_frame_states.remove(&table_rep);
            record_net_stream_metrics(self);
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
#[path = "tcp_stream_tests.rs"]
mod tests;

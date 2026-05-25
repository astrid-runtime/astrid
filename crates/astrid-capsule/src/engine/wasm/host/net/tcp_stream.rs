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
        let sem = self.host_semaphore.clone();
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
        let sem = self.host_semaphore.clone();
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
        let sem = self.host_semaphore.clone();
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
        let sem = self.host_semaphore.clone();
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
        let sem = self.host_semaphore.clone();
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
        let sem = self.host_semaphore.clone();
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
        if self
            .resource_table
            .delete::<NetStream>(Resource::new_own(rep.rep()))
            .is_ok()
        {
            self.net_stream_count = self.net_stream_count.saturating_sub(1);
        }
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
}

//! `HostTcpStream` impl — byte-oriented operations on Unix-domain and
//! outbound TCP streams. Stream halves (`read-stream` / `write-stream`)
//! land in a follow-up commit alongside the wasmtime-wasi-io
//! `InputStream`/`OutputStream` adapter for our `NetStream` type.

use std::time::Duration;

use wasmtime::component::Resource;
use wasmtime_wasi::p2::DynPollable;

use super::stream::{
    MAX_BYTES_PER_CALL, read_bytes_inner, read_frame, write_bytes_inner, write_frame,
};
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
        match status {
            Some(Ok(st)) => Ok(st),
            Some(Err(e)) => Err(ErrorCode::Unknown(e)),
            None => Ok(NetReadStatus::Pending),
        }
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
            Some(Err(_)) => {
                // Peer disconnect — non-fatal; capsule discovers on next read.
                Ok(())
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
            None => Ok(Vec::new()),
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
                            Ok(Err(e)) => return Err(map_io_err(e)),
                            Err(_) => return Err(ErrorCode::WouldBlock),
                        },
                        None => fut.await.map_err(map_io_err)?,
                    };
                    buf.truncate(n);
                    Ok(buf)
                });
                result.unwrap_or(Ok(Vec::new()))
            },
            NetStream::Unix(_) => Err(ErrorCode::NotTcp),
        }
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
        // Pollable wiring for tcp-stream readiness lands with the stream-
        // halves commit alongside read-stream / write-stream.
        todo!("TcpStream.subscribe_readable: pollable wiring pending")
    }

    fn read_stream(&mut self, _self_: Resource<TcpStream>) -> Resource<InputStream> {
        // Wrap the underlying tokio TcpStream / UnixStream as a
        // wasmtime-wasi-io InputStream. Non-trivial — requires impl of
        // the InputStream trait (read + Pollable::ready) on a custom
        // adapter type. Tracked for a dedicated follow-up commit so the
        // splice path lands with proper readiness wiring.
        todo!("TcpStream.read_stream: stream-half adapter pending")
    }

    fn write_stream(&mut self, _self_: Resource<TcpStream>) -> Resource<OutputStream> {
        todo!("TcpStream.write_stream: stream-half adapter pending")
    }

    fn drop(&mut self, rep: Resource<TcpStream>) -> wasmtime::Result<()> {
        let _ = self
            .resource_table
            .delete::<NetStream>(Resource::new_own(rep.rep()));
        Ok(())
    }
}

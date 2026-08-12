//! `HostTcpListener` impl — inbound TCP server hosting.
//!
//! The listener is created and capability-gated in
//! [`super::Host::bind_tcp`]; the `Resource<TcpListener>` is a token over a
//! [`TcpListenerSlot`] holding the live `tokio` listener. `accept` /
//! `poll_accept` produce `TcpStream` resources that reuse the SAME
//! [`NetStream::Tcp`] representation as outbound `connect-tcp` streams, so
//! every existing read / write / peek / timeout host fn works on accepted
//! connections with no extra wiring.

use std::sync::Arc;

use async_trait::async_trait;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::{DynPollable, Pollable, subscribe};

use super::{HostState, MAX_ACTIVE_STREAMS, TcpListenerSlot, audit_net_accept, map_io_err};
use crate::engine::wasm::bindings::astrid::net::host::{
    ErrorCode, HostTcpListener, TcpListener, TcpStream,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::{NetStream, TcpStreamSlot};

type PendingTcpConnection =
    Arc<tokio::sync::Mutex<Option<(tokio::net::TcpStream, std::net::SocketAddr)>>>;
type TcpListenerParts = (Arc<tokio::net::TcpListener>, PendingTcpConnection);

#[async_trait]
impl Pollable for TcpListenerSlot {
    async fn ready(&mut self) {
        let mut pending = self.pending.lock().await;
        if pending.is_none() {
            tokio::select! {
                connection = self.listener.accept() => {
                    if let Ok(connection) = connection {
                        *pending = Some(connection);
                    }
                }
                () = self.cancel_token.cancelled() => {}
            }
        }
    }
}

impl HostState {
    /// Clone the `Arc<tokio::net::TcpListener>` out of the resource slot,
    /// releasing the table borrow before any blocking accept.
    fn tcp_listener_slot(&self, rep: u32) -> Result<TcpListenerParts, ErrorCode> {
        let slot = self
            .resource_table
            .get::<TcpListenerSlot>(&Resource::new_borrow(rep))
            .map_err(|_| ErrorCode::InvalidHandle)?;
        Ok((Arc::clone(&slot.listener), Arc::clone(&slot.pending)))
    }

    /// Register an accepted stream as a `NetStream::Tcp` resource, bumping the
    /// per-capsule active-stream counter. Shared by `accept` / `poll_accept`.
    fn register_accepted(
        &mut self,
        stream: tokio::net::TcpStream,
    ) -> Result<Resource<TcpStream>, ErrorCode> {
        if self.net_stream_count >= MAX_ACTIVE_STREAMS {
            drop(stream);
            return Err(ErrorCode::Quota);
        }
        let net_stream = NetStream::Tcp(TcpStreamSlot {
            stream: Arc::new(tokio::sync::Mutex::new(stream)),
            read_timeout: None,
            write_timeout: None,
        });
        let res = self
            .resource_table
            .push(net_stream)
            .map_err(|e| ErrorCode::Unknown(format!("resource table: {e}")))?;
        self.net_stream_count += 1;
        Ok(Resource::new_own(res.rep()))
    }
}

impl HostTcpListener for HostState {
    fn accept(&mut self, self_: Resource<TcpListener>) -> Result<Resource<TcpStream>, ErrorCode> {
        let (listener, pending) = self.tcp_listener_slot(self_.rep())?;
        if self.net_stream_count >= MAX_ACTIVE_STREAMS {
            return Err(ErrorCode::Quota);
        }
        // Mark cooperative progress so a bound accept-loop is not mistaken for
        // a no-yield spinner and epoch-trapped (parity with `ipc::recv`).
        self.recv_yielded = true;

        let rt = self.runtime_handle.clone();
        let sem = self.blocking_semaphore.clone();
        let tok = self.effective_cancel_token();
        let accepted = util::bounded_block_on_cancellable(&rt, &sem, &tok, async move {
            if let Some(connection) = pending.lock().await.take() {
                Ok(connection)
            } else {
                listener.accept().await
            }
        });
        let (stream, peer_addr) = match accepted {
            Some(Ok(pair)) => pair,
            Some(Err(e)) => return Err(map_io_err(e)),
            None => return Err(ErrorCode::Closed), // cancelled (capsule unload)
        };
        let local_addr = stream.local_addr().map_err(map_io_err)?.to_string();
        let peer_addr = peer_addr.to_string();
        let result = self.register_accepted(stream);
        audit_net_accept(self, &local_addr, &peer_addr, &result);
        result
    }

    fn poll_accept(
        &mut self,
        self_: Resource<TcpListener>,
        timeout_ms: u64,
    ) -> Result<Option<Resource<TcpStream>>, ErrorCode> {
        let (listener, pending) = self.tcp_listener_slot(self_.rep())?;
        if self.net_stream_count >= MAX_ACTIVE_STREAMS {
            return Err(ErrorCode::Quota);
        }
        self.recv_yielded = true;

        let rt = self.runtime_handle.clone();
        let sem = self.blocking_semaphore.clone();
        let tok = self.effective_cancel_token();
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let accepted = util::bounded_block_on_cancellable(&rt, &sem, &tok, async move {
            tokio::time::timeout(timeout, async move {
                if let Some(connection) = pending.lock().await.take() {
                    Ok(connection)
                } else {
                    listener.accept().await
                }
            })
            .await
        });
        match accepted {
            Some(Ok(Ok((stream, peer_addr)))) => {
                let local_addr = stream.local_addr().map_err(map_io_err)?.to_string();
                let peer_addr = peer_addr.to_string();
                let result = self.register_accepted(stream);
                audit_net_accept(self, &local_addr, &peer_addr, &result);
                result.map(Some)
            },
            Some(Ok(Err(e))) => Err(map_io_err(e)),
            Some(Err(_elapsed)) => Ok(None), // no connection within the window
            None => Err(ErrorCode::Closed),  // cancelled (capsule unload)
        }
    }

    fn local_addr(&mut self, self_: Resource<TcpListener>) -> Result<String, ErrorCode> {
        let (listener, _) = self.tcp_listener_slot(self_.rep())?;
        listener
            .local_addr()
            .map(|a| a.to_string())
            .map_err(map_io_err)
    }

    fn subscribe_readiness(&mut self, self_: Resource<TcpListener>) -> Resource<DynPollable> {
        // Borrow the listener slot so the pollable is a child resource: the
        // listener cannot be dropped while a readiness subscription is alive.
        let listener = Resource::<TcpListenerSlot>::new_borrow(self_.rep());
        subscribe(&mut self.resource_table, listener)
            .expect("component model supplied a valid TCP listener resource")
    }

    fn drop(&mut self, rep: Resource<TcpListener>) -> wasmtime::Result<()> {
        // Deleting the slot drops the Arc<tokio listener>, closing the socket
        // and releasing the shared per-capsule listener quota reservation.
        let _ = self
            .resource_table
            .delete::<TcpListenerSlot>(Resource::new_own(rep.rep()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test]
    async fn readiness_accepts_once_and_preserves_the_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(1));
        let mut slot = TcpListenerSlot {
            listener: Arc::new(listener),
            pending: Arc::new(tokio::sync::Mutex::new(None)),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            listener_count: Arc::clone(&count),
        };
        let client = tokio::spawn(tokio::net::TcpStream::connect(addr));

        Pollable::ready(&mut slot).await;

        let (stream, peer) = slot
            .pending
            .lock()
            .await
            .take()
            .expect("accepted connection");
        assert_eq!(stream.local_addr().unwrap(), addr);
        assert_eq!(stream.peer_addr().unwrap(), peer);
        client.await.unwrap().unwrap();
        drop(slot);
        assert_eq!(count.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn readiness_wakes_when_the_principal_is_cancelled() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let count = Arc::new(AtomicUsize::new(1));
        let mut slot = TcpListenerSlot {
            listener: Arc::new(listener),
            pending: Arc::new(tokio::sync::Mutex::new(None)),
            cancel_token: cancel.clone(),
            listener_count: Arc::clone(&count),
        };
        cancel.cancel();

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            Pollable::ready(&mut slot),
        )
        .await
        .expect("cancelled readiness must wake");

        assert!(slot.pending.lock().await.is_none());
        drop(slot);
        assert_eq!(count.load(Ordering::Acquire), 0);
    }
}

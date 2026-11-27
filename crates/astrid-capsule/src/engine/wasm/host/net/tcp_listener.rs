//! `HostTcpListener` impl — inbound TCP server hosting.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::{DynPollable, Pollable, subscribe};

use super::{
    HostState, MAX_ACTIVE_STREAMS, PendingTcpAccepted, PendingTcpConnection, TcpListenerSlot,
    audit_net_accept, map_io_err,
};
use crate::audit_sink::{HostAuditEvent, HostAuditOutcome, HostAuditSink};
use crate::engine::wasm::bindings::astrid::net::host::{
    ErrorCode, HostTcpListener, TcpListener, TcpStream,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::{NetStream, TcpStreamSlot};

type TcpListenerParts = (
    Arc<tokio::net::TcpListener>,
    Arc<PendingTcpConnection>,
    tokio_util::sync::CancellationToken,
);

/// Observe listener readability without consuming a connection. The actual
/// accept remains the single authority-bearing point for quota and audit.
struct TcpListenerReadiness {
    listener: std::sync::Weak<tokio::net::TcpListener>,
    pending: std::sync::Weak<PendingTcpConnection>,
    cancel_token: tokio_util::sync::CancellationToken,
    audit_sink: Option<Arc<dyn HostAuditSink>>,
    principal: astrid_core::principal::PrincipalId,
}

#[async_trait]
impl Pollable for TcpListenerReadiness {
    async fn ready(&mut self) {
        let (Some(listener), Some(pending)) = (self.listener.upgrade(), self.pending.upgrade())
        else {
            return;
        };
        // Holding this shared slot lock across accept serializes every watcher.
        // Losing a WASI poll race simply drops the future and lock; no quota
        // has been reserved and no connection has been consumed at that point.
        let mut slot = pending.connection.lock().await;
        if slot.is_some() {
            return;
        }
        let accepted = tokio::select! {
            result = listener.accept() => Some(result),
            () = self.cancel_token.cancelled() => None,
        };
        let Some(Ok((stream, peer_addr))) = accepted else {
            return;
        };
        let local_addr = stream.local_addr().map_or_else(
            |error| format!("unknown ({error})"),
            |addr| addr.to_string(),
        );
        let peer_addr = peer_addr.to_string();
        if pending
            .stream_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                super::reservation::reserve(count, MAX_ACTIVE_STREAMS)
            })
            .is_err()
        {
            if let Some(sink) = &self.audit_sink {
                sink.record(
                    &self.principal,
                    HostAuditEvent::NetAccept {
                        local_addr: &local_addr,
                        peer_addr: &peer_addr,
                    },
                    HostAuditOutcome::Failed("network stream quota exceeded"),
                );
            }
            return;
        }
        pending.local_stream_count.fetch_add(1, Ordering::AcqRel);
        if let Some(sink) = &self.audit_sink {
            sink.record(
                &self.principal,
                HostAuditEvent::NetAccept {
                    local_addr: &local_addr,
                    peer_addr: &peer_addr,
                },
                HostAuditOutcome::Allowed,
            );
        }
        *slot = Some(PendingTcpAccepted {
            stream,
            local_addr,
            peer_addr,
        });
    }
}

impl HostState {
    fn tcp_listener_slot(&self, rep: u32) -> Result<TcpListenerParts, ErrorCode> {
        let slot = self
            .resource_table
            .get::<TcpListenerSlot>(&Resource::new_borrow(rep))
            .map_err(|_| ErrorCode::InvalidHandle)?;
        Ok((
            Arc::clone(&slot.listener),
            Arc::clone(&slot.pending),
            slot.cancel_token.clone(),
        ))
    }

    fn register_accepted(
        &mut self,
        stream: tokio::net::TcpStream,
        reserved: bool,
    ) -> Result<Resource<TcpStream>, ErrorCode> {
        if !reserved && !self.reserve_net_stream() {
            drop(stream);
            return Err(ErrorCode::Quota);
        }
        if reserved {
            self.claim_reserved_net_stream();
        }
        let net_stream = NetStream::Tcp(TcpStreamSlot {
            stream: Arc::new(tokio::sync::Mutex::new(stream)),
            read_timeout: None,
            write_timeout: None,
        });
        let resource = match self.resource_table.push(net_stream) {
            Ok(resource) => resource,
            Err(error) => {
                self.release_net_stream();
                return Err(ErrorCode::Unknown(format!("resource table: {error}")));
            },
        };
        Ok(Resource::new_own(resource.rep()))
    }

    /// Readiness charges the capsule stream budget before it publishes a
    /// socket, while holding `pending.connection`. Admission uses that same
    /// lock so a full budget still delivers the reserved socket, and a full
    /// budget with an empty slot does not take a new one.
    fn admit_tcp_accept(
        &self,
        pending: Arc<PendingTcpConnection>,
    ) -> Result<TcpAcceptAdmission, ErrorCode> {
        let runtime = self.runtime_handle.clone();
        let semaphore = self.blocking_semaphore.clone();
        let cancel = self.effective_cancel_token();
        util::bounded_block_on_cancellable(&runtime, &semaphore, &cancel, async move {
            let mut slot = pending.connection.lock().await;
            if let Some(connection) = slot.take() {
                TcpAcceptAdmission::Reserved(connection)
            } else if pending.stream_count.load(Ordering::Acquire) >= MAX_ACTIVE_STREAMS {
                TcpAcceptAdmission::Full
            } else {
                TcpAcceptAdmission::Fresh
            }
        })
        .ok_or(ErrorCode::Closed)
    }
}

enum TcpAcceptAdmission {
    Reserved(PendingTcpAccepted),
    Fresh,
    Full,
}

impl HostTcpListener for HostState {
    fn accept(&mut self, self_: Resource<TcpListener>) -> Result<Resource<TcpStream>, ErrorCode> {
        let (listener, pending, _) = self.tcp_listener_slot(self_.rep())?;
        let (stream, local_addr, peer_addr, reserved) = match self.admit_tcp_accept(pending)? {
            TcpAcceptAdmission::Full => return Err(ErrorCode::Quota),
            TcpAcceptAdmission::Reserved(connection) => {
                self.recv_yielded = true;
                (
                    connection.stream,
                    connection.local_addr,
                    connection.peer_addr,
                    true,
                )
            },
            TcpAcceptAdmission::Fresh => {
                self.recv_yielded = true;
                let runtime = self.runtime_handle.clone();
                let semaphore = self.blocking_semaphore.clone();
                let cancel = self.effective_cancel_token();
                let accepted =
                    util::bounded_block_on_cancellable(&runtime, &semaphore, &cancel, async move {
                        listener.accept().await
                    });
                let (stream, peer_addr) = match accepted {
                    Some(Ok(connection)) => connection,
                    Some(Err(error)) => return Err(map_io_err(error)),
                    None => return Err(ErrorCode::Closed),
                };
                let local_addr = stream.local_addr().map_or_else(
                    |error| format!("unknown ({error})"),
                    |addr| addr.to_string(),
                );
                (stream, local_addr, peer_addr.to_string(), false)
            },
        };
        let result = self.register_accepted(stream, reserved);
        if !reserved {
            audit_net_accept(self, &local_addr, &peer_addr, &result);
        }
        result
    }

    fn poll_accept(
        &mut self,
        self_: Resource<TcpListener>,
        timeout_ms: u64,
    ) -> Result<Option<Resource<TcpStream>>, ErrorCode> {
        let (listener, pending, _) = self.tcp_listener_slot(self_.rep())?;
        match self.admit_tcp_accept(pending)? {
            TcpAcceptAdmission::Full => return Err(ErrorCode::Quota),
            TcpAcceptAdmission::Reserved(connection) => {
                self.recv_yielded = true;
                return self.register_accepted(connection.stream, true).map(Some);
            },
            TcpAcceptAdmission::Fresh => self.recv_yielded = true,
        }
        let runtime = self.runtime_handle.clone();
        let semaphore = self.blocking_semaphore.clone();
        let cancel = self.effective_cancel_token();
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let accepted =
            util::bounded_block_on_cancellable(&runtime, &semaphore, &cancel, async move {
                tokio::time::timeout(timeout, listener.accept()).await
            });
        match accepted {
            Some(Ok(Ok((stream, peer_addr)))) => {
                let local_addr = stream.local_addr().map_or_else(
                    |error| format!("unknown ({error})"),
                    |addr| addr.to_string(),
                );
                let peer_addr = peer_addr.to_string();
                let result = self.register_accepted(stream, false);
                audit_net_accept(self, &local_addr, &peer_addr, &result);
                result.map(Some)
            },
            Some(Ok(Err(error))) => Err(map_io_err(error)),
            Some(Err(_)) => Ok(None),
            None => Err(ErrorCode::Closed),
        }
    }

    fn local_addr(&mut self, self_: Resource<TcpListener>) -> Result<String, ErrorCode> {
        let (listener, _, _) = self.tcp_listener_slot(self_.rep())?;
        listener
            .local_addr()
            .map(|addr| addr.to_string())
            .map_err(map_io_err)
    }

    fn subscribe_readiness(&mut self, self_: Resource<TcpListener>) -> Resource<DynPollable> {
        let (listener, pending, cancel_token) = self
            .tcp_listener_slot(self_.rep())
            .expect("component model supplied a valid TCP listener resource");
        let watcher = self
            .resource_table
            .push(TcpListenerReadiness {
                listener: Arc::downgrade(&listener),
                pending: Arc::downgrade(&pending),
                cancel_token,
                audit_sink: self.audit_sink.clone(),
                principal: self.effective_principal(),
            })
            .expect("resource table accepted TCP readiness watcher");
        subscribe(&mut self.resource_table, watcher)
            .expect("resource table accepted TCP readiness pollable")
    }

    fn drop(&mut self, rep: Resource<TcpListener>) -> wasmtime::Result<()> {
        self.resource_table
            .delete::<TcpListenerSlot>(Resource::new_own(rep.rep()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wasmtime::component::Resource;

    use super::*;
    use crate::engine::wasm::bindings::astrid::net::host::{
        ErrorCode, Host as _, HostTcpListener, HostTcpStream,
    };
    use crate::engine::wasm::test_fixtures::minimal_host_state;

    fn stream_budget(state: &HostState) -> (usize, usize, usize) {
        (
            state.capsule_net_stream_count.load(Ordering::Acquire),
            state.local_net_stream_count.load(Ordering::Acquire),
            state.net_stream_count,
        )
    }

    fn fill_other_stores(state: &mut HostState) {
        state
            .capsule_net_stream_count
            .store(MAX_ACTIVE_STREAMS - 1, Ordering::Release);
    }

    fn listener_socket(state: &HostState, rep: u32) -> (Arc<tokio::net::TcpListener>, SocketAddr) {
        let slot = state
            .resource_table
            .get::<TcpListenerSlot>(&Resource::new_borrow(rep))
            .unwrap();
        let listener = Arc::clone(&slot.listener);
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    async fn reserve_last_connection(state: &mut HostState, rep: u32) -> tokio::net::TcpStream {
        let (listener, pending) = {
            let slot = state
                .resource_table
                .get::<TcpListenerSlot>(&Resource::new_borrow(rep))
                .unwrap();
            (Arc::clone(&slot.listener), Arc::clone(&slot.pending))
        };
        let addr = listener.local_addr().unwrap();
        let client =
            tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
        let mut readiness = TcpListenerReadiness {
            listener: Arc::downgrade(&listener),
            pending: Arc::downgrade(&pending),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            audit_sink: None,
            principal: astrid_core::principal::PrincipalId::default(),
        };
        Pollable::ready(&mut readiness).await;
        let client = client.await.unwrap();
        assert_eq!(stream_budget(state), (MAX_ACTIVE_STREAMS, 1, 0));
        client
    }

    async fn assert_connection_still_queued(
        mut client: tokio::net::TcpStream,
        raw: Arc<tokio::net::TcpListener>,
    ) {
        let (mut server, _) = tokio::time::timeout(Duration::from_secs(1), raw.accept())
            .await
            .expect("unreserved connection must stay queued")
            .unwrap();
        client.write_all(&[0xA5]).await.unwrap();
        let mut buf = [0u8; 1];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0xA5]);
    }

    fn assert_stream_drop_releases(state: &mut HostState, stream: Resource<TcpStream>, rep: u32) {
        HostTcpStream::drop(state, stream).unwrap();
        assert_eq!(stream_budget(state), (MAX_ACTIVE_STREAMS - 1, 0, 0));
        HostTcpListener::drop(state, Resource::new_own(rep)).unwrap();
        assert_eq!(stream_budget(state), (MAX_ACTIVE_STREAMS - 1, 0, 0));
    }

    fn pending(count: &Arc<std::sync::atomic::AtomicUsize>) -> Arc<PendingTcpConnection> {
        Arc::new(PendingTcpConnection {
            connection: tokio::sync::Mutex::new(None),
            stream_count: Arc::clone(count),
            local_stream_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    #[tokio::test]
    async fn readiness_accepts_once_and_reserves_exactly_once() {
        let listener = Arc::new(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pending = pending(&count);
        let mut readiness = TcpListenerReadiness {
            listener: Arc::downgrade(&listener),
            pending: Arc::downgrade(&pending),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            audit_sink: None,
            principal: astrid_core::principal::PrincipalId::default(),
        };
        let client = tokio::spawn(tokio::net::TcpStream::connect(addr));

        Pollable::ready(&mut readiness).await;

        assert_eq!(count.load(Ordering::Acquire), 1);
        let accepted = pending.connection.lock().await.take().unwrap();
        assert_eq!(accepted.stream.local_addr().unwrap(), addr);
        client.await.unwrap().unwrap();
        count.fetch_sub(1, Ordering::AcqRel);
        pending.local_stream_count.fetch_sub(1, Ordering::AcqRel);
    }

    #[tokio::test]
    async fn readiness_wakes_when_cancelled() {
        let listener = Arc::new(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pending = pending(&count);
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut readiness = TcpListenerReadiness {
            listener: Arc::downgrade(&listener),
            pending: Arc::downgrade(&pending),
            cancel_token: cancel.clone(),
            audit_sink: None,
            principal: astrid_core::principal::PrincipalId::default(),
        };
        cancel.cancel();

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            Pollable::ready(&mut readiness),
        )
        .await
        .expect("cancelled readiness must wake");
        assert_eq!(count.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn readiness_pollable_does_not_keep_listener_or_quota_alive() {
        let listener = Arc::new(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
        let listener_count = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let stream_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pending = pending(&stream_count);
        let mut table = wasmtime::component::ResourceTable::new();
        let listener_resource = table
            .push(TcpListenerSlot {
                listener: Arc::clone(&listener),
                pending: Arc::clone(&pending),
                cancel_token: tokio_util::sync::CancellationToken::new(),
                share: None,
                listener_count: Some(Arc::clone(&listener_count)),
            })
            .unwrap();
        let watcher = table
            .push(TcpListenerReadiness {
                listener: Arc::downgrade(&listener),
                pending: Arc::downgrade(&pending),
                cancel_token: tokio_util::sync::CancellationToken::new(),
                audit_sink: None,
                principal: astrid_core::principal::PrincipalId::default(),
            })
            .unwrap();
        let pollable = subscribe(&mut table, watcher).unwrap();
        drop(listener);

        table.delete(listener_resource).unwrap();
        assert_eq!(listener_count.load(Ordering::Acquire), 0);
        table.delete(pollable).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn accept_delivers_reserved_connection_at_capacity() {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        fill_other_stores(&mut state);
        let listener = state.bind_tcp("127.0.0.1".into(), 0).unwrap();
        let rep = listener.rep();
        let mut client = reserve_last_connection(&mut state, rep).await;
        assert!(!state.recv_yielded);

        let accepted = HostTcpListener::accept(&mut state, Resource::new_borrow(rep)).unwrap();

        assert!(state.recv_yielded);
        assert_eq!(stream_budget(&state), (MAX_ACTIVE_STREAMS, 1, 1));
        assert_stream_drop_releases(&mut state, accepted, rep);
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(1), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0, "delivered stream drop must close the peer");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn poll_accept_delivers_reserved_connection_at_capacity() {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        fill_other_stores(&mut state);
        let listener = state.bind_tcp("127.0.0.1".into(), 0).unwrap();
        let rep = listener.rep();
        let client = reserve_last_connection(&mut state, rep).await;

        let accepted = HostTcpListener::poll_accept(&mut state, Resource::new_borrow(rep), 0)
            .unwrap()
            .expect("reserved connection is ready without waiting");

        assert!(state.recv_yielded);
        assert_eq!(stream_budget(&state), (MAX_ACTIVE_STREAMS, 1, 1));
        assert_stream_drop_releases(&mut state, accepted, rep);
        drop(client);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn accept_at_capacity_leaves_unreserved_connection_queued() {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        state
            .capsule_net_stream_count
            .store(MAX_ACTIVE_STREAMS, Ordering::Release);
        let listener = state.bind_tcp("127.0.0.1".into(), 0).unwrap();
        let rep = listener.rep();
        let (raw, addr) = listener_socket(&state, rep);
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();

        let started = Instant::now();
        let result = HostTcpListener::accept(&mut state, Resource::new_borrow(rep));

        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(matches!(result, Err(ErrorCode::Quota)));
        assert!(!state.recv_yielded);
        assert_eq!(stream_budget(&state), (MAX_ACTIVE_STREAMS, 0, 0));
        assert_connection_still_queued(client, raw).await;
        HostTcpListener::drop(&mut state, listener).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn poll_accept_at_capacity_leaves_unreserved_connection_queued() {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        state
            .capsule_net_stream_count
            .store(MAX_ACTIVE_STREAMS, Ordering::Release);
        let listener = state.bind_tcp("127.0.0.1".into(), 0).unwrap();
        let rep = listener.rep();
        let (raw, addr) = listener_socket(&state, rep);
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();

        let started = Instant::now();
        let result = HostTcpListener::poll_accept(&mut state, Resource::new_borrow(rep), 30_000);

        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(matches!(result, Err(ErrorCode::Quota)));
        assert!(!state.recv_yielded);
        assert_eq!(stream_budget(&state), (MAX_ACTIVE_STREAMS, 0, 0));
        assert_connection_still_queued(client, raw).await;
        HostTcpListener::drop(&mut state, listener).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fresh_accept_fills_last_slot_then_refuses_the_next() {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        fill_other_stores(&mut state);
        let listener = state.bind_tcp("127.0.0.1".into(), 0).unwrap();
        let rep = listener.rep();
        let (raw, addr) = listener_socket(&state, rep);
        let first = tokio::net::TcpStream::connect(addr).await.unwrap();
        let accepted = HostTcpListener::accept(&mut state, Resource::new_borrow(rep)).unwrap();
        assert_eq!(stream_budget(&state), (MAX_ACTIVE_STREAMS, 1, 1));

        let second = tokio::net::TcpStream::connect(addr).await.unwrap();
        let result = HostTcpListener::accept(&mut state, Resource::new_borrow(rep));
        assert!(matches!(result, Err(ErrorCode::Quota)));
        assert_eq!(stream_budget(&state), (MAX_ACTIVE_STREAMS, 1, 1));
        assert_connection_still_queued(second, raw).await;

        HostTcpStream::drop(&mut state, accepted).unwrap();
        assert_eq!(stream_budget(&state), (MAX_ACTIVE_STREAMS - 1, 0, 0));
        HostTcpListener::drop(&mut state, listener).unwrap();
        drop(first);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dropping_unclaimed_reservation_releases_its_budget() {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        fill_other_stores(&mut state);
        let listener = state.bind_tcp("127.0.0.1".into(), 0).unwrap();
        let mut client = reserve_last_connection(&mut state, listener.rep()).await;

        HostTcpListener::drop(&mut state, listener).unwrap();

        assert_eq!(stream_budget(&state), (MAX_ACTIVE_STREAMS - 1, 0, 0));
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(1), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0, "dropping the reservation must close the peer");
    }
}

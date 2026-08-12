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
        let local_addr = stream
            .local_addr()
            .map_or_else(|error| format!("unknown ({error})"), |addr| addr.to_string());
        let peer_addr = peer_addr.to_string();
        if pending
            .stream_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_ACTIVE_STREAMS).then_some(count + 1)
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

    fn take_pending(
        &self,
        pending: Arc<PendingTcpConnection>,
    ) -> Option<PendingTcpAccepted> {
        let runtime = self.runtime_handle.clone();
        let semaphore = self.blocking_semaphore.clone();
        let cancel = self.effective_cancel_token();
        util::bounded_block_on_cancellable(&runtime, &semaphore, &cancel, async move {
            pending.connection.lock().await.take()
        })
        .flatten()
    }
}

impl HostTcpListener for HostState {
    fn accept(&mut self, self_: Resource<TcpListener>) -> Result<Resource<TcpStream>, ErrorCode> {
        let (listener, pending, _) = self.tcp_listener_slot(self_.rep())?;
        if self.net_stream_count.load(Ordering::Acquire) >= MAX_ACTIVE_STREAMS {
            return Err(ErrorCode::Quota);
        }
        self.recv_yielded = true;

        let pending = self.take_pending(pending);
        let (stream, local_addr, peer_addr, reserved) = if let Some(connection) = pending {
            (
                connection.stream,
                connection.local_addr,
                connection.peer_addr,
                true,
            )
        } else {
            let runtime = self.runtime_handle.clone();
            let semaphore = self.blocking_semaphore.clone();
            let cancel = self.effective_cancel_token();
            let accepted = util::bounded_block_on_cancellable(
                &runtime,
                &semaphore,
                &cancel,
                async move { listener.accept().await },
            );
            let (stream, peer_addr) = match accepted {
                Some(Ok(connection)) => connection,
                Some(Err(error)) => return Err(map_io_err(error)),
                None => return Err(ErrorCode::Closed),
            };
            let local_addr = stream
                .local_addr()
                .map_or_else(|error| format!("unknown ({error})"), |addr| addr.to_string());
            (stream, local_addr, peer_addr.to_string(), false)
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
        if self.net_stream_count.load(Ordering::Acquire) >= MAX_ACTIVE_STREAMS {
            return Err(ErrorCode::Quota);
        }
        self.recv_yielded = true;

        if let Some(connection) = self.take_pending(pending) {
            let result = self.register_accepted(connection.stream, true);
            return result.map(Some);
        }
        let runtime = self.runtime_handle.clone();
        let semaphore = self.blocking_semaphore.clone();
        let cancel = self.effective_cancel_token();
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let accepted = util::bounded_block_on_cancellable(
            &runtime,
            &semaphore,
            &cancel,
            async move { tokio::time::timeout(timeout, listener.accept()).await },
        );
        match accepted {
            Some(Ok(Ok((stream, peer_addr)))) => {
                let local_addr = stream
                    .local_addr()
                    .map_or_else(|error| format!("unknown ({error})"), |addr| addr.to_string());
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
    use super::*;

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
                listener_count: Arc::clone(&listener_count),
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
}

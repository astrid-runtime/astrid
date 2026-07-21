//! `HostUnixListener` impl — the kernel-pre-bound Unix listener.
//!
//! `accept` / `poll-accept` perform session-token + peer-credential
//! handshake before exposing the authenticated stream as a
//! `NetStream::Unix` resource handle.

use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use std::os::fd::{AsFd, OwnedFd};

use wasmtime::component::Resource;
use wasmtime_wasi::p2::{DynPollable, Pollable, subscribe};

use super::client_lifecycle;
use super::handshake::validate_handshake;
#[cfg(unix)]
use super::handshake::verify_peer_credentials;
use super::{
    HostState, NetStream, UnixListenerSlot, audit_net, map_io_err, record_net_stream_metrics,
};
use crate::engine::wasm::bindings::astrid::net::host::{
    ErrorCode, HostUnixListener, TcpStream, UnixListener,
};
use crate::engine::wasm::host::util;

#[cfg(unix)]
struct UnixListenerReadiness {
    descriptor: tokio::io::unix::AsyncFd<OwnedFd>,
    budget: Arc<crate::NetStreamBudget>,
}

#[cfg(unix)]
#[async_trait::async_trait]
impl Pollable for UnixListenerReadiness {
    async fn ready(&mut self) {
        loop {
            self.budget.wait_available().await;
            if let Ok(mut readiness) = self.descriptor.readable().await {
                // The listener itself remains level-triggered. Clear only this
                // duplicate descriptor's cached Tokio readiness so the next
                // poll waits for the post-accept state instead of firing
                // forever.
                readiness.clear_ready();
                if self.budget.has_capacity() {
                    return;
                }
            } else {
                return;
            }
        }
    }
}

impl HostUnixListener for HostState {
    fn accept(&mut self, _self_: Resource<UnixListener>) -> Result<Resource<TcpStream>, ErrorCode> {
        let listener_arc = self.cli_socket_listener.clone().ok_or(ErrorCode::Closed)?;
        if !self.net_stream_budget.has_capacity() {
            return Err(ErrorCode::Quota);
        }
        let rt_handle = self.runtime_handle.clone();
        let cancel_token = self.effective_cancel_token();
        let session_token = self.session_token.clone();
        let blocking_semaphore = self.blocking_semaphore.clone();

        // Resolved once and reused for every accept iteration: where a claimed
        // principal's profile/keys load from during the handshake challenge
        // (issue #45/#852). Only resolved when a session token gates the
        // handshake; an unauthenticated daemon never reaches
        // `validate_handshake`, so `None` is fine there.
        let astrid_home = if session_token.is_some() {
            Some(
                astrid_core::dirs::AstridHome::resolve()
                    .map_err(|e| ErrorCode::Unknown(format!("cannot resolve astrid home: {e}")))?,
            )
        } else {
            None
        };

        // The handshake yields `Some((principal, device_key_id))` for a
        // crypto-authenticated connection — the device id rides forward so the
        // cap-gate can scope it — or `None` for a legacy/unauthenticated peer.
        let (stream, verified_identity): (
            _,
            Option<(astrid_core::principal::PrincipalId, String)>,
        ) = loop {
            let accept_result = util::bounded_block_on_cancellable(
                &rt_handle,
                &blocking_semaphore,
                &cancel_token,
                async {
                    let listener = listener_arc.lock().await;
                    listener.accept().await.map(|(stream, _)| stream)
                },
            );
            let stream = match accept_result {
                Some(result) => result.map_err(map_io_err)?,
                None => return Err(ErrorCode::Closed),
            };

            #[cfg(unix)]
            if let Err(reason) = verify_peer_credentials(&stream) {
                tracing::warn!(
                    security_event = true,
                    reason = %reason,
                    "rejected unix accept: peer creds"
                );
                drop(stream);
                // Backoff to keep a flood of UID-mismatched clients
                // from spinning the accept loop at syscall speed.
                // The handshake path has a 5s timeout that already
                // throttles slow-but-valid-creds clients; this branch
                // doesn't enter the handshake at all.
                let _ = util::bounded_block_on_cancellable(
                    &rt_handle,
                    &blocking_semaphore,
                    &cancel_token,
                    async {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    },
                );
                continue;
            }

            let mut stream = stream;
            if let (Some(token), Some(home)) = (&session_token, &astrid_home) {
                let handshake_result = util::bounded_block_on_cancellable(
                    &rt_handle,
                    &blocking_semaphore,
                    &cancel_token,
                    validate_handshake(&mut stream, token, home),
                );
                match handshake_result {
                    None => return Err(ErrorCode::Closed),
                    Some(Ok(identity)) => break (stream, identity),
                    Some(Err(reason)) => {
                        tracing::warn!(
                            security_event = true,
                            reason = %reason,
                            "rejected unix accept: handshake"
                        );
                        drop(stream);
                        continue;
                    },
                }
            } else {
                break (stream, None);
            }
        };

        // Waiting for an inbound connection does not consume another file
        // descriptor, so acquire only after accept and authentication. The
        // atomic acquisition closes the race between concurrent acceptors.
        let Some(stream_lease) = self.net_stream_budget.try_acquire() else {
            drop(stream);
            return Err(ErrorCode::Quota);
        };
        let net_stream = NetStream::Unix(Arc::new(tokio::sync::Mutex::new(stream)));
        let res = self
            .resource_table
            .push(net_stream)
            .map_err(|e| ErrorCode::Unknown(format!("resource table: {e}")))?;
        self.net_stream_count += 1;
        let rep = res.rep();
        let previous = self.net_stream_leases.insert(rep, stream_lease);
        debug_assert!(
            previous.is_none(),
            "net stream resource rep reused while live"
        );
        record_net_stream_metrics(self);
        // Record the verified principal AND its authenticating device key_id
        // (issue #45/#852) keyed by the stream resource rep, now that the rep
        // is known. Storage only; enforcement reads this registry separately —
        // the framed read copies both onto the in-flight ingress fields so
        // `publish-as` stamps the device id for cap-gate scoping. The binding
        // is removed when the stream resource drops (see `TcpStream::drop`).
        let verified_principal = verified_identity.as_ref().map(|(p, _)| p.clone());
        if let Some((principal, key_id)) = verified_identity {
            self.bind_connection_principal(rep, principal, Some(key_id));
        }
        // Emit `client.v1.connect` for the kernel connection tracker, stamped
        // with the host-verified principal — `anonymous` for a legacy /
        // unauthenticated peer so connect/disconnect balance on one identity.
        // The matching disconnect fires from the stream-resource drop path
        // (see `TcpStream::drop`). Inbound-only: outbound TCP never reaches
        // here, so a capsule-dialed socket never moves the counter.
        client_lifecycle::register_and_emit_connect(
            self,
            rep,
            verified_principal.unwrap_or_else(astrid_core::principal::PrincipalId::anonymous),
        );
        let result: Result<Resource<TcpStream>, ErrorCode> = Ok(Resource::new_own(rep));
        audit_net(self, "astrid:net/host.unix-listener.accept", 0, &result);
        result
    }

    fn poll_accept(
        &mut self,
        _self_: Resource<UnixListener>,
        timeout_ms: u64,
    ) -> Result<Option<Resource<TcpStream>>, ErrorCode> {
        let listener_arc = self.cli_socket_listener.clone().ok_or(ErrorCode::Closed)?;
        let rt_handle = self.runtime_handle.clone();
        let cancel_token = self.effective_cancel_token();
        let session_token = self.session_token.clone();
        let blocking_semaphore = self.blocking_semaphore.clone();

        if !self.net_stream_budget.has_capacity() {
            return Ok(None);
        }

        let timeout_ms = timeout_ms.min(60_000);
        let accept_result = util::bounded_block_on_cancellable(
            &rt_handle,
            &blocking_semaphore,
            &cancel_token,
            async {
                let listener = listener_arc.lock().await;
                tokio::time::timeout(Duration::from_millis(timeout_ms), listener.accept()).await
            },
        );

        let stream = match accept_result {
            None => return Ok(None),
            Some(Err(_)) => return Ok(None),
            Some(Ok(Err(e))) => return Err(map_io_err(e)),
            Some(Ok(Ok((stream, _)))) => stream,
        };

        #[cfg(unix)]
        if let Err(reason) = verify_peer_credentials(&stream) {
            tracing::warn!(
                security_event = true,
                reason = %reason,
                "rejected unix poll_accept: peer creds"
            );
            drop(stream);
            return Ok(None);
        }

        let mut stream = stream;
        let mut verified_identity: Option<(astrid_core::principal::PrincipalId, String)> = None;
        if let Some(ref token) = session_token {
            // See `accept` for why home is resolved here (issue #45/#852).
            let home = match astrid_core::dirs::AstridHome::resolve() {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(
                        security_event = true,
                        error = %e,
                        "rejected unix poll_accept: cannot resolve astrid home"
                    );
                    drop(stream);
                    return Ok(None);
                },
            };
            let handshake_result = util::bounded_block_on_cancellable(
                &rt_handle,
                &blocking_semaphore,
                &cancel_token,
                validate_handshake(&mut stream, token, &home),
            );
            match handshake_result {
                None => return Ok(None),
                Some(Err(reason)) => {
                    tracing::warn!(
                        security_event = true,
                        reason = %reason,
                        "rejected unix poll_accept: handshake"
                    );
                    drop(stream);
                    return Ok(None);
                },
                Some(Ok(identity)) => verified_identity = identity,
            }
        }

        let Some(stream_lease) = self.net_stream_budget.try_acquire() else {
            drop(stream);
            return Ok(None);
        };
        let net_stream = NetStream::Unix(Arc::new(tokio::sync::Mutex::new(stream)));
        let res = self
            .resource_table
            .push(net_stream)
            .map_err(|e| ErrorCode::Unknown(format!("resource table: {e}")))?;
        self.net_stream_count += 1;
        let rep = res.rep();
        let previous = self.net_stream_leases.insert(rep, stream_lease);
        debug_assert!(
            previous.is_none(),
            "net stream resource rep reused while live"
        );
        record_net_stream_metrics(self);
        // Same per-connection principal + device-key binding as `accept`
        // (issue #45/#852).
        let verified_principal = verified_identity.as_ref().map(|(p, _)| p.clone());
        if let Some((principal, key_id)) = verified_identity {
            self.bind_connection_principal(rep, principal, Some(key_id));
        }
        // Same `client.v1.connect` emission as `accept` — see there for the
        // anonymous-fallback and inbound-only rationale.
        client_lifecycle::register_and_emit_connect(
            self,
            rep,
            verified_principal.unwrap_or_else(astrid_core::principal::PrincipalId::anonymous),
        );
        Ok(Some(Resource::new_own(rep)))
    }

    fn subscribe_readiness(&mut self, _self_: Resource<UnixListener>) -> Resource<DynPollable> {
        let Some(listener) = self.cli_socket_listener.clone() else {
            return Resource::new_own(0);
        };
        let runtime = self.runtime_handle.clone();
        let semaphore = self.blocking_semaphore.clone();
        let cancel = self.effective_cancel_token();
        let async_fd = util::bounded_block_on_cancellable(&runtime, &semaphore, &cancel, async {
            let listener = listener.lock().await;
            let descriptor = listener.as_fd().try_clone_to_owned()?;
            tokio::io::unix::AsyncFd::new(descriptor)
        });
        let Some(Ok(async_fd)) = async_fd else {
            return Resource::new_own(0);
        };
        let Ok(readiness) = self.resource_table.push(UnixListenerReadiness {
            descriptor: async_fd,
            budget: Arc::clone(&self.net_stream_budget),
        }) else {
            return Resource::new_own(0);
        };
        subscribe(&mut self.resource_table, readiness).unwrap_or_else(|_| Resource::new_own(0))
    }

    fn drop(&mut self, rep: Resource<UnixListener>) -> wasmtime::Result<()> {
        let _ = self
            .resource_table
            .delete::<UnixListenerSlot>(Resource::new_own(rep.rep()));
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod readiness_tests {
    use std::os::fd::AsFd;

    use wasmtime_wasi::p2::Pollable;

    use super::UnixListenerReadiness;

    #[tokio::test]
    async fn listener_readiness_waits_for_connection_and_capacity_without_accepting() {
        let directory = tempfile::tempdir().expect("temporary socket directory");
        let socket_path = directory.path().join("readiness.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind test listener");
        let descriptor = listener
            .as_fd()
            .try_clone_to_owned()
            .expect("duplicate listener descriptor");
        let mut readiness = UnixListenerReadiness {
            descriptor: tokio::io::unix::AsyncFd::new(descriptor)
                .expect("register duplicate descriptor"),
            budget: std::sync::Arc::new(crate::NetStreamBudget::new(1)),
        };
        let lease = readiness
            .budget
            .try_acquire()
            .expect("occupy the only stream slot");

        let connector = tokio::spawn(async move {
            tokio::net::UnixStream::connect(socket_path)
                .await
                .expect("connect test client")
        });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), readiness.ready())
                .await
                .is_err(),
            "a readable listener must not wake while stream capacity is full"
        );
        drop(lease);
        tokio::time::timeout(std::time::Duration::from_secs(2), readiness.ready())
            .await
            .expect("readiness should fire");
        tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
            .await
            .expect("readiness must not consume the connection")
            .expect("accept test connection");
        connector.await.expect("connector task");
    }
}

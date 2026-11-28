//! Lifetime of a signed local stream and the frames authenticated by it.

use std::sync::{Arc, Weak};

use super::{ConnectionIdentity, HostState};
use crate::engine::wasm::host::net::client_lifecycle::SignedLifecycle;
use astrid_core::local_transport::LocalStream;
use astrid_core::profile::device_sessions::DeviceSession;
use tokio::sync::{Mutex, oneshot};

#[derive(Debug)]
struct LiveSocket {
    // Close the OS handle before releasing this operation's retirement receiver.
    stream: Mutex<LocalStream>,
    lifecycle: std::sync::OnceLock<SignedLifecycle>,
    session: Arc<DeviceSession>,
}

/// A received frame can outlive its transport without keeping the socket open.
#[derive(Clone, Debug)]
pub(crate) struct SocketAuthority {
    session: Weak<DeviceSession>,
    pub(crate) registration: Option<uuid::Uuid>,
    pub(crate) identity: Arc<ConnectionIdentity>,
    _owner: Arc<oneshot::Sender<()>>,
}

impl SocketAuthority {
    pub(crate) async fn run<F: Future>(&self, operation: F) -> Option<F::Output> {
        let session = self.session.upgrade()?;
        session.while_live(operation).await
    }
}

/// Guest handles refer weakly to the transport so an idle guest cannot
/// prevent the kernel from acknowledging device retirement.
#[derive(Clone, Debug)]
pub struct SignedSocket {
    socket: Weak<LiveSocket>,
    authority: SocketAuthority,
    _owner: Arc<oneshot::Sender<()>>,
}

impl SignedSocket {
    pub(crate) fn new(
        stream: LocalStream,
        session: DeviceSession,
        identity: ConnectionIdentity,
        runtime: &tokio::runtime::Handle,
    ) -> Self {
        let session = Arc::new(session);
        let live = Arc::new(LiveSocket {
            stream: Mutex::new(stream),
            lifecycle: std::sync::OnceLock::new(),
            session: Arc::clone(&session),
        });
        let (socket_owner, socket_released) = oneshot::channel();
        let (frame_owner, frames_released) = oneshot::channel();
        let handle = Self {
            socket: Arc::downgrade(&live),
            authority: SocketAuthority {
                session: Arc::downgrade(&session),
                registration: session.registration().map(Into::into),
                identity: Arc::new(identity),
                _owner: Arc::new(frame_owner),
            },
            _owner: Arc::new(socket_owner),
        };
        runtime.spawn(async move {
            let _ = session
                .while_live(async move {
                    let _ = socket_released.await;
                    drop(live);
                    let _ = frames_released.await;
                })
                .await;
        });
        handle
    }

    pub(crate) fn register_connection(&self, state: &HostState) -> bool {
        let Some(live) = self.socket.upgrade() else {
            return false;
        };
        if live.session.is_retired() {
            return false;
        }
        // Holding live across both the event and installation orders the
        // matching disconnect before device retirement can acknowledge.
        live.lifecycle.get_or_init(|| {
            SignedLifecycle::connect(state, self.authority.identity.principal.clone())
        });
        true
    }

    pub(crate) fn live_identity(&self) -> Option<ConnectionIdentity> {
        let live = self.socket.upgrade()?;
        (!live.session.is_retired()).then(|| self.authority.identity.as_ref().clone())
    }

    pub(crate) fn authority(&self) -> &SocketAuthority {
        &self.authority
    }

    pub(crate) async fn io<R>(&self, effect: impl AsyncFnOnce(&mut LocalStream) -> R) -> Option<R> {
        let live = self.socket.upgrade()?;
        live.session
            .while_live(async {
                let mut stream = live.stream.lock().await;
                effect(&mut stream).await
            })
            .await
    }
}

#[cfg(all(test, unix))]
#[path = "signed_socket_tests.rs"]
mod tests;

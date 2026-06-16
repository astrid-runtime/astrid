//! Host service for Path-1 spawn binding (issue #45/#852).
//!
//! When the host spawns a native agent via `host_process`, that agent needs to
//! reach the daemon as its own principal — but it must not hold a private key
//! (the sandbox masks `~/.astrid/keys`) and, once the sandbox masks
//! `~/.astrid/run` too, it cannot even dial the socket. So the daemon opens an
//! authenticated, principal-bound connection on the child's behalf and
//! fd-passes the live socket into the sandboxed child, which adopts it via
//! [`SocketClient::from_raw_fd`](../../astrid_uplink). The kernel binds
//! connection→principal at the handshake and enforces it on every message (the
//! publish-as enforcement already on `main`), so a child cannot escalate.
//!
//! The WASM engine cannot depend on the uplink client crate, so the broker is a
//! trait the daemon implements and injects into the engine (mirroring the way
//! the security gate and hook manager are injected).

use astrid_core::principal::PrincipalId;

/// Establishes an authenticated, principal-bound daemon connection for a
/// freshly host-spawned native agent and yields it as a raw fd to fd-pass into
/// the sandboxed child.
pub trait SpawnConnectionBroker: Send + Sync {
    /// Open and authenticate a daemon connection bound to `principal`, returning
    /// the connected socket as a raw fd. The implementation dials the kernel
    /// socket and authenticates AS `principal` using that principal's
    /// daemon-custodied key (the same crypto handshake an external client runs),
    /// so the connection is kernel-bound to `principal` exactly like any other
    /// authenticated connection.
    ///
    /// The caller takes ownership of the returned fd: it fd-passes it to the
    /// child (sets `ASTRID_CONN_FD` and clears `FD_CLOEXEC` so the child inherits
    /// it) and closes its own copy once the child is spawned.
    ///
    /// This is synchronous on purpose — it is called from the synchronous
    /// `host_process` spawn path. The implementation owns the daemon runtime and
    /// drives the async dial internally (e.g. via `block_in_place`).
    ///
    /// # Errors
    /// Returns an error string if the connection or handshake fails. The spawn
    /// path treats a bound-connection failure as fatal rather than silently
    /// running the agent unbound.
    fn authenticated_fd(&self, principal: &PrincipalId) -> Result<std::os::fd::RawFd, String>;
}

//! Per-connection verified-principal binding accessors for `HostState`.
//! Split out of `host_state.rs` to stay under the 1000-line CI cap; included via `#[path]`.

use super::*;

impl HostState {
    /// Build a fresh, empty per-connection identity registry.
    ///
    /// The `OnceLock` stays unset until the first bind so unused runtimes do
    /// not pay `DashMap`'s CPU-sized empty shard array. `OnceLock` rather than
    /// `LazyLock`: `Deref` would allocate on idle `get`/`remove`/`clear`.
    /// First insert uses `DashMap::new` (default shard count).
    ///
    /// Callers that construct a `HostState` outside the pooled-capsule path
    /// (lifecycle hooks, the hook handler, tests) use this so they do not have
    /// to name the map type. The pooled path instead clones one shared
    /// registry into every instance (issue #45/#852).
    #[must_use]
    pub fn new_connection_principals()
    -> Arc<std::sync::OnceLock<dashmap::DashMap<u32, ConnectionIdentity>>> {
        Arc::new(std::sync::OnceLock::new())
    }

    /// Build a fresh, empty per-connection client-lifecycle registry.
    ///
    /// Distinct from [`new_connection_principals`](Self::new_connection_principals):
    /// `client_connections` maps a stream rep to the verified principal alone
    /// (no device id) for the connect/disconnect counter, whereas
    /// `connection_principals` carries the device-aware [`ConnectionIdentity`].
    /// Out-of-pool constructors (lifecycle hooks, the hook handler, tests) use
    /// this so they do not have to name the map type.
    #[must_use]
    pub fn new_client_connections()
    -> Arc<std::sync::OnceLock<dashmap::DashMap<u32, astrid_core::principal::PrincipalId>>> {
        Arc::new(std::sync::OnceLock::new())
    }

    /// Build a fresh, empty shared-listener registry.
    ///
    /// Run-loop worker Stores (`bind_workers > 1`) clone ONE registry so they
    /// dedupe onto a single bound `TcpListener`. Sharing is gated by
    /// `share_tcp_listeners`; N=1 never consults this map. Interceptor /
    /// non-worker pool instances each get a fresh map so a concrete-port bind
    /// stays private. Out-of-pool constructors use this so they do not have
    /// to name the map type.
    #[must_use]
    pub fn new_shared_listeners()
    -> Arc<std::sync::OnceLock<dashmap::DashMap<(String, u16), super::SharedTcpListener>>> {
        Arc::new(std::sync::OnceLock::new())
    }

    /// Bind `principal` and the authenticating device `key_id` to the
    /// connection identified by stream resource `rep`.
    ///
    /// Called by the `net.unix-listener.accept` path after a verified
    /// per-connection principal challenge-response (issue #45/#852). The
    /// `device_key_id` is the matched [`DeviceKey`](astrid_core::profile::DeviceKey)
    /// fingerprint from the handshake; it rides forward so the cap-gate can
    /// scope the connection. Storage only — see
    /// [`connection_principals`](Self::connection_principals).
    pub(crate) fn bind_connection_principal(
        &self,
        rep: u32,
        principal: astrid_core::principal::PrincipalId,
        device_key_id: Option<String>,
    ) {
        self.connection_principals
            .get_or_init(dashmap::DashMap::new)
            .insert(
                rep,
                ConnectionIdentity {
                    principal,
                    device_key_id,
                    request_owner: astrid_events::ipc::RequestOwnerId::generate(),
                },
            );
    }

    /// Return the verified principal bound to the connection identified by
    /// stream resource `rep`, if any.
    ///
    /// The READ side of the registry (issue #45/#852). Existing callers want
    /// only the principal; the device `key_id` is read separately at the
    /// `tcp-stream.read` enforcement seam, which clones the whole
    /// [`ConnectionIdentity`] entry. The enforcement seam reads the registry
    /// directly via `connection_principals.get`, so this principal-only
    /// accessor is exercised only by the registry round-trip test —
    /// `allow(dead_code)` keeps it under `-D warnings`.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn connection_principal(
        &self,
        rep: u32,
    ) -> Option<astrid_core::principal::PrincipalId> {
        self.connection_principals
            .get()
            .and_then(|map| map.get(&rep).map(|entry| entry.principal.clone()))
    }

    /// Remove any verified-identity binding for the connection identified by
    /// stream resource `rep`. Called when the stream resource drops so the
    /// registry does not leak entries for closed connections.
    pub(crate) fn unbind_connection_principal(&self, rep: u32) {
        if let Some(map) = self.connection_principals.get() {
            map.remove(&rep);
        }
    }
}

#[cfg(test)]
#[path = "host_state_connection/tests.rs"]
mod tests;

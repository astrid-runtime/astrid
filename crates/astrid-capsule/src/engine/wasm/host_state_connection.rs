//! Per-connection verified-principal binding accessors for `HostState`.
//! Split out of `host_state.rs` to stay under the 1000-line CI cap; included via `#[path]`.

use super::*;

impl HostState {
    /// Build a fresh, empty per-connection identity registry.
    ///
    /// Callers that construct a `HostState` outside the pooled-capsule path
    /// (lifecycle hooks, the hook handler, tests) use this so they do not have
    /// to name the `dashmap` type. The pooled path instead clones one shared
    /// registry into every instance (issue #45/#852).
    #[must_use]
    pub fn new_connection_principals() -> Arc<dashmap::DashMap<u32, ConnectionIdentity>> {
        Arc::new(dashmap::DashMap::new())
    }

    /// Build a fresh, empty per-connection client-lifecycle registry.
    ///
    /// Distinct from [`new_connection_principals`](Self::new_connection_principals):
    /// `client_connections` maps a stream rep to the verified principal alone
    /// (no device id) for the connect/disconnect counter, whereas
    /// `connection_principals` carries the device-aware [`ConnectionIdentity`].
    /// Out-of-pool constructors (lifecycle hooks, the hook handler, tests) use
    /// this so they do not have to name the `dashmap` type.
    #[must_use]
    pub fn new_client_connections()
    -> Arc<dashmap::DashMap<u32, astrid_core::principal::PrincipalId>> {
        Arc::new(dashmap::DashMap::new())
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
        self.connection_principals.insert(
            rep,
            ConnectionIdentity {
                principal,
                device_key_id,
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
            .get(&rep)
            .map(|e| e.principal.clone())
    }

    /// Remove any verified-identity binding for the connection identified by
    /// stream resource `rep`. Called when the stream resource drops so the
    /// registry does not leak entries for closed connections.
    pub(crate) fn unbind_connection_principal(&self, rep: u32) {
        self.connection_principals.remove(&rep);
    }
}

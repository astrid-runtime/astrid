//! Per-connection verified-principal binding accessors for `HostState`.
//! Split out of `host_state.rs` to stay under the 1000-line CI cap; included via `#[path]`.

use super::*;

impl HostState {
    /// Build a fresh, empty per-connection principal registry.
    ///
    /// Callers that construct a `HostState` outside the pooled-capsule path
    /// (lifecycle hooks, the hook handler, tests) use this so they do not have
    /// to name the `dashmap` type. The pooled path instead clones one shared
    /// registry into every instance (issue #45/#852).
    #[must_use]
    pub fn new_connection_principals()
    -> Arc<dashmap::DashMap<u32, astrid_core::principal::PrincipalId>> {
        Arc::new(dashmap::DashMap::new())
    }

    /// Bind `principal` to the connection identified by stream resource `rep`.
    ///
    /// Called by the `net.unix-listener.accept` path after a verified
    /// per-connection principal challenge-response (issue #45/#852). Storage
    /// only — see [`connection_principals`](Self::connection_principals).
    pub(crate) fn bind_connection_principal(
        &self,
        rep: u32,
        principal: astrid_core::principal::PrincipalId,
    ) {
        self.connection_principals.insert(rep, principal);
    }

    /// Return the verified principal bound to the connection identified by
    /// stream resource `rep`, if any.
    ///
    /// The READ side of the registry (issue #45/#852). This change only
    /// POPULATES the registry; the enforcement that consumes it — binding the
    /// connection's verified principal to its outbound traffic — lands
    /// separately, so the accessor is exercised by tests but not yet by any
    /// non-test call path. `allow(dead_code)` keeps the accessor in place for
    /// that follow-up without tripping `-D warnings` in the interim.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn connection_principal(
        &self,
        rep: u32,
    ) -> Option<astrid_core::principal::PrincipalId> {
        self.connection_principals.get(&rep).map(|e| e.clone())
    }

    /// Remove any verified-principal binding for the connection identified by
    /// stream resource `rep`. Called when the stream resource drops so the
    /// registry does not leak entries for closed connections.
    pub(crate) fn unbind_connection_principal(&self, rep: u32) {
        self.connection_principals.remove(&rep);
    }
}

//! Per-connection verified-principal binding accessors for `HostState`.
//! Split out of `host_state.rs` to stay under the 1000-line CI cap; included via `#[path]`.

use super::*;

// These registries belong to a capsule pool, not the whole process. DashMap's
// CPU-sized default eagerly allocates empty shards for every loaded capsule.
// Two is its minimum supported shard count; entries still grow on demand and
// pooled Stores retain the same shared, independently locked registries.

impl HostState {
    /// Build a fresh, empty per-connection identity registry.
    ///
    /// Callers that construct a `HostState` outside the pooled-capsule path
    /// (lifecycle hooks, the hook handler, tests) use this so they do not have
    /// to name the `dashmap` type. The pooled path instead clones one shared
    /// registry into every instance (issue #45/#852).
    #[must_use]
    pub fn new_connection_principals() -> Arc<dashmap::DashMap<u32, ConnectionIdentity>> {
        Arc::new(dashmap::DashMap::with_shard_amount(2))
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
        Arc::new(dashmap::DashMap::with_shard_amount(2))
    }

    /// Build a fresh, empty shared-listener registry.
    ///
    /// Run-loop worker Stores (`bind_workers > 1`) clone ONE registry so they
    /// dedupe onto a single bound `TcpListener`. Sharing is gated by
    /// `share_tcp_listeners`; N=1 never consults this map. Interceptor /
    /// non-worker pool instances each get a fresh map so a concrete-port bind
    /// stays private. Out-of-pool constructors use this so they do not have
    /// to name the `dashmap` type.
    #[must_use]
    pub fn new_shared_listeners() -> Arc<dashmap::DashMap<(String, u16), super::SharedTcpListener>>
    {
        Arc::new(dashmap::DashMap::with_shard_amount(2))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_connection_registries_have_bounded_shard_overhead() {
        assert_eq!(HostState::new_connection_principals().shards().len(), 2);
        assert_eq!(HostState::new_client_connections().shards().len(), 2);
        assert_eq!(HostState::new_shared_listeners().shards().len(), 2);
    }

    #[test]
    fn concurrent_connection_bindings_preserve_identity_and_owner() {
        let registry = HostState::new_connection_principals();
        std::thread::scope(|scope| {
            for rep in 0..16 {
                let registry = &registry;
                scope.spawn(move || {
                    let principal = astrid_core::PrincipalId::new(format!("client-{rep}"))
                        .expect("valid principal");
                    let device_key_id = Some(format!("device-{rep}"));
                    let request_owner = astrid_events::ipc::RequestOwnerId::generate();
                    registry.insert(
                        rep,
                        ConnectionIdentity {
                            principal: principal.clone(),
                            device_key_id: device_key_id.clone(),
                            request_owner,
                        },
                    );
                    let identity = registry.get(&rep).expect("bound identity");
                    assert_eq!(identity.principal, principal);
                    assert_eq!(identity.device_key_id, device_key_id);
                    assert_eq!(identity.request_owner, request_owner);
                    drop(identity);
                    assert!(registry.remove(&rep).is_some());
                });
            }
        });
        assert!(registry.is_empty());
    }

    #[test]
    fn fresh_client_registries_keep_stream_identifiers_private() {
        let first = HostState::new_client_connections();
        let second = HostState::new_client_connections();
        let alice = astrid_core::PrincipalId::new("alice").expect("valid principal");
        first.insert(42, alice.clone());
        assert_eq!(first.get(&42).as_deref(), Some(&alice));
        assert!(second.get(&42).is_none());
        first.remove(&42);
        assert!(first.is_empty());
    }
}

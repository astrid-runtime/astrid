//! Per-connection verified-principal binding accessors for `HostState`.
//! Split out of `host_state.rs` to stay under the 1000-line CI cap; included via `#[path]`.

use super::*;

/// The topic and normalized JSON body read from one authenticated client frame.
pub(crate) struct IngressPublication {
    pub(crate) topic: String,
    pub(crate) payload: String,
}

impl IngressPublication {
    pub(crate) fn from_frame(bytes: &[u8]) -> Option<Self> {
        let mut frame: serde_json::Value = serde_json::from_slice(bytes).ok()?;
        let topic = frame.get("topic")?.as_str()?.to_owned();
        let payload = Self::canonical_payload(frame.get_mut("payload")?)?;
        Some(Self { topic, payload })
    }

    pub(crate) fn canonical_payload(value: &mut serde_json::Value) -> Option<String> {
        value.sort_all_objects();
        serde_json::to_string(value).ok()
    }
}

impl HostState {
    /// Build a fresh, empty per-connection identity registry.
    ///
    /// Each registry belongs to the Store whose resource table allocated the handles.
    #[must_use]
    pub fn new_connection_principals() -> dashmap::DashMap<u32, ConnectionIdentity> {
        dashmap::DashMap::new()
    }

    /// Track inbound client lifecycle events for this Store's resource table.
    #[must_use]
    pub fn new_client_connections() -> dashmap::DashMap<u32, astrid_core::principal::PrincipalId> {
        dashmap::DashMap::new()
    }

    pub(crate) fn clear_ingress_frame(&mut self) {
        self.ingress_publication = None;
        self.ingress_principal = None;
        self.ingress_device_key_id = None;
        self.ingress_request_owner = None;
        self.ingress_origin = None;
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

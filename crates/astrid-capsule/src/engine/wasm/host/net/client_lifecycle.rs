//! Host-emitted client-connection lifecycle events for the kernel connection
//! tracker.
//!
//! The kernel keeps a per-principal active-connection count: `+1` on a
//! `client.v1.connect` bus event, `-1` on `client.v1.disconnect`, keyed by the
//! event's `principal` (see `astrid-kernel`'s `spawn_connection_tracker`).
//!
//! These two events are emitted HERE — by the host that owns the inbound uplink
//! socket — rather than by the uplink (capsule-cli) proxy. The proxy used to
//! emit them via `ipc::publish-as`, but the host's `publish-as` deliberately
//! ignores the guest-supplied principal and derives the effective principal
//! from the connection's verified identity (issues #45/#852). That identity is
//! recorded at the handshake and CLEARED on close, so the proxy's
//! `client.v1.disconnect` — published after the connection was already torn
//! down — lost its principal and was stamped `anonymous`. Connect incremented
//! the real principal, disconnect decremented `anonymous` (a saturating no-op),
//! and the real principal's counter leaked `+1` per connection, unbounded.
//!
//! Emitting from the host fixes this at the root: the host holds the
//! handshake-verified principal for the connection's whole lifetime (stored in
//! [`HostState::client_connections`](crate::engine::wasm::host_state::HostState::client_connections)),
//! so connect AND disconnect carry the IDENTICAL host-verified principal and
//! the counter balances. A legacy/unauthenticated peer balances on the reserved
//! `anonymous` identity.
//!
//! SECURITY INVARIANT: the stamped principal is ALWAYS the host-verified one
//! recorded at the handshake — never a value supplied by guest/capsule code.
//! Only INBOUND connections accepted on the uplink listener reach this path;
//! outbound TCP streams a capsule dials never do.

use astrid_core::principal::PrincipalId;
use astrid_events::AstridEvent;
use astrid_events::EventMetadata;
use astrid_events::ipc::{IpcMessage as InternalIpcMessage, IpcPayload, Topic};

use crate::engine::wasm::host_state::HostState;

/// `source` tag on the emitted event metadata, for audit/trace attribution.
const EVENT_SOURCE: &str = "net_client_lifecycle";

/// Record `principal` as the lifecycle identity of the inbound connection at
/// stream resource `rep` and emit `client.v1.connect` stamped with it.
///
/// Called from the `net.unix-listener.{accept, poll-accept}` path the moment a
/// verified (or `anonymous`) inbound connection is exposed as a stream
/// resource. The recorded principal survives until [`emit_client_disconnect`]
/// removes it at stream drop, guaranteeing the connect/disconnect pair balances
/// on the identical host-verified principal.
pub(super) fn register_and_emit_connect(state: &HostState, rep: u32, principal: PrincipalId) {
    state.client_connections.insert(rep, principal.clone());
    publish_lifecycle(
        state,
        Topic::client_connect(),
        IpcPayload::RawJson(serde_json::json!({})),
        &principal,
    );
}

/// Emit `client.v1.disconnect` for the inbound connection at stream resource
/// `rep`, stamped with the SAME host-verified principal recorded by
/// [`register_and_emit_connect`], and drop the registry entry.
///
/// A no-op for any rep that was never registered as an inbound client
/// connection — outbound TCP streams (`connect-tcp`) and non-net resources —
/// so a capsule-dialed socket dropping never moves the client counter.
pub(super) fn emit_client_disconnect(state: &HostState, rep: u32) {
    let Some((_, principal)) = state.client_connections.remove(&rep) else {
        return;
    };
    publish_lifecycle(
        state,
        Topic::client_disconnect(),
        IpcPayload::RawJson(serde_json::json!({ "reason": "socket closed" })),
        &principal,
    );
}

/// Publish a lifecycle event on the kernel event bus stamped with the
/// host-verified `principal`. The host is trusted, so this bypasses the
/// guest-facing publish capability/quota gates — but the principal is never
/// guest-controlled, so the anti-forge boundary is preserved.
fn publish_lifecycle(
    state: &HostState,
    topic: Topic,
    payload: IpcPayload,
    principal: &PrincipalId,
) {
    let message = InternalIpcMessage::new(topic, payload, state.capsule_uuid)
        .with_principal(principal.as_str());
    state.event_bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new(EVENT_SOURCE).with_session_id(state.capsule_uuid),
        message,
    });
}

#[cfg(test)]
#[path = "client_lifecycle_tests.rs"]
mod tests;

//! `astrid:ipc@1.0.0` host implementation.
//!
//! STUBBED to the new shape — every entry point compiles against the
//! per-domain WIT bindings, but most paths return `todo!()` pending
//! the resource-table integration. The previous u64-keyed subscription
//! map (`HostState.subscriptions`) is retained but no longer reachable
//! from these traits; follow-up work moves the receiver to the wasmtime
//! `ResourceTable` so `Subscription` resources can be handed out to the
//! guest cleanly.

#![allow(dead_code)] // helpers retained for the resource-table port-back

use wasmtime::component::Resource;
use wasmtime_wasi::p2::DynPollable;

use crate::engine::wasm::bindings::astrid::ipc::host::{
    self as ipc, ErrorCode, HostSubscription, InterceptorBinding, IpcEnvelope, IpcMessage,
    PrincipalAttribution, Subscription,
};
use crate::engine::wasm::host_state::HostState;
use astrid_events::AstridEvent;
use astrid_events::EventMetadata;
use astrid_events::ipc::{IpcMessage as InternalIpcMessage, IpcPayload};

/// Per-call payload cap (re-exported for shared use across modules).
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Check whether a subscription topic pattern is allowed by the capsule's
/// declared `ipc_subscribe` ACL patterns. Returns `Ok(())` if allowed,
/// or `Err(reason)` if denied.
pub(crate) fn check_subscribe_acl(
    capsule_id: &str,
    topic_pattern: &str,
    acl_patterns: &[String],
) -> Result<(), String> {
    if acl_patterns.is_empty() {
        return Err(format!(
            "Capsule '{capsule_id}' has no ipc_subscribe declarations"
        ));
    }
    if !acl_patterns
        .iter()
        .any(|acl| crate::topic::topic_matches(topic_pattern, acl))
    {
        return Err(format!(
            "Capsule '{capsule_id}' is not allowed to subscribe to topic '{topic_pattern}'"
        ));
    }
    Ok(())
}

/// Map an internal message's principal string into the typed
/// `PrincipalAttribution` variant emitted to the guest.
fn map_principal(msg: &InternalIpcMessage) -> PrincipalAttribution {
    match msg.principal.clone() {
        Some(p) => PrincipalAttribution::Verified(p),
        None => PrincipalAttribution::System,
    }
}

/// Convert an internal `IpcMessage` to the WIT-generated message type.
pub(crate) fn to_wit_message(msg: &InternalIpcMessage) -> IpcMessage {
    let payload = msg
        .payload
        .to_guest_bytes()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    IpcMessage {
        topic: msg.topic.clone(),
        payload,
        source_id: msg.source_id.to_string(),
        principal: map_principal(msg),
    }
}

/// Shared publish path used by [`ipc::Host::publish`] and
/// [`ipc::Host::publish_as`].
fn publish_inner(
    state: &mut HostState,
    topic: String,
    payload: String,
    principal_str: String,
) -> Result<(), ErrorCode> {
    if topic.len() > 256 {
        return Err(ErrorCode::InvalidInput);
    }

    let payload_len = payload.len();
    let principal = astrid_core::principal::PrincipalId::new(&principal_str)
        .unwrap_or_else(|_| state.effective_principal());
    let throughput_cap = usize::try_from(state.effective_profile().quotas.max_ipc_throughput_bytes)
        .unwrap_or(usize::MAX);
    state
        .ipc_limiter
        .check_quota(state.capsule_uuid, &principal, payload_len, throughput_cap)
        .map_err(|_| ErrorCode::RateLimited)?;

    if !crate::topic::has_valid_segments(&topic) {
        return Err(ErrorCode::InvalidInput);
    }
    if topic.split('.').count() > 8 {
        return Err(ErrorCode::InvalidInput);
    }
    if state.ipc_publish_patterns.is_empty() {
        return Err(ErrorCode::CapabilityDenied);
    }
    if !state
        .ipc_publish_patterns
        .iter()
        .any(|pattern| crate::topic::topic_matches(&topic, pattern))
    {
        return Err(ErrorCode::CapabilityDenied);
    }

    let payload_bytes = payload.as_bytes();
    if payload_bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(ErrorCode::InvalidInput);
    }

    let ipc_payload = match serde_json::from_slice::<serde_json::Value>(payload_bytes) {
        Ok(data) => IpcPayload::from_json_value(data),
        Err(_) => return Err(ErrorCode::InvalidInput),
    };

    let message = InternalIpcMessage::new(topic, ipc_payload, state.capsule_uuid)
        .with_principal(principal_str);

    state.event_bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("wasm_guest").with_session_id(state.capsule_uuid),
        message,
    });
    Ok(())
}

impl ipc::Host for HostState {
    fn publish(&mut self, topic: String, payload: String) -> Result<(), ErrorCode> {
        let principal_str = self
            .caller_context
            .as_ref()
            .and_then(|c| c.principal.clone())
            .unwrap_or_else(|| self.principal.to_string());
        publish_inner(self, topic, payload, principal_str)
    }

    fn publish_as(
        &mut self,
        topic: String,
        payload: String,
        principal: String,
    ) -> Result<(), ErrorCode> {
        if !self.has_uplink_capability {
            return Err(ErrorCode::CapabilityDenied);
        }
        if astrid_core::principal::PrincipalId::new(&principal).is_err() {
            return Err(ErrorCode::InvalidInput);
        }
        publish_inner(self, topic, payload, principal)
    }

    fn subscribe(&mut self, _topic_pattern: String) -> Result<Resource<Subscription>, ErrorCode> {
        // Subscription as a resource: pending the wasmtime ResourceTable
        // wiring. Production capsules used u64 handles before; the
        // resource API replaces those, but the receiver lifecycle and
        // ACL checks need to be re-plumbed.
        todo!("ipc.subscribe: Resource<Subscription> wiring pending")
    }

    fn get_interceptor_bindings(&mut self) -> Result<Vec<InterceptorBinding>, ErrorCode> {
        // Per-export world dispatch on the kernel side will rewire how
        // pre-registered interceptor handles are exposed; until then,
        // return what we know but mark the binding handle as 0 (it's
        // no longer a u64-addressable subscription id under the new ABI).
        Ok(self
            .interceptor_handles
            .iter()
            .map(|h| InterceptorBinding {
                handle_id: h.handle_id,
                action: h.action.clone(),
                topic: h.topic.clone(),
            })
            .collect())
    }
}

impl HostSubscription for HostState {
    fn poll(&mut self, _self_: Resource<Subscription>) -> Result<IpcEnvelope, ErrorCode> {
        todo!("Subscription.poll: ResourceTable wiring pending")
    }

    fn recv(
        &mut self,
        _self_: Resource<Subscription>,
        _timeout_ms: u64,
    ) -> Result<IpcEnvelope, ErrorCode> {
        todo!("Subscription.recv: ResourceTable wiring pending")
    }

    fn subscribe_readiness(&mut self, _self_: Resource<Subscription>) -> Resource<DynPollable> {
        todo!("Subscription.subscribe_readiness: pollable wiring pending")
    }

    fn drop(&mut self, _rep: Resource<Subscription>) -> wasmtime::Result<()> {
        Ok(())
    }
}

// Tests live in `ipc_tests.rs` but reference the previous u64-handle
// API. Re-enable after the Subscription resource-table integration lands.
//
// #[cfg(test)]
// #[path = "ipc_tests.rs"]
// mod tests;

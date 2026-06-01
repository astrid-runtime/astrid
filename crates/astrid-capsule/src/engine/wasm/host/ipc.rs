//! `astrid:ipc@1.0.0` host implementation.
//!
//! Subscriptions are first-class wasmtime resources. `subscribe` allocates
//! an `EventReceiver` against the kernel event bus, stores it in the
//! capsule's resource table, and hands back a `Resource<Subscription>`.
//! All drop / lifetime / cross-capsule isolation rides wasmtime's
//! resource machinery — there is no parallel `HashMap<u64, EventReceiver>`
//! on `HostState` anymore.
//!
//! Audit envelope: every publish / publish-as / subscribe / poll / recv
//! / drop emits a tracing event under `target = "astrid.audit.ipc"` with
//! capsule + principal + topic + message count. Blocking `recv` races
//! against the calling capsule's cancellation token so capsule unload
//! always wins over a stuck wait.

use std::sync::Arc;

use tokio::sync::Mutex;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::DynPollable;

use crate::engine::wasm::bindings::astrid::ipc::host::{
    self as ipc, ErrorCode, HostSubscription, InterceptorBinding, IpcEnvelope,
    IpcMessage as WitIpcMessage, PrincipalAttribution, Subscription,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use astrid_events::AstridEvent;
use astrid_events::EventMetadata;
use astrid_events::EventReceiver;
use astrid_events::ipc::{IpcMessage as InternalIpcMessage, IpcPayload};

/// Per-call payload cap. Matches the IPC bus message-size ceiling.
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Per-call drain cap so a runaway publisher can't blow guest memory on a
/// single recv/poll.
const MAX_DRAIN_BYTES: usize = MAX_PAYLOAD_BYTES;

/// Per-capsule subscription cap. Defense-in-depth on top of the per-principal
/// profile quota.
const MAX_SUBSCRIPTIONS: usize = 128;

/// Maximum blocking-recv timeout in milliseconds. Larger values are clamped.
const MAX_RECV_TIMEOUT_MS: u64 = 60_000;

/// Storage type for `Resource<Subscription>` entries in the wasmtime
/// resource table.
///
/// The `EventReceiver` is wrapped in `Arc<Mutex<…>>` so a blocking
/// `recv` can hold an exclusive borrow on the receiver across the
/// `bounded_block_on_cancellable` await without keeping the wasmtime
/// `ResourceTable` borrowed for the duration of the wait. A naive
/// `get_mut` on the table would force `&mut self.resource_table` to
/// outlive the await, blocking every other host fn the guest might
/// want to call from a co-running stream.
///
/// Wasmtime stores are single-threaded for the WASM guest, so the
/// `Mutex` is contention-free in practice — its job is to make the
/// borrow checker happy across the await boundary, not to coordinate
/// real concurrent access.
pub(super) struct SubscriptionEntry {
    pub(super) receiver: Arc<Mutex<EventReceiver>>,
    pub(super) topic_pattern: String,
}

/// Drain result returned by `drain_receiver`.
struct DrainResult {
    messages: Vec<InternalIpcMessage>,
    dropped: u64,
    lagged: u64,
}

/// Drain all available IPC messages from a receiver (non-blocking).
fn drain_receiver(receiver: &mut EventReceiver, max_payload_bytes: usize) -> DrainResult {
    let mut messages = Vec::new();
    let mut payload_bytes: usize = 0;
    let mut dropped: u64 = 0;
    while let Some(event) = receiver.try_recv() {
        if let AstridEvent::Ipc { message, .. } = &*event {
            let msg_len = serde_json::to_vec(&message.payload)
                .map(|v| v.len())
                .unwrap_or(max_payload_bytes);
            if payload_bytes + msg_len > max_payload_bytes {
                dropped += 1;
                break;
            }
            messages.push(message.clone());
            payload_bytes += msg_len;
        }
    }
    let lagged = receiver.drain_lagged();
    DrainResult {
        messages,
        dropped,
        lagged,
    }
}

/// Truncate a drained batch so every retained message shares the same
/// publisher principal as the first — the per-recv principal context
/// installed by `install_recv_invocation_context` is keyed off a single
/// principal, so mixed batches would silently mis-stamp tail messages.
fn truncate_to_homogeneous_principal(messages: &mut Vec<InternalIpcMessage>) {
    let Some(first) = messages.first() else {
        return;
    };
    let first_principal = first.principal.clone();
    let first_match = messages
        .iter()
        .position(|m| m.principal != first_principal)
        .unwrap_or(messages.len());
    if first_match < messages.len() {
        let dropped = messages.len() - first_match;
        tracing::warn!(
            kept = first_match,
            dropped,
            first_principal = first_principal.as_deref().unwrap_or("<none>"),
            security_event = true,
            "ipc::recv: mixed-principal batch truncated to first publisher's messages",
        );
        messages.truncate(first_match);
    }
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
fn to_wit_message(msg: &InternalIpcMessage) -> WitIpcMessage {
    let payload = msg
        .payload
        .to_guest_bytes()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    WitIpcMessage {
        topic: msg.topic.clone(),
        payload,
        source_id: msg.source_id.to_string(),
        principal: map_principal(msg),
    }
}

fn drain_to_envelope(drain: &DrainResult) -> IpcEnvelope {
    IpcEnvelope {
        messages: drain.messages.iter().map(to_wit_message).collect(),
        dropped: drain.dropped,
        lagged: drain.lagged,
    }
}

/// Audit a top-level ipc host fn invocation.
fn audit_ipc<T, E: std::fmt::Debug>(
    state: &HostState,
    op: &'static str,
    topic: &str,
    bytes: u64,
    result: &Result<T, E>,
) {
    let capsule_id = state.capsule_id.as_str();
    let principal = state.effective_principal();
    match result {
        Ok(_) => tracing::debug!(
            target: "astrid.audit.ipc",
            %capsule_id,
            %principal,
            fn = op,
            topic,
            bytes,
            "audit",
        ),
        Err(e) => tracing::debug!(
            target: "astrid.audit.ipc",
            %capsule_id,
            %principal,
            fn = op,
            topic,
            error = ?e,
            "audit",
        ),
    }
}

/// Check whether `topic_pattern` is allowed by the capsule's
/// `ipc_subscribe` ACL.
fn check_subscribe_acl(state: &HostState, topic_pattern: &str) -> Result<(), ErrorCode> {
    if state.ipc_subscribe_patterns.is_empty() {
        return Err(ErrorCode::CapabilityDenied);
    }
    if !state
        .ipc_subscribe_patterns
        .iter()
        .any(|acl| crate::topic::topic_matches(topic_pattern, acl))
    {
        return Err(ErrorCode::CapabilityDenied);
    }
    Ok(())
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
        let bytes = payload.len() as u64;
        let topic_for_audit = topic.clone();
        let result = publish_inner(self, topic, payload, principal_str);
        audit_ipc(
            self,
            "astrid:ipc/host.publish",
            &topic_for_audit,
            bytes,
            &result,
        );
        result
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
        let bytes = payload.len() as u64;
        let topic_for_audit = topic.clone();
        let result = publish_inner(self, topic, payload, principal);
        audit_ipc(
            self,
            "astrid:ipc/host.publish-as",
            &topic_for_audit,
            bytes,
            &result,
        );
        result
    }

    fn subscribe(&mut self, topic_pattern: String) -> Result<Resource<Subscription>, ErrorCode> {
        if topic_pattern.len() > 256 {
            return Err(ErrorCode::InvalidInput);
        }
        if !crate::topic::has_valid_segments(&topic_pattern) {
            return Err(ErrorCode::InvalidInput);
        }
        // EventReceiver::matches only supports trailing-suffix wildcards
        // (e.g. `foo.bar.*`) and exact matches. Reject mid-segment
        // wildcards (`a.*.b`) up front.
        {
            let mut segments = topic_pattern.split('.');
            #[expect(clippy::search_is_some)]
            if segments.position(|s| s == "*").is_some() && segments.next().is_some() {
                return Err(ErrorCode::InvalidInput);
            }
        }
        if topic_pattern.split('.').count() > 8 {
            return Err(ErrorCode::InvalidInput);
        }

        check_subscribe_acl(self, &topic_pattern)?;

        if self.subscription_count >= MAX_SUBSCRIPTIONS {
            return Err(ErrorCode::Quota);
        }

        let receiver = self.event_bus.subscribe_topic(topic_pattern.clone());
        let entry = SubscriptionEntry {
            receiver: Arc::new(Mutex::new(receiver)),
            topic_pattern: topic_pattern.clone(),
        };
        let res = self
            .resource_table
            .push(entry)
            .map_err(|e| ErrorCode::Unknown(format!("resource table: {e}")))?;
        self.subscription_count += 1;
        let result: Result<Resource<Subscription>, ErrorCode> = Ok(Resource::new_own(res.rep()));
        audit_ipc(
            self,
            "astrid:ipc/host.subscribe",
            &topic_pattern,
            0,
            &result,
        );
        result
    }

    fn get_interceptor_bindings(&mut self) -> Result<Vec<InterceptorBinding>, ErrorCode> {
        // Interceptor bindings are metadata under the new ABI — the
        // kernel dispatches matching messages via `astrid-hook-trigger`,
        // and the capsule cannot turn the `handle-id: u64` back into a
        // `Resource<Subscription>`. Returning the list lets capsules
        // enumerate what they're subscribed to (for debugging and
        // tooling); calls do not consume from these handles.
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
    fn poll(&mut self, self_: Resource<Subscription>) -> Result<IpcEnvelope, ErrorCode> {
        let rep = self_.rep();
        let entry = self
            .resource_table
            .get::<SubscriptionEntry>(&Resource::new_borrow(rep))
            .map_err(|_| ErrorCode::Closed)?;
        let topic_for_audit = entry.topic_pattern.clone();
        let receiver_arc = Arc::clone(&entry.receiver);

        // Drain through the shared lock. `try_lock` is fine — wasmtime
        // stores are single-threaded so contention is impossible; we
        // would only hit a blocked lock if someone smuggled an Arc
        // across a thread boundary, which the kernel never does.
        let drain = {
            let mut receiver = receiver_arc
                .try_lock()
                .expect("Subscription receiver Arc accessed across threads");
            drain_receiver(&mut receiver, MAX_DRAIN_BYTES)
        };
        let mut drain = drain;
        truncate_to_homogeneous_principal(&mut drain.messages);

        // Empty drains keep the prior caller context. A run-loop
        // capsule (prompt-builder, registry) frequently dispatches
        // its own follow-up publishes between recvs — e.g. fetching
        // session messages after a hook fan-out timed out. Clearing
        // here would force those follow-up publishes to fall back
        // to the capsule's load-time principal, which silently
        // flipped the orchestration chain to `default` mid-flow
        // under any non-default caller.
        if let Some(first) = drain.messages.first() {
            self.install_recv_invocation_context(first);
        }

        let count = drain.messages.len() as u64;
        let result: Result<IpcEnvelope, ErrorCode> = Ok(drain_to_envelope(&drain));
        audit_ipc(
            self,
            "astrid:ipc/host.subscription.poll",
            &topic_for_audit,
            count,
            &result,
        );
        result
    }

    fn recv(
        &mut self,
        self_: Resource<Subscription>,
        timeout_ms: u64,
    ) -> Result<IpcEnvelope, ErrorCode> {
        let timeout_ms = timeout_ms.min(MAX_RECV_TIMEOUT_MS);
        let rep = self_.rep();

        // Borrow the entry to clone its receiver Arc. The resource
        // stays in the table — the guest's `Resource<Subscription>`
        // remains valid across repeated `recv` calls.
        let (receiver_arc, topic_for_audit) = {
            let entry = self
                .resource_table
                .get::<SubscriptionEntry>(&Resource::new_borrow(rep))
                .map_err(|_| ErrorCode::Closed)?;
            (Arc::clone(&entry.receiver), entry.topic_pattern.clone())
        };

        let runtime_handle = self.runtime_handle.clone();
        let cancel_token = self.cancel_token.clone();
        let host_semaphore = self.host_semaphore.clone();

        let receiver_for_wait = Arc::clone(&receiver_arc);
        let event = util::bounded_block_on_cancellable(
            &runtime_handle,
            &host_semaphore,
            &cancel_token,
            async move {
                let mut receiver = receiver_for_wait.lock().await;
                tokio::time::timeout(
                    std::time::Duration::from_millis(timeout_ms),
                    receiver.recv(),
                )
                .await
                .ok()
                .flatten()
            },
        )
        .flatten();

        let mut drain = {
            let mut receiver = receiver_arc
                .try_lock()
                .expect("Subscription receiver Arc accessed across threads");
            drain_receiver(&mut receiver, MAX_DRAIN_BYTES)
        };

        if let Some(event) = event
            && let AstridEvent::Ipc { message, .. } = &*event
        {
            drain.messages.insert(0, message.clone());
        }

        truncate_to_homogeneous_principal(&mut drain.messages);
        // Empty drains keep the prior caller context (see the
        // matching note above `poll`'s drain).
        if let Some(first) = drain.messages.first() {
            self.install_recv_invocation_context(first);
        }

        let count = drain.messages.len() as u64;
        let result: Result<IpcEnvelope, ErrorCode> = Ok(drain_to_envelope(&drain));
        audit_ipc(
            self,
            "astrid:ipc/host.subscription.recv",
            &topic_for_audit,
            count,
            &result,
        );
        result
    }

    fn subscribe_readiness(&mut self, _self_: Resource<Subscription>) -> Resource<DynPollable> {
        // Real pollable wiring (sourced from the receiver's notify
        // channel) lands with the dedicated pollable commit. Until
        // then, hand out an always-ready sentinel so guests get a
        // clean poll-then-recv loop rather than a host panic.
        super::stubs::always_ready_pollable(&mut self.resource_table)
    }

    fn drop(&mut self, rep: Resource<Subscription>) -> wasmtime::Result<()> {
        if self
            .resource_table
            .delete::<SubscriptionEntry>(Resource::new_own(rep.rep()))
            .is_ok()
        {
            self.subscription_count = self.subscription_count.saturating_sub(1);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Regression tests for the multi-principal recv batching fix.
    //!
    //! Background (PR #752 review): a drained batch of subscription
    //! messages must be truncated at the first publisher-principal
    //! boundary, otherwise tail messages get stamped with the first
    //! message's principal context and break attribution.
    use super::truncate_to_homogeneous_principal;
    use astrid_events::ipc::{IpcMessage as InternalIpcMessage, IpcPayload};
    use serde_json::json;
    use uuid::Uuid;

    fn msg(principal: Option<&str>) -> InternalIpcMessage {
        let mut m =
            InternalIpcMessage::new("test.topic", IpcPayload::RawJson(json!({})), Uuid::nil());
        m.principal = principal.map(String::from);
        m
    }

    #[test]
    fn empty_batch_is_noop() {
        let mut batch: Vec<InternalIpcMessage> = vec![];
        truncate_to_homogeneous_principal(&mut batch);
        assert!(batch.is_empty());
    }

    #[test]
    fn homogeneous_batch_is_preserved() {
        let mut batch = vec![msg(Some("alice")), msg(Some("alice")), msg(Some("alice"))];
        truncate_to_homogeneous_principal(&mut batch);
        assert_eq!(batch.len(), 3);
    }

    #[test]
    fn mixed_principal_truncates_at_first_boundary() {
        let mut batch = vec![msg(Some("alice")), msg(Some("alice")), msg(Some("bob"))];
        truncate_to_homogeneous_principal(&mut batch);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].principal.as_deref(), Some("alice"));
        assert_eq!(batch[1].principal.as_deref(), Some("alice"));
    }

    #[test]
    fn system_then_principal_truncates() {
        let mut batch = vec![msg(None), msg(None), msg(Some("alice"))];
        truncate_to_homogeneous_principal(&mut batch);
        assert_eq!(batch.len(), 2);
        assert!(batch[0].principal.is_none());
        assert!(batch[1].principal.is_none());
    }

    #[test]
    fn principal_then_system_truncates() {
        let mut batch = vec![msg(Some("alice")), msg(None)];
        truncate_to_homogeneous_principal(&mut batch);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].principal.as_deref(), Some("alice"));
    }

    #[test]
    fn boundary_at_index_one_keeps_only_first() {
        let mut batch = vec![msg(Some("alice")), msg(Some("bob")), msg(Some("alice"))];
        truncate_to_homogeneous_principal(&mut batch);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].principal.as_deref(), Some("alice"));
    }
}

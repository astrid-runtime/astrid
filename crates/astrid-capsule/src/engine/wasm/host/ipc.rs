//! `astrid:ipc@1.0.0` host implementation.
//!
//! Subscriptions are first-class wasmtime resources. `subscribe` allocates
//! a [`RoutedEventReceiver`] against the kernel event bus, stores it in
//! the capsule's resource table, and hands back a `Resource<Subscription>`.
//! All drop / lifetime / cross-capsule isolation rides wasmtime's
//! resource machinery — there is no parallel `HashMap<u64, EventReceiver>`
//! on `HostState` anymore.
//!
//! Per-(capsule, topic, principal) isolation lives one layer down in
//! `astrid_events::route`: each guest subscription gets its own routed
//! entry in the bus's `routes` table, with per-principal FIFO queues
//! drained under deficit-round-robin. The legacy "pending bucket
//! requeue" workaround that lived here is gone — routed receivers
//! never see mixed-principal batches in the first place because the
//! demux happens publish-side, not consumer-side.
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
use astrid_events::RoutedEventReceiver;
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
/// The [`RoutedEventReceiver`] is wrapped in `Arc<Mutex<…>>` so a
/// blocking `recv` can hold an exclusive borrow on the receiver across
/// the `bounded_block_on_cancellable` await without keeping the wasmtime
/// `ResourceTable` borrowed for the duration of the wait. Wasmtime
/// stores are single-threaded for the WASM guest, so the `Mutex` is
/// contention-free in practice — its job is to make the borrow checker
/// happy across the await boundary.
pub(super) struct SubscriptionEntry {
    pub(super) receiver: Arc<Mutex<RoutedEventReceiver>>,
    pub(super) topic_pattern: String,
}

/// Convert an `AstridEvent::Ipc` arc into the internal message clone the
/// WIT translation layer expects. Returns `None` for non-IPC events;
/// the routed demux already filters non-IPC, so this is just defensive.
fn extract_message(event: &Arc<AstridEvent>) -> Option<InternalIpcMessage> {
    match &**event {
        AstridEvent::Ipc { message, .. } => Some(message.clone()),
        _ => None,
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

fn envelope_from(messages: Vec<InternalIpcMessage>, lagged: u64) -> IpcEnvelope {
    IpcEnvelope {
        messages: messages.iter().map(to_wit_message).collect(),
        dropped: 0,
        lagged,
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
        // TopicMatcher (route layer) supports both trailing-suffix
        // wildcards and mid-segment single-segment wildcards. Reject
        // multiple wildcards in one pattern to keep the ACL surface
        // small.
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

        // Per-(capsule, topic, principal) routed receiver. The bus
        // owns a publish-side demux that buckets messages by the
        // originating principal, so the guest never sees a
        // mixed-principal batch and the cross-principal fairness lives
        // in the bus's DRR drain — no consumer-side requeue logic
        // needed here (#813).
        let receiver = self.event_bus.subscribe_topic_routed(
            self.capsule_uuid,
            topic_pattern.clone(),
            self.capsule_id.as_str().to_string(),
            "capsule_guest",
        );
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
            .get_mut::<SubscriptionEntry>(&Resource::new_borrow(rep))
            .map_err(|_| ErrorCode::Closed)?;
        let topic_for_audit = entry.topic_pattern.clone();
        let receiver_arc = Arc::clone(&entry.receiver);

        // Drain the routed sub via DRR. The bus's per-route DRR
        // guarantees fairness; we just budget the byte total per call.
        let drained = {
            let mut receiver = receiver_arc
                .try_lock()
                .expect("Subscription receiver Arc accessed across threads");
            receiver.try_drain(MAX_DRAIN_BYTES)
        };
        let messages: Vec<InternalIpcMessage> =
            drained.iter().filter_map(extract_message).collect();
        let lagged = {
            let mut receiver = receiver_arc
                .try_lock()
                .expect("Subscription receiver Arc accessed across threads");
            receiver.drain_lagged()
        };

        // Empty drains keep the prior caller context. A run-loop
        // capsule (prompt-builder, registry) frequently dispatches its
        // own follow-up publishes between recvs — e.g. fetching session
        // messages after a hook fan-out timed out. Clearing here would
        // force those follow-up publishes to fall back to the
        // capsule's load-time principal.
        if let Some(first) = messages.first() {
            self.install_recv_invocation_context(first);
        }

        let count = messages.len() as u64;
        let result: Result<IpcEnvelope, ErrorCode> = Ok(envelope_from(messages, lagged));
        audit_ipc(
            self,
            "astrid:ipc/host.subscription.poll",
            &topic_for_audit,
            count,
            &result,
        );
        result
    }

    async fn recv(
        &mut self,
        self_: Resource<Subscription>,
        timeout_ms: u64,
    ) -> Result<IpcEnvelope, ErrorCode> {
        let timeout_ms = timeout_ms.min(MAX_RECV_TIMEOUT_MS);
        let rep = self_.rep();

        let (receiver_arc, topic_for_audit) = {
            let entry = self
                .resource_table
                .get_mut::<SubscriptionEntry>(&Resource::new_borrow(rep))
                .map_err(|_| ErrorCode::Closed)?;
            (Arc::clone(&entry.receiver), entry.topic_pattern.clone())
        };

        // Wait for at least one event up to `timeout_ms`, then drain
        // additional events without further blocking. This is an `async`
        // host fn (see the bindgen async selector), so we `.await` the
        // wait directly via `bounded_await_cancellable` — the tokio worker
        // is freed while the receiver is idle rather than pinned via
        // `block_in_place` (issue #816).
        let cancel_token = self.cancel_token.clone();
        let host_semaphore = self.host_semaphore.clone();
        let receiver_for_wait = Arc::clone(&receiver_arc);
        let first = util::bounded_await_cancellable(&host_semaphore, &cancel_token, async move {
            let mut receiver = receiver_for_wait.lock().await;
            receiver
                .recv(Some(std::time::Duration::from_millis(timeout_ms)))
                .await
        })
        .await
        .flatten();

        let mut messages: Vec<InternalIpcMessage> = Vec::new();
        let mut consumed = 0usize;
        if let Some(event) = first
            && let Some(msg) = extract_message(&event)
        {
            consumed = msg
                .payload
                .to_guest_bytes()
                .map(|v| v.len())
                .unwrap_or(0)
                .saturating_add(msg.topic.len());
            messages.push(msg);
        }

        let drained = {
            let mut receiver = receiver_arc
                .try_lock()
                .expect("Subscription receiver Arc accessed across threads");
            receiver.try_drain(MAX_DRAIN_BYTES.saturating_sub(consumed))
        };
        for event in &drained {
            if let Some(msg) = extract_message(event) {
                messages.push(msg);
            }
        }

        let lagged = {
            let mut receiver = receiver_arc
                .try_lock()
                .expect("Subscription receiver Arc accessed across threads");
            receiver.drain_lagged()
        };

        if let Some(first) = messages.first() {
            self.install_recv_invocation_context(first);
        }

        let count = messages.len() as u64;
        let result: Result<IpcEnvelope, ErrorCode> = Ok(envelope_from(messages, lagged));
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

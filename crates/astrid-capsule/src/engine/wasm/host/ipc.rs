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

use std::collections::{HashMap, VecDeque};
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

/// Maximum number of queued messages buffered per principal bucket.
/// Tail messages from a mixed-principal drain are partitioned into
/// per-principal `pending` buckets so the next recv/poll surfaces them
/// instead of dropping them. Overflow drops oldest-first.
const PENDING_PER_PRINCIPAL: usize = 64;

/// Maximum number of distinct principal buckets a subscription may
/// queue at once. When a new principal would exceed this cap, the
/// least-recently-pushed bucket is evicted entirely (audited).
const PENDING_MAX_PRINCIPALS: usize = 8;

/// Counter: messages dropped from the pending tail queue when a
/// per-principal bucket overflowed or a 9th-principal bucket forced
/// eviction. Labelled by `capsule` and a bounded `principal_class`
/// (`system` / `user` / `agent`) — never the raw `PrincipalId`, which
/// would explode label cardinality.
const METRIC_PENDING_TAIL_OVERFLOW_TOTAL: &str = "astrid_capsule_pending_tail_overflow_total";

/// Map an `InternalIpcMessage::principal` (Option<String>) to a bounded
/// telemetry class. The mapping mirrors `PrincipalId` naming conventions:
/// the kernel-internal "system" principal stays in its own bucket;
/// everything else groups by an `agent.*` prefix heuristic so a flood of
/// distinct ephemeral agents doesn't inflate the metric label set.
fn principal_class(principal: Option<&str>) -> &'static str {
    match principal {
        None => "system",
        Some(p) if p.starts_with("agent.") || p.starts_with("agent:") => "agent",
        Some(_) => "user",
    }
}

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
    /// Per-principal FIFO queues for messages whose principal didn't
    /// match the head of a drained batch. The next `poll`/`recv` consumes
    /// from these before pulling fresh events from the broadcast
    /// receiver, so cross-principal traffic is preserved instead of
    /// silently truncated.
    ///
    /// `principal_order` records the insertion order of distinct
    /// principal keys for fair round-robin draining; HashMap iteration
    /// is randomized per-process and would otherwise starve specific
    /// principals across recv cycles.
    pub(super) pending: HashMap<Option<String>, VecDeque<InternalIpcMessage>>,
    pub(super) principal_order: VecDeque<Option<String>>,
}

/// Drain result returned by `drain_receiver`.
struct DrainResult {
    messages: Vec<InternalIpcMessage>,
    dropped: u64,
    lagged: u64,
}

/// Drain all available IPC messages from a receiver (non-blocking).
///
/// `start_bytes` is the number of payload bytes already consumed by an
/// upstream drain (e.g. the pending tail queues). The receiver drain
/// budgets against `max_payload_bytes - start_bytes` so the per-call
/// 1MiB cap stays effective across the pending + fresh path.
fn drain_receiver(
    receiver: &mut EventReceiver,
    max_payload_bytes: usize,
    start_bytes: usize,
) -> DrainResult {
    let mut messages = Vec::new();
    let mut payload_bytes: usize = start_bytes;
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

/// Push a message into a per-principal `pending` bucket, applying the
/// per-bucket and per-bucket-count caps. Drops oldest-first inside a
/// bucket; evicts the least-recently-pushed bucket entirely when a new
/// principal would exceed [`PENDING_MAX_PRINCIPALS`]. Each drop emits an
/// audit-tagged ERROR and bumps [`METRIC_PENDING_TAIL_OVERFLOW_TOTAL`].
fn push_with_overflow(
    pending: &mut HashMap<Option<String>, VecDeque<InternalIpcMessage>>,
    principal_order: &mut VecDeque<Option<String>>,
    msg: InternalIpcMessage,
    capsule_id: &str,
    subscription_rep: u32,
) {
    let key = msg.principal.clone();
    let is_new_bucket = !pending.contains_key(&key);

    if is_new_bucket
        && pending.len() >= PENDING_MAX_PRINCIPALS
        && let Some(evict_key) = principal_order.pop_front()
        && let Some(bucket) = pending.remove(&evict_key)
    {
        let evicted = bucket.len();
        let class = principal_class(evict_key.as_deref());
        tracing::error!(
            target: "astrid.audit.ipc",
            security_event = true,
            capsule_id,
            subscription_id = subscription_rep,
            principal = evict_key.as_deref().unwrap_or("<none>"),
            principal_cap = PENDING_MAX_PRINCIPALS,
            evicted,
            "ipc::recv: principal-bucket cap reached, evicting least-recently-pushed bucket",
        );
        metrics::counter!(
            METRIC_PENDING_TAIL_OVERFLOW_TOTAL,
            "capsule" => capsule_id.to_string(),
            "principal_class" => class,
        )
        .increment(evicted as u64);
    }

    let bucket = pending.entry(key.clone()).or_default();
    if is_new_bucket {
        principal_order.push_back(key.clone());
    }

    if bucket.len() >= PENDING_PER_PRINCIPAL
        && let Some(dropped) = bucket.pop_front()
    {
        let class = principal_class(key.as_deref());
        tracing::error!(
            target: "astrid.audit.ipc",
            security_event = true,
            capsule_id,
            subscription_id = subscription_rep,
            principal = key.as_deref().unwrap_or("<none>"),
            pending_cap = PENDING_PER_PRINCIPAL,
            oldest_topic = %dropped.topic,
            "ipc::recv: pending tail overflow, dropping oldest queued message",
        );
        metrics::counter!(
            METRIC_PENDING_TAIL_OVERFLOW_TOTAL,
            "capsule" => capsule_id.to_string(),
            "principal_class" => class,
        )
        .increment(1);
    }
    bucket.push_back(msg);
}

/// Partition a mixed-principal batch: keep the head's homogeneous prefix
/// in `messages`, route the rest into per-principal `pending` buckets so
/// the next recv/poll surfaces them under the correct principal context.
///
/// Returns `(kept, requeued)` for audit and test assertions.
fn requeue_mixed_principal_tail(
    messages: &mut Vec<InternalIpcMessage>,
    pending: &mut HashMap<Option<String>, VecDeque<InternalIpcMessage>>,
    principal_order: &mut VecDeque<Option<String>>,
    capsule_id: &str,
    subscription_rep: u32,
) -> (usize, usize) {
    let Some(first) = messages.first() else {
        return (0, 0);
    };
    let first_principal = first.principal.clone();
    let split_at = messages
        .iter()
        .position(|m| m.principal != first_principal)
        .unwrap_or(messages.len());
    if split_at == messages.len() {
        return (messages.len(), 0);
    }
    let tail: Vec<InternalIpcMessage> = messages.drain(split_at..).collect();
    let requeued = tail.len();
    for msg in tail {
        push_with_overflow(pending, principal_order, msg, capsule_id, subscription_rep);
    }
    (messages.len(), requeued)
}

/// Drain the per-principal pending queues into `messages` in
/// round-robin principal-FIFO order (one message per visit per principal
/// before revisiting). Respects the per-call byte budget the receiver
/// drain enforces. Returns the number of bytes consumed so the caller
/// can charge the budget for the broadcast-receiver drain.
fn drain_pending(
    messages: &mut Vec<InternalIpcMessage>,
    pending: &mut HashMap<Option<String>, VecDeque<InternalIpcMessage>>,
    principal_order: &mut VecDeque<Option<String>>,
    max_payload_bytes: usize,
) -> usize {
    let mut payload_bytes: usize = 0;
    // Loop until either all buckets are empty or the byte budget is
    // exhausted. Each iteration of the outer loop visits every
    // principal once (FIFO), guaranteeing round-robin fairness across
    // any number of buckets and message counts.
    loop {
        if principal_order.is_empty() {
            break;
        }
        let mut progress = false;
        let visit = principal_order.len();
        for _ in 0..visit {
            let Some(key) = principal_order.pop_front() else {
                break;
            };
            let Some(bucket) = pending.get_mut(&key) else {
                continue;
            };
            let Some(front) = bucket.front() else {
                pending.remove(&key);
                continue;
            };
            let msg_len = serde_json::to_vec(&front.payload)
                .map(|v| v.len())
                .unwrap_or(max_payload_bytes);
            if payload_bytes + msg_len > max_payload_bytes {
                principal_order.push_front(key);
                return payload_bytes;
            }
            let msg = bucket.pop_front().expect("front checked above");
            payload_bytes += msg_len;
            messages.push(msg);
            progress = true;
            if bucket.is_empty() {
                pending.remove(&key);
            } else {
                principal_order.push_back(key);
            }
        }
        if !progress {
            break;
        }
    }
    payload_bytes
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
            pending: HashMap::new(),
            principal_order: VecDeque::new(),
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
        let capsule_id = self.capsule_id.as_str().to_string();
        let entry = self
            .resource_table
            .get_mut::<SubscriptionEntry>(&Resource::new_borrow(rep))
            .map_err(|_| ErrorCode::Closed)?;
        let topic_for_audit = entry.topic_pattern.clone();
        let receiver_arc = Arc::clone(&entry.receiver);

        let mut messages: Vec<InternalIpcMessage> = Vec::new();
        let pending_bytes = drain_pending(
            &mut messages,
            &mut entry.pending,
            &mut entry.principal_order,
            MAX_DRAIN_BYTES,
        );

        // Drain through the shared lock. `try_lock` is fine — wasmtime
        // stores are single-threaded so contention is impossible; we
        // would only hit a blocked lock if someone smuggled an Arc
        // across a thread boundary, which the kernel never does.
        let mut drain = {
            let mut receiver = receiver_arc
                .try_lock()
                .expect("Subscription receiver Arc accessed across threads");
            drain_receiver(&mut receiver, MAX_DRAIN_BYTES, pending_bytes)
        };
        messages.append(&mut drain.messages);
        drain.messages = messages;

        let (_kept, _requeued) = requeue_mixed_principal_tail(
            &mut drain.messages,
            &mut entry.pending,
            &mut entry.principal_order,
            &capsule_id,
            rep,
        );

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
        let capsule_id = self.capsule_id.as_str().to_string();

        // Borrow the entry to clone its receiver Arc and drain any
        // pending tail messages that requeued from a prior mixed-principal
        // batch. The resource stays in the table — the guest's
        // `Resource<Subscription>` remains valid across repeated `recv`
        // calls.
        let (receiver_arc, topic_for_audit, mut prequeued, pending_bytes) = {
            let entry = self
                .resource_table
                .get_mut::<SubscriptionEntry>(&Resource::new_borrow(rep))
                .map_err(|_| ErrorCode::Closed)?;
            let mut prequeued: Vec<InternalIpcMessage> = Vec::new();
            let bytes = drain_pending(
                &mut prequeued,
                &mut entry.pending,
                &mut entry.principal_order,
                MAX_DRAIN_BYTES,
            );
            (
                Arc::clone(&entry.receiver),
                entry.topic_pattern.clone(),
                prequeued,
                bytes,
            )
        };

        // If pending already gave us at least one message, skip the
        // blocking wait — the guest has work to do without us parking
        // the host worker on the broadcast receiver.
        let event = if prequeued.is_empty() {
            let runtime_handle = self.runtime_handle.clone();
            let cancel_token = self.cancel_token.clone();
            let host_semaphore = self.host_semaphore.clone();
            let receiver_for_wait = Arc::clone(&receiver_arc);
            util::bounded_block_on_cancellable(
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
            .flatten()
        } else {
            None
        };

        let mut drain = {
            let mut receiver = receiver_arc
                .try_lock()
                .expect("Subscription receiver Arc accessed across threads");
            drain_receiver(&mut receiver, MAX_DRAIN_BYTES, pending_bytes)
        };

        if let Some(event) = event
            && let AstridEvent::Ipc { message, .. } = &*event
        {
            drain.messages.insert(0, message.clone());
        }

        if !prequeued.is_empty() {
            prequeued.append(&mut drain.messages);
            drain.messages = prequeued;
        }

        // Re-borrow the entry to thread per-principal buckets into the
        // requeue path. The receiver Arc was already extracted above.
        let entry = self
            .resource_table
            .get_mut::<SubscriptionEntry>(&Resource::new_borrow(rep))
            .map_err(|_| ErrorCode::Closed)?;
        let (_kept, _requeued) = requeue_mixed_principal_tail(
            &mut drain.messages,
            &mut entry.pending,
            &mut entry.principal_order,
            &capsule_id,
            rep,
        );

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
    //! Regression tests for the non-destructive recv batching fix
    //! (#813). A mixed-principal drain previously truncated at the
    //! first principal boundary and dropped the tail — collapsing
    //! delivery under cross-principal traffic. The tail now requeues
    //! into per-principal buckets so the next recv/poll surfaces it.
    use super::{
        PENDING_MAX_PRINCIPALS, PENDING_PER_PRINCIPAL, drain_pending, push_with_overflow,
        requeue_mixed_principal_tail,
    };
    use astrid_events::ipc::{IpcMessage as InternalIpcMessage, IpcPayload};
    use serde_json::json;
    use std::collections::{HashMap, VecDeque};
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
        let mut pending = HashMap::new();
        let mut order = VecDeque::new();
        let (kept, requeued) =
            requeue_mixed_principal_tail(&mut batch, &mut pending, &mut order, "c", 0);
        assert_eq!((kept, requeued), (0, 0));
        assert!(batch.is_empty());
        assert!(pending.is_empty());
    }

    #[test]
    fn homogeneous_batch_is_preserved() {
        let mut batch = vec![msg(Some("alice")), msg(Some("alice")), msg(Some("alice"))];
        let mut pending = HashMap::new();
        let mut order = VecDeque::new();
        let (kept, requeued) =
            requeue_mixed_principal_tail(&mut batch, &mut pending, &mut order, "c", 0);
        assert_eq!((kept, requeued), (3, 0));
        assert_eq!(batch.len(), 3);
        assert!(pending.is_empty());
    }

    #[test]
    fn mixed_principal_requeues_tail_without_loss() {
        let mut batch = vec![msg(Some("alice")), msg(Some("alice")), msg(Some("bob"))];
        let mut pending = HashMap::new();
        let mut order = VecDeque::new();
        let (kept, requeued) =
            requeue_mixed_principal_tail(&mut batch, &mut pending, &mut order, "c", 7);
        assert_eq!(kept, 2);
        assert_eq!(requeued, 1);
        assert_eq!(batch[0].principal.as_deref(), Some("alice"));
        assert_eq!(batch[1].principal.as_deref(), Some("alice"));
        let bob_bucket = pending.get(&Some("bob".to_string())).expect("bob requeued");
        assert_eq!(bob_bucket.len(), 1);
    }

    #[test]
    fn requeued_tail_surfaces_on_next_drain() {
        // Round-trip: mixed batch -> requeue tail -> next drain returns
        // the second principal's messages.
        let mut batch = vec![
            msg(Some("alice")),
            msg(Some("alice")),
            msg(Some("bob")),
            msg(Some("bob")),
        ];
        let mut pending = HashMap::new();
        let mut order = VecDeque::new();
        let (kept, requeued) =
            requeue_mixed_principal_tail(&mut batch, &mut pending, &mut order, "c", 0);
        assert_eq!((kept, requeued), (2, 2));

        let mut next: Vec<InternalIpcMessage> = Vec::new();
        let _ = drain_pending(&mut next, &mut pending, &mut order, usize::MAX);
        assert_eq!(next.len(), 2);
        assert!(next.iter().all(|m| m.principal.as_deref() == Some("bob")));
        assert!(pending.is_empty());
    }

    #[test]
    fn system_then_principal_requeues() {
        let mut batch = vec![msg(None), msg(None), msg(Some("alice"))];
        let mut pending = HashMap::new();
        let mut order = VecDeque::new();
        let (kept, requeued) =
            requeue_mixed_principal_tail(&mut batch, &mut pending, &mut order, "c", 0);
        assert_eq!((kept, requeued), (2, 1));
        assert!(batch[0].principal.is_none());
        assert_eq!(
            pending.get(&Some("alice".to_string())).map(|b| b.len()),
            Some(1)
        );
    }

    #[test]
    fn per_principal_overflow_drops_oldest_in_bucket() {
        let mut pending = HashMap::new();
        let mut order = VecDeque::new();
        // Tag oldest with a topic we can identify; fill to the cap and
        // push one more — the oldest must be the one dropped.
        let mut oldest = msg(Some("alice"));
        oldest.topic = "alice.oldest".into();
        push_with_overflow(&mut pending, &mut order, oldest, "c", 0);
        for _ in 1..PENDING_PER_PRINCIPAL {
            push_with_overflow(&mut pending, &mut order, msg(Some("alice")), "c", 0);
        }
        let mut newest = msg(Some("alice"));
        newest.topic = "alice.newest".into();
        push_with_overflow(&mut pending, &mut order, newest, "c", 0);

        let bucket = pending.get(&Some("alice".to_string())).expect("alice");
        assert_eq!(bucket.len(), PENDING_PER_PRINCIPAL);
        // Oldest evicted; newest still present at the tail.
        assert!(bucket.iter().all(|m| m.topic != "alice.oldest"));
        assert_eq!(bucket.back().unwrap().topic, "alice.newest");
    }

    #[test]
    fn ninth_principal_evicts_oldest_bucket() {
        let mut pending = HashMap::new();
        let mut order = VecDeque::new();
        // Fill PENDING_MAX_PRINCIPALS distinct buckets — first added is
        // the oldest.
        for i in 0..PENDING_MAX_PRINCIPALS {
            let p = format!("p{i}");
            push_with_overflow(&mut pending, &mut order, msg(Some(&p)), "c", 0);
        }
        assert_eq!(pending.len(), PENDING_MAX_PRINCIPALS);

        // Push a 9th distinct principal; the oldest ("p0") must be
        // evicted entirely.
        push_with_overflow(&mut pending, &mut order, msg(Some("p_new")), "c", 0);
        assert_eq!(pending.len(), PENDING_MAX_PRINCIPALS);
        assert!(!pending.contains_key(&Some("p0".to_string())));
        assert!(pending.contains_key(&Some("p_new".to_string())));
    }

    #[test]
    fn pending_drain_is_fair_round_robin() {
        // alice and bob each have two pending messages. drain_pending
        // should interleave them in insertion order, never starving one.
        let mut pending = HashMap::new();
        let mut order = VecDeque::new();
        push_with_overflow(&mut pending, &mut order, msg(Some("alice")), "c", 0);
        push_with_overflow(&mut pending, &mut order, msg(Some("alice")), "c", 0);
        push_with_overflow(&mut pending, &mut order, msg(Some("bob")), "c", 0);
        push_with_overflow(&mut pending, &mut order, msg(Some("bob")), "c", 0);

        let mut out: Vec<InternalIpcMessage> = Vec::new();
        let _ = drain_pending(&mut out, &mut pending, &mut order, usize::MAX);
        let principals: Vec<_> = out.iter().map(|m| m.principal.clone()).collect();
        // alice was inserted before bob, so alice's first message comes
        // out first, then bob's first, then alice's second, then bob's.
        assert_eq!(
            principals,
            vec![
                Some("alice".to_string()),
                Some("bob".to_string()),
                Some("alice".to_string()),
                Some("bob".to_string()),
            ]
        );
        assert!(pending.is_empty());
    }
}

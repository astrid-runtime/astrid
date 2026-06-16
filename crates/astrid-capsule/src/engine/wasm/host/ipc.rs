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

/// The cross-principal audit feed topic. Mirrors `astrid-kernel`'s
/// `kernel_router::AUDIT_TOPIC` (the sole production publisher) and
/// `astrid-gateway`'s `events::AUDIT_TOPIC` (the SSE consumer). Kept as a
/// capsule-local literal so the capsule does not depend on `astrid-kernel`;
/// its value is pinned by [`audit_scope_tests::audit_topic_literal_pinned`]
/// so the copies cannot silently drift (a drift would make
/// [`pattern_covers_audit`] stop recognising the kernel's renamed topic and
/// silently leave every audit subscription on the unscoped firehose default).
const AUDIT_TOPIC: &str = "astrid.v1.audit.entry";

/// Whether `pattern` (a subscribe topic pattern) covers the audit topic —
/// i.e. a subscription to `pattern` would receive `astrid.v1.audit.entry`
/// events.
///
/// Uses the ROUTE-LAYER [`astrid_events::TopicMatcher`], NOT
/// [`crate::topic::topic_matches`]: the latter only does equal-segment
/// single-`*` matching and so CANNOT detect that a trailing-suffix wildcard
/// like `astrid.v1.*` covers the 4-segment audit topic. The route matcher's
/// trailing-`*` branch does — which is the matcher the bus actually routes
/// with — so this closes the wildcard-superset bypass: any audit-covering
/// pattern is scoped, not just the exact string.
///
/// NOTE on over-scoping: the scope is per-ROUTE, not per-subtopic. An
/// audit-covering SUPERSET pattern (`astrid.v1.*`, `astrid.*`) therefore
/// scopes the WHOLE subscription to the owner principal, not just its audit
/// subtree — a future capsule using `astrid.v1.*` to gather all-principal
/// NON-audit telemetry without holding the firehose cap would have that whole
/// feed silently collapse to own-principal-only. This is the deliberate
/// secure default (an audit leak is worse than over-scoping), and no current
/// capsule subscribes to an audit-covering superset, so the #813 fan-in is
/// untouched in practice. Such a telemetry consumer must hold `audit:read_all`
/// (firehose ⇒ unscoped) or narrow its pattern below the audit topic.
fn pattern_covers_audit(pattern: &str) -> bool {
    let synthetic = AstridEvent::Ipc {
        metadata: EventMetadata::new("audit_scope_probe"),
        message: InternalIpcMessage::new(
            AUDIT_TOPIC,
            IpcPayload::RawJson(serde_json::Value::Null),
            uuid::Uuid::nil(),
        ),
    };
    astrid_events::TopicMatcher::new(pattern).matches(&synthetic)
}

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
///
/// Uses the ROUTE-LAYER [`astrid_events::TopicMatcher`] so a declared trailing
/// `*` authorizes the whole subtree (any depth) — the same semantics by which
/// events are actually delivered. A manifest `[subscribe]` entry of
/// `astrid.v1.admin.*` therefore authorizes subscribing to anything under that
/// namespace without enumerating each depth. Breadth is the operator's call
/// (the manifest declares intent; capabilities + install review are the
/// boundary), not something the matcher enforces by forcing enumeration.
fn check_subscribe_acl(state: &HostState, topic_pattern: &str) -> Result<(), ErrorCode> {
    if state.ipc_subscribe_patterns.is_empty() {
        return Err(ErrorCode::CapabilityDenied);
    }
    if !state
        .ipc_subscribe_patterns
        .iter()
        .any(|acl| astrid_events::topic_pattern_matches(acl, topic_pattern))
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
    // Route-layer matcher: a declared trailing `*` authorizes publishing the
    // whole subtree (any depth), matching delivery semantics — so a manifest
    // `[publish]` entry of `astrid.v1.admin.*` covers `astrid.v1.admin.agent.list`,
    // `astrid.v1.admin.auth.pair.issue`, etc. without enumerating each depth.
    if !state
        .ipc_publish_patterns
        .iter()
        .any(|pattern| astrid_events::topic_pattern_matches(pattern, &topic))
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
        // The verified principal bound to the source connection — a Path-1
        // daemon-spawned agent or a Path-2 crypto-authenticated client, recorded
        // by the framed `tcp-stream.read` that pulled this frame — OVERRIDES the
        // capsule-supplied name. An uplink relays a connection; it does not get
        // to NAME a principal, so a socket client can no longer forge one it has
        // not proven (issue #45/#852, the self-stamp fix). A connection with no
        // kernel binding — a local operator trusted by peer-credential match —
        // falls back to the supplied name.
        let effective = match self.ingress_principal.as_ref() {
            Some(verified) => verified.to_string(),
            None => principal,
        };
        if astrid_core::principal::PrincipalId::new(&effective).is_err() {
            return Err(ErrorCode::InvalidInput);
        }
        let bytes = payload.len() as u64;
        let topic_for_audit = topic.clone();
        let result = publish_inner(self, topic, payload, effective);
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

        // Audit self-scope: a subscription whose pattern COVERS the audit
        // topic is route-scoped to the OWNER principal unless this capsule
        // holds `audit:read_all` (the privileged firehose, resolved at load
        // — see `HostState::audit_firehose`). Default-deny: a capsule that
        // merely declared the audit topic in its `Capsule.toml` gets only
        // its own principal's entries, closing the firehose leak.
        //
        // Scope identity is the LOAD-TIME owner (`self.principal`),
        // DELIBERATELY NOT `effective_principal()`: this RouteEntry is
        // created once at subscribe() and outlives every per-invocation
        // `caller_context`, so the stable identity that owns the receiver is
        // the owner principal. (At a dedicated run-loop's subscribe call
        // `caller_context` is None anyway, so `effective_principal()` would
        // already fall back to `self.principal` — binding it explicitly
        // documents intent and removes any dependence on transient caller
        // context. Do not "fix" this to `effective_principal()`.)
        //
        // AXIS: own-principal scoping matches against the bus bucket key,
        // which `record_admin_audit` sets to the audited CALLER (the actor who
        // performed the admin action), NOT the action's `target_principal`.
        // So an owner scoped to itself sees audit entries it ACTED in, not
        // admin-on-me entries where it was the target but not the actor. This
        // is deliberate and exactly mirrors the gateway SSE reference filter
        // (which also keys on the JSON `principal` == caller). The
        // target-principal axis ("all audit about me") is a separate, future
        // (Phase 2) concern.
        // `pattern_covers_audit` recompiles the matcher and rebuilds a
        // synthetic probe event, so evaluate it once and reuse for both the
        // scope decision and the audit log line.
        let covers_audit = pattern_covers_audit(&topic_pattern);
        let scope: Option<astrid_events::PrincipalKey> = if covers_audit && !self.audit_firehose {
            Some(Some(self.principal.to_string()))
        } else {
            None
        };
        if covers_audit {
            tracing::info!(
                target: "astrid.audit.ipc",
                security_event = true,
                capsule_id = %self.capsule_id.as_str(),
                principal = %self.principal,
                topic = %topic_pattern,
                scoped = scope.is_some(),
                firehose = self.audit_firehose,
                "ipc::subscribe: audit-covering subscription scoped to owner principal unless firehose holder",
            );
        }

        // Per-(capsule, topic, principal) routed receiver. The bus
        // owns a publish-side demux that buckets messages by the
        // originating principal, so the guest never sees a
        // mixed-principal batch and the cross-principal fairness lives
        // in the bus's DRR drain — no consumer-side requeue logic
        // needed here (#813). `scope` (Option B) additionally self-scopes
        // an audit-covering subscription to the owner principal at enqueue.
        let receiver = self.event_bus.subscribe_topic_routed_scoped(
            self.capsule_uuid,
            topic_pattern.clone(),
            self.capsule_id.as_str().to_string(),
            "capsule_guest",
            scope,
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
        // Run-loop CPU-bound cooperative-yield signal: a guest that calls
        // `ipc::recv` is a legitimate event loop, not a no-recv spinner. The
        // bound run-loop's epoch-deadline callback reads + clears this each
        // window to avoid trapping a healthy loop (see `epoch_decision`). Set
        // unconditionally on entry — even a non-blocking `recv(0)` counts as a
        // cooperative yield, because the call drives the guest through the host
        // boundary and back into the executor. Inert for pooled/lifecycle
        // Stores (their epoch callback never reads it).
        //
        // SCOPE: only `ipc::recv` sets this. A bounded run-loop that blocks on
        // some OTHER host import instead (e.g. a net-accept uplink) would not
        // mark progress and could be epoch-trapped — out of scope today because
        // the one uplink (cli) holds the granted net_bind capability and is
        // therefore exempt from the bound entirely. Revisit if a non-exempt
        // uplink ever needs bounding.
        self.recv_yielded = true;
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
        let io_semaphore = self.io_semaphore.clone();
        let receiver_for_wait = Arc::clone(&receiver_arc);
        let first = util::bounded_await_cancellable(&io_semaphore, &cancel_token, async move {
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

#[cfg(test)]
mod audit_scope_tests {
    use super::*;
    use crate::engine::wasm::bindings::astrid::ipc::host::Host as IpcHost;
    use crate::engine::wasm::test_fixtures::minimal_host_state;

    #[test]
    fn audit_topic_literal_pinned() {
        // The capsule-local `AUDIT_TOPIC` must stay byte-equal to the
        // kernel's sole publisher (`astrid_kernel::kernel_router::AUDIT_TOPIC`)
        // and the gateway SSE consumer (`astrid-gateway`'s
        // `events::AUDIT_TOPIC`). The capsule cannot import the kernel
        // constant without a dependency cycle, so this pins the literal the
        // capsule routes against. If the kernel ever renames the topic,
        // `pattern_covers_audit` would otherwise silently stop recognising
        // audit subscriptions and leave them on the unscoped firehose default
        // for the renamed topic — exactly the drift the doc comment promises
        // is guarded. Mirrors `tests::audit_firehose_cap_literal_pinned`.
        assert_eq!(AUDIT_TOPIC, "astrid.v1.audit.entry");
    }

    // ── pattern_covers_audit (route-layer matcher, NOT topic_matches) ──

    #[test]
    fn pattern_covers_audit_via_route_matcher() {
        // Exact + audit-subtree wildcard + broad superset all COVER the
        // audit topic via the route matcher's trailing-suffix branch.
        assert!(pattern_covers_audit("astrid.v1.audit.entry"));
        assert!(pattern_covers_audit("astrid.v1.audit.*"));
        // The wildcard-superset bypass the route matcher closes: the
        // capsule's own topic_matches CANNOT see this coverage, but the
        // route matcher (what the bus routes with) DOES.
        assert!(pattern_covers_audit("astrid.v1.*"));
        assert!(pattern_covers_audit("astrid.*"));

        // Non-audit patterns are NOT covered → never scoped.
        assert!(!pattern_covers_audit("astrid.v1.request.*"));
        assert!(!pattern_covers_audit("astrid.v1.session.*"));
        assert!(!pattern_covers_audit("astrid.v1.audit"));
        assert!(!pattern_covers_audit("user.prompt"));
    }

    /// Build a routed publish on `bus` for an audit entry attributed to
    /// `principal` (mirrors the kernel's `record_admin_audit` shape: topic
    /// `astrid.v1.audit.entry`, `with_principal`).
    fn publish_audit(bus: &astrid_events::EventBus, principal: &str) {
        let msg = InternalIpcMessage::new(
            AUDIT_TOPIC,
            IpcPayload::RawJson(serde_json::json!({ "principal": principal })),
            uuid::Uuid::nil(),
        )
        .with_principal(principal.to_string());
        bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test_kernel"),
            message: msg,
        });
    }

    /// Drain the subscription's delivered messages and collect the
    /// `Verified` principal strings.
    fn drained_principals(state: &mut HostState, sub: &Resource<Subscription>) -> Vec<String> {
        let envelope = HostSubscription::poll(state, Resource::new_borrow(sub.rep()))
            .expect("poll should succeed");
        envelope
            .messages
            .iter()
            .map(|m| match &m.principal {
                PrincipalAttribution::Verified(p) | PrincipalAttribution::Claimed(p) => p.clone(),
                PrincipalAttribution::System => "<system>".to_string(),
            })
            .collect()
    }

    fn host_state_for(
        rt: tokio::runtime::Handle,
        owner: &str,
        firehose: bool,
        subscribe_acl: &[&str],
    ) -> HostState {
        let mut state = minimal_host_state(rt);
        state.principal = astrid_core::PrincipalId::new(owner).expect("valid principal");
        state.audit_firehose = firehose;
        state.ipc_subscribe_patterns = subscribe_acl.iter().map(|s| (*s).to_string()).collect();
        state
    }

    #[tokio::test]
    async fn subscribe_audit_default_is_scoped_regression() {
        // THE bug regression. A capsule with audit_firehose=false and the
        // audit topic in its ACL, owner=alice, must receive ONLY alice's
        // entries — bob's leak on today's unconditional firehose default.
        let rt = tokio::runtime::Handle::current();
        let mut state = host_state_for(rt, "alice", false, &["astrid.v1.audit.entry"]);
        let bus = state.event_bus.clone();

        let sub = IpcHost::subscribe(&mut state, AUDIT_TOPIC.to_string())
            .expect("subscribe should be allowed by the ACL");

        for _ in 0..5 {
            publish_audit(&bus, "alice");
        }
        for _ in 0..5 {
            publish_audit(&bus, "bob");
        }

        let got = drained_principals(&mut state, &sub);
        assert_eq!(got.len(), 5, "only alice's five entries are delivered");
        assert!(
            got.iter().all(|p| p == "alice"),
            "no foreign-principal audit entry may leak, got: {got:?}"
        );
    }

    #[tokio::test]
    async fn subscribe_wildcard_superset_is_scoped() {
        // A broad `astrid.v1.*` subscription (covers audit) by a
        // non-firehose capsule is still scoped — closes the wildcard bypass.
        let rt = tokio::runtime::Handle::current();
        let mut state = host_state_for(rt, "alice", false, &["astrid.v1.*"]);
        let bus = state.event_bus.clone();

        let sub = IpcHost::subscribe(&mut state, "astrid.v1.*".to_string())
            .expect("subscribe should be allowed by the ACL");

        publish_audit(&bus, "alice");
        publish_audit(&bus, "bob");

        let got = drained_principals(&mut state, &sub);
        assert!(
            got.iter().all(|p| p == "alice"),
            "wildcard superset must not leak bob's audit entry, got: {got:?}"
        );
        assert_eq!(got.len(), 1);
    }

    #[tokio::test]
    async fn subscribe_firehose_holder_unscoped() {
        // audit_firehose=true ⇒ unscoped: both alice and bob delivered.
        let rt = tokio::runtime::Handle::current();
        let mut state = host_state_for(rt, "alice", true, &["astrid.v1.audit.entry"]);
        let bus = state.event_bus.clone();

        let sub = IpcHost::subscribe(&mut state, AUDIT_TOPIC.to_string())
            .expect("subscribe should be allowed by the ACL");

        publish_audit(&bus, "alice");
        publish_audit(&bus, "bob");

        let got = drained_principals(&mut state, &sub);
        assert_eq!(got.len(), 2, "firehose holder receives both principals");
        assert!(got.iter().any(|p| p == "alice"));
        assert!(got.iter().any(|p| p == "bob"));
    }

    #[tokio::test]
    async fn subscribe_non_audit_topic_unaffected() {
        // A non-audit subscription (pattern_covers_audit=false) stays
        // unscoped even for a non-firehose capsule: cross-principal fan-in
        // is untouched by the audit flip.
        let rt = tokio::runtime::Handle::current();
        let mut state = host_state_for(rt, "alice", false, &["astrid.v1.session.*"]);
        let bus = state.event_bus.clone();

        let sub = IpcHost::subscribe(&mut state, "astrid.v1.session.*".to_string())
            .expect("subscribe should be allowed by the ACL");

        // Publish session events from two principals.
        for who in ["alice", "bob"] {
            let msg = InternalIpcMessage::new(
                "astrid.v1.session.update",
                IpcPayload::RawJson(serde_json::json!({})),
                uuid::Uuid::nil(),
            )
            .with_principal(who.to_string());
            bus.publish(AstridEvent::Ipc {
                metadata: EventMetadata::new("test"),
                message: msg,
            });
        }

        let got = drained_principals(&mut state, &sub);
        assert_eq!(got.len(), 2, "non-audit fan-in delivers all principals");
        assert!(got.iter().any(|p| p == "alice"));
        assert!(got.iter().any(|p| p == "bob"));
    }

    #[tokio::test]
    async fn subscribe_rejects_non_terminal_wildcard() {
        // Regression guard for the daemon-down crash (capsule-cli #25). The cli
        // run loop tried to runtime-subscribe to a multi-wildcard pattern; the
        // syntactic gate returned InvalidInput, run() returned Err before
        // signal_ready, and the whole daemon went unreachable (the cli owns the
        // socket). The patterns are even DECLARED in the subscribe ACL here — the
        // gate rejects them regardless, so a manifest can declare a [subscribe]
        // pattern a runtime subscribe can never use. Pin it: a `*` that is not the
        // final segment is rejected; the single trailing `*` the fix kept works.
        let rt = tokio::runtime::Handle::current();
        let acl = &[
            "astrid.v1.admin.response.*",
            "astrid.v1.admin.response.*.*",
            "astrid.v1.admin.response.*.*.*",
        ];
        let mut state = host_state_for(rt, "default", false, acl);

        assert!(
            matches!(
                IpcHost::subscribe(&mut state, "astrid.v1.admin.response.*.*".to_string()),
                Err(ErrorCode::InvalidInput)
            ),
            "a non-terminal wildcard must be rejected even when declared in the ACL",
        );
        assert!(
            matches!(
                IpcHost::subscribe(&mut state, "astrid.v1.admin.response.*.*.*".to_string()),
                Err(ErrorCode::InvalidInput)
            ),
            "a deeper multi-wildcard must be rejected too",
        );
        assert!(
            IpcHost::subscribe(&mut state, "astrid.v1.admin.response.*".to_string()).is_ok(),
            "the single trailing wildcard the fix kept must be subscribable",
        );
    }

    // ── publish-as principal enforcement (issue #45/#852) ──

    /// The self-stamp fix: when the source connection carries a kernel-verified
    /// principal (recorded by the framed read that pulled the frame), `publish-as`
    /// stamps THAT principal and ignores the capsule-supplied name. A socket
    /// client that authenticated as `claude` but names `default` (admin) on the
    /// wire cannot escalate — the kernel-bound identity wins.
    #[tokio::test]
    async fn publish_as_verified_principal_overrides_claimed_name() {
        let rt = tokio::runtime::Handle::current();
        let mut state = minimal_host_state(rt);
        state.has_uplink_capability = true;
        state.ipc_publish_patterns = vec!["client.v1.*".to_string()];
        state.ipc_subscribe_patterns = vec!["client.v1.*".to_string()];
        // The framed read recorded the connection's verified principal.
        state.ingress_principal = Some(astrid_core::PrincipalId::new("claude").unwrap());

        let sub = IpcHost::subscribe(&mut state, "client.v1.connect".to_string())
            .expect("subscribe allowed by ACL");

        // The client lies on the wire: it names `default`.
        IpcHost::publish_as(
            &mut state,
            "client.v1.connect".to_string(),
            "{}".to_string(),
            "default".to_string(),
        )
        .expect("publish_as should succeed");

        assert_eq!(
            drained_principals(&mut state, &sub),
            vec!["claude".to_string()],
            "the verified principal must override the claimed name (no escalation)"
        );
    }

    /// Without a kernel binding — a legacy local operator trusted by
    /// peer-credential match — `publish-as` falls back to the supplied name, so
    /// the zero-config operator CLI keeps acting as `default`. This pins that
    /// the enforcement does NOT regress the operator path.
    #[tokio::test]
    async fn publish_as_without_binding_honours_claimed_name() {
        let rt = tokio::runtime::Handle::current();
        let mut state = minimal_host_state(rt);
        state.has_uplink_capability = true;
        state.ipc_publish_patterns = vec!["client.v1.*".to_string()];
        state.ipc_subscribe_patterns = vec!["client.v1.*".to_string()];
        // No in-flight verified principal (an unbound connection).
        assert_eq!(state.ingress_principal, None);

        let sub = IpcHost::subscribe(&mut state, "client.v1.connect".to_string())
            .expect("subscribe allowed by ACL");

        IpcHost::publish_as(
            &mut state,
            "client.v1.connect".to_string(),
            "{}".to_string(),
            "default".to_string(),
        )
        .expect("publish_as should succeed");

        assert_eq!(
            drained_principals(&mut state, &sub),
            vec!["default".to_string()],
            "an unbound connection's supplied name is honoured (operator fallback)"
        );
    }
}

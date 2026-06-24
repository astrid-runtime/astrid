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
///
/// `device_key_id` is the host-derived authenticating-device fingerprint to
/// stamp onto the outbound message so the kernel cap-gate can apply the
/// device's scope. `None` for a capsule's own-principal `publish` (its own
/// host calls are never device-scoped) and for an unauthenticated forward;
/// `publish_as` passes the connection's in-flight `ingress_device_key_id`.
///
/// `origin` is the host-stamped transport [`MessageOrigin`] of the ORIGINATING
/// request. It is ALWAYS taken from host-populated state (the in-flight
/// `caller_context` for a guest `publish`, or `ingress_origin` for a
/// `publish-as` forward), NEVER from a guest argument and NEVER reset to a
/// per-publish default — so a `RemoteGateway` request flowing through a fan-out
/// capsule (react → openai-compat) stays `RemoteGateway` and cannot be elevated
/// to `LocalSocket`. The freshly built `InternalIpcMessage` would otherwise
/// reset origin to its `System` default, dropping the provenance the egress
/// gate depends on.
fn publish_inner(
    state: &mut HostState,
    topic: String,
    payload: String,
    principal_str: String,
    device_key_id: Option<&str>,
    origin: astrid_events::ipc::MessageOrigin,
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

    let mut message = InternalIpcMessage::new(topic, ipc_payload, state.capsule_uuid)
        .with_principal(principal_str)
        // Carry the host-stamped transport origin of the originating request.
        // A fresh `InternalIpcMessage` defaults to `System`; stamping it here
        // preserves `RemoteGateway` / `LocalSocket` provenance across a
        // guest-publish fan-out hop so a downstream egress gate sees the true
        // origin. `origin` is host-populated by the caller (caller_context for
        // `publish`, ingress_origin for `publish-as`), never guest-supplied.
        .with_origin(origin);
    // Stamp the host-derived authenticating-device fingerprint so the kernel
    // cap-gate can apply the device's scope as an attenuation floor. Only the
    // `publish_as` forward path carries one; a capsule's own `publish` passes
    // `None` (its host calls run at the owner's full authority).
    if let Some(id) = device_key_id {
        message = message.with_device_key_id(id);
    }

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
        // Inherit the originating request's transport origin from the in-flight
        // caller context (host-populated by the dispatcher), so a fan-out
        // capsule re-publishing on behalf of a `RemoteGateway` / `LocalSocket`
        // request preserves that provenance downstream. A run-loop publish with
        // no caller context (load-time, self-triggered) is `System`. A guest
        // can never name this origin — it only ever inherits its caller's.
        let origin = self
            .caller_context
            .as_ref()
            .map(|m| m.origin)
            .unwrap_or(astrid_events::ipc::MessageOrigin::System);
        // A capsule's own host calls are never device-scoped: the owner acts at
        // full principal authority, so no device_key_id is stamped here.
        let result = publish_inner(self, topic, payload, principal_str, None, origin);
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
        _principal: String,
    ) -> Result<(), ErrorCode> {
        if !self.has_uplink_capability {
            return Err(ErrorCode::CapabilityDenied);
        }
        // The principal is DERIVED from the source connection, never named by
        // the capsule (issue #45/#852). A connection the kernel verified at the
        // handshake — recorded by the framed `tcp-stream.read` that pulled this
        // frame — stamps that verified principal. An UNAUTHENTICATED (unbound)
        // connection stamps the reserved no-capability `anonymous` identity, NOT
        // the name it claimed: an uplink relays a connection, it cannot forge a
        // principal, and an unproven claim earns no privilege (it fails closed
        // on every capability check). The capsule-supplied name is ignored.
        let effective = match self.ingress_principal.as_ref() {
            Some(verified) => verified.as_str().to_owned(),
            None => astrid_core::principal::PrincipalId::anonymous().into_inner(),
        };
        // The authenticating device is host-derived from the same in-flight
        // connection (recorded by the framed read that pulled this frame),
        // never named by the capsule. It rides onto the message so the kernel
        // cap-gate attenuates the principal's authority to the device's scope.
        // `None` for an unbound (unauthenticated) connection — the anonymous
        // stamp already fails closed on every capability check.
        let device_key_id = self.ingress_device_key_id.clone();
        // The transport origin is host-derived from the SAME in-flight
        // connection (recorded by the framed read that pulled this frame),
        // parallel to `ingress_principal` / `ingress_device_key_id`. A BOUND
        // local connection forwards `LocalSocket`; an unbound connection has
        // `ingress_origin = None`, which is `System` (fail-closed, non-local) —
        // an unauthenticated local forward earns no local-operator privilege.
        // The capsule cannot supply or elevate this.
        let origin = self
            .ingress_origin
            .unwrap_or(astrid_events::ipc::MessageOrigin::System);
        let bytes = payload.len() as u64;
        let topic_for_audit = topic.clone();
        let result = publish_inner(
            self,
            topic,
            payload,
            effective,
            device_key_id.as_deref(),
            origin,
        );
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
#[path = "ipc_tests.rs"]
mod audit_scope_tests;

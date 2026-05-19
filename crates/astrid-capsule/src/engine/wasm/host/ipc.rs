use crate::engine::wasm::bindings::astrid::capsule::ipc;
use crate::engine::wasm::bindings::astrid::capsule::types::{
    InterceptorHandle as WitInterceptorHandle, IpcEnvelope as WitIpcEnvelope,
    IpcMessage as WitIpcMessage,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use astrid_events::AstridEvent;
use astrid_events::EventMetadata;
use astrid_events::EventReceiver;
use astrid_events::ipc::{IpcMessage, IpcPayload};

// ── Extracted testable core ─────────────────────────────────────────

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
            "Capsule '{capsule_id}' has no ipc_subscribe declarations - \
             subscribing is denied. Add ipc_subscribe patterns to Capsule.toml [capabilities]"
        ));
    }

    // NOTE: argument order is intentional. topic_matches(topic, pattern) checks
    // whether `topic` (here: the subscription request) falls within `pattern`
    // (here: the ACL entry). This means:
    //   subscribe("foo.bar") vs ACL "foo.*" -> topic_matches("foo.bar", "foo.*") = true
    //   subscribe("foo.*")   vs ACL "foo.bar" -> topic_matches("foo.*", "foo.bar") = false
    // The second case correctly prevents scope escalation via wildcard subscriptions.
    if !acl_patterns
        .iter()
        .any(|acl| crate::topic::topic_matches(topic_pattern, acl))
    {
        return Err(format!(
            "Capsule '{capsule_id}' is not allowed to subscribe to topic \
             '{topic_pattern}' - declared ipc_subscribe patterns: {acl_patterns:?}"
        ));
    }

    Ok(())
}

/// Result of draining IPC messages from an `EventReceiver`.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct DrainResult {
    pub messages: Vec<IpcMessage>,
    pub dropped: u64,
    pub lagged: u64,
}

/// Drain all available IPC messages from a receiver (non-blocking).
///
/// Collects messages until the buffer exceeds `max_payload_bytes` or no
/// more messages are available. Returns the collected messages, a count
/// of messages dropped due to buffer overflow, and the cumulative lag.
pub(crate) fn drain_receiver(
    receiver: &mut EventReceiver,
    max_payload_bytes: usize,
) -> DrainResult {
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

/// Convert an internal `IpcMessage` to the WIT-generated `IpcMessage`.
fn to_wit_ipc_message(msg: &IpcMessage) -> WitIpcMessage {
    let payload = msg
        .payload
        .to_guest_bytes()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    WitIpcMessage {
        topic: msg.topic.clone(),
        payload,
        source_id: msg.source_id.to_string(),
        principal: msg.principal.clone(),
    }
}

/// Convert a `DrainResult` into a WIT-generated `IpcEnvelope`.
fn drain_to_wit_envelope(drain: &DrainResult) -> WitIpcEnvelope {
    WitIpcEnvelope {
        messages: drain.messages.iter().map(to_wit_ipc_message).collect(),
        dropped: drain.dropped,
        lagged: drain.lagged,
    }
}

/// Truncate a drained message batch in place so every retained message
/// shares the same publisher principal as the first.
///
/// The per-invocation context installed by
/// [`HostState::install_recv_invocation_context`](super::super::host_state::HostState::install_recv_invocation_context)
/// is keyed off a single principal, so a batch that interleaves
/// publishers would silently process trailing messages under the first
/// message's principal — wrong KV namespace, wrong publish stamping,
/// and (worst) a confidentiality breach across tenants on a fan-in
/// topic. Truncate at the first cross-principal boundary; the dropped
/// tail messages are lost from this subscriber's view of the bus (the
/// batch has already been pulled out of the receiver by the
/// `drain_receiver` call upstream).
///
/// Trade-off: this prefers throughput loss (operator observable via
/// the warn) over silent cross-principal mis-stamping. A follow-up
/// ABI change to one-message-at-a-time `ipc::recv` removes the need
/// for this guard entirely.
fn truncate_to_homogeneous_principal(messages: &mut Vec<IpcMessage>, handle_id: u64) {
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
            handle_id,
            kept = first_match,
            dropped,
            first_principal = first_principal.as_deref().unwrap_or("<none>"),
            security_event = true,
            "ipc::recv: mixed-principal batch truncated to first publisher's messages so per-recv context is honoured; tail messages dropped (file a follow-up for one-msg-at-a-time recv ABI if this fires under steady-state load)"
        );
        messages.truncate(first_match);
    }
}

/// Remove a subscription by handle ID, rejecting runtime-owned interceptor handles.
///
/// Returns `Err` if the handle is protected (auto-subscribed interceptor) or
/// if the handle ID is not found in `subscriptions`.
pub(crate) fn remove_subscription(
    subscriptions: &mut std::collections::HashMap<u64, EventReceiver>,
    is_protected: bool,
    handle_id: u64,
) -> Result<(), String> {
    if is_protected {
        tracing::warn!(
            handle_id,
            "Guest attempted to unsubscribe a runtime-owned interceptor handle",
        );
        return Err("Cannot unsubscribe a runtime-owned interceptor handle".to_string());
    }

    if subscriptions.remove(&handle_id).is_none() {
        return Err("Subscription handle not found".to_string());
    }

    Ok(())
}

/// Maximum timeout for blocking IPC receive (60 seconds).
const MAX_RECV_TIMEOUT_MS: u64 = 60_000;

impl ipc::Host for HostState {
    fn ipc_publish(&mut self, topic: String, payload: String) -> Result<(), String> {
        // Propagate the principal to the outgoing message. Capsules never
        // touch the principal — it's invisible. Two cases:
        // 1. Invocation context exists (triggered by IPC) → copy from caller
        // 2. No context (uplink publishing from socket) → use capsule's own principal
        // This ensures the principal is ALWAYS set on published messages.
        let principal_str = self
            .caller_context
            .as_ref()
            .and_then(|c| c.principal.clone())
            .unwrap_or_else(|| self.principal.to_string());
        publish_inner(self, topic, payload, principal_str)
    }

    fn ipc_publish_as(
        &mut self,
        topic: String,
        payload: String,
        principal: String,
    ) -> Result<(), String> {
        // Gate on uplink capability: only uplinks (CLI proxy, Telegram
        // bridge, etc.) may stamp messages with a principal other than
        // their own. The trust model is "trust the uplink" — see issue
        // #658 for cryptographic per-connection auth.
        if !self.has_uplink_capability {
            return Err(format!(
                "Capsule '{}' is not an uplink — `ipc-publish-as` requires \
                 `uplink = true` in `Capsule.toml [capabilities]`",
                self.capsule_id
            ));
        }
        // Validate the claimed principal parses cleanly. The kernel-side
        // dispatcher only re-parses the principal field for capability
        // checks; an invalid value would silently fall back to default
        // and confuse audit logs. Reject up front instead.
        if astrid_core::principal::PrincipalId::new(&principal).is_err() {
            return Err(format!("invalid principal: {principal:?}"));
        }
        publish_inner(self, topic, payload, principal)
    }

    fn ipc_subscribe(&mut self, topic_pattern: String) -> Result<u64, String> {
        if topic_pattern.len() > 256 {
            return Err("Topic pattern exceeds maximum allowed length (256 bytes)".to_string());
        }

        // Reject malformed subscription pattern structure before registration.
        if !crate::topic::has_valid_segments(&topic_pattern) {
            return Err(
                "Topic pattern contains empty segments (consecutive dots, leading/trailing dots, or is empty)"
                    .to_string(),
            );
        }

        // EventReceiver::matches only supports trailing-suffix wildcards (e.g. `foo.bar.*`)
        // and exact matches. Mid-segment wildcards like `a.*.b` would silently never fire.
        // Reject them upfront with a clear error.
        {
            let mut segments = topic_pattern.split('.');
            // Use `position` (not `any`) to advance the iterator past the wildcard,
            // then check if there are trailing segments after it.
            #[expect(clippy::search_is_some)]
            if segments.position(|s| s == "*").is_some() && segments.next().is_some() {
                return Err(
                    "Wildcard `*` is only supported as the last segment (e.g. `foo.bar.*`). \
                     Mid-segment wildcards like `a.*.b` are not supported by the event bus."
                        .to_string(),
                );
            }
        }

        // Subscriptions are unprefixed. Capsules subscribe to system topics
        // directly (e.g., `agent.response`). Provenance is tracked via
        // `IpcMessage::source_id`, not topic namespacing.

        if topic_pattern.split('.').count() > 8 {
            return Err("Topic pattern exceeds maximum allowed segments (8)".to_string());
        }

        // Enforce IPC topic subscription restrictions from Capsule.toml.
        // Fail-closed: capsules without ipc_subscribe declarations cannot subscribe.
        check_subscribe_acl(
            self.capsule_id.as_ref(),
            &topic_pattern,
            &self.ipc_subscribe_patterns,
        )?;

        if self.subscriptions.len() >= 128 {
            return Err("Subscription limit reached (128 max per plugin)".to_string());
        }

        let receiver = self.event_bus.subscribe_topic(topic_pattern);

        let handle_id = self.next_subscription_id;
        if self.subscriptions.contains_key(&handle_id) {
            return Err("Subscription handle ID collision due to wraparound".to_string());
        }

        self.next_subscription_id = self.next_subscription_id.wrapping_add(1);
        self.subscriptions.insert(handle_id, receiver);

        Ok(handle_id)
    }

    fn ipc_unsubscribe(&mut self, handle_id: u64) -> Result<(), String> {
        let is_protected = self
            .interceptor_handles
            .iter()
            .any(|h| h.handle_id == handle_id);
        remove_subscription(&mut self.subscriptions, is_protected, handle_id)
    }

    fn ipc_poll(&mut self, handle_id: u64) -> Result<WitIpcEnvelope, String> {
        let receiver = self
            .subscriptions
            .get_mut(&handle_id)
            .ok_or_else(|| "Subscription handle not found".to_string())?;

        let mut drain = drain_receiver(receiver, util::MAX_GUEST_PAYLOAD_LEN as usize);
        truncate_to_homogeneous_principal(&mut drain.messages, handle_id);

        // Install or clear per-message principal context so subsequent
        // publishes / KV reads in the same run-loop iteration stamp /
        // scope to the publisher's principal rather than the capsule
        // owner's. Empty drain clears so a previous publisher's
        // context doesn't leak into the next guest operation.
        match drain.messages.first() {
            Some(first) => self.install_recv_invocation_context(first),
            None => self.clear_recv_invocation_context(),
        }

        Ok(drain_to_wit_envelope(&drain))
    }

    fn ipc_recv(&mut self, handle_id: u64, timeout_ms: u64) -> Result<WitIpcEnvelope, String> {
        let timeout_ms = timeout_ms.min(MAX_RECV_TIMEOUT_MS);

        // Temporarily remove the receiver from the map so we can use it
        // without holding &mut self during blocking. WASM is single-threaded
        // so no concurrent access is possible.
        let mut receiver = self
            .subscriptions
            .remove(&handle_id)
            .ok_or_else(|| "Subscription handle not found".to_string())?;
        let runtime_handle = self.runtime_handle.clone();
        let cancel_token = self.cancel_token.clone();
        let host_semaphore = self.host_semaphore.clone();

        // Block the WASM thread until a message arrives, timeout expires, or the
        // capsule is unloaded (cancellation). Routed through the host semaphore to
        // bound concurrent blocking operations across all capsules.
        //
        // Note: the helper uses a biased select that strictly prioritises
        // cancellation over completion. If a message arrives in the same poll
        // tick as cancellation, the message is discarded. This is acceptable
        // during teardown and prevents delayed shutdown under high throughput.
        let event = util::bounded_block_on_cancellable(
            &runtime_handle,
            &host_semaphore,
            &cancel_token,
            async {
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

        // Collect the blocking-wake message (if any) plus drain remaining.
        let mut drain = drain_receiver(&mut receiver, util::MAX_GUEST_PAYLOAD_LEN as usize);

        // Prepend the message that woke us (it was consumed by recv, not try_recv).
        if let Some(event) = event
            && let AstridEvent::Ipc { message, .. } = &*event
        {
            drain.messages.insert(0, message.clone());
        }

        // Re-insert the receiver after draining. During teardown (cancel token
        // fired), skip re-insertion: the capsule is dying and the lock may be
        // poisoned from concurrent cleanup, which would surface a misleading error.
        if !cancel_token.is_cancelled() {
            self.subscriptions.insert(handle_id, receiver);
        }

        truncate_to_homogeneous_principal(&mut drain.messages, handle_id);

        // Install or clear per-message principal context so subsequent
        // publishes / KV reads in the same run-loop iteration stamp /
        // scope to the publisher's principal rather than the capsule
        // owner's. Empty drain (timeout, cancellation, no messages)
        // clears so the previous wake-up's principal doesn't leak.
        match drain.messages.first() {
            Some(first) => self.install_recv_invocation_context(first),
            None => self.clear_recv_invocation_context(),
        }

        Ok(drain_to_wit_envelope(&drain))
    }

    /// Return the pre-registered interceptor handle mappings for run-loop capsules.
    ///
    /// Called by the WASM guest at startup to discover which IPC subscription
    /// handles correspond to interceptor actions. Returns a list of
    /// `InterceptorHandle` objects, or an empty list if no interceptors are
    /// auto-subscribed.
    fn get_interceptor_handles(&mut self) -> Result<Vec<WitInterceptorHandle>, String> {
        Ok(self
            .interceptor_handles
            .iter()
            .map(|h| WitInterceptorHandle {
                handle_id: h.handle_id,
                action: h.action.clone(),
                topic: h.topic.clone(),
            })
            .collect())
    }
}

/// Shared publish path used by [`ipc::Host::ipc_publish`] and
/// [`ipc::Host::ipc_publish_as`]. The only difference between the two
/// entry points is how `principal_str` is resolved — quota check,
/// topic validation, ACL, and event-bus publication are identical.
fn publish_inner(
    state: &mut HostState,
    topic: String,
    payload: String,
    principal_str: String,
) -> Result<(), String> {
    // Prevent IPC topic abuse
    if topic.len() > 256 {
        return Err("Topic exceeds maximum allowed length (256 bytes)".to_string());
    }

    let payload_len = payload.len();

    // Check rate limit and quotas using the length *before* allocating
    // the memory. Buckets are keyed by (capsule, principal) and bounded
    // by the invoking principal's `max_ipc_throughput_bytes`, so two
    // principals sharing the same capsule instance cannot starve each
    // other's budget.
    //
    // For `ipc_publish_as`, the bucket key is the **claimed** principal
    // (the validated `principal_str`), not the uplink's own principal —
    // otherwise every principal relaying through one uplink would share
    // a single bucket and could starve each other. Falls back to
    // `effective_principal()` if `principal_str` is somehow unparseable
    // (defence-in-depth — `ipc_publish_as` already validates the input,
    // and the `ipc_publish` path constructs it from a valid `PrincipalId`).
    let principal = astrid_core::principal::PrincipalId::new(&principal_str)
        .unwrap_or_else(|_| state.effective_principal());
    let throughput_cap = usize::try_from(state.effective_profile().quotas.max_ipc_throughput_bytes)
        .unwrap_or(usize::MAX);
    state
        .ipc_limiter
        .check_quota(state.capsule_uuid, &principal, payload_len, throughput_cap)
        .map_err(|e| e.to_string())?;

    if !crate::topic::has_valid_segments(&topic) {
        return Err(
            "Topic contains empty segments (consecutive dots, leading/trailing dots, or is empty)"
                .to_string(),
        );
    }

    if topic.split('.').count() > 8 {
        return Err("Topic exceeds maximum allowed segments (8)".to_string());
    }

    // Enforce IPC topic publishing restrictions from Capsule.toml.
    // Fail-closed: capsules without ipc_publish declarations cannot
    // publish. Protected topics (kernel.*) require explicit declaration
    // even if a capsule has other patterns — defense-in-depth against
    // privilege escalation.
    if state.ipc_publish_patterns.is_empty() {
        return Err(format!(
            "Capsule '{}' has no ipc_publish declarations — publishing is denied. \
             Add ipc_publish patterns to Capsule.toml [capabilities]",
            state.capsule_id
        ));
    }

    if !state
        .ipc_publish_patterns
        .iter()
        .any(|pattern| crate::topic::topic_matches(&topic, pattern))
    {
        return Err(format!(
            "Capsule '{}' is not allowed to publish to topic '{topic}' — \
             declared ipc_publish patterns: {:?}",
            state.capsule_id, state.ipc_publish_patterns
        ));
    }

    let payload_bytes = payload.as_bytes();

    if payload_bytes.len() > util::MAX_GUEST_PAYLOAD_LEN as usize {
        return Err(format!(
            "IPC payload exceeds maximum allowed length ({} bytes)",
            util::MAX_GUEST_PAYLOAD_LEN
        ));
    }

    // Deserialize the guest payload into an IpcPayload, falling back to
    // Custom for unrecognised or missing type tags. See
    // `IpcPayload::from_json_value` for the rationale behind the
    // pre-check.
    let ipc_payload = match serde_json::from_slice::<serde_json::Value>(payload_bytes) {
        Ok(data) => IpcPayload::from_json_value(data),
        Err(_) => return Err("IPC payload is not valid JSON".to_string()),
    };

    let message =
        IpcMessage::new(topic, ipc_payload, state.capsule_uuid).with_principal(principal_str);

    let event = AstridEvent::Ipc {
        metadata: EventMetadata::new("wasm_guest").with_session_id(state.capsule_uuid),
        message,
    };

    state.event_bus.publish(event);
    Ok(())
}

#[cfg(test)]
#[path = "ipc_tests.rs"]
mod tests;

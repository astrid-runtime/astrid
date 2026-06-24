//! Runtime operator-consent for capsule local-egress (issue #1028).
//!
//! After the SSRF-airlock hardening closed the accidental `http://127.0.0.1`
//! IP-literal bypass, the only sanctioned way for a capsule to reach a
//! loopback/private LLM endpoint is the operator allowlist
//! `[security.capsule_local_egress]` (snapshotted onto [`HostState::local_egress`]).
//! That allowlist must be set ahead of time. This module is the **runtime**
//! complement: when a capsule's egress hits the airlock-rejected arm for an
//! IP-literal local endpoint, and the request demonstrably came from a *local
//! operator* (a `LocalSocket` transport origin), the host elicits one-shot
//! consent via the existing approval primitive and — on approve — lets the
//! in-flight request through.
//!
//! # Why transport origin is load-bearing
//!
//! The gateway `POST /agent` drives the SAME react/openai-compat egress path a
//! local CLI prompt does. A remote bearer caller therefore reaches the same
//! egress site as a local operator. The ONLY thing that distinguishes them is
//! the host-stamped [`MessageOrigin`](astrid_events::ipc::MessageOrigin): a
//! `LocalSocket` request is a verified local operator; a `RemoteGateway` (or
//! `System`, or unbound) request is not. Consent is therefore gated on
//! `effective_origin() == LocalSocket` and fails closed for everything else —
//! a remote user can never trigger a local-egress prompt, let alone grant one.
//!
//! # Scope (v1)
//!
//! Covers IP-LITERAL local endpoints (`127.0.0.1:port`, `[::1]:port`,
//! `192.168.x`, `10.x`, `169.254.x`) — the airlock-rejected arm of
//! [`egress_decision`](super::http). HOSTNAME endpoints (`localhost:1234`,
//! resolved through `SafeDnsResolver`) are NOT consent-granted in v1; they still
//! require an operator pre-bless. See the call site in `host/http.rs`.
//!
//! # Grant scoping
//!
//! The runtime grant is **per-principal** (keyed `principal` + the network
//! `host:port`), held in the shared [`AllowanceStore`] — principal A's grant
//! never exempts principal B, mirroring the store's per-principal isolation. The
//! operator pre-bless (`[security.capsule_local_egress]`) stays capsule-keyed
//! and unchanged.

use astrid_approval::action::SensitiveAction;
use astrid_approval::{Allowance, AllowanceId, AllowancePattern, AllowanceStore};
use astrid_core::principal::PrincipalId;
use astrid_core::types::Timestamp;
use astrid_crypto::KeyPair;
use astrid_events::AstridEvent;
use astrid_events::ipc::{IpcMessage, IpcPayload, MessageOrigin};
use uuid::Uuid;

use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;

/// Maximum time to wait for the operator's consent response, in milliseconds.
/// Mirrors `host/approval.rs`'s `MAX_APPROVAL_TIMEOUT_MS` so every runtime
/// consent shares one human-facing budget.
const CONSENT_TIMEOUT_MS: u64 = 60_000;

/// Build the per-principal network action this consent is about. The grant and
/// the lookup must use the same shape so a cached grant short-circuits a repeat.
fn egress_action(host: &str, port: u16) -> SensitiveAction {
    SensitiveAction::NetworkRequest {
        host: host.to_string(),
        port,
    }
}

/// `true` if `principal` already holds a runtime grant for `host:port` in the
/// allowance store. A prior `approve`/`approve_session`/`approve_always` left a
/// [`AllowancePattern::NetworkHost`] entry; matching it here is what makes a
/// second request to the same endpoint silent.
///
/// Per-principal by construction: the store buckets allowances by principal, so
/// this can only ever see `principal`'s own grants.
fn has_runtime_grant(
    store: &AllowanceStore,
    principal: &PrincipalId,
    host: &str,
    port: u16,
) -> bool {
    // `find_matching_and_consume` consumes one use of a limited allowance; our
    // grants are unlimited (`uses_remaining: None`), so this is a pure lookup
    // with no side effect on them. Workspace scoping is irrelevant to a network
    // grant, so pass `None`.
    store
        .find_matching_and_consume(principal, &egress_action(host, port), None)
        .is_some()
}

/// Add an unlimited runtime egress grant for `principal` to `host:port`.
///
/// `session_only = true` for `approve`/`approve_session` (cleared when the
/// principal's last session disconnects); `false` for `approve_always` (also
/// persisted to the profile on disk by the caller). Keyed per-principal in the
/// shared store, so it never leaks to another principal.
fn add_runtime_grant(
    store: &AllowanceStore,
    principal: &PrincipalId,
    host: &str,
    port: u16,
    session_only: bool,
) {
    let keypair = KeyPair::generate();
    let allowance = Allowance {
        id: AllowanceId::new(),
        principal: principal.clone(),
        action_pattern: AllowancePattern::NetworkHost {
            host: host.to_string(),
            ports: Some(vec![port]),
        },
        created_at: Timestamp::now(),
        expires_at: None,
        max_uses: None,
        uses_remaining: None,
        session_only,
        // A network egress grant is not workspace-relative — it holds for the
        // principal regardless of cwd.
        workspace_root: None,
        signature: keypair.sign(b"local-egress-consent"),
    };
    if let Err(e) = store.add_allowance(allowance) {
        tracing::warn!(
            security_event = true,
            %principal,
            endpoint = %format!("{host}:{port}"),
            error = %e,
            "local-egress consent: failed to cache runtime grant"
        );
    }
}

/// Classify a consent decision string. Mirrors `host/approval.rs`'s
/// `decision_from_str` mapping (anything not in the approve set — explicit
/// deny, unknown, empty — is a deny).
enum Decision {
    /// One-shot approve: let the in-flight request through, no persistence.
    Once,
    /// Approve for the session: cache a session-scoped per-principal grant.
    Session,
    /// Approve always: cache a non-session grant AND persist to the profile.
    Always,
    /// Deny / unknown / empty — fail closed.
    Deny,
}

fn classify_decision(decision: &str) -> Decision {
    match decision {
        "approve" => Decision::Once,
        "approve_session" => Decision::Session,
        "approve_always" => Decision::Always,
        _ => Decision::Deny,
    }
}

impl HostState {
    /// Decide whether to permit a local-egress request to `host:port` that the
    /// SSRF airlock rejected, by eliciting one-shot operator consent.
    ///
    /// Returns `true` to PERMIT the in-flight request (re-enter the exempt
    /// path), `false` to keep it blocked (`AirlockRejected`).
    ///
    /// # Policy (fail-closed)
    ///
    /// 1. If [`effective_origin`](Self::effective_origin) is NOT
    ///    [`LocalSocket`](MessageOrigin::LocalSocket) — i.e. `System`,
    ///    `RemoteGateway`, or an unbound socket — return `false` WITHOUT
    ///    prompting. A remote/system request can never earn a local-egress
    ///    grant.
    /// 2. Else, if `principal` already holds a runtime grant for `host:port`,
    ///    return `true` immediately (no prompt).
    /// 3. Else elicit consent (`ApprovalRequired` on `astrid.v1.approval`,
    ///    resource = `host:port` only, reason names the capsule) and block,
    ///    bounded by [`CONSENT_TIMEOUT_MS`] and the capsule cancel token. On
    ///    approve / approve_session: cache a per-principal session grant and
    ///    return `true`. On approve_always: also persist to
    ///    `profile.network.egress` on disk. On deny / timeout / cancel /
    ///    unknown decision: return `false`.
    ///
    /// `host` is the URL host (an IP literal in v1 scope); `port` is the
    /// resolved request port.
    pub fn consent_local_egress(&mut self, host: &str, port: u16) -> bool {
        // 1. ORIGIN GATE (fail-closed). Only a verified local-operator request
        // may even be considered. Everything else — remote gateway callers,
        // system events, unbound local connections — is refused silently,
        // without a prompt, so a remote user can neither see nor answer a
        // local-egress consent dialog.
        if self.effective_origin() != MessageOrigin::LocalSocket {
            tracing::debug!(
                target: "astrid.audit.http",
                capsule_id = %self.capsule_id.as_str(),
                principal = %self.effective_principal(),
                endpoint = %format!("{host}:{port}"),
                origin = ?self.effective_origin(),
                "local-egress consent declined: non-local transport origin (fail-closed)"
            );
            return false;
        }

        let Some(store) = self.allowance_store.clone() else {
            // No allowance store wired (minimal/test host): cannot cache or
            // look up a grant, so cannot consent. Fail closed.
            return false;
        };
        let principal = self.effective_principal();
        let endpoint = format!("{host}:{port}");

        // 2. EXISTING-GRANT FAST PATH. A prior consent for this principal +
        // endpoint short-circuits the prompt.
        if has_runtime_grant(&store, &principal, host, port) {
            return true;
        }

        // 3. ELICIT. Publish `ApprovalRequired` and block for the response.
        let decision = self.elicit_egress_consent(&principal, &endpoint);
        match classify_decision(&decision) {
            Decision::Deny => {
                tracing::info!(
                    security_event = true,
                    capsule_id = %self.capsule_id.as_str(),
                    %principal,
                    endpoint = %endpoint,
                    decision = %decision,
                    "local-egress consent: not approved; request stays blocked (fail-closed)"
                );
                false
            },
            Decision::Once => {
                // Approved for this request only — let it through, cache
                // nothing. The next request to the same endpoint prompts again.
                tracing::info!(
                    security_event = true,
                    capsule_id = %self.capsule_id.as_str(),
                    %principal,
                    endpoint = %endpoint,
                    "local-egress consent: approved once"
                );
                true
            },
            Decision::Session => {
                add_runtime_grant(&store, &principal, host, port, true);
                tracing::info!(
                    security_event = true,
                    capsule_id = %self.capsule_id.as_str(),
                    %principal,
                    endpoint = %endpoint,
                    "local-egress consent: approved for session"
                );
                true
            },
            Decision::Always => {
                // Cache a non-session grant for the running daemon AND persist
                // to disk so it survives a restart. A disk-persist failure is a
                // fail-closed no-op for the persistence only — the in-flight
                // request still proceeds on the in-memory grant just added.
                add_runtime_grant(&store, &principal, host, port, false);
                if let Some(cache) = self.profile_cache.as_ref() {
                    if let Err(e) = cache.persist_egress(&principal, &endpoint) {
                        tracing::warn!(
                            security_event = true,
                            %principal,
                            endpoint = %endpoint,
                            error = %e,
                            "local-egress consent: approve_always disk persist failed; \
                             in-memory grant stands for this session"
                        );
                    }
                } else {
                    tracing::warn!(
                        security_event = true,
                        %principal,
                        endpoint = %endpoint,
                        "local-egress consent: approve_always but no profile cache wired; \
                         grant is session-scoped only"
                    );
                }
                tracing::info!(
                    security_event = true,
                    capsule_id = %self.capsule_id.as_str(),
                    %principal,
                    endpoint = %endpoint,
                    "local-egress consent: approved always"
                );
                true
            },
        }
    }

    /// Publish an `ApprovalRequired` for the local-egress endpoint and block for
    /// the operator's response. Returns the raw decision string (`""` on
    /// timeout / cancel / malformed reply, treated as deny by the caller).
    ///
    /// The resource is the `host:port` ONLY (no URL path / query — the consent
    /// is for the endpoint, not a specific request), and the reason names the
    /// capsule so the operator knows who is asking. Subscribe-before-publish
    /// avoids a response race, exactly like `host/approval.rs::request_approval`.
    fn elicit_egress_consent(&self, principal: &PrincipalId, endpoint: &str) -> String {
        let event_bus = self.event_bus.clone();
        let runtime_handle = self.runtime_handle.clone();
        let cancel_token = self.cancel_token.clone();
        let blocking_semaphore = self.blocking_semaphore.clone();
        let capsule_id = self.capsule_id.to_string();

        let request_id = Uuid::new_v4().to_string();
        let response_topic = format!("astrid.v1.approval.response.{request_id}");
        // Subscribe BEFORE publishing to prevent a publish/subscribe race.
        let mut receiver = event_bus.subscribe_topic(&response_topic);

        let payload = IpcPayload::ApprovalRequired {
            request_id: request_id.clone(),
            action: "local-network-egress".to_string(),
            resource: endpoint.to_string(),
            reason: format!(
                "Capsule '{capsule_id}' wants to reach the local endpoint \
                 {endpoint} (running as '{principal}')"
            ),
        };
        // Kernel-originated (nil source_id): the host is asking on the operator's
        // behalf, not a capsule forging an approval request.
        let message = IpcMessage::new("astrid.v1.approval", payload, Uuid::nil());
        event_bus.publish(AstridEvent::Ipc {
            message,
            metadata: astrid_events::EventMetadata::default(),
        });

        let event = util::bounded_block_on_cancellable(
            &runtime_handle,
            &blocking_semaphore,
            &cancel_token,
            async {
                tokio::time::timeout(
                    std::time::Duration::from_millis(CONSENT_TIMEOUT_MS),
                    receiver.recv(),
                )
                .await
                .ok()
                .flatten()
            },
        )
        .flatten();

        match event {
            Some(event) => match &*event {
                AstridEvent::Ipc { message, .. } => match &message.payload {
                    IpcPayload::ApprovalResponse { decision, .. } => decision.clone(),
                    // Unexpected payload on the response topic — treat as deny.
                    _ => String::new(),
                },
                _ => String::new(),
            },
            // Timeout or cancellation — deny (fail closed).
            None => String::new(),
        }
    }
}

#[cfg(test)]
#[path = "consent_egress_tests.rs"]
mod tests;

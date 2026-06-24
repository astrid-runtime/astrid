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
//! The runtime grant is **per-principal AND per-capsule** (keyed `principal` +
//! `capsule_id` + the network `host:port`), held in the shared
//! [`AllowanceStore`] — principal A's grant never exempts principal B (the store
//! buckets by principal), and capsule A's grant never exempts capsule B even for
//! the same principal (the [`AllowancePattern::NetworkHost`] carries the
//! `capsule_id` and the matcher requires it to match). The `approve_always`
//! persistence mirrors this: it writes to the capsule-keyed
//! `profile.network.capsule_egress[<capsule>]` map, not a flat per-principal
//! list, so a remembered grant likewise cannot widen across capsules. The
//! operator pre-bless (`[security.capsule_local_egress]`) stays capsule-keyed
//! and unchanged.
//!
//! # Persistence is honored at runtime ("remember across restarts")
//!
//! The in-memory [`AllowanceStore`] starts EMPTY on every daemon boot, so the
//! in-memory grant alone cannot survive a restart. To actually keep the
//! `approve_always` promise, the gate ALSO consults the on-disk
//! `profile.network.capsule_egress[<capsule>]` for the effective principal
//! before eliciting (see [`has_persisted_grant`] and step 3 of
//! [`consent_local_egress`](HostState::consent_local_egress)) — the same way it
//! already consults the operator pre-bless allowlist
//! ([`HostState::local_egress`]), just per-principal from the profile. The
//! persisted consult preserves both isolation axes: it reads only THIS
//! capsule's bucket in THIS principal's profile, so a remembered grant for
//! capsule A / principal X never permits capsule B / principal Y. It is reached
//! only AFTER the upstream origin gate (`LocalSocket` only) and SSRF airlock, so
//! it short-circuits the elicitation — never the origin/airlock checks.

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
use crate::profile_cache::PrincipalProfileCache;
use crate::security::net_connect_pattern_matches;

/// Maximum time to wait for the operator's consent response, in milliseconds.
/// Mirrors `host/approval.rs`'s `MAX_APPROVAL_TIMEOUT_MS` so every runtime
/// consent shares one human-facing budget.
const CONSENT_TIMEOUT_MS: u64 = 60_000;

/// Build the per-principal, per-capsule network action this consent is about.
/// The grant and the lookup must use the same shape so a cached grant
/// short-circuits a repeat. `capsule_id` scopes the action so a grant for one
/// capsule never exempts another reaching the same endpoint.
fn egress_action(capsule_id: &str, host: &str, port: u16) -> SensitiveAction {
    SensitiveAction::NetworkRequest {
        capsule_id: capsule_id.to_string(),
        host: host.to_string(),
        port,
    }
}

/// `true` if `principal` already holds a runtime grant for `capsule_id`
/// reaching `host:port` in the allowance store. A prior
/// `approve`/`approve_session`/`approve_always` left a
/// [`AllowancePattern::NetworkHost`] entry; matching it here is what makes a
/// second request to the same endpoint silent.
///
/// Per-principal AND per-capsule by construction: the store buckets allowances
/// by principal, and the action carries `capsule_id`, so a grant for capsule A
/// never short-circuits capsule B even for the same principal and endpoint.
fn has_runtime_grant(
    store: &AllowanceStore,
    principal: &PrincipalId,
    capsule_id: &str,
    host: &str,
    port: u16,
) -> bool {
    // `find_matching_and_consume` consumes one use of a limited allowance; our
    // grants are unlimited (`uses_remaining: None`), so this is a pure lookup
    // with no side effect on them. Workspace scoping is irrelevant to a network
    // grant, so pass `None`.
    store
        .find_matching_and_consume(principal, &egress_action(capsule_id, host, port), None)
        .is_some()
}

/// `true` if `principal`'s on-disk profile remembers an `approve_always` grant
/// for THIS capsule reaching `host:port`.
///
/// The in-memory [`AllowanceStore`] starts EMPTY on every daemon boot, so an
/// `approve_always` grant — whose contract is "remember across restarts" — is
/// only honored if the egress gate also consults the persisted profile. This is
/// that consult: it reads `profile.network.capsule_egress[capsule_id]` for the
/// effective principal and matches the requested `host:port` against those
/// remembered endpoints with the SAME `host:port` / `host:*` semantics the
/// operator pre-bless allowlist uses ([`egress_allowed`](super::http)).
///
/// Isolation is preserved across the persisted path exactly as it is for the
/// in-memory store:
/// - **per-capsule** — only the `capsule_egress[capsule_id]` bucket is read, so
///   a remembered grant for capsule A never matches capsule B even for the same
///   principal and endpoint; and
/// - **per-principal** — the profile is resolved for THIS principal only, so
///   principal X's remembered grant never matches principal Y.
///
/// Fail-closed: a profile load/parse error (malformed TOML, unknown field,
/// future `profile_version`) returns `false` — the gate falls through to
/// eliciting consent rather than silently permitting on an unreadable profile.
fn has_persisted_grant(
    cache: &PrincipalProfileCache,
    principal: &PrincipalId,
    capsule_id: &str,
    host: &str,
    port: u16,
) -> bool {
    let Ok(profile) = cache.resolve(principal) else {
        // Unreadable/invalid profile → no remembered grant we can trust.
        return false;
    };
    let Some(entries) = profile.network.capsule_egress.get(capsule_id) else {
        return false;
    };
    entries
        .iter()
        .any(|entry| net_connect_pattern_matches(entry, host, port))
}

/// Add an unlimited runtime egress grant for `principal` + `capsule_id` to
/// `host:port`.
///
/// `session_only = true` for `approve`/`approve_session` (cleared when the
/// principal's last session disconnects); `false` for `approve_always` (also
/// persisted to the profile on disk by the caller). Keyed per-principal in the
/// shared store and per-capsule via the pattern's `capsule_id`, so it never
/// leaks to another principal NOR to another capsule of the same principal.
fn add_runtime_grant(
    store: &AllowanceStore,
    principal: &PrincipalId,
    capsule_id: &str,
    host: &str,
    port: u16,
    session_only: bool,
) {
    let keypair = KeyPair::generate();
    let allowance = Allowance {
        id: AllowanceId::new(),
        principal: principal.clone(),
        action_pattern: AllowancePattern::NetworkHost {
            capsule_id: capsule_id.to_string(),
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
    /// 2. Else, if `principal` already holds a runtime grant for THIS capsule
    ///    reaching `host:port`, return `true` immediately (no prompt). The grant
    ///    is keyed on `capsule_id` too, so capsule B never short-circuits on
    ///    capsule A's grant.
    /// 3. Else, if `principal`'s on-disk profile remembers an `approve_always`
    ///    grant for THIS capsule reaching `host:port`
    ///    (`network.capsule_egress[<capsule>]`), return `true` immediately (no
    ///    prompt). The in-memory store above starts empty after a daemon
    ///    restart, so this persisted consult is what makes `approve_always`
    ///    actually survive a restart. It is per-capsule AND per-principal by
    ///    construction (only this capsule's bucket in this principal's profile
    ///    is read).
    /// 4. Else elicit consent (`ApprovalRequired` on `astrid.v1.approval`,
    ///    resource = `host:port` only, reason names the capsule) and block,
    ///    bounded by [`CONSENT_TIMEOUT_MS`] and the capsule cancel token. On
    ///    approve / approve_session: cache a per-principal, per-capsule session
    ///    grant and return `true`. On approve_always: also persist to the
    ///    capsule-keyed `profile.network.capsule_egress[<capsule>]` on disk. On
    ///    deny / timeout / cancel / unknown decision: return `false`.
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
        // The grant is scoped to THIS capsule: a grant for capsule A reaching
        // H:P must never exempt capsule B reaching H:P for the same principal.
        let capsule_id = self.capsule_id.to_string();
        let endpoint = format!("{host}:{port}");

        // 2. EXISTING-GRANT FAST PATH. A prior consent for this principal +
        // capsule + endpoint short-circuits the prompt.
        if has_runtime_grant(&store, &principal, &capsule_id, host, port) {
            return true;
        }

        // 3. PERSISTED-GRANT FAST PATH. The in-memory store above is empty
        // after a daemon restart, so a prior `approve_always` would otherwise be
        // silently forgotten and the operator re-prompted. Consult the
        // principal's on-disk profile for a remembered grant under THIS capsule
        // — the persistence half of the `approve_always` "remember across
        // restarts" contract. Per-capsule AND per-principal by construction (see
        // `has_persisted_grant`); never widens beyond this principal+capsule.
        // This short-circuits only the ELICIT — the origin gate and SSRF airlock
        // upstream still bind (we are only reached on a `LocalSocket`,
        // airlock-rejected IP-literal endpoint).
        if let Some(cache) = self.profile_cache.as_ref()
            && has_persisted_grant(cache, &principal, &capsule_id, host, port)
        {
            tracing::debug!(
                target: "astrid.audit.http",
                capsule_id = %self.capsule_id.as_str(),
                %principal,
                endpoint = %endpoint,
                "local-egress consent: honoring persisted approve_always grant (no prompt)"
            );
            return true;
        }

        // 4. ELICIT. Publish `ApprovalRequired` and block for the response.
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
                add_runtime_grant(&store, &principal, &capsule_id, host, port, true);
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
                add_runtime_grant(&store, &principal, &capsule_id, host, port, false);
                if let Some(cache) = self.profile_cache.as_ref() {
                    if let Err(e) = cache.persist_egress(&principal, &capsule_id, &endpoint) {
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
    ///
    /// # Response-topic isolation (documented residual, PR #1029 FIX 2)
    ///
    /// Egress consent reuses the shared `astrid.v1.approval[.response.*]`
    /// channel rather than a structurally distinct `astrid.v1.egress.response.*`
    /// namespace. A distinct namespace was considered and deliberately NOT
    /// adopted: the only surfaces that may answer a consent are the ones holding
    /// publish rights on the response topic — today the operator uplink
    /// (`capsule-cli`) and the trusted MCP broker (`sage-mcp`), both of which
    /// declare `astrid.v1.approval.response.*` in their `Capsule.toml [publish]`
    /// ACL. Both repos are OUTSIDE this one, so switching the host to a new
    /// `astrid.v1.egress.response.*` topic would silently break the consent
    /// round-trip (the operator surface could no longer publish the decision)
    /// until those out-of-repo manifests were extended in lockstep — an ACL
    /// spread across repos this change must not require.
    ///
    /// The residual is therefore: a surface already holding response-topic
    /// publish rights AND subscribed to `astrid.v1.approval` (where the
    /// `request_id` is broadcast for the operator to render) could in principle
    /// answer an egress consent. This is LOW severity and non-escalating:
    /// - those rights belong only to TRUSTED operator/broker surfaces — an
    ///   arbitrary untrusted tool capsule does not declare (and cannot obtain)
    ///   publish on `astrid.v1.approval.response.*`, which the subtree publish
    ///   ACL enforces — so this is not a capsule-forgeable approve;
    /// - the consent is already origin-gated upstream
    ///   ([`consent_local_egress`](Self::consent_local_egress) only reaches here
    ///   for a verified `LocalSocket` operator), so a remote caller can never
    ///   trigger one to be answered at all; and
    /// - the `request_id` is an unguessable v4 UUID, so a surface NOT subscribed
    ///   to `astrid.v1.approval` cannot blind-guess the response topic.
    ///
    /// Closing it fully (a distinct egress namespace) is deferred to a paired
    /// change that also extends the operator-surface publish ACL in `capsule-cli`.
    fn elicit_egress_consent(&self, principal: &PrincipalId, endpoint: &str) -> String {
        let event_bus = self.event_bus.clone();
        let runtime_handle = self.runtime_handle.clone();
        let cancel_token = self.cancel_token.clone();
        let blocking_semaphore = self.blocking_semaphore.clone();
        let capsule_id = self.capsule_id.to_string();

        let request_id = Uuid::new_v4().to_string();
        // Shared approval response channel — see the "Response-topic isolation"
        // residual in this method's doc comment for why a distinct
        // `astrid.v1.egress.response.*` namespace is deferred (out-of-repo
        // operator-surface ACL spread).
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

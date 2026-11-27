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
//!
//! # Revocation
//!
//! Managed profile invalidation removes a remembered endpoint on the next
//! admission. A durable approval has no duplicate session allowance. Direct
//! disk edits need an explicit cache invalidation or daemon restart. Operator
//! pre-bless is a load-time snapshot and still requires reload or restart.

use astrid_approval::action::SensitiveAction;
use astrid_approval::{Allowance, AllowanceId, AllowancePattern, AllowanceStore};
use astrid_core::principal::PrincipalId;
use astrid_core::types::Timestamp;
use astrid_crypto::KeyPair;
use astrid_events::AstridEvent;
use astrid_events::ipc::{IpcMessage, IpcPayload, MessageOrigin, Topic};
use uuid::Uuid;

use crate::audit_sink::HostApprovalScope;
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;

use crate::security::net_connect_pattern_matches;

/// Maximum time to wait for the operator's consent response, in milliseconds.
/// Mirrors `host/approval.rs`'s `MAX_APPROVAL_TIMEOUT_MS` so every runtime
/// consent shares one human-facing budget.
const CONSENT_TIMEOUT_MS: u64 = 60_000;

/// Approval action name of a local-egress consent prompt.
const EGRESS_CONSENT_ACTION: &str = "local-network-egress";

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
/// session consent left a
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
fn has_persisted_grant(
    profile: &astrid_core::PrincipalProfile,
    capsule_id: &str,
    host: &str,
    port: u16,
) -> bool {
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
/// Session allowances expire when the principal's last session disconnects.
fn add_runtime_grant(
    store: &AllowanceStore,
    principal: &PrincipalId,
    capsule_id: &str,
    host: &str,
    port: u16,
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
        session_only: true,
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

use super::consent_reply::Decision;

use super::egress_reply::GrantTarget;

type LocalTarget<'a> = GrantTarget<&'a PrincipalId, &'a str, &'a str>;

pub(super) type EgressAuthority = super::consent_reply::ReplyAuthority<
    Option<crate::engine::wasm::PrincipalInvocationGuard>,
    Option<astrid_core::profile::device_sessions::DeviceSession>,
    Option<astrid_core::profile::device_sessions::DeviceSession>,
>;

impl EgressAuthority {
    pub(super) fn devices_live(&self) -> bool {
        let (caller, responder) = self.devices();
        [caller, responder]
            .into_iter()
            .all(|s| s.as_ref().is_none_or(|s| !s.is_retired()))
    }

    /// Drop a pending send when either admitted device retires. Both session
    /// guards remain owned by the caller until the transport future is dropped.
    pub(super) async fn while_live<F: Future>(&self, send: F) -> Option<F::Output> {
        async fn guarded<F: Future>(
            session: Option<&astrid_core::profile::device_sessions::DeviceSession>,
            work: F,
        ) -> Option<F::Output> {
            match session {
                Some(session) => session.while_live(work).await,
                None => Some(work.await),
            }
        }
        let (caller, responder) = self.devices();
        guarded(caller.as_ref(), guarded(responder.as_ref(), send))
            .await
            .flatten()
    }
}

impl LocalTarget<'_> {
    fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

struct GrantWriter<'a> {
    devices: [astrid_events::ipc::DeviceStamp<'a>; 2],
    store: &'a AllowanceStore,
    profile: Option<(
        &'a crate::profile_cache::PrincipalProfileCache,
        std::sync::Arc<astrid_core::PrincipalProfile>,
    )>,
}

impl super::egress_reply::Writer<LocalTarget<'_>> for GrantWriter<'_> {
    type Error = astrid_core::profile::ProfileError;

    fn install(
        &mut self,
        store: super::egress_reply::Store,
        target: LocalTarget<'_>,
    ) -> Result<(), Self::Error> {
        match store {
            super::egress_reply::Store::Session => {
                let install = || {
                    add_runtime_grant(
                        self.store,
                        target.principal,
                        target.capsule,
                        target.host,
                        target.port,
                    )
                };
                if let Some((cache, snapshot)) = &self.profile {
                    return cache.with_session_devices(
                        target.principal,
                        self.devices,
                        Some(snapshot),
                        install,
                    );
                }
                install();
                Ok(())
            },
            super::egress_reply::Store::Profile => {
                let (cache, snapshot) = self
                    .profile
                    .as_ref()
                    .ok_or_else(|| Self::Error::Invalid("egress profile unavailable".into()))?;
                cache.persist_egress_for_profile(
                    target.principal,
                    target.capsule,
                    &target.endpoint(),
                    Some(snapshot),
                    self.devices,
                )
            },
        }
    }
}

fn event_principal(event: &AstridEvent) -> Option<&str> {
    match event {
        AstridEvent::Ipc { message, .. } => message.principal.as_deref(),
        _ => None,
    }
}

fn event_request_owner(event: &AstridEvent) -> Option<astrid_events::ipc::RequestOwnerId> {
    match event {
        AstridEvent::Ipc { message, .. } => message.request_owner,
        _ => None,
    }
}

use super::consent_identity;

fn response_identity_matches(
    expected_principal: &str,
    expected_owner: astrid_events::ipc::RequestOwnerId,
    event: &AstridEvent,
) -> bool {
    consent_identity::matches(
        expected_principal.as_bytes(),
        expected_owner.as_u128(),
        event_principal(event).map(str::as_bytes),
        event_request_owner(event).map(astrid_events::ipc::RequestOwnerId::as_u128),
    )
}

async fn await_matching_consent_response(
    receiver: &mut astrid_events::EventReceiver,
    expected_principal: &str,
    expected_owner: astrid_events::ipc::RequestOwnerId,
    capsule_id: &str,
    request_id: &str,
    timeout: std::time::Duration,
) -> Option<std::sync::Arc<AstridEvent>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let Ok(Some(event)) = tokio::time::timeout(remaining, receiver.recv()).await else {
            return None;
        };
        if response_identity_matches(expected_principal, expected_owner, &event) {
            return Some(event);
        }
        let got = event_principal(&event);
        let got_owner = event_request_owner(&event).map(|owner| owner.to_string());
        tracing::warn!(
            target: "astrid.audit.http",
            security_event = true,
            capsule_id = %capsule_id,
            request_id = %request_id,
            expected_principal = %expected_principal,
            got_principal = got.unwrap_or("<none>"),
            expected_request_owner = %expected_owner,
            got_request_owner = got_owner.as_deref().unwrap_or("<none>"),
            "local-egress consent: rejected response from the wrong principal or authenticated request owner",
        );
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
    ///
    ///    TRUST ASSUMPTION: treating `LocalSocket` as "the local operator" is
    ///    sound only at two host-controlled boundaries. The native uplink stamps
    ///    it after its signed handshake verifies the principal and device. The
    ///    compatibility capsule path stamps it in `net::tcp_stream::read` only
    ///    when `has_uplink_capability` holds; that capability must remain limited
    ///    to designated uplink capsules. A weaker handshake or a grant to an
    ///    arbitrary capsule would let it forge local origin and self-approve
    ///    egress. Those authentication and capability boundaries—not this
    ///    origin comparison—are the enforcement floor.
    /// 2. Else, when a profile cache is installed, resolve the principal
    ///    before either allowance. A failed resolve or `enabled = false`
    ///    returns `false` with no prompt and no new runtime grant. The
    ///    resolved `Arc` is the profile this decision admits.
    /// 3. Else, if `principal` already holds a runtime grant for THIS capsule
    ///    reaching `host:port`, return `true` immediately (no prompt). The grant
    ///    is keyed on `capsule_id` too, so capsule B never short-circuits on
    ///    capsule A's grant. This check runs only after step 2 succeeds.
    /// 4. Else, if the admitted profile remembers an `approve_always` grant for
    ///    THIS capsule reaching `host:port` (`network.capsule_egress[<capsule>]`),
    ///    return `true` immediately (no prompt). The in-memory store above starts
    ///    empty after a daemon restart, so this persisted consult is what makes
    ///    `approve_always` actually survive a restart. It is per-capsule AND
    ///    per-principal by construction.
    /// 5. Else elicit consent (`ApprovalRequired` on `astrid.v1.approval`,
    ///    resource = `host:port` only, reason names the capsule) and block,
    ///    bounded by [`CONSENT_TIMEOUT_MS`] and the capsule cancel token.
    ///    A changed admitted profile denies the reply and records no session
    ///    grant. A one-shot approval admits this request. Session approval
    ///    records an in-memory allowance. Durable approval writes the capsule's
    ///    profile entry and rechecks the admitted profile under the write lock.
    ///    Denial and timeout close the request.
    ///
    /// `host` is the URL host (an IP literal in v1 scope); `port` is the
    /// resolved request port.
    pub fn consent_local_egress(&mut self, host: &str, port: u16) -> bool {
        self.admit_local_egress(host, port).is_some()
    }

    pub(super) fn admit_egress_caller(&self) -> Option<EgressAuthority> {
        super::consent_reply::admit(
            self.begin_host_operation(),
            || self.begin_device_operation(),
            || Ok(None),
        )
    }

    pub(super) fn admit_local_egress(&mut self, host: &str, port: u16) -> Option<EgressAuthority> {
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
            return None;
        }

        let Some(store) = self.allowance_store.clone() else {
            // No allowance store wired (minimal/test host): cannot cache or
            // look up a grant, so cannot consent. Fail closed.
            return None;
        };
        let principal = self.effective_principal();
        // The grant is scoped to THIS capsule: a grant for capsule A reaching
        // H:P must never exempt capsule B reaching H:P for the same principal.
        let capsule_id = self.capsule_id.to_string();
        let target = LocalTarget {
            principal: &principal,
            capsule: &capsule_id,
            host,
            port,
        };
        let endpoint = target.endpoint();

        let mut audit = super::approval_audit::ApprovalAudit::new(
            self,
            &principal,
            EGRESS_CONSENT_ACTION,
            &endpoint,
        );

        let Some(prompt_authority) = self.admit_egress_caller() else {
            audit.denied("authority_unavailable", "could not admit the egress caller");
            return None;
        };

        // Pin the profile used for this decision before consulting either
        // allowance source. Invalidation while a prompt is open cancels it.
        let admitted_profile = if let Some(cache) = &self.profile_cache {
            let Ok(profile) = cache.resolve(&principal) else {
                audit.denied("profile", "principal profile unavailable");
                return None;
            };
            if !profile.enabled {
                audit.denied("profile", "principal disabled");
                return None;
            }
            Some((cache.as_ref(), profile))
        } else {
            None
        };
        // 3. EXISTING-GRANT FAST PATH. A prior consent for this principal +
        // capsule + endpoint short-circuits the prompt.
        if has_runtime_grant(&store, &principal, &capsule_id, host, port) {
            audit.granted(HostApprovalScope::Session, "session_grant");
            return Some(prompt_authority);
        }

        // 4. PERSISTED-GRANT FAST PATH. The in-memory store above is empty
        // after a daemon restart, so a prior `approve_always` would otherwise be
        // silently forgotten and the operator re-prompted. Consult the
        // principal's on-disk profile for a remembered grant under THIS capsule
        // — the persistence half of the `approve_always` "remember across
        // restarts" contract. Per-capsule AND per-principal by construction (see
        // `has_persisted_grant`); never widens beyond this principal+capsule.
        // This short-circuits only the ELICIT — the origin gate and SSRF airlock
        // upstream still bind (we are only reached on a `LocalSocket`,
        // airlock-rejected IP-literal endpoint).
        if let Some((_, profile)) = &admitted_profile
            && has_persisted_grant(profile, &capsule_id, host, port)
        {
            tracing::debug!(
                target: "astrid.audit.http",
                capsule_id = %self.capsule_id.as_str(),
                %principal,
                endpoint = %endpoint,
                "local-egress consent: honoring persisted approve_always grant (no prompt)"
            );
            audit.granted(HostApprovalScope::Always, "remembered_consent");
            return Some(prompt_authority);
        }

        // 5. ELICIT. Publish `ApprovalRequired` and block for the response.
        let event =
            self.elicit_egress_consent(&principal, &endpoint, &mut audit, prompt_authority)?;
        let AstridEvent::Ipc { message, .. } = &*event else {
            audit.denied("error", "unexpected response event");
            return None;
        };
        let IpcPayload::ApprovalResponse { decision, .. } = &message.payload else {
            audit.denied("error", "unexpected response payload");
            return None;
        };
        let Some(authority) = super::consent_reply::admit(
            self.begin_host_operation(),
            || self.begin_device_operation(),
            || self.begin_message_device_operation(message),
        ) else {
            audit.denied(
                "authority_unavailable",
                "could not re-admit the egress reply",
            );
            return None;
        };
        if let Some((cache, admitted)) = &admitted_profile
            && !cache
                .resolve(&principal)
                .is_ok_and(|current| std::sync::Arc::ptr_eq(admitted, &current))
        {
            audit.denied("profile", "principal profile changed during consent");
            return None;
        }
        let mut writer = GrantWriter {
            devices: [
                self.caller_context
                    .as_ref()
                    .map(IpcMessage::device_stamp)
                    .unwrap_or_default(),
                message.device_stamp(),
            ],
            store: &store,
            profile: admitted_profile,
        };
        let outcome = match super::egress_reply::apply(
            &authority,
            decision.as_bytes(),
            writer.profile.is_some(),
            target,
            &mut writer,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::warn!(security_event = true, %principal, %endpoint, %error,
                    "could not persist local egress approval");
                audit.denied("profile", "could not persist egress approval");
                return None;
            },
        };
        match outcome {
            Decision::Deny => {
                audit.denied("user", "not approved");
                tracing::info!(
                    security_event = true,
                    capsule_id = %self.capsule_id.as_str(),
                    %principal,
                    endpoint = %endpoint,
                    decision = %decision,
                    "local-egress consent: not approved; request stays blocked (fail-closed)"
                );
                None
            },
            Decision::Once => {
                if let Some((cache, snapshot)) = &writer.profile
                    && cache
                        .with_session_devices(&principal, writer.devices, Some(snapshot), || {})
                        .is_err()
                {
                    audit.denied(
                        "authority_unavailable",
                        "egress profile changed before approval",
                    );
                    return None;
                }
                // Approved for this request only — let it through, cache
                // nothing. The next request to the same endpoint prompts again.
                tracing::info!(
                    security_event = true,
                    capsule_id = %self.capsule_id.as_str(),
                    %principal,
                    endpoint = %endpoint,
                    "local-egress consent: approved once"
                );
                audit.granted(HostApprovalScope::Once, "user");
                Some(authority)
            },
            Decision::Session => {
                tracing::info!(
                    security_event = true,
                    capsule_id = %self.capsule_id.as_str(),
                    %principal,
                    endpoint = %endpoint,
                    "local-egress consent: approved for session"
                );
                audit.granted(HostApprovalScope::Session, "user");
                Some(authority)
            },
            Decision::Always => {
                tracing::info!(
                    security_event = true,
                    capsule_id = %self.capsule_id.as_str(),
                    %principal,
                    endpoint = %endpoint,
                    "local-egress consent: approved always"
                );
                audit.granted(HostApprovalScope::Always, "user");
                Some(authority)
            },
        }
    }

    /// Publish an `ApprovalRequired` for the local-egress endpoint and block for
    /// the operator's response. Returns the matched event so admission can
    /// validate the responding device before applying its decision.
    ///
    /// The resource is the `host:port` ONLY (no URL path / query — the consent
    /// is for the endpoint, not a specific request), and the reason names the
    /// capsule so the operator knows who is asking. Subscribe-before-publish
    /// avoids a response race, exactly like `host/approval.rs::request_approval`.
    ///
    /// # Response principal isolation
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
    /// Because the topic is shared, the request is stamped with the originating
    /// principal and the response waiter accepts only replies stamped with that
    /// same principal. A surface with response-topic publish rights but the
    /// wrong principal can no longer satisfy another principal's consent prompt,
    /// and unstamped replies fail closed by timing out.
    fn elicit_egress_consent(
        &self,
        principal: &PrincipalId,
        endpoint: &str,
        audit: &mut super::approval_audit::ApprovalAudit,
        prompt_guards: EgressAuthority,
    ) -> Option<std::sync::Arc<AstridEvent>> {
        let event_bus = self.event_bus.clone();
        let runtime_handle = self.runtime_handle.clone();
        let cancel_token = self.effective_cancel_token();
        let blocking_semaphore = self.blocking_semaphore.clone();
        let capsule_id = self.capsule_id.to_string();
        let principal_name = principal.to_string();
        let Some(request_owner) = self
            .caller_context
            .as_ref()
            .and_then(|message| message.request_owner)
        else {
            tracing::warn!(
                security_event = true,
                capsule_id = %capsule_id,
                %principal,
                endpoint,
                "local-egress consent has no authenticated request owner; denying"
            );
            audit.denied("no_request_owner", "no authenticated request owner");
            return None;
        };

        let request_id = Uuid::new_v4().to_string();
        // Durable before the prompt is published.
        audit.requested(&request_id);
        // Shared approval response channel — see the "Response principal
        // isolation" note above for the same-principal response check that
        // makes this safe without a separate egress namespace.
        let response_topic = Topic::approval_response(&request_id);
        // Subscribe BEFORE publishing to prevent a publish/subscribe race.
        let mut receiver = event_bus.subscribe_topic(response_topic.as_str());

        let payload = IpcPayload::ApprovalRequired {
            request_id: request_id.clone(),
            request_owner: request_owner.to_string(),
            action: EGRESS_CONSENT_ACTION.to_string(),
            resource: endpoint.to_string(),
            reason: format!(
                "Capsule '{capsule_id}' wants to reach the local endpoint \
                 {endpoint} (running as '{principal}')"
            ),
        };
        // Kernel-originated (nil source_id): the host is asking on the operator's
        // behalf, not a capsule forging an approval request.
        let message = IpcMessage::new(Topic::approval_request(), payload, Uuid::nil())
            .with_principal(principal.to_string())
            .with_request_owner(request_owner);
        event_bus.publish(AstridEvent::Ipc {
            message,
            metadata: astrid_events::EventMetadata::default(),
        });

        drop(prompt_guards);
        let event = util::bounded_block_on_cancellable(
            &runtime_handle,
            &blocking_semaphore,
            &cancel_token,
            async {
                await_matching_consent_response(
                    &mut receiver,
                    &principal_name,
                    request_owner,
                    &capsule_id,
                    &request_id,
                    std::time::Duration::from_millis(CONSENT_TIMEOUT_MS),
                )
                .await
            },
        )
        .flatten();

        if event.is_none() {
            if cancel_token.is_cancelled() {
                audit.denied("cancelled", "invocation cancelled");
            } else {
                audit.denied("timeout", "no response before the timeout");
            }
        }
        event
    }
}

#[cfg(test)]
#[path = "consent_egress_tests.rs"]
mod tests;

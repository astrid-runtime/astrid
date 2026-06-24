/// Admin management API dispatcher (issue #672, Layer 6).
pub mod admin;
/// `KernelRequest::InstallCapsule` handler — delegates to the
/// `astrid-capsule-install` library so the daemon and the CLI reach
/// disk through the same code path.
mod install;

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use astrid_audit::{AuditAction, AuditOutcome, AuthorizationProof};
use astrid_capabilities::{CapabilityCheck, PermissionError};
use astrid_core::principal::PrincipalId;
use astrid_events::ipc::{IpcMessage, IpcPayload};
use astrid_events::kernel_api::{KernelRequest, KernelResponse};
use serde::Serialize;
use tracing::{debug, info, warn};

#[cfg(test)]
mod capability_catalog_tests;
#[cfg(test)]
mod connection_tracker_tests;

/// Spawns background tasks for the kernel management API and connection tracking.
///
/// Two listeners:
/// 1. `astrid.v1.request.*` - handles management commands (list capsules, reload, etc.)
/// 2. `client.v1.*` - tracks the active connection count per principal.
///
/// Uplink capsules (e.g. the CLI proxy) publish `client.v1.connect` /
/// `client.v1.disconnect` carrying the authenticated principal as a socket is
/// accepted / closed; the tracker adjusts `active_connections` accordingly.
/// Because the SDK exposes no typed-payload publish (only JSON), the tracker
/// keys off the **topic** as well as the typed `IpcPayload::Connect` /
/// `Disconnect` that native producers emit — see [`connection_signal`].
#[must_use]
pub(crate) fn spawn_kernel_router(kernel: Arc<crate::Kernel>) -> tokio::task::JoinHandle<()> {
    // Spawn the connection tracker as a sibling task.
    drop(spawn_connection_tracker(Arc::clone(&kernel)));
    // Spawn the Layer 6 admin dispatcher as a sibling task (issue #672).
    drop(admin::spawn_admin_router(Arc::clone(&kernel)));

    // Broadcast-path subscriber. Routed demux
    // (`EventBus::subscribe_topic_routed`) is reserved for guest
    // subscriptions where per-principal isolation matters; kernel-
    // internal consumers see every event by design (no synthetic
    // capsule_uuid).
    let mut receiver = kernel
        .event_bus
        .subscribe_topic_as("astrid.v1.request.*", "kernel_router");

    tokio::spawn(async move {
        let mut rate_limiter = ManagementRateLimiter::new();

        while let Some(event) = receiver.recv().await {
            let astrid_events::AstridEvent::Ipc { message, .. } = &*event else {
                continue;
            };

            // Only process standard IPC messages that contain JSON payloads.
            let IpcPayload::RawJson(val) = &message.payload else {
                continue;
            };

            match serde_json::from_value::<KernelRequest>(val.clone()) {
                Ok(req) => {
                    let (method, limit) = rate_limit_for_request(&req);
                    if let Some(max) = limit
                        && !rate_limiter.check(method, max)
                    {
                        warn!(
                            security_event = true,
                            method = method,
                            "Rate limited kernel management request"
                        );
                        let response_topic = response_topic_for(&message.topic);
                        publish_response(
                            &kernel,
                            response_topic,
                            KernelResponse::Error(format!(
                                "Rate limited: max {max} {method} requests per minute"
                            )),
                        );
                        continue;
                    }
                    let caller = resolve_caller(message);
                    let device_key_id = resolve_device_key_id(message);
                    handle_request(&kernel, message.topic.clone(), caller, device_key_id, req)
                        .await;
                },
                Err(e) => {
                    // The kernel router shares the broadcast
                    // `astrid.v1.request.*` namespace with capsule traffic — the
                    // sage-mcp broker's `astrid.v1.request.mcp.*`, and any future
                    // capsule-to-capsule request topics. `KernelRequest` is
                    // `#[serde(tag = "method")]`, so a payload WITHOUT a `method`
                    // discriminator was never addressed to the kernel; ignore it
                    // quietly rather than warning. Only a payload that IS shaped
                    // like a kernel request (`method` present) yet fails to parse
                    // is a genuinely malformed management request worth a warning.
                    if val.get("method").is_some() {
                        warn!(error = %e, topic = %message.topic, "Failed to parse KernelRequest from IPC");
                    } else {
                        debug!(topic = %message.topic, "Ignoring non-kernel request on shared astrid.v1.request.* namespace");
                    }
                },
            }
        }
    })
}

/// Whether a `client.v1.*` message opens or closes a connection.
#[derive(Debug, PartialEq, Eq)]
enum ConnectionSignal {
    Opened,
    /// Carries the disconnect reason when present — the typed
    /// `IpcPayload::Disconnect { reason }`, or a `"reason"` string in a JSON
    /// payload — so the tracker can preserve it in the diagnostic log.
    Closed {
        reason: Option<String>,
    },
}

/// Classifies a `client.v1.*` message as a connection open/close.
///
/// Recognises **both** the typed [`IpcPayload::Connect`]/[`IpcPayload::Disconnect`]
/// that native producers emit, **and** the `client.v1.connect` /
/// `client.v1.disconnect` topics carrying any payload. Uplink capsules can only
/// reach the bus through the JSON-only SDK publish surface (no typed-payload
/// publish exists), so the topic is the only signal they can produce — without
/// the topic arm, the per-principal connection counter is never populated and
/// the idle monitor / `astrid who` see zero connections regardless of reality.
///
/// Typed payloads take precedence over the topic, so a mismatched topic can
/// never suppress a real connection event.
fn connection_signal(topic: &str, payload: &IpcPayload) -> Option<ConnectionSignal> {
    match payload {
        IpcPayload::Disconnect { reason } => Some(ConnectionSignal::Closed {
            reason: reason.clone(),
        }),
        IpcPayload::Connect => Some(ConnectionSignal::Opened),
        // Uplink capsules can only publish JSON; the topic is the signal, and
        // the reason (if any) rides along under the `"reason"` key.
        IpcPayload::RawJson(val) if topic == "client.v1.disconnect" => {
            let reason = val.get("reason").and_then(|r| r.as_str().map(String::from));
            Some(ConnectionSignal::Closed { reason })
        },
        _ if topic == "client.v1.disconnect" => Some(ConnectionSignal::Closed { reason: None }),
        _ if topic == "client.v1.connect" => Some(ConnectionSignal::Opened),
        _ => None,
    }
}

/// Tracks client connection lifecycle events.
///
/// Listens on `client.v1.*` topics and adjusts the per-principal connection
/// count via [`connection_signal`] (typed payload or topic).
fn spawn_connection_tracker(kernel: Arc<crate::Kernel>) -> tokio::task::JoinHandle<()> {
    // Broadcast-path subscriber. See `spawn_kernel_router` for the
    // rationale on staying on the untargeted subscribe path.
    let mut receiver = kernel
        .event_bus
        .subscribe_topic_as("client.v1.*", "connection_tracker");

    tokio::spawn(async move {
        while let Some(event) = receiver.recv().await {
            let astrid_events::AstridEvent::Ipc { message, .. } = &*event else {
                continue;
            };
            // Derive the connecting principal from the IPC message. Today's
            // CLI socket always sets this to the default principal
            // (bootstrapped in `bootstrap_cli_root_user`), but as per-agent
            // socket auth lands (#658) the same plumbing will carry the
            // real invoking principal.
            let principal = message
                .principal
                .as_deref()
                .and_then(|p| astrid_core::principal::PrincipalId::new(p).ok())
                .unwrap_or_default();
            match connection_signal(&message.topic, &message.payload) {
                Some(ConnectionSignal::Closed { reason }) => {
                    kernel.connection_closed(&principal);
                    debug!(%principal, topic = %message.topic, ?reason, "Client disconnected");
                },
                Some(ConnectionSignal::Opened) => {
                    kernel.connection_opened(&principal);
                    debug!(%principal, topic = %message.topic, "New client connection accepted");
                },
                None => {},
            }
        }
    })
}

/// Map a kernel request topic (`astrid.v1.request.<suffix>`) to its correlated
/// response topic (`astrid.v1.response.<suffix>`), so a reply lands on the
/// channel the client is waiting on. A topic that is not a kernel request topic
/// is returned unchanged.
fn response_topic_for(request_topic: &str) -> String {
    request_topic
        .strip_prefix("astrid.v1.request.")
        .map_or_else(
            || request_topic.to_string(),
            |suffix| format!("astrid.v1.response.{suffix}"),
        )
}

#[expect(clippy::too_many_lines)]
async fn handle_request(
    kernel: &Arc<crate::Kernel>,
    topic: String,
    caller: PrincipalId,
    device_key_id: Option<String>,
    req: KernelRequest,
) {
    let response_topic = response_topic_for(&topic);

    // Capability enforcement preamble (issue #670). Resolve the caller's
    // profile, compute the required capability for this request, and
    // reject with an audited `Denied` entry on failure. No match arm
    // below is reached without `authorize_request` returning Ok.
    let method = kernel_request_method(&req);
    let scope = resolve_scope(&req, &caller);
    let required_cap = required_capability(&req, scope);
    match authorize_request(kernel, &caller, device_key_id.as_deref(), required_cap) {
        Ok(()) => {
            record_admin_audit(
                kernel,
                AdminAuditEntry {
                    caller: &caller,
                    method,
                    required_cap,
                    device_key_id: device_key_id.as_deref(),
                    target_principal: None,
                    params: None,
                    authorization: AuthorizationProof::System {
                        reason: format!("policy allow: {caller} holds {required_cap}"),
                    },
                    outcome: AuditOutcome::success(),
                },
            );
        },
        Err(e) => {
            warn!(
                security_event = true,
                method = method,
                principal = %caller,
                required = required_cap,
                "Permission check denied admin request"
            );
            record_admin_audit(
                kernel,
                AdminAuditEntry {
                    caller: &caller,
                    method,
                    required_cap,
                    device_key_id: device_key_id.as_deref(),
                    target_principal: None,
                    params: None,
                    authorization: AuthorizationProof::Denied {
                        reason: e.to_string(),
                    },
                    outcome: AuditOutcome::failure(e.to_string()),
                },
            );
            publish_response(kernel, response_topic, KernelResponse::Error(e.to_string()));
            return;
        },
    }

    let res = match req {
        KernelRequest::InstallCapsule { source, workspace } => {
            info!(source = %source, workspace, "Kernel received install request");
            install::handle_install_capsule(kernel, &source, workspace).await
        },
        KernelRequest::ApproveCapability {
            request_id,
            signature: _,
        } => {
            info!(request_id = %request_id, "Kernel received capability approval");
            KernelResponse::Error("Approval logic not yet implemented in kernel router".to_string())
        },
        KernelRequest::ListCapsules => {
            let reg = kernel.capsules.read().await;
            let mut list = Vec::new();
            for c in reg.list() {
                list.push(c.to_string());
            }
            KernelResponse::Success(serde_json::json!(list))
        },
        KernelRequest::GetCommands => {
            let reg = kernel.capsules.read().await;
            let mut commands = Vec::new();
            for c in reg.values() {
                for cmd in &c.manifest().commands {
                    commands.push(astrid_events::kernel_api::CommandInfo {
                        name: cmd.name.clone(),
                        description: cmd
                            .description
                            .clone()
                            .unwrap_or_else(|| "No description".to_string()),
                        provider_capsule: c.id().to_string(),
                        kind: cmd.kind,
                    });
                }
            }
            info!(
                count = commands.len(),
                capsules = reg.len(),
                "GetCommands: returning {} commands from {} capsules",
                commands.len(),
                reg.len()
            );
            KernelResponse::Commands(commands)
        },
        KernelRequest::ReloadCapsules => {
            // Unregister capsules in a Failed state so they can be re-loaded
            // with fresh configuration (e.g. after onboarding writes .env.json).
            {
                let reg = kernel.capsules.read().await;
                let failed_ids: Vec<_> = reg
                    .list()
                    .into_iter()
                    .filter(|id| {
                        reg.get(id).is_some_and(|c| {
                            matches!(c.state(), astrid_capsule::capsule::CapsuleState::Failed(_))
                        })
                    })
                    .cloned()
                    .collect();
                drop(reg);

                let mut reg = kernel.capsules.write().await;
                for id in failed_ids {
                    let _ = reg.unregister(&id);
                }
            }

            kernel.load_all_capsules().await;
            KernelResponse::Success(serde_json::json!({"status": "reloaded"}))
        },
        KernelRequest::ReloadCapsule { id } => {
            // Hot-swap a single capsule (or add it if not yet loaded) without a
            // daemon restart. The kernel publishes capsules_loaded on success so
            // the tool surface refreshes. `id` is client-supplied over IPC, so
            // validate it (CapsuleId::new rejects unsafe ids) before using it as
            // a registry key — never construct it unchecked from untrusted input.
            match astrid_capsule::capsule::CapsuleId::new(id.clone()) {
                Ok(cap_id) => match kernel.reload_one_capsule(&cap_id).await {
                    Ok(()) => KernelResponse::Success(
                        serde_json::json!({"status": "reloaded", "capsule": id}),
                    ),
                    Err(e) => {
                        KernelResponse::Error(format!("reload of capsule '{id}' failed: {e}"))
                    },
                },
                Err(e) => KernelResponse::Error(format!("invalid capsule id '{id}': {e}")),
            }
        },
        KernelRequest::UnloadCapsule { id } => {
            // Unload a single capsule from the running daemon without a restart.
            // The on-disk removal that triggers this is authoritative and
            // dependency-checked by the CLI; here we only unregister the live
            // instance. `id` is client-supplied over IPC, so validate it
            // (CapsuleId::new rejects unsafe ids) before using it as a registry
            // key — never construct it unchecked from untrusted input.
            match astrid_capsule::capsule::CapsuleId::new(id.clone()) {
                Ok(cap_id) => match kernel.unload_one_capsule(&cap_id).await {
                    Ok(true) => KernelResponse::Success(
                        serde_json::json!({"status": "unloaded", "capsule": id}),
                    ),
                    Ok(false) => KernelResponse::Success(
                        serde_json::json!({"status": "not_loaded", "capsule": id}),
                    ),
                    Err(e) => {
                        KernelResponse::Error(format!("unload of capsule '{id}' failed: {e}"))
                    },
                },
                Err(e) => KernelResponse::Error(format!("invalid capsule id '{id}': {e}")),
            }
        },
        KernelRequest::Shutdown { reason } => {
            info!(
                reason = reason.as_deref().unwrap_or("none"),
                "Kernel received shutdown request via management API"
            );
            // Publish response before signaling shutdown so the client gets confirmation.
            publish_response(
                kernel,
                response_topic.clone(),
                KernelResponse::Success(serde_json::json!({"status": "shutting_down"})),
            );
            // Signal the daemon's main loop to exit gracefully.
            let _ = kernel.shutdown_tx.send(true);
            // Return early — the daemon will call kernel.shutdown() from its main loop.
            return;
        },
        KernelRequest::GetStatus => {
            let uptime = kernel.boot_time.elapsed().as_secs();
            let reg = kernel.capsules.read().await;
            let loaded: Vec<String> = reg.list().iter().map(ToString::to_string).collect();
            let by_principal = kernel
                .connections_by_principal()
                .into_iter()
                .map(
                    |(p, c)| astrid_events::kernel_api::PrincipalConnectionCount {
                        principal: p.to_string(),
                        count: u32::try_from(c).unwrap_or(u32::MAX),
                    },
                )
                .collect();
            let status = astrid_events::kernel_api::DaemonStatus {
                pid: std::process::id(),
                uptime_secs: uptime,
                version: env!("CARGO_PKG_VERSION").to_string(),
                ephemeral: false, // The kernel doesn't know; daemon sets this via response override if needed
                connected_clients: u32::try_from(kernel.total_connection_count())
                    .unwrap_or(u32::MAX),
                connections_by_principal: by_principal,
                loaded_capsules: loaded,
            };
            KernelResponse::Status(status)
        },
        KernelRequest::GetCapsuleMetadata => {
            let reg = kernel.capsules.read().await;
            let mut entries = Vec::new();
            for capsule in reg.values() {
                let manifest = capsule.manifest();
                entries.push(astrid_events::kernel_api::CapsuleMetadataEntry {
                    name: manifest.package.name.clone(),
                    interceptor_events: manifest
                        .subscribes
                        .iter()
                        .filter(|(_, def)| def.handler.is_some())
                        .map(|(topic, _)| topic.clone())
                        .collect(),
                });
            }
            KernelResponse::CapsuleMetadata(entries)
        },
        KernelRequest::GetAgentReadiness => {
            let reg = kernel.capsules.read().await;
            let manifests: Vec<&astrid_capsule::manifest::CapsuleManifest> = reg
                .values()
                .map(astrid_capsule::capsule::Capsule::manifest)
                .collect();
            let readiness = astrid_capsule::readiness::agent_loop_readiness(&manifests);
            KernelResponse::AgentReadiness(readiness)
        },
    };

    publish_response(kernel, response_topic, res);
}

fn publish_response<R: Serialize>(kernel: &Arc<crate::Kernel>, response_topic: String, res: R) {
    if let Ok(val) = serde_json::to_value(res) {
        let msg = IpcMessage::new(
            response_topic,
            IpcPayload::RawJson(val),
            kernel.session_id.0,
        );
        let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
            metadata: astrid_events::EventMetadata::new("kernel_router"),
            message: msg,
        });
    }
}

// ---------------------------------------------------------------------------
// Management API rate limiting
// ---------------------------------------------------------------------------

/// Sliding window rate limiter for management API requests.
/// Tracks per-request timestamps and evicts entries older than 60 seconds,
/// preventing the 2x burst possible with fixed-window designs.
/// Single-consumer (owned by the router task), no concurrency concerns.
struct ManagementRateLimiter {
    buckets: HashMap<&'static str, VecDeque<Instant>>,
}

impl ManagementRateLimiter {
    fn new() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }

    /// Check if a request of the given type is within the rate limit.
    /// Returns `true` if allowed, `false` if rate-limited.
    fn check(&mut self, method: &'static str, max_per_minute: u32) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_mins(1);
        let timestamps = self.buckets.entry(method).or_default();

        // Evict timestamps older than the 60-second sliding window.
        while let Some(&oldest) = timestamps.front() {
            if now.saturating_duration_since(oldest) >= window {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        if timestamps.len() >= max_per_minute as usize {
            return false;
        }
        timestamps.push_back(now);
        true
    }
}

/// Return the rate limit label and max-per-minute for a request type.
/// Returns `None` for the limit if the request type is not rate-limited.
fn rate_limit_for_request(req: &KernelRequest) -> (&'static str, Option<u32>) {
    (kernel_request_method(req), rate_limit_max(req))
}

/// Return the max-per-minute rate limit for a request type, if any.
fn rate_limit_max(req: &KernelRequest) -> Option<u32> {
    match req {
        KernelRequest::ReloadCapsules
        | KernelRequest::ReloadCapsule { .. }
        | KernelRequest::UnloadCapsule { .. } => Some(5),
        KernelRequest::InstallCapsule { .. } | KernelRequest::ApproveCapability { .. } => Some(10),
        KernelRequest::Shutdown { .. } => Some(1),
        KernelRequest::ListCapsules
        | KernelRequest::GetCommands
        | KernelRequest::GetCapsuleMetadata
        | KernelRequest::GetAgentReadiness
        | KernelRequest::GetStatus => None,
    }
}

// ---------------------------------------------------------------------------
// Management API capability enforcement (issue #670)
// ---------------------------------------------------------------------------

/// The authority surface a given [`KernelRequest`] operates over.
///
/// Today's `KernelRequest` variants carry no target-principal field, so
/// [`resolve_scope`] always returns [`AuthorityScope::Self_`] — the
/// request operates on the caller's own home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityScope {
    /// Request operates on the caller's own principal.
    Self_,
    /// Request operates on global/system-wide state (e.g. shutdown).
    Global,
}

/// Return the authority scope the caller is exercising for `req`.
///
/// Currently always returns [`AuthorityScope::Self_`] because no
/// `KernelRequest` variant carries a `target_principal` field yet.
#[must_use]
pub fn resolve_scope(_req: &KernelRequest, _caller: &PrincipalId) -> AuthorityScope {
    AuthorityScope::Self_
}

/// Return the static capability string required to satisfy `req` under
/// `scope`.
///
/// Pure function so the capability mapping can be unit-tested in
/// isolation. Every `KernelRequest` variant is covered; there is no
/// default-allow branch.
#[must_use]
pub fn required_capability(req: &KernelRequest, scope: AuthorityScope) -> &'static str {
    match (req, scope) {
        (KernelRequest::Shutdown { .. }, _) => "system:shutdown",
        (KernelRequest::GetStatus, _) => "system:status",
        (
            KernelRequest::ReloadCapsules | KernelRequest::ReloadCapsule { .. },
            AuthorityScope::Self_,
        ) => "self:capsule:reload",
        (KernelRequest::ReloadCapsules | KernelRequest::ReloadCapsule { .. }, _) => {
            "capsule:reload"
        },
        (KernelRequest::UnloadCapsule { .. }, AuthorityScope::Self_) => "self:capsule:remove",
        (KernelRequest::UnloadCapsule { .. }, _) => "capsule:remove",
        (KernelRequest::InstallCapsule { .. }, AuthorityScope::Self_) => "self:capsule:install",
        (KernelRequest::InstallCapsule { .. }, _) => "capsule:install",
        (
            KernelRequest::ListCapsules
            | KernelRequest::GetCommands
            | KernelRequest::GetCapsuleMetadata
            | KernelRequest::GetAgentReadiness,
            AuthorityScope::Self_,
        ) => "self:capsule:list",
        (
            KernelRequest::ListCapsules
            | KernelRequest::GetCommands
            | KernelRequest::GetCapsuleMetadata
            | KernelRequest::GetAgentReadiness,
            _,
        ) => "capsule:list",
        (KernelRequest::ApproveCapability { .. }, _) => "self:approval:respond",
    }
}

/// Short identifier for a [`KernelRequest`] variant, used for rate-limit
/// labels and audit method names.
#[must_use]
pub fn kernel_request_method(req: &KernelRequest) -> &'static str {
    match req {
        KernelRequest::ReloadCapsules => "ReloadCapsules",
        KernelRequest::ReloadCapsule { .. } => "ReloadCapsule",
        KernelRequest::UnloadCapsule { .. } => "UnloadCapsule",
        KernelRequest::InstallCapsule { .. } => "InstallCapsule",
        KernelRequest::ApproveCapability { .. } => "ApproveCapability",
        KernelRequest::ListCapsules => "ListCapsules",
        KernelRequest::GetCommands => "GetCommands",
        KernelRequest::GetCapsuleMetadata => "GetCapsuleMetadata",
        KernelRequest::GetAgentReadiness => "GetAgentReadiness",
        KernelRequest::Shutdown { .. } => "Shutdown",
        KernelRequest::GetStatus => "GetStatus",
    }
}

/// Resolve the caller [`PrincipalId`] from an incoming [`IpcMessage`].
///
/// Pre-#658 single-token socket traffic arrives without a principal
/// field set; we fall back to [`PrincipalId::default`] — the default
/// principal is bootstrapped with the built-in `admin` group, matching
/// today's single-tenant behaviour.
fn resolve_caller(message: &IpcMessage) -> PrincipalId {
    message
        .principal
        .as_deref()
        .and_then(|p| PrincipalId::new(p).ok())
        .unwrap_or_default()
}

/// Resolve the authenticating device `key_id` from an incoming [`IpcMessage`].
///
/// Host-derived metadata stamped by the socket per-connection registry or the
/// gateway-signed bearer (never a client-controlled field). `Some(key_id)`
/// means the request authenticated with a specific registered device, whose
/// scope the cap-gate applies as an attenuation floor; `None` means an
/// unattenuated full-principal request (every legacy / unpaired connection).
fn resolve_device_key_id(message: &IpcMessage) -> Option<String> {
    message.device_key_id.clone()
}

/// Evaluate the capability check for `caller` against the kernel's
/// resolved group config and the caller's profile.
///
/// Returns `Ok(())` on success, or the policy reason on denial. Profile
/// resolution failures (malformed TOML, IO error) are themselves treated
/// as deny — fail-closed — with a synthesized `MissingCapability` so the
/// deny path has a single shape in the audit log.
fn authorize_request(
    kernel: &crate::Kernel,
    caller: &PrincipalId,
    device_key_id: Option<&str>,
    required_cap: &str,
) -> Result<(), PermissionError> {
    let profile = match kernel.profile_cache.resolve(caller) {
        Ok(p) => p,
        Err(e) => {
            warn!(
                security_event = true,
                principal = %caller,
                error = %e,
                "Profile resolution failed — fail-closed deny"
            );
            return Err(PermissionError::MissingCapability {
                principal: caller.clone(),
                required: required_cap.to_string(),
            });
        },
    };
    // Enabled gate runs BEFORE the capability check so a disabled
    // principal cannot exercise any management API surface — even one
    // they would otherwise be authorized for. The `default` principal
    // is bootstrap-managed and `caps.revoke`/`agent.disable` against
    // it are rejected up front, so this check cannot lock the
    // single-tenant path.
    if !profile.enabled {
        warn!(
            security_event = true,
            principal = %caller,
            required = required_cap,
            "Disabled principal denied — fail-closed enforcement"
        );
        return Err(PermissionError::PrincipalDisabled {
            principal: caller.clone(),
        });
    }
    let groups = kernel.groups.load_full();

    // Per-device scope attenuation. When the request authenticated with a
    // specific registered device, the device's scope is applied as a floor on
    // the principal's effective capabilities (deny wins, can only narrow).
    //
    // Fail-closed on an unresolved key_id: a request that names a device the
    // principal no longer has (revoked / unknown) must NOT fall back to the
    // principal's full authority — that would let a revoked device keep acting.
    //
    // The scope is cloned into a local so it outlives the borrow of `profile`
    // for the `require` call below (a `DeviceScope` clone is cheap — at most a
    // couple of small pattern vectors — and avoids fighting the borrow that
    // `device_by_key_id` takes on `profile`).
    let device_scope: Option<astrid_core::profile::DeviceScope> = if let Some(kid) = device_key_id {
        let Some(dev) = profile.auth.device_by_key_id(kid) else {
            warn!(
                security_event = true,
                principal = %caller,
                key_id = %kid,
                required = required_cap,
                "device_key_id resolves to no registered key — fail-closed deny"
            );
            return Err(PermissionError::DeviceScopeDenied {
                principal: caller.clone(),
                required: required_cap.to_string(),
            });
        };
        Some(dev.scope.clone())
    } else {
        None
    };

    let mut check = CapabilityCheck::new(profile.as_ref(), groups.as_ref(), caller.clone());
    if let Some(scope) = &device_scope {
        check = check.with_device_scope(scope);
    }
    check.require(required_cap)
}

/// Bundled inputs for [`record_admin_audit`] — keeps the call site
/// readable and the function under clippy's `too_many_arguments` cap.
pub(crate) struct AdminAuditEntry<'a> {
    /// Caller principal making the request.
    pub caller: &'a PrincipalId,
    /// Wire-name identifier for the request variant.
    pub method: &'a str,
    /// Capability string evaluated for this request.
    pub required_cap: &'a str,
    /// The authenticating device `key_id` when the request was device-scoped,
    /// so the audit row records which paired device acted. Non-secret (derived
    /// from the public key); `None` for a full-authority request.
    pub device_key_id: Option<&'a str>,
    /// `None` when the request operates on the caller's own principal
    /// (Layer 5) and `Some` when the request mutates another principal
    /// (Layer 6 admin topics like `admin.quota.set`).
    pub target_principal: Option<PrincipalId>,
    /// Request payload for forensic replay (issue #672) — `None` for
    /// [`KernelRequest`] entries that have no params struct, `Some` with
    /// the wire payload for [`AdminKernelRequest`].
    pub params: Option<serde_json::Value>,
    /// Authorization proof (allow / deny).
    pub authorization: AuthorizationProof,
    /// Success or failure outcome.
    pub outcome: AuditOutcome,
}

/// IPC topic the kernel publishes structured audit-entry events to
/// for live subscribers (the HTTP gateway's SSE stream).
///
/// The persistent audit log under `~/.astrid/audit.db` remains the
/// system of record — this topic is a fire-and-forget broadcast for
/// dashboards / monitoring tools that want a live feed. Subscribers
/// scope their view at the consumer end: operators with
/// `audit:read_all` see the firehose, agents see only entries
/// whose `principal` field matches their own.
pub const AUDIT_TOPIC: &str = "astrid.v1.audit.entry";

/// Append an `AdminRequest` audit entry for the given outcome.
/// Persists to the on-disk log AND publishes a live event on
/// [`AUDIT_TOPIC`]. Failures to persist are logged but do not abort
/// the request — the audit log degrades to "continue + alert" by
/// design. A bus-publish failure is similarly best-effort.
fn record_admin_audit(kernel: &crate::Kernel, entry: AdminAuditEntry<'_>) {
    let AdminAuditEntry {
        caller,
        method,
        required_cap,
        device_key_id,
        target_principal,
        params,
        authorization,
        outcome,
    } = entry;
    let action = AuditAction::AdminRequest {
        method: method.to_string(),
        required_capability: required_cap.to_string(),
        target_principal: target_principal.clone(),
        params: params.clone(),
        device_key_id: device_key_id.map(str::to_owned),
    };
    if let Err(e) = kernel.audit_log.append_with_principal(
        kernel.session_id.clone(),
        caller.clone(),
        action,
        authorization.clone(),
        outcome.clone(),
    ) {
        warn!(
            security_event = true,
            principal = %caller,
            method = method,
            error = %e,
            "Failed to persist admin-request audit entry — continuing"
        );
    }

    // Live broadcast. Subscribers filter at the consumer end (the
    // `principal` field is what the gateway's SSE handler uses).
    // The payload is intentionally a flat JSON shape so SSE
    // consumers don't have to reify the kernel-side enum types.
    let event = serde_json::json!({
        "ts_epoch": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        "method": method,
        "required_capability": required_cap,
        "principal": caller.to_string(),
        "device_key_id": device_key_id,
        "target_principal": target_principal.as_ref().map(ToString::to_string),
        "params": params,
        "outcome": match &outcome {
            AuditOutcome::Success { .. } => "success",
            AuditOutcome::Failure { .. } => "failure",
        },
    });
    let msg = IpcMessage::new(AUDIT_TOPIC, IpcPayload::RawJson(event), uuid::Uuid::nil())
        .with_principal(caller.to_string());
    let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("kernel_router::audit"),
        message: msg,
    });
}

#[cfg(test)]
mod tests;

/// Admin management API dispatcher (issue #672, Layer 6).
pub mod admin;
mod device_scope;
/// `KernelRequest::InstallCapsule` handler — delegates to the
/// `astrid-capsule-install` library so the daemon and the CLI reach
/// disk through the same code path.
mod install;
mod rate_limit;
/// Kernel-response publishing envelope + the long-request keepalive pinger.
mod response;

pub(crate) use rate_limit::rate_limit_for_request;
pub(crate) use response::{KeepalivePinger, publish_response, workspace_commit_response};

use astrid_runtime::time::Instant;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use astrid_audit::{AuditAction, AuditOutcome, AuthorizationProof};
use astrid_capabilities::{CapabilityCheck, PermissionError};
use astrid_core::groups::GroupConfig;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{DeviceScope, PrincipalProfile};
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use astrid_events::kernel_api::{KernelRequest, KernelResponse};
use tracing::{debug, info, warn};

use device_scope::resolve_device_scope;

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
pub(crate) fn spawn_kernel_router(kernel: Arc<crate::Kernel>) -> astrid_runtime::JoinHandle<()> {
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

    astrid_runtime::spawn(async move {
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
fn spawn_connection_tracker(kernel: Arc<crate::Kernel>) -> astrid_runtime::JoinHandle<()> {
    // Broadcast-path subscriber. See `spawn_kernel_router` for the
    // rationale on staying on the untargeted subscribe path.
    let mut receiver = kernel
        .event_bus
        .subscribe_topic_as("client.v1.*", "connection_tracker");

    astrid_runtime::spawn(async move {
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
fn response_topic_for(request_topic: &str) -> Topic {
    request_topic
        .strip_prefix("astrid.v1.request.")
        .map_or_else(|| Topic::from_raw(request_topic), Topic::kernel_response)
}

#[expect(clippy::too_many_lines)]
async fn handle_request(
    kernel: &Arc<crate::Kernel>,
    topic: Topic,
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
    let authorization =
        match authorize_request(kernel, &caller, device_key_id.as_deref(), required_cap) {
            Ok(authorization) => {
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
                )
                .await;
                authorization
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
                )
                .await;
                publish_response(kernel, response_topic, KernelResponse::Error(e.to_string()));
                return;
            },
        };

    // Keepalive pinger: from here until the terminal response is published, emit
    // a `KernelResponse::Working` frame every `KEEPALIVE_INTERVAL` so a waiting
    // uplink treats a slow-but-live handler (chiefly `InstallCapsule`, which
    // loads + runs the capsule's `#[install]` hook) as an *inactivity* window it
    // keeps resetting, rather than tripping a total-deadline timeout. A fast
    // handler finishes before the first interval and emits zero pings. Uniform
    // across every request — no per-endpoint config. Dropped before each
    // terminal publish below so the terminal frame is never preceded by a late
    // redundant ping.
    let pinger = KeepalivePinger::spawn(kernel, response_topic.clone());

    let res = match req {
        KernelRequest::InstallCapsule { source, workspace } => {
            info!(source = %source, workspace, "Kernel received install request");
            install::handle_install_capsule(kernel, &caller, &source, workspace).await
        },
        KernelRequest::ApproveCapability {
            request_id,
            signature: _,
        } => {
            info!(request_id = %request_id, "Kernel received capability approval");
            KernelResponse::Error("Approval logic not yet implemented in kernel router".to_string())
        },
        KernelRequest::ListCapsules => {
            let visibility = CapsuleVisibility::new(&authorization);
            let list: Vec<_> = visible_inventory_manifests(kernel, &visibility)
                .await
                .into_iter()
                .map(|manifest| manifest.package.name)
                .collect();
            KernelResponse::Success(serde_json::json!(list))
        },
        KernelRequest::GetCommands => {
            let visibility = CapsuleVisibility::new(&authorization);
            let mut commands = Vec::new();
            let manifests = visible_inventory_manifests(kernel, &visibility).await;
            for manifest in &manifests {
                for cmd in &manifest.commands {
                    commands.push(astrid_events::kernel_api::CommandInfo {
                        name: cmd.name.clone(),
                        description: cmd
                            .description
                            .clone()
                            .unwrap_or_else(|| "No description".to_string()),
                        provider_capsule: manifest.package.name.clone(),
                        kind: cmd.kind,
                    });
                }
            }
            info!(
                count = commands.len(),
                capsules = manifests.len(),
                "GetCommands: returning {} commands from {} capsules",
                commands.len(),
                manifests.len()
            );
            KernelResponse::Commands(commands)
        },
        KernelRequest::ReloadCapsules => {
            let status = if schedule_reload_capsules(Arc::clone(kernel)) {
                "reload_started"
            } else {
                "reload_already_running"
            };
            KernelResponse::Success(serde_json::json!({ "status": status }))
        },
        KernelRequest::ReloadCapsule { id } => {
            // Hot-swap a single capsule (or add it if not yet loaded) without a
            // daemon restart. The kernel publishes capsules_loaded on success so
            // the tool surface refreshes. `id` is client-supplied over IPC, so
            // validate it (CapsuleId::new rejects unsafe ids) before using it as
            // a registry key — never construct it unchecked from untrusted input.
            match astrid_capsule::capsule::CapsuleId::new(id.clone()) {
                Ok(cap_id) => match kernel.reload_one_capsule(&cap_id, &caller).await {
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
                Ok(cap_id) => match kernel.unload_one_capsule(&cap_id, &caller).await {
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
        KernelRequest::PromoteWorkspace { id } => {
            workspace_commit_response(kernel, &caller, &id, true).await
        },
        KernelRequest::RollbackWorkspace { id } => {
            workspace_commit_response(kernel, &caller, &id, false).await
        },
        KernelRequest::Shutdown { reason } => {
            info!(
                reason = reason.as_deref().unwrap_or("none"),
                "Kernel received shutdown request via management API"
            );
            // Stop the keepalive before the terminal frame so a late `Working`
            // can't trail the shutdown confirmation.
            drop(pinger);
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
            let loaded: Vec<String> = reg.list_any().iter().map(ToString::to_string).collect();
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
            let visibility = CapsuleVisibility::new(&authorization);
            let mut entries = Vec::new();
            for manifest in visible_inventory_manifests(kernel, &visibility).await {
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
            let visibility = CapsuleVisibility::new(&authorization);
            let manifests = visible_inventory_manifests(kernel, &visibility).await;
            let readiness = astrid_capsule::readiness::agent_loop_readiness(&manifests);
            KernelResponse::AgentReadiness(readiness)
        },
    };

    // Stop the keepalive before the terminal frame so it isn't preceded by a
    // late redundant `Working`.
    drop(pinger);
    publish_response(kernel, response_topic, res);
}

async fn inventory_manifest_map(
    kernel: &crate::Kernel,
    visibility: &CapsuleVisibility,
) -> BTreeMap<String, astrid_capsule::manifest::CapsuleManifest> {
    let paths = crate::capsule_discovery_paths_for(
        &kernel.astrid_home,
        &kernel.workspace_root,
        &visibility.principal,
    );
    let discovered = match tokio::task::spawn_blocking(move || {
        astrid_capsule::discovery::discover_manifests(Some(&paths))
    })
    .await
    {
        Ok(discovered) => discovered,
        Err(err) => {
            warn!(error = %err, "Capsule inventory discovery task failed");
            Vec::new()
        },
    };

    discovered
        .into_iter()
        .filter_map(|(manifest, _)| {
            let id = astrid_capsule::capsule::CapsuleId::new(manifest.package.name.clone()).ok()?;
            visibility.allows(&id).then_some((id.to_string(), manifest))
        })
        .collect()
}

async fn visible_inventory_manifests(
    kernel: &crate::Kernel,
    visibility: &CapsuleVisibility,
) -> Vec<astrid_capsule::manifest::CapsuleManifest> {
    let mut manifests = inventory_manifest_map(kernel, visibility).await;
    let registry = kernel.capsules.read().await;
    for capsule in visibility.capsules(&registry) {
        if visibility.allows(capsule.id()) {
            manifests
                .entry(capsule.id().to_string())
                .or_insert_with(|| capsule.manifest().clone());
        }
    }
    manifests.into_values().collect()
}

fn schedule_reload_capsules(kernel: Arc<crate::Kernel>) -> bool {
    if !try_start_full_reload(&kernel.full_reload_in_flight) {
        debug!("ReloadCapsules request coalesced; full reload already in flight");
        return false;
    }
    astrid_runtime::spawn(async move {
        let _guard = FullReloadGuard(&kernel.full_reload_in_flight);
        unregister_failed_capsules(&kernel).await;
        kernel.load_all_capsules().await;
    });
    true
}

fn try_start_full_reload(in_flight: &AtomicBool) -> bool {
    !in_flight.swap(true, Ordering::AcqRel)
}

struct FullReloadGuard<'a>(&'a AtomicBool);

impl Drop for FullReloadGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

async fn unregister_failed_capsules(kernel: &crate::Kernel) {
    let failed: Vec<_> = {
        let reg = kernel.capsules.read().await;
        reg.cloned_values_with_principal()
            .into_iter()
            .filter_map(|(principal, capsule)| {
                matches!(
                    capsule.state(),
                    astrid_capsule::capsule::CapsuleState::Failed(_)
                )
                .then(|| (principal, capsule.id().clone()))
            })
            .collect()
    };

    let mut reg = kernel.capsules.write().await;
    for (principal, id) in failed {
        let _ = reg.unregister_for(&principal, &id);
    }
}

struct CapsuleVisibility {
    principal: PrincipalId,
    is_admin: bool,
    capsule_grants: BTreeSet<String>,
}

impl CapsuleVisibility {
    fn new(authorization: &AuthorizedRequest) -> Self {
        if authorization.principal.as_str() == "anonymous" {
            return Self::denied(&authorization.principal);
        }
        let profile = authorization.profile.as_ref();
        let check = authorization.capability_check();

        Self {
            principal: authorization.principal.clone(),
            is_admin: check.has("capsule:list"),
            capsule_grants: profile.capsules.iter().cloned().collect(),
        }
    }

    fn denied(caller: &PrincipalId) -> Self {
        Self {
            principal: caller.clone(),
            is_admin: false,
            capsule_grants: BTreeSet::new(),
        }
    }

    fn allows(&self, capsule_id: &astrid_capsule::capsule::CapsuleId) -> bool {
        self.is_admin || self.capsule_grants.contains(capsule_id.as_str())
    }

    fn capsules(
        &self,
        registry: &astrid_capsule::registry::CapsuleRegistry,
    ) -> Vec<Arc<dyn astrid_capsule::capsule::Capsule>> {
        if self.is_admin {
            registry.cloned_values()
        } else {
            registry.cloned_values_for(&self.principal)
        }
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

// ---------------------------------------------------------------------------
// Management API capability enforcement (issue #670)
// ---------------------------------------------------------------------------

/// The authority surface a given [`KernelRequest`] operates over.
///
/// Most `KernelRequest` variants carry no target-principal field, so
/// [`resolve_scope`] treats caller-scoped requests as [`AuthorityScope::Self_`].
/// Full-daemon mutations stay global.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityScope {
    /// Request operates on the caller's own principal.
    Self_,
    /// Request operates on global/system-wide state (e.g. shutdown).
    Global,
}

/// Return the authority scope the caller is exercising for `req`.
///
/// A daemon-side capsule install with `workspace = false` mutates the daemon's
/// configured install target, so it requires the global install capability even
/// though it does not grant any principal visibility by itself. Workspace
/// installs remain self-scoped; the daemon rejects them later because it has no
/// meaningful current workspace.
#[must_use]
pub fn resolve_scope(req: &KernelRequest, _caller: &PrincipalId) -> AuthorityScope {
    match req {
        KernelRequest::ReloadCapsules
        | KernelRequest::InstallCapsule {
            workspace: false, ..
        } => AuthorityScope::Global,
        _ => AuthorityScope::Self_,
    }
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
        // Promote/rollback are self-scoped (no target-principal field), so
        // `resolve_scope` always yields `Self_`; the `_` arm is for exhaustiveness.
        (KernelRequest::PromoteWorkspace { .. }, _) => "self:workspace:promote",
        (KernelRequest::RollbackWorkspace { .. }, _) => "self:workspace:rollback",
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
        KernelRequest::PromoteWorkspace { .. } => "PromoteWorkspace",
        KernelRequest::RollbackWorkspace { .. } => "RollbackWorkspace",
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

/// Authorization inputs pinned at the request's policy decision point.
#[derive(Debug)]
struct AuthorizedRequest {
    principal: PrincipalId,
    profile: Arc<PrincipalProfile>,
    groups: Arc<GroupConfig>,
    device_scope: Option<DeviceScope>,
}

impl AuthorizedRequest {
    fn capability_check(&self) -> CapabilityCheck<'_> {
        let check = CapabilityCheck::new(
            self.profile.as_ref(),
            self.groups.as_ref(),
            self.principal.clone(),
        );
        match &self.device_scope {
            Some(scope) => check.with_device_scope(scope),
            None => check,
        }
    }
}

/// Evaluate the capability check for `caller` against the kernel's resolved
/// group config and the caller's profile.
///
/// Returns the pinned authorization snapshot on success, or the policy reason
/// on denial. Profile resolution failures (malformed TOML, IO error) are
/// themselves treated as deny — fail-closed — with a synthesized
/// `MissingCapability` so the deny path has a single shape in the audit log.
fn authorize_request(
    kernel: &crate::Kernel,
    caller: &PrincipalId,
    device_key_id: Option<&str>,
    required_cap: &str,
) -> Result<AuthorizedRequest, PermissionError> {
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

    let device_scope = resolve_device_scope(profile.as_ref(), caller, device_key_id, required_cap)?;

    let mut check = CapabilityCheck::new(profile.as_ref(), groups.as_ref(), caller.clone());
    if let Some(scope) = &device_scope {
        check = check.with_device_scope(scope);
    }
    check.require(required_cap)?;
    Ok(AuthorizedRequest {
        principal: caller.clone(),
        profile,
        groups,
        device_scope,
    })
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
///
/// The wire string is single-sourced through [`Topic::audit_entry`] at the
/// publish site; this `pub const` remains the named cross-crate anchor that
/// the capsule's `audit_topic_literal_pinned` test and the gateway SSE
/// consumer mirror against. The
/// [`audit_topic_const_matches_constructor`](tests::audit_topic_const_matches_constructor)
/// test pins the two together so neither can drift.
pub const AUDIT_TOPIC: &str = "astrid.v1.audit.entry";

/// Append an `AdminRequest` audit entry for the given outcome.
/// Persists to the on-disk log AND publishes a live event on
/// [`AUDIT_TOPIC`]. Failures to persist are logged but do not abort
/// the request — the audit log degrades to "continue + alert" by
/// design. A bus-publish failure is similarly best-effort.
async fn record_admin_audit(kernel: &crate::Kernel, entry: AdminAuditEntry<'_>) {
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
    if let Err(e) = kernel
        .audit_log
        .append_with_principal(
            kernel.session_id.clone(),
            caller.clone(),
            action,
            authorization.clone(),
            outcome.clone(),
        )
        .await
    {
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
        "ts_epoch": astrid_runtime::clock::now_epoch_secs(),
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
    let msg = IpcMessage::new(
        Topic::audit_entry(),
        IpcPayload::RawJson(event),
        uuid::Uuid::nil(),
    )
    .with_principal(caller.to_string());
    let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("kernel_router::audit"),
        message: msg,
    });
}

#[cfg(test)]
mod tests;

//! Host function implementation for plugin-level approval requests.
//!
//! Called by WASM guests via the `request_approval` trait method when a plugin
//! needs human consent for a sensitive action. Checks persisted always-grants,
//! then the shared [`AllowanceStore`] (instant path), then publishes an
//! [`ApprovalRequired`] IPC event and blocks until the frontend responds.

use super::consent_reply::{self, Decision, Destination, Writer};
use crate::audit_sink::HostApprovalScope;
use crate::engine::wasm::bindings::astrid::approval::host::{
    self as approval, ApprovalDecision, ApprovalRequest, ApprovalResponse, ErrorCode,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use astrid_approval::action::SensitiveAction;
use astrid_approval::{Allowance, AllowanceId, AllowancePattern, AllowanceStore};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::CommandApprovalLocation;
use astrid_core::types::Timestamp;
use astrid_crypto::KeyPair;
use astrid_events::AstridEvent;
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use uuid::Uuid;

/// Maximum timeout for approval requests (60 seconds).
const MAX_APPROVAL_TIMEOUT_MS: u64 = 60_000;

/// Maximum length for action strings from WASM guests.
///
/// Actions longer than this are rejected at the entry point and truncated
/// in the sanitization layer. Prevents DoS via oversized glob pattern
/// compilation.
const MAX_ACTION_LEN: usize = 256;

/// Maximum length for resource strings from WASM guests.
///
/// Resources contain full command strings with arguments, so the limit is
/// higher than [`MAX_ACTION_LEN`]. Strings exceeding this are truncated
/// (not rejected) since resource is a display/audit field that does not
/// drive glob pattern compilation.
const MAX_RESOURCE_LEN: usize = 1024;

/// Check the allowance store for a matching pattern, consuming limited-use
/// allowances.
///
/// Builds a `SensitiveAction::ExecuteCommand` from the full resource string
/// so that `CommandPattern` glob matching works against the complete command.
/// Uses `find_matching_and_consume` to correctly decrement `uses_remaining`
/// on limited-use allowances. Scoped to the invoking `principal` — Agent A's
/// approval never matches Agent B's action (Layer 4, issue #668).
fn check_allowance(
    store: &AllowanceStore,
    principal: &PrincipalId,
    resource: &str,
    workspace_root: Option<&std::path::Path>,
) -> bool {
    let action = SensitiveAction::ExecuteCommand {
        command: resource.to_owned(),
        args: vec![],
    };
    store
        .find_matching_and_consume(principal, &action, workspace_root)
        .is_some()
}

/// Reuse the saved command family with the same principal/workspace matching
/// contract as an in-memory allowance. Do not import it into the session store:
/// the profile cache remains the single source for durable approvals.
fn check_persisted_allowance(
    state: &HostState,
    principal: &PrincipalId,
    resource: &str,
) -> Result<bool, ErrorCode> {
    let Some(cache) = &state.profile_cache else {
        return Ok(false);
    };
    let profile = cache.resolve(principal).map_err(|error| {
        tracing::warn!(%error, "Cannot load durable action approvals");
        ErrorCode::StoreUnavailable
    })?;
    if !profile.enabled {
        return Ok(false);
    }
    let action = SensitiveAction::ExecuteCommand {
        command: resource.to_owned(),
        args: vec![],
    };
    let location = approval_location(state);
    let hosted_identity = state.hosted_workspace_root.as_path();
    if location == CommandApprovalLocation::Hosted
        && (hosted_identity.as_os_str().is_empty() || hosted_identity.to_str().is_none())
    {
        return Ok(false);
    }
    Ok(profile.approvals.command_always.iter().any(|grant| {
        if grant.location != location {
            return false;
        }
        let workspace_ok = match (&grant.workspace_root, location) {
            (Some(workspace), CommandApprovalLocation::Hosted) => {
                std::path::Path::new(workspace) == hosted_identity
            },
            (None, CommandApprovalLocation::AstridWorkspace) => true,
            _ => false,
        };
        if !workspace_ok {
            return false;
        }
        let pattern = AllowancePattern::CommandPattern {
            command: format!("{} *", escape_glob_metacharacters(&grant.command)),
        };
        pattern.matches(&action, Some(hosted_identity))
    }))
}

/// Hosted durable grants bind the pristine portal path, never the `CoW` merged
/// path used for FS confinement. Empty or non-UTF-8 identity cannot persist.
fn hosted_workspace_identity(state: &HostState) -> Result<&str, ErrorCode> {
    let path = state.hosted_workspace_root.as_path();
    if path.as_os_str().is_empty() {
        return Err(ErrorCode::InvalidInput);
    }
    path.to_str().ok_or(ErrorCode::InvalidInput)
}

fn approval_location(state: &HostState) -> CommandApprovalLocation {
    use crate::engine::wasm::host_state::PrincipalMountLocation;
    if state
        .effective_workspace()
        .is_some_and(|mount| matches!(mount.location, PrincipalMountLocation::AstridFilesystem))
    {
        CommandApprovalLocation::AstridWorkspace
    } else {
        CommandApprovalLocation::Hosted
    }
}

fn grant_destination(state: &HostState) -> Result<Destination<&str>, ErrorCode> {
    state
        .profile_cache
        .as_ref()
        .ok_or(ErrorCode::StoreUnavailable)?;
    match approval_location(state) {
        CommandApprovalLocation::AstridWorkspace => Ok(Destination::AstridWorkspace),
        CommandApprovalLocation::Hosted => {
            Ok(Destination::Hosted(hosted_workspace_identity(state)?))
        },
    }
}

struct CommandGrants<'a> {
    state: &'a HostState,
    responder: &'a IpcMessage,
}

impl<'a> CommandGrants<'a> {
    fn devices(
        &self,
        owner: &PrincipalId,
    ) -> Result<[astrid_events::ipc::DeviceStamp<'a>; 2], ErrorCode> {
        let mut devices = [Default::default(); 2];
        for (slot, message) in devices
            .iter_mut()
            .zip([self.state.caller_context.as_ref(), Some(self.responder)])
        {
            if let Some(message) = message {
                let stamp = message.device_stamp();
                if stamp.fingerprint.is_some()
                    && message.principal.as_deref() != Some(owner.as_str())
                {
                    return Err(ErrorCode::StoreUnavailable);
                }
                *slot = stamp;
            }
        }
        Ok(devices)
    }

    fn session(
        &self,
        outcome: Decision,
        owner: &PrincipalId,
        install: impl FnOnce(),
    ) -> Result<(), ErrorCode> {
        use consent_reply::SessionRoute;
        let caller = self
            .state
            .caller_context
            .as_ref()
            .map(IpcMessage::device_stamp)
            .unwrap_or_default();
        let responder = self.responder.device_stamp();
        match consent_reply::session_route(
            outcome,
            (caller.fingerprint, caller.registration),
            (responder.fingerprint, responder.registration),
        ) {
            SessionRoute::Skip => Ok(()),
            SessionRoute::Unstamped => {
                install();
                Ok(())
            },
            SessionRoute::CheckProfile => self
                .state
                .profile_cache
                .as_ref()
                .ok_or(ErrorCode::StoreUnavailable)?
                .with_session_devices(owner, self.devices(owner)?, install)
                .map_err(|_| ErrorCode::StoreUnavailable),
        }
    }

    fn write(
        &self,
        owner: &PrincipalId,
        family: &str,
        path: Option<&str>,
        location: CommandApprovalLocation,
    ) -> Result<(), ErrorCode> {
        let cache = self
            .state
            .profile_cache
            .as_ref()
            .ok_or(ErrorCode::StoreUnavailable)?;
        let devices = self.devices(owner)?;
        cache
            .persist_command_at(owner, family, path, location, devices)
            .map_err(|error| {
                tracing::warn!(%error, "Cannot persist Always approval");
                ErrorCode::StoreUnavailable
            })
    }
}

impl Writer<&PrincipalId, &str, &str> for CommandGrants<'_> {
    type Error = ErrorCode;

    fn hosted(&mut self, owner: &PrincipalId, family: &str, path: &str) -> Result<(), ErrorCode> {
        self.write(owner, family, Some(path), CommandApprovalLocation::Hosted)
    }
    fn workspace(&mut self, owner: &PrincipalId, family: &str) -> Result<(), ErrorCode> {
        self.write(
            owner,
            family,
            None,
            CommandApprovalLocation::AstridWorkspace,
        )
    }
}

/// Sanitize a guest-supplied display field in place.
///
/// Trims whitespace, strips control characters, and enforces a character-count
/// length cap. Logs a warning (with plugin ID and field name) when control
/// characters were stripped or the string was truncated. Returns whether the
/// display text still equals the complete guest-supplied value.
fn sanitize_guest_field(
    s: &mut String,
    max_len: usize,
    field_name: &str,
    capsule_id: &str,
) -> bool {
    let trimmed = s.trim();
    let sanitized: String = trimmed
        .chars()
        .filter(|c| !c.is_control())
        .take(max_len)
        .collect();

    // Only warn for control-char stripping or truncation, not whitespace trim.
    if sanitized.len() != trimmed.len() {
        let original_chars = trimmed.chars().count();
        let sanitized_chars = sanitized.chars().count();
        tracing::warn!(
            plugin = %capsule_id,
            field = field_name,
            original_chars,
            sanitized_chars,
            "{field_name} sanitized: control characters stripped or length truncated"
        );
    }

    let unchanged = *s == sanitized;
    *s = sanitized;
    unchanged
}

/// Sanitize a guest-supplied action string for safe use in glob patterns.
///
/// Defense layer 1: strips control characters and enforces a length cap.
/// Runs BEFORE [`escape_glob_metacharacters`] (layer 2). Together they
/// guarantee that no guest input can produce a dangerous or oversized glob
/// pattern.
fn sanitize_action_for_pattern(action: &str, capsule_id: &str) -> String {
    let trimmed = action.trim();
    let mut sanitized: String = trimmed
        .chars()
        .filter(|c| !c.is_control())
        .skip_while(|c| c.is_whitespace())
        .take(MAX_ACTION_LEN)
        .collect();

    // Filtering or truncation can expose whitespace at the boundary.
    sanitized.truncate(sanitized.trim_end().len());
    let trimmed_chars = trimmed.chars().count();
    let sanitized_chars = sanitized.chars().count();
    if sanitized_chars != trimmed_chars {
        tracing::warn!(
            plugin = %capsule_id,
            original_chars = trimmed_chars,
            sanitized_chars = sanitized_chars,
            "Action string sanitized: control characters stripped or length truncated"
        );
    }

    sanitized
}

/// Escape glob metacharacters in a guest-supplied action string.
///
/// Defense layer 2: escapes glob wildcards so they are matched literally.
fn escape_glob_metacharacters(action: &str) -> String {
    let mut escaped = String::with_capacity(action.len() * 2);
    for c in action.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '{' | '}' | '\\') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

/// Create a session-scoped allowance from an approval decision.
fn create_allowance_from_decision(
    store: &AllowanceStore,
    principal: &PrincipalId,
    action: &str,
    decision: &str,
    workspace_root: Option<std::path::PathBuf>,
    capsule_id: &str,
) {
    let session_only = match decision {
        "approve_session" => true,
        "approve_always" => false,
        _ => return,
    };

    // Layer 1: strip control characters, enforce length cap.
    let sanitized_action = sanitize_action_for_pattern(action, capsule_id);
    if sanitized_action.is_empty() {
        return;
    }
    // Layer 2: escape glob metacharacters so wildcards match literally.
    let escaped_action = escape_glob_metacharacters(&sanitized_action);
    let pattern = AllowancePattern::CommandPattern {
        command: format!("{escaped_action} *"),
    };

    let keypair = KeyPair::generate();
    let allowance = Allowance {
        id: AllowanceId::new(),
        principal: principal.clone(),
        action_pattern: pattern,
        created_at: Timestamp::now(),
        expires_at: None,
        max_uses: None,
        uses_remaining: None,
        session_only,
        workspace_root,
        signature: keypair.sign(b"plugin-approval"),
    };

    if let Err(e) = store.add_allowance(allowance) {
        tracing::warn!("Failed to add approval allowance: {e}");
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

fn response_identity_matches(
    expected_principal: &str,
    expected_owner: astrid_events::ipc::RequestOwnerId,
    event: &AstridEvent,
) -> bool {
    super::consent_identity::matches(
        expected_principal.as_bytes(),
        expected_owner.as_u128(),
        event_principal(event).map(str::as_bytes),
        event_request_owner(event).map(astrid_events::ipc::RequestOwnerId::as_u128),
    )
}

async fn await_matching_approval_response(
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
            target: "astrid.audit.approval",
            security_event = true,
            capsule_id = %capsule_id,
            request_id = %request_id,
            expected_principal = %expected_principal,
            got_principal = got.unwrap_or("<none>"),
            expected_request_owner = %expected_owner,
            got_request_owner = got_owner.as_deref().unwrap_or("<none>"),
            "approval: rejected response from the wrong principal or authenticated request owner",
        );
    }
}

impl approval::Host for HostState {
    /// Host function: `request_approval(request) -> ApprovalResponse`
    ///
    /// Blocks the WASM thread until the frontend user approves or denies, or
    /// the request times out. If an allowance already exists, returns immediately
    /// with `ApprovalDecision::Allowance` so the capsule UI can communicate
    /// WHY consent was granted.
    fn request_approval(
        &mut self,
        mut request: ApprovalRequest,
    ) -> Result<ApprovalResponse, ErrorCode> {
        let request_principal = self
            .begin_host_operation()
            .map_err(|()| ErrorCode::StoreUnavailable)?;
        let allowance_store = self.allowance_store.clone();
        let event_bus = self.event_bus.clone();
        let runtime_handle = self.runtime_handle.clone();
        let capsule_id = self.capsule_id.to_string();
        let cancel_token = self.effective_cancel_token();
        let blocking_semaphore = self.blocking_semaphore.clone();
        let workspace_root = self.workspace_root.clone();
        // Layer 4 (#668): the invoking principal scopes allowance lookups.
        // Falls back to the capsule owner for load-time / tests / daemons.
        let principal = self.effective_principal();

        // Validate and sanitize all guest-supplied strings at the entry point.
        let action_char_count = request.action.chars().count();
        if action_char_count > MAX_ACTION_LEN {
            return Err(ErrorCode::InvalidInput);
        }
        request.action = sanitize_action_for_pattern(&request.action, &capsule_id);
        let exact_resource = sanitize_guest_field(
            &mut request.target_resource,
            MAX_RESOURCE_LEN,
            "resource",
            &capsule_id,
        );

        let ws_path = Some(workspace_root.as_path());
        let mut audit = super::approval_audit::ApprovalAudit::new(
            self,
            &principal,
            &request.action,
            &request.target_resource,
        );

        let request_device = self
            .begin_device_operation()
            .map_err(|()| ErrorCode::StoreUnavailable)?;
        if exact_resource && check_persisted_allowance(self, &principal, &request.target_resource)?
        {
            audit.granted(HostApprovalScope::Always, "remembered_consent");
            return Ok(ApprovalResponse {
                decision: ApprovalDecision::Allowance,
            });
        }

        // Fast path: check existing allowances.
        if exact_resource
            && let Some(ref store) = allowance_store
            && check_allowance(store, &principal, &request.target_resource, ws_path)
        {
            tracing::debug!(
                plugin = %capsule_id,
                action = %request.action,
                resource = %request.target_resource,
                "Approval auto-granted via existing allowance"
            );
            audit.granted(HostApprovalScope::Session, "session_allowance");

            return Ok(ApprovalResponse {
                decision: ApprovalDecision::Allowance,
            });
        }

        // Slow path: publish ApprovalRequired and wait for response.
        let Some(request_owner) = self
            .caller_context
            .as_ref()
            .and_then(|message| message.request_owner)
        else {
            tracing::warn!(
                target: "astrid.audit.approval",
                security_event = true,
                capsule_id = %capsule_id,
                principal = %principal,
                "approval request has no authenticated owner; denying"
            );
            audit.denied("no_request_owner", "no authenticated request owner");
            return Ok(ApprovalResponse {
                decision: ApprovalDecision::Denied,
            });
        };
        let destination = grant_destination(self);
        let request_id = Uuid::new_v4().to_string();
        let response_topic = Topic::approval_response(&request_id);
        // Durable before the prompt is published.
        audit.requested(&request_id);

        // Subscribe BEFORE publishing to prevent a race.
        let mut receiver = event_bus.subscribe_topic(response_topic.as_str());

        let request_payload = IpcPayload::ApprovalRequired {
            request_id: request_id.clone(),
            request_owner: request_owner.to_string(),
            action: request.action.clone(),
            resource: request.target_resource.clone(),
            reason: format!("Capsule '{capsule_id}' requests approval"),
        };
        let message = IpcMessage::new(
            Topic::approval_request(),
            request_payload,
            Uuid::nil(), // Kernel-originated
        )
        .with_principal(principal.to_string())
        .with_request_owner(request_owner);
        event_bus.publish(AstridEvent::Ipc {
            message,
            metadata: astrid_events::EventMetadata::default(),
        });

        tracing::info!(
            plugin = %capsule_id,
            %request_id,
            "Approval request pending"
        );
        tracing::debug!(
            action = %request.action,
            resource = %request.target_resource,
            "Approval request details"
        );

        // Retirement can finish while the operator is deciding.
        drop((request_device, request_principal));
        // Block until response, timeout, or cancellation.
        let event = util::bounded_block_on_cancellable(
            &runtime_handle,
            &blocking_semaphore,
            &cancel_token,
            async {
                await_matching_approval_response(
                    &mut receiver,
                    principal.as_str(),
                    request_owner,
                    &capsule_id,
                    &request_id,
                    std::time::Duration::from_millis(MAX_APPROVAL_TIMEOUT_MS),
                )
                .await
            },
        )
        .flatten();

        match event {
            Some(event) => {
                if let AstridEvent::Ipc { message, .. } = &*event {
                    match &message.payload {
                        IpcPayload::ApprovalResponse {
                            decision, reason, ..
                        } => {
                            let authority = consent_reply::admit(
                                self.begin_host_operation(),
                                || self.begin_device_operation(),
                                || self.begin_message_device_operation(message),
                            )
                            .ok_or_else(|| {
                                audit.denied(
                                    "authority_unavailable",
                                    "could not re-admit the approval reply",
                                );
                                ErrorCode::StoreUnavailable
                            })?;
                            let mut grants = CommandGrants {
                                state: self,
                                responder: message,
                            };
                            let outcome = authority
                                .apply(
                                    decision.as_bytes(),
                                    &principal,
                                    request.action.as_str(),
                                    destination,
                                    &mut grants,
                                )
                                .inspect_err(|_| {
                                    audit.denied("user", "approve_always could not be persisted");
                                })?;
                            grants
                                .session(outcome, &principal, || {
                                    if let Some(ref store) = allowance_store {
                                        create_allowance_from_decision(
                                            store,
                                            &principal,
                                            &request.action,
                                            decision,
                                            Some(workspace_root.clone()),
                                            &capsule_id,
                                        );
                                    }
                                })
                                .inspect_err(|_| {
                                    audit.denied(
                                        "authority_unavailable",
                                        "could not establish current session approval authority",
                                    )
                                })?;
                            let typed = match outcome {
                                Decision::Once => ApprovalDecision::Approved,
                                Decision::Session => ApprovalDecision::ApprovedSession,
                                Decision::Always => ApprovalDecision::ApprovedAlways,
                                Decision::Deny => ApprovalDecision::Denied,
                            };
                            match typed {
                                ApprovalDecision::Approved => {
                                    audit.granted(HostApprovalScope::Once, "user");
                                },
                                ApprovalDecision::ApprovedSession => {
                                    audit.granted(HostApprovalScope::Session, "user");
                                },
                                ApprovalDecision::ApprovedAlways => {
                                    audit.granted(HostApprovalScope::Always, "user");
                                },
                                _ => audit.denied("user", "denied by user"),
                            }
                            tracing::info!(
                                plugin = %capsule_id,
                                action = %request.action,
                                %decision,
                                reason = reason.as_deref().unwrap_or("none"),
                                "Approval response received"
                            );

                            Ok(ApprovalResponse { decision: typed })
                        },
                        _ => Err(ErrorCode::Unknown(
                            "unexpected IPC payload type in approval response".to_string(),
                        )),
                    }
                } else {
                    Err(ErrorCode::Unknown(
                        "unexpected event type in approval response".to_string(),
                    ))
                }
            },
            None => {
                tracing::warn!(
                    plugin = %capsule_id,
                    action = %request.action,
                    "Approval request timed out or was cancelled"
                );
                if cancel_token.is_cancelled() {
                    audit.denied("cancelled", "invocation cancelled");
                } else {
                    audit.denied("timeout", "no response before the timeout");
                }
                // Per WIT: timeout returns the typed `timeout` ErrorCode arm.
                Err(ErrorCode::Timeout)
            },
        }
    }
}

#[cfg(test)]
#[path = "approval_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "approval_hosted_identity_tests.rs"]
mod hosted_identity_tests;

#[cfg(test)]
#[path = "approval_audit_tests.rs"]
mod audit_tests;

#[cfg(test)]
#[path = "approval_device_tests.rs"]
mod device_tests;

//! Host function implementation for plugin-level approval requests.
//!
//! Called by WASM guests via the `request_approval` trait method when a plugin
//! needs human consent for a sensitive action. Checks the shared
//! [`AllowanceStore`] first (instant path), then publishes an
//! [`ApprovalRequired`] IPC event and blocks until the frontend responds.

use crate::engine::wasm::bindings::astrid::approval::host::{
    self as approval, ApprovalDecision, ApprovalRequest, ApprovalResponse, ErrorCode,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use astrid_approval::action::SensitiveAction;
use astrid_approval::{Allowance, AllowanceId, AllowancePattern, AllowanceStore};
use astrid_core::principal::PrincipalId;
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

/// Sanitize a guest-supplied display field in place.
///
/// Trims whitespace, strips control characters, and enforces a character-count
/// length cap. Logs a warning (with plugin ID and field name) when control
/// characters were stripped or the string was truncated.
fn sanitize_guest_field(s: &mut String, max_len: usize, field_name: &str, capsule_id: &str) {
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

    *s = sanitized;
}

/// Sanitize a guest-supplied action string for safe use in glob patterns.
///
/// Defense layer 1: strips control characters and enforces a length cap.
/// Runs BEFORE [`escape_glob_metacharacters`] (layer 2). Together they
/// guarantee that no guest input can produce a dangerous or oversized glob
/// pattern.
fn sanitize_action_for_pattern(action: &str, capsule_id: &str) -> String {
    let trimmed = action.trim();
    let sanitized: String = trimmed
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_ACTION_LEN)
        .collect();

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

/// Map the JSON-string decision in `IpcPayload::ApprovalResponse` to the
/// typed [`ApprovalDecision`] returned to the WASM guest.
fn decision_from_str(decision: &str) -> ApprovalDecision {
    match decision {
        "approve" => ApprovalDecision::Approved,
        "approve_session" => ApprovalDecision::ApprovedSession,
        "approve_always" => ApprovalDecision::ApprovedAlways,
        // Anything else — including explicit denies, unknown strings, or
        // empty — is treated as a deny.
        _ => ApprovalDecision::Denied,
    }
}

fn event_principal(event: &AstridEvent) -> Option<&str> {
    match event {
        AstridEvent::Ipc { message, .. } => message.principal.as_deref(),
        _ => None,
    }
}

fn response_principal_matches(expected: &str, event: &AstridEvent) -> bool {
    event_principal(event) == Some(expected)
}

async fn await_matching_approval_response(
    receiver: &mut astrid_events::EventReceiver,
    expected_principal: &str,
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
        if response_principal_matches(expected_principal, &event) {
            return Some(event);
        }
        let got = event_principal(&event);
        tracing::warn!(
            target: "astrid.audit.approval",
            security_event = true,
            capsule_id = %capsule_id,
            request_id = %request_id,
            expected_principal = %expected_principal,
            got_principal = got.unwrap_or("<none>"),
            "approval: rejected cross-principal response; continuing to wait",
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
        sanitize_guest_field(
            &mut request.target_resource,
            MAX_RESOURCE_LEN,
            "resource",
            &capsule_id,
        );

        let ws_path = Some(workspace_root.as_path());

        // Fast path: check existing allowances.
        if let Some(ref store) = allowance_store
            && check_allowance(store, &principal, &request.target_resource, ws_path)
        {
            tracing::debug!(
                plugin = %capsule_id,
                action = %request.action,
                resource = %request.target_resource,
                "Approval auto-granted via existing allowance"
            );

            return Ok(ApprovalResponse {
                decision: ApprovalDecision::Allowance,
            });
        }

        // Slow path: publish ApprovalRequired and wait for response.
        let request_id = Uuid::new_v4().to_string();
        let response_topic = Topic::approval_response(&request_id);

        // Subscribe BEFORE publishing to prevent a race.
        let mut receiver = event_bus.subscribe_topic(response_topic.as_str());

        let request_payload = IpcPayload::ApprovalRequired {
            request_id: request_id.clone(),
            action: request.action.clone(),
            resource: request.target_resource.clone(),
            reason: format!("Capsule '{capsule_id}' requests approval"),
        };
        let message = IpcMessage::new(
            Topic::approval_request(),
            request_payload,
            Uuid::nil(), // Kernel-originated
        )
        .with_principal(principal.to_string());
        event_bus.publish(AstridEvent::Ipc {
            message,
            metadata: astrid_events::EventMetadata::default(),
        });

        tracing::debug!(
            plugin = %capsule_id,
            action = %request.action,
            resource = %request.target_resource,
            %request_id,
            "Published approval request, waiting for response"
        );

        // Block until response, timeout, or cancellation.
        let event = util::bounded_block_on_cancellable(
            &runtime_handle,
            &blocking_semaphore,
            &cancel_token,
            async {
                await_matching_approval_response(
                    &mut receiver,
                    principal.as_str(),
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
                            let typed = decision_from_str(decision);
                            let approved = matches!(
                                typed,
                                ApprovalDecision::Approved
                                    | ApprovalDecision::ApprovedSession
                                    | ApprovalDecision::ApprovedAlways
                            );

                            // Create allowance for session/always decisions.
                            if approved && let Some(ref store) = allowance_store {
                                create_allowance_from_decision(
                                    store,
                                    &principal,
                                    &request.action,
                                    decision,
                                    Some(workspace_root.clone()),
                                    &capsule_id,
                                );
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
                // Per WIT: timeout returns the typed `timeout` ErrorCode arm.
                Err(ErrorCode::Timeout)
            },
        }
    }
}

#[cfg(test)]
#[path = "approval_tests.rs"]
mod tests;

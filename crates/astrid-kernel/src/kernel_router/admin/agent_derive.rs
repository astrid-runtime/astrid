//! Restricted derived-principal request dispatch.

use std::sync::Arc;

use astrid_audit::{AuditOutcome, AuthorizationProof};
use astrid_core::principal::PrincipalId;
use astrid_events::ipc::{IpcMessage, Topic};
use astrid_events::kernel_api::{
    AdminKernelResponse, AdminResponseBody, AgentDeriveKernelRequest, AgentDeriveRequest,
};
use serde_json::Value;
use tracing::warn;

use super::handlers::{err_bad_input, principal_profile_path};
use super::{AdminAuditEntry, CallerResolutionError, MANAGEMENT_CALLER_REQUIRED};

const METHOD: &str = "admin.agent.derive";
const REQUIRED_CAPABILITY: &str = "agent:create:inherit";

pub(super) fn try_dispatch(
    kernel: &Arc<crate::Kernel>,
    message: &IpcMessage,
    value: &Value,
) -> bool {
    if message.topic.as_str() != "astrid.v1.admin.agent.derive" {
        return false;
    }
    let Ok(request) = serde_json::from_value::<AgentDeriveKernelRequest>(value.clone()) else {
        warn!(topic = %message.topic, "Failed to parse AgentDeriveKernelRequest from IPC");
        return true;
    };
    let response_topic = super::admin_response_topic(&message.topic);
    let device_key_id = super::resolve_device_key_id(message);
    match super::resolve_caller(message) {
        Ok(caller) => {
            let kernel = Arc::clone(kernel);
            astrid_runtime::spawn(async move {
                handle_request(&kernel, response_topic, caller, device_key_id, request).await;
            });
        },
        Err(error) => {
            let kernel = Arc::clone(kernel);
            astrid_runtime::spawn(async move {
                reject_without_caller(&kernel, response_topic, device_key_id, request, error).await;
            });
        },
    }
    true
}

async fn reject_without_caller(
    kernel: &Arc<crate::Kernel>,
    response_topic: Topic,
    device_key_id: Option<String>,
    request: AgentDeriveKernelRequest,
    error: CallerResolutionError,
) {
    let caller = PrincipalId::anonymous();
    let reason = format!("{MANAGEMENT_CALLER_REQUIRED}: {}", error.reason());
    super::record_admin_audit(
        kernel,
        AdminAuditEntry {
            caller: &caller,
            method: METHOD,
            required_cap: REQUIRED_CAPABILITY,
            device_key_id: device_key_id.as_deref(),
            target_principal: None,
            params: serde_json::to_value(&request.request).ok(),
            authorization: AuthorizationProof::Denied {
                reason: reason.clone(),
            },
            outcome: AuditOutcome::failure(&reason),
        },
    )
    .await;
    publish(
        kernel,
        response_topic,
        &caller,
        device_key_id.as_deref(),
        request.request_id,
        AdminResponseBody::Error(MANAGEMENT_CALLER_REQUIRED.to_string()),
    );
}

async fn handle_request(
    kernel: &Arc<crate::Kernel>,
    response_topic: Topic,
    caller: PrincipalId,
    device_key_id: Option<String>,
    request: AgentDeriveKernelRequest,
) {
    let params = serde_json::to_value(&request.request).ok();
    let body = match super::authorize_request(
        kernel,
        &caller,
        device_key_id.as_deref(),
        REQUIRED_CAPABILITY,
    ) {
        Ok(_) => {
            super::record_admin_audit(
                kernel,
                AdminAuditEntry {
                    caller: &caller,
                    method: METHOD,
                    required_cap: REQUIRED_CAPABILITY,
                    device_key_id: device_key_id.as_deref(),
                    target_principal: None,
                    params,
                    authorization: AuthorizationProof::System {
                        reason: format!("policy allow: {caller} holds {REQUIRED_CAPABILITY}"),
                    },
                    outcome: AuditOutcome::success(),
                },
            )
            .await;
            agent_derive_from_req(kernel, request.request).await
        },
        Err(error) => {
            let error = error.to_string();
            super::record_admin_audit(
                kernel,
                AdminAuditEntry {
                    caller: &caller,
                    method: METHOD,
                    required_cap: REQUIRED_CAPABILITY,
                    device_key_id: device_key_id.as_deref(),
                    target_principal: None,
                    params,
                    authorization: AuthorizationProof::Denied {
                        reason: error.clone(),
                    },
                    outcome: AuditOutcome::failure(&error),
                },
            )
            .await;
            AdminResponseBody::Error(error)
        },
    };
    publish(
        kernel,
        response_topic,
        &caller,
        device_key_id.as_deref(),
        request.request_id,
        body,
    );
}

fn publish(
    kernel: &Arc<crate::Kernel>,
    response_topic: Topic,
    caller: &PrincipalId,
    device_key_id: Option<&str>,
    request_id: Option<String>,
    body: AdminResponseBody,
) {
    super::publish_response(
        kernel,
        response_topic,
        caller.as_str(),
        device_key_id,
        AdminKernelResponse::for_request(request_id, body),
    );
}

pub(super) async fn agent_derive_from_req(
    kernel: &Arc<crate::Kernel>,
    req: AgentDeriveRequest,
) -> AdminResponseBody {
    let AgentDeriveRequest {
        name,
        source,
        load_capsules,
        allow_capsules,
        inherit_capsule_state,
        network_egress,
    } = req;
    let principal = match PrincipalId::new(&name) {
        Ok(principal) => principal,
        Err(e) => return err_bad_input(format!("principal rejected: {e}")),
    };
    if let Some(reason) = principal.reserved_reason() {
        return err_bad_input(format!("principal {name:?} is {reason}"));
    }
    let _guard = kernel.admin_write_lock.lock().await;
    let profile_path = principal_profile_path(kernel, &principal);
    if profile_path.exists() {
        return err_bad_input(format!("principal `{principal}` already exists"));
    }
    super::agent_create_helpers::provision_derived_principal(
        kernel,
        principal,
        profile_path,
        source,
        load_capsules,
        allow_capsules,
        inherit_capsule_state,
        network_egress,
    )
    .await
}

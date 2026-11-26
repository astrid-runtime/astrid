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
    let device = astrid_events::ipc::OwnedDeviceStamp::from(message.device_stamp());
    match super::resolve_caller(message) {
        Ok(caller) => {
            let kernel = Arc::clone(kernel);
            astrid_runtime::spawn(async move {
                let device = device.as_stamp();
                handle_request(&kernel, response_topic, caller, device, request).await;
            });
        },
        Err(error) => {
            let kernel = Arc::clone(kernel);
            astrid_runtime::spawn(async move {
                reject_without_caller(&kernel, response_topic, device.as_stamp(), request, error)
                    .await;
            });
        },
    }
    true
}

async fn reject_without_caller(
    kernel: &Arc<crate::Kernel>,
    response_topic: Topic,
    device: astrid_events::ipc::DeviceStamp<'_>,
    request: AgentDeriveKernelRequest,
    error: CallerResolutionError,
) {
    let Some(_work) = kernel.runtime_work.admit() else {
        publish(
            kernel,
            response_topic,
            &PrincipalId::anonymous(),
            device,
            request.request_id,
            AdminResponseBody::Error("runtime is shutting down".to_owned()),
        );
        return;
    };
    let caller = PrincipalId::anonymous();
    let reason = format!("{MANAGEMENT_CALLER_REQUIRED}: {}", error.reason());
    super::record_admin_audit(
        kernel,
        AdminAuditEntry {
            caller: &caller,
            method: METHOD,
            required_cap: REQUIRED_CAPABILITY,
            device_key_id: device.fingerprint,
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
        device,
        request.request_id,
        AdminResponseBody::Error(MANAGEMENT_CALLER_REQUIRED.to_string()),
    );
}

async fn handle_request(
    kernel: &Arc<crate::Kernel>,
    response_topic: Topic,
    caller: PrincipalId,
    device: astrid_events::ipc::DeviceStamp<'_>,
    request: AgentDeriveKernelRequest,
) {
    let Some(_work) = kernel.runtime_work.admit() else {
        publish(
            kernel,
            response_topic,
            &caller,
            device,
            request.request_id,
            AdminResponseBody::Error("runtime is shutting down".to_owned()),
        );
        return;
    };
    let params = serde_json::to_value(&request.request).ok();
    // Deletion closes admission under this same lock. Check the caller only
    // after obtaining it so a queued request cannot carry stale authority
    // into provisioning.
    let guard = kernel.admin_write_lock.lock().await;
    let body =
        match super::super::admit_management_request(kernel, &caller, device, REQUIRED_CAPABILITY)
            .await
        {
            Ok(_) => {
                super::record_admin_audit(
                    kernel,
                    AdminAuditEntry {
                        caller: &caller,
                        method: METHOD,
                        required_cap: REQUIRED_CAPABILITY,
                        device_key_id: device.fingerprint,
                        target_principal: None,
                        params,
                        authorization: AuthorizationProof::System {
                            reason: format!("policy allow: {caller} holds {REQUIRED_CAPABILITY}"),
                        },
                        outcome: AuditOutcome::success(),
                    },
                )
                .await;
                derive_under_admin_lock(kernel, &caller, request.request, guard).await
            },
            Err(error) => {
                drop(guard);
                let error = error.to_string();
                super::record_admin_audit(
                    kernel,
                    AdminAuditEntry {
                        caller: &caller,
                        method: METHOD,
                        required_cap: REQUIRED_CAPABILITY,
                        device_key_id: device.fingerprint,
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
        device,
        request.request_id,
        body,
    );
}

fn publish(
    kernel: &Arc<crate::Kernel>,
    response_topic: Topic,
    caller: &PrincipalId,
    device: astrid_events::ipc::DeviceStamp<'_>,
    request_id: Option<String>,
    body: AdminResponseBody,
) {
    super::publish_response(
        kernel,
        response_topic,
        caller.as_str(),
        device,
        AdminKernelResponse::for_request(request_id, body),
    );
}

#[cfg(test)]
pub(super) async fn agent_derive_from_req(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    req: AgentDeriveRequest,
) -> AdminResponseBody {
    let guard = kernel.admin_write_lock.lock().await;
    derive_under_admin_lock(kernel, caller, req, guard).await
}

async fn derive_under_admin_lock(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    req: AgentDeriveRequest,
    _guard: tokio::sync::MutexGuard<'_, ()>,
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
    let profile_path = principal_profile_path(kernel, &principal);
    if profile_path.exists() {
        return err_bad_input(format!("principal `{principal}` already exists"));
    }
    let creator = match kernel.principal_directory.uid_for(caller) {
        Ok(uid) => uid,
        Err(error) => return err_bad_input(error.to_string()),
    };
    let ownership = match kernel
        .ownership_store
        .capture_derived_ownership(creator)
        .await
    {
        Ok(ownership) => ownership,
        Err(error) => return err_bad_input(format!("spawn ownership rejected: {error}")),
    };
    super::agent_create_helpers::provision_derived_principal(
        kernel,
        super::agent_create_helpers::DerivedPrincipalTarget {
            principal,
            profile_path,
            ownership,
        },
        source,
        load_capsules,
        allow_capsules,
        inherit_capsule_state,
        network_egress,
    )
    .await
}

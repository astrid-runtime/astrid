//! Projection-name diagnostic request boundary.
//!
//! This method is intentionally transported as a named raw-JSON request rather
//! than extending the public exhaustive [`KernelRequest`] and
//! [`KernelResponse`] enums. The module owns the complete boundary: strict wire
//! decoding, authenticated caller resolution, capability enforcement, audit,
//! and store dispatch.

use std::sync::Arc;

use astrid_audit::{AuditOutcome, AuthorizationProof};
use astrid_events::ipc::{IpcMessage, Topic};
use astrid_events::kernel_api::{
    KernelResponse, PROJECTION_NAME_DIAGNOSTIC_METHOD, ProjectionNamePolicyPreset,
};
use tracing::warn;

use super::caller::{MANAGEMENT_CALLER_REQUIRED, resolve_caller};
use super::{
    AdminAuditEntry, authorize_request, publish_response, record_admin_audit,
    resolve_device_key_id, response_topic_for,
};

const REQUIRED_CAPABILITY: &str = "system:status";

#[derive(serde::Deserialize)]
struct WireRequest {
    method: String,
    params: WireParams,
}

#[derive(serde::Deserialize)]
struct WireParams {
    policy: ProjectionNamePolicyPreset,
}

/// Handle the projection diagnostic when `value` names its additive method.
///
/// Returns `false` without side effects for every other method so the parent
/// router can continue with the stable `KernelRequest` decoder.
pub(super) async fn try_handle(
    kernel: &Arc<crate::Kernel>,
    message: &IpcMessage,
    value: &serde_json::Value,
) -> bool {
    if value.get("method").and_then(serde_json::Value::as_str)
        != Some(PROJECTION_NAME_DIAGNOSTIC_METHOD)
    {
        return false;
    }

    let request = match serde_json::from_value::<WireRequest>(value.clone()) {
        Ok(request) if request.method == PROJECTION_NAME_DIAGNOSTIC_METHOD => request,
        Ok(_) | Err(_) => {
            publish_response(
                kernel,
                response_topic_for(&message.topic),
                KernelResponse::Error("invalid projection-name diagnostic request".to_owned()),
            );
            return true;
        },
    };
    let caller = match resolve_caller(message) {
        Ok(caller) => caller,
        Err(error) => {
            warn!(
                security_event = true,
                topic = %message.topic,
                reason = error.reason(),
                "Rejected projection-name diagnostic without a valid principal"
            );
            publish_response(
                kernel,
                response_topic_for(&message.topic),
                KernelResponse::Error(MANAGEMENT_CALLER_REQUIRED.to_string()),
            );
            return true;
        },
    };

    handle(
        kernel,
        message.topic.clone(),
        caller,
        resolve_device_key_id(message),
        request.params.policy,
    )
    .await;
    true
}

async fn handle(
    kernel: &Arc<crate::Kernel>,
    topic: Topic,
    caller: astrid_core::principal::PrincipalId,
    device_key_id: Option<String>,
    policy: ProjectionNamePolicyPreset,
) {
    let audit_params = Some(serde_json::json!({ "policy": policy }));
    let response_topic = response_topic_for(&topic);
    if let Err(error) = authorize_request(
        kernel,
        &caller,
        device_key_id.as_deref(),
        REQUIRED_CAPABILITY,
    ) {
        let reason = error.to_string();
        record_admin_audit(
            kernel,
            AdminAuditEntry {
                caller: &caller,
                method: PROJECTION_NAME_DIAGNOSTIC_METHOD,
                required_cap: REQUIRED_CAPABILITY,
                device_key_id: device_key_id.as_deref(),
                target_principal: None,
                params: audit_params.clone(),
                authorization: AuthorizationProof::Denied {
                    reason: reason.clone(),
                },
                outcome: AuditOutcome::failure(reason.clone()),
            },
        )
        .await;
        publish_response(kernel, response_topic, KernelResponse::Error(reason));
        return;
    }

    record_admin_audit(
        kernel,
        AdminAuditEntry {
            caller: &caller,
            method: PROJECTION_NAME_DIAGNOSTIC_METHOD,
            required_cap: REQUIRED_CAPABILITY,
            device_key_id: device_key_id.as_deref(),
            target_principal: None,
            params: audit_params,
            authorization: AuthorizationProof::System {
                reason: format!("policy allow: {caller} holds {REQUIRED_CAPABILITY}"),
            },
            outcome: AuditOutcome::success(),
        },
    )
    .await;

    #[cfg(not(target_family = "wasm"))]
    let response = match kernel.principal_store.as_ref() {
        Some(store) => {
            let directory = store.principal_directory();
            match directory.uid_for(&caller) {
                Ok(uid) => match store
                    .projection_name_diagnostic(astrid_storage::StateOwner::Principal(uid), policy)
                    .await
                {
                    Ok(report) => match serde_json::to_value(report) {
                        Ok(report) => KernelResponse::Success(report),
                        Err(error) => KernelResponse::Error(error.to_string()),
                    },
                    Err(error) => KernelResponse::Error(error.to_string()),
                },
                Err(error) => KernelResponse::Error(error.to_string()),
            }
        },
        None => KernelResponse::Error(
            "projection-name diagnosis is unavailable on this host".to_owned(),
        ),
    };
    #[cfg(target_family = "wasm")]
    let response = {
        let _ = policy;
        KernelResponse::Error("projection-name diagnosis is unavailable on this host".to_owned())
    };
    publish_response(kernel, response_topic, response);
}

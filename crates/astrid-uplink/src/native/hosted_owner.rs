//! Direct authenticated native controls, consumed before event-bus admission.

use super::handshake::AuthenticatedIdentity;
use astrid_core::{
    PrincipalId,
    kernel_api::hosted_owner::{HostedOwnerRequest, HostedOwnerResponse},
};
use astrid_types::{
    Topic,
    ipc::{IpcMessage, IpcPayload},
};
use std::sync::Arc;

/// Reserved direct-native topic; a capsule publishing this topic reaches no handler.
pub const REQUEST_TOPIC: &str = "astrid.v1.native.owner.request";
/// Response written exclusively to the requesting native connection.
pub const RESPONSE_TOPIC: &str = "astrid.v1.native.owner.response";

/// Kernel-owned receiver for independently authenticated local provisioning.
#[async_trait::async_trait]
pub trait HostedOwnerResponder: Send + Sync {
    /// Resolve current credential/policy under the installation/device gate.
    ///
    /// # Errors
    /// Closed rejection; must not echo supplied evidence or key material.
    async fn respond(
        &self,
        principal: &PrincipalId,
        device_key_id: &str,
        request: HostedOwnerRequest,
    ) -> Result<HostedOwnerResponse, &'static str>;
}

pub(super) async fn respond(
    identity: &AuthenticatedIdentity,
    handler: Option<&Arc<dyn HostedOwnerResponder>>,
    message: IpcMessage,
) -> IpcMessage {
    let result = match (&message.payload, identity.device_key_id.as_deref(), handler) {
        (IpcPayload::RawJson(value), Some(device), Some(handler)) => {
            if serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= super::MAX_PAYLOAD_BYTES)
            {
                match serde_json::from_value::<HostedOwnerRequest>(value.clone()) {
                    Ok(request) => handler.respond(&identity.principal, device, request).await,
                    Err(_) => Err("invalid"),
                }
            } else {
                Err("invalid")
            }
        },
        _ => Err("unavailable"),
    };
    let body = match result {
        Ok(result) => serde_json::json!({"result": result}),
        Err(reason) => serde_json::json!({"error": reason}),
    };
    IpcMessage::new(
        Topic::from_raw(RESPONSE_TOPIC),
        IpcPayload::RawJson(body),
        message.source_id,
    )
    .with_principal(identity.principal.to_string())
}

#[cfg(test)]
mod tests;

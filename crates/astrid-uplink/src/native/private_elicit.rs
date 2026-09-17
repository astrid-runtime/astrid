//! Direct local secret replies. Never forward these frames onto the event bus.

use astrid_core::PrincipalId;
use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload};
use uuid::Uuid;

use super::handshake::AuthenticatedIdentity;

/// Separate from legacy bus replies so stale or unsupported requests cannot
/// fall back to public IPC. The request UUID is carried in the typed payload.
pub const REPLY_TOPIC: &str = "astrid.v1.private.elicit.reply";

/// Runtime-owned destination for replies received over an authenticated local
/// connection. Implementations must resolve the request's captured owner and
/// enforce responder authority before consuming it. Principal authentication
/// alone is not proof of human interaction.
pub trait PrivateElicitResponder: Send + Sync {
    /// Deliver or cancel a pending request. Both `value` and `values` absent
    /// means explicit cancellation. Empty text or an empty list is valid at
    /// this layer; kind checks belong to the registry.
    /// Success means accepted for delivery, not persisted to the secret store.
    ///
    /// # Errors
    /// Return a typed rejection without including any submitted input.
    fn reply(
        &self,
        principal: &PrincipalId,
        device_key_id: &str,
        request_id: Uuid,
        value: Option<String>,
        values: Option<Vec<String>>,
    ) -> Result<(), PrivateElicitRejection>;
}

/// Deliberately closed error vocabulary: neither log nor echo secret input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateElicitRejection {
    /// No matching live request, including replies arriving after expiry.
    Unavailable,
    /// The verified local identity cannot answer this request.
    Forbidden,
    /// Answer shape or size is invalid.
    Invalid,
}

/// Empty JSON strings cost two quotes plus a comma or bracket delimiter
/// (`""` + `,`/`[`/`]`). Bound element count first so a million empty
/// strings cannot force envelope serialization before the 1 `MiB` host IPC
/// ceiling. This is a protocol/DoS guard derived from [`super::MAX_PAYLOAD_BYTES`],
/// not an operator knob and not a second silent ceiling.
const MAX_ELICIT_ARRAY_ITEMS: usize = super::MAX_PAYLOAD_BYTES / 3;

fn payload_too_large(payload: &IpcPayload) -> bool {
    let IpcPayload::ElicitResponse { value, values, .. } = payload else {
        return true;
    };
    if values
        .as_ref()
        .is_some_and(|items| items.len() > MAX_ELICIT_ARRAY_ITEMS)
    {
        return true;
    }
    if value
        .as_deref()
        .is_some_and(|value| value.len() > super::MAX_PAYLOAD_BYTES)
        || values.as_ref().is_some_and(|items| {
            items
                .iter()
                .fold(0usize, |acc, item| acc.saturating_add(item.len()))
                > super::MAX_PAYLOAD_BYTES
        })
    {
        return true;
    }
    match serde_json::to_vec(payload) {
        Ok(bytes) => bytes.len() > super::MAX_PAYLOAD_BYTES,
        Err(_) => true,
    }
}

pub(super) fn respond(
    identity: &AuthenticatedIdentity,
    handler: Option<&dyn PrivateElicitResponder>,
    message: IpcMessage,
) -> IpcMessage {
    let (request_id, result) = match message.payload {
        IpcPayload::ElicitResponse {
            request_id,
            value,
            values,
        } => {
            if value.is_some() && values.is_some() {
                (request_id, Err(PrivateElicitRejection::Invalid))
            } else {
                let payload = IpcPayload::ElicitResponse {
                    request_id,
                    value,
                    values,
                };
                let result = if payload_too_large(&payload) {
                    Err(PrivateElicitRejection::Invalid)
                } else if let Some(device) = identity.device_key_id.as_deref() {
                    match payload {
                        IpcPayload::ElicitResponse { value, values, .. } => {
                            handler.map_or(Err(PrivateElicitRejection::Unavailable), |handler| {
                                handler.reply(
                                    &identity.principal,
                                    device,
                                    request_id,
                                    value,
                                    values,
                                )
                            })
                        },
                        _ => Err(PrivateElicitRejection::Invalid),
                    }
                } else {
                    Err(PrivateElicitRejection::Forbidden)
                };
                (request_id, result)
            }
        },
        _ => (Uuid::nil(), Err(PrivateElicitRejection::Invalid)),
    };
    let status = match result {
        Ok(()) => "delivered",
        Err(PrivateElicitRejection::Unavailable) => "unavailable",
        Err(PrivateElicitRejection::Forbidden) => "forbidden",
        Err(PrivateElicitRejection::Invalid) => "invalid",
    };
    IpcMessage::new(
        Topic::from_raw("astrid.v1.private.elicit.result"),
        IpcPayload::RawJson(serde_json::json!({"request_id": request_id, "status": status})),
        Uuid::nil(),
    )
    .with_principal(identity.principal.to_string())
}

#[cfg(test)]
mod tests;

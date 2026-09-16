//! Private typed input transport; schema notifications contain no answer.

use std::sync::Arc;
use std::time::Duration;

use astrid_events::ipc::OnboardingFieldType;

use super::{ElicitRequest, ElicitResponse, ErrorCode, HostState, OnboardingField};
use crate::elicitation::{
    ElicitAnswerKind, PendingSecretElicits, SecretElicitIdentity, SecretElicitKey,
    SecretElicitReply,
};

pub(super) fn collect(
    state: &mut HostState,
    request: &ElicitRequest,
    field: OnboardingField,
    registry: Arc<PendingSecretElicits>,
) -> Result<ElicitResponse, ErrorCode> {
    let identity = SecretElicitIdentity::new(
        state.effective_principal().clone(),
        state.capsule_id.clone(),
        SecretElicitKey::new(request.key.clone()).map_err(|_| ErrorCode::InvalidInput)?,
    );
    let waiter = registry
        .register_kind(identity, expected_kind(&field))
        .map_err(|_| ErrorCode::Unknown("secret input request capacity unavailable".into()))?;
    let event = super::elicit_request_event(
        astrid_events::ipc::Topic::private_elicit_request(),
        waiter.id().as_uuid(),
        state.capsule_id.to_string(),
        field.clone(),
        state.effective_principal().to_string(),
    );
    let bus = state.event_bus.clone();
    let cancellation = state.effective_cancel_token();
    let reply = super::util::bounded_block_on_cancellable(
        &state.runtime_handle,
        &state.blocking_semaphore,
        &cancellation,
        async move {
            // Publish only after admission to the blocking-operation budget.
            // The owned waiter is dropped on timeout or capsule cancellation.
            bus.publish(event);
            tokio::time::timeout(
                Duration::from_millis(super::MAX_ELICIT_TIMEOUT_MS),
                waiter.recv(),
            )
            .await
        },
    );
    let reply = match reply {
        Some(Ok(reply)) => reply,
        None if cancellation.is_cancelled() => return Err(ErrorCode::Cancelled),
        None | Some(Err(_)) => return Err(ErrorCode::Timeout),
    };
    into_guest_response(state, request, &field, reply)
}

fn expected_kind(field: &OnboardingField) -> ElicitAnswerKind {
    match &field.field_type {
        OnboardingFieldType::Text => ElicitAnswerKind::Text,
        OnboardingFieldType::Secret => ElicitAnswerKind::Secret,
        OnboardingFieldType::Enum(options) => ElicitAnswerKind::Select(options.clone()),
        OnboardingFieldType::Array => ElicitAnswerKind::Array,
    }
}

fn into_guest_response(
    state: &mut HostState,
    request: &ElicitRequest,
    field: &OnboardingField,
    reply: SecretElicitReply,
) -> Result<ElicitResponse, ErrorCode> {
    // The invocation can retire while the human is answering. Delivery alone
    // does not authorize either returning ordinary input or storing a secret.
    if !state.invocation_authority_active() {
        return Err(ErrorCode::Cancelled);
    }
    match reply {
        SecretElicitReply::Cancelled => Err(ErrorCode::Cancelled),
        SecretElicitReply::Provided(secret) => {
            if !matches!(field.field_type, OnboardingFieldType::Secret) {
                return Err(ErrorCode::InvalidInput);
            }
            // Completion only delivers bytes. Authority and persistence remain here,
            // in the same invocation, never in the UI/admin handler or an env reload.
            state
                .effective_secret_store()
                .set(&request.key, secret.expose_as_str())
                .map_err(|_| ErrorCode::StoreUnavailable)?;
            Ok(ElicitResponse::SecretStored)
        },
        SecretElicitReply::Value(value) => {
            if let OnboardingFieldType::Enum(options) = &field.field_type
                && !options.iter().any(|option| option == &value)
            {
                return Err(ErrorCode::InvalidInput);
            }
            if matches!(
                field.field_type,
                OnboardingFieldType::Secret | OnboardingFieldType::Array
            ) {
                return Err(ErrorCode::InvalidInput);
            }
            Ok(ElicitResponse::Value(value))
        },
        SecretElicitReply::Values(values) => {
            if !matches!(field.field_type, OnboardingFieldType::Array) {
                return Err(ErrorCode::InvalidInput);
            }
            Ok(ElicitResponse::Values(values))
        },
    }
}

#[cfg(test)]
#[path = "private_secret/tests.rs"]
mod tests;

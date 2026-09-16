use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use astrid_events::AstridEvent;
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use uuid::Uuid;

use super::*;
use crate::elicitation::{SecretElicitError, SecretElicitId};
use crate::engine::wasm::bindings::astrid::elicit::host::{ElicitType, Host};
use crate::engine::wasm::test_fixtures::{mem_secret_store, minimal_host_state};

fn request() -> ElicitRequest {
    ElicitRequest {
        kind: ElicitType::Secret,
        key: "token".into(),
        description: "Enter a token".into(),
        options: None,
        default_value: None,
    }
}

fn text_request() -> ElicitRequest {
    ElicitRequest {
        kind: ElicitType::Text,
        key: "name".into(),
        description: "Enter a name".into(),
        options: None,
        default_value: None,
    }
}

fn select_request() -> ElicitRequest {
    ElicitRequest {
        kind: ElicitType::Select,
        key: "network".into(),
        description: "Choose network".into(),
        options: Some(vec!["mainnet".into(), "testnet".into()]),
        default_value: None,
    }
}

fn array_request() -> ElicitRequest {
    ElicitRequest {
        kind: ElicitType::Array,
        key: "relays".into(),
        description: "Enter relays".into(),
        options: None,
        default_value: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_answer_cannot_resume_retired_or_unauthorized_invocation() {
    for unauthorized in [false, true] {
        for req in [text_request(), select_request(), array_request()] {
            let (mut state, _, _) = setup();
            let field = super::super::map_to_onboarding_field(&req).unwrap();
            let reply = match req.kind {
                ElicitType::Text => SecretElicitReply::Value("text".into()),
                ElicitType::Select => SecretElicitReply::Value("mainnet".into()),
                ElicitType::Array => SecretElicitReply::Values(vec!["relay".into()]),
                ElicitType::Secret => unreachable!(),
            };
            if unauthorized {
                state.invocation_profile_authorized = false;
            } else {
                state.effective_cancel_token().cancel();
            }
            assert!(matches!(
                into_guest_response(&mut state, &req, &field, reply),
                Err(ErrorCode::Cancelled)
            ));
        }
    }
}

fn identity_for(state: &HostState, key: &str) -> SecretElicitIdentity {
    SecretElicitIdentity::new(
        state.effective_principal().clone(),
        state.capsule_id.clone(),
        SecretElicitKey::new(key).unwrap(),
    )
}

async fn request_id(rx: &mut astrid_events::EventReceiver) -> SecretElicitId {
    let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let AstridEvent::Ipc { message, .. } = &*event else {
        panic!("expected IPC")
    };
    let IpcPayload::ElicitRequest {
        request_id, field, ..
    } = &message.payload
    else {
        panic!("expected schema")
    };
    assert!(field.default.is_none());
    SecretElicitId::from_uuid(*request_id)
}

fn setup() -> (HostState, Arc<PendingSecretElicits>, SecretElicitIdentity) {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt.clone());
    state.secret_store = mem_secret_store("capsule:private-test", rt);
    let registry = Arc::new(PendingSecretElicits::for_principals(
        NonZeroUsize::new(2).unwrap(),
        [state.effective_principal()].into(),
    ));
    state.secret_elicits = Some(Arc::clone(&registry));
    let identity = SecretElicitIdentity::new(
        state.effective_principal().clone(),
        state.capsule_id.clone(),
        SecretElicitKey::new("token").unwrap(),
    );
    (state, registry, identity)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unselected_principal_keeps_legacy_transport() {
    let (mut state, _, identity) = setup();
    let registry = Arc::new(PendingSecretElicits::for_principals(
        NonZeroUsize::MIN,
        [astrid_core::PrincipalId::new("other-principal").unwrap()].into(),
    ));
    assert!(!registry.routes_principal(identity.principal()));
    assert!(matches!(
        registry.register(identity.clone()),
        Err(SecretElicitError::IdentityMismatch)
    ));
    state.secret_elicits = Some(registry);
    let bus = state.event_bus.clone();
    let mut legacy = bus.subscribe_topic(Topic::elicit_request().as_str());
    let mut native = bus.subscribe_topic(Topic::private_elicit_request().as_str());
    let host = tokio::task::spawn_blocking(move || state.elicit(request()));
    let id = request_id(&mut legacy).await;
    bus.publish(AstridEvent::Ipc {
        message: IpcMessage::new(
            Topic::elicit_response(id.as_uuid()),
            IpcPayload::ElicitResponse {
                request_id: id.as_uuid(),
                value: None,
                values: None,
            },
            Uuid::nil(),
        )
        .with_principal(identity.principal().to_string()),
        metadata: astrid_events::EventMetadata::default(),
    });
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), host)
            .await
            .unwrap()
            .unwrap(),
        Err(ErrorCode::Cancelled)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), native.recv())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_secret_resumes_host_without_bus_reply_or_reload() {
    let (mut state, registry, identity) = setup();
    let bus = state.event_bus.clone();
    let mut requests = bus.subscribe_topic(Topic::private_elicit_request().as_str());
    let mut legacy_requests = bus.subscribe_topic(Topic::elicit_request().as_str());
    let host = tokio::task::spawn_blocking(move || {
        let result = state.elicit(request());
        let stored = state.effective_secret_store().get("token").unwrap();
        (result, stored)
    });
    let id = request_id(&mut requests).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), legacy_requests.recv())
            .await
            .is_err(),
        "native input must not trigger a competing legacy prompt"
    );
    let mut replies = bus.subscribe_topic(Topic::elicit_response(id.as_uuid()).as_str());
    registry
        .complete(id, &identity, "synthetic-private-value".into())
        .unwrap();
    let (result, stored) = tokio::time::timeout(Duration::from_secs(5), host)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Ok(ElicitResponse::SecretStored)));
    assert_eq!(stored.as_deref(), Some("synthetic-private-value"));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), replies.recv())
            .await
            .is_err()
    );
    assert_eq!(
        registry.cancel(id, &identity),
        Err(SecretElicitError::UnknownRequest)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bus_answer_cannot_complete_private_secret_and_cancel_writes_nothing() {
    let (mut state, registry, identity) = setup();
    let bus = state.event_bus.clone();
    let mut requests = bus.subscribe_topic(Topic::private_elicit_request().as_str());
    let host = tokio::task::spawn_blocking(move || {
        let result = state.elicit(request());
        (result, state.effective_secret_store().get("token").unwrap())
    });
    let id = request_id(&mut requests).await;
    bus.publish(AstridEvent::Ipc {
        message: IpcMessage::new(
            Topic::elicit_response(id.as_uuid()),
            IpcPayload::ElicitResponse {
                request_id: id.as_uuid(),
                value: Some("bus-answer".into()),
                values: None,
            },
            Uuid::nil(),
        )
        .with_principal(identity.principal().to_string()),
        metadata: astrid_events::EventMetadata::default(),
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!host.is_finished());
    registry.cancel(id, &identity).unwrap();
    let (result, stored) = tokio::time::timeout(Duration::from_secs(5), host)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(ErrorCode::Cancelled)));
    assert!(stored.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unload_cancels_private_wait_and_rejects_late_secret() {
    let (mut state, registry, identity) = setup();
    let cancellation = state.effective_cancel_token();
    let mut requests = state
        .event_bus
        .subscribe_topic(Topic::private_elicit_request().as_str());
    let host = tokio::task::spawn_blocking(move || {
        let result = state.elicit(request());
        (result, state.effective_secret_store().get("token").unwrap())
    });
    let id = request_id(&mut requests).await;
    cancellation.cancel();
    let (result, stored) = tokio::time::timeout(Duration::from_secs(5), host)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(ErrorCode::Cancelled)));
    assert!(stored.is_none());
    assert_eq!(
        registry.complete(id, &identity, "late".into()),
        Err(SecretElicitError::UnknownRequest)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_default_is_rejected_before_public_notification() {
    let (mut state, _, _) = setup();
    // Keep the publisher alive after the host returns, so this checks absence
    // of a notification rather than observing a closed receiver.
    let bus = state.event_bus.clone();
    let mut requests = bus.subscribe_topic(Topic::private_elicit_request().as_str());
    let mut req = request();
    req.default_value = Some("must-not-be-published".into());
    let result = tokio::task::spawn_blocking(move || state.elicit(req))
        .await
        .unwrap();
    assert!(matches!(result, Err(ErrorCode::InvalidInput)));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), requests.recv())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_text_empty_and_cancel_are_distinct() {
    let (mut state, registry, _) = setup();
    let identity = identity_for(&state, "name");
    let mut requests = state
        .event_bus
        .subscribe_topic(Topic::private_elicit_request().as_str());
    let host = tokio::task::spawn_blocking(move || state.elicit(text_request()));
    let id = request_id(&mut requests).await;
    registry
        .reply_for_principal(id, identity.principal(), Some(String::new()), None)
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), host)
            .await
            .unwrap()
            .unwrap(),
        Ok(ElicitResponse::Value(value)) if value.is_empty()
    ));

    let (mut state, registry, _) = setup();
    let identity = identity_for(&state, "name");
    let mut requests = state
        .event_bus
        .subscribe_topic(Topic::private_elicit_request().as_str());
    let host = tokio::task::spawn_blocking(move || state.elicit(text_request()));
    let id = request_id(&mut requests).await;
    registry
        .reply_for_principal(id, identity.principal(), None, None)
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), host)
            .await
            .unwrap()
            .unwrap(),
        Err(ErrorCode::Cancelled)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_array_empty_list_is_distinct_from_cancel() {
    let (mut state, registry, _) = setup();
    let identity = identity_for(&state, "relays");
    let mut requests = state
        .event_bus
        .subscribe_topic(Topic::private_elicit_request().as_str());
    let host = tokio::task::spawn_blocking(move || state.elicit(array_request()));
    let id = request_id(&mut requests).await;
    registry
        .reply_for_principal(id, identity.principal(), None, Some(Vec::new()))
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), host)
            .await
            .unwrap()
            .unwrap(),
        Ok(ElicitResponse::Values(values)) if values.is_empty()
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_select_member_completes_and_bus_cannot_answer() {
    let (mut state, registry, _) = setup();
    let identity = identity_for(&state, "network");
    let bus = state.event_bus.clone();
    let mut requests = bus.subscribe_topic(Topic::private_elicit_request().as_str());
    let host = tokio::task::spawn_blocking(move || state.elicit(select_request()));
    let id = request_id(&mut requests).await;
    bus.publish(AstridEvent::Ipc {
        message: IpcMessage::new(
            Topic::elicit_response(id.as_uuid()),
            IpcPayload::ElicitResponse {
                request_id: id.as_uuid(),
                value: Some("mainnet".into()),
                values: None,
            },
            Uuid::nil(),
        )
        .with_principal(identity.principal().to_string()),
        metadata: astrid_events::EventMetadata::default(),
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!host.is_finished());
    registry
        .reply_for_principal(id, identity.principal(), Some("mainnet".into()), None)
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), host)
            .await
            .unwrap()
            .unwrap(),
        Ok(ElicitResponse::Value(value)) if value == "mainnet"
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unselected_principal_text_keeps_legacy_transport() {
    let (mut state, _, identity) = setup();
    let registry = Arc::new(PendingSecretElicits::for_principals(
        NonZeroUsize::MIN,
        [astrid_core::PrincipalId::new("other-principal").unwrap()].into(),
    ));
    state.secret_elicits = Some(registry);
    let bus = state.event_bus.clone();
    let mut legacy = bus.subscribe_topic(Topic::elicit_request().as_str());
    let mut native = bus.subscribe_topic(Topic::private_elicit_request().as_str());
    let host = tokio::task::spawn_blocking(move || state.elicit(text_request()));
    let id = request_id(&mut legacy).await;
    bus.publish(AstridEvent::Ipc {
        message: IpcMessage::new(
            Topic::elicit_response(id.as_uuid()),
            IpcPayload::ElicitResponse {
                request_id: id.as_uuid(),
                value: Some("from-legacy".into()),
                values: None,
            },
            Uuid::nil(),
        )
        .with_principal(identity.principal().to_string()),
        metadata: astrid_events::EventMetadata::default(),
    });
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), host)
            .await
            .unwrap()
            .unwrap(),
        Ok(ElicitResponse::Value(value)) if value == "from-legacy"
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), native.recv())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn array_default_and_select_non_member_default_reject_before_notification() {
    let (mut state, _, _) = setup();
    let bus = state.event_bus.clone();
    let mut requests = bus.subscribe_topic(Topic::private_elicit_request().as_str());
    let mut array = array_request();
    array.default_value = Some("must-not-publish".into());
    let result = tokio::task::spawn_blocking(move || state.elicit(array))
        .await
        .unwrap();
    assert!(matches!(result, Err(ErrorCode::InvalidInput)));

    let (mut state, _, _) = setup();
    let mut select = select_request();
    select.default_value = Some("devnet".into());
    let result = tokio::task::spawn_blocking(move || state.elicit(select))
        .await
        .unwrap();
    assert!(matches!(result, Err(ErrorCode::InvalidInput)));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), requests.recv())
            .await
            .is_err()
    );
}

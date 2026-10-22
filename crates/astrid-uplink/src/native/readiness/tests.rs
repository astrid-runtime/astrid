use super::*;
use crate::native::{egress, input::PendingInput};
use astrid_core::PrincipalId;
use astrid_events::{AstridEvent, EventBus};
use astrid_types::{
    Topic,
    ipc::{IpcPayload, RequestOwnerId},
};
use std::time::Duration;
use uuid::Uuid;

fn identity() -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: Some("verified-key".into()),
        request_owner: RequestOwnerId::generate(),
    }
}

#[tokio::test]
async fn cold_capsule_request_waits_before_publication_and_uses_authenticated_principal() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = identity();
    let receiver = registry.subscribe(
        "alice".into(),
        identity.device_key_id.clone(),
        identity.request_owner,
    );
    let topic = "cli.v1.command.run.fixture";
    let mut deliveries = bus.subscribe_topic(topic);
    let ready = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::clone(&ready);
    let probe = CapsuleTopicProbe::new_with_ensure(
        |_| Box::pin(async { false }),
        move |key| {
            let ready = Arc::clone(&ready);
            Box::pin(async move {
                assert_eq!(
                    key,
                    "\0astrid.scoped-topic\0alice\0cli.v1.command.run.fixture"
                );
                let permit = ready.acquire().await.unwrap();
                permit.forget();
                true
            })
        },
    );
    let message = IpcMessage::new(
        Topic::from_raw(topic),
        IpcPayload::RawJson(serde_json::json!({"req_id":"first"})),
        Uuid::nil(),
    )
    .with_principal("spoofed");
    let mut pending =
        PendingInput::with_readiness(&bus, &identity, &receiver, message, Some(&probe));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), pending.future.as_mut())
            .await
            .is_err()
    );
    assert!(
        deliveries.try_recv().is_none(),
        "cold input must not be silently lost before subscription"
    );
    release.add_permits(1);
    pending.future.await.unwrap();
    let event = deliveries.try_recv().expect("ready input delivered");
    let AstridEvent::Ipc { message, .. } = &*event else {
        panic!("IPC expected")
    };
    assert_eq!(message.principal.as_deref(), Some("alice"));
    assert_eq!(message.device_key_id, identity.device_key_id);
}

#[tokio::test]
async fn unavailable_provider_refuses_without_publishing() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = identity();
    let receiver = registry.subscribe(
        "alice".into(),
        identity.device_key_id.clone(),
        identity.request_owner,
    );
    let mut deliveries = bus.subscribe_topic("cli.v1.command.run.fixture");
    let probe = CapsuleTopicProbe::new(|_| Box::pin(async { false }));
    let message = IpcMessage::new(
        Topic::from_raw("cli.v1.command.run.fixture"),
        IpcPayload::RawJson(serde_json::json!({})),
        Uuid::nil(),
    );
    let pending = PendingInput::with_readiness(&bus, &identity, &receiver, message, Some(&probe));
    assert!(pending.future.await.is_err());
    assert!(deliveries.try_recv().is_none());
}

#[tokio::test]
async fn management_human_reply_and_cancellation_do_not_wait_for_capsules() {
    let identity = identity();
    let probe = CapsuleTopicProbe::new(|_| panic!("control must not invoke capsule readiness"));
    for topic in [
        "astrid.v1.request.status.req",
        "astrid.v1.admin.agent.list.req",
        "astrid.v1.elicit.response.req",
        "astrid.v1.approval.response.req",
    ] {
        let message = IpcMessage::new(
            Topic::from_raw(topic),
            IpcPayload::RawJson(serde_json::json!({})),
            Uuid::nil(),
        );
        ensure(Some(&probe), &identity, &message).await.unwrap();
    }
    let cancel = IpcMessage::new(
        Topic::user_prompt(),
        IpcPayload::UserInput {
            text: String::new(),
            session_id: "session".into(),
            context: Some(serde_json::json!({"action":"cancel_turn"})),
        },
        Uuid::nil(),
    );
    ensure(Some(&probe), &identity, &cancel).await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn cancellation_drops_pending_readiness_without_publishing_the_prompt() {
    use crate::native::{
        FramedReader, LocalStream, input::handle_connection_input, local_transport,
    };
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = identity();
    let receiver = registry.subscribe(
        "alice".into(),
        identity.device_key_id.clone(),
        identity.request_owner,
    );
    let mut deliveries = bus.subscribe_topic(routing::CHAT_REQUEST_TOPIC);
    let probe = CapsuleTopicProbe::new_with_ensure(
        |_| Box::pin(async { false }),
        |_| Box::pin(std::future::pending()),
    );
    let prompt = |context| {
        IpcMessage::new(
            Topic::user_prompt(),
            IpcPayload::UserInput {
                text: "prompt".into(),
                session_id: "conversation".into(),
                context,
            },
            Uuid::nil(),
        )
    };
    let mut pending = Some(PendingInput::with_readiness(
        &bus,
        &identity,
        &receiver,
        prompt(None),
        Some(&probe),
    ));
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            pending.as_mut().unwrap().future.as_mut()
        )
        .await
        .is_err()
    );
    assert_eq!(receiver.turn_owner(), None);
    let (server, client) = LocalStream::pair().unwrap();
    let (_, mut writer) = local_transport::split(server);
    let mut read = FramedReader::new(client);
    handle_connection_input(
        &mut writer,
        &bus,
        &identity,
        &receiver,
        None,
        prompt(Some(serde_json::json!({"action":"cancel_turn"}))),
        (&mut pending, &mut None, &mut None),
    )
    .await
    .unwrap();
    let terminal = read.read_message().await.unwrap().unwrap();
    assert!(matches!(
        terminal.payload,
        IpcPayload::AgentResponse { is_final: true, .. }
    ));
    assert!(pending.is_none());
    assert!(deliveries.try_recv().is_none());
    assert_eq!(receiver.turn_owner(), None);
}

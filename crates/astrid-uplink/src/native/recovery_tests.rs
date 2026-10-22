//! Turn recovery must not reuse authority from a completed or retired turn.

use super::*;

#[derive(Debug)]
struct BlockedDelivery(Arc<tokio::sync::Semaphore>);

struct AdmittedDelivery(tokio::sync::OwnedSemaphorePermit);

impl astrid_events::ReservedEventDelivery for AdmittedDelivery {
    fn deliver(self: Box<Self>, _event: &AstridEvent) {
        drop(self.0);
    }
}

#[async_trait::async_trait]
impl astrid_events::EventDeliveryAdmitter for BlockedDelivery {
    async fn reserve(
        &self,
        _event: &AstridEvent,
    ) -> Result<Box<dyn astrid_events::ReservedEventDelivery>, astrid_events::DeliveryAdmissionError>
    {
        let permit = self
            .0
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| astrid_events::DeliveryAdmissionError::Closed)?;
        Ok(Box::new(AdmittedDelivery(permit)))
    }
}

#[tokio::test]
async fn native_input_waits_for_capacity_and_cancelled_admission_releases_turn() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let receiver = registry.subscribe("alice".to_owned(), None, identity.request_owner);
    let capacity = Arc::new(tokio::sync::Semaphore::new(0));
    let admitter: Arc<dyn astrid_events::EventDeliveryAdmitter> =
        Arc::new(BlockedDelivery(capacity.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    let mut ingress = bus.subscribe_topic(routing::CHAT_REQUEST_TOPIC);
    let prompt = || {
        IpcMessage::new(
            Topic::user_prompt(),
            IpcPayload::UserInput {
                text: "prompt".into(),
                session_id: "conversation".into(),
                context: None,
            },
            Uuid::nil(),
        )
    };
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            process_inbound(&bus, &identity, "alice", &receiver, prompt())
        )
        .await
        .is_err()
    );
    assert!(
        ingress.try_recv().is_none(),
        "no input published without capacity"
    );
    assert_eq!(
        receiver.session(),
        None,
        "aborted reservation must not strand the turn"
    );
    capacity.add_permits(1);
    process_inbound(&bus, &identity, "alice", &receiver, prompt())
        .await
        .expect("retry admitted");
    assert!(ingress.try_recv().is_some(), "admitted input delivered");
}
use astrid_core::PrincipalId;
use astrid_types::ipc::RequestOwnerId;
use uuid::Uuid;

#[derive(Debug)]
struct PendingDelivery(tokio::sync::Notify);

#[derive(Debug)]
struct BlockedPromptDelivery(tokio::sync::Notify);

#[async_trait::async_trait]
impl astrid_events::EventDeliveryAdmitter for BlockedPromptDelivery {
    async fn reserve(
        &self,
        event: &AstridEvent,
    ) -> Result<Box<dyn astrid_events::ReservedEventDelivery>, astrid_events::DeliveryAdmissionError>
    {
        if matches!(event, AstridEvent::Ipc { message, .. } if message.topic == Topic::user_prompt())
        {
            self.0.notify_one();
            std::future::pending().await
        } else {
            Ok(Box::new(AdmittedDelivery(
                Arc::new(tokio::sync::Semaphore::new(1))
                    .acquire_owned()
                    .await
                    .unwrap(),
            )))
        }
    }
}

#[tokio::test]
async fn socket_answers_delivered_approval_while_ordinary_input_is_blocked() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let owner = RequestOwnerId::generate();
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: None,
        request_owner: owner,
    };
    let receiver = registry.subscribe("alice".into(), None, owner);
    let blocked = Arc::new(BlockedPromptDelivery(tokio::sync::Notify::new()));
    let admitter: Arc<dyn astrid_events::EventDeliveryAdmitter> = blocked.clone();
    assert!(bus.register_delivery_admitter(&admitter));
    let mut ingress = bus.subscribe_topic(Topic::user_prompt().as_str());
    let (server, client) = LocalStream::pair().unwrap();
    let (read, mut write) = local_transport::split(client);
    let mut read = FramedReader::new(read);
    let (shutdown, watch) = tokio::sync::watch::channel(false);
    let permits = Arc::new(tokio::sync::Semaphore::new(1));
    let admission = socket_admission(permits.clone()).await;
    let task = tokio::spawn(serve_connection(
        server,
        identity,
        bus.clone(),
        receiver,
        watch,
        admission,
        None,
    ));
    write_message(
        &mut write,
        &IpcMessage::new(
            Topic::user_prompt(),
            IpcPayload::UserInput {
                text: "waiting".into(),
                session_id: "conversation".into(),
                context: None,
            },
            Uuid::nil(),
        ),
    )
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), blocked.0.notified())
        .await
        .unwrap();
    bus.publish(approval_event(owner));
    let delivered = tokio::time::timeout(std::time::Duration::from_secs(1), read.read_message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(delivered.topic, Topic::approval_request());
    let response_topic = Topic::approval_response("grant");
    let mut responses = bus.subscribe_topic(response_topic.as_str());
    write_message(
        &mut write,
        &IpcMessage::new(
            response_topic,
            IpcPayload::ApprovalResponse {
                request_id: "grant".into(),
                decision: "approve".into(),
                reason: None,
            },
            Uuid::nil(),
        ),
    )
    .await
    .unwrap();
    let reply = tokio::time::timeout(std::time::Duration::from_secs(1), responses.recv())
        .await
        .expect("control reply bypasses blocked ordinary admission")
        .unwrap();
    let AstridEvent::Ipc { message, .. } = &*reply else {
        panic!("IPC approval reply")
    };
    assert_eq!(message.request_owner, Some(owner));
    assert!(
        ingress.try_recv().is_none(),
        "ordinary input remains uncommitted"
    );
    bus.publish(alive_event(owner));
    let alive = tokio::time::timeout(std::time::Duration::from_secs(1), read.read_message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(alive.topic.as_str(), "astrid.v1.response.alive");
    shutdown.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(permits.available_permits(), 1);
    let retry = registry.subscribe("alice".into(), None, RequestOwnerId::generate());
    assert!(
        retry.begin_turn("conversation"),
        "shutdown releases pending turn"
    );
}

fn approval_event(owner: RequestOwnerId) -> AstridEvent {
    AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::approval_request(),
            IpcPayload::ApprovalRequired {
                request_id: "grant".into(),
                request_owner: owner.to_string(),
                action: "invoke".into(),
                resource: "capsule".into(),
                reason: "test".into(),
            },
            Uuid::nil(),
        )
        .with_principal("alice")
        .with_request_owner(owner),
    }
}

#[tokio::test]
async fn overlapping_human_replies_claim_once_and_abandoned_wait_allows_retry() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let receiver = registry.subscribe("alice".into(), None, identity.request_owner);
    let mut receiver = receiver;
    bus.publish(approval_event(identity.request_owner));
    receiver.try_recv().unwrap();
    let capacity = Arc::new(tokio::sync::Semaphore::new(0));
    let admitter: Arc<dyn astrid_events::EventDeliveryAdmitter> =
        Arc::new(BlockedDelivery(capacity.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    let topic = Topic::approval_response("grant");
    let mut replies = bus.subscribe_topic(topic.as_str());
    let reply = || {
        IpcMessage::new(
            topic.clone(),
            IpcPayload::ApprovalResponse {
                request_id: "grant".into(),
                decision: "approve".into(),
                reason: None,
            },
            Uuid::nil(),
        )
    };
    let mut first = Box::pin(process_inbound(
        &bus,
        &identity,
        "alice",
        &receiver,
        reply(),
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), first.as_mut())
            .await
            .is_err()
    );
    let duplicate = tokio::time::timeout(
        std::time::Duration::from_millis(20),
        process_inbound(&bus, &identity, "alice", &receiver, reply()),
    )
    .await;
    assert!(
        matches!(duplicate, Ok(Err(_))),
        "duplicate must refuse, not queue behind the same reply"
    );
    assert!(replies.try_recv().is_none());
    drop(first);
    capacity.add_permits(1);
    process_inbound(&bus, &identity, "alice", &receiver, reply())
        .await
        .unwrap();
    assert!(
        replies.try_recv().is_some(),
        "abandoned admission preserves retry"
    );
    assert!(
        process_inbound(&bus, &identity, "alice", &receiver, reply())
            .await
            .is_err()
    );
    assert!(
        replies.try_recv().is_none(),
        "successful reply is single-use"
    );
}

async fn socket_admission(permits: Arc<tokio::sync::Semaphore>) -> ConnectionAdmission {
    ConnectionAdmission {
        _permit: permits.acquire_owned().await.unwrap(),
        initial_message: None,
        reserved_response: None,
    }
}

fn blocked_management_input() -> IpcMessage {
    IpcMessage::new(
        Topic::from_raw("astrid.v1.request.commands.blocked"),
        IpcPayload::RawJson(serde_json::to_value(KernelRequest::GetCommands).unwrap()),
        Uuid::nil(),
    )
}

fn grant_reply_input() -> IpcMessage {
    IpcMessage::new(
        Topic::approval_response("grant"),
        IpcPayload::ApprovalResponse {
            request_id: "grant".into(),
            decision: "approve".into(),
            reason: None,
        },
        Uuid::nil(),
    )
}

async fn write_inbound_frame(writer: &mut LocalWriteHalf, message: &IpcMessage) {
    // Native clients send the tagged IPC envelope; outbound display frames
    // deliberately unwrap RawJson and are not an ingress encoder.
    let bytes = serde_json::to_vec(message).unwrap();
    writer
        .write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    writer.write_all(&bytes).await.unwrap();
    writer.flush().await.unwrap();
}

fn alive_event(owner: RequestOwnerId) -> AstridEvent {
    AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::from_raw("astrid.v1.response.alive"),
            IpcPayload::Disconnect {
                reason: Some("alive".into()),
            },
            Uuid::nil(),
        )
        .with_principal("alice")
        .with_request_owner(owner),
    }
}

#[tokio::test]
async fn buffered_management_inputs_commit_before_the_next_frame_is_admitted() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let receiver = registry.subscribe("alice".into(), None, identity.request_owner);
    let request = |id| {
        IpcMessage::new(
            Topic::from_raw(format!("astrid.v1.request.commands.{id}")),
            IpcPayload::RawJson(serde_json::to_value(KernelRequest::GetCommands).unwrap()),
            Uuid::nil(),
        )
    };
    let mut ingress = bus.subscribe_topic("astrid.v1.request.commands.*");
    let (server, peer) = LocalStream::pair().unwrap();
    let (_, mut writer) = local_transport::split(server);
    let mut peer = FramedReader::new(peer);
    let mut pending = Some(PendingInput::new(
        &bus,
        &identity,
        &receiver,
        request("first"),
    ));
    handle_connection_input(
        &mut writer,
        &bus,
        &identity,
        &receiver,
        None,
        request("second"),
        (&mut pending, &mut None, &mut None),
    )
    .await
    .unwrap();
    assert!(
        ingress.try_recv().is_some(),
        "first ready request was polled and committed"
    );
    assert!(pending.is_some(), "second request is admitted, not refused");
    pending.as_mut().unwrap().future.as_mut().await.unwrap();
    drop(pending.take());
    assert!(ingress.try_recv().is_some(), "second request commits");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), peer.read_message())
            .await
            .is_err(),
        "no spurious disconnect/refusal for buffered management requests"
    );
}

#[tokio::test]
async fn unpolled_busy_prompt_does_not_swallow_cancellation_of_the_existing_turn() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let mut receiver = registry.subscribe("alice".into(), None, identity.request_owner);
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
    process_inbound(&bus, &identity, "alice", &receiver, prompt(None))
        .await
        .unwrap();
    let retired = receiver.turn_owner().unwrap();
    let mut pending = Some(PendingInput::new(&bus, &identity, &receiver, prompt(None)));
    let mut cancellation = None;
    let mut ingress = bus.subscribe_topic(routing::CHAT_REQUEST_TOPIC);
    let (server, peer) = LocalStream::pair().unwrap();
    let (_, mut writer) = local_transport::split(server);
    let mut peer = FramedReader::new(peer);
    handle_connection_input(
        &mut writer,
        &bus,
        &identity,
        &receiver,
        None,
        prompt(Some(serde_json::json!({"action":"cancel_turn"}))),
        (&mut pending, &mut None, &mut cancellation),
    )
    .await
    .unwrap();
    assert!(
        pending.is_none(),
        "busy prompt was refused before cancellation"
    );
    assert!(
        cancellation.is_some(),
        "cancel remains a real runtime input"
    );
    cancellation
        .as_mut()
        .unwrap()
        .future
        .as_mut()
        .await
        .unwrap();
    drop(cancellation.take());
    let refused = peer.read_message().await.unwrap().unwrap();
    assert!(
        matches!(refused.payload, IpcPayload::AgentResponse { text, .. } if text.contains("already has an active turn"))
    );
    let forwarded = ingress.try_recv().expect("capsules receive cancellation");
    let AstridEvent::Ipc { message, .. } = &*forwarded else {
        panic!("IPC cancellation")
    };
    assert!(routing::is_cancel_turn(&message.payload));
    assert_eq!(message.request_owner, Some(retired));
    drop(pending);
    drop(cancellation);
    assert!(
        receiver.try_recv().is_ok(),
        "native terminal releases existing turn"
    );
    assert_eq!(receiver.session(), None);
}

#[async_trait::async_trait]
impl astrid_events::EventDeliveryAdmitter for PendingDelivery {
    async fn reserve(
        &self,
        _: &AstridEvent,
    ) -> Result<Box<dyn astrid_events::ReservedEventDelivery>, astrid_events::DeliveryAdmissionError>
    {
        self.0.notify_one();
        std::future::pending().await
    }
}

#[tokio::test]
async fn pending_socket_admission_drains_egress_and_releases_on_eof_or_shutdown() {
    for shutdown_requested in [false, true] {
        let bus = Arc::new(EventBus::new());
        let registry = egress::Registry::install(&bus);
        let identity = AuthenticatedIdentity {
            principal: PrincipalId::new("alice").unwrap(),
            device_key_id: None,
            request_owner: RequestOwnerId::generate(),
        };
        let owner = identity.request_owner;
        let receiver = registry.subscribe("alice".into(), None, owner);
        let blocked = Arc::new(PendingDelivery(tokio::sync::Notify::new()));
        let admitter: Arc<dyn astrid_events::EventDeliveryAdmitter> = blocked.clone();
        assert!(bus.register_delivery_admitter(&admitter));
        let (server, client) = LocalStream::pair().unwrap();
        let (read, mut write) = local_transport::split(client);
        let mut read = FramedReader::new(read);
        let (shutdown, watch) = tokio::sync::watch::channel(false);
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let admission = ConnectionAdmission {
            _permit: permits.clone().acquire_owned().await.unwrap(),
            initial_message: None,
            reserved_response: None,
        };
        let task = tokio::spawn(serve_connection(
            server,
            identity,
            bus.clone(),
            receiver,
            watch,
            admission,
            None,
        ));
        write_message(
            &mut write,
            &IpcMessage::new(
                Topic::user_prompt(),
                IpcPayload::UserInput {
                    text: "waiting".into(),
                    session_id: "conversation".into(),
                    context: None,
                },
                Uuid::nil(),
            ),
        )
        .await
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), blocked.0.notified())
            .await
            .expect("admission entered");
        bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: IpcMessage::new(
                Topic::from_raw("astrid.v1.response.test"),
                IpcPayload::Disconnect {
                    reason: Some("alive".into()),
                },
                Uuid::nil(),
            )
            .with_principal("alice")
            .with_request_owner(owner),
        });
        let response = tokio::time::timeout(std::time::Duration::from_secs(1), read.read_message())
            .await
            .expect("egress drains while admission waits")
            .unwrap()
            .unwrap();
        assert_eq!(response.topic.as_str(), "astrid.v1.response.test");
        if shutdown_requested {
            shutdown.send(true).unwrap();
        } else {
            write.shutdown().await.unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("pending admission does not obstruct lifecycle")
            .unwrap();
        assert_eq!(permits.available_permits(), 1);
        let retry = registry.subscribe("alice".into(), None, RequestOwnerId::generate());
        assert!(
            retry.begin_turn("conversation"),
            "connection closure releases unpublished turn"
        );
    }
}

#[tokio::test]
async fn pending_input_cancellation_is_private_and_allows_a_subsequent_turn() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let receiver = registry.subscribe("alice".into(), None, identity.request_owner);
    let capacity = Arc::new(tokio::sync::Semaphore::new(0));
    let admitter: Arc<dyn astrid_events::EventDeliveryAdmitter> =
        Arc::new(BlockedDelivery(capacity.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    let mut ingress = bus.subscribe_topic(routing::CHAT_REQUEST_TOPIC);
    let prompt = |session: &str, context| {
        IpcMessage::new(
            Topic::user_prompt(),
            IpcPayload::UserInput {
                text: "prompt".into(),
                session_id: session.into(),
                context,
            },
            Uuid::nil(),
        )
    };
    let mut pending = Some(PendingInput::new(
        &bus,
        &identity,
        &receiver,
        prompt("conversation", None),
    ));
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            pending.as_mut().unwrap().future.as_mut()
        )
        .await
        .is_err()
    );
    let retired = receiver.turn_owner().unwrap();
    let (server, client) = LocalStream::pair().unwrap();
    let (_, mut writer) = local_transport::split(server);
    let mut read = FramedReader::new(client);
    let cancel = |session| prompt(session, Some(serde_json::json!({"action":"cancel_turn"})));
    handle_connection_input(
        &mut writer,
        &bus,
        &identity,
        &receiver,
        None,
        cancel("foreign"),
        (&mut pending, &mut None, &mut None),
    )
    .await
    .unwrap();
    read.read_message().await.unwrap().unwrap();
    assert!(pending.is_some());
    assert_eq!(receiver.turn_owner(), Some(retired));
    handle_connection_input(
        &mut writer,
        &bus,
        &identity,
        &receiver,
        None,
        cancel("conversation"),
        (&mut pending, &mut None, &mut None),
    )
    .await
    .unwrap();
    let terminal = read.read_message().await.unwrap().unwrap();
    assert!(
        matches!(terminal.payload, IpcPayload::AgentResponse { is_final: true, ref text, .. }
        if text == "Request cancelled.")
    );
    assert_eq!(terminal.request_owner, Some(retired));
    assert!(pending.is_none());
    assert_eq!(receiver.session(), None);
    assert!(
        ingress.try_recv().is_none(),
        "unpublished input and cancellation never reach capsules"
    );
    capacity.add_permits(1);
    handle_connection_input(
        &mut writer,
        &bus,
        &identity,
        &receiver,
        None,
        prompt("conversation", None),
        (&mut pending, &mut None, &mut None),
    )
    .await
    .unwrap();
    pending.as_mut().unwrap().future.as_mut().await.unwrap();
    drop(pending.take());
    assert!(ingress.try_recv().is_some());
    assert_ne!(receiver.turn_owner(), Some(retired));
}

#[tokio::test]
async fn cancellation_releases_turn_when_forwarding_consumer_has_closed() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").expect("principal"),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let mut receiver = registry.subscribe("alice".to_owned(), None, identity.request_owner);
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
    process_inbound(&bus, &identity, "alice", &receiver, prompt(None))
        .await
        .expect("initial turn");
    let retired_owner = receiver.turn_owner().expect("active owner");
    let capacity = Arc::new(tokio::sync::Semaphore::new(0));
    capacity.close();
    let admitter: Arc<dyn astrid_events::EventDeliveryAdmitter> =
        Arc::new(BlockedDelivery(capacity));
    assert!(bus.register_delivery_admitter(&admitter));
    process_inbound(
        &bus,
        &identity,
        "alice",
        &receiver,
        prompt(Some(serde_json::json!({"action": "cancel_turn"}))),
    )
    .await
    .expect("native cancellation survives forwarding failure");
    let terminal = receiver.try_recv().expect("cancellation terminal");
    let AstridEvent::Ipc { message, .. } = &*terminal else {
        panic!("IPC terminal");
    };
    assert_eq!(message.request_owner, Some(retired_owner));
    assert!(
        matches!(&message.payload, IpcPayload::AgentResponse { is_final: true, text, .. }
        if text == "Request cancelled.")
    );
    assert_eq!(receiver.session(), None);
    assert!(
        process_inbound(&bus, &identity, "alice", &receiver, prompt(None))
            .await
            .is_err(),
        "ordinary input must still report failed admission"
    );
    assert_eq!(receiver.session(), None);
    drop(admitter);
    let recovered: Arc<dyn astrid_events::EventDeliveryAdmitter> =
        Arc::new(BlockedDelivery(Arc::new(tokio::sync::Semaphore::new(1))));
    assert!(bus.register_delivery_admitter(&recovered));
    process_inbound(&bus, &identity, "alice", &receiver, prompt(None))
        .await
        .expect("subsequent turn after delivery recovery");
    assert_ne!(receiver.turn_owner(), Some(retired_owner));
}

#[tokio::test]
async fn cancellation_releases_abandoned_turn_without_capsule_response() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").expect("principal"),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let mut receiver = registry.subscribe("alice".to_owned(), None, identity.request_owner);
    let prompt = |context| {
        IpcMessage::new(
            Topic::from_raw(routing::CHAT_REQUEST_TOPIC),
            IpcPayload::UserInput {
                text: String::new(),
                session_id: "conversation".to_owned(),
                context,
            },
            Uuid::new_v4(),
        )
    };
    process_inbound(&bus, &identity, "alice", &receiver, prompt(None))
        .await
        .expect("start");
    let first_owner = receiver.turn_owner().expect("first owner");
    // No capsule answers this request. Native cancellation must not depend on
    // the retired/crashed capsule remembering the lost turn.
    process_inbound(
        &bus,
        &identity,
        "alice",
        &receiver,
        prompt(Some(serde_json::json!({"action": "cancel_turn"}))),
    )
    .await
    .expect("owner can cancel abandoned turn");
    let terminal = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
        .await
        .expect("cancellation must complete without a capsule")
        .expect("cancellation terminal");
    let AstridEvent::Ipc { message, .. } = &*terminal else {
        panic!("IPC terminal");
    };
    assert_eq!(message.request_owner, Some(first_owner));
    assert!(
        matches!(&message.payload, IpcPayload::AgentResponse { is_final: true, session_id, .. }
        if session_id == "conversation")
    );
    assert_eq!(receiver.session(), None);
    process_inbound(&bus, &identity, "alice", &receiver, prompt(None))
        .await
        .expect("retry");
    let next_owner = receiver.turn_owner().expect("next owner");
    assert_ne!(next_owner, first_owner);
    for owner in [first_owner, next_owner] {
        bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: IpcMessage::new(
                Topic::from_raw("agent.v1.response"),
                IpcPayload::AgentResponse {
                    text: "response".to_owned(),
                    is_final: true,
                    session_id: "conversation".to_owned(),
                },
                Uuid::new_v4(),
            )
            .with_principal("alice")
            .with_request_owner(owner),
        });
        if owner == first_owner {
            assert_eq!(receiver.session().as_deref(), Some("conversation"));
            assert!(matches!(
                receiver.try_recv(),
                Err(egress::TryRecvError::Empty)
            ));
        }
    }
    receiver.try_recv().expect("subsequent turn completes");
    assert_eq!(receiver.session(), None);
}

#[tokio::test]
async fn cancellation_releases_turn_when_open_consumer_stops_draining() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let mut receiver = registry.subscribe("alice".into(), None, identity.request_owner);
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
    process_inbound(&bus, &identity, "alice", &receiver, prompt(None))
        .await
        .unwrap();
    let retired = receiver.turn_owner().unwrap();
    let capacity = Arc::new(tokio::sync::Semaphore::new(0));
    let admitter: Arc<dyn astrid_events::EventDeliveryAdmitter> =
        Arc::new(BlockedDelivery(capacity.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    let mut ingress = bus.subscribe_topic(routing::CHAT_REQUEST_TOPIC);
    tokio::time::timeout(
        CANCEL_FORWARD_TIMEOUT + std::time::Duration::from_millis(500),
        process_inbound(
            &bus,
            &identity,
            "alice",
            &receiver,
            prompt(Some(serde_json::json!({"action":"cancel_turn"}))),
        ),
    )
    .await
    .expect("open full consumer cannot strand cancellation")
    .unwrap();
    let terminal = receiver.try_recv().expect("native cancellation terminal");
    let AstridEvent::Ipc { message, .. } = &*terminal else {
        panic!("IPC terminal")
    };
    assert_eq!(message.request_owner, Some(retired));
    assert_eq!(receiver.session(), None);
    assert!(
        ingress.try_recv().is_none(),
        "timed-out forwarding never commits later"
    );
    capacity.add_permits(1);
    process_inbound(&bus, &identity, "alice", &receiver, prompt(None))
        .await
        .unwrap();
    assert_ne!(receiver.turn_owner(), Some(retired));
    let event = ingress.try_recv().expect("subsequent prompt commits");
    let AstridEvent::Ipc { message, .. } = &*event else {
        panic!("IPC prompt")
    };
    assert!(!routing::is_cancel_turn(&message.payload));
}

#[tokio::test]
async fn active_cancellation_preserves_blocked_management_and_human_reply() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let mut receiver = registry.subscribe("alice".into(), None, identity.request_owner);
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
    process_inbound(&bus, &identity, "alice", &receiver, prompt(None))
        .await
        .unwrap();
    let retired = receiver.turn_owner().unwrap();
    bus.publish(approval_event(identity.request_owner));
    receiver.try_recv().unwrap();
    let capacity = Arc::new(tokio::sync::Semaphore::new(0));
    let admitter: Arc<dyn astrid_events::EventDeliveryAdmitter> =
        Arc::new(BlockedDelivery(capacity.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    let management = blocked_management_input();
    let human = grant_reply_input();
    let mut pending = Some(PendingInput::new(&bus, &identity, &receiver, management));
    let mut control = Some(PendingInput::new(&bus, &identity, &receiver, human));
    let mut cancellation = None;
    let (server, client) = LocalStream::pair().unwrap();
    let (_, mut writer) = local_transport::split(server);
    // The public connection input handler polls both blocked futures before
    // classifying cancellation, just as it does for buffered socket frames.
    handle_connection_input(
        &mut writer,
        &bus,
        &identity,
        &receiver,
        None,
        prompt(Some(serde_json::json!({"action":"cancel_turn"}))),
        (&mut pending, &mut control, &mut cancellation),
    )
    .await
    .unwrap();
    assert!(
        pending.is_some() && control.is_some(),
        "unrelated input is not dropped"
    );
    assert!(
        cancellation.is_some(),
        "active cancellation gets independent admission"
    );
    tokio::time::timeout(
        CANCEL_FORWARD_TIMEOUT + std::time::Duration::from_secs(1),
        wait_pending(&mut cancellation),
    )
    .await
    .unwrap()
    .unwrap();
    drop(cancellation.take());
    let terminal = receiver
        .egress_queue()
        .recv()
        .await
        .expect("native terminal despite non-draining consumer");
    assert!(matches!(&*terminal, AstridEvent::Ipc { message, .. }
        if message.request_owner == Some(retired)
        && matches!(message.payload, IpcPayload::AgentResponse { is_final: true, .. })));
    assert_eq!(receiver.session(), None);
    let mut published = bus.subscribe();
    capacity.add_permits(1);
    wait_pending(&mut pending).await.unwrap();
    drop(pending.take());
    wait_pending(&mut control).await.unwrap();
    drop(control.take());
    for expected in [
        "astrid.v1.request.commands.blocked",
        "astrid.v1.approval.response.grant",
    ] {
        let event = published.try_recv().unwrap();
        assert!(matches!(&*event, AstridEvent::Ipc { message, .. }
            if message.topic.as_str() == expected && message.request_owner == Some(identity.request_owner)));
    }
    process_inbound(&bus, &identity, "alice", &receiver, prompt(None))
        .await
        .unwrap();
    assert_ne!(receiver.turn_owner(), Some(retired), "next turn can start");
    drop(client);
}

#[tokio::test]
async fn socket_cancels_active_turn_with_both_other_input_slots_blocked() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let receiver = registry.subscribe("alice".into(), None, identity.request_owner);
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
    process_inbound(&bus, &identity, "alice", &receiver, prompt(None))
        .await
        .unwrap();
    let retired = receiver.turn_owner().unwrap();
    bus.publish(approval_event(identity.request_owner));
    let capacity = Arc::new(tokio::sync::Semaphore::new(0));
    let admitter: Arc<dyn astrid_events::EventDeliveryAdmitter> =
        Arc::new(BlockedDelivery(capacity.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    let (server, client) = LocalStream::pair().unwrap();
    let (reader, mut writer) = local_transport::split(client);
    let mut reader = FramedReader::new(reader);
    let (shutdown, watch) = tokio::sync::watch::channel(false);
    let permits = Arc::new(tokio::sync::Semaphore::new(1));
    let admission = socket_admission(permits.clone()).await;
    let task = tokio::spawn(serve_connection(
        server,
        identity,
        bus.clone(),
        receiver,
        watch,
        admission,
        None,
    ));
    let approval = reader.read_message().await.unwrap().unwrap();
    assert_eq!(approval.topic, Topic::approval_request());
    let management = blocked_management_input();
    let human = grant_reply_input();
    write_inbound_frame(&mut writer, &management).await;
    write_inbound_frame(&mut writer, &human).await;
    write_inbound_frame(
        &mut writer,
        &prompt(Some(serde_json::json!({"action":"cancel_turn"}))),
    )
    .await;
    let terminal = tokio::time::timeout(
        CANCEL_FORWARD_TIMEOUT + std::time::Duration::from_secs(1),
        reader.read_message(),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert!(
        matches!(terminal.payload, IpcPayload::AgentResponse { is_final: true, ref text, .. }
        if text == "Request cancelled.")
    );
    assert_eq!(terminal.request_owner, Some(retired));
    let mut completed = bus.subscribe();
    capacity.add_permits(1);
    let mut topics = Vec::new();
    for _ in 0..2 {
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), completed.recv())
            .await
            .unwrap()
            .unwrap();
        topics.push(event_topic(&event).unwrap().to_owned());
    }
    topics.sort();
    assert_eq!(
        topics,
        vec![
            "astrid.v1.approval.response.grant",
            "astrid.v1.request.commands.blocked"
        ]
    );
    write_message(&mut writer, &prompt(None)).await.unwrap();
    let next = tokio::time::timeout(std::time::Duration::from_secs(1), completed.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(&*next, AstridEvent::Ipc { message, .. }
        if message.topic == Topic::user_prompt() && message.request_owner != Some(retired)));
    shutdown.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(permits.available_permits(), 1);
}

#[tokio::test]
async fn socket_buffers_next_prompt_until_capacity_blocked_cancel_retires() {
    for extra_frame in [false, true] {
        assert_buffered_prompt_after_cancel(extra_frame).await;
    }
}

#[tokio::test]
async fn ready_cancellation_settles_buffered_prompt_before_management_frame() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let receiver = registry.subscribe("alice".into(), None, identity.request_owner);
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
    process_inbound(&bus, &identity, "alice", &receiver, prompt(None))
        .await
        .unwrap();
    let retired = receiver.turn_owner().unwrap();
    let capacity = Arc::new(tokio::sync::Semaphore::new(0));
    let admitter: Arc<dyn astrid_events::EventDeliveryAdmitter> =
        Arc::new(BlockedDelivery(capacity.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    let mut pending = Some(PendingInput::new(&bus, &identity, &receiver, prompt(None)));
    let mut control = None;
    let mut cancellation = Some(PendingInput::new(
        &bus,
        &identity,
        &receiver,
        prompt(Some(serde_json::json!({"action":"cancel_turn"}))),
    ));
    let mut published = bus.subscribe_topic(routing::CHAT_REQUEST_TOPIC);
    let (server, _client) = LocalStream::pair().unwrap();
    let (_, mut writer) = local_transport::split(server);
    // Capacity returns before the buffered management frame wins scheduling.
    // Cancellation and then the queued prompt can both finish in this call.
    capacity.add_permits(1);
    handle_connection_input(
        &mut writer,
        &bus,
        &identity,
        &receiver,
        None,
        blocked_management_input(),
        (&mut pending, &mut control, &mut cancellation),
    )
    .await
    .expect("ready prompt must not cause a management disconnect");
    assert!(cancellation.is_none());
    assert!(pending.as_ref().is_some_and(|input| !input.starts_turn));
    let cancellation_event = published.try_recv().expect("cancellation was forwarded");
    assert!(
        matches!(&*cancellation_event, AstridEvent::Ipc { message, .. }
        if routing::is_cancel_turn(&message.payload))
    );
    let event = published.try_recv().expect("queued prompt was published");
    assert!(matches!(&*event, AstridEvent::Ipc { message, .. }
        if message.request_owner != Some(retired)
        && !routing::is_cancel_turn(&message.payload)));
}

async fn assert_buffered_prompt_after_cancel(extra_frame: bool) {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let receiver = registry.subscribe("alice".into(), None, identity.request_owner);
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
    process_inbound(&bus, &identity, "alice", &receiver, prompt(None))
        .await
        .unwrap();
    let retired = receiver.turn_owner().unwrap();
    let capacity = Arc::new(tokio::sync::Semaphore::new(0));
    let admitter: Arc<dyn astrid_events::EventDeliveryAdmitter> =
        Arc::new(BlockedDelivery(capacity.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    let (server, client) = LocalStream::pair().unwrap();
    let (reader, mut writer) = local_transport::split(client);
    let mut reader = FramedReader::new(reader);
    let (shutdown, watch) = tokio::sync::watch::channel(false);
    let admission = socket_admission(Arc::new(tokio::sync::Semaphore::new(1))).await;
    let task = tokio::spawn(serve_connection(
        server,
        identity,
        bus.clone(),
        receiver,
        watch,
        admission,
        None,
    ));
    write_inbound_frame(
        &mut writer,
        &prompt(Some(serde_json::json!({"action":"cancel_turn"}))),
    )
    .await;
    write_inbound_frame(&mut writer, &prompt(None)).await;
    if extra_frame {
        // Exercise the eager polling path too, not only the select branch.
        write_inbound_frame(&mut writer, &prompt(None)).await;
    }
    let terminal = tokio::time::timeout(
        CANCEL_FORWARD_TIMEOUT
            .checked_add(std::time::Duration::from_secs(1))
            .expect("bounded cancellation fixture deadline"),
        async {
            loop {
                let frame = reader.read_message().await.unwrap().unwrap();
                let IpcPayload::AgentResponse { ref text, .. } = frame.payload else {
                    panic!("expected private response")
                };
                if text == "Request cancelled." {
                    break frame;
                }
                assert!(
                    extra_frame && text.contains("previous input is awaiting runtime delivery"),
                    "buffered prompt must not be refused: {text}"
                );
            }
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(terminal.payload, IpcPayload::AgentResponse { is_final: true, ref text, .. }
        if text == "Request cancelled."),
        "next prompt must wait rather than get a busy refusal"
    );
    assert_eq!(terminal.request_owner, Some(retired));
    let mut completed = bus.subscribe();
    capacity.add_permits(1);
    let next = tokio::time::timeout(std::time::Duration::from_secs(1), completed.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(&*next, AstridEvent::Ipc { message, .. }
        if message.topic == Topic::user_prompt() && message.request_owner != Some(retired)));
    shutdown.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn management_reply_survives_chat_completion() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").expect("principal"),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let mut receiver = registry.subscribe("alice".to_owned(), None, identity.request_owner);
    receiver.begin_turn("conversation");
    let mut ingress = bus.subscribe_topic("astrid.v1.request.status.test");
    process_inbound(
        &bus,
        &identity,
        "alice",
        &receiver,
        IpcMessage::new(
            Topic::from_raw("astrid.v1.request.status.test"),
            IpcPayload::RawJson(serde_json::json!({"request": "status"})),
            Uuid::new_v4(),
        ),
    )
    .await
    .expect("management request admitted during chat");
    let event = ingress.recv().await.expect("management ingress");
    let AstridEvent::Ipc { message, .. } = &*event else {
        panic!("IPC ingress")
    };
    assert_eq!(message.request_owner, Some(identity.request_owner));
    bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::from_raw("agent.v1.response"),
            IpcPayload::AgentResponse {
                text: String::new(),
                is_final: true,
                session_id: "conversation".to_owned(),
            },
            Uuid::nil(),
        )
        .with_principal("alice")
        .with_request_owner(receiver.turn_owner().expect("turn")),
    });
    receiver.try_recv().expect("chat completes");
    bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::from_raw("astrid.v1.response.status.test"),
            IpcPayload::RawJson(serde_json::json!({"status": "running"})),
            Uuid::nil(),
        )
        .with_principal("alice")
        .with_request_owner(identity.request_owner),
    });
    receiver
        .try_recv()
        .expect("management reply delivered after chat completes");
}

#[tokio::test]
async fn late_terminal_from_previous_turn_cannot_complete_next_turn() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").expect("principal"),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let mut receiver = registry.subscribe("alice".to_owned(), None, identity.request_owner);
    let mut ingress = bus.subscribe_topic(routing::CHAT_REQUEST_TOPIC);
    let prompt = || {
        IpcMessage::new(
            Topic::from_raw(routing::CHAT_REQUEST_TOPIC),
            IpcPayload::UserInput {
                text: "prompt".to_owned(),
                session_id: "conversation".to_owned(),
                context: None,
            },
            Uuid::new_v4(),
        )
    };
    process_inbound(&bus, &identity, "alice", &receiver, prompt())
        .await
        .expect("first turn");
    let first = ingress.recv().await.expect("first ingress");
    let AstridEvent::Ipc { message: first, .. } = &*first else {
        panic!("IPC ingress");
    };
    let terminal = IpcMessage::new(
        Topic::from_raw("agent.v1.response"),
        IpcPayload::AgentResponse {
            text: "old response".to_owned(),
            is_final: true,
            session_id: "conversation".to_owned(),
        },
        Uuid::new_v4(),
    )
    .with_principal("alice")
    .with_request_owner(first.request_owner.expect("stamped owner"));
    let publish = |message| {
        bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message,
        })
    };
    publish(terminal.clone());
    receiver.try_recv().expect("first terminal delivered");
    process_inbound(&bus, &identity, "alice", &receiver, prompt())
        .await
        .expect("next turn");
    ingress.recv().await.expect("next ingress");

    // The old producer (or a delayed retry) must not gain authority over the
    // next request just because both requests share a conversation and socket.
    publish(terminal);
    assert_eq!(receiver.session().as_deref(), Some("conversation"));
    assert!(
        matches!(receiver.try_recv(), Err(egress::TryRecvError::Empty)),
        "late terminal must not be delivered to the new turn"
    );
}
mod cancellation;

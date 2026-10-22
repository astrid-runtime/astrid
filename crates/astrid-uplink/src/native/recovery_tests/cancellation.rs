use super::*;

#[tokio::test]
async fn repeated_cancel_does_not_acknowledge_an_unretired_turn_twice() {
    let bus = Arc::new(EventBus::new());
    let registry = egress::Registry::install(&bus);
    let identity = AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: None,
        request_owner: RequestOwnerId::generate(),
    };
    let mut receiver = registry.subscribe("alice".into(), None, identity.request_owner);
    let prompt = |cancel: bool| {
        IpcMessage::new(
            Topic::user_prompt(),
            IpcPayload::UserInput {
                text: "prompt".into(),
                session_id: "conversation".into(),
                context: cancel.then(|| serde_json::json!({"action":"cancel_turn"})),
            },
            Uuid::nil(),
        )
    };
    process_inbound(&bus, &identity, "alice", &receiver, prompt(false))
        .await
        .unwrap();
    let retired = receiver.turn_owner().unwrap();
    let capacity = Arc::new(tokio::sync::Semaphore::new(0));
    let admitter: Arc<dyn astrid_events::EventDeliveryAdmitter> =
        Arc::new(BlockedDelivery(capacity.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    let mut pending = Some(PendingInput::new(&bus, &identity, &receiver, prompt(false)));
    let mut control = None;
    let mut cancellation = Some(PendingInput::new(&bus, &identity, &receiver, prompt(true)));
    let (server, client) = LocalStream::pair().unwrap();
    let (_, mut writer) = local_transport::split(server);
    let (reader, _) = local_transport::split(client);
    let mut reader = FramedReader::new(reader);
    handle_connection_input(
        &mut writer,
        &bus,
        &identity,
        &receiver,
        None,
        prompt(true),
        (&mut pending, &mut control, &mut cancellation),
    )
    .await
    .unwrap();
    assert!(
        pending.is_none(),
        "repeated cancel discards the queued unstarted prompt"
    );
    assert!(
        cancellation.is_some(),
        "original cancellation owns retirement"
    );
    assert_eq!(receiver.turn_owner(), Some(retired));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), reader.read_message())
            .await
            .is_err(),
        "no private early acknowledgment before original retirement"
    );
    tokio::time::timeout(
        CANCEL_FORWARD_TIMEOUT + std::time::Duration::from_secs(1),
        wait_pending(&mut cancellation),
    )
    .await
    .unwrap()
    .unwrap();
    drop(cancellation);
    drop(pending);
    drop(control);
    let terminal = receiver.try_recv().expect("one cancellation terminal");
    assert!(
        matches!(&*terminal, AstridEvent::Ipc { message, .. } if message.request_owner == Some(retired))
    );
    assert!(matches!(
        receiver.try_recv(),
        Err(egress::TryRecvError::Empty)
    ));
    capacity.add_permits(1);
    process_inbound(&bus, &identity, "alice", &receiver, prompt(false))
        .await
        .unwrap();
    assert_ne!(receiver.turn_owner(), Some(retired));
}

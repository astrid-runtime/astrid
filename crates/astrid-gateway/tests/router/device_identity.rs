use super::*;

#[tokio::test]
async fn pair_redeem_mints_the_registration_returned_by_the_kernel() {
    use astrid_core::kernel_api::{
        AdminKernelResponse, AdminRequestKind, AdminResponseBody, PairTokenRedeemed,
    };
    use astrid_events::{
        AstridEvent, EventBus, EventMetadata,
        ipc::{IpcMessage, IpcPayload},
    };
    use astrid_uplink::{request_topic, response_topic};

    let mut state = fresh_state_with_distro(None);
    let bus = Arc::new(EventBus::new());
    let kernel = uuid::Uuid::new_v4();
    let config = Arc::get_mut(&mut state).unwrap();
    config.session_id = Some(SessionId(kernel));
    config.event_bus = Some(bus.clone());
    let principal = PrincipalId::new("registered").unwrap();
    let registration = uuid::Uuid::new_v4().to_string().parse().unwrap();
    let kind = AdminRequestKind::PairDeviceRedeem {
        token: "token".into(),
        public_key: "pubkey".into(),
    };
    let mut requests = bus.subscribe_topic(request_topic(&kind).as_str());
    let reply = PairTokenRedeemed {
        principal: principal.clone(),
        public_key_fingerprint: "fingerprint".into(),
        key_id: "0123456789abcdef".into(),
        registration_id: Some(registration),
    };
    let kernel_task = tokio::spawn(async move {
        let event = requests.recv().await.unwrap();
        let AstridEvent::Ipc { message, .. } = &*event else {
            panic!("expected kernel request")
        };
        let IpcPayload::RawJson(body) = &message.payload else {
            panic!("expected admin request")
        };
        let response = AdminKernelResponse::for_request(
            Some(body["request_id"].as_str().unwrap().to_owned()),
            AdminResponseBody::PairTokenRedeemed(reply),
        );
        bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test::kernel"),
            message: IpcMessage::new(
                response_topic(&kind),
                IpcPayload::RawJson(serde_json::to_value(response).unwrap()),
                kernel,
            ),
        });
    });
    let req = Request::post("/api/auth/pair-device/redeem")
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            4000,
        ))))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"token":"token","public_key":"pubkey"}"#))
        .unwrap();
    let resp = routes::build(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    kernel_task.await.unwrap();
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let caller = verify_bearer(&state, json["session_token"].as_str().unwrap()).unwrap();
    assert_eq!(caller.registration_id, Some(registration));
    assert_eq!(caller.principal, principal);
    assert_eq!(caller.device_key_id.as_deref(), Some("0123456789abcdef"));
}

#[tokio::test]
async fn prompt_publishes_the_verified_bearer_identity() {
    let mut state = fresh_state_with_distro(None);
    let bus = Arc::new(astrid_events::EventBus::new());
    Arc::get_mut(&mut state).unwrap().event_bus = Some(bus.clone());
    let mut prompts = bus.subscribe_topic(astrid_events::ipc::Topic::user_prompt().as_str());
    let principal = PrincipalId::new("prompt-owner").unwrap();
    let bearer = mint_bearer_scoped(&state.signing.signer, &principal, "0123456789abcdef", 600);
    let caller = verify_bearer(&state, &bearer).unwrap();
    let response = routes::build(state)
        .oneshot(
            Request::post("/api/agent/prompt")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"text":"hello"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let event = tokio::time::timeout(std::time::Duration::from_secs(2), prompts.recv())
        .await
        .unwrap()
        .unwrap();
    let astrid_events::AstridEvent::Ipc { message, .. } = &*event else {
        panic!("expected prompt")
    };
    assert_eq!(message.principal.as_deref(), Some(principal.as_str()));
    assert_eq!(message.device_key_id, caller.device_key_id);
    assert_eq!(message.request_owner, Some(caller.request_owner));
    assert_eq!(
        message.origin,
        astrid_events::ipc::MessageOrigin::RemoteGateway
    );
}

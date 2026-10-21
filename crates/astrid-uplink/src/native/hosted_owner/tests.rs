use super::*;
use astrid_core::kernel_api::hosted_owner::HostedEnrollmentPhase;
use astrid_types::ipc::RequestOwnerId;
use std::sync::Mutex;

#[derive(Default)]
struct Recorder(Mutex<Vec<(PrincipalId, String)>>);
#[async_trait::async_trait]
impl HostedOwnerResponder for Recorder {
    async fn respond(
        &self,
        principal: &PrincipalId,
        device: &str,
        _request: HostedOwnerRequest,
    ) -> Result<HostedOwnerResponse, &'static str> {
        self.0
            .lock()
            .unwrap()
            .push((principal.clone(), device.to_owned()));
        Ok(HostedOwnerResponse::Inspected {
            enrollment: HostedEnrollmentPhase::Unenrolled,
            policy: None,
            installation: None,
            completion: None,
        })
    }
}
fn identity(verified: bool) -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: verified.then(|| "actual-device".into()),
        request_owner: RequestOwnerId::generate(),
    }
}
fn request(value: serde_json::Value) -> IpcMessage {
    IpcMessage::new(
        Topic::from_raw(REQUEST_TOPIC),
        IpcPayload::RawJson(value),
        uuid::Uuid::new_v4(),
    )
    .with_principal("forged")
    .with_device_key_id("forged")
}

#[tokio::test]
async fn direct_control_uses_only_authenticated_connection_facts() {
    let recorder = Arc::new(Recorder::default());
    let handler: Arc<dyn HostedOwnerResponder> = recorder.clone();
    let result = respond(
        &identity(true),
        Some(&handler),
        request(serde_json::json!({"operation":"inspect"})),
    )
    .await;
    assert_eq!(result.topic.as_str(), RESPONSE_TOPIC);
    assert_eq!(result.principal.as_deref(), Some("alice"));
    assert_eq!(
        recorder.0.lock().unwrap().as_slice(),
        &[(PrincipalId::new("alice").unwrap(), "actual-device".into())]
    );
}

#[tokio::test]
async fn unverified_missing_and_malformed_controls_never_reach_handler() {
    let recorder = Arc::new(Recorder::default());
    let handler: Arc<dyn HostedOwnerResponder> = recorder.clone();
    for (verified, available, value) in [
        (false, true, serde_json::json!({"operation":"inspect"})),
        (true, false, serde_json::json!({"operation":"inspect"})),
        (
            true,
            true,
            serde_json::json!({"operation":"configure","deployment_key":"forged"}),
        ),
        (
            true,
            true,
            serde_json::json!({"operation":"inspect","principal":"forged"}),
        ),
    ] {
        let response = respond(
            &identity(verified),
            available.then_some(&handler),
            request(value),
        )
        .await;
        let IpcPayload::RawJson(body) = response.payload else {
            panic!("wrong payload");
        };
        assert!(body.get("error").is_some());
    }
    assert!(recorder.0.lock().unwrap().is_empty());
}

#[test]
fn neither_request_nor_response_is_a_guest_bus_route() {
    // Ingress interception is the sole path. Egress refusal also prevents a
    // capsule from forging an enrollment-success response on the bus.
    for topic in [REQUEST_TOPIC, RESPONSE_TOPIC] {
        assert!(!super::super::routing::ingress_allowed(topic));
        assert!(!super::super::routing::egress_allowed(topic));
    }
}

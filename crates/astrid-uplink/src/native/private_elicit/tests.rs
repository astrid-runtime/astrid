use std::sync::Mutex;

use super::*;

type RecordedReply = (
    PrincipalId,
    String,
    Uuid,
    Option<String>,
    Option<Vec<String>>,
);

#[derive(Default)]
struct Recorder(Mutex<Vec<RecordedReply>>);

impl PrivateElicitResponder for Recorder {
    fn reply(
        &self,
        principal: &PrincipalId,
        device: &str,
        id: Uuid,
        value: Option<String>,
        values: Option<Vec<String>>,
    ) -> Result<(), PrivateElicitRejection> {
        self.0
            .lock()
            .unwrap()
            .push((principal.clone(), device.into(), id, value, values));
        Ok(())
    }
}

fn identity(verified: bool) -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        principal: PrincipalId::new("alice").unwrap(),
        device_key_id: verified.then(|| "verified-device".into()),
    }
}

fn message(id: Uuid, value: Option<&str>, values: Option<Vec<String>>) -> IpcMessage {
    IpcMessage::new(
        Topic::from_raw(REPLY_TOPIC),
        IpcPayload::ElicitResponse {
            request_id: id,
            value: value.map(str::to_owned),
            values,
        },
        Uuid::new_v4(),
    )
    .with_principal("forged")
    .with_device_key_id("forged")
}

fn status(response: &IpcMessage) -> &str {
    let IpcPayload::RawJson(value) = &response.payload else {
        panic!("expected result")
    };
    value["status"].as_str().unwrap()
}

#[test]
fn uses_verified_identity_and_never_echoes_secret() {
    let handler = Recorder::default();
    let id = Uuid::new_v4();
    let response = respond(
        &identity(true),
        Some(&handler),
        message(id, Some("synthetic-secret"), None),
    );
    assert_eq!(status(&response), "delivered");
    assert!(!format!("{response:?}").contains("synthetic-secret"));
    let calls = handler.0.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0.as_str(), "alice");
    assert_eq!(calls[0].1, "verified-device");
    assert_eq!(calls[0].2, id);
    assert_eq!(calls[0].3.as_deref(), Some("synthetic-secret"));
}

#[test]
fn missing_handler_and_unverified_identity_fail_closed() {
    let handler = Recorder::default();
    let id = Uuid::new_v4();
    assert_eq!(
        status(&respond(
            &identity(true),
            None,
            message(id, Some("s"), None)
        )),
        "unavailable"
    );
    assert_eq!(
        status(&respond(
            &identity(false),
            Some(&handler),
            message(id, Some("s"), None)
        )),
        "forbidden"
    );
    assert!(handler.0.lock().unwrap().is_empty());
}

#[test]
fn empty_text_and_list_are_delivered_both_present_is_invalid() {
    let handler = Recorder::default();
    let id = Uuid::new_v4();
    assert_eq!(
        status(&respond(
            &identity(true),
            Some(&handler),
            message(id, Some("s"), Some(vec!["x".into()]))
        )),
        "invalid"
    );
    assert!(handler.0.lock().unwrap().is_empty());
    assert_eq!(
        status(&respond(
            &identity(true),
            Some(&handler),
            message(id, Some(""), None)
        )),
        "delivered"
    );
    assert_eq!(
        status(&respond(
            &identity(true),
            Some(&handler),
            message(id, None, Some(Vec::new()))
        )),
        "delivered"
    );
    assert_eq!(
        status(&respond(
            &identity(true),
            Some(&handler),
            message(id, None, None)
        )),
        "delivered"
    );
    let calls = handler.0.lock().unwrap();
    assert_eq!(calls[0].3.as_deref(), Some(""));
    assert_eq!(calls[0].4, None);
    assert_eq!(calls[1].3, None);
    assert_eq!(calls[1].4.as_deref(), Some(&[] as &[String]));
    assert_eq!(calls[2].3, None);
    assert_eq!(calls[2].4, None);
}

#[test]
fn private_topics_are_not_bus_ingress_or_egress() {
    assert!(!super::super::routing::ingress_allowed(REPLY_TOPIC));
    assert!(!super::super::routing::egress_allowed(REPLY_TOPIC));
    assert!(!super::super::routing::ingress_allowed(
        "astrid.v1.private.elicit.result"
    ));
    assert!(!super::super::routing::egress_allowed(
        "astrid.v1.private.elicit.result"
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn real_socket_rejects_token_only_secret_without_bus_publication() {
    use crate::native::NativeUplink;
    use crate::socket_client::{SocketClient, perform_handshake_in_home};
    use astrid_core::{SessionId, dirs::AstridHome, local_transport, session_token::SessionToken};
    use astrid_events::EventBus;
    use std::sync::Arc;
    use std::time::Duration;

    let temp = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temp.path().join("home"));
    home.ensure().unwrap();
    std::fs::create_dir_all(home.run_dir()).unwrap();
    let token = Arc::new(SessionToken::generate());
    token.write_to_file(&home.token_path()).unwrap();
    let listener = Arc::new(tokio::sync::Mutex::new(
        local_transport::bind(&home.socket_path()).unwrap(),
    ));
    let bus = Arc::new(EventBus::new());
    let mut observed = bus.subscribe_topic(REPLY_TOPIC);
    let handler = Arc::new(Recorder::default());
    let (shutdown, rx) = tokio::sync::watch::channel(false);
    let server = NativeUplink {
        listener,
        session_token: token,
        home: home.clone(),
        event_bus: Arc::clone(&bus),
        shutdown: rx,
    }
    .spawn_with_private_elicits(handler.clone());
    let principal = PrincipalId::new("default").unwrap();
    let mut stream = local_transport::connect(&home.socket_path()).await.unwrap();
    assert!(
        !perform_handshake_in_home(&mut stream, &principal, &home)
            .await
            .unwrap()
    );
    let mut client =
        SocketClient::from_stream_for_test(stream, SessionId::from_uuid(Uuid::new_v4()), principal);
    client
        .send_message(message(Uuid::new_v4(), Some("socket-sentinel"), None))
        .await
        .unwrap();
    let bytes = tokio::time::timeout(Duration::from_secs(2), client.read_raw_frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(response["payload"]["status"], "forbidden");
    assert!(!String::from_utf8_lossy(&bytes).contains("socket-sentinel"));
    assert!(handler.0.lock().unwrap().is_empty());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), observed.recv())
            .await
            .is_err()
    );
    shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}

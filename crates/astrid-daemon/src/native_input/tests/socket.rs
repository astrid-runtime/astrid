use super::*;
use astrid_capsule::profile_cache::PrincipalProfileCache;
use astrid_core::PrincipalProfile;
use astrid_core::dirs::AstridHome;
use astrid_core::local_transport::{self, LocalStream};
use astrid_core::profile::{AuthMethod, DeviceKey, DeviceScope};
use astrid_core::session_token::{
    HandshakeRequest, HandshakeResponse, PROTOCOL_VERSION, SessionToken,
    principal_auth_challenge_message,
};
use astrid_crypto::KeyPair;
use astrid_events::EventBus;
use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload};
use astrid_uplink::native::{NativeUplink, private_elicit::REPLY_TOPIC};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct SignedNative {
    _temp: tempfile::TempDir,
    home: AstridHome,
    identity: astrid_capsule::elicitation::SecretElicitIdentity,
    key: KeyPair,
    device: DeviceKey,
    cache: Arc<PrincipalProfileCache>,
}

fn write_profile(home: &AstridHome, principal: &PrincipalId, device: &DeviceKey, enabled: bool) {
    let mut profile = PrincipalProfile {
        enabled,
        ..PrincipalProfile::default()
    };
    profile.auth.public_keys.push(device.clone());
    profile.auth.methods.push(AuthMethod::Keypair);
    let path = PrincipalProfile::path_for(home, principal);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    profile.save_to_path(&path).unwrap();
}

fn signed_native() -> SignedNative {
    let temp = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temp.path().join("home"));
    home.ensure().unwrap();
    std::fs::create_dir_all(home.run_dir()).unwrap();
    let identity = owner("alice");
    let key = KeyPair::generate();
    let device = DeviceKey::new(key.export_public_key().to_hex(), DeviceScope::Full, None, 0);
    write_profile(&home, identity.principal(), &device, true);
    let cache = Arc::new(PrincipalProfileCache::with_home(home.clone()));
    SignedNative {
        _temp: temp,
        home,
        identity,
        key,
        device,
        cache,
    }
}

fn live_handler(
    registry: Arc<PendingSecretElicits>,
    native: &SignedNative,
) -> NativeSecretResponder {
    let cache = Arc::clone(&native.cache);
    NativeSecretResponder::with_registration_check(
        registry,
        native.identity.principal().clone(),
        native.device.key_id.clone(),
        move |principal, key, registration| {
            astrid_kernel::native_input_registration_is_live(&cache, principal, key, registration)
        },
    )
    .unwrap()
}

fn secret_frame(request_id: Uuid) -> Vec<u8> {
    serde_json::to_vec(
        &IpcMessage::new(
            Topic::from_raw(REPLY_TOPIC),
            IpcPayload::ElicitResponse {
                request_id,
                value: Some("private-socket-sentinel".into()),
                values: None,
            },
            Uuid::new_v4(),
        )
        .with_principal("forged")
        .with_device_key_id("forged"),
    )
    .unwrap()
}

async fn exchange(stream: &mut LocalStream, bytes: &[u8]) -> Vec<u8> {
    stream
        .write_u32(u32::try_from(bytes.len()).unwrap())
        .await
        .unwrap();
    stream.write_all(bytes).await.unwrap();
    stream.flush().await.unwrap();
    read_frame(stream).await
}

async fn read_frame(stream: &mut LocalStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let len = stream.read_u32().await.unwrap();
        assert!(len < 64 * 1024, "unexpected test response size");
        let mut body = vec![0; len as usize];
        stream.read_exact(&mut body).await.unwrap();
        body
    })
    .await
    .unwrap()
}

async fn authenticate(stream: &mut LocalStream, token: &SessionToken, key: &KeyPair) {
    let mut request = HandshakeRequest {
        token: token.to_hex(),
        protocol_version: PROTOCOL_VERSION,
        client_version: "native-input-test".into(),
        claimed_principal: Some("alice".into()),
        signature: None,
    };
    let first = exchange(stream, &serde_json::to_vec(&request).unwrap()).await;
    let challenge: HandshakeResponse = serde_json::from_slice(&first).unwrap();
    let signed = principal_auth_challenge_message("alice", &challenge.challenge.unwrap());
    request.signature = Some(key.sign(signed.as_bytes()).to_hex());
    let second = exchange(stream, &serde_json::to_vec(&request).unwrap()).await;
    assert!(
        serde_json::from_slice::<HandshakeResponse>(&second)
            .unwrap()
            .is_ok()
    );
}

fn spawn_private(
    native: &SignedNative,
    handler: NativeSecretResponder,
) -> (
    tokio::task::JoinHandle<()>,
    Arc<SessionToken>,
    tokio::sync::watch::Sender<bool>,
    Arc<EventBus>,
) {
    let token = Arc::new(SessionToken::generate());
    let bus = Arc::new(EventBus::new());
    let (shutdown, rx) = tokio::sync::watch::channel(false);
    let server = NativeUplink {
        listener: Arc::new(tokio::sync::Mutex::new(
            local_transport::bind(&native.home.socket_path()).unwrap(),
        )),
        session_token: token.clone(),
        home: native.home.clone(),
        event_bus: bus.clone(),
        shutdown: rx,
    }
    .spawn_with_private_elicits(Arc::new(handler));
    (server, token, shutdown, bus)
}

#[tokio::test]
async fn signed_socket_writer_delivers_to_the_addressed_registration() {
    let native = signed_native();
    let registry = Arc::new(PendingSecretElicits::new(NonZeroUsize::new(1).unwrap()));
    let (server, token, shutdown, bus) = spawn_private(&native, live_handler(registry, &native));
    let mut connected = bus.subscribe_topic(Topic::client_connect().as_str());
    let mut original = connect_signed(&native, &token).await;
    tokio::time::timeout(Duration::from_secs(2), connected.recv())
        .await
        .unwrap()
        .unwrap();
    let replacement = DeviceKey::new(
        native.key.export_public_key().to_hex(),
        DeviceScope::Full,
        None,
        0,
    );
    assert_ne!(native.device.registration_id, replacement.registration_id);
    write_profile(
        &native.home,
        native.identity.principal(),
        &replacement,
        true,
    );
    let mut current = connect_signed(&native, &token).await;
    tokio::time::timeout(Duration::from_secs(2), connected.recv())
        .await
        .unwrap()
        .unwrap();

    let topic = Topic::admin_response("status");
    for (label, device) in [
        ("original", Some(&native.device)),
        ("current", Some(&replacement)),
        ("both", None),
    ] {
        let mut message = IpcMessage::new(
            topic.clone(),
            IpcPayload::RawJson(serde_json::json!({"label":label})),
            Uuid::nil(),
        )
        .with_principal("alice");
        if let Some(device) = device {
            message.device_key_id = Some(device.key_id.clone());
            message.device_registration_id = device.registration_id.map(Into::into);
        }
        bus.publish(astrid_events::AstridEvent::Ipc {
            metadata: astrid_events::EventMetadata::new("kernel_router"),
            message,
        });
    }
    for (socket, expected) in [(&mut original, "original"), (&mut current, "current")] {
        for label in [expected, "both"] {
            let frame: serde_json::Value =
                serde_json::from_slice(&read_frame(socket).await).unwrap();
            assert_eq!(
                frame,
                serde_json::json!({"topic":topic, "payload":{"label":label}, "source_id":Uuid::nil(), "principal":"alice"})
            );
        }
    }
    shutdown.send_replace(true);
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn device_retirement_drains_the_signed_native_socket() {
    let native = signed_native();
    let token = Arc::new(SessionToken::generate());
    let (shutdown, rx) = tokio::sync::watch::channel(false);
    let sessions = astrid_core::profile::device_sessions::DeviceSessions::default();
    let bus = Arc::new(EventBus::new());
    let mut connected = bus.subscribe_topic(Topic::client_connect().as_str());
    let mut disconnected = bus.subscribe_topic(Topic::client_disconnect().as_str());
    let server = NativeUplink {
        listener: Arc::new(tokio::sync::Mutex::new(
            local_transport::bind(&native.home.socket_path()).unwrap(),
        )),
        session_token: token.clone(),
        home: native.home.clone(),
        event_bus: bus,
        shutdown: rx,
    }
    .spawn_with_device_sessions(
        astrid_core::kernel_api::CapsuleTopicProbe::new(|_| Box::pin(async { false })),
        None,
        sessions.clone(),
    );
    let mut socket = connect_signed(&native, &token).await;
    let key = astrid_core::profile::DeviceKeyId::new(native.device.key_id.clone()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        connected.recv().await.unwrap();
        sessions
            .retire(native.identity.principal(), &key)
            .await
            .unwrap();
        disconnected.recv().await.unwrap();
        tokio::io::copy(&mut socket, &mut tokio::io::sink())
            .await
            .unwrap();
    })
    .await
    .expect("revocation must release the serving task and close the peer");
    shutdown.send_replace(true);
    server.await.unwrap();
}

async fn connect_signed(native: &SignedNative, token: &SessionToken) -> LocalStream {
    let mut stream = local_transport::connect(&native.home.socket_path())
        .await
        .unwrap();
    authenticate(&mut stream, token, &native.key).await;
    stream
}

fn status(bytes: &[u8]) -> String {
    let ack: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    ack["payload"]["status"].as_str().unwrap().to_owned()
}

fn load_profile(native: &SignedNative) -> PrincipalProfile {
    PrincipalProfile::load_from_path(&PrincipalProfile::path_for(
        &native.home,
        native.identity.principal(),
    ))
    .unwrap()
}

#[tokio::test]
async fn signed_socket_delivers_only_to_private_waiter() {
    let native = signed_native();
    let registry = Arc::new(PendingSecretElicits::new(NonZeroUsize::new(1).unwrap()));
    let waiter = registry.register(native.identity.clone()).unwrap();
    let request_id = waiter.id().as_uuid();
    let (server, token, shutdown, bus) = spawn_private(&native, live_handler(registry, &native));
    let mut observed = bus.subscribe_topic(REPLY_TOPIC);
    let mut stream = connect_signed(&native, &token).await;
    let response = exchange(&mut stream, &secret_frame(request_id)).await;
    assert_eq!(status(&response), "delivered");
    assert!(!String::from_utf8_lossy(&response).contains("private-socket-sentinel"));
    let SecretElicitReply::Provided(value) =
        tokio::time::timeout(Duration::from_secs(2), waiter.recv())
            .await
            .unwrap()
    else {
        panic!("original private waiter did not receive answer");
    };
    assert_eq!(value.expose_as_str(), "private-socket-sentinel");
    let late = exchange(&mut stream, &secret_frame(request_id)).await;
    assert_eq!(status(&late), "unavailable");
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

async fn pending_socket_after_profile_change(mutate: impl FnOnce(&mut PrincipalProfile)) {
    let native = signed_native();
    let registry = Arc::new(PendingSecretElicits::new(NonZeroUsize::new(1).unwrap()));
    let waiter = registry.register(native.identity.clone()).unwrap();
    let request_id = waiter.id().as_uuid();
    let (server, token, shutdown, bus) = spawn_private(&native, live_handler(registry, &native));
    let mut observed = bus.subscribe_topic(REPLY_TOPIC);
    let mut stream = connect_signed(&native, &token).await;
    let mut profile = load_profile(&native);
    mutate(&mut profile);
    profile
        .save_to_path(&PrincipalProfile::path_for(
            &native.home,
            native.identity.principal(),
        ))
        .unwrap();
    native.cache.invalidate(native.identity.principal());
    let response = exchange(&mut stream, &secret_frame(request_id)).await;
    assert_eq!(status(&response), "forbidden");
    assert!(!String::from_utf8_lossy(&response).contains("private-socket-sentinel"));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), waiter.recv())
            .await
            .is_err(),
        "pending secret must not be delivered after revoke or disable"
    );
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

#[tokio::test]
async fn revoked_device_cannot_answer_pending_secret_on_existing_socket() {
    pending_socket_after_profile_change(|profile| {
        profile.auth.public_keys.clear();
        profile
            .auth
            .methods
            .retain(|method| *method != AuthMethod::Keypair);
    })
    .await;
}

#[tokio::test]
async fn disabled_principal_cannot_answer_pending_secret_on_existing_socket() {
    pending_socket_after_profile_change(|profile| {
        profile.enabled = false;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_private_reply_requires_the_original_pairing_of_the_key() {
    pending_socket_after_profile_change(|profile| {
        let previous = profile.auth.public_keys.pop().unwrap();
        let replacement = DeviceKey::new(previous.pubkey, DeviceScope::Full, None, 0);
        assert_eq!(replacement.key_id, previous.key_id);
        assert_ne!(replacement.registration_id, previous.registration_id);
        profile.add_device(replacement);
    })
    .await;
}

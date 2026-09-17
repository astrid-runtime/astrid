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
    NativeSecretResponder::new(
        registry,
        native.identity.principal().clone(),
        native.device.key_id.clone(),
        {
            let cache = Arc::clone(&native.cache);
            move |principal, device| {
                astrid_kernel::native_input_device_is_live(&cache, principal, device)
            }
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
    astrid_events::EventReceiver,
) {
    let token = Arc::new(SessionToken::generate());
    let bus = Arc::new(EventBus::new());
    let observed = bus.subscribe_topic(REPLY_TOPIC);
    let (shutdown, rx) = tokio::sync::watch::channel(false);
    let server = NativeUplink {
        listener: Arc::new(tokio::sync::Mutex::new(
            local_transport::bind(&native.home.socket_path()).unwrap(),
        )),
        session_token: token.clone(),
        home: native.home.clone(),
        event_bus: bus,
        shutdown: rx,
    }
    .spawn_with_private_elicits(Arc::new(handler));
    (server, token, shutdown, observed)
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
    let (server, token, shutdown, mut observed) =
        spawn_private(&native, live_handler(registry, &native));
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
    let (server, token, shutdown, mut observed) =
        spawn_private(&native, live_handler(registry, &native));
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

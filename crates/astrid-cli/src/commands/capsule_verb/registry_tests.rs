//! Cold command discovery keeps waiting through management keepalives.

use super::*;
use tokio::io::AsyncReadExt as _;

fn wait_client_pair() -> (SocketClient, tokio::net::UnixStream) {
    let (client, peer) = tokio::net::UnixStream::pair().unwrap();
    (
        SocketClient::from_stream_for_test(
            client,
            astrid_core::SessionId::new(),
            astrid_core::PrincipalId::new("alice").unwrap(),
        ),
        peer,
    )
}

async fn send_wait_frame(peer: &mut tokio::net::UnixStream, value: serde_json::Value) {
    use tokio::io::AsyncWriteExt;
    let bytes = serde_json::to_vec(&value).unwrap();
    peer.write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    peer.write_all(&bytes).await.unwrap();
}

#[tokio::test]
async fn cold_registry_keepalives_preserve_correlated_commands_without_replay() {
    use astrid_core::kernel_api::KernelResponse;
    let (socket, mut peer) = wait_client_pair();
    let mut client = astrid_uplink::KernelClient::from_socket_for_test(
        socket,
        astrid_core::PrincipalId::new("alice").unwrap(),
        Duration::from_secs(15),
    );
    let waiting = tokio::spawn(async move { fetch_commands(&mut client).await });
    let size = peer.read_u32().await.unwrap();
    let mut bytes = vec![0; usize::try_from(size).unwrap()];
    peer.read_exact(&mut bytes).await.unwrap();
    let request: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(request["principal"], "alice");
    let topic = request["topic"].as_str().unwrap();
    let correlation = topic
        .strip_prefix("astrid.v1.request.get_commands.")
        .unwrap();
    assert_eq!(correlation.len(), 32);
    assert!(Uuid::parse_str(correlation).is_ok());
    let response_topic = format!("astrid.v1.response.get_commands.{correlation}");
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        send_wait_frame(
            &mut peer,
            serde_json::json!({
                "topic": response_topic,
                "payload": serde_json::to_value(KernelResponse::Working).unwrap()
            }),
        )
        .await;
        // The local socket uses real I/O readiness; keep wall time here rather
        // than letting paused Tokio time outrun the OS readiness notification.
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }
        assert!(
            !waiting.is_finished(),
            "Working must not terminate discovery"
        );
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let commands = vec![CommandInfo {
        name: "realm".into(),
        description: "Retained Realm".into(),
        provider_capsule: "aos-linux-realm".into(),
        kind: CommandKind::Cli,
    }];
    send_wait_frame(
        &mut peer,
        serde_json::json!({
            "topic": response_topic,
            "payload": serde_json::to_value(KernelResponse::Commands(commands)).unwrap()
        }),
    )
    .await;
    let commands = waiting.await.unwrap().unwrap();
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].provider_capsule, "aos-linux-realm");
    assert_eq!(
        peer.read(&mut [0; 1]).await.unwrap(),
        0,
        "discovery must send one request and no command or retry"
    );
}

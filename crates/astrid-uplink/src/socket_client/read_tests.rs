//! Framed response waits on an owned socket pair, without a live daemon.

use super::*;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

fn client_pair() -> (SocketClient, tokio::net::UnixStream) {
    let (client, peer) = tokio::net::UnixStream::pair().unwrap();
    let (read_half, write_half) = local_transport::split(client);
    (
        SocketClient {
            read_half,
            write_half,
            session_id: SessionId::new(),
            principal: PrincipalId::new("alice").unwrap(),
            authenticated: true,
        },
        peer,
    )
}

async fn frame(peer: &mut tokio::net::UnixStream, value: serde_json::Value) {
    let bytes = serde_json::to_vec(&value).unwrap();
    peer.write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    peer.write_all(&bytes).await.unwrap();
}

#[tokio::test]
async fn matched_terminal_frame_leaves_connection_usable() {
    let (mut client, mut peer) = client_pair();
    frame(&mut peer, serde_json::json!({"topic":"stale"})).await;
    frame(
        &mut peer,
        serde_json::json!({"topic":"failure", "trusted":false}),
    )
    .await;
    frame(
        &mut peer,
        serde_json::json!({"topic":"failure", "trusted":true}),
    )
    .await;
    frame(&mut peer, serde_json::json!({"topic":"healthy"})).await;
    let result = client
        .read_until_matching_typed(Duration::from_secs(1), |raw| {
            raw["topic"] == "failure" && raw["trusted"] == true
        })
        .await
        .unwrap();
    assert_eq!(result["trusted"], true);
    let healthy = client
        .read_until_topic_typed("healthy", Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(healthy["topic"], "healthy");
}

#[tokio::test]
async fn unrelated_frames_do_not_reset_the_response_deadline() {
    let (mut client, mut peer) = client_pair();
    let writer = tokio::spawn(async move {
        loop {
            let bytes = b"{}";
            if peer.write_all(&2_u32.to_be_bytes()).await.is_err()
                || peer.write_all(bytes).await.is_err()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        client.read_until_matching_typed(Duration::from_millis(30), |_| false),
    )
    .await;
    writer.abort();
    let _ = writer.await;
    assert!(matches!(result, Ok(Err(ReadError::Timeout))));
}

#[tokio::test]
async fn tool_call_frame_preserves_the_stamped_principal_and_request() {
    let (mut client, mut peer) = client_pair();
    let message = IpcMessage::new(
        Topic::from_raw("astrid.v1.request.mcp.tool.call"),
        IpcPayload::RawJson(serde_json::json!({
            "req_id": "first", "name": "capsule.read", "arguments": {"path": "report"}
        })),
        uuid::Uuid::nil(),
    );
    let expected = serde_json::to_vec(&message.clone().with_principal("alice")).unwrap();
    client.send_message(message).await.unwrap();
    let size = peer.read_u32().await.unwrap();
    assert_eq!(usize::try_from(size).unwrap(), expected.len());
    let mut body = vec![0; expected.len()];
    peer.read_exact(&mut body).await.unwrap();
    assert_eq!(body, expected);
}

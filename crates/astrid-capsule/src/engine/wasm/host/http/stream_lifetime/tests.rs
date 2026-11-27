use super::*;
use crate::engine::wasm::test_fixtures::minimal_host_state;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn response(state: &HostState) -> Arc<OpenResponse> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 2048];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nsame")
            .await
            .unwrap();
    });
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{endpoint}/"))
        .send()
        .await
        .unwrap();
    peer.await.unwrap();
    Arc::new(OpenResponse {
        response: tokio::sync::Mutex::new(response),
        authority: state.admit_egress_caller().unwrap(),
        status: 200,
        headers: Vec::new(),
        owner_cancel: CancellationToken::new(),
        invocation_cancel: CancellationToken::new(),
    })
}

#[tokio::test]
async fn equal_payloads_on_distinct_responses_cannot_exchange_observations() {
    let state = minimal_host_state(tokio::runtime::Handle::current());
    let first = response(&state).await;
    let second = response(&state).await;
    let timeout = Duration::from_secs(5);
    assert!(second.outcome_of(first.read(timeout).await).is_none());
    let observed = second.read(timeout).await;
    assert_eq!(
        Arc::clone(&second)
            .outcome_of(observed)
            .unwrap()
            .unwrap()
            .unwrap()
            .unwrap()
            .as_ref(),
        b"same"
    );
    let eof = second.read(timeout).await;
    assert!(first.outcome_of(eof).is_none());
}

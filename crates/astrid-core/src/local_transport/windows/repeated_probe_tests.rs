//! Repeated endpoint publication and release proofs.

use super::*;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
async fn repeated_presence_probes_remain_deterministic_until_explicit_release() {
    let endpoint = Path::new(r"C:\ignored\repeated-probes.sock");
    let listener = bind(endpoint).unwrap();
    let mut clients = Vec::new();
    let mut servers = Vec::new();

    for round in 0..4 {
        assert!(
            endpoint_is_present(endpoint).unwrap(),
            "round {round}: published endpoint must remain authoritative"
        );
        let ConnectOutcome::Connected(mut client) = connect_outcome(endpoint).await.unwrap() else {
            panic!("round {round}: published endpoint must connect");
        };
        client.write_all(b"probe").await.unwrap();
        client.flush().await.unwrap();
        let mut server = accept(&listener).await.unwrap();
        assert!(peer_is_current_user(&server).unwrap());
        let mut bytes = [0_u8; 5];
        server.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"probe", "round {round} payload");
        clients.push(client);
        servers.push(server);
    }

    assert!(endpoint_is_present(endpoint).unwrap());
    drop(clients);
    drop(servers);
    drop(listener);
    wait_until_endpoint_is_absent(endpoint).await;
    assert!(!endpoint_is_present(endpoint).unwrap());
    assert!(matches!(
        connect_outcome(endpoint).await.unwrap(),
        ConnectOutcome::Absent
    ));

    let replacement = bind(endpoint).expect("explicit release must allow republication");
    assert!(endpoint_is_present(endpoint).unwrap());
    drop(replacement);
    wait_until_endpoint_is_absent(endpoint).await;
}

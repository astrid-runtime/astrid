use super::*;
use astrid_core::PrincipalId;
use astrid_core::profile::{DeviceKeyId, device_sessions::DeviceSessions};
use tokio::io::AsyncReadExt;

fn connection(
    registry: &DeviceSessions,
    owner: &PrincipalId,
    key: &DeviceKeyId,
) -> (SignedSocket, LocalStream) {
    let session = registry
        .challenge(owner.clone())
        .unwrap()
        .bind(key.clone())
        .unwrap();
    let (server, peer) = LocalStream::pair().unwrap();
    (
        SignedSocket::new(
            server,
            session,
            ConnectionIdentity::new(owner.clone(), Some(key.as_str().to_owned())),
            &tokio::runtime::Handle::current(),
        ),
        peer,
    )
}

#[tokio::test]
async fn captured_frame_outlives_socket_but_not_device_grant() {
    let registry = DeviceSessions::default();
    let owner = PrincipalId::new("alice").unwrap();
    let key = DeviceKeyId::new("1".repeat(16)).unwrap();
    let (socket, mut peer) = connection(&registry, &owner, &key);
    let frame = socket.authority().clone();
    drop(socket);
    assert_eq!(
        peer.read_u8().await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    assert_eq!(frame.run(async { 1 }).await, Some(1));
    registry.retire(&owner, &key).await.unwrap();
    let (_paired_again, _peer) = connection(&registry, &owner, &key);
    assert_eq!(frame.run(async { 1 }).await, None);
}

#[tokio::test]
async fn retirement_drains_pending_io_without_closing_a_sibling() {
    let registry = DeviceSessions::default();
    let owner = PrincipalId::new("alice").unwrap();
    let key = DeviceKeyId::new("1".repeat(16)).unwrap();
    let sibling_key = DeviceKeyId::new("2".repeat(16)).unwrap();
    let (socket, _peer) = connection(&registry, &owner, &key);
    let (sibling, mut peer) = connection(&registry, &owner, &sibling_key);
    let mut read = std::pin::pin!(socket.io(async |stream| stream.read_u8().await));
    tokio::select! {
        biased;
        _ = &mut read => panic!("idle read completed before retirement"),
        () = std::future::ready(()) => {}
    }
    let (read, retired) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(read, registry.retire(&owner, &key))
    })
    .await
    .unwrap();
    assert!(read.is_none());
    retired.unwrap();
    use tokio::io::AsyncWriteExt;
    peer.write_u8(42).await.unwrap();
    assert_eq!(
        sibling.io(async |s| s.read_u8().await.unwrap()).await,
        Some(42)
    );
}

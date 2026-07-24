use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use windows_sys::Win32::Security::WinAnonymousSid;

#[test]
fn endpoint_name_is_sid_derived_not_path_derived() {
    let first = pipe_name(Path::new(r"C:\controlled\one.sock")).unwrap();
    let second = pipe_name(Path::new(r"D:\different\two.sock")).unwrap();
    assert_eq!(first, second);
    assert!(first.to_string_lossy().starts_with(PIPE_PREFIX));
    assert!(!first.to_string_lossy().contains("controlled"));
}

#[test]
fn different_user_identity_is_rejected() {
    let current = current_user_sid().unwrap();
    let anonymous = well_known_sid(WinAnonymousSid).unwrap();
    assert!(!current.equals(&anonymous));
}

#[tokio::test]
async fn native_backend_bind_instances_shutdown_and_reconnect() {
    let endpoint = Path::new(r"C:\ignored\system.sock");
    assert!(!endpoint_is_present(endpoint).unwrap());
    assert!(matches!(
        connect_outcome(endpoint).await.unwrap(),
        ConnectOutcome::Absent
    ));
    assert!(!remove_stale_endpoint(endpoint).unwrap());

    let listener = bind(endpoint).unwrap();
    assert!(endpoint_is_present(endpoint).unwrap());
    assert!(!remove_stale_endpoint(endpoint).unwrap());
    assert!(
        bind(endpoint).is_err(),
        "live pipe name must not be squattable"
    );

    let client_one = connect(endpoint).await.unwrap();
    let (reader_one, mut writer_one) = split(client_one);
    writer_one.write_all(b"first").await.unwrap();
    writer_one.flush().await.unwrap();
    let mut server_one = accept(&listener).await.unwrap();
    assert!(peer_is_current_user(&server_one).unwrap());

    let client_two = connect(endpoint).await.unwrap();
    let (reader_two, mut writer_two) = split(client_two);
    writer_two.write_all(b"second").await.unwrap();
    writer_two.flush().await.unwrap();
    let mut server_two = accept(&listener).await.unwrap();
    assert!(peer_is_current_user(&server_two).unwrap());

    let mut first = [0_u8; 5];
    server_one.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"first");

    let mut second = [0_u8; 6];
    server_two.read_exact(&mut second).await.unwrap();
    assert_eq!(&second, b"second");

    drop(listener);
    drop(server_one);
    drop(server_two);
    drop(reader_one);
    drop(reader_two);
    drop(writer_one);
    drop(writer_two);
    assert!(!endpoint_is_present(endpoint).unwrap());

    let replacement = bind(endpoint).expect("pipe must be reusable after shutdown");
    let mut client = connect(endpoint).await.unwrap();
    client.write_all(b"x").await.unwrap();
    let server = accept(&replacement).await.unwrap();
    drop(client);
    drop(server);
    drop(replacement);
    assert!(!endpoint_is_present(endpoint).unwrap());
}

#[tokio::test]
async fn busy_and_missing_peer_identity_fail_closed() {
    let endpoint = Path::new(r"C:\ignored\system.sock");
    let name = pipe_name(endpoint).unwrap();
    let pending = create_server(&name, true).unwrap();

    let disconnected = LocalStream {
        inner: StreamInner::Server(pending),
        replay_byte: None,
    };
    assert!(
        peer_is_current_user(&disconnected).is_err(),
        "peer identity must not default to a match"
    );

    let pending = match disconnected.inner {
        StreamInner::Server(server) => server,
        StreamInner::Client(_) => unreachable!(),
    };
    let _client = ClientOptions::new().open(&name).unwrap();
    let busy = connect(endpoint).await.unwrap_err();
    assert_eq!(busy.kind(), io::ErrorKind::WouldBlock);
    drop(pending);
}

#[tokio::test]
async fn cancelled_pre_read_preserves_replacement_instance() {
    let endpoint = Path::new(r"C:\ignored\system.sock");
    let listener = std::sync::Arc::new(bind(endpoint).unwrap());

    let timed_out =
        tokio::time::timeout(std::time::Duration::from_millis(25), accept(&listener)).await;
    assert!(
        timed_out.is_err(),
        "first accept must be cancelled by timeout"
    );

    // Connect but send nothing. `accept` must now be blocked in the real
    // authentication pre-read, after it has installed the replacement.
    let idle_client = connect(endpoint).await.unwrap();
    let cancelled_listener = std::sync::Arc::clone(&listener);
    let cancelled = tokio::spawn(async move { accept(&cancelled_listener).await });

    // Reaching a second connected instance proves the cancelled accept
    // advanced past connect and replenished the listener before pre-read.
    let mut client = connect(endpoint)
        .await
        .expect("replacement must exist while the first accept pre-reads");
    client.write_all(b"after-cancel").await.unwrap();
    client.flush().await.unwrap();

    cancelled.abort();
    assert!(
        cancelled.await.unwrap_err().is_cancelled(),
        "outer task abort must cancel the authentication pre-read"
    );
    drop(idle_client);

    let mut server = accept(&listener)
        .await
        .expect("replacement must remain usable after pre-read cancellation");
    let mut bytes = [0_u8; 12];
    server.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"after-cancel");

    drop(client);
    drop(server);
    drop(listener);
    assert!(!endpoint_is_present(endpoint).unwrap());
}

#[tokio::test]
async fn production_probe_then_immediate_connect_waits_for_replacement_instance() {
    let endpoint = Path::new(r"C:\ignored\system.sock");
    let listener = std::sync::Arc::new(bind(endpoint).unwrap());

    let probe = connect_outcome(endpoint).await.unwrap();
    let ConnectOutcome::Connected(probe) = probe else {
        panic!("production probe must connect");
    };
    drop(probe);

    let real_connect = tokio::spawn(async move { connect(endpoint).await });
    tokio::task::yield_now().await;
    assert!(
        !real_connect.is_finished(),
        "the real connect must wait while the probe occupies the only instance"
    );

    let probe_eof = accept(&listener)
        .await
        .expect_err("an EOF-only availability probe must not authenticate");
    assert_eq!(probe_eof.kind(), io::ErrorKind::UnexpectedEof);

    let mut real_client = real_connect
        .await
        .unwrap()
        .expect("busy retry must reach the replacement instance");
    real_client.write_all(b"real").await.unwrap();
    real_client.flush().await.unwrap();
    let mut real_server = accept(&listener)
        .await
        .expect("listener must remain usable after probe EOF");
    let mut bytes = [0_u8; 4];
    real_server.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"real");
}

#[tokio::test]
async fn simultaneous_clients_wait_for_successive_instances() {
    let endpoint = Path::new(r"C:\ignored\system.sock");
    let listener = std::sync::Arc::new(bind(endpoint).unwrap());

    let first = tokio::spawn(async move {
        let mut client = connect(endpoint).await?;
        client.write_all(b"1").await?;
        Ok::<_, io::Error>(client)
    });
    let second = tokio::spawn(async move {
        let mut client = connect(endpoint).await?;
        client.write_all(b"2").await?;
        Ok::<_, io::Error>(client)
    });
    tokio::task::yield_now().await;

    let first_server = accept(&listener).await.unwrap();
    let second_server = accept(&listener).await.unwrap();
    let first_client = first.await.unwrap().expect("first client");
    let second_client = second.await.unwrap().expect("second client");

    assert!(peer_is_current_user(&first_server).unwrap());
    assert!(peer_is_current_user(&second_server).unwrap());
    drop(first_client);
    drop(second_client);
}

#[tokio::test]
async fn cancelled_busy_connect_does_not_poison_endpoint() {
    let endpoint = Path::new(r"C:\ignored\system.sock");
    let listener = std::sync::Arc::new(bind(endpoint).unwrap());
    let name = pipe_name(endpoint).unwrap();
    let mut options = ClientOptions::new();
    options.security_qos_flags(SECURITY_IDENTIFICATION);
    let mut occupying_client = options.open(&name).unwrap();

    let cancelled = tokio::time::timeout(Duration::from_millis(25), connect(endpoint)).await;
    assert!(
        cancelled.is_err(),
        "busy connect must remain cancellable during WaitNamedPipe backoff"
    );

    occupying_client.write_all(b"x").await.unwrap();
    let occupying_server = accept(&listener).await.unwrap();
    drop(occupying_client);
    drop(occupying_server);

    let mut client = connect(endpoint).await.unwrap();
    client.write_all(b"x").await.unwrap();
    let server = accept(&listener).await.unwrap();
    drop(client);
    drop(server);
}

#[tokio::test]
async fn permissive_acl_is_rejected_before_wire_handshake() {
    let endpoint = Path::new(r"C:\ignored\system.sock");
    let name = pipe_name(endpoint).unwrap();
    let permissive = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&name)
        .unwrap();

    let server_task = tokio::spawn(async move {
        permissive.connect().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    });
    let error = connect(endpoint).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    server_task.await.unwrap();
}

#[tokio::test]
async fn exact_aces_without_protected_dacl_are_rejected_before_handshake() {
    let endpoint = Path::new(r"C:\ignored\system.sock");
    let name = pipe_name(endpoint).unwrap();
    let user = current_user_sid().unwrap().to_sddl().unwrap();
    let descriptor =
        PipeSecurity::from_sddl(&format!("O:{user}D:(A;;GA;;;SY)(A;;GA;;;{user})")).unwrap();
    let unprotected = create_server_with_security(&name, true, descriptor).unwrap();

    let server_task = tokio::spawn(async move {
        unprotected.connect().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    });
    let error = connect(endpoint).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    server_task.await.unwrap();
}

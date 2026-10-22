#![cfg(windows)]

use astrid_core::dirs::AstridHome;
use astrid_core::local_transport;
use astrid_core::profile::{AuthMethod, DeviceKey, DeviceScope};
use astrid_core::session_token::SessionToken;
use astrid_core::{PrincipalId, PrincipalProfile};

#[tokio::test]
async fn native_windows_preread_replays_full_signed_handshake() {
    let directory = tempfile::tempdir().expect("tempdir");
    // `tempfile` creates the root before Astrid can attach its exact protected
    // DACL. Use a missing child so the production filesystem boundary creates
    // the test home atomically with the required Windows descriptor.
    let home = AstridHome::from_path(directory.path().join("astrid-home"));
    home.ensure().expect("prepare Astrid home");

    let principal = PrincipalId::new("windows-e2e").expect("valid principal");
    let keypair = astrid_crypto::KeyPair::generate();
    let device = DeviceKey::new(
        keypair.export_public_key().to_hex(),
        DeviceScope::Full,
        None,
        0,
    );
    let expected_key_id = device.key_id.clone();

    let mut profile = PrincipalProfile::default();
    profile.auth.methods.push(AuthMethod::Keypair);
    profile.auth.public_keys.push(device);
    let profile_path = PrincipalProfile::path_for(&home, &principal);
    profile
        .save_to_path(&profile_path)
        .expect("write principal profile");

    let key_path = home.keys_dir().join(format!("{principal}.key"));
    std::fs::create_dir_all(home.keys_dir()).expect("create key directory");
    std::fs::write(&key_path, keypair.secret_key_bytes()).expect("write principal key");

    let token = SessionToken::generate();
    astrid_core::platform_fs::ensure_private_directory(&home.run_dir())
        .expect("create private run directory");
    astrid_core::platform_fs::validate_private_directory(&home.run_dir())
        .expect("run directory must satisfy the private-access contract");
    token
        .write_to_file(&home.token_path())
        .expect("write session token");

    let listener = std::sync::Arc::new(
        local_transport::bind(&home.socket_path()).expect("bind production Windows transport"),
    );
    let server_listener = std::sync::Arc::clone(&listener);
    let server_home = home.clone();
    let server = tokio::spawn(async move {
        let mut stream = local_transport::accept(&server_listener)
            .await
            .expect("accept same-user client");
        astrid_capsule::test_support::validate_local_handshake(&mut stream, &token, &server_home)
            .await
    });

    let mut client = local_transport::connect(&home.socket_path())
        .await
        .expect("connect through production Windows transport");
    let authenticated =
        astrid_uplink::socket_client::perform_handshake_for_test(&mut client, &principal, &home)
            .await
            .expect("production client handshake");
    assert!(authenticated, "client must complete signed-principal path");

    let verified = server
        .await
        .expect("server task")
        .expect("production handshake validator");
    assert_eq!(
        verified,
        Some((principal, expected_key_id)),
        "server must bind the principal and exact registered device key"
    );
    // The first byte of the four-byte frame length was consumed by the
    // transport's effective-token pre-read. Reaching this assertion proves it
    // was replayed exactly and both signed handshake frames remained intact.

    drop(client);
    drop(listener);
    assert!(
        !local_transport::endpoint_is_present(&home.socket_path()).expect("endpoint state"),
        "named-pipe endpoint must disappear after shutdown"
    );
}

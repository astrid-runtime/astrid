//! Drive both WIT accept methods with a process-isolated profile root.

use super::*;
use crate::engine::wasm::bindings::astrid::net::host::{Host, HostUnixListener};
use crate::engine::wasm::test_fixtures::minimal_host_state;
use astrid_core::local_transport;
use std::sync::Arc;

#[test]
fn signed_listeners_close_the_peer_on_retirement() {
    let home = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--ignored")
        .arg("--exact")
        .arg(
            concat!(module_path!(), "::signed_listener_child")
                .split_once("::")
                .unwrap()
                .1,
        )
        .env("ASTRID_HOME", home.path())
        .env("ASTRID_TEST_LISTENER_HOME", home.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "invoked by signed_listeners_close_the_peer_on_retirement with an isolated ASTRID_HOME"]
async fn signed_listener_child() {
    let child_home = std::env::var_os("ASTRID_TEST_LISTENER_HOME").expect("isolated child home");
    let principal = PrincipalId::new("socket-home-test").unwrap();
    let keypair = astrid_crypto::KeyPair::generate();
    let home = AstridHome::resolve().unwrap();
    assert_eq!(home.root(), std::path::Path::new(&child_home));
    let mut profile = astrid_core::PrincipalProfile::default();
    profile.auth.public_keys.push(full_device(&keypair));
    profile
        .auth
        .methods
        .push(astrid_core::profile::AuthMethod::Keypair);
    profile.save(&home, &principal).unwrap();
    let path = home.root().join("cli.sock");
    let listener = local_transport::bind(&path).unwrap();
    let token = Arc::new(token());
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.profile_cache = Some(Arc::new(
        crate::profile_cache::PrincipalProfileCache::with_home(home),
    ));
    state.session_token = Some(token.clone());
    state.cli_socket_listener = Some(Arc::new(tokio::sync::Mutex::new(listener)));

    for poll in [false, true] {
        let slot = state.bind_unix().unwrap();
        let mut client = local_transport::connect(&path).await.unwrap();
        let cancel = state.effective_cancel_token();
        let server = tokio::task::spawn_blocking(move || {
            let stream = if poll {
                state.poll_accept(slot, 1000).unwrap().unwrap()
            } else {
                state.accept(slot).unwrap()
            };
            let identity = crate::engine::wasm::bindings::astrid::request_context::host::Host::connection_principal(&mut state, stream).unwrap();
            (state, identity)
        });
        let guard = cancel.drop_guard();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            sign_challenge(&mut client, token.to_hex(), &principal, &keypair),
        )
        .await
        .unwrap();
        let identity;
        (state, identity) = server.await.unwrap();
        let _ = guard.disarm();
        assert_eq!(identity.as_deref(), Some(principal.as_str()));
        let key = DeviceKeyId::new(full_device(&keypair).key_id).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            state
                .device_sessions
                .retire(&principal, &key)
                .await
                .unwrap();
            assert_eq!(client.read(&mut [0u8; 1]).await.unwrap(), 0);
        })
        .await
        .expect("retirement must close the accepted resource on both listener paths");
    }
}

//! Reopen hosted storage after a child exits immediately after its WIT write acknowledgements.
use std::path::Path;
use std::sync::Arc;

use astrid_core::{PrincipalId, dirs::AstridHome};
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use astrid_storage::{
    IdentityStore, KvIdentityStore, RuntimePrincipalStore, ScopedKvStore, StateOwner,
};

use super::super::{
    PrincipalInvocationTracker, bindings::astrid::kv::host::Host, install_principal_overlays_sync,
    test_fixtures::minimal_host_state,
};
use super::HostState;

const CHILD_HOME: &str = "ASTRID_GUEST_KV_RESTART_TEST_HOME";
const ACKNOWLEDGED: i32 = 73;

async fn open(root: &Path) -> RuntimePrincipalStore {
    astrid_storage::open_runtime_principal_store(
        &AstridHome::from_path(root),
        Arc::new(|_: &StateOwner| Ok(None)),
    )
    .await
    .unwrap()
}

fn guest(store: &RuntimePrincipalStore, alias: &str) -> HostState {
    let caller = PrincipalId::new(alias).unwrap();
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.system_runtime = true;
    state.principal_directory = store.principal_directory();
    state.principal_store = Some(store.clone());
    state.kv_backend = store.kv();
    state.principal_invocations = Some(Arc::new(PrincipalInvocationTracker::default()));
    state.caller_context = Some(
        IpcMessage::new(
            Topic::from_raw("restart.test"),
            IpcPayload::RawJson(serde_json::Value::Null),
            uuid::Uuid::new_v4(),
        )
        .with_principal(caller.to_string()),
    );
    assert!(install_principal_overlays_sync(&mut state, Some(&caller)));
    state
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "internal writer for the hosted guest KV restart regression"]
async fn exit_after_acknowledged_guest_writes() {
    let home = std::env::var_os(CHILD_HOME).unwrap();
    let store = open(Path::new(&home)).await;
    let identities = KvIdentityStore::with_principal_directory(
        ScopedKvStore::new(store.kv(), "system:identity").unwrap(),
        store.principal_directory(),
    );
    for (alias, value) in [
        ("alice", b"alice-value".as_slice()),
        ("bob", b"bob-value".as_slice()),
    ] {
        identities
            .create_principal(
                PrincipalId::new(alias).unwrap(),
                *blake3::hash(alias.as_bytes()).as_bytes(),
            )
            .await
            .unwrap();
        let mut state = guest(&store, alias);
        state
            .kv_set("shared-key".into(), b"initial".to_vec())
            .unwrap();
        state
            .kv_cas(
                "shared-key".into(),
                Some(b"initial".to_vec()),
                value.to_vec(),
            )
            .unwrap();
    }
    // Skip engine shutdown and destructors. The parent knows which operations returned.
    std::process::exit(ACKNOWLEDGED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovered_guest_reads_its_own_acknowledged_value() {
    let root = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "engine::wasm::host_state::kv_restart_tests::exit_after_acknowledged_guest_writes",
        ])
        .env(CHILD_HOME, root.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(ACKNOWLEDGED));
    let store = open(root.path()).await;
    for (alias, value) in [
        ("bob", b"bob-value".as_slice()),
        ("alice", b"alice-value".as_slice()),
    ] {
        assert_eq!(
            guest(&store, alias)
                .kv_get("shared-key".into())
                .unwrap()
                .as_deref(),
            Some(value)
        );
    }
}

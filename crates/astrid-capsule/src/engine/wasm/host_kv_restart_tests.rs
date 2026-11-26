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
const CHILD_WAL: &str = "ASTRID_GUEST_KV_RESTART_TEST_WAL";
const ACKNOWLEDGED: i32 = 73;

async fn open(root: &Path, wal: astrid_storage::TransactionWalPolicy) -> RuntimePrincipalStore {
    astrid_storage::open_runtime_principal_store_with_policy(
        &AstridHome::from_path(root),
        Arc::new(|_: &StateOwner| Ok(None)),
        astrid_storage::PrincipalDirectory::default(),
        astrid_storage::DurableEnginePolicy::default().with_transaction_wal(wal),
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
    let wal = match std::env::var(CHILD_WAL).unwrap().as_str() {
        "enabled" => astrid_storage::TransactionWalPolicy::enabled(std::num::NonZeroU64::MAX),
        "disabled" => astrid_storage::TransactionWalPolicy::disabled(),
        other => panic!("unknown test WAL policy {other}"),
    };
    let store = open(Path::new(&home), wal).await;
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
    check_acknowledged_restart(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovered_guest_reads_its_acknowledged_wal_value() {
    check_acknowledged_restart(true).await;
}

async fn check_acknowledged_restart(with_wal: bool) {
    use astrid_storage::volume::{AstridVolume, HostedFileVolume, VolumeRegion};
    let root = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "engine::wasm::host_state::kv_restart_tests::exit_after_acknowledged_guest_writes",
        ])
        .env(CHILD_HOME, root.path())
        .env(CHILD_WAL, if with_wal { "enabled" } else { "disabled" })
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(ACKNOWLEDGED));
    if with_wal {
        let path = AstridHome::from_path(root.path()).storage_volume_path();
        let volume = HostedFileVolume::open(path).unwrap();
        assert!(
            volume
                .region_len(&VolumeRegion::new("transactions.wal").unwrap())
                .unwrap()
                > 0
        );
    }
    // Reopen with new WAL writes disabled. Existing WAL must still be replayed.
    let store = open(
        root.path(),
        astrid_storage::TransactionWalPolicy::disabled(),
    )
    .await;
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

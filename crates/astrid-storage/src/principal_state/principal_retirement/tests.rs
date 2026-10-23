use std::path::Path;
use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_core::{FleetUid, PrincipalUid};

use crate::principal_state::{StateOwner, open_runtime_principal_store};
use crate::{ContentName, KvQuotaResolver, WorkspaceBranchStore, WorkspaceUid};

#[tokio::test]
async fn true_uid_retirement_removes_all_components_and_former_fleet_bindings() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    let uid = PrincipalUid::from_bytes([4; 32]);
    let peer = PrincipalUid::from_bytes([5; 32]);
    let alias = PrincipalId::new("retired-agent").unwrap();
    store
        .principal_directory()
        .register(alias.clone(), uid)
        .unwrap();
    store
        .principal_directory()
        .register(PrincipalId::new("peer").unwrap(), peer)
        .unwrap();
    store
        .kv()
        .set(
            "retired-agent:capsule:removed",
            "state",
            b"orphan KV".to_vec(),
        )
        .await
        .unwrap();
    store
        .kv()
        .set("peer:capsule:live", "state", b"peer KV".to_vec())
        .await
        .unwrap();
    let name = ContentName::new("private-content").unwrap();
    store
        .content()
        .put(&StateOwner::Principal(uid), &name, b"retired content")
        .unwrap();
    let branches = WorkspaceBranchStore::new(store.content());
    let prefix = ContentName::new("workspace/default").unwrap();
    let fleets = [
        StateOwner::Fleet(FleetUid::from_bytes([1; 32])),
        StateOwner::Fleet(FleetUid::from_bytes([2; 32])),
    ];
    for owner in fleets {
        let receipt = WorkspaceUid::random();
        branches
            .begin_for_uid_at(&owner, uid, receipt, prefix.clone())
            .unwrap();
        branches.promote(&owner, receipt).unwrap();
        branches
            .begin_for_uid_at(&owner, uid, WorkspaceUid::random(), prefix.clone())
            .unwrap();
        branches
            .begin_for_uid_at(&owner, peer, WorkspaceUid::random(), prefix.clone())
            .unwrap();
    }
    store.principal_directory().unregister(&alias, uid);
    let replacement = PrincipalUid::from_bytes([6; 32]);
    store
        .principal_directory()
        .register(alias, replacement)
        .unwrap();
    store
        .kv()
        .set(
            "retired-agent:capsule:live",
            "state",
            b"replacement KV".to_vec(),
        )
        .await
        .unwrap();
    assert!(store.purge_principal_state(uid).unwrap());
    assert!(!store.purge_principal_state(uid).unwrap());
    assert_private_state_absent(&store, uid, &name);
    for owner in fleets {
        assert!(
            branches
                .list_bindings_by_uid(&owner, uid)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            branches.list_bindings_by_uid(&owner, peer).unwrap().len(),
            1
        );
    }
    assert_eq!(
        store.kv().get("peer:capsule:live", "state").await.unwrap(),
        Some(b"peer KV".to_vec())
    );
    assert_eq!(
        store
            .kv()
            .get("retired-agent:capsule:live", "state")
            .await
            .unwrap(),
        Some(b"replacement KV".to_vec())
    );
}

fn assert_private_state_absent(
    store: &crate::principal_state::RuntimePrincipalStore,
    uid: PrincipalUid,
    name: &ContentName,
) {
    assert!(
        store
            .engine
            .root(&StateOwner::Principal(uid))
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .content()
            .read(&StateOwner::Principal(uid), name)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn independent_reader_accepts_true_uid_retired_volume() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    let uid = PrincipalUid::from_bytes([0x41; 32]);
    let peer = PrincipalUid::from_bytes([0x42; 32]);
    let alias = PrincipalId::new("retired-reader").unwrap();
    store
        .principal_directory()
        .register(alias.clone(), uid)
        .unwrap();
    store
        .principal_directory()
        .register(PrincipalId::new("peer-reader").unwrap(), peer)
        .unwrap();
    store
        .kv()
        .set(
            "retired-reader:capsule:removed",
            "state",
            b"retire me".to_vec(),
        )
        .await
        .unwrap();
    store
        .kv()
        .set("peer-reader:capsule:live", "state", b"keep me".to_vec())
        .await
        .unwrap();
    assert!(store.purge_principal_state(uid).unwrap());
    drop(store);

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/runatal_v1_reader.py");
    let output = std::process::Command::new("python3")
        .arg(&script)
        .arg(home.storage_volume_path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "independent reader rejected retired volume: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decoded: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let retired = uid.to_string();
    let peer_name = peer.to_string();
    assert!(
        decoded["roots"].get(retired.as_str()).is_none(),
        "retired principal remained in independent-reader roots"
    );
    assert!(
        decoded["roots"]
            .get(peer_name.as_str())
            .and_then(|root| root.get("commit"))
            .is_some(),
        "peer principal missing from independent-reader roots"
    );
}

#[tokio::test]
async fn independent_reader_accepts_nonempty_indexed_workspace_volume() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    let alice = PrincipalUid::from_bytes([0x71; 32]);
    let bob = PrincipalUid::from_bytes([0x72; 32]);
    store
        .principal_directory()
        .register(PrincipalId::new("alice-indexed").unwrap(), alice)
        .unwrap();
    store
        .principal_directory()
        .register(PrincipalId::new("bob-indexed").unwrap(), bob)
        .unwrap();
    let owner = StateOwner::Fleet(FleetUid::from_bytes([0x61; 32]));
    let branches = WorkspaceBranchStore::new(store.content());
    let docs = ContentName::new("docs/src").unwrap();
    let notes = ContentName::new("notes").unwrap();
    let live_alice = WorkspaceUid::from_bytes([0x81; 16]);
    let terminal_alice = WorkspaceUid::from_bytes([0x82; 16]);
    let live_bob = WorkspaceUid::from_bytes([0x83; 16]);
    branches
        .begin_for_uid_at(&owner, alice, terminal_alice, docs.clone())
        .unwrap();
    branches
        .write(
            &owner,
            terminal_alice,
            &ContentName::new("README").unwrap(),
            b"terminal body",
        )
        .unwrap();
    branches.promote(&owner, terminal_alice).unwrap();
    branches
        .begin_for_uid_at(&owner, alice, live_alice, docs.clone())
        .unwrap();
    branches
        .write(
            &owner,
            live_alice,
            &ContentName::new("main.rs").unwrap(),
            b"fn main() {}",
        )
        .unwrap();
    branches
        .begin_for_uid_at(&owner, bob, live_bob, notes.clone())
        .unwrap();
    branches
        .write(
            &owner,
            live_bob,
            &ContentName::new("todo.txt").unwrap(),
            b"ship indexed fixture",
        )
        .unwrap();
    assert_eq!(branches.list_bindings(&owner).unwrap().len(), 3);
    drop(store);

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/runatal_v1_reader.py");
    let output = std::process::Command::new("python3")
        .arg(&script)
        .arg(home.storage_volume_path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "independent reader rejected nonempty indexed workspace volume: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decoded: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let fleet = format!("fleet:{}", FleetUid::from_bytes([0x61; 32]));
    assert!(
        decoded["roots"]
            .get(fleet.as_str())
            .and_then(|root| root.get("commit"))
            .is_some(),
        "fleet root missing from independent-reader roots: {decoded}"
    );
}

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;
use astrid_core::principal::PrincipalId;

use super::{RuntimePrincipalStore, StateOwner, open_runtime_principal_store};
use crate::KvQuotaResolver;

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) | StateOwner::User(_) => Some(u64::MAX),
        })
    })
}

fn create_principal(store: &RuntimePrincipalStore, alias: &str) -> PrincipalUid {
    let uid = PrincipalUid::from_bytes(*blake3::hash(alias.as_bytes()).as_bytes());
    store
        .principal_directory()
        .register(PrincipalId::new(alias).unwrap(), uid)
        .unwrap();
    uid
}

#[tokio::test]
async fn principal_kv_purge_removes_orphan_namespaces_without_touching_peers() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let alice_uid = create_principal(&store, "alice");
    create_principal(&store, "bob");
    store
        .kv()
        .set("alice:capsule:removed", "orphan", b"secret".to_vec())
        .await
        .unwrap();
    store
        .kv()
        .set("alice:capsule:live", "state", b"state".to_vec())
        .await
        .unwrap();
    store
        .kv()
        .set("bob:capsule:live", "state", b"bob".to_vec())
        .await
        .unwrap();

    assert!(store.purge_principal_kv(alice_uid).unwrap());

    assert!(
        store
            .kv()
            .get("alice:capsule:removed", "orphan")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .kv()
            .get("alice:capsule:live", "state")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.kv().get("bob:capsule:live", "state").await.unwrap(),
        Some(b"bob".to_vec())
    );
}

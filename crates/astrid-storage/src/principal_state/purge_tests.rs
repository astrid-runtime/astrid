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
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
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

#[tokio::test]
async fn capsule_kv_purge_removes_only_the_selected_principal_capsule() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let alice = PrincipalId::new("alice").unwrap();
    let bob = PrincipalId::new("bob").unwrap();
    create_principal(&store, alice.as_str());
    create_principal(&store, bob.as_str());

    for (namespace, value) in [
        ("alice:capsule:codewall-protocol", b"credential".as_slice()),
        ("alice:capsule:notes", b"keep-alice".as_slice()),
        ("bob:capsule:codewall-protocol", b"keep-bob".as_slice()),
    ] {
        store
            .kv()
            .set(namespace, "state", value.to_vec())
            .await
            .unwrap();
    }

    assert_eq!(
        store
            .purge_capsule_kv(&alice, "codewall-protocol")
            .await
            .unwrap(),
        1
    );
    assert!(
        store
            .kv()
            .get("alice:capsule:codewall-protocol", "state")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .kv()
            .get("alice:capsule:notes", "state")
            .await
            .unwrap(),
        Some(b"keep-alice".to_vec())
    );
    assert_eq!(
        store
            .kv()
            .get("bob:capsule:codewall-protocol", "state")
            .await
            .unwrap(),
        Some(b"keep-bob".to_vec())
    );
}

#[tokio::test]
async fn immutable_owner_purge_cannot_follow_a_reused_alias() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let alias = PrincipalId::new("alice").unwrap();
    let renamed = PrincipalId::new("alice-retired").unwrap();
    let original_uid = create_principal(&store, alias.as_str());
    store
        .kv()
        .set(
            "alice:capsule:codewall-protocol",
            "state",
            b"old enrolment".to_vec(),
        )
        .await
        .unwrap();

    store
        .principal_directory()
        .rename(original_uid, &alias, renamed)
        .unwrap();
    let replacement_uid = PrincipalUid::from_bytes([42; 32]);
    store
        .principal_directory()
        .register(alias.clone(), replacement_uid)
        .unwrap();
    store
        .kv()
        .set(
            "alice:capsule:codewall-protocol",
            "state",
            b"replacement enrolment".to_vec(),
        )
        .await
        .unwrap();

    assert_eq!(
        store
            .purge_capsule_kv_for_owner(original_uid, &alias, "codewall-protocol")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .kv()
            .get("alice:capsule:codewall-protocol", "state")
            .await
            .unwrap(),
        Some(b"replacement enrolment".to_vec()),
        "purging the retired UID must not follow the reused alias"
    );
}

#[tokio::test]
async fn retired_uid_purge_survives_alias_removal_and_reuse_with_strict_live_quota() {
    use crate::principal_state::open_runtime_principal_store_with_directory;
    use crate::{ContentName, PrincipalDirectory};
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let principals = PrincipalDirectory::default();
    let quota_directory = principals.clone();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> =
        Arc::new(move |owner: &StateOwner| match owner {
            StateOwner::Principal(uid) => quota_directory.alias_for(*uid).map(|_| Some(u64::MAX)),
            StateOwner::System | StateOwner::Fleet(_) => Ok(None),
        });
    let store = open_runtime_principal_store_with_directory(&home, quota, principals.clone())
        .await
        .unwrap();
    let retired = create_principal(&store, "alice");
    create_principal(&store, "bob");
    store
        .kv()
        .set("alice:capsule:notes", "key", b"old private state".to_vec())
        .await
        .unwrap();
    store
        .kv()
        .set("bob:capsule:notes", "key", b"peer state".to_vec())
        .await
        .unwrap();
    let name = ContentName::new("retained-content").unwrap();
    store
        .content()
        .put(&StateOwner::Principal(retired), &name, b"keep non-KV state")
        .unwrap();
    let alias = PrincipalId::new("alice").unwrap();
    principals.unregister(&alias, retired);
    assert!(principals.alias_for(retired).is_err());
    let replacement = PrincipalUid::from_bytes([0x99; 32]);
    principals.register(alias, replacement).unwrap();
    store
        .kv()
        .set("alice:capsule:notes", "key", b"replacement state".to_vec())
        .await
        .unwrap();
    assert!(store.purge_principal_kv(retired).unwrap());
    assert!(!store.purge_principal_kv(retired).unwrap());
    assert_eq!(
        store.kv().get("alice:capsule:notes", "key").await.unwrap(),
        Some(b"replacement state".to_vec())
    );
    assert_eq!(
        store.kv().get("bob:capsule:notes", "key").await.unwrap(),
        Some(b"peer state".to_vec())
    );
    assert_eq!(
        store
            .content()
            .read(&StateOwner::Principal(retired), &name)
            .unwrap(),
        Some(b"keep non-KV state".to_vec())
    );
    let dead_namespace = format!("principal-uid:{retired}:control:env:notes");
    assert!(
        store
            .kv()
            .set(&dead_namespace, "key", b"forbidden".to_vec())
            .await
            .is_err()
    );
}

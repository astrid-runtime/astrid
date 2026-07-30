use std::sync::Arc;

use super::*;
use crate::MemoryKvStore;

fn make_principal_store() -> (KvIdentityStore, PrincipalDirectory) {
    let kv_backend = Arc::new(MemoryKvStore::new());
    let scoped = ScopedKvStore::new(kv_backend, "system:identity").unwrap();
    let principals = PrincipalDirectory::default();
    (
        KvIdentityStore::with_principal_directory(scoped, principals.clone()),
        principals,
    )
}

#[tokio::test]
async fn principal_identity_survives_alias_and_auth_key_changes() {
    let (store, principals) = make_principal_store();
    let original = PrincipalId::new("alice").unwrap();
    let renamed = PrincipalId::new("alice-renamed").unwrap();
    let user = store
        .create_principal(original.clone(), [0x11; 32])
        .await
        .unwrap();
    let identity = store
        .get_principal_identity(user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(principals.uid_for(&original).unwrap(), identity.uid);

    let rebound = store
        .bind_principal_identity(user.id, renamed.clone(), [0x22; 32])
        .await
        .unwrap();
    assert_eq!(rebound, identity);
    assert!(principals.uid_for(&original).is_err());
    assert_eq!(principals.uid_for(&renamed).unwrap(), identity.uid);
    assert_eq!(principals.alias_for(identity.uid).unwrap(), renamed);
    assert_eq!(
        store.get_principal_identity(user.id).await.unwrap(),
        Some(identity)
    );
}

#[tokio::test]
async fn deleting_principal_removes_only_its_live_alias_binding() {
    let (store, principals) = make_principal_store();
    let alice_alias = PrincipalId::new("alice").unwrap();
    let bob_alias = PrincipalId::new("bob").unwrap();
    let alice = store
        .create_principal(alice_alias.clone(), [0x11; 32])
        .await
        .unwrap();
    let bob = store
        .create_principal(bob_alias.clone(), [0x22; 32])
        .await
        .unwrap();
    let bob_uid = store
        .get_principal_identity(bob.id)
        .await
        .unwrap()
        .unwrap()
        .uid;

    assert!(store.delete_user(alice.id).await.unwrap());
    assert!(principals.uid_for(&alice_alias).is_err());
    assert_eq!(principals.uid_for(&bob_alias).unwrap(), bob_uid);
}

#[tokio::test]
async fn loading_directory_rejects_alias_or_uid_collisions_atomically() {
    let kv_backend = Arc::new(MemoryKvStore::new());
    let scoped = ScopedKvStore::new(kv_backend, "system:identity").unwrap();
    let principals = PrincipalDirectory::default();
    let store = KvIdentityStore::with_principal_directory(scoped, principals.clone());
    let retained_alias = PrincipalId::new("retained").unwrap();
    let retained_uid = PrincipalUid::from_bytes([0x77; 32]);
    principals
        .register(retained_alias.clone(), retained_uid)
        .unwrap();

    let first = AstridUserId::new().with_principal(PrincipalId::new("same").unwrap());
    let mut second = AstridUserId::new().with_principal(PrincipalId::new("other").unwrap());
    second.principal = PrincipalId::new("same").unwrap();
    let first_identity = PrincipalIdentity::from_genesis(PrincipalGenesis::from_parts(
        first.id,
        first.created_at,
        [1; 32],
    ))
    .unwrap();
    let second_identity = PrincipalIdentity::from_genesis(PrincipalGenesis::from_parts(
        second.id,
        second.created_at,
        [2; 32],
    ))
    .unwrap();
    store
        .persist_user_record(&first, Some(first_identity))
        .await
        .unwrap();
    store
        .persist_user_record(&second, Some(second_identity))
        .await
        .unwrap();

    assert!(matches!(
        store.load_principal_directory().await,
        Err(IdentityError::InvalidInput(_))
    ));
    assert_eq!(principals.uid_for(&retained_alias).unwrap(), retained_uid);
    assert!(
        principals
            .uid_for(&PrincipalId::new("same").unwrap())
            .is_err()
    );
}

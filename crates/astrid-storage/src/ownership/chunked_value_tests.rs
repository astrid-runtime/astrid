//! Exercise the ownership caller through the native durable KV path.
use super::*;
use astrid_core::{UserGenesis, dirs::AstridHome};
use chrono::{TimeZone, Utc};
use uuid::Uuid;

fn user(index: u128) -> UserIdentity {
    UserIdentity::from_genesis(UserGenesis::from_parts(
        Uuid::from_u128(index),
        Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        [7; 32],
    ))
    .unwrap()
}

#[tokio::test]
async fn large_ownership_mutation_recovers_exact_graph() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let runtime = crate::principal_state::open_runtime_principal_store(
        &home,
        Arc::new(|_: &crate::principal_state::StateOwner| Ok(None)),
    )
    .await
    .unwrap();
    let kv = runtime.kv();
    let mut expected = OwnershipSnapshot::default();
    for index in 1..=2048 {
        let identity = user(index);
        expected.users.insert(identity.uid, identity);
    }
    let original = serde_json::to_vec(&expected).unwrap();
    assert!(original.len() > 256 * 1024);
    kv.set(OWNERSHIP_NAMESPACE, GRAPH_KEY, original)
        .await
        .unwrap();
    let owner = OwnershipStore::new(kv.clone(), PrincipalDirectory::default()).unwrap();
    let added = user(4096);
    owner.create_user(added.clone()).await.unwrap();
    expected.users.insert(added.uid, added);
    assert_eq!(owner.load().await.unwrap(), expected);
    let exact = serde_json::to_vec(&expected).unwrap();
    assert_eq!(
        kv.get(OWNERSHIP_NAMESPACE, GRAPH_KEY).await.unwrap(),
        Some(exact.clone())
    );
    kv.close().await.unwrap();
    drop(owner);
    drop(kv);
    drop(runtime);
    let reopened = crate::principal_state::open_runtime_principal_store(
        &home,
        Arc::new(|_: &crate::principal_state::StateOwner| Ok(None)),
    )
    .await
    .unwrap();
    assert_eq!(
        reopened
            .kv()
            .get(OWNERSHIP_NAMESPACE, GRAPH_KEY)
            .await
            .unwrap(),
        Some(exact)
    );
    let owner = OwnershipStore::new(reopened.kv(), PrincipalDirectory::default()).unwrap();
    assert_eq!(owner.load().await.unwrap(), expected);
    reopened.kv().close().await.unwrap();
}

//! Bounded, unlogged identity-deletion comparison using the native adapter.

use std::sync::Arc;
use std::time::Instant;

use super::tree_tests::{Resolver, TestIdentity};
use super::{ScopedKvStore, TreeKvStore};
use crate::engine::InMemoryEngine;
use crate::identity::{IdentityStore, KvIdentityStore};

#[tokio::test]
#[ignore = "manual matched identity deletion performance measurement; not a CI gate"]
async fn identity_deletion_measurement() {
    let mut samples = Vec::new();
    for _ in 0..9 {
        let backend = Arc::new(
            TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(
                Arc::new(InMemoryEngine::new(TestIdentity)),
                Resolver,
            ),
        );
        let store =
            KvIdentityStore::new(ScopedKvStore::new(backend, "system:capsule:identity").unwrap());
        let mut users = Vec::new();
        for index in 0..128 {
            let user = store
                .create_user(Some(&format!("user-{index}")))
                .await
                .unwrap();
            for link in 0..8 {
                store
                    .link("service", &format!("{index}-{link}"), user.id, "operator")
                    .await
                    .unwrap();
            }
            users.push(user.id);
        }
        let started = Instant::now();
        for user in users {
            assert!(store.delete_user(user).await.unwrap());
        }
        samples.push(started.elapsed().as_micros());
        assert!(store.list_users().await.unwrap().is_empty());
    }
    println!("identity_delete_128_users_1024_links_us={samples:?}");
}

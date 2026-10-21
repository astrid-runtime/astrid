//! Failed policy persistence must leave only recoverable execution admission.
use super::*;
use astrid_core::identity::hosted_owner::HostedOwnerConfiguration;
use astrid_storage::IdentityStore;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

async fn admitted(
    home: &astrid_core::dirs::AstridHome,
) -> (astrid_core::PrincipalUid, serde_json::Value) {
    let directory = astrid_storage::PrincipalDirectory::default();
    let profiles =
        Arc::new(astrid_capsule::profile_cache::PrincipalProfileCache::with_home(home.clone()));
    let quota = crate::Kernel::storage_quota_resolver(profiles, directory.clone());
    let runtime =
        astrid_storage::open_runtime_principal_store_with_directory(home, quota, directory.clone())
            .await
            .unwrap();
    let kv = runtime.kv();
    let identity = astrid_storage::KvIdentityStore::with_principal_directory(
        astrid_storage::ScopedKvStore::new(kv.clone(), "system:identity").unwrap(),
        directory.clone(),
    );
    identity.load_principal_directory().await.unwrap();
    let user = identity.resolve("cli", "local").await.unwrap().unwrap();
    let principal = identity
        .get_principal_identity(user.id)
        .await
        .unwrap()
        .unwrap();
    let ownership = astrid_storage::OwnershipStore::new(kv, directory).unwrap();
    let graph = ownership.load().await.unwrap();
    assert!(!ownership.first_owner_state().await.unwrap().is_enrolled());
    assert_eq!(graph.users().count(), 0);
    assert_eq!(graph.fleets().count(), 0);
    assert_eq!(graph.principal_owners().count(), 0);
    (principal.uid, serde_json::to_value(graph).unwrap())
}

#[tokio::test]
async fn expiry_after_execution_admission_retries_same_identity_without_authority() {
    let directory = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(directory.path().join("home"));
    let deployment = astrid_crypto::KeyPair::generate();
    let configuration = HostedOwnerConfiguration {
        deployment_key: *deployment.public_key_bytes(),
        generation: 1.try_into().unwrap(),
        expires_at: 1500.try_into().unwrap(),
        target: None,
    };
    // First clock read validates configuration; the CAS admission then observes
    // expiry after real key/profile/execution identity writes have completed.
    let calls = AtomicUsize::new(0);
    assert!(
        configure(&home, configuration.clone(), true, || {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                1000
            } else {
                1500
            }
        })
        .await
        .is_err()
    );
    assert!(calls.load(Ordering::SeqCst) >= 2);
    let key = std::fs::read(home.keys_dir().join("default.key")).unwrap();
    let (uid, graph) = admitted(&home).await;
    assert!(graph.get("hosted").is_none_or(serde_json::Value::is_null));
    assert!(graph.get("local_user_binding_initialized").is_none());
    assert!(graph.get("user_bindings").is_none());
    let configured = configure(&home, configuration, true, || 1000)
        .await
        .unwrap();
    assert_eq!(configured.policy.target.principal, uid);
    assert_eq!(
        std::fs::read(home.keys_dir().join("default.key")).unwrap(),
        key
    );
    assert!(configured.pending.is_none() && configured.completion.is_none());
    let (retried_uid, retried_graph) = admitted(&home).await;
    assert_eq!(retried_uid, uid);
    assert!(
        retried_graph
            .get("local_user_binding_initialized")
            .is_none()
    );
    assert!(retried_graph.get("user_bindings").is_none());
}

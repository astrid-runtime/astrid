//! Persist the verified halfway state through the real disk-backed store.
use super::Runtime;
use astrid_core::dirs::AstridHome;
use astrid_core::identity::hosted_owner::HostedOwnerEnvelope;
use astrid_storage::{IdentityStore, KvQuotaResolver, PrincipalDirectory, StateOwner};
use std::sync::Arc;

pub(super) fn persist(runtime: &Runtime, signed: &serde_json::Value) {
    let envelope: HostedOwnerEnvelope = serde_json::from_value(signed.clone()).unwrap();
    let home = AstridHome::from_path(runtime.home.clone());
    let lifecycle = astrid_storage::principal_state::RuntimeLifecycleGuard::acquire(&home).unwrap();
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    executor.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(45), async {
            let directory = PrincipalDirectory::default();
            // A disposable host fixture has no quota restriction. Authority is
            // still verified by the actual ownership transition and graph CAS.
            let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
            let store = astrid_storage::open_runtime_principal_store_with_directory(
                &home,
                quota,
                directory.clone(),
            )
            .await
            .unwrap();
            let kv = store.kv();
            let identity = astrid_storage::KvIdentityStore::with_principal_directory(
                astrid_storage::ScopedKvStore::new(kv.clone(), "system:identity").unwrap(),
                directory.clone(),
            );
            identity.load_principal_directory().await.unwrap();
            let ownership = astrid_storage::OwnershipStore::new(kv, directory).unwrap();
            ownership
                .begin_hosted_owner(&envelope, || {
                    chrono::Utc::now().timestamp().try_into().unwrap()
                })
                .await
                .unwrap();
            assert!(ownership.first_owner_state().await.unwrap().is_pending());
            let graph = ownership.load().await.unwrap();
            assert_eq!(graph.users().count(), 0);
            assert_eq!(graph.fleets().count(), 0);
            assert_eq!(graph.principal_owners().count(), 0);
        })
        .await
        .expect("bounded Pending fixture write");
    });
    // No store/task handle survives into normal projection finalization.
    executor
        .block_on(lifecycle.finish())
        .expect("persist Pending volume");
}

//! Retained immutable reads must not resurrect a retired cache account.
use std::sync::Arc;

use astrid_core::{PrincipalUid, dirs::AstridHome};

use crate::principal_state::{StateOwner, open_runtime_principal_store_with_object_cache};
use crate::resources::ResidentMemoryAuthority;
use crate::{ContentName, GovernedObjectCache, KvQuotaResolver};

#[tokio::test]
async fn retained_read_lease_does_not_recreate_retired_cache_reservations() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let uid = PrincipalUid::from_bytes([0xB1; 32]);
    let owner = StateOwner::Principal(uid);
    let peer = StateOwner::Principal(PrincipalUid::from_bytes([0xB2; 32]));
    let authority = ResidentMemoryAuthority::new(8 * 1024 * 1024);
    for principal in [StateOwner::System, owner, peer] {
        authority
            .register_principal(principal, None, u64::MAX)
            .unwrap();
    }
    let cache = GovernedObjectCache::new(authority.clone());
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store_with_object_cache(&home, quota, cache.config())
        .await
        .unwrap();
    let name = ContentName::new("lease-shared-content").unwrap();
    let bytes = vec![0x73; 32 * 1024];
    store.content().put(&owner, &name, &bytes).unwrap();
    store.content().put(&peer, &name, &bytes).unwrap();
    let lease = store.content().open_read(&owner, &name).unwrap().unwrap();
    assert_eq!(lease.read().unwrap(), bytes);
    assert_eq!(
        store.content().read(&peer, &name).unwrap(),
        Some(bytes.clone())
    );
    let historical = store.engine.root(&owner).unwrap().unwrap();
    assert!(store.object_cache_principal_charge(&owner) > 0);
    assert!(store.purge_principal_state(uid).unwrap());
    assert_eq!(store.object_cache_principal_charge(&owner), 0);
    let peer_charge = store.object_cache_principal_charge(&peer);
    assert!(peer_charge > 0);
    let live_lease_count = authority.snapshot().logical_leases.len();

    assert_eq!(lease.read().unwrap(), bytes);
    assert_eq!(lease.read_range(17, 257).unwrap(), bytes[17..274]);
    assert!(
        store
            .engine
            .shared_object_for(&owner, historical.commit)
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .engine
            .shared_objects_for(&owner, &[historical.commit])
            .unwrap()[0]
            .is_some()
    );
    assert!(store.engine.root(&owner).unwrap().is_none());
    assert_eq!(
        store.object_cache_principal_charge(&owner),
        0,
        "a retained read recreated a retired principal cache partition"
    );
    assert_eq!(
        authority.snapshot().logical_leases.len(),
        live_lease_count,
        "a retained read recreated a retired principal logical memory lease"
    );
    assert_eq!(store.object_cache_principal_charge(&peer), peer_charge);
    assert_eq!(store.content().read(&peer, &name).unwrap(), Some(bytes));
    store.engine.close().unwrap();
}

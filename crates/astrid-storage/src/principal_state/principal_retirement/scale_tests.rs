//! Explicit native scale regression; daemon/guest acceptance is separate.
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Instant;

use astrid_core::dirs::AstridHome;
use astrid_core::{FleetUid, PrincipalUid};

use crate::engine::ObjectCacheConfig;
use crate::principal_state::{StateOwner, open_runtime_principal_store_with_object_cache};
use crate::{ContentName, KvQuotaResolver, WorkspaceBranchStore, WorkspaceUid};

fn uid(index: u32) -> PrincipalUid {
    let mut bytes = [0; 32];
    bytes[..4].copy_from_slice(&index.to_be_bytes());
    PrincipalUid::from_bytes(bytes)
}
fn branch(index: u32) -> WorkspaceUid {
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&index.to_be_bytes());
    WorkspaceUid::from_bytes(bytes)
}

#[tokio::test]
#[ignore = "explicit native 10000-UID workspace restart and full retirement soak"]
async fn ten_thousand_uid_workspace_restart_and_retirement() {
    const AGENTS: u32 = 10_000;
    const CACHE_BYTES: u64 = 64 * 1024 * 1024;
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let cache = || ObjectCacheConfig::bounded(NonZeroU64::new(CACHE_BYTES).unwrap());
    let owner = StateOwner::Fleet(FleetUid::from_bytes([0x66; 32]));
    let name = ContentName::new("sentinel").unwrap();
    let prefix = ContentName::new("workspace/default").unwrap();
    let started = Instant::now();
    let store = open_runtime_principal_store_with_object_cache(&home, Arc::clone(&quota), cache())
        .await
        .unwrap();
    let branches = WorkspaceBranchStore::new(store.content());
    for index in 0..AGENTS {
        branches
            .begin_for_uid_at(&owner, uid(index), branch(index), prefix.clone())
            .unwrap();
        branches
            .write(&owner, branch(index), &name, &index.to_be_bytes())
            .unwrap();
        // A complete private component proves retirement removes real roots,
        // rather than leaving an empty per-UID authority row behind.
        store
            .content()
            .put(
                &StateOwner::Principal(uid(index)),
                &name,
                &index.to_be_bytes(),
            )
            .unwrap();
        if index % 1000 == 999 {
            println!(
                "created={} seconds={:.3} cache={:?}",
                index.checked_add(1).unwrap(),
                started.elapsed().as_secs_f64(),
                store.object_cache_stats()
            );
            assert!(store.object_cache_stats().resident_bytes <= CACHE_BYTES);
        }
    }
    assert_eq!(
        branches.list_branches(&owner).unwrap().len(),
        AGENTS as usize
    );
    drop(branches);
    store.engine.close().unwrap();
    drop(store);
    let store = open_runtime_principal_store_with_object_cache(&home, quota, cache())
        .await
        .unwrap();
    let branches = WorkspaceBranchStore::new(store.content());
    for index in 0..AGENTS {
        let binding = branches
            .binding_for_uid(&owner, uid(index), &prefix)
            .unwrap()
            .unwrap();
        assert_eq!(binding.branch_id(), branch(index));
        assert_eq!(
            branches
                .read(&owner, branch(index), &name)
                .unwrap()
                .unwrap(),
            index.to_be_bytes()
        );
        assert_eq!(
            store
                .content()
                .read(&StateOwner::Principal(uid(index)), &name)
                .unwrap()
                .unwrap(),
            index.to_be_bytes()
        );
    }
    println!(
        "restarted_and_read={} seconds={:.3}",
        AGENTS,
        started.elapsed().as_secs_f64()
    );
    retire_all(&store, AGENTS, started);
    assert!(branches.list_bindings(&owner).unwrap().is_empty());
    assert!(
        store
            .engine
            .roots_in_range(StateOwner::Principal(uid(0))..=StateOwner::Principal(uid(AGENTS)))
            .unwrap()
            .is_empty()
    );
    println!(
        "native_scale_pass seconds={:.3} cache={:?}",
        started.elapsed().as_secs_f64(),
        store.object_cache_stats()
    );
    store.engine.close().unwrap();
}

fn retire_all(
    store: &crate::principal_state::RuntimePrincipalStore,
    agents: u32,
    started: Instant,
) {
    for index in 0..agents {
        assert!(store.purge_principal_state(uid(index)).unwrap());
        assert!(
            store
                .engine
                .root(&StateOwner::Principal(uid(index)))
                .unwrap()
                .is_none()
        );
        if index % 1000 == 999 {
            println!(
                "retired={} seconds={:.3}",
                index.checked_add(1).unwrap(),
                started.elapsed().as_secs_f64()
            );
        }
    }
}

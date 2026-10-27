//! Cleanup reads one validated graph without changing branch custody.
use super::*;
use astrid_storage::{KvStore, StorageResult};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountReads {
    inner: Arc<dyn KvStore>,
    reads: AtomicUsize,
}

#[async_trait::async_trait]
impl KvStore for CountReads {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        if namespace == astrid_storage::ownership::OWNERSHIP_NAMESPACE && key == "graph-v1" {
            self.reads.fetch_add(1, Ordering::Relaxed);
        }
        self.inner.get(namespace, key).await
    }
    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        self.inner.set(namespace, key, value).await
    }
    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.delete(namespace, key).await
    }
    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.exists(namespace, key).await
    }
    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        self.inner.list_keys(namespace).await
    }
    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool> {
        self.inner
            .compare_and_swap(namespace, key, expected, new)
            .await
    }
    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        self.inner.clear_namespace(namespace).await
    }
}

#[tokio::test]
async fn cleanup_reads_one_graph_and_preserves_branches_after_ownership_moves() {
    let fixture = workspace_branch_tests::fixture().await;
    let counted = Arc::new(CountReads {
        inner: fixture.store.kv(),
        reads: AtomicUsize::new(0),
    });
    let ownership = Arc::new(
        astrid_storage::OwnershipStore::new(counted.clone(), fixture.directory.clone()).unwrap(),
    );
    let user = workspace_branch_tests::user_identity(0xF1, 9);
    let fleet = workspace_branch_tests::fleet_identity(0xF2, user.uid);
    ownership.create_user(user.clone()).await.unwrap();
    ownership.create_fleet(fleet.clone()).await.unwrap();
    let warm_service = WorkspaceBranchService::new_with_ownership(
        fixture.store.clone(),
        fixture.directory.clone(),
        Some(ownership.clone()),
    );
    let branches = astrid_storage::WorkspaceBranchStore::new(fixture.store.content());
    let prefix =
        astrid_storage::ContentName::new(WorkspaceBranchService::ATTACHMENT_PREFIX).unwrap();
    let mut recorded = Vec::new();
    for index in 0_u8..32 {
        let principal = PrincipalId::new(format!("cleanup-{index}")).unwrap();
        let uid = astrid_core::PrincipalUid::from_bytes([index; 32]);
        fixture.directory.register(principal.clone(), uid).unwrap();
        let owner = astrid_storage::StateOwner::Principal(uid);
        let branch = branches
            .begin_for_uid_at(
                &owner,
                uid,
                astrid_storage::WorkspaceUid::random(),
                prefix.clone(),
            )
            .unwrap();
        let binding = warm_service.binding_for(&principal).await.unwrap();
        assert_eq!(binding.branch, branch.id());
        recorded.push((owner, branch.id(), binding));
        // Move ownership after binding. Cleanup must retain the old data;
        // fresh authority checks must still reject using the old binding.
        ownership
            .assign_principal(astrid_core::PrincipalOwnership {
                principal_uid: uid,
                fleet_uid: fleet.uid,
                assigned_by: user.uid,
            })
            .await
            .unwrap();
    }
    let service = WorkspaceBranchService::new_with_ownership(
        fixture.store.clone(),
        fixture.directory.clone(),
        Some(ownership),
    );
    counted.reads.store(0, Ordering::Relaxed);
    service.cleanup_orphaned().await.unwrap();
    assert_eq!(
        counted.reads.load(Ordering::Relaxed),
        1,
        "cleanup repeatedly decoded the full ownership graph"
    );
    for (owner, branch, _) in &recorded {
        assert!(
            branches.describe(owner, *branch).is_ok(),
            "cleanup removed bound state after ownership moved"
        );
    }
    assert_cold_owner_rebinding(&service, recorded[0].2, fleet.uid).await;

    counted
        .inner
        .set(
            astrid_storage::ownership::OWNERSHIP_NAMESPACE,
            "graph-v1",
            b"malformed".to_vec(),
        )
        .await
        .unwrap();
    assert!(
        service.cleanup_orphaned().await.is_err(),
        "invalid ownership graph must fail closed"
    );
    for (owner, branch, _) in recorded {
        assert!(branches.describe(&owner, branch).is_ok());
    }
}

// Boot cleanup has no cached bindings. A moved owner must receive a new
// branch while the former owner's uncommitted branch stays inaccessible.
async fn assert_cold_owner_rebinding(
    service: &WorkspaceBranchService,
    old: WorkspaceBranchBinding,
    fleet: astrid_core::FleetUid,
) {
    let principal = PrincipalId::new("cleanup-0").unwrap();
    assert!(service.binding_for(&principal).await.is_err());
    assert!(
        service
            .finish(&principal, old, WorkspaceCommitOp::Promote)
            .await
            .is_err()
    );
    let rebound = service.bind(&principal).await.unwrap();
    assert_eq!(rebound.owner, astrid_storage::StateOwner::Fleet(fleet));
    assert_ne!(rebound.branch, old.branch);
    assert!(service.branches.describe(&old.owner, old.branch).is_ok());
    assert!(
        service
            .branches
            .list_branches(&rebound.owner)
            .unwrap()
            .iter()
            .all(|branch| branch.id() != old.branch)
    );
}

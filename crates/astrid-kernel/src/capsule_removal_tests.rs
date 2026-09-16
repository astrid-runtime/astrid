use std::sync::Arc;

use astrid_capsule::capsule::{Capsule, CapsuleState};
use astrid_capsule::context::CapsuleContext;
use astrid_capsule::registry::WasmHash;
use astrid_capsule_types::CapsuleId;
use astrid_capsule_types::error::CapsuleResult;
use astrid_capsule_types::manifest::CapsuleManifest;
use astrid_core::PrincipalId;
use astrid_storage::{CapsuleInstallExpectation, CapsulePackage, StateOwner};

struct BlockingQuiesceCapsule {
    id: CapsuleId,
    manifest: CapsuleManifest,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl Capsule for BlockingQuiesceCapsule {
    fn id(&self) -> &CapsuleId {
        &self.id
    }

    fn manifest(&self) -> &CapsuleManifest {
        &self.manifest
    }

    fn state(&self) -> CapsuleState {
        CapsuleState::Ready
    }

    async fn load(&mut self, _context: &CapsuleContext) -> CapsuleResult<()> {
        Ok(())
    }

    async fn unload(&mut self) -> CapsuleResult<()> {
        Ok(())
    }

    async fn quiesce_for(&self, _principal: &PrincipalId) {
        self.entered.notify_one();
        self.release.notified().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capsule_removal_cannot_delete_or_purge_a_concurrent_replacement() {
    let directory = tempfile::tempdir().expect("capsule-removal tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(directory.path());
    let kernel = crate::test_kernel_with_home(home).await;
    let principal = PrincipalId::default();
    let uid = kernel.principal_directory.uid_for(&principal).unwrap();
    let owner = StateOwner::Principal(uid);
    let id = CapsuleId::new("remove-generation-race").unwrap();
    let original = CapsulePackage::new(
        b"original archive".to_vec(),
        b"original metadata".to_vec(),
        b"original authority".to_vec(),
    );
    let replacement = CapsulePackage::new(
        b"replacement archive".to_vec(),
        b"replacement metadata".to_vec(),
        b"replacement authority".to_vec(),
    );
    let store = kernel.principal_store.as_ref().unwrap();
    store
        .capsules()
        .install(
            &owner,
            id.as_str(),
            &original,
            CapsuleInstallExpectation::Absent,
        )
        .unwrap();
    store
        .kv()
        .set(
            "default:capsule:remove-generation-race",
            "state",
            b"must survive the rejected removal".to_vec(),
        )
        .await
        .unwrap();

    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    kernel
        .capsules
        .write()
        .await
        .register_principal_runtime(
            Box::new(BlockingQuiesceCapsule {
                id: id.clone(),
                manifest: CapsuleManifest::default(),
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            }),
            WasmHash::from_raw("remove-generation-race"),
            &principal,
            uid,
        )
        .unwrap();

    let removing = {
        let kernel = Arc::clone(&kernel);
        let principal = principal.clone();
        let id = id.clone();
        tokio::spawn(async move { kernel.remove_one_capsule(&id, &principal, true).await })
    };
    entered.notified().await;

    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            kernel.admin_write_lock.lock(),
        )
        .await
        .is_err(),
        "principal rename/delete must remain fenced through package removal and purge"
    );

    store
        .capsules()
        .install(
            &owner,
            id.as_str(),
            &replacement,
            CapsuleInstallExpectation::Any,
        )
        .unwrap();
    release.notify_one();

    let error = removing.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("conflict"), "{error:#}");
    assert_eq!(
        store.capsules().get(&owner, id.as_str()).unwrap(),
        Some(replacement),
        "a generation-checked removal must preserve the concurrent replacement"
    );
    assert_eq!(
        store
            .kv()
            .get("default:capsule:remove-generation-race", "state")
            .await
            .unwrap(),
        Some(b"must survive the rejected removal".to_vec()),
        "a rejected removal must not purge state"
    );
}

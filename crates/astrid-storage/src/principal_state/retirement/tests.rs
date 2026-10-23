//! Finalization must survive task-runtime teardown with closed former views.
use super::*;
use crate::principal_state::RuntimeLifecycleGuard;
use crate::{ContentName, open_runtime_principal_store};

fn quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

#[test]
fn transferred_owner_packs_after_runtime_drop_and_reopens_exact_state() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let name = ContentName::new("capsules/test.wasm").unwrap();
    let (owner, old_kv, old_content) = {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let store = open_runtime_principal_store(&home, quota()).await.unwrap();
            let kv = store.kv();
            kv.set("system:retirement", "key", b"durable".to_vec())
                .await
                .unwrap();
            let content = store.content();
            content.put(&StateOwner::System, &name, b"capsule").unwrap();
            std::fs::write(home.root().join("config.toml"), b"before handoff").unwrap();
            store.publish_runtime_projection(&home).unwrap();
            let owner = store.handoff_for_retirement(&home).unwrap();
            assert!(kv.get("system:retirement", "key").await.is_err());
            assert!(content.read(&StateOwner::System, &name).is_err());
            kv.close().await.unwrap();
            (owner, kv, content)
        })
    };
    assert!(RuntimeLifecycleGuard::acquire(&home).is_err());
    std::fs::write(home.root().join("config.toml"), b"final host write").unwrap();
    lifecycle.finish_with_owner(owner).unwrap();
    let entries = std::fs::read_dir(home.root())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].file_name(), "astrid.volume");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        assert!(
            old_kv
                .set("system:retirement", "key", b"forbidden".to_vec())
                .await
                .is_err()
        );
        assert!(
            old_content
                .put(&StateOwner::System, &name, b"forbidden")
                .is_err()
        );
        let reopened = open_runtime_principal_store(&home, quota()).await.unwrap();
        assert_eq!(
            reopened.kv().get("system:retirement", "key").await.unwrap(),
            Some(b"durable".to_vec())
        );
        assert_eq!(
            reopened.content().read(&StateOwner::System, &name).unwrap(),
            Some(b"capsule".to_vec())
        );
        assert_eq!(
            std::fs::read(home.root().join("config.toml")).unwrap(),
            b"final host write"
        );
    });
}

#[tokio::test]
async fn wrong_home_fails_before_closing_runtime_handles() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let wrong = AstridHome::from_path(parent.path().join("wrong"));
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    store.publish_runtime_projection(&home).unwrap();
    assert!(store.handoff_for_retirement(&wrong).is_err());
    store
        .kv()
        .set("system:retirement", "key", b"still usable".to_vec())
        .await
        .unwrap();
}

#[tokio::test]
async fn shutdown_error_does_not_drop_packing_owner_or_hide_failure() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    store.publish_runtime_projection(&home).unwrap();
    let mut owner = store.handoff_for_retirement(&home).unwrap();
    owner.record_shutdown_error(StorageError::Internal(
        "injected shutdown close failure".into(),
    ));
    store.kv().close().await.unwrap();
    assert!(RuntimeLifecycleGuard::acquire(&home).is_err());
    std::fs::write(home.root().join("config.toml"), b"pack despite close error").unwrap();
    let error = lifecycle.finish_with_owner(owner).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected shutdown close failure")
    );
    assert!(!home.root().join("config.toml").exists());
    let reopened = open_runtime_principal_store(&home, quota()).await.unwrap();
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"pack despite close error"
    );
    drop(reopened);
}

#[cfg(unix)]
#[tokio::test]
async fn failed_pack_preserves_host_evidence_and_allows_fenced_retry() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    store
        .kv()
        .set("system:retirement", "key", b"keep durable".to_vec())
        .await
        .unwrap();
    store.publish_runtime_projection(&home).unwrap();
    let owner = store.handoff_for_retirement(&home).unwrap();
    std::fs::write(home.root().join("config.toml"), b"keep host evidence").unwrap();
    std::os::unix::fs::symlink(parent.path(), home.root().join("redirect")).unwrap();
    assert!(lifecycle.finish_with_owner(owner).is_err());
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"keep host evidence"
    );
    assert!(store.kv().get("system:retirement", "key").await.is_err());
    std::fs::remove_file(home.root().join("redirect")).unwrap();
    RuntimeLifecycleGuard::acquire(&home)
        .unwrap()
        .finish()
        .await
        .unwrap();
    let reopened = open_runtime_principal_store(&home, quota()).await.unwrap();
    assert_eq!(
        reopened.kv().get("system:retirement", "key").await.unwrap(),
        Some(b"keep durable".to_vec())
    );
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"keep host evidence"
    );
}

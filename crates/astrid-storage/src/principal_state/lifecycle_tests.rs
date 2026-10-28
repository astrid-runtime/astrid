use super::*;
use crate::{ContentName, open_runtime_principal_store};

#[tokio::test]
async fn finalizer_fences_replacement_and_is_idempotent() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    assert!(
        !home.root().exists(),
        "fencing must not preempt fresh-home admission"
    );
    let original_path = home.lifecycle_lock_path().unwrap();
    assert_eq!(
        original_path.parent().unwrap().parent().unwrap(),
        std::fs::canonicalize(parent.path()).unwrap(),
        "control storage must be a stable sibling, not process temp storage"
    );
    let other_temp = tempfile::tempdir().unwrap();
    let probe = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "principal_state::lifecycle::tests::different_temp_process_cannot_acquire_fence",
            "--nocapture",
        ])
        .env("ASTRID_TEST_LIFECYCLE_ROOT", home.root())
        .env("TMPDIR", other_temp.path())
        .env("TMP", other_temp.path())
        .env("TEMP", other_temp.path())
        .output()
        .unwrap();
    assert!(
        probe.status.success(),
        "{}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota.clone())
        .await
        .unwrap();
    let name = ContentName::new("bin/test.wasm").unwrap();
    store
        .content()
        .put(&StateOwner::System, &name, b"capsule")
        .unwrap();
    store.publish_runtime_projection(&home).unwrap();
    drop(store);
    assert_eq!(original_path, home.lifecycle_lock_path().unwrap());
    assert!(RuntimeLifecycleGuard::acquire(&home).is_err());
    lifecycle.finish().await.unwrap();
    let entries = std::fs::read_dir(home.root())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].file_name(), "astrid.volume");
    RuntimeLifecycleGuard::acquire(&home)
        .unwrap()
        .finish()
        .await
        .unwrap();
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    assert_eq!(
        store.content().read(&StateOwner::System, &name).unwrap(),
        Some(b"capsule".to_vec())
    );
}

#[cfg(unix)]
#[tokio::test]
async fn failed_finalization_preserves_recovery_evidence() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    std::fs::write(home.root().join("config.toml"), b"keep").unwrap();
    drop(store);
    std::os::unix::fs::symlink(parent.path(), home.root().join("redirect")).unwrap();
    assert!(lifecycle.finish().await.is_err());
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"keep"
    );
    assert!(home.root().join("redirect").symlink_metadata().is_ok());
    assert!(RuntimeLifecycleGuard::acquire(&home).is_ok());
}

#[test]
fn different_temp_process_cannot_acquire_fence() {
    let Some(root) = std::env::var_os("ASTRID_TEST_LIFECYCLE_ROOT") else {
        return;
    };
    assert!(RuntimeLifecycleGuard::acquire(&AstridHome::from_path(root)).is_err());
}

async fn retained_fixture() -> (
    tempfile::TempDir,
    AstridHome,
    RuntimeLifecycleGuard,
    super::super::RuntimePrincipalStore,
) {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    std::fs::write(home.root().join("config.toml"), b"before shutdown").unwrap();
    store.publish_runtime_projection(&home).unwrap();
    (parent, home, lifecycle, store)
}

#[tokio::test]
async fn retained_finalizer_packs_late_host_writes_without_reopening_locked_engine() {
    let (_parent, home, lifecycle, store) = retained_fixture().await;
    let token = store.retain_for_finalization();
    std::fs::write(home.root().join("config.toml"), b"after task teardown").unwrap();
    // A second open cannot recover this volume while the retained engine owns
    // it. Successful finalization must use the original engine despite the
    // store clone remaining alive across the call.
    assert!(crate::volume::HostedFileVolume::open(home.storage_volume_path()).is_err());
    lifecycle.finish_retained(token).unwrap();
    assert!(store.kv().get("system:test", "late").await.is_err());
    assert!(!home.root().join("config.toml").exists());
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let reopened = open_runtime_principal_store(&home, quota).await.unwrap();
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"after task teardown"
    );
    reopened.kv().close().await.unwrap();
}

#[tokio::test]
async fn abandoned_token_closes_surviving_store_and_releases_volume() {
    let (_parent, home, _lifecycle, store) = retained_fixture().await;
    drop(store.retain_for_finalization());
    assert!(
        store
            .kv()
            .set("system:test", "late", b"rejected".to_vec())
            .await
            .is_err()
    );
    let volume = crate::volume::HostedFileVolume::open(home.storage_volume_path()).unwrap();
    drop(volume);
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"before shutdown"
    );
}

#[tokio::test]
async fn retained_finalizer_rejects_wrong_home_before_packing_and_closes_original() {
    let (_parent, home, _lifecycle, store) = retained_fixture().await;
    let (_other_parent, other_home, other_lifecycle, other_store) = retained_fixture().await;
    std::fs::write(other_home.root().join("config.toml"), b"other home").unwrap();
    assert!(
        other_lifecycle
            .finish_retained(store.retain_for_finalization())
            .is_err()
    );
    assert!(store.kv().get("system:test", "late").await.is_err());
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"before shutdown"
    );
    assert_eq!(
        std::fs::read(other_home.root().join("config.toml")).unwrap(),
        b"other home"
    );
    other_store.kv().close().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn retained_finalizer_rejects_replaced_volume_and_preserves_host() {
    let (_parent, home, lifecycle, store) = retained_fixture().await;
    let volume_path = home.storage_volume_path();
    let original = home.root().join("original.volume");
    std::fs::rename(&volume_path, &original).unwrap();
    std::fs::copy(&original, &volume_path).unwrap();
    let replacement = std::fs::read(&volume_path).unwrap();
    assert!(
        lifecycle
            .finish_retained(store.retain_for_finalization())
            .is_err()
    );
    assert_eq!(std::fs::read(&volume_path).unwrap(), replacement);
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"before shutdown"
    );
    assert!(store.kv().get("system:test", "late").await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn retained_finalizer_rejects_volume_symlink_and_closes_original() {
    let (_parent, home, lifecycle, store) = retained_fixture().await;
    let volume_path = home.storage_volume_path();
    let original = home.root().join("original.volume");
    std::fs::rename(&volume_path, &original).unwrap();
    std::os::unix::fs::symlink(&original, &volume_path).unwrap();
    assert!(
        lifecycle
            .finish_retained(store.retain_for_finalization())
            .is_err()
    );
    assert!(volume_path.symlink_metadata().unwrap().is_symlink());
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"before shutdown"
    );
    assert!(store.kv().get("system:test", "late").await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn retained_finalizer_closes_storage_when_host_pack_fails() {
    let (parent, home, lifecycle, store) = retained_fixture().await;
    std::os::unix::fs::symlink(parent.path(), home.root().join("redirect")).unwrap();
    assert!(
        lifecycle
            .finish_retained(store.retain_for_finalization())
            .is_err()
    );
    assert!(store.kv().get("system:test", "late").await.is_err());
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"before shutdown"
    );
    assert!(crate::volume::HostedFileVolume::open(home.storage_volume_path()).is_ok());
}

#[cfg(unix)]
#[tokio::test]
async fn retained_finalizer_uses_current_handle_after_legitimate_reclaim() {
    use crate::volume::AstridVolume as _;
    use std::os::unix::fs::MetadataExt as _;

    let (_parent, home, lifecycle, store) = retained_fixture().await;
    store.engine.flush().unwrap();
    let before = std::fs::metadata(home.storage_volume_path()).unwrap().ino();
    let volume = store.volume_binding.upgrade().unwrap();
    volume.reclaim().unwrap();
    let after = std::fs::metadata(home.storage_volume_path()).unwrap().ino();
    assert_ne!(before, after, "reclaim must exercise an inode replacement");
    drop(volume);
    lifecycle
        .finish_retained(store.retain_for_finalization())
        .unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let reopened = open_runtime_principal_store(&home, quota).await.unwrap();
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"before shutdown"
    );
    reopened.kv().close().await.unwrap();
}

//! Finalization must survive task-runtime teardown with closed former views.
use super::*;
use crate::principal_state::RuntimeLifecycleGuard;
use crate::{ContentName, StorageError, open_runtime_principal_store};
use crate::{KvQuotaResolver, StateOwner};

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
            let owner = store.handoff_for_finalization(&home).unwrap();
            assert!(kv.get("system:retirement", "key").await.is_err());
            assert!(content.read(&StateOwner::System, &name).is_err());
            kv.close().await.unwrap();
            (owner, kv, content)
        })
    };
    assert!(RuntimeLifecycleGuard::acquire(&home).is_err());
    std::fs::write(home.root().join("config.toml"), b"final host write").unwrap();
    lifecycle.finish_retained(owner).unwrap();
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
    assert!(store.handoff_for_finalization(&wrong).is_err());
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
    let mut owner = store.handoff_for_finalization(&home).unwrap();
    owner.record_shutdown_error(StorageError::Internal(
        "injected shutdown close failure".into(),
    ));
    owner.record_shutdown_error(StorageError::Internal(
        "injected second close failure".into(),
    ));
    store.kv().close().await.unwrap();
    assert!(RuntimeLifecycleGuard::acquire(&home).is_err());
    std::fs::write(home.root().join("config.toml"), b"pack despite close error").unwrap();
    let error = lifecycle.finish_retained(owner).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected shutdown close failure")
    );
    assert!(error.to_string().contains("injected second close failure"));
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
    let owner = store.handoff_for_finalization(&home).unwrap();
    std::fs::write(home.root().join("config.toml"), b"keep host evidence").unwrap();
    std::os::unix::fs::symlink(parent.path(), home.root().join("redirect")).unwrap();
    assert!(lifecycle.finish_retained(owner).is_err());
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

struct ReleaseOnDrop(Option<std::sync::Arc<std::sync::Barrier>>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.wait();
        }
    }
}

impl ReleaseOnDrop {
    fn new(release: std::sync::Arc<std::sync::Barrier>) -> Self {
        Self(Some(release))
    }

    fn release(mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.wait();
        }
    }
}

fn assert_busy_handoff_message(message: &str) {
    assert!(
        message.contains("active writers"),
        "expected busy handoff 'active writers', got {message}"
    );
}

fn wait_for_drain_entry(
    reached: std::sync::Arc<std::sync::Barrier>,
) -> tokio::sync::oneshot::Receiver<()> {
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        reached.wait();
        let _ = entered_tx.send(());
    });
    entered_rx
}

async fn retain_while_blocked_commit(
    home: &AstridHome,
    reached: std::sync::Arc<std::sync::Barrier>,
    release: std::sync::Arc<std::sync::Barrier>,
    key: &'static str,
    value: &'static [u8],
) -> (
    crate::principal_state::RuntimePrincipalStore,
    super::super::PendingRuntimeFinalization,
) {
    use std::sync::Arc;

    let store = open_runtime_principal_store(home, quota())
        .await
        .expect("open store");
    store
        .kv()
        .set("system:retirement", "seed", b"before".to_vec())
        .await
        .expect("seed write");
    store.publish_runtime_projection(home).expect("publish");
    store
        .engine
        .gate_next_group_drain(Arc::clone(&reached), Arc::clone(&release));

    let entered_rx = wait_for_drain_entry(Arc::clone(&reached));
    let writer = store.clone();
    let write = tokio::spawn(async move {
        writer
            .kv()
            .set("system:retirement", key, value.to_vec())
            .await
    });
    entered_rx.await.expect("commit entered drain gate");
    write.abort();
    let join = write.await.expect_err("cancelled write must join as error");
    assert!(
        join.is_cancelled(),
        "async waiter must be cancelled while blocking commit stays live"
    );

    let pending = store
        .retain_for_finalization(home)
        .expect("retain pending custody");
    assert!(
        RuntimeLifecycleGuard::acquire(home).is_err(),
        "pending custody must keep the continuous lifecycle lock"
    );
    let Err(busy) = store.handoff_for_finalization(home) else {
        panic!("expected busy handoff during blocked commit");
    };
    assert_busy_handoff_message(&busy.to_string());
    (store, pending)
}

fn assert_reopened_blocked_bytes(home: &AstridHome, old_kv: &dyn crate::KvStore) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("reopen runtime");
    runtime.block_on(async {
        assert!(
            old_kv
                .set("system:retirement", "blocked", b"forbidden".to_vec())
                .await
                .is_err(),
            "old handles must stay revoked after deferred handoff"
        );
        let reopened = open_runtime_principal_store(home, quota())
            .await
            .expect("reopen");
        assert_eq!(
            reopened
                .kv()
                .get("system:retirement", "blocked")
                .await
                .expect("read blocked"),
            Some(b"joined-by-runtime-drop".to_vec())
        );
        assert_eq!(
            reopened
                .kv()
                .get("system:retirement", "seed")
                .await
                .expect("read seed"),
            Some(b"before".to_vec())
        );
        reopened.kv().close().await.expect("close reopened");
    });
}

#[test]
fn pending_custody_waits_for_blocked_commit_across_runtime_drop() {
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::Duration;

    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let reached = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let release_guard = ReleaseOnDrop::new(Arc::clone(&release));
    let (drop_started_tx, drop_started_rx) = mpsc::sync_channel::<()>(1);
    let (drop_done_tx, drop_done_rx) = mpsc::sync_channel::<()>(1);
    let (custody_tx, custody_rx) = mpsc::sync_channel(1);

    let runtime_home = home.clone();
    let reached_for_runtime = Arc::clone(&reached);
    let release_for_runtime = Arc::clone(&release);
    let runtime_thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let (old_kv, pending) = runtime.block_on(async move {
            let (store, pending) = retain_while_blocked_commit(
                &runtime_home,
                reached_for_runtime,
                release_for_runtime,
                "blocked",
                b"joined-by-runtime-drop",
            )
            .await;
            (store.kv(), pending)
        });
        custody_tx
            .send((old_kv, pending))
            .expect("send pending custody");
        drop_started_tx.send(()).expect("signal runtime drop start");
        drop(runtime);
        drop_done_tx.send(()).expect("signal runtime drop complete");
    });

    let (old_kv, pending_custody) = custody_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("pending custody from runtime thread");
    drop_started_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("runtime drop started while gate held");
    assert!(
        drop_done_rx.try_recv().is_err(),
        "runtime drop must still be waiting on the blocked commit"
    );
    release_guard.release();
    drop_done_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("runtime drop completed after gate release");
    runtime_thread.join().expect("runtime thread");

    let owner = pending_custody
        .handoff_for_finalization()
        .expect("handoff after runtime drop");
    assert!(RuntimeLifecycleGuard::acquire(&home).is_err());
    lifecycle.finish_retained(owner).expect("finish retained");
    assert_reopened_blocked_bytes(&home, old_kv.as_ref());
}

#[test]
fn pending_custody_drop_closes_original_engine_without_transfer() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let _lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let store = open_runtime_principal_store(&home, quota()).await.unwrap();
        store.publish_runtime_projection(&home).unwrap();
        let pending = store.retain_for_finalization(&home).unwrap();
        drop(pending);
        assert!(
            store
                .kv()
                .set("system:retirement", "after-drop", b"x".to_vec())
                .await
                .is_err(),
            "abandoning pending custody must close the original engine"
        );
    });
}

#[test]
fn pending_busy_handoff_failure_closes_engine_and_preserves_shutdown_error() {
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::Duration;

    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let _lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let reached = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let release_guard = ReleaseOnDrop::new(Arc::clone(&release));
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let (drop_done_tx, drop_done_rx) = mpsc::sync_channel::<()>(1);

    let runtime_home = home.clone();
    let reached_for_runtime = Arc::clone(&reached);
    let release_for_runtime = Arc::clone(&release);
    let runtime_thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let outcome = runtime.block_on(async move {
            let (store, mut pending) = retain_while_blocked_commit(
                &runtime_home,
                reached_for_runtime,
                release_for_runtime,
                "busy",
                b"in-flight",
            )
            .await;
            pending.record_shutdown_error(StorageError::Internal(
                "injected ancillary close failure".into(),
            ));
            let Err(error) = pending.handoff_for_finalization() else {
                panic!("expected busy handoff failure");
            };
            (store.kv(), error)
        });
        result_tx.send(outcome).expect("send busy failure outcome");
        drop(runtime);
        drop_done_tx.send(()).expect("signal runtime drop complete");
    });

    let (old_kv, error) = result_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("busy failure outcome");
    release_guard.release();
    drop_done_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("runtime drop completed after gate release");
    runtime_thread.join().expect("runtime thread");

    let message = error.to_string();
    assert_busy_handoff_message(&message);
    assert!(
        message.contains("injected ancillary close failure"),
        "ancillary shutdown error must survive busy handoff failure: {message}"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("verify runtime");
    runtime.block_on(async {
        assert!(
            old_kv
                .set("system:retirement", "busy", b"forbidden".to_vec())
                .await
                .is_err(),
            "failed pending handoff must invalidate old handles"
        );
    });
}

#[tokio::test]
async fn pending_wrong_home_retain_rejects_without_closing_live_store() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let wrong = AstridHome::from_path(parent.path().join("wrong"));
    let _lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    store.publish_runtime_projection(&home).unwrap();
    assert!(store.retain_for_finalization(&wrong).is_err());
    store
        .kv()
        .set("system:retirement", "still-live", b"ok".to_vec())
        .await
        .unwrap();
}

#[tokio::test]
async fn pending_replaced_volume_handoff_failure_closes_original_engine() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let _lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    store
        .kv()
        .set("system:retirement", "seed", b"before".to_vec())
        .await
        .unwrap();
    store.publish_runtime_projection(&home).unwrap();
    let mut pending = store.retain_for_finalization(&home).unwrap();
    pending.record_shutdown_error(StorageError::Internal(
        "injected ancillary close failure".into(),
    ));
    let volume = home.storage_volume_path();
    let backup = parent.path().join("astrid.volume.replaced");
    std::fs::rename(&volume, &backup).unwrap();
    std::fs::write(&volume, b"not-a-volume").unwrap();
    let Err(error) = pending.handoff_for_finalization() else {
        panic!("expected replaced-volume handoff failure");
    };
    let message = error.to_string();
    assert!(
        message.contains("injected ancillary close failure"),
        "ancillary shutdown error must survive wrong-binding handoff failure: {message}"
    );
    assert!(
        store
            .kv()
            .set("system:retirement", "after-fail", b"x".to_vec())
            .await
            .is_err(),
        "failed pending handoff must invalidate old handles"
    );
}

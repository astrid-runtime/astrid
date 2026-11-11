//! Finalization must survive task-runtime teardown with closed former views.
use super::drain_gate::{BlockedCommitGate, ENTRY_OBSERVE_TIMEOUT};
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

fn assert_busy_handoff_message(message: &str) {
    assert!(
        message.contains("active writers"),
        "expected busy handoff 'active writers', got {message}"
    );
}

async fn retain_while_blocked_commit(
    home: &AstridHome,
    key: &'static str,
    value: &'static [u8],
) -> Result<
    (
        crate::principal_state::RuntimePrincipalStore,
        super::super::PendingRuntimeFinalization,
        BlockedCommitGate,
    ),
    String,
> {
    let store = open_runtime_principal_store(home, quota())
        .await
        .map_err(|error| error.to_string())?;
    store
        .kv()
        .set("system:retirement", "seed", b"before".to_vec())
        .await
        .map_err(|error| error.to_string())?;
    store
        .publish_runtime_projection(home)
        .map_err(|error| error.to_string())?;

    let (entered_rx, release_tx) = store.engine.gate_next_group_drain_channel();
    let mut gate = BlockedCommitGate::from_channel_gate(entered_rx, release_tx);

    let writer = store.clone();
    let write = tokio::spawn(async move {
        writer
            .kv()
            .set("system:retirement", key, value.to_vec())
            .await
    });
    tokio::task::block_in_place(|| gate.wait_for_entry(ENTRY_OBSERVE_TIMEOUT))
        .map_err(|error| error.to_string())?;
    write.abort();
    let join = write.await.expect_err("cancelled write must join as error");
    if !join.is_cancelled() {
        return Err("async waiter must be cancelled while blocking commit stays live".to_owned());
    }

    let pending = store
        .retain_for_finalization(home)
        .map_err(|error| error.to_string())?;
    if RuntimeLifecycleGuard::acquire(home).is_ok() {
        return Err("pending custody must keep the continuous lifecycle lock".to_owned());
    }
    let Err(busy) = store.handoff_for_finalization(home) else {
        return Err("expected busy handoff during blocked commit".to_owned());
    };
    assert_busy_handoff_message(&busy.to_string());
    Ok((store, pending, gate))
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
fn retain_while_blocked_commit_reports_open_failure_before_entry() {
    use std::sync::mpsc;
    use std::time::Duration;

    let parent = tempfile::tempdir().unwrap();
    let home_path = parent.path().join("runtime");
    std::fs::write(&home_path, b"not-a-directory").unwrap();
    let home = AstridHome::from_path(home_path);
    let (result_tx, result_rx) = mpsc::sync_channel(1);

    let runtime_home = home.clone();
    let worker = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let outcome = runtime.block_on(async move {
            retain_while_blocked_commit(&runtime_home, "blocked", b"never-written").await
        });
        result_tx
            .send(outcome.map(|_| ()))
            .expect("report pre-entry open outcome");
        drop(runtime);
    });

    let result = result_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("pre-entry open failure must be reported");
    let error = result.expect_err("file-as-root must fail before drain entry");
    assert!(!error.is_empty(), "{error}");
    worker
        .join()
        .expect("worker must join without hanging on an unentered drain gate");
}

#[test]
fn pending_custody_waits_for_blocked_commit_across_runtime_drop() {
    use std::sync::mpsc;
    use std::time::Duration;

    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let (drop_started_tx, drop_started_rx) = mpsc::sync_channel::<()>(1);
    let (drop_done_tx, drop_done_rx) = mpsc::sync_channel::<()>(1);
    let (custody_tx, custody_rx) = mpsc::sync_channel(1);

    let runtime_home = home.clone();
    let runtime_thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let outcome = runtime.block_on(async move {
            retain_while_blocked_commit(&runtime_home, "blocked", b"joined-by-runtime-drop").await
        });
        match outcome {
            Ok((store, pending, gate)) => {
                custody_tx
                    .send(Ok((store.kv(), pending, gate)))
                    .expect("send pending custody");
                drop_started_tx.send(()).expect("signal runtime drop start");
                drop(runtime);
                drop_done_tx.send(()).expect("signal runtime drop complete");
            },
            Err(error) => {
                let _ = custody_tx.send(Err(error));
            },
        }
    });

    let custody = match custody_rx.recv_timeout(Duration::from_secs(20)) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => panic!("blocked-commit worker failed before custody: {error}"),
        Err(_) => panic!("timed out waiting for pending custody from runtime thread"),
    };
    let (old_kv, pending_custody, gate) = custody;
    drop_started_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("runtime drop started while gate held");
    assert!(
        drop_done_rx.try_recv().is_err(),
        "runtime drop must still be waiting on the blocked commit"
    );
    assert!(
        gate.entered(),
        "runtime drop wait requires an entered drain gate"
    );
    gate.release();
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
    use std::sync::mpsc;
    use std::time::Duration;

    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let _lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let (drop_done_tx, drop_done_rx) = mpsc::sync_channel::<()>(1);

    let runtime_home = home.clone();
    let runtime_thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let outcome = runtime.block_on(async move {
            let (store, mut pending, gate) =
                retain_while_blocked_commit(&runtime_home, "busy", b"in-flight").await?;
            pending.record_shutdown_error(StorageError::Internal(
                "injected ancillary close failure".into(),
            ));
            let Err(error) = pending.handoff_for_finalization() else {
                return Err("expected busy handoff failure".to_owned());
            };
            Ok((store.kv(), error, gate))
        });
        match outcome {
            Ok((old_kv, error, gate)) => {
                result_tx
                    .send(Ok((old_kv, error, gate)))
                    .expect("send busy failure outcome");
                drop(runtime);
                drop_done_tx.send(()).expect("signal runtime drop complete");
            },
            Err(error) => {
                let _ = result_tx.send(Err(error));
            },
        }
    });

    let (old_kv, error, gate) = match result_rx.recv_timeout(Duration::from_secs(20)) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => panic!("busy handoff worker failed before entry: {error}"),
        Err(_) => panic!("timed out waiting for busy failure outcome"),
    };
    assert!(
        gate.entered(),
        "busy handoff path requires entered drain gate"
    );
    gate.release();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn busy_engine_handoff_failure_restores_old_staging_begin() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let _lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();

    // Open before arming so a fresh-root failure cannot leave a release sender
    // outstanding against an unstarted drain worker.
    let store = open_runtime_principal_store(&home, quota())
        .await
        .expect("open store");
    store
        .kv()
        .set("system:retirement", "seed", b"before".to_vec())
        .await
        .unwrap();
    store.publish_runtime_projection(&home).unwrap();
    let old_area = store.staging();
    old_area
        .begin(
            StateOwner::System,
            ContentName::new("var/tmp/pre-busy.bin").unwrap(),
            crate::content::ChunkingProfile::ASTRID_V1,
        )
        .unwrap();
    // Drop the open writer so staging reserve can succeed; only the engine is busy.
    drop(old_area);

    let (entered_rx, release_tx) = store.engine.gate_next_group_drain_channel();
    let mut gate = BlockedCommitGate::from_channel_gate(entered_rx, release_tx);
    let writer = store.clone();
    let write = tokio::spawn(async move {
        writer
            .kv()
            .set("system:retirement", "busy", b"in-flight".to_vec())
            .await
    });
    tokio::task::block_in_place(|| gate.wait_for_entry(ENTRY_OBSERVE_TIMEOUT))
        .expect("commit entered drain gate");
    write.abort();
    let join = write.await.expect_err("cancelled write must join as error");
    assert!(join.is_cancelled());

    let Err(error) = store.handoff_for_finalization(&home) else {
        panic!("expected busy engine handoff failure");
    };
    assert_busy_handoff_message(&error.to_string());

    // Staging reserve rolled back via token Drop; begin must work again.
    store
        .staging()
        .begin(
            StateOwner::System,
            ContentName::new("var/tmp/after-busy-fail.bin").unwrap(),
            crate::content::ChunkingProfile::ASTRID_V1,
        )
        .expect("failed engine handoff must restore open staging");

    gate.release();
    let _ = home;
}

#[tokio::test]
async fn old_staging_facade_is_closed_after_successful_handoff() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    let old_area = store.staging();
    old_area
        .begin(
            StateOwner::System,
            ContentName::new("var/tmp/pre-handoff.bin").unwrap(),
            crate::content::ChunkingProfile::ASTRID_V1,
        )
        .unwrap();
    let finalization = store.handoff_for_finalization(&home).unwrap();
    assert!(finalization.store.staging.get().is_none());
    let err = old_area
        .begin(
            StateOwner::System,
            ContentName::new("var/tmp/after-handoff.bin").unwrap(),
            crate::content::ChunkingProfile::ASTRID_V1,
        )
        .expect_err("old staging facade must close after handoff");
    assert!(
        err.to_string()
            .contains("runtime staging is closed after projection retirement"),
        "{err}"
    );
    assert!(
        old_area
            .ready()
            .expect_err("old ready must close after handoff")
            .to_string()
            .contains("runtime staging is closed after projection retirement")
    );
    drop(finalization);
    drop(store);
}

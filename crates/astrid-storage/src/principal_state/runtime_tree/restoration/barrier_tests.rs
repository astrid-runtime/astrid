//! Faults occur after real sync calls; these test receipt/namespace recovery,
//! not physical power cuts or whether hardware honored a flush.

use std::fs;
use std::sync::Arc;

use super::restore_with_sync;
use crate::principal_state::runtime_tree::{active, transition_retiring_projection};
use crate::principal_state::{RuntimePrincipalStore, StateOwner};
use crate::{ContentName, KvQuotaResolver, StorageError, open_runtime_principal_store};
use astrid_core::dirs::AstridHome;

const EXISTING: &str = "restoration/existing.conf";
const ABSENT: &str = "restoration/volume-only.conf";
const BEFORE: &[u8] = b"previous host generation\n";
const AUTHORITATIVE: &[u8] = b"durable volume generation\n";

fn unlimited() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

async fn fixture() -> (tempfile::TempDir, AstridHome, RuntimePrincipalStore) {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited())
        .await
        .unwrap();
    fs::create_dir_all(home.root().join("restoration")).unwrap();
    for name in [EXISTING, ABSENT, "zz-redirected.conf"] {
        fs::write(home.root().join(name), AUTHORITATIVE).unwrap();
    }
    store.publish_runtime_projection(&home).unwrap();
    transition_retiring_projection(&home, &store).unwrap();
    // Model stale and absent host files after a durable RETIRING receipt.
    // Volume contents and receipt inventory stay mutually consistent.
    fs::write(home.root().join(EXISTING), BEFORE).unwrap();
    fs::remove_file(home.root().join(ABSENT)).unwrap();
    fs::remove_file(home.root().join("zz-redirected.conf")).unwrap();
    (directory, home, store)
}

fn injected(point: &str) -> StorageError {
    StorageError::Connection(format!("injected projection sync failure: {point}"))
}

fn assert_volume_authority(home: &AstridHome, store: &RuntimePrincipalStore) {
    assert_eq!(
        active::read(home, store).unwrap().unwrap().phase(),
        super::super::ReceiptPhase::Retiring
    );
    for name in [EXISTING, ABSENT] {
        assert_eq!(
            store
                .content()
                .read(&StateOwner::System, &ContentName::new(name).unwrap())
                .unwrap(),
            Some(AUTHORITATIVE.to_vec())
        );
    }
}

async fn assert_reopens_authoritatively(home: &AstridHome) {
    let store = open_runtime_principal_store(home, unlimited())
        .await
        .unwrap();
    for name in [EXISTING, ABSENT] {
        assert_eq!(fs::read(home.root().join(name)).unwrap(), AUTHORITATIVE);
    }
    assert_eq!(
        active::read(home, &store).unwrap().unwrap().phase(),
        super::super::ReceiptPhase::Active
    );
}

#[tokio::test]
async fn terminal_projection_sync_error_rolls_back_and_preserves_volume_authority() {
    let (_directory, home, store) = fixture().await;
    let mut syncs = 0;
    let error = restore_with_sync(&home, &store, &store.content(), || {
        syncs += 1;
        if syncs == 1 {
            Err(injected("terminal"))
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert!(error.to_string().contains("terminal"));
    assert_eq!(syncs, 2, "failed restore and completed rollback both fence");
    assert_eq!(fs::read(home.root().join(EXISTING)).unwrap(), BEFORE);
    assert!(!home.root().join(ABSENT).exists());
    assert_volume_authority(&home, &store);
    drop(store);
    assert_reopens_authoritatively(&home).await;
}

#[tokio::test]
async fn rollback_sync_error_keeps_retiring_recovery_intent() {
    let (_directory, home, store) = fixture().await;
    let mut syncs = 0;
    let error = restore_with_sync(&home, &store, &store.content(), || {
        syncs += 1;
        Err(injected("terminal and rollback"))
    })
    .unwrap_err();
    assert!(error.to_string().contains("rollback failures"));
    assert_eq!(syncs, 2);
    assert_volume_authority(&home, &store);
    drop(store);
    assert_reopens_authoritatively(&home).await;
}

#[tokio::test]
async fn successful_restore_fences_once_before_returning() {
    let (_directory, home, store) = fixture().await;
    let mut syncs = 0;
    restore_with_sync(&home, &store, &store.content(), || {
        syncs += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(syncs, 1);
    for name in [EXISTING, ABSENT] {
        assert_eq!(fs::read(home.root().join(name)).unwrap(), AUTHORITATIVE);
    }
    assert_volume_authority(&home, &store);
}

#[cfg(unix)]
#[tokio::test]
async fn redirected_late_destination_rolls_back_without_touching_target() {
    let (_directory, home, store) = fixture().await;
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("untouched");
    fs::write(&target, b"outside bytes").unwrap();
    let name = ContentName::new("zz-redirected.conf").unwrap();
    std::os::unix::fs::symlink(&target, home.root().join(name.as_str())).unwrap();
    let mut syncs = 0;
    assert!(
        restore_with_sync(&home, &store, &store.content(), || {
            syncs += 1;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(syncs, 1, "error rollback still fences");
    assert_eq!(fs::read(target).unwrap(), b"outside bytes");
    assert_eq!(fs::read(home.root().join(EXISTING)).unwrap(), BEFORE);
    assert!(!home.root().join(ABSENT).exists());
    assert_volume_authority(&home, &store);
}

#[tokio::test]
async fn rollback_attempts_every_destination_after_one_fails() {
    let (_directory, home, store) = fixture().await;
    let mut prepared = super::record_intent(&home, &store).unwrap();
    let writer = prepared.writer().unwrap();
    let mut spool = super::rollback::RollbackSpool::default();

    // Capture a real prior generation, then replace the live path with a directory
    // so rollback restore fails without manufacturing spool tokens.
    writer
        .write(std::path::Path::new("blocked"), b"prior")
        .unwrap();
    let previous_blocked = spool
        .capture(writer, std::path::Path::new("blocked"))
        .unwrap();
    writer
        .write(std::path::Path::new("blocked"), b"new")
        .unwrap();
    fs::remove_file(home.root().join("blocked")).unwrap();
    fs::create_dir(home.root().join("blocked")).unwrap();

    let previous_removed = spool
        .capture(writer, std::path::Path::new("removed"))
        .unwrap();
    writer
        .write(std::path::Path::new("removed"), b"remove")
        .unwrap();

    let written = vec![
        super::WrittenFile {
            name: ContentName::new("removed").unwrap(),
            previous: previous_removed,
        },
        super::WrittenFile {
            name: ContentName::new("blocked").unwrap(),
            previous: previous_blocked,
        },
    ];
    let errors = super::rollback(&home, Some(&prepared), &mut spool, written, &mut || Ok(()));
    assert_eq!(errors.len(), 1, "one destination should fail: {errors:?}");
    assert!(
        !home.root().join("removed").exists(),
        "later rollback destination was skipped"
    );
    assert!(
        home.root().join("blocked").is_dir(),
        "failed rollback destination must remain untouched"
    );
}

#[tokio::test]
async fn failed_restore_keeps_private_directory_marker_under_retiring_authority() {
    use crate::{AstridFilesystem, FilesystemPath};

    let (_directory, home, store) = fixture().await;
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::System);
    let name = FilesystemPath::new("empty-directory").unwrap();
    filesystem.create_dir(&name).unwrap();
    assert!(!home.root().join("empty-directory").exists());
    let mut syncs = 0;
    let error = restore_with_sync(&home, &store, &store.content(), || {
        syncs += 1;
        if syncs == 1 {
            Err(injected("terminal"))
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert!(error.to_string().contains("terminal"));
    assert_eq!(syncs, 2);
    // File rollback never removes directories: the durable RETIRING inventory
    // remains authority for these private, idempotently restorable markers.
    let path = home.root().join("empty-directory");
    astrid_core::platform_fs::validate_private_directory(&path).unwrap();
    filesystem.stat(&name).unwrap();
    assert_volume_authority(&home, &store);
    drop(filesystem);
    drop(store);
    assert_reopens_authoritatively(&home).await;
    assert!(path.is_dir());
}

#[tokio::test]
async fn retiring_restart_rejects_unreceipted_atomic_looking_file() {
    let (_directory, home, store) = fixture().await;
    let staging = home
        .root()
        .join(".astrid-private-00000000000040008000000000000002");
    astrid_core::platform_fs::atomic_write_private_file(&staging, b"unexplained bytes").unwrap();
    assert_volume_authority(&home, &store);
    drop(store);
    let error = open_runtime_principal_store(&home, unlimited())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("unreceipted host file"));
    assert_eq!(fs::read(staging).unwrap(), b"unexplained bytes");
}

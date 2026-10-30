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

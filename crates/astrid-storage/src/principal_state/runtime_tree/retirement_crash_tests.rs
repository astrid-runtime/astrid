//! Deterministic retirement-error and crash-state recovery tests. These model
//! lost/resurrected namespace changes; they do not emulate physical power cuts
//! or assert that a device completed a hardware cache flush.

use std::fs::{self, File};
use std::sync::Arc;

use astrid_core::dirs::AstridHome;

use super::{ReceiptPhase, active, pack_and_retire_projection_with_retirement};
use crate::principal_state::{RuntimePrincipalStore, StateOwner};
use crate::{ContentName, KvQuotaResolver, StorageError, open_runtime_principal_store};

const ABSENT: &str = "projection-absent/state.conf";
const RESURRECTED: &str = "projection-resurrected/state.conf";
const SURVIVING: &str = "projection-surviving/state.conf";
const PUBLISHED: &[u8] = b"volume-authoritative generation\n";
const STALE: &[u8] = b"resurrected stale host generation\n";

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

async fn fixture() -> (tempfile::TempDir, AstridHome, RuntimePrincipalStore) {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    for name in [ABSENT, RESURRECTED, SURVIVING] {
        let path = home.root().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, PUBLISHED).unwrap();
    }
    (directory, home, store)
}

fn injected_failure(point: &str) -> StorageError {
    StorageError::Connection(format!("injected retirement failure: {point}"))
}

fn assert_receipt(home: &AstridHome, store: &RuntimePrincipalStore, phase: ReceiptPhase) {
    let receipt = active::read(home, store)
        .unwrap()
        .expect("receipt must remain durable");
    assert_eq!(receipt.phase(), phase);
    for name in [ABSENT, RESURRECTED, SURVIVING] {
        assert!(
            receipt.contains_inventory_name(name),
            "missing receipt name {name}"
        );
        let name = ContentName::new(name).unwrap();
        assert_eq!(
            store.content().read(&StateOwner::System, &name).unwrap(),
            Some(PUBLISHED.to_vec())
        );
    }
}

fn unlink_partial_projection(home: &AstridHome) {
    for name in [ABSENT, RESURRECTED] {
        let path = home.root().join(name);
        fs::remove_file(&path).unwrap();
        // The child-directory fence precedes its unlink, just as in real
        // retirement. The test chooses whether the root fence then succeeds.
        File::open(path.parent().unwrap())
            .unwrap()
            .sync_all()
            .unwrap();
        fs::remove_dir(path.parent().unwrap()).unwrap();
    }
}

async fn assert_authoritative_recovery(home: &AstridHome) {
    assert!(!home.root().join(ABSENT).exists());
    let resurrected = home.root().join(RESURRECTED);
    fs::create_dir_all(resurrected.parent().unwrap()).unwrap();
    fs::write(&resurrected, STALE).unwrap();
    // A different receipted file survives cleanup but its host bytes are also
    // stale. Neither surviving nor resurrected bytes may overwrite the volume.
    fs::write(home.root().join(SURVIVING), STALE).unwrap();
    let reopened = open_runtime_principal_store(home, unlimited_quota())
        .await
        .unwrap();
    assert_receipt(home, &reopened, ReceiptPhase::Active);
    for name in [ABSENT, RESURRECTED, SURVIVING] {
        assert_eq!(fs::read(home.root().join(name)).unwrap(), PUBLISHED);
    }
}

#[tokio::test]
async fn unlink_before_intermediate_sync_error_recovers_retiring_volume_authority() {
    let (_directory, home, store) = fixture().await;
    let error = pack_and_retire_projection_with_retirement(&home, &store, |home| {
        unlink_partial_projection(home);
        Err(injected_failure("after unlink before root directory sync"))
    })
    .unwrap_err();
    assert!(error.to_string().contains("before root directory sync"));
    assert_receipt(&home, &store, ReceiptPhase::Retiring);
    drop(store);
    assert_authoritative_recovery(&home).await;
}

#[tokio::test]
async fn intermediate_sync_then_error_recovers_retiring_volume_authority() {
    let (_directory, home, store) = fixture().await;
    let error = pack_and_retire_projection_with_retirement(&home, &store, |home| {
        unlink_partial_projection(home);
        File::open(home.root()).unwrap().sync_all().unwrap();
        Err(injected_failure(
            "after successful intermediate directory sync",
        ))
    })
    .unwrap_err();
    assert!(error.to_string().contains("after successful intermediate"));
    assert_receipt(&home, &store, ReceiptPhase::Retiring);
    drop(store);
    assert_authoritative_recovery(&home).await;
}

#[tokio::test]
async fn final_retirement_error_after_cleanup_keeps_retiring_receipt() {
    let (_directory, home, store) = fixture().await;
    let error = pack_and_retire_projection_with_retirement(&home, &store, |home| {
        // Use real cleanup to reach the completely removed host projection,
        // then inject the error a final hardware flush could report. This
        // verifies receipt handling for that namespace state, not hardware.
        super::retire_projection(home)?;
        Err(injected_failure("final hardware flush"))
    })
    .unwrap_err();
    assert!(error.to_string().contains("final hardware flush"));
    assert_eq!(fs::read_dir(home.root()).unwrap().count(), 1);
    assert_receipt(&home, &store, ReceiptPhase::Retiring);
    drop(store);
    // Even wholly absent host projection entries may return after a crash;
    // model one resurrected name while the others remain absent.
    let resurrected = home.root().join(RESURRECTED);
    fs::create_dir_all(resurrected.parent().unwrap()).unwrap();
    fs::write(resurrected, STALE).unwrap();
    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_receipt(&home, &reopened, ReceiptPhase::Active);
    for name in [ABSENT, RESURRECTED, SURVIVING] {
        assert_eq!(fs::read(home.root().join(name)).unwrap(), PUBLISHED);
    }
}

#[tokio::test]
async fn retiring_recovery_rejects_unreceipted_file_and_preserves_bytes() {
    let (_directory, home, store) = fixture().await;
    pack_and_retire_projection_with_retirement(&home, &store, |home| {
        unlink_partial_projection(home);
        Err(injected_failure("partial cleanup"))
    })
    .unwrap_err();
    assert_receipt(&home, &store, ReceiptPhase::Retiring);
    let extra = home.root().join("unreceipted.conf");
    fs::write(&extra, b"never admitted; preserve these bytes\n").unwrap();
    let error = pack_and_retire_projection_with_retirement(&home, &store, |_| {
        panic!("unreceipted host names must fail before retirement")
    })
    .unwrap_err();
    assert!(
        error.to_string().contains("unreceipted host file"),
        "{error}"
    );
    assert_receipt(&home, &store, ReceiptPhase::Retiring);
    drop(store);
    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("restart must reject unreceipted host names");
    };
    assert!(
        error.to_string().contains("unreceipted host file"),
        "{error}"
    );
    assert_eq!(
        fs::read(extra).unwrap(),
        b"never admitted; preserve these bytes\n"
    );
    assert!(
        !home.root().join(ABSENT).exists(),
        "rejected recovery must not restore over an unsafe host tree"
    );
    assert_eq!(fs::read(home.root().join(SURVIVING)).unwrap(), PUBLISHED);
}

//! Causal regressions for intent-scoped restoration temporary discharge.

use std::fs;
use std::sync::Arc;

#[cfg(unix)]
use crate::ContentName;
use crate::principal_state::runtime_tree::{active, transition_retiring_projection};
use crate::principal_state::{RuntimePrincipalStore, StateOwner};
use crate::{KvQuotaResolver, open_runtime_principal_store};
use astrid_core::dirs::AstridHome;

const EXISTING: &str = "restoration/existing.conf";
const ABSENT: &str = "restoration/volume-only.conf";
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
    fs::write(home.root().join(EXISTING), b"previous host generation\n").unwrap();
    fs::remove_file(home.root().join(ABSENT)).unwrap();
    fs::remove_file(home.root().join("zz-redirected.conf")).unwrap();
    (directory, home, store)
}

// Scoped-temp fixtures model materialization after legacy cleanup, which is
// the production boundary that upgrades an unscoped RETIRING receipt.
fn scoped_intent<'a>(
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
) -> super::PreparedRestoration<'a> {
    let mut prepared = super::record_intent(home, store).unwrap();
    prepared.ensure_scoped_intent().unwrap();
    prepared
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
fn plant_private(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn scoped_staging_temps_are_discharged_on_retiring_reopen() {
    let (_directory, home, store) = fixture().await;
    let prepared = scoped_intent(&home, &store);
    let scope = prepared
        .staging_scope()
        .expect("bootstrap restoration intent mints a durable scope");
    let root_temp = home.root().join(scope.temporary_basename());
    let nested_temp = home
        .root()
        .join("restoration")
        .join(scope.temporary_basename());
    plant_private(&root_temp, b"scoped root residue");
    plant_private(&nested_temp, b"scoped nested residue");
    assert_volume_authority(&home, &store);
    drop(prepared);
    drop(store);
    assert_reopens_authoritatively(&home).await;
    assert!(!root_temp.exists(), "root scoped temp must be discharged");
    assert!(
        !nested_temp.exists(),
        "nested scoped temp must be discharged"
    );
}

#[cfg(unix)]
async fn reject_unreceipted_temp(
    plant: impl FnOnce(
        &AstridHome,
        astrid_core::platform_fs::StagingScope,
    ) -> (std::path::PathBuf, &'static [u8]),
) {
    let (_directory, home, store) = fixture().await;
    let prepared = scoped_intent(&home, &store);
    let scope = prepared
        .staging_scope()
        .expect("bootstrap restoration intent mints a durable scope");
    let (path, bytes) = plant(&home, scope);
    drop(prepared);
    drop(store);
    let error = open_runtime_principal_store(&home, unlimited())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("unreceipted host file"));
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[cfg(unix)]
#[tokio::test]
async fn wrong_epoch_temp_remains_rejected() {
    reject_unreceipted_temp(|home, scope| {
        let foreign =
            astrid_core::platform_fs::StagingScope::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();
        assert_ne!(scope, foreign);
        let wrong = home.root().join(foreign.temporary_basename());
        plant_private(&wrong, b"wrong epoch");
        (wrong, b"wrong epoch")
    })
    .await;
}

#[cfg(unix)]
#[tokio::test]
async fn legacy_shape_temp_remains_rejected_under_scoped_intent() {
    reject_unreceipted_temp(|home, _scope| {
        let legacy = home
            .root()
            .join(".astrid-private-00000000000040008000000000000002");
        plant_private(&legacy, b"legacy shape");
        (legacy, b"legacy shape")
    })
    .await;
}

#[cfg(unix)]
#[tokio::test]
async fn catalogue_collision_keeps_scoped_name_unreceipted() {
    let (_directory, home, store) = fixture().await;
    let prepared = scoped_intent(&home, &store);
    let scope = prepared
        .staging_scope()
        .expect("bootstrap restoration intent mints a durable scope");
    let basename = scope.temporary_basename();
    let relative = format!("restoration/{basename}");
    let path = home.root().join(&relative);
    plant_private(&path, b"collision bytes");
    let name = ContentName::new(&relative).unwrap();
    // Catalogue presence without inventory membership must not authorize delete.
    store
        .content()
        .put(&StateOwner::System, &name, b"catalogued")
        .unwrap();
    store.content().flush().unwrap();
    drop(prepared);
    drop(store);
    let error = open_runtime_principal_store(&home, unlimited())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("unreceipted host file"));
    assert_eq!(fs::read(&path).unwrap(), b"collision bytes");
}

#[cfg(unix)]
#[tokio::test]
async fn legacy_schema1_retiring_rejects_scoped_looking_temp() {
    let (_directory, home, store) = fixture().await;
    // fixture already published a schema-1 Retiring receipt via
    // transition_retiring_projection (no staging scope).
    let scope =
        astrid_core::platform_fs::StagingScope::parse("cccccccccccccccccccccccccccccccc").unwrap();
    let staging = home.root().join(scope.temporary_basename());
    plant_private(&staging, b"no schema2 authority");
    assert_volume_authority(&home, &store);
    drop(store);
    let error = open_runtime_principal_store(&home, unlimited())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("unreceipted host file"));
    assert_eq!(fs::read(&staging).unwrap(), b"no schema2 authority");
}

#[tokio::test]
async fn record_intent_refresh_retains_durable_staging_scope() {
    let (_directory, home, store) = fixture().await;
    let first = scoped_intent(&home, &store);
    let scope = first
        .staging_scope()
        .expect("bootstrap restoration intent mints a durable scope");
    drop(first);
    let second = super::record_intent(&home, &store).unwrap();
    assert_eq!(second.staging_scope(), Some(scope));
    let receipt = active::read(&home, &store).unwrap().unwrap();
    assert_eq!(receipt.staging_scope(), Some(scope));
}

#[cfg(unix)]
#[tokio::test]
async fn staging_shaped_directory_spoof_is_rejected() {
    let (_directory, home, store) = fixture().await;
    let prepared = scoped_intent(&home, &store);
    let scope = prepared
        .staging_scope()
        .expect("bootstrap restoration intent mints a durable scope");
    let spoof = home.root().join(format!(
        ".astrid-private-{}-dddddddddddddddddddddddddddddddd",
        scope.as_hex()
    ));
    fs::create_dir(&spoof).unwrap();
    drop(prepared);
    drop(store);
    let error = open_runtime_principal_store(&home, unlimited())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("unreceipted host file"));
    assert!(spoof.is_dir());
}

#[cfg(unix)]
#[tokio::test]
async fn scoped_temp_under_unrelated_parent_is_preserved() {
    let (_directory, home, store) = fixture().await;
    let prepared = scoped_intent(&home, &store);
    let orphan = home.root().join("unrelated").join(
        prepared
            .staging_scope()
            .expect("bootstrap restoration intent mints a durable scope")
            .temporary_basename(),
    );
    plant_private(&orphan, b"not a writer parent");
    drop(prepared);
    drop(store);
    let error = open_runtime_principal_store(&home, unlimited())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("unreceipted host file"));
    assert_eq!(fs::read(&orphan).unwrap(), b"not a writer parent");
}

#[cfg(unix)]
#[tokio::test]
async fn partial_cleanup_failure_retries_with_the_same_durable_scope() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_directory, home, store) = fixture().await;
    let prepared = scoped_intent(&home, &store);
    let scope = prepared
        .staging_scope()
        .expect("bootstrap restoration intent mints a durable scope");
    let first = home.root().join(format!(
        ".astrid-private-{scope}-00000000000000000000000000000001"
    ));
    let second = home.root().join(format!(
        ".astrid-private-{scope}-00000000000000000000000000000002"
    ));
    plant_private(&first, b"first authorized residue");
    plant_private(&second, b"second authorized residue");
    fs::set_permissions(&second, fs::Permissions::from_mode(0o644)).unwrap();
    drop(prepared);
    drop(store);
    assert!(
        open_runtime_principal_store(&home, unlimited())
            .await
            .is_err()
    );
    assert!(
        !first.exists(),
        "first unlink must have exercised partial cleanup"
    );
    assert_eq!(fs::read(&second).unwrap(), b"second authorized residue");
    fs::set_permissions(&second, fs::Permissions::from_mode(0o600)).unwrap();
    assert_reopens_authoritatively(&home).await;
    assert!(
        !second.exists(),
        "retry must retain original scope authority"
    );
}

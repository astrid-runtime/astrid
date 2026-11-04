//! Regression coverage for stopped/pack scoped cleanup authority.
//!
//! Drive public open/reopen/pack (and same-crate `stopped_recovery::recover`
//! already used by `key_recovery_tests`) with production error strings. No
//! mirrored bookkeeping. New-scope and legacy shape stay separate fixtures.

#![cfg(unix)]

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::platform_fs::StagingScope;

use crate::principal_state::RuntimePrincipalStore;
use crate::{ContentName, KvQuotaResolver, StateOwner, open_runtime_principal_store};

fn quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

fn plant_private(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if let Some(parent) = path.parent() {
        astrid_core::platform_fs::ensure_private_directory(parent).unwrap();
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

/// Packed volume with live store still open — mirrors `key_recovery_tests`.
async fn packed_open_home() -> (
    tempfile::TempDir,
    AstridHome,
    RuntimePrincipalStore,
    [u8; 32],
) {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    home.ensure().unwrap();
    let authority = [7u8; 32];
    astrid_core::platform_fs::ensure_private_directory(&home.keys_dir()).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &authority)
        .unwrap();
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    store.pack_and_retire_runtime_projection(&home).unwrap();
    (root, home, store, authority)
}

fn plant_replacement_key(home: &AstridHome) {
    astrid_core::platform_fs::ensure_private_directory(&home.keys_dir()).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &[9; 32])
        .unwrap();
}

fn publish_key_only_scoped_retiring(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StagingScope {
    let scope = StagingScope::new();
    let entries = super::active_projection_entries(home, store)
        .unwrap()
        .into_iter()
        .filter(|entry| entry.name.as_str() == super::RUNTIME_KEY_PROJECTION)
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1, "fixture must retain volume runtime key");
    let receipt =
        super::receipt_ingest(home, super::ReceiptPhase::Retiring, &entries, Some(scope)).unwrap();
    store
        .replace_contiguous_files_removing_exact(StateOwner::System, [receipt], &[], None)
        .unwrap();
    store.content().flush().unwrap();
    scope
}

fn durable_scope(home: &AstridHome, store: &RuntimePrincipalStore) -> StagingScope {
    super::active::read(home, store)
        .unwrap()
        .unwrap()
        .staging_scope()
        .expect("schema-2 RETIRING intent must record a durable scope")
}

#[tokio::test]
async fn stopped_scoped_sentinel_staging_is_discharged_on_reopen() {
    let (_root, home, store, authority) = packed_open_home().await;
    plant_replacement_key(&home);
    assert!(
        super::stopped_recovery::recover(&home, &store)
            .unwrap()
            .is_some()
    );
    let scope = durable_scope(&home, &store);
    let staged = home.root().join("etc").join(scope.temporary_basename());
    plant_private(&staged, b"incomplete scoped sentinel");
    drop(store);

    home.ensure().unwrap();
    let store = open_runtime_principal_store(&home, quota())
        .await
        .expect("exact-scope sentinel residue must reopen");
    assert!(!staged.exists(), "scoped etc residue must be discharged");
    assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), authority);
    store.pack_and_retire_runtime_projection(&home).unwrap();
}

#[tokio::test]
async fn stopped_scoped_catalogue_collision_preserves_etc_temp() {
    let (_root, home, store, _) = packed_open_home().await;
    plant_replacement_key(&home);
    assert!(
        super::stopped_recovery::recover(&home, &store)
            .unwrap()
            .is_some()
    );
    let scope = durable_scope(&home, &store);
    let basename = scope.temporary_basename();
    let relative = format!("etc/{basename}");
    let staged = home.root().join(&relative);
    plant_private(&staged, b"catalogue collision bytes");
    let name = ContentName::new(&relative).unwrap();
    store
        .content()
        .put(&StateOwner::System, &name, b"catalogued")
        .unwrap();
    store.content().flush().unwrap();
    drop(store);

    home.ensure().unwrap();
    let error = open_runtime_principal_store(&home, quota())
        .await
        .err()
        .expect("catalogue collision must fail closed");
    assert!(
        error
            .to_string()
            .contains("sentinel staging entry lacks original inventory authority"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&staged).unwrap(),
        b"catalogue collision bytes"
    );
}

#[tokio::test]
async fn schema1_stopped_scoped_etc_is_rejected_without_delete() {
    let (_root, home, store, _) = packed_open_home().await;
    plant_replacement_key(&home);
    // Establish volume inventory, then downgrade to schema-1 (no scope).
    assert!(
        super::stopped_recovery::recover(&home, &store)
            .unwrap()
            .is_some()
    );
    let entries = super::active_projection_entries(&home, &store).unwrap();
    let receipt =
        super::receipt_ingest(&home, super::ReceiptPhase::Retiring, &entries, None).unwrap();
    store
        .replace_contiguous_files_removing_exact(StateOwner::System, [receipt], &[], None)
        .unwrap();
    store.content().flush().unwrap();
    let scope = StagingScope::parse("cccccccccccccccccccccccccccccccc").unwrap();
    let staged = home.root().join("etc").join(scope.temporary_basename());
    astrid_core::platform_fs::ensure_private_directory(&home.root().join("etc")).unwrap();
    plant_private(&staged, b"schema1 rejects scoped");
    drop(store);

    home.ensure().unwrap();
    let error = open_runtime_principal_store(&home, quota())
        .await
        .err()
        .expect("schema1 must not delete scoped etc residue");
    assert!(
        error
            .to_string()
            .contains("scoped sentinel staging entry is not accepted by legacy shape policy"),
        "{error}"
    );
    assert_eq!(std::fs::read(&staged).unwrap(), b"schema1 rejects scoped");
}

#[tokio::test]
async fn inventory_named_exactscope_file_is_preserved_and_restored() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    std::fs::create_dir_all(home.root().join("restoration")).unwrap();
    let scope = StagingScope::parse("dddddddddddddddddddddddddddddddd").unwrap();
    let inventory_name = format!("restoration/{}", scope.temporary_basename());
    let authoritative = b"inventory wins over staging shape\n";
    std::fs::write(home.root().join(&inventory_name), authoritative).unwrap();
    std::fs::write(home.root().join("zz-redirected.conf"), authoritative).unwrap();
    store.publish_runtime_projection(&home).unwrap();
    let entries = super::active_projection_entries(&home, &store).unwrap();
    let receipt =
        super::receipt_ingest(&home, super::ReceiptPhase::Retiring, &entries, Some(scope)).unwrap();
    store
        .replace_contiguous_files_removing_exact(StateOwner::System, [receipt], &[], None)
        .unwrap();
    store.content().flush().unwrap();
    assert_eq!(scope, durable_scope(&home, &store));
    std::fs::write(home.root().join(&inventory_name), b"stale host bytes\n").unwrap();
    drop(store);

    let store = open_runtime_principal_store(&home, quota())
        .await
        .expect("inventory-named exact-scope file must reopen");
    assert_eq!(
        std::fs::read(home.root().join(&inventory_name)).unwrap(),
        authoritative
    );
    assert_eq!(
        super::active::read(&home, &store).unwrap().unwrap().phase(),
        super::ReceiptPhase::Active
    );
}

#[tokio::test]
async fn pack_hardfails_scoped_residue_without_deleting() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    std::fs::create_dir_all(home.root().join("restoration")).unwrap();
    for name in ["restoration/existing.conf", "zz-redirected.conf"] {
        std::fs::write(home.root().join(name), b"durable\n").unwrap();
    }
    store.publish_runtime_projection(&home).unwrap();
    let prepared = super::restoration::record_intent(&home, &store).unwrap();
    let scoped = home
        .root()
        .join("restoration")
        .join(prepared.staging_scope().temporary_basename());
    plant_private(&scoped, b"pack must not delete");
    drop(prepared);

    let error = store
        .pack_and_retire_runtime_projection(&home)
        .expect_err("RETIRING pack must not discharge scoped residue");
    assert!(
        error.to_string().contains("unreceipted host file"),
        "{error}"
    );
    assert_eq!(std::fs::read(&scoped).unwrap(), b"pack must not delete");
}

#[tokio::test]
async fn key_only_old_inventory_does_not_authorize_scoped_etc_after_seed() {
    let (_root, home, store, _) = packed_open_home().await;
    // Publish schema-2 key-only RETIRING while still volume-only. Do not reopen
    // first: that would restore etc/layout-version and widen host shape.
    let scope = publish_key_only_scoped_retiring(&home, &store);
    drop(store);

    plant_replacement_key(&home);
    astrid_core::platform_fs::ensure_private_directory(&home.root().join("etc")).unwrap();
    let staged = home.root().join("etc").join(scope.temporary_basename());
    plant_private(&staged, b"key-only inventory must not authorize");

    home.ensure().unwrap();
    let error = open_runtime_principal_store(&home, quota())
        .await
        .err()
        .expect("etc parent absent from original inventory must fail closed");
    let message = error.to_string();
    assert!(
        message.contains("sentinel staging entry lacks original inventory authority"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&staged).unwrap(),
        b"key-only inventory must not authorize"
    );
}

#[tokio::test]
async fn empty_etc_cleanup_does_not_open_restoration_writer() {
    let (_root, home, store, _) = packed_open_home().await;
    plant_replacement_key(&home);
    assert!(
        super::stopped_recovery::recover(&home, &store)
            .unwrap()
            .is_some()
    );
    astrid_core::platform_fs::ensure_private_directory(&home.root().join("etc")).unwrap();
    super::restoration::begin_writer_count(home.root());
    let prepared = super::stopped_recovery::recover(&home, &store)
        .unwrap()
        .expect("key recovery must prepare restoration");
    assert_eq!(
        super::restoration::take_writer_opens(home.root()),
        0,
        "empty etc cleanup must not open the private writer or fence"
    );
    drop(prepared);
}

#[tokio::test]
async fn foreign_root_retiring_volume_copy_is_rejected_without_mutation() {
    let source = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(source.path());
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    std::fs::create_dir_all(home.root().join("restoration")).unwrap();
    std::fs::write(home.root().join("restoration/existing.conf"), b"durable\n").unwrap();
    std::fs::write(home.root().join("zz-redirected.conf"), b"durable\n").unwrap();
    store.publish_runtime_projection(&home).unwrap();
    let prepared = super::restoration::record_intent(&home, &store).unwrap();
    assert!(prepared.staging_scope().as_hex().len() == 32);
    drop(prepared);
    store.content().flush().unwrap();

    let copy_dir = tempfile::tempdir().unwrap();
    let copy_home = AstridHome::from_path(copy_dir.path());
    copy_home.ensure().unwrap();
    std::fs::copy(home.storage_volume_path(), copy_home.storage_volume_path()).unwrap();
    drop(store);

    let rogue = copy_home.root().join("etc/user.conf");
    astrid_core::platform_fs::ensure_private_directory(rogue.parent().unwrap()).unwrap();
    std::fs::write(&rogue, b"arbitrary-not-authority").unwrap();
    let scoped = copy_home.root().join(
        StagingScope::parse("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
            .unwrap()
            .temporary_basename(),
    );
    plant_private(&scoped, b"foreign retiring must not delete");

    let error = open_runtime_principal_store(&copy_home, quota())
        .await
        .err()
        .expect("foreign RETIRING receipt must not relocate");
    assert!(
        error
            .to_string()
            .contains("active projection receipt root does not match this durable root"),
        "{error}"
    );
    assert_eq!(std::fs::read(&rogue).unwrap(), b"arbitrary-not-authority");
    assert_eq!(
        std::fs::read(&scoped).unwrap(),
        b"foreign retiring must not delete"
    );
}

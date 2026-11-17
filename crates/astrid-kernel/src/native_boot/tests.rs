//! Exercise interrupted startup through the actual explicit-home boot owner.

use std::{path::Path, sync::Arc};

use super::*;
use astrid_core::dirs::{AstridHome, WorkspaceLayout};
use astrid_storage::{
    ContentName, KvIdentityStore, KvQuotaResolver, PrincipalDirectory, StateOwner,
};

fn quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

fn private_write(home: &AstridHome, name: &str, bytes: &[u8]) {
    let writer = astrid_core::platform_fs::PrivateFileProjection::open(home.root()).unwrap();
    writer.write(Path::new(name), bytes).unwrap();
    writer.sync().unwrap();
}

async fn fixture() -> (
    tempfile::TempDir,
    AstridHome,
    RuntimePrincipalStore,
    std::fs::File,
    Vec<u8>,
) {
    // These tests never consult or mutate an ambient application home/run dir.
    assert!(
        std::env::var_os("ASTRID_RUN_DIR").is_none(),
        "owned boot fixture needs its own run dir"
    );
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path().join("home"));
    let principals = PrincipalDirectory::default();
    let (store, singleton, origin) = NativeBootAdmission::acquire(&home)
        .unwrap()
        .open(quota(), principals.clone())
        .await
        .unwrap();
    assert_eq!(origin, legacy_migration_barrier::LayoutOrigin::Fresh);
    let key = crate::load_or_generate_runtime_key(&home.keys_dir()).unwrap();
    let audit = Arc::new(astrid_audit::AuditLog::in_memory(key));
    let identities = KvIdentityStore::with_principal_directory(
        store.system_control_kv("identity").unwrap(),
        principals.clone(),
    );
    let workspace = directory.path().join("workspace");
    astrid_core::platform_fs::create_private_directory(&workspace).unwrap();
    // The production barrier writes the canonical complete ledger; the fixture
    // does not manufacture a migration JSON document or bypass validation.
    legacy_migration_barrier::run(
        &home,
        &store,
        &principals,
        &identities,
        &audit,
        origin,
        &workspace,
        &WorkspaceLayout::default(),
    )
    .await
    .unwrap();
    drop(identities);
    drop(audit);
    astrid_core::platform_fs::create_private_directory(&home.log_dir()).unwrap();
    astrid_core::platform_fs::create_private_directory(&home.wit_dir()).unwrap();
    store.publish_runtime_projection(&home).unwrap();
    let ledger = std::fs::read(legacy_migration_barrier::ledger_path(&home)).unwrap();
    (directory, home, store, singleton, ledger)
}

async fn open(
    home: &AstridHome,
) -> io::Result<(
    RuntimePrincipalStore,
    std::fs::File,
    legacy_migration_barrier::LayoutOrigin,
)> {
    NativeBootAdmission::acquire(home)?
        .open(quota(), PrincipalDirectory::default())
        .await
}

fn interrupt_retirement(home: &AstridHome, store: RuntimePrincipalStore, singleton: std::fs::File) {
    astrid_core::dirs::interrupt_retirement_before_unlink_once(home.root(), Path::new("log"))
        .unwrap();
    let error = store.pack_and_retire_runtime_projection(home).unwrap_err();
    assert!(
        error.to_string().contains("injected projection retirement"),
        "{error}"
    );
    assert!(!home.layout_version_path().exists());
    assert!(!home.runtime_key_path().exists());
    assert!(legacy_migration_barrier::ledger_path(home).is_file());
    drop(store);
    drop(singleton);
}

#[tokio::test]
async fn interrupted_retirement_resumes_before_home_ensure_through_native_boot() {
    let (_directory, home, store, singleton, ledger) = fixture().await;
    interrupt_retirement(&home, store, singleton);
    assert!(
        home.ensure().is_err(),
        "old early ensure must reject this actual partial retirement"
    );
    let (store, _singleton, origin) = open(&home).await.unwrap();
    assert_eq!(origin, legacy_migration_barrier::LayoutOrigin::ExistingV2);
    legacy_migration_barrier::reject_incomplete_layout_v2(&home).unwrap();
    assert_eq!(
        std::fs::read(legacy_migration_barrier::ledger_path(&home)).unwrap(),
        ledger
    );
    assert!(home.runtime_key_path().is_file());
    store.pack_and_retire_runtime_projection(&home).unwrap();
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
}

#[tokio::test]
async fn interrupted_sentinel_restore_resumes_before_missing_ledger_rejection() {
    let (_directory, home, store, singleton, ledger) = fixture().await;
    store.pack_and_retire_runtime_projection(&home).unwrap();
    drop(store);
    drop(singleton);
    astrid_storage::engine::crash_replay::host_projection::interrupt_restore_after_write_once(
        &home,
        &ContentName::new("etc/layout-version").unwrap(),
    )
    .unwrap();
    let interrupted_home = home.clone();
    let Err(failure) = tokio::spawn(async move { open(&interrupted_home).await }).await else {
        panic!("restore interruption must panic before returning a store");
    };
    assert!(
        failure.is_panic(),
        "real restore must consume the interruption"
    );
    assert_eq!(
        home.layout_version().unwrap().as_deref(),
        Some(astrid_core::dirs::LAYOUT_VERSION)
    );
    assert!(!legacy_migration_barrier::ledger_path(&home).exists());
    assert!(legacy_migration_barrier::reject_incomplete_layout_v2(&home).is_err());
    let (store, _singleton, origin) = open(&home).await.unwrap();
    assert_eq!(origin, legacy_migration_barrier::LayoutOrigin::ExistingV2);
    assert_eq!(
        std::fs::read(legacy_migration_barrier::ledger_path(&home)).unwrap(),
        ledger
    );
    store.pack_and_retire_runtime_projection(&home).unwrap();
}

#[tokio::test]
async fn malformed_present_ledger_is_not_repaired_by_retiring_authority() {
    let (_directory, home, store, singleton, _ledger) = fixture().await;
    interrupt_retirement(&home, store, singleton);
    private_write(
        &home,
        "var/migrations/layout-v2-components.complete",
        b"{broken",
    );
    let volume = std::fs::read(home.storage_volume_path()).unwrap();
    let Err(error) = open(&home).await else {
        panic!("invalid startup state must not open a store");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        error.to_string().contains("decode migration ledger"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(home.storage_volume_path()).unwrap(),
        volume,
        "preflight rejection must precede even physical container recovery"
    );
    assert_eq!(
        std::fs::read(legacy_migration_barrier::ledger_path(&home)).unwrap(),
        b"{broken"
    );
    assert!(!home.layout_version_path().exists());
}

#[tokio::test]
async fn missing_ledger_without_existing_media_never_initializes_a_volume() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path().join("home"));
    home.ensure().unwrap();
    private_write(&home, "etc/layout-version", b"2");
    assert!(open(&home).await.is_err());
    assert!(!home.storage_volume_path().exists());
    assert!(!home.run_dir().exists());
}

#[tokio::test]
async fn active_receipt_cannot_authorize_a_missing_startup_ledger() {
    let (_directory, home, store, singleton, _ledger) = fixture().await;
    let receipt_name = ContentName::new("run/.active-projection-v1.json").unwrap();
    let receipt = store
        .content()
        .read(&StateOwner::System, &receipt_name)
        .unwrap();
    std::fs::remove_file(legacy_migration_barrier::ledger_path(&home)).unwrap();
    drop(store);
    drop(singleton);
    let Err(error) = open(&home).await else {
        panic!("invalid startup state must not open a store");
    };
    assert!(error.to_string().contains("RETIRING"), "{error}");
    assert!(!legacy_migration_barrier::ledger_path(&home).exists());
    let store =
        astrid_storage::principal_state::open_runtime_principal_store_for_pack(&home, quota())
            .await
            .unwrap();
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &receipt_name)
            .unwrap(),
        receipt
    );
}

#[tokio::test]
async fn acquired_then_abandoned_stopped_boot_retries_before_first_media_open() {
    let (_directory, home, store, singleton, ledger) = fixture().await;
    let key = std::fs::read(home.runtime_key_path()).unwrap();
    store.pack_and_retire_runtime_projection(&home).unwrap();
    drop(store);
    drop(singleton);
    let volume = std::fs::read(home.storage_volume_path()).unwrap();

    // Acquisition itself creates the singleton namespace. Abandon it before
    // `.open`: neither container recovery nor host restoration has happened.
    let admission = NativeBootAdmission::acquire(&home).unwrap();
    assert!(home.run_dir().join("system.lock").is_file());
    assert!(!home.layout_version_path().exists());
    assert!(!home.runtime_key_path().exists());
    assert_eq!(std::fs::read(home.storage_volume_path()).unwrap(), volume);
    drop(admission);

    let (store, _singleton, origin) = open(&home).await.unwrap();
    assert_eq!(origin, legacy_migration_barrier::LayoutOrigin::Fresh);
    assert_eq!(
        std::fs::read(legacy_migration_barrier::ledger_path(&home)).unwrap(),
        ledger
    );
    assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), key);
    store.pack_and_retire_runtime_projection(&home).unwrap();
}

#[tokio::test]
async fn acquired_then_abandoned_fresh_boot_retries_without_prior_media() {
    assert!(std::env::var_os("ASTRID_RUN_DIR").is_none());
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path().join("home"));
    let admission = NativeBootAdmission::acquire(&home).unwrap();
    assert!(home.run_dir().join("system.lock").is_file());
    assert!(!home.storage_volume_path().exists());
    assert!(!home.layout_version_path().exists());
    assert!(!legacy_migration_barrier::ledger_path(&home).exists());
    drop(admission);

    let (_store, _singleton, origin) = open(&home).await.unwrap();
    assert_eq!(origin, legacy_migration_barrier::LayoutOrigin::Fresh);
    assert!(home.storage_volume_path().is_file());
    // This is pre-barrier startup, not permission to invent a completed ledger.
    assert!(!legacy_migration_barrier::ledger_path(&home).exists());
}

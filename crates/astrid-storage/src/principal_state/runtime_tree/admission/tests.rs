use super::*;
use crate::{AstridFilesystem, FilesystemPath, KvQuotaResolver, open_runtime_principal_store};
use std::sync::Arc;

fn control() -> ContentName {
    ContentName::new("var/migrations/boot-admission.json").unwrap()
}

async fn fixture() -> (tempfile::TempDir, AstridHome, RuntimePrincipalStore) {
    let (parent, home) = super::super::lifecycle_tests::fixture();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    (parent, home, store)
}

fn physical_writes(store: &RuntimePrincipalStore) -> Vec<(String, u64)> {
    store
        .volume_binding
        .upgrade()
        .expect("live test store retains its volume")
        .write_record_payloads()
        .unwrap()
}

#[tokio::test]
async fn unchanged_payload_batch_adds_no_root_or_physical_history() {
    let (_parent, home, store) = fixture().await;
    let first = scan(home.root()).unwrap();
    store
        .admit_runtime_tree_snapshot(&home, &first, control())
        .unwrap()
        .finish(b"receipt".to_vec())
        .unwrap();
    let before_root = store.engine.root(&StateOwner::System).unwrap();
    let before_writes = physical_writes(&store);
    let entries = scan(home.root()).unwrap();
    let pending = store
        .admit_runtime_tree_snapshot(&home, &entries, control())
        .unwrap();
    assert_eq!(store.engine.root(&StateOwner::System).unwrap(), before_root);
    assert_eq!(physical_writes(&store), before_writes);
    pending.finish(b"receipt".to_vec()).unwrap();
    assert_eq!(store.engine.root(&StateOwner::System).unwrap(), before_root);
    assert_eq!(physical_writes(&store), before_writes);
}

#[tokio::test]
async fn same_size_source_change_after_payload_commit_does_not_complete_receipt() {
    let (_parent, home, store) = fixture().await;
    let path = home.root().join("config.toml");
    std::fs::write(&path, b"old").unwrap();
    let snapshot = scan(home.root()).unwrap();

    let pending = store
        .admit_runtime_tree_snapshot(&home, &snapshot, control())
        .unwrap();
    let prepared_active = catalog_file(&store, &active::active_projection_name().unwrap()).unwrap();
    std::fs::write(&path, b"new").unwrap();
    let error = pending.finish(b"receipt".to_vec()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(!home.root().join(control().as_str()).exists());
    assert_eq!(
        catalog_file(&store, &active::active_projection_name().unwrap()).unwrap(),
        prepared_active
    );
    let retry = scan(home.root()).unwrap();
    store
        .admit_runtime_tree_snapshot(&home, &retry, control())
        .unwrap()
        .finish(b"receipt".to_vec())
        .unwrap();
    assert_eq!(
        store
            .content()
            .read(
                &StateOwner::System,
                &ContentName::new("config.toml").unwrap()
            )
            .unwrap(),
        Some(b"new".to_vec())
    );
}

#[tokio::test]
async fn completion_catalog_conflict_rolls_back_only_its_host_receipt() {
    for prior in [None, Some(b"previous".as_slice())] {
        let (_parent, home, store) = fixture().await;
        let control_path = home.root().join(control().as_str());
        if let Some(bytes) = prior {
            astrid_core::platform_fs::ensure_private_directory(control_path.parent().unwrap())
                .unwrap();
            astrid_core::platform_fs::atomic_write_private_file(&control_path, bytes).unwrap();
        }
        let snapshot = scan(home.root()).unwrap();
        let pending = store
            .admit_runtime_tree_snapshot(&home, &snapshot, control())
            .unwrap();
        // The host snapshot is unchanged; only the catalog control identity raced.
        store
            .content()
            .put(&StateOwner::System, &control(), b"concurrent catalog")
            .unwrap();
        assert!(pending.finish(b"ours".to_vec()).is_err());
        match prior {
            Some(bytes) => assert_eq!(std::fs::read(&control_path).unwrap(), bytes),
            None => assert!(!control_path.exists()),
        }
        assert_eq!(
            store
                .content()
                .read(&StateOwner::System, &control())
                .unwrap(),
            Some(b"concurrent catalog".to_vec())
        );
    }
}

#[tokio::test]
async fn active_keeps_explicit_directories_without_claiming_volume_only_files() {
    let (_parent, home, store) = fixture().await;
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::System);
    filesystem
        .create_dir(&FilesystemPath::new("empty").unwrap())
        .unwrap();
    std::fs::create_dir(home.root().join("empty")).unwrap();
    let volume_only = ContentName::new("bin/never-materialized.wasm").unwrap();
    store
        .content()
        .put(&StateOwner::System, &volume_only, b"volume only")
        .unwrap();
    let snapshot = scan(home.root()).unwrap();
    store
        .admit_runtime_tree_snapshot(&home, &snapshot, control())
        .unwrap()
        .finish(b"receipt".to_vec())
        .unwrap();
    let receipt = active::read(&home, &store).unwrap().unwrap();
    assert!(receipt.contains_inventory_name("empty/"));
    assert!(!receipt.contains_inventory_name(volume_only.as_str()));
    store.publish_runtime_projection(&home).unwrap();
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &volume_only)
            .unwrap(),
        Some(b"volume only".to_vec())
    );
}

#[tokio::test]
async fn snapshot_from_another_home_is_rejected_before_publication() {
    let (_parent, home, store) = fixture().await;
    let (_other_parent, other, _other_store) = fixture().await;
    let foreign = scan(other.root()).unwrap();
    let before = store.engine.root(&StateOwner::System).unwrap();
    assert!(
        store
            .admit_runtime_tree_snapshot(&home, &foreign, control())
            .is_err()
    );
    assert_eq!(store.engine.root(&StateOwner::System).unwrap(), before);
}

#[tokio::test]
async fn directory_removed_during_admission_is_not_claimed_materialized() {
    let (_parent, home, store) = fixture().await;
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::System);
    filesystem
        .create_dir(&FilesystemPath::new("empty").unwrap())
        .unwrap();
    std::fs::create_dir(home.root().join("empty")).unwrap();
    let snapshot = scan(home.root()).unwrap();
    let pending = store
        .admit_runtime_tree_snapshot(&home, &snapshot, control())
        .unwrap();
    std::fs::remove_dir(home.root().join("empty")).unwrap();
    pending.finish(b"receipt".to_vec()).unwrap();
    assert!(
        !active::read(&home, &store)
            .unwrap()
            .unwrap()
            .contains_inventory_name("empty/")
    );
    assert!(
        filesystem
            .stat(&FilesystemPath::new("empty").unwrap())
            .is_ok()
    );
}

#[tokio::test]
async fn dropped_pending_admission_reopens_with_prepared_payload_identity() {
    let (_parent, home, store) = fixture().await;
    let path = home.root().join("config.toml");
    std::fs::write(&path, b"old").unwrap();
    let volume_only = add_directory_and_volume_only(&home, &store);
    store.publish_runtime_projection(&home).unwrap();
    store.establish_runtime_projection_receipt(&home).unwrap();
    std::fs::write(&path, b"new").unwrap();
    let snapshot = scan(home.root()).unwrap();
    let pending = store
        .admit_runtime_tree_snapshot(&home, &snapshot, control())
        .unwrap();
    drop(pending);
    store.engine.close().unwrap();
    drop(store);
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let reopened = open_runtime_principal_store(&home, quota)
        .await
        .expect("interrupted admission must remain restartable");
    assert_resume_inventory(&home, &reopened, &volume_only);
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
    assert_eq!(
        reopened
            .content()
            .read(
                &StateOwner::System,
                &ContentName::new("config.toml").unwrap()
            )
            .unwrap(),
        Some(b"new".to_vec())
    );
}

#[tokio::test]
async fn source_change_refusal_reopens_and_preserves_latest_host_bytes() {
    let (_parent, home, store) = fixture().await;
    let path = home.root().join("config.toml");
    std::fs::write(&path, b"old").unwrap();
    let volume_only = add_directory_and_volume_only(&home, &store);
    store.publish_runtime_projection(&home).unwrap();
    store.establish_runtime_projection_receipt(&home).unwrap();
    std::fs::write(&path, b"mid").unwrap();
    let snapshot = scan(home.root()).unwrap();
    let pending = store
        .admit_runtime_tree_snapshot(&home, &snapshot, control())
        .unwrap();
    std::fs::write(&path, b"new").unwrap();
    assert_eq!(
        pending.finish(b"receipt".to_vec()).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(!home.root().join(control().as_str()).exists());
    store.engine.close().unwrap();
    drop(store);
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let reopened = open_runtime_principal_store(&home, quota).await.unwrap();
    assert_resume_inventory(&home, &reopened, &volume_only);
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
    assert_eq!(
        reopened
            .content()
            .read(
                &StateOwner::System,
                &ContentName::new("config.toml").unwrap()
            )
            .unwrap(),
        Some(b"new".to_vec())
    );
}

fn add_directory_and_volume_only(home: &AstridHome, store: &RuntimePrincipalStore) -> ContentName {
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::System);
    filesystem
        .create_dir(&FilesystemPath::new("empty").unwrap())
        .unwrap();
    astrid_core::platform_fs::create_private_directory(&home.root().join("empty")).unwrap();
    let volume_only = ContentName::new("bin/unmaterialized.wasm").unwrap();
    store
        .content()
        .put(&StateOwner::System, &volume_only, b"volume only")
        .unwrap();
    volume_only
}

fn assert_resume_inventory(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    volume_only: &ContentName,
) {
    assert!(home.root().join("empty").is_dir());
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, volume_only)
            .unwrap(),
        Some(b"volume only".to_vec())
    );
    assert!(!home.root().join(volume_only.as_str()).exists());
    let receipt = active::read(home, store).unwrap().unwrap();
    assert!(receipt.contains_inventory_name("empty/"));
    assert!(!receipt.contains_inventory_name(volume_only.as_str()));
}

#[tokio::test]
async fn invalid_control_names_do_not_mutate_host_or_volume() {
    let (_parent, home, store) = fixture().await;
    let snapshot = scan(home.root()).unwrap();
    let before = store.engine.root(&StateOwner::System).unwrap();
    let writes = physical_writes(&store);
    for raw in [
        "../astrid.volume",
        "x/../astrid.volume",
        "./receipt",
        "x//receipt",
        "x\\receipt",
        "astrid.volume",
        "volume",
        "volume/part",
        "var/astrid.volume",
        "astrid.migrating",
        "run/.active-projection-v1.json",
        "run/control",
        "bin/astrid-daemon",
    ] {
        assert!(
            store
                .admit_runtime_tree_snapshot(&home, &snapshot, ContentName::new(raw).unwrap())
                .is_err(),
            "accepted {raw}"
        );
        assert_eq!(store.engine.root(&StateOwner::System).unwrap(), before);
        assert_eq!(physical_writes(&store), writes);
    }
}

#[tokio::test]
async fn control_namespace_aliases_use_the_real_host_rules() {
    let (_parent, home, store) = fixture().await;
    let snapshot = scan(home.root()).unwrap();
    let before = store.engine.root(&StateOwner::System).unwrap();
    let writes = physical_writes(&store);
    // Admission uses the same actual-target name semantics as restoration.
    let case_sensitive =
        astrid_core::platform_fs::name_semantics::directory_is_case_sensitive(home.root()).unwrap();
    let result = store.admit_runtime_tree_snapshot(
        &home,
        &snapshot,
        ContentName::new("ASTRID.VOLUME").unwrap(),
    );
    if case_sensitive {
        // This is a valid distinct name, so payload/ACTIVE publication is
        // allowed; only the completed host control receipt is still absent.
        drop(result.expect("distinct spelling on a case-sensitive root"));
        assert!(active::read(&home, &store).unwrap().is_some());
        assert!(!home.root().join("ASTRID.VOLUME").exists());
    } else {
        assert!(result.is_err());
        assert_eq!(store.engine.root(&StateOwner::System).unwrap(), before);
        assert_eq!(physical_writes(&store), writes);
    }
}

#[tokio::test]
async fn control_peer_alias_uses_the_real_host_rules_before_publication() {
    let (_parent, home, store) = fixture().await;
    let path = home.root().join("data.toml");
    std::fs::write(&path, b"source data").unwrap();
    let first = scan(home.root()).unwrap();
    store
        .admit_runtime_tree_snapshot(&home, &first, control())
        .unwrap()
        .finish(b"receipt".to_vec())
        .unwrap();
    let snapshot = scan(home.root()).unwrap();
    let before = store.engine.root(&StateOwner::System).unwrap();
    let writes = physical_writes(&store);
    let case_sensitive =
        astrid_core::platform_fs::name_semantics::directory_is_case_sensitive(home.root()).unwrap();
    let result =
        store.admit_runtime_tree_snapshot(&home, &snapshot, ContentName::new("DATA.TOML").unwrap());
    if case_sensitive {
        drop(result.expect("distinct file spelling on a sensitive root"));
    } else {
        assert!(
            result.is_err(),
            "a peer alias must not overwrite the source"
        );
    }
    assert_eq!(std::fs::read(&path).unwrap(), b"source data");
    assert_eq!(store.engine.root(&StateOwner::System).unwrap(), before);
    assert_eq!(physical_writes(&store), writes);
}

#[cfg(unix)]
thread_local! {
    static ROOT_SWAP: std::cell::RefCell<Option<(std::path::PathBuf, std::path::PathBuf)>> = const { std::cell::RefCell::new(None) };
}

#[cfg(unix)]
pub(super) fn before_writer_creation(root: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    ROOT_SWAP.with_borrow_mut(|slot| {
        if let Some((expected, parked)) = slot.take() {
            assert_eq!(expected, root);
            std::fs::rename(root, parked)?;
            std::fs::create_dir(root)?;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755))?;
            std::fs::write(root.join("foreign-sentinel"), b"foreign")?;
        }
        Ok(())
    })
}

#[cfg(unix)]
#[tokio::test]
async fn root_swap_before_writer_does_not_repair_or_create_foreign_entries() {
    use std::os::unix::fs::PermissionsExt as _;
    let (parent, home, store) = fixture().await;
    let snapshot = scan(home.root()).unwrap();
    let pending = store
        .admit_runtime_tree_snapshot(&home, &snapshot, control())
        .unwrap();
    ROOT_SWAP.with_borrow_mut(|slot| {
        *slot = Some((home.root().to_path_buf(), parent.path().join("parked")));
    });
    assert!(pending.finish(b"receipt".to_vec()).is_err());
    assert_eq!(
        std::fs::metadata(home.root()).unwrap().permissions().mode() & 0o777,
        0o755,
        "foreign privacy must not be repaired by a stale admission"
    );
    let entries = std::fs::read_dir(home.root())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries, [std::ffi::OsString::from("foreign-sentinel")]);
    assert_eq!(
        std::fs::read(home.root().join("foreign-sentinel")).unwrap(),
        b"foreign"
    );
}

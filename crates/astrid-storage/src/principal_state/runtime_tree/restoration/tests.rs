//! Interrupt the actual ordinary restore before ACTIVE publication.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::super as runtime_tree;
use crate::{ContentName, KvQuotaResolver, StateOwner, open_runtime_principal_store};
use astrid_core::dirs::AstridHome;

thread_local! {
    static CUT: RefCell<Option<(PathBuf, &'static str)>> = const { RefCell::new(None) };
    static INTENTS: RefCell<Option<(PathBuf, usize)>> = const { RefCell::new(None) };
    static WRITERS: RefCell<Option<(PathBuf, usize)>> = const { RefCell::new(None) };
}

pub(super) fn intent_committed(root: &Path) {
    INTENTS.with_borrow_mut(|counter| {
        if let Some((expected, count)) = counter
            && expected == root
        {
            *count = count.strict_add(1);
        }
    });
}

#[cfg(unix)]
pub(super) fn begin_writer_count(root: &Path) {
    WRITERS.with_borrow_mut(|counter| *counter = Some((root.to_path_buf(), 0)));
}

pub(super) fn writer_opened(root: &Path) {
    WRITERS.with_borrow_mut(|counter| {
        if let Some((expected, count)) = counter
            && expected == root
        {
            *count = count.strict_add(1);
        }
    });
}

#[cfg(unix)]
pub(super) fn take_writer_opens(root: &Path) -> usize {
    WRITERS.with_borrow_mut(|counter| match counter.take() {
        Some((expected, count)) if expected == root => count,
        Some((expected, _)) => panic!("writer counter root mismatch: {}", expected.display()),
        None => panic!("writer counter was not armed for {}", root.display()),
    })
}

pub(super) fn after_intent(root: &Path) {
    after_write(root, "<durable-intent>");
}

pub(super) fn after_write(root: &Path, relative: &str) {
    let interrupt = CUT.with_borrow_mut(|cut| {
        if cut
            .as_ref()
            .is_some_and(|(expected, name)| expected == root && *name == relative)
        {
            cut.take();
            true
        } else {
            false
        }
    });
    assert!(!interrupt, "injected ordinary restoration interruption");
}

#[tokio::test]
async fn ordinary_restore_resumes_before_first_host_write() {
    interrupted_restore("<durable-intent>").await;
}

#[tokio::test]
async fn ordinary_restore_resumes_after_private_root_repair() {
    interrupted_restore("<private-root>").await;
}

#[tokio::test]
async fn ordinary_restore_resumes_after_layout_sentinel() {
    interrupted_restore("etc/layout-version").await;
}

#[tokio::test]
async fn ordinary_restore_resumes_after_root_file() {
    interrupted_restore("config.toml").await;
}

#[tokio::test]
async fn ordinary_restore_resumes_after_profile_file() {
    interrupted_restore("etc/profiles/example.toml").await;
}

#[tokio::test]
async fn keyless_sentinel_parent_resumes_through_public_admission() {
    interrupted_restore_with_residue("<durable-intent>", Some(SentinelResidue::Parent)).await;
}

#[tokio::test]
async fn keyless_sentinel_staging_resumes_through_public_admission() {
    interrupted_restore_with_residue("<durable-intent>", Some(SentinelResidue::Staging)).await;
}

#[derive(Clone, Copy)]
enum SentinelResidue {
    Parent,
    Staging,
}

async fn interrupted_restore(cut: &'static str) {
    interrupted_restore_with_residue(cut, None).await;
}

async fn interrupted_restore_with_residue(cut: &'static str, residue: Option<SentinelResidue>) {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    home.ensure().unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota.clone())
        .await
        .unwrap();
    for (relative, bytes) in [
        ("config.toml", b"# durable config\n".as_slice()),
        (
            "etc/profiles/example.toml",
            b"# durable profile\n".as_slice(),
        ),
    ] {
        runtime_tree::write_projection_file(home.root(), relative, bytes).unwrap();
    }
    store.pack_and_retire_runtime_projection(&home).unwrap();
    assert!(runtime_tree::active::read(&home, &store).unwrap().is_none());
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);

    #[cfg(unix)]
    if cut == "<durable-intent>" {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(home.root(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    CUT.with_borrow_mut(|value| *value = Some((home.root().to_path_buf(), cut)));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime_tree::reconcile_running_projection(&home, &store, false)
    }));
    assert!(result.is_err(), "the real restoration must reach the cut");
    CUT.with_borrow(|value| assert!(value.is_none(), "interruption hook was consumed"));
    if matches!(cut, "<durable-intent>" | "<private-root>") {
        assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
    } else {
        assert!(home.root().join(cut).is_file());
    }
    #[cfg(unix)]
    if cut == "<durable-intent>" {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(home.root()).unwrap().permissions().mode() & 0o777,
            0o755,
            "the durable-intent cut must precede root privacy mutation"
        );
    }
    let scope = runtime_tree::active::read(&home, &store)
        .unwrap()
        .unwrap()
        .staging_scope()
        .unwrap();
    drop(store);
    create_sentinel_residue(&home, residue, scope);

    if residue.is_some() {
        INTENTS.with_borrow_mut(|counter| *counter = Some((home.root().to_path_buf(), 0)));
    }
    home.ensure()
        .expect("real boot admission must accept interrupted restore");
    let restored = open_runtime_principal_store(&home, quota)
        .await
        .expect("ordinary interrupted restoration must resume from durable intent");
    if residue.is_some() {
        INTENTS.with_borrow_mut(|counter| {
            let (expected, count) = counter.take().expect("recovery intent counter installed");
            assert_eq!(expected, home.root());
            assert_eq!(
                count, 1,
                "recovery must hand its committed inventory to restoration"
            );
        });
    }
    for (relative, bytes) in [
        ("config.toml", b"# durable config\n".as_slice()),
        (
            "etc/profiles/example.toml",
            b"# durable profile\n".as_slice(),
        ),
    ] {
        assert_eq!(std::fs::read(home.root().join(relative)).unwrap(), bytes);
        assert_eq!(
            restored
                .content()
                .read(&StateOwner::System, &ContentName::new(relative).unwrap())
                .unwrap(),
            Some(bytes.to_vec())
        );
    }
    assert_eq!(
        runtime_tree::active::read(&home, &restored)
            .unwrap()
            .unwrap()
            .phase(),
        runtime_tree::ReceiptPhase::Active
    );
    restored.pack_and_retire_runtime_projection(&home).unwrap();
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
}

fn create_sentinel_residue(
    home: &AstridHome,
    residue: Option<SentinelResidue>,
    scope: astrid_core::platform_fs::StagingScope,
) {
    if let Some(residue) = residue {
        let etc = home.root().join("etc");
        astrid_core::platform_fs::ensure_private_directory(&etc).unwrap();
        if matches!(residue, SentinelResidue::Staging) {
            astrid_core::platform_fs::atomic_write_private_file(
                &etc.join(scope.temporary_basename()),
                b"interrupted sentinel",
            )
            .unwrap();
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn matching_payload_still_repairs_nonprivate_projection() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    home.ensure().unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    let sentinel = home.layout_version_path();
    let before = std::fs::read(&sentinel).unwrap();
    std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o644)).unwrap();
    super::restore_projection(&home, &store, &store.content()).unwrap();
    assert_eq!(std::fs::read(&sentinel).unwrap(), before);
    astrid_core::platform_fs::validate_private_file(&sentinel).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn storage_bootstrap_repairs_root_privacy_without_repeated_journal_growth() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota.clone())
        .await
        .unwrap();
    astrid_core::platform_fs::validate_private_directory(home.root()).unwrap();
    store.engine.close().unwrap();
    drop(store);
    let committed_len = std::fs::metadata(home.storage_volume_path()).unwrap().len();
    for _ in 0..2 {
        let store = open_runtime_principal_store(&home, quota.clone())
            .await
            .unwrap();
        astrid_core::platform_fs::validate_private_directory(home.root()).unwrap();
        assert_eq!(
            std::fs::metadata(home.storage_volume_path()).unwrap().len(),
            committed_len
        );
        store.engine.close().unwrap();
        drop(store);
    }
}

#[derive(Clone, Copy, Debug)]
enum InvalidSentinelIntent {
    Missing,
    Active,
    ForeignRoot,
    MissingSentinel,
}

#[tokio::test]
async fn keyless_sentinel_cleanup_requires_its_same_root_retiring_inventory() {
    for invalid in [
        InvalidSentinelIntent::Missing,
        InvalidSentinelIntent::Active,
        InvalidSentinelIntent::ForeignRoot,
        InvalidSentinelIntent::MissingSentinel,
    ] {
        reject_sentinel_cleanup(invalid).await;
    }
}

async fn reject_sentinel_cleanup(invalid: InvalidSentinelIntent) {
    use runtime_tree::ReceiptPhase;

    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    home.ensure().unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota.clone())
        .await
        .unwrap();
    store.pack_and_retire_runtime_projection(&home).unwrap();
    match invalid {
        InvalidSentinelIntent::Missing => {},
        InvalidSentinelIntent::Active => {
            runtime_tree::establish_active_receipt(&home, &store).unwrap();
        },
        InvalidSentinelIntent::ForeignRoot | InvalidSentinelIntent::MissingSentinel => {
            let other = tempfile::tempdir().unwrap();
            let other_home = AstridHome::from_path(other.path());
            let receipt_home = if matches!(invalid, InvalidSentinelIntent::ForeignRoot) {
                &other_home
            } else {
                &home
            };
            let entries = if matches!(invalid, InvalidSentinelIntent::ForeignRoot) {
                runtime_tree::active_projection_entries(&home, &store).unwrap()
            } else {
                Vec::new()
            };
            let receipt =
                runtime_tree::receipt_ingest(receipt_home, ReceiptPhase::Retiring, &entries, None)
                    .unwrap();
            store
                .replace_contiguous_files_removing_exact(StateOwner::System, [receipt], &[], None)
                .unwrap();
            store.content().flush().unwrap();
        },
    }
    let etc = home.root().join("etc");
    astrid_core::platform_fs::ensure_private_directory(&etc).unwrap();
    let staging = etc.join(".astrid-private-00000000000040008000000000000001");
    astrid_core::platform_fs::atomic_write_private_file(&staging, b"unadmitted partial sentinel")
        .unwrap();
    drop(store);
    home.ensure().unwrap();
    assert!(
        open_runtime_principal_store(&home, quota).await.is_err(),
        "admitted {invalid:?}"
    );
    assert_eq!(
        std::fs::read(&staging).unwrap(),
        b"unadmitted partial sentinel",
        "mutated {invalid:?}"
    );
    assert!(!etc.join("layout-version").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn matching_payload_replaces_hardlink_without_mutating_alias() {
    use std::os::unix::fs::MetadataExt as _;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    home.ensure().unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    let sentinel = home.layout_version_path();
    let alias = outside.path().join("sentinel-alias");
    let before = std::fs::read(&sentinel).unwrap();
    std::fs::hard_link(&sentinel, &alias).unwrap();
    let old = std::fs::metadata(&alias).unwrap();
    super::restore_projection(&home, &store, &store.content()).unwrap();
    let restored = std::fs::metadata(&sentinel).unwrap();
    assert_ne!(restored.ino(), old.ino());
    assert_eq!(restored.nlink(), 1);
    assert_eq!(std::fs::metadata(&alias).unwrap().ino(), old.ino());
    assert_eq!(std::fs::read(&alias).unwrap(), before);
    assert_eq!(std::fs::read(&sentinel).unwrap(), before);
    astrid_core::platform_fs::validate_private_file(&sentinel).unwrap();
}

#[tokio::test]
async fn unchanged_private_directory_marker_does_not_rotate_restoration_intent() {
    use crate::{AstridFilesystem, FilesystemPath};
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    home.ensure().unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::System);
    filesystem
        .create_dir(&FilesystemPath::new("empty").unwrap())
        .unwrap();
    astrid_core::platform_fs::ensure_private_directory(&home.root().join("empty")).unwrap();
    store.publish_runtime_projection(&home).unwrap();
    INTENTS.with_borrow_mut(|counter| *counter = Some((home.root().to_path_buf(), 0)));
    super::restore_projection(&home, &store, &store.content()).unwrap();
    INTENTS.with_borrow_mut(|counter| {
        let (_, count) = counter.take().unwrap();
        assert_eq!(count, 0, "unchanged private directory is already projected");
    });
    assert!(home.root().join("empty").is_dir());
}

#[cfg(all(unix, target_os = "linux"))]
#[tokio::test]
#[ignore = "requires CAP_SYS_ADMIN in a caller-owned private mount namespace; run by native Linux CI"]
async fn bind_mount_matching_skip_rejects_mounted_private_subtree() {
    use crate::{AstridFilesystem, FilesystemPath};
    use astrid_core::platform_fs::mount_test_fixtures::{BindMount, require_private_namespace};

    require_private_namespace();
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    home.ensure().unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::System);
    filesystem
        .create_dir(&FilesystemPath::new("mounted").unwrap())
        .unwrap();
    filesystem
        .write(
            &FilesystemPath::new("mounted/leaf").unwrap(),
            b"catalog-identical",
        )
        .unwrap();
    astrid_core::platform_fs::ensure_private_directory(&home.root().join("mounted")).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(
        &home.root().join("mounted/leaf"),
        b"catalog-identical",
    )
    .unwrap();
    store.publish_runtime_projection(&home).unwrap();

    let target = home.root().join("mounted");
    let mut mounted = BindMount::attach(&target).unwrap();
    INTENTS.with_borrow_mut(|counter| *counter = Some((home.root().to_path_buf(), 0)));
    let result = super::restore_projection(&home, &store, &store.content());
    mounted.unmount().unwrap();
    let error = result.expect_err("mounted matching subtree must not reach ACTIVE via skip");
    assert!(
        error.to_string().contains("mount boundary")
            || error.to_string().contains("InvalidData")
            || error.to_string().contains("restore failed"),
        "{error}"
    );
    INTENTS.with_borrow_mut(|counter| {
        let (_, count) = counter.take().unwrap();
        assert!(
            count >= 1,
            "bind rejection must force durable restoration intent instead of ambient skip"
        );
    });
}

#[tokio::test]
async fn ordinary_restore_has_durable_retiring_intent_before_host_publication() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    runtime_tree::write_projection_file(home.root(), "config.toml", b"# durable config\n").unwrap();
    store.pack_and_retire_runtime_projection(&home).unwrap();
    assert!(runtime_tree::active::read(&home, &store).unwrap().is_none());
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
    CUT.with_borrow_mut(|cut| *cut = Some((home.root().to_path_buf(), "config.toml")));
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime_tree::reconcile_running_projection(&home, &store, false)
    }));
    assert!(
        interrupted.is_err(),
        "the actual restoration must reach the cut"
    );
    CUT.with_borrow(|cut| assert!(cut.is_none(), "interruption hook consumed"));
    assert!(home.root().join("config.toml").is_file());
    let phase = runtime_tree::active::read(&home, &store)
        .unwrap()
        .map(|receipt| receipt.phase());
    assert_eq!(
        phase,
        Some(runtime_tree::ReceiptPhase::Retiring),
        "host publication needs preexisting durable recovery intent"
    );
}

#[test]
fn volume_sentinel_seed_avoids_global_temporary_files() {
    const PROBE_HOME: &str = "ASTRID_TEST_VOLUME_SENTINEL_HOME";
    if let Some(root) = std::env::var_os(PROBE_HOME) {
        let home = AstridHome::from_path(PathBuf::from(root));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
            let store = open_runtime_principal_store(&home, quota).await.unwrap();
            assert_eq!(
                store
                    .content()
                    .read(
                        &StateOwner::System,
                        &ContentName::new("etc/layout-version").unwrap()
                    )
                    .unwrap(),
                Some(astrid_core::dirs::LAYOUT_VERSION.as_bytes().to_vec())
            );
        });
        return;
    }
    // The child owns a disposable application home. Its temporary-directory
    // override never changes this test process or the shared Cargo environment.
    let directory = tempfile::tempdir().unwrap();
    let unavailable = directory.path().join("unavailable-global-temp");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "principal_state::runtime_tree::restoration::tests::volume_sentinel_seed_avoids_global_temporary_files", "--nocapture"])
        .env(PROBE_HOME, directory.path().join("home"))
        .env("TMPDIR", &unavailable)
        .env("TMP", &unavailable)
        .env("TEMP", &unavailable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sentinel publication required global temporary storage: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// Neutral old-compatible hook: no production behavior or new core API involved.
thread_local! {
    static BACKUP_RACE: RefCell<Option<(PathBuf, bool)>> = const { RefCell::new(None) };
}
pub(super) fn after_backup(root: &Path, name: &str) {
    if name != "config.toml" {
        return;
    }
    let race = BACKUP_RACE.with_borrow_mut(|slot| {
        if slot.as_ref().is_some_and(|(expected, _)| expected == root) {
            slot.take()
        } else {
            None
        }
    });
    let Some((_, existing)) = race else { return };
    let path = root.join(name);
    if existing {
        // Retain the old inode to exclude inode-reuse ambiguity.
        std::fs::rename(&path, root.join("prior-config.saved"))
            .expect("perform the exact armed replacement race");
    } else {
        assert!(!path.exists(), "armed absence must really be absent");
    }
    std::fs::write(path, b"concurrent host generation")
        .expect("perform the exact armed create race");
}
struct BackupRaceReset;
impl Drop for BackupRaceReset {
    fn drop(&mut self) {
        BACKUP_RACE.with_borrow_mut(|slot| *slot = None);
    }
}
async fn restore_refuses_target_changed_after_backup(existing: bool) {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    home.ensure().unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    runtime_tree::write_projection_file(home.root(), "config.toml", b"durable config").unwrap();
    store.pack_and_retire_runtime_projection(&home).unwrap();
    if existing {
        // A mismatching host generation forces actual replacement, not skip.
        runtime_tree::write_projection_file(home.root(), "config.toml", b"prior host config")
            .unwrap();
    }
    BACKUP_RACE.with_borrow_mut(|slot| *slot = Some((home.root().to_path_buf(), existing)));
    let _reset = BackupRaceReset;
    let result = super::restore_projection(&home, &store, &store.content);
    assert!(
        BACKUP_RACE.with_borrow(Option::is_none),
        "race hook was not reached"
    );
    assert!(
        result.is_err(),
        "restore must refuse the changed generation before publication"
    );
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"concurrent host generation",
        "a prepublication failure must not roll back an unrelated target"
    );
}
#[tokio::test]
async fn ordinary_restore_preserves_file_created_after_backup() {
    restore_refuses_target_changed_after_backup(false).await;
}
#[tokio::test]
async fn ordinary_restore_preserves_file_replaced_after_backup() {
    restore_refuses_target_changed_after_backup(true).await;
}

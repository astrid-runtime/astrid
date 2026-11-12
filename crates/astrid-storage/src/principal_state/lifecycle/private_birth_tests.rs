//! Windows runtime-root admission regressions for public store open.
//!
//! Shared Windows store-open admission requires an `ExactPrivate` root before
//! any volume bootstrap or legacy `.migrating` mutation. Broad/redirected
//! roots fail closed without creating volume media or mutating ACL/reparse
//! shape. A retained final-boundary file fences ancestor rename for the open
//! lifetime; after every owner drops, the same rename succeeds.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use astrid_core::dirs::AstridHome;

use crate::KvQuotaResolver;
use crate::principal_state::format_amendment::STORE_METADATA_FILE;
use crate::principal_state::migrations::{KV_TRANSITION_CHECKPOINT_MARKER, MIGRATION_MARKER_FILE};
use crate::principal_state::{
    StateOwner, open_runtime_principal_store, open_runtime_principal_store_for_pack,
};

fn quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

fn volume_paths(home: &AstridHome) -> (PathBuf, PathBuf) {
    let destination = home.storage_volume_path();
    let migrating = destination.with_extension("migrating");
    (destination, migrating)
}

fn admission_reject_message(message: &str) -> bool {
    message.contains("private Windows path ACL is not restricted")
        || message.contains("create private directory")
        || message.contains("admit Astrid runtime root")
        || message.contains("redirected or not a directory")
        || message.contains("private Windows path")
}

fn assert_access_denied(error: &io::Error) {
    assert!(
        error.kind() == io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(5)
            || error.raw_os_error() == Some(32),
        "expected sharing/access denial, got {error:?}"
    );
}

/// Test-only: grant Everyone RX so `ExactPrivate` fails for a known reason.
fn grant_everyone_rx(path: &Path) {
    let status = Command::new("icacls")
        .arg(path)
        .args(["/grant", "*S-1-1-0:(RX)"])
        .status()
        .expect("spawn icacls grant");
    assert!(
        status.success(),
        "icacls grant *S-1-1-0:(RX) failed: {status}"
    );
}

/// Test-only: capture the path DACL via `icacls /save` for exact before/after compare.
///
/// Uses the same systemic `icacls` binary as [`grant_everyone_rx`]. Writes into an
/// owned temp directory file (no held `NamedTempFile` handle) so `/save` cannot
/// collide with an open destination. Compares raw saved DACL bytes, not a full
/// security descriptor. Avoids `Get-Acl` because PS5 can inherit PS7 module paths
/// and fail module load on native CI.
fn dacl_snapshot(path: &Path) -> Vec<u8> {
    let directory = tempfile::tempdir().expect("owned acl snapshot directory");
    let acl_file = directory.path().join("acl.txt");
    let status = Command::new("icacls")
        .arg(path)
        .arg("/save")
        .arg(&acl_file)
        .arg("/q")
        .status()
        .expect("spawn icacls /save");
    assert!(
        status.success(),
        "icacls /save failed for {}: {status}",
        path.display()
    );
    let bytes = std::fs::read(&acl_file).unwrap_or_else(|error| {
        panic!("read icacls DACL snapshot {}: {error}", acl_file.display())
    });
    assert!(
        !bytes.is_empty(),
        "icacls /save returned empty DACL snapshot for {}",
        path.display()
    );
    bytes
}

/// Test-only: capture inode identity + mtime so same-byte rewrites still fail.
fn regular_file_stamp(path: &Path) -> (same_file::Handle, u64, std::time::SystemTime) {
    let file = std::fs::File::open(path).expect("open identity snapshot");
    let metadata = file.metadata().expect("metadata");
    (
        same_file::Handle::from_file(file).expect("file identity"),
        metadata.len(),
        metadata.modified().expect("mtime"),
    )
}

#[tokio::test]
async fn fresh_missing_runtime_root_opens_with_private_acl_and_survives_reopen() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    assert!(
        !home.root().exists(),
        "fixture must start with a missing runtime root"
    );

    let store = open_runtime_principal_store(&home, quota())
        .await
        .expect("fresh open");
    astrid_core::platform_fs::validate_private_directory(home.root())
        .expect("fresh root must be ExactPrivate");

    let name = crate::ContentName::new("capsules/private-birth.wasm").unwrap();
    store
        .content()
        .put(&StateOwner::System, &name, b"capsule-v1")
        .expect("write through fresh store");
    assert_eq!(
        store.content().read(&StateOwner::System, &name).unwrap(),
        Some(b"capsule-v1".to_vec())
    );
    store.engine.close().expect("close fresh engine");

    let reopened = open_runtime_principal_store(&home, quota())
        .await
        .expect("reopen after private birth");
    astrid_core::platform_fs::validate_private_directory(home.root())
        .expect("reopened root remains ExactPrivate");
    assert_eq!(
        reopened.content().read(&StateOwner::System, &name).unwrap(),
        Some(b"capsule-v1".to_vec())
    );
}

#[tokio::test]
async fn for_pack_fresh_missing_root_admits_private_runtime_root() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let store = open_runtime_principal_store_for_pack(&home, quota())
        .await
        .expect("for-pack fresh open");
    astrid_core::platform_fs::validate_private_directory(home.root())
        .expect("for-pack fresh root must be ExactPrivate");
    assert!(
        home.storage_volume_path().is_file(),
        "for-pack fresh open must create the durable volume file"
    );
    // Bounded proof: private root + volume birth only. Content/reopen coverage
    // lives in the normal opener regression above.
    store.engine.close().unwrap();
}

#[tokio::test]
async fn preexisting_broad_runtime_root_rejects_without_creating_volume() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    std::fs::create_dir(home.root()).expect("create runtime root");
    // Do not rely on host tempfile inheritance: deliberately grant Everyone RX
    // so ExactPrivate fails for a fixture-owned reason on every Windows host.
    grant_everyone_rx(home.root());
    // icacls /save is UTF-16LE; do not UTF-8-decode for content markers.
    // Grant success + ExactPrivate rejection already prove the broad fixture.
    let before = dacl_snapshot(home.root());
    let validate_before = astrid_core::platform_fs::validate_private_directory(home.root())
        .expect_err("Everyone RX root must fail ExactPrivate");
    assert!(
        validate_before
            .to_string()
            .contains("private Windows path ACL is not restricted"),
        "{validate_before}"
    );

    let (destination, migrating) = volume_paths(&home);
    let Err(error) = open_runtime_principal_store(&home, quota()).await else {
        panic!("broad root must fail closed before volume bootstrap");
    };
    let message = error.to_string();
    assert!(admission_reject_message(&message), "{message}");
    assert!(
        !destination.exists(),
        "reject must not create astrid.volume"
    );
    assert!(
        !migrating.exists(),
        "reject must not create astrid.volume.migrating"
    );

    let after = dacl_snapshot(home.root());
    assert_eq!(
        before, after,
        "reject must preserve the deliberate broad DACL"
    );
    let validate_after = astrid_core::platform_fs::validate_private_directory(home.root())
        .expect_err("broad ACL must remain unrestored/unnormalized");
    assert!(
        validate_after
            .to_string()
            .contains("private Windows path ACL is not restricted"),
        "{validate_after}"
    );
}

#[tokio::test]
async fn redirected_symlink_runtime_root_rejects_without_creating_volume() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let target = parent.path().join("target");
    std::fs::create_dir(&target).unwrap();

    // Native CI already creates directory symlinks in core platform_fs tests;
    // do not silently substitute a regular file when privilege is missing.
    std::os::windows::fs::symlink_dir(&target, home.root())
        .expect("directory symlink fixture (SeCreateSymbolicLinkPrivilege / Developer Mode)");
    assert!(
        home.root()
            .symlink_metadata()
            .expect("symlink metadata")
            .file_type()
            .is_symlink(),
        "fixture must remain a directory symlink"
    );

    let (destination, migrating) = volume_paths(&home);
    let Err(error) = open_runtime_principal_store(&home, quota()).await else {
        panic!("symlink runtime root must fail closed");
    };
    let message = error.to_string();
    assert!(admission_reject_message(&message), "{message}");
    assert_eq!(std::fs::read_link(home.root()).unwrap(), target);
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
    assert!(!destination.exists(), "{destination:?} must stay absent");
    assert!(!migrating.exists(), "{migrating:?} must stay absent");
    assert!(
        home.root()
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "reject must not replace the symlink root"
    );
}

#[tokio::test]
async fn nondirectory_runtime_root_rejects_without_creating_volume() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    std::fs::write(home.root(), b"not-a-directory").unwrap();
    assert!(home.root().is_file());

    let (destination, migrating) = volume_paths(&home);
    let Err(error) = open_runtime_principal_store(&home, quota()).await else {
        panic!("file runtime root must fail closed");
    };
    assert!(matches!(error, crate::StorageError::Connection(_)));
    assert_eq!(std::fs::read(home.root()).unwrap(), b"not-a-directory");
    assert!(!destination.exists(), "{destination:?} must stay absent");
    assert!(!migrating.exists(), "{migrating:?} must stay absent");
    assert!(
        home.root().is_file(),
        "reject must leave the non-directory root in place"
    );
}

#[tokio::test]
async fn legacy_directory_store_under_broad_root_rejects_before_migrating_mutation() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));

    // Valid LEGACY directory-backed fixture under an ExactPrivate root first.
    astrid_core::platform_fs::ensure_private_directory(home.root())
        .expect("create private runtime root for fixture seeding");
    crate::principal_state::runtime_tests::seed_legacy_layout(&home);
    crate::principal_state::format_migration_tests::seed_current_directory_store(&home);

    let store_path = home.principal_store_path();
    astrid_core::platform_fs::validate_private_directory(&store_path)
        .expect("seeded principal-store must be ExactPrivate");
    assert_eq!(
        home.layout_version().unwrap().as_deref(),
        Some(astrid_core::dirs::LEGACY_LAYOUT_VERSION),
        "fixture must select the legacy migration path"
    );
    let metadata_path = store_path.join(STORE_METADATA_FILE);
    let marker_path = store_path.join(MIGRATION_MARKER_FILE);
    let metadata_before = std::fs::read(&metadata_path).expect("store.meta");
    let marker_before = std::fs::read(&marker_path).expect("migration.complete");
    assert_eq!(
        marker_before, KV_TRANSITION_CHECKPOINT_MARKER,
        "fixture must carry the completed directory-store migration marker"
    );
    assert!(
        !home.storage_volume_path().exists(),
        "fixture must have no hosted volume yet"
    );

    let (destination, migrating) = volume_paths(&home);
    let sentinel = b"stale-migrating-sentinel-before-admission";
    std::fs::write(&migrating, sentinel).expect("plant stale .migrating sentinel");
    let migrating_before = std::fs::read(&migrating).unwrap();
    assert_eq!(migrating_before, sentinel);
    let migrating_stamp = regular_file_stamp(&migrating);
    let metadata_stamp = regular_file_stamp(&metadata_path);
    let marker_stamp = regular_file_stamp(&marker_path);

    // Broaden only the runtime root. Keep the private principal-store intact so
    // rejection proves root admission, not invalid directory-store metadata.
    grant_everyone_rx(home.root());
    let root_dacl_before = dacl_snapshot(home.root());
    let store_dacl_before = dacl_snapshot(&store_path);
    astrid_core::platform_fs::validate_private_directory(home.root())
        .expect_err("Everyone RX root must fail ExactPrivate");
    astrid_core::platform_fs::validate_private_directory(&store_path)
        .expect("principal-store must remain ExactPrivate after root grant");

    let Err(error) = open_runtime_principal_store(&home, quota()).await else {
        panic!("broad legacy root must fail closed before migrate_directory_store");
    };
    let message = error.to_string();
    assert!(admission_reject_message(&message), "{message}");

    assert!(
        !destination.exists(),
        "reject must not publish astrid.volume"
    );
    assert_eq!(
        std::fs::read(&migrating).unwrap(),
        sentinel,
        "reject must not remove or rewrite the stale .migrating sentinel"
    );
    assert_eq!(
        regular_file_stamp(&migrating),
        migrating_stamp,
        "reject must preserve .migrating file identity and mtime"
    );
    assert_eq!(
        std::fs::read(&metadata_path).unwrap(),
        metadata_before,
        "directory-store metadata must stay untouched"
    );
    assert_eq!(
        regular_file_stamp(&metadata_path),
        metadata_stamp,
        "reject must preserve store.meta identity and mtime"
    );
    assert_eq!(
        std::fs::read(&marker_path).unwrap(),
        marker_before,
        "completed migration marker must stay untouched"
    );
    assert_eq!(
        regular_file_stamp(&marker_path),
        marker_stamp,
        "reject must preserve migration.complete identity and mtime"
    );
    assert_eq!(
        dacl_snapshot(home.root()),
        root_dacl_before,
        "reject must preserve the deliberate broad root DACL"
    );
    assert_eq!(
        dacl_snapshot(&store_path),
        store_dacl_before,
        "reject must not normalize the private principal-store DACL"
    );
}

#[tokio::test]
async fn retained_root_fences_ancestor_rename_for_normal_open_until_all_guards_drop() {
    let scratch = tempfile::tempdir().unwrap();
    let ancestor = scratch.path().join("ancestor");
    std::fs::create_dir(&ancestor).unwrap();
    let home = AstridHome::from_path(ancestor.join("runtime"));
    let moved = scratch.path().join("ancestor-moved");

    super::super::runtime_root_admission::arm_cutover_gap_hook({
        let ancestor = ancestor.clone();
        let moved = moved.clone();
        move || {
            let error = std::fs::rename(&ancestor, &moved)
                .expect_err("ancestor rename must fail during cutover gap");
            assert_access_denied(&error);
            assert!(ancestor.is_dir(), "cutover-gap rename must leave ancestor");
            assert!(
                !moved.exists(),
                "cutover-gap rename must not create destination"
            );
            // Hook body cannot mutate outer locals; record via side file.
            std::fs::write(scratch_gap_marker(&ancestor), b"denied").unwrap();
        }
    });

    let store = open_runtime_principal_store(&home, quota())
        .await
        .expect("fresh normal open under retained root");
    assert!(
        scratch_gap_marker(&ancestor).is_file(),
        "cutover-gap hook must run and deny ancestor rename before publish"
    );
    let _ = std::fs::remove_file(scratch_gap_marker(&ancestor));

    let error = std::fs::rename(&ancestor, &moved)
        .expect_err("live store must keep the retained-root ancestor fence");
    assert_access_denied(&error);
    assert!(ancestor.join("runtime").is_dir());
    assert!(!moved.exists());

    store.engine.close().expect("close live engine");
    drop(store);

    std::fs::rename(&ancestor, &moved)
        .expect("after engine close and store drop, ancestor rename must succeed");
    assert!(moved.join("runtime").is_dir());
    assert!(!ancestor.exists());
}

#[tokio::test]
async fn retained_root_fences_ancestor_rename_for_for_pack_open_until_all_guards_drop() {
    let scratch = tempfile::tempdir().unwrap();
    let ancestor = scratch.path().join("ancestor");
    std::fs::create_dir(&ancestor).unwrap();
    let home = AstridHome::from_path(ancestor.join("runtime"));
    let moved = scratch.path().join("ancestor-moved");

    super::super::runtime_root_admission::arm_cutover_gap_hook({
        let ancestor = ancestor.clone();
        let moved = moved.clone();
        move || {
            let error = std::fs::rename(&ancestor, &moved)
                .expect_err("for-pack cutover gap must deny ancestor rename");
            assert_access_denied(&error);
            assert!(ancestor.is_dir());
            assert!(!moved.exists());
            std::fs::write(scratch_gap_marker(&ancestor), b"denied").unwrap();
        }
    });

    let store = open_runtime_principal_store_for_pack(&home, quota())
        .await
        .expect("fresh for-pack open under retained root");
    assert!(
        scratch_gap_marker(&ancestor).is_file(),
        "for-pack cutover-gap hook must deny ancestor rename"
    );
    let _ = std::fs::remove_file(scratch_gap_marker(&ancestor));

    let error = std::fs::rename(&ancestor, &moved)
        .expect_err("live for-pack store must keep the retained-root ancestor fence");
    assert_access_denied(&error);
    assert!(ancestor.join("runtime").is_dir());
    assert!(!moved.exists());

    store.engine.close().expect("close for-pack engine");
    drop(store);

    std::fs::rename(&ancestor, &moved)
        .expect("after for-pack guards drop, ancestor rename must succeed");
    assert!(moved.join("runtime").is_dir());
    assert!(!ancestor.exists());
}

fn scratch_gap_marker(ancestor: &Path) -> PathBuf {
    ancestor
        .parent()
        .expect("ancestor has parent scratch")
        .join("cutover-gap-denied.marker")
}

#[test]
fn fresh_admit_allows_ambient_private_directory_while_retained_fence_holds() {
    use crate::principal_state::native_io::PrivateDirectory;
    use astrid_core::platform_fs::directory_capability::RetainedPrivateRoot;

    let scratch = tempfile::tempdir().unwrap();
    let ancestor = scratch.path().join("ancestor");
    std::fs::create_dir(&ancestor).unwrap();
    let root = ancestor.join("runtime");
    let moved = scratch.path().join("ancestor-moved");
    assert!(!root.exists(), "fixture starts with a missing runtime root");

    let retained = RetainedPrivateRoot::admit(&root).expect("fresh missing root admit");
    astrid_core::platform_fs::validate_private_directory(retained.path())
        .expect("admitted root must be ExactPrivate");

    // Old DELETE-retained admit fails here with OS 32 against cap-std ambient open.
    let directory = PrivateDirectory::open(retained.path())
        .expect("ambient PrivateDirectory::open must succeed under post-ensure retained reader");
    directory
        .sync()
        .expect("directory sync must succeed under retained reader");
    drop(directory);

    let error = std::fs::rename(&ancestor, &moved)
        .expect_err("retained admit fence must still block ancestor rename");
    assert_access_denied(&error);
    assert!(root.is_dir(), "denied rename must leave runtime root");
    assert!(!moved.exists(), "denied rename must not create destination");

    drop(retained);
    std::fs::rename(&ancestor, &moved)
        .expect("after retained-root drop, ancestor rename must succeed");
    assert!(moved.join("runtime").is_dir());
    assert!(!ancestor.exists());
}

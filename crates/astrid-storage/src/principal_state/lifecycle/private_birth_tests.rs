//! Windows fresh runtime-store private-at-birth regressions.
//!
//! The Windows initializer creates an ExactPrivate root before
//! volume bootstrap, and that deliberately broad/redirected roots fail closed
//! without creating volume media or mutating their ACL/reparse shape.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use astrid_core::dirs::AstridHome;

use crate::principal_state::{StateOwner, open_runtime_principal_store};
use crate::{KvQuotaResolver, open_runtime_principal_store_for_pack};

fn quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

fn volume_paths(home: &AstridHome) -> (PathBuf, PathBuf) {
    let destination = home.storage_volume_path();
    let migrating = destination.with_extension("migrating");
    (destination, migrating)
}

/// Test-only: grant Everyone RX so ExactPrivate fails for a known reason.
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

/// Test-only: capture the current DACL as SDDL for exact before/after compare.
fn dacl_sddl(path: &Path) -> String {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "(Get-Acl -LiteralPath '{}').Sddl",
                path.display().to_string().replace('\'', "''")
            ),
        ])
        .output()
        .expect("spawn Get-Acl");
    assert!(
        output.status.success(),
        "Get-Acl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let sddl = String::from_utf8(output.stdout)
        .expect("SDDL utf8")
        .trim()
        .to_owned();
    assert!(!sddl.is_empty(), "Get-Acl returned empty SDDL for {path:?}");
    sddl
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
    let before = dacl_sddl(home.root());
    assert!(
        before.contains("WD") || before.to_ascii_uppercase().contains("EVERYONE"),
        "fixture SDDL must include Everyone/World after grant: {before}"
    );
    let validate_before = astrid_core::platform_fs::validate_private_directory(home.root())
        .expect_err("Everyone RX root must fail ExactPrivate");
    assert!(
        validate_before
            .to_string()
            .contains("private Windows path ACL is not restricted"),
        "{validate_before}"
    );

    let (destination, migrating) = volume_paths(&home);
    let error = open_runtime_principal_store(&home, quota())
        .await
        .expect_err("broad root must fail closed before volume bootstrap");
    let message = error.to_string();
    assert!(
        message.contains("private Windows path ACL is not restricted")
            || message.contains("create private directory"),
        "{message}"
    );
    assert!(
        !destination.exists(),
        "reject must not create astrid.volume"
    );
    assert!(
        !migrating.exists(),
        "reject must not create astrid.volume.migrating"
    );

    let after = dacl_sddl(home.root());
    assert_eq!(
        before, after,
        "reject must preserve the deliberate broad security descriptor"
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
    let error = open_runtime_principal_store(&home, quota())
        .await
        .expect_err("symlink runtime root must fail closed");
    let message = error.to_string();
    assert!(
        message.contains("redirected or not a directory")
            || message.contains("create private directory")
            || message.contains("private Windows path"),
        "{message}"
    );
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
    let error = open_runtime_principal_store(&home, quota())
        .await
        .expect_err("file runtime root must fail closed");
    assert!(matches!(error, crate::StorageError::Connection(_)));
    assert_eq!(std::fs::read(home.root()).unwrap(), b"not-a-directory");
    assert!(!destination.exists(), "{destination:?} must stay absent");
    assert!(!migrating.exists(), "{migrating:?} must stay absent");
    assert!(
        home.root().is_file(),
        "reject must leave the non-directory root in place"
    );
}

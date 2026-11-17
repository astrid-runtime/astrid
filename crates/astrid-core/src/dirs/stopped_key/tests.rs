use super::*;

fn fixture() -> (tempfile::TempDir, AstridHome) {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    crate::platform_fs::ensure_private_directory(home.root()).unwrap();
    crate::platform_fs::atomic_write_private_file(&home.storage_volume_path(), b"media").unwrap();
    crate::platform_fs::ensure_private_directory(&home.keys_dir()).unwrap();
    crate::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &[9; 32]).unwrap();
    (root, home)
}

#[test]
fn only_exact_recovery_shape_is_recognized() {
    let (_root, home) = fixture();
    assert!(recognize(&home).unwrap());
    assert!(home.validate_runtime_identity_provisioning().is_err());
    fs::write(home.keys_dir().join("other.key"), b"unexpected").unwrap();
    assert!(!recognize(&home).unwrap());
    assert!(home.ensure().is_err());
}

#[test]
fn malformed_key_lengths_remain_rejected_and_unchanged() {
    for length in [0, 31, 33] {
        let (_root, home) = fixture();
        let bytes = vec![8; length];
        crate::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &bytes).unwrap();
        assert!(recognize(&home).is_err());
        assert!(home.ensure().is_err());
        assert_eq!(fs::read(home.runtime_key_path()).unwrap(), bytes);
    }
}

#[test]
fn boot_singleton_is_allowed_but_other_run_state_is_not() {
    let (_root, home) = fixture();
    let run = home.root().join("run");
    crate::platform_fs::ensure_private_directory(&run).unwrap();
    assert!(!recognize(&home).unwrap());
    crate::platform_fs::atomic_write_private_file(&run.join("system.lock"), b"").unwrap();
    assert!(recognize(&home).unwrap());
    crate::platform_fs::atomic_write_private_file(&run.join("system.ready"), b"ready").unwrap();
    assert!(!recognize(&home).unwrap());
}

#[test]
fn interrupted_sentinel_parent_cannot_admit_configuration() {
    let (_root, home) = fixture();
    let etc = home.root().join("etc");
    crate::platform_fs::ensure_private_directory(&etc).unwrap();
    assert!(recognize(&home).unwrap());
    assert!(home.validate_runtime_identity_provisioning().is_err());
    let run = home.root().join("run");
    crate::platform_fs::ensure_private_directory(&run).unwrap();
    crate::platform_fs::atomic_write_private_file(&run.join("system.lock"), b"").unwrap();
    assert!(recognize(&home).unwrap());
    crate::platform_fs::atomic_write_private_file(&etc.join("config.toml"), b"foreign").unwrap();
    assert!(!recognize(&home).unwrap());
    assert!(home.ensure().is_err());
    assert_eq!(fs::read(etc.join("config.toml")).unwrap(), b"foreign");
}

#[cfg(unix)]
#[test]
fn sentinel_staging_must_have_exact_name_and_private_access() {
    use std::os::unix::fs::PermissionsExt;

    let (_root, home) = fixture();
    let staged = home
        .root()
        .join("etc/.astrid-private-00000000000040008000000000000001");
    crate::platform_fs::atomic_write_private_file(&staged, b"incomplete").unwrap();
    assert!(recognize(&home).unwrap());
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(recognize(&home).is_err());
    crate::platform_fs::restrict_private_file(&staged).unwrap();
    let malformed = staged.parent().unwrap().join(".astrid-private-unknown");
    fs::rename(&staged, &malformed).unwrap();
    assert!(!recognize(&home).unwrap());
    assert!(home.ensure().is_err());
    assert_eq!(fs::read(malformed).unwrap(), b"incomplete");
}

#[cfg(unix)]
#[test]
fn unsafe_access_and_redirects_remain_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let (_root, home) = fixture();
    fs::set_permissions(home.keys_dir(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(recognize(&home).is_err());
    fs::set_permissions(home.keys_dir(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(recognize(&home).unwrap());
    fs::set_permissions(home.runtime_key_path(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(recognize(&home).is_err());
    crate::platform_fs::restrict_private_file(&home.runtime_key_path()).unwrap();
    let saved = tempfile::tempdir().unwrap();
    let target = saved.path().join("saved-key");
    fs::rename(home.runtime_key_path(), &target).unwrap();
    symlink(&target, home.runtime_key_path()).unwrap();
    assert!(recognize(&home).is_err());
    assert!(home.ensure().is_err());
    assert_eq!(fs::read(target).unwrap(), [9; 32]);
}

#[cfg(target_os = "macos")]
#[test]
fn legacy_key_directory_with_extended_acl_is_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let (_root, home) = fixture();
    fs::set_permissions(home.keys_dir(), fs::Permissions::from_mode(0o755)).unwrap();
    let status = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone allow write,delete_child"])
        .arg(home.keys_dir())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(recognize(&home).is_err());
    assert!(home.ensure().is_err());
    assert_eq!(fs::read(home.runtime_key_path()).unwrap(), [9; 32]);
}

#[test]
fn keyless_sentinel_residue_is_recognized_without_identity_authority() {
    for staged in [false, true] {
        let (_root, home) = fixture();
        fs::remove_file(home.runtime_key_path()).unwrap();
        fs::remove_dir(home.keys_dir()).unwrap();
        let etc = home.root().join("etc");
        crate::platform_fs::ensure_private_directory(&etc).unwrap();
        if staged && cfg!(unix) {
            crate::platform_fs::atomic_write_private_file(
                &etc.join(".astrid-private-00000000000040008000000000000001"),
                b"partial",
            )
            .unwrap();
        }
        assert_eq!(
            home.stopped_projection_recovery().unwrap(),
            Some(StoppedProjectionRecovery::Sentinel)
        );
        assert!(!home.requires_stopped_key_recovery().unwrap());
        home.ensure().unwrap();
        assert!(home.validate_runtime_identity_provisioning().is_err());
        let run = home.root().join("run");
        crate::platform_fs::ensure_private_directory(&run).unwrap();
        crate::platform_fs::atomic_write_private_file(&run.join("system.lock"), b"").unwrap();
        home.ensure().unwrap();
        crate::platform_fs::atomic_write_private_file(&etc.join("config.toml"), b"unadmitted")
            .unwrap();
        assert!(home.stopped_projection_recovery().unwrap().is_none());
        assert!(home.ensure().is_err());
        assert_eq!(fs::read(etc.join("config.toml")).unwrap(), b"unadmitted");
    }
}

#[cfg(unix)]
#[test]
fn stopped_recovery_admission_does_not_repair_root_before_authority() {
    use std::os::unix::fs::PermissionsExt as _;

    for residue in [
        None,
        Some(StoppedProjectionRecovery::RuntimeKey),
        Some(StoppedProjectionRecovery::Sentinel),
    ] {
        for mode in [0o755, 0o777] {
            let (_root, home) = fixture();
            if residue != Some(StoppedProjectionRecovery::RuntimeKey) {
                fs::remove_file(home.runtime_key_path()).unwrap();
                fs::remove_dir(home.keys_dir()).unwrap();
            }
            if residue == Some(StoppedProjectionRecovery::Sentinel) {
                crate::platform_fs::ensure_private_directory(&home.root().join("etc")).unwrap();
            }
            fs::set_permissions(home.root(), fs::Permissions::from_mode(mode)).unwrap();
            let result = home.ensure();
            assert_eq!(
                result.is_ok(),
                mode == 0o755,
                "{residue:?}, {mode:o}: {result:?}"
            );
            assert_eq!(
                fs::metadata(home.root()).unwrap().permissions().mode() & 0o777,
                mode
            );
            assert!(home.validate_runtime_identity_provisioning().is_err());
            assert_eq!(fs::read(home.storage_volume_path()).unwrap(), b"media");
            if mode == 0o755 {
                assert_eq!(home.stopped_projection_recovery().unwrap(), residue);
            }
            if residue == Some(StoppedProjectionRecovery::Sentinel) {
                assert_eq!(fs::read_dir(home.root().join("etc")).unwrap().count(), 0);
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn scoped_sentinel_staging_is_recognized_without_cleanup_authority() {
    let (_root, home) = fixture();
    fs::remove_file(home.runtime_key_path()).unwrap();
    fs::remove_dir(home.keys_dir()).unwrap();
    let scope = crate::platform_fs::StagingScope::new();
    let staged = home.root().join("etc").join(scope.temporary_basename());
    crate::platform_fs::atomic_write_private_file(&staged, b"partial").unwrap();
    assert_eq!(
        home.stopped_projection_recovery().unwrap(),
        Some(StoppedProjectionRecovery::Sentinel)
    );
    home.ensure().unwrap();
    assert_eq!(fs::read(staged).unwrap(), b"partial");
    assert!(home.validate_runtime_identity_provisioning().is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn stopped_root_acl_is_rejected_without_repair() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_root, home) = fixture();
    fs::set_permissions(home.root(), fs::Permissions::from_mode(0o755)).unwrap();
    let status = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone allow read,readattr"])
        .arg(home.root())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(home.ensure().is_err());
    assert!(crate::platform_fs::validate_no_extended_acl(home.root()).is_err());
    assert_eq!(
        fs::metadata(home.root()).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(fs::read(home.runtime_key_path()).unwrap(), [9; 32]);
}

#[cfg(unix)]
#[test]
fn ordinary_configuration_is_not_classified_as_stopped_sentinel_residue() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_root, home) = fixture();
    fs::remove_file(home.runtime_key_path()).unwrap();
    fs::remove_dir(home.keys_dir()).unwrap();
    let etc = home.root().join("etc");
    fs::create_dir(&etc).unwrap();
    fs::set_permissions(&etc, fs::Permissions::from_mode(0o755)).unwrap();
    let configuration = etc.join("operator.conf");
    fs::write(&configuration, b"unreceipted configuration").unwrap();
    assert_eq!(home.stopped_projection_recovery().unwrap(), None);
    assert!(home.validate_runtime_identity_provisioning().is_err());
    assert_eq!(
        fs::read(configuration).unwrap(),
        b"unreceipted configuration"
    );
    assert_eq!(
        fs::metadata(etc).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

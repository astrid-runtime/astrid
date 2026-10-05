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

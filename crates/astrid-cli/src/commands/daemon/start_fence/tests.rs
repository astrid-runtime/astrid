use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn lock_leaf_alias_is_refused_without_mutating_target() {
    let root = tempfile::tempdir().expect("owned root");
    let target = root.path().join("target");
    std::fs::write(&target, b"retained").expect("target contents");
    let directory = root.path().join("astrid-start-fences");
    std::fs::create_dir(&directory).expect("directory");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("private directory");
    let path = directory.join("fixture.lock");
    std::os::unix::fs::symlink(&target, &path).expect("leaf alias");
    assert!(open(&path).is_err());
    assert_eq!(
        std::fs::read(&target).expect("retained target"),
        b"retained"
    );
    assert!(
        path.symlink_metadata()
            .expect("retained alias")
            .is_symlink()
    );
}

#[test]
fn private_fence_can_be_reused_after_unlock() {
    let root = tempfile::tempdir().expect("owned root");
    let path = root.path().join("astrid-start-fences/fixture.lock");
    drop(open(&path).expect("first fence"));
    drop(open(&path).expect("reused fence"));
    assert!(path.is_file());
}

#[test]
fn legacy_owner_keeps_the_original_lock_inode() {
    use std::os::unix::fs::MetadataExt;

    let root = tempfile::tempdir().expect("owned root");
    let path = root.path().join("astrid-start-fences/fixture.lock");
    drop(open(&path).expect("legacy fence"));
    let original_inode = std::fs::metadata(&path).expect("legacy metadata").ino();
    let lock = open(&path).expect("new CLI reuses legacy fence");
    assert_eq!(
        lock.metadata().expect("lock metadata").ino(),
        original_inode
    );
    let competitor = File::options().read(true).write(true).open(&path).unwrap();
    assert!(matches!(
        competitor.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn unsafe_private_lock_files_are_refused() {
    for mode in [0o644, 0o666] {
        let root = tempfile::tempdir().expect("owned root");
        let path = root.path().join("astrid-start-fences/fixture.lock");
        drop(open(&path).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(open(&path).is_err());
    }
    let root = tempfile::tempdir().expect("owned root");
    let path = root.path().join("astrid-start-fences/fixture.lock");
    drop(open(&path).unwrap());
    std::fs::hard_link(&path, root.path().join("alias")).unwrap();
    assert!(open(&path).is_err());
}

// Run under a root Linux test process to exercise actual ownership, not a
// mocked UID predicate. Ordinary developer runs still exercise the other tests.
#[cfg(target_os = "linux")]
#[test]
fn foreign_owner_uses_private_fence_without_changing_legacy() {
    use std::os::unix::{fs::MetadataExt, process::CommandExt};

    if !nix::unistd::getuid().is_root() {
        eprintln!("requires root Linux runner for real second-UID regression");
        return;
    }
    let root = tempfile::tempdir().expect("shared temporary root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
    let legacy = root.path().join("astrid-start-fences/fixture.lock");
    let lock = open(&legacy).expect("first user's held legacy fence");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "commands::daemon::start_fence::tests::foreign_owner_child",
            "--nocapture",
        ])
        .env("ASTRID_TEST_FOREIGN_FENCE", &legacy)
        .uid(65534)
        .gid(65534)
        .output()
        .expect("second OS user");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(lock.metadata().unwrap().uid(), 0);
    assert_eq!(
        std::fs::metadata(legacy.parent().unwrap()).unwrap().mode() & 0o777,
        0o700
    );
}

#[cfg(target_os = "linux")]
#[test]
fn foreign_owner_child() {
    use std::os::unix::fs::MetadataExt;

    let Some(path) = std::env::var_os("ASTRID_TEST_FOREIGN_FENCE") else {
        return;
    };
    assert_eq!(nix::unistd::getuid().as_raw(), 65534);
    let path = std::path::PathBuf::from(path);
    let root = path.parent().unwrap().parent().unwrap();
    let lock = open(&path).expect("foreign legacy directory must not block startup");
    let private = root.join("astrid-start-fences-65534");
    assert_eq!(std::fs::metadata(&private).unwrap().uid(), 65534);
    assert_eq!(std::fs::metadata(&private).unwrap().mode() & 0o777, 0o700);
    let competitor = File::options()
        .read(true)
        .write(true)
        .open(private.join("fixture.lock"))
        .unwrap();
    assert!(matches!(
        competitor.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(lock);
    drop(open(&path).expect("repeated same-user acquisition"));
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(open(&path).is_err(), "fallback must remain private");
    assert_eq!(std::fs::metadata(&private).unwrap().mode() & 0o777, 0o755);
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_file(private.join("fixture.lock")).unwrap();
    std::os::unix::fs::symlink(&path, private.join("fixture.lock")).unwrap();
    assert!(open(&path).is_err(), "fallback leaf alias must be rejected");
    std::fs::remove_file(private.join("fixture.lock")).unwrap();
    std::fs::remove_dir(&private).unwrap();
    std::os::unix::fs::symlink(root.join("astrid-start-fences"), &private).unwrap();
    assert!(
        open(&path).is_err(),
        "fallback directory alias must be rejected"
    );
    std::fs::remove_file(&private).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn foreign_socket_cannot_select_a_fallback_directory() {
    use std::os::unix::{net::UnixListener, process::CommandExt};

    if !nix::unistd::getuid().is_root() {
        eprintln!("requires root Linux runner for real foreign socket regression");
        return;
    }
    let root = tempfile::tempdir().expect("shared temporary root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
    let legacy = root.path().join("astrid-start-fences");
    let _listener = UnixListener::bind(&legacy).expect("foreign owned socket");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "commands::daemon::start_fence::tests::foreign_socket_child",
            "--nocapture",
        ])
        .env("ASTRID_TEST_FOREIGN_SOCKET", legacy.join("fixture.lock"))
        .uid(65534)
        .gid(65534)
        .output()
        .expect("second OS user");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.path().join("astrid-start-fences-65534").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn foreign_socket_child() {
    let Some(path) = std::env::var_os("ASTRID_TEST_FOREIGN_SOCKET") else {
        return;
    };
    assert_eq!(nix::unistd::getuid().as_raw(), 65534);
    assert!(
        open(Path::new(&path)).is_err(),
        "foreign socket must not be admitted as a directory"
    );
}

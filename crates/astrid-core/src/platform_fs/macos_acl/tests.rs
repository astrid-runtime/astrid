use super::*;
use std::path::Path;

fn add_acl(path: &Path, rule: &str) {
    assert!(
        std::process::Command::new("/bin/chmod")
            .args(["+a", rule])
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn descriptor_checks_reject_allow_deny_and_inherited_acl_entries() {
    let root = tempfile::tempdir().unwrap();
    for (index, rule) in [
        "everyone allow read",
        "everyone deny write",
        "everyone allow read,file_inherit,directory_inherit",
    ]
    .into_iter()
    .enumerate()
    {
        let path = root.path().join(index.to_string());
        std::fs::create_dir(&path).unwrap();
        let file = File::open(&path).unwrap();
        validate(&file).unwrap();
        add_acl(&path, rule);
        assert_eq!(
            validate(&file).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        restrict(&file).unwrap();
        validate(&file).unwrap();
        // Re-read through the public boundary as well as the captured handle.
        super::super::validate_no_extended_acl(&path).unwrap();
    }
}

#[test]
fn acl_restriction_targets_the_captured_inode_after_path_replacement() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("secret");
    let displaced = root.path().join("captured");
    std::fs::write(&path, b"captured").unwrap();
    add_acl(&path, "everyone allow read");
    let file = File::open(&path).unwrap();
    std::fs::rename(&path, &displaced).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    add_acl(&path, "everyone allow read");
    restrict(&file).unwrap();
    super::super::validate_no_extended_acl(&displaced).unwrap();
    assert!(super::super::validate_no_extended_acl(&path).is_err());
    assert_eq!(std::fs::read(&displaced).unwrap(), b"captured");
    assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
}

#[test]
fn public_acl_inspection_rejects_missing_and_redirected_paths() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target");
    std::fs::write(&target, b"secret").unwrap();
    let alias = root.path().join("alias");
    symlink(&target, &alias).unwrap();
    assert!(super::super::validate_no_extended_acl(&alias).is_err());
    assert!(super::super::validate_no_extended_acl(&root.path().join("missing")).is_err());
}

#[test]
fn empty_acl_is_accepted_after_repeated_restriction() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("secret");
    std::fs::write(&path, b"secret").unwrap();
    let file = File::open(path).unwrap();
    for _ in 0..64 {
        restrict(&file).unwrap();
        validate(&file).unwrap();
    }
}

#[test]
fn inherited_child_acl_is_rejected_without_changing_posix_modes() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("parent");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    add_acl(
        &parent,
        "everyone allow read,file_inherit,directory_inherit",
    );
    let path = parent.join("child");
    std::fs::write(&path, b"secret").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let file = File::open(&path).unwrap();
    assert!(validate(&file).is_err());
    restrict(&file).unwrap();
    assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    let directory = File::open(&parent).unwrap();
    restrict(&directory).unwrap();
    assert_eq!(
        directory.metadata().unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn private_file_validation_rejects_fifo_without_waiting_for_a_writer() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("fifo");
    nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        send.send(super::super::validate_private_file(&path))
            .unwrap();
    });
    let result = receive
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    worker.join().unwrap();
}

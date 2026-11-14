use std::io;
use std::os::unix::fs::symlink;

use super::{retire_projection_root, unix::retire_with_hook};

#[test]
fn retirement_does_not_require_regular_leaf_read_permission() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("run")).unwrap();
    std::fs::write(temp.path().join("astrid.volume"), b"durable authority").unwrap();
    for relative in ["excluded-host-file", "run/packed"] {
        let path = temp.path().join(relative);
        std::fs::write(&path, b"already packed or excluded").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
    }

    retire_projection_root(temp.path()).unwrap();

    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    assert_eq!(
        std::fs::read(temp.path().join("astrid.volume")).unwrap(),
        b"durable authority"
    );
}

#[test]
fn retirement_keeps_only_canonical_volume() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    std::fs::create_dir_all(root.join("profiles/a/nested")).unwrap();
    std::fs::write(root.join("astrid.volume"), b"durable authority").unwrap();
    std::fs::write(root.join("profiles/a/nested/文書"), b"packed").unwrap();
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStringExt as _;
        let name = std::ffi::OsString::from_vec(vec![b'n', 0xff]);
        std::fs::write(root.join("profiles/a/nested").join(name), b"packed").unwrap();
    }
    std::fs::write(root.join("root-file"), b"packed too").unwrap();

    retire_projection_root(&root).unwrap();

    assert_eq!(
        std::fs::read(root.join("astrid.volume")).unwrap(),
        b"durable authority"
    );
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 1);
}

#[test]
fn late_nested_redirect_preflight_leaves_every_entry_untouched() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(root.join("z/nested")).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("precious"), b"outside").unwrap();
    std::fs::write(root.join("a"), b"must survive preflight").unwrap();
    symlink(&outside, root.join("z/nested/redirect")).unwrap();

    assert!(retire_projection_root(&root).is_err());

    assert_eq!(
        std::fs::read(root.join("a")).unwrap(),
        b"must survive preflight"
    );
    assert_eq!(std::fs::read(outside.join("precious")).unwrap(), b"outside");
}

#[test]
fn replaced_root_between_preflight_and_delete_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let moved = temp.path().join("original");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("packed"), b"original").unwrap();

    let result = retire_with_hook(&root, || {
        std::fs::rename(&root, &moved)?;
        std::fs::create_dir(&root)?;
        std::fs::write(root.join("packed"), b"replacement")
    });

    assert!(result.is_err());
    assert_eq!(std::fs::read(moved.join("packed")).unwrap(), b"original");
    assert_eq!(std::fs::read(root.join("packed")).unwrap(), b"replacement");
}

#[test]
fn missing_root_cannot_retire_its_nearest_existing_parent() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("precious"), b"parent").unwrap();

    let error = retire_projection_root(&temp.path().join("missing/tail")).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(
        std::fs::read(temp.path().join("precious")).unwrap(),
        b"parent"
    );
}

#[test]
fn canonical_volume_must_not_be_a_directory() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("astrid.volume")).unwrap();
    std::fs::write(temp.path().join("a"), b"untouched").unwrap();

    assert!(retire_projection_root(temp.path()).is_err());
    assert_eq!(std::fs::read(temp.path().join("a")).unwrap(), b"untouched");
}

#[test]
fn late_special_entry_is_rejected_before_any_removal() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("z")).unwrap();
    std::fs::write(temp.path().join("a"), b"untouched").unwrap();
    nix::unistd::mkfifo(&temp.path().join("z/fifo"), nix::sys::stat::Mode::S_IRUSR).unwrap();

    assert!(retire_projection_root(temp.path()).is_err());
    assert_eq!(std::fs::read(temp.path().join("a")).unwrap(), b"untouched");
}

#[test]
fn redirect_introduced_after_preflight_cannot_touch_outside_contents() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(root.join("projection")).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(root.join("astrid.volume"), b"durable authority").unwrap();
    std::fs::write(outside.join("precious"), b"outside").unwrap();

    let result = retire_with_hook(&root, || {
        std::fs::remove_dir(root.join("projection"))?;
        symlink(&outside, root.join("projection"))
    });

    assert!(result.is_err());
    assert_eq!(std::fs::read(outside.join("precious")).unwrap(), b"outside");
    assert_eq!(
        std::fs::read(root.join("astrid.volume")).unwrap(),
        b"durable authority"
    );
}

#[test]
fn nested_file_replaced_after_preflight_cannot_redirect_deletion() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::write(root.join("nested/file"), b"packed").unwrap();
    std::fs::write(&outside, b"precious").unwrap();

    let result = retire_with_hook(&root, || {
        std::fs::remove_file(root.join("nested/file"))?;
        symlink(&outside, root.join("nested/file"))
    });

    assert!(result.is_err());
    assert_eq!(std::fs::read(&outside).unwrap(), b"precious");
}

#[test]
fn redirected_canonical_volume_preflight_preserves_siblings() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let outside = temp.path().join("outside");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("a"), b"untouched").unwrap();
    std::fs::write(&outside, b"precious").unwrap();
    symlink(&outside, root.join("astrid.volume")).unwrap();

    assert!(retire_projection_root(&root).is_err());
    assert_eq!(std::fs::read(root.join("a")).unwrap(), b"untouched");
    assert_eq!(std::fs::read(&outside).unwrap(), b"precious");
}

#[test]
fn canonical_survivor_does_not_require_content_read_permission() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir().unwrap();
    let volume = temp.path().join("astrid.volume");
    std::fs::write(&volume, b"durable authority").unwrap();
    std::fs::set_permissions(&volume, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::write(temp.path().join("packed"), b"retire").unwrap();

    retire_projection_root(temp.path()).unwrap();

    std::fs::set_permissions(&volume, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(std::fs::read(volume).unwrap(), b"durable authority");
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
}

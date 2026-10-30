use std::ffi::{OsStr, OsString};
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::symlink;
use std::path::Path;

use super::retire_after_preflight;

fn volume(root: &Path) {
    fs::write(root.join("astrid.volume"), b"canonical media").unwrap();
}

#[test]
fn public_retirement_walks_ancestry_once_for_many_siblings() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    volume(root);
    for number in 0..48 {
        let child = root.join(format!("projection-{number}"));
        fs::create_dir(&child).unwrap();
        fs::write(child.join("state"), b"projection").unwrap();
    }
    crate::platform_fs::reset_directory_walk_count();
    crate::dirs::retire_projection_root(root).unwrap();
    assert_eq!(crate::platform_fs::directory_walk_count(), 1);
    assert_eq!(fs::read_dir(root).unwrap().count(), 1);
    assert_eq!(
        fs::read(root.join("astrid.volume")).unwrap(),
        b"canonical media"
    );
}

#[test]
fn late_nested_redirect_preserves_earlier_file() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    let outside = directory.path().join("outside");
    fs::create_dir_all(root.join("z-late/nested")).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    fs::write(outside.join("sentinel"), b"outside").unwrap();
    symlink(&outside, root.join("z-late/nested/redirect")).unwrap();
    assert!(crate::dirs::retire_projection_root(&root).is_err());
    assert_eq!(fs::read(root.join("a-earlier")).unwrap(), b"keep");
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"outside");
}

#[test]
fn late_nested_special_preserves_earlier_file() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    fs::create_dir_all(root.join("z-late/nested")).unwrap();
    nix::unistd::mkfifo(
        &root.join("z-late/nested/fifo"),
        nix::sys::stat::Mode::S_IRUSR,
    )
    .unwrap();
    assert!(crate::dirs::retire_projection_root(root).is_err());
    assert_eq!(fs::read(root.join("a-earlier")).unwrap(), b"keep");
}

#[test]
fn redirected_root_preserves_target() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("sentinel"), b"keep").unwrap();
    let root = directory.path().join("redirect");
    symlink(&target, &root).unwrap();
    assert!(crate::dirs::retire_projection_root(&root).is_err());
    assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"keep");
}

#[test]
fn missing_root_preserves_existing_ancestor() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("sentinel"), b"keep").unwrap();
    let error =
        crate::dirs::retire_projection_root(&directory.path().join("missing/nested")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(
        fs::read(directory.path().join("sentinel")).unwrap(),
        b"keep"
    );
}

#[test]
fn post_preflight_replacement_preserves_all_entries() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir_all(root.join("z-child")).unwrap();
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    fs::write(root.join("z-child/state"), b"original").unwrap();
    let replacement = directory.path().join("replacement");
    fs::write(&replacement, b"replacement").unwrap();
    let result = retire_after_preflight(&root, || {
        fs::rename(&replacement, root.join("z-child/state")).unwrap();
    });
    assert!(result.is_err());
    assert_eq!(fs::read(root.join("a-earlier")).unwrap(), b"keep");
    assert_eq!(
        fs::read(root.join("z-child/state")).unwrap(),
        b"replacement"
    );
}

#[test]
fn post_preflight_volume_swap_preserves_projection() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    volume(&root);
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    let replacement = directory.path().join("replacement");
    fs::write(&replacement, b"replacement volume").unwrap();
    let result = retire_after_preflight(&root, || {
        fs::rename(&replacement, root.join("astrid.volume")).unwrap();
    });
    assert!(result.is_err());
    assert_eq!(fs::read(root.join("a-earlier")).unwrap(), b"keep");
    assert_eq!(
        fs::read(root.join("astrid.volume")).unwrap(),
        b"replacement volume"
    );
}

#[test]
fn canonical_volume_is_only_survivor() {
    check_only_volume_survives(OsStr::new("projection"), OsStr::new("state"));
}

#[cfg(target_os = "linux")]
#[test]
fn canonical_volume_is_only_survivor_with_non_utf8_entries() {
    check_only_volume_survives(OsStr::from_bytes(&[b'p', 0xff]), OsStr::from_bytes(&[0xfe]));
}

fn check_only_volume_survives(opaque: &OsStr, file_name: &OsStr) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    volume(root);
    fs::create_dir(root.join(opaque)).unwrap();
    fs::write(root.join(opaque).join(file_name), b"projection").unwrap();
    fs::write(root.join("astrid.volume.extra"), b"projection").unwrap();
    crate::dirs::retire_projection_root(root).unwrap();
    let names = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(names, [OsString::from("astrid.volume")]);
    assert_eq!(
        fs::read(root.join("astrid.volume")).unwrap(),
        b"canonical media"
    );
}

#[test]
fn canonical_volume_must_be_a_regular_file() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("astrid.volume")).unwrap();
    fs::write(directory.path().join("a-earlier"), b"keep").unwrap();
    assert!(crate::dirs::retire_projection_root(directory.path()).is_err());
    assert!(directory.path().join("a-earlier").exists());
}

#[test]
fn unreadable_root_files_retire_without_requiring_content_access() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    volume(root);
    let media = root.join("astrid.volume");
    let projection = root.join("a-unreadable");
    fs::write(&projection, b"projection").unwrap();
    for path in [&media, &projection] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o0)).unwrap();
        if !nix::unistd::geteuid().is_root() {
            assert_eq!(
                fs::File::open(path).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
    }
    let result = crate::dirs::retire_projection_root(root);
    fs::set_permissions(&media, fs::Permissions::from_mode(0o600)).unwrap();
    result.unwrap();
    assert!(!projection.exists());
    assert_eq!(fs::read(&media).unwrap(), b"canonical media");
}

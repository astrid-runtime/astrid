//! The captured core handle must remain usable as storage traversal authority.

use super::assert_path_writer_excluded;
use astrid_core::platform_fs::{CapturedDirectory, create_private_directory};
use std::path::Path;

fn assert_captured_entries(captured: &CapturedDirectory, path: &Path) {
    let directory = super::PrivateDirectory::from_std_directory_file(
        captured.try_clone_directory_file().unwrap(),
        path.to_path_buf(),
    )
    .unwrap();
    let mut names = directory.entries().unwrap();
    names.sort();
    assert_eq!(names, ["LOCK", "payload"].map(std::ffi::OsString::from));
}

#[test]
fn captured_source_capability_moves_and_retires_under_the_same_writer_fence() {
    let temporary = super::private_temp();
    let workspace = temporary.path().join("workspace");
    create_private_directory(&workspace).unwrap();
    let source = workspace.join("source");
    let staging = workspace.join("staging");
    let staged = staging.join("captured");
    create_private_directory(&source).unwrap();
    create_private_directory(&staging).unwrap();
    std::fs::write(source.join("LOCK"), b"unchanged lock").unwrap();
    std::fs::write(source.join("payload"), b"original source").unwrap();

    let mut captured = CapturedDirectory::open(&source).unwrap();
    let identity = captured.identity();
    assert_captured_entries(&captured, &source);
    // Do not reopen the directory by path: that is a different native file
    // object, incompatible with the retained DELETE/no-share-delete owner.
    let directory = cap_std::fs::Dir::from_std_file(captured.try_clone_directory_file().unwrap());
    let lock = directory.open("LOCK").unwrap().into_std();
    lock.try_lock_shared().unwrap();
    let guard = super::super::source_lock::handoff(lock).unwrap();
    assert_path_writer_excluded(&source.join("LOCK"));
    assert_eq!(directory.read("payload").unwrap(), b"original source");
    assert_eq!(directory.entries().unwrap().count(), 2);
    captured.rename_to(&staged).unwrap();
    assert!(!source.exists());
    assert_eq!(captured.identity(), identity);
    assert_captured_entries(&captured, &staged);
    assert_eq!(directory.read("payload").unwrap(), b"original source");
    assert_eq!(directory.read("LOCK").unwrap(), b"unchanged lock");
    assert_path_writer_excluded(&staged.join("LOCK"));

    // The former source name is no longer authority for the captured object.
    create_private_directory(&source).unwrap();
    std::fs::write(source.join("sentinel"), b"new source must survive").unwrap();
    directory.remove_file("payload").unwrap();
    directory.remove_file("LOCK").unwrap();
    drop(directory);
    captured.remove_empty().unwrap();
    drop(guard);
    assert!(!staged.exists());
    assert_eq!(
        std::fs::read(source.join("sentinel")).unwrap(),
        b"new source must survive"
    );
}

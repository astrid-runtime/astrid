use std::fs::{self, File};
use std::io;
use std::os::unix::fs::MetadataExt as _;

use super::{RetirementSync, retire_with_sync};

#[test]
fn directory_fences_share_one_terminal_device_barrier() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::create_dir_all(root.join("a/inner")).unwrap();
    fs::create_dir(root.join("b")).unwrap();
    fs::write(root.join("a/inner/state"), b"published").unwrap();
    fs::write(root.join("astrid.volume"), b"authority").unwrap();
    let inode = |path: &std::path::Path| fs::metadata(path).unwrap().ino();
    let expected = [
        (inode(&root.join("a/inner")), RetirementSync::Directory),
        (inode(&root.join("a")), RetirementSync::Directory),
        (inode(root), RetirementSync::Directory),
        (inode(&root.join("b")), RetirementSync::Directory),
        (inode(root), RetirementSync::Directory),
        (inode(root), RetirementSync::Device),
    ];
    let mut actual = Vec::new();
    retire_with_sync(
        root,
        || {},
        |file, kind| {
            actual.push((file.metadata()?.ino(), kind));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(fs::read_dir(root).unwrap().count(), 1);
    assert_eq!(fs::read(root.join("astrid.volume")).unwrap(), b"authority");
}

#[test]
fn intermediate_sync_error_still_runs_terminal_device_barrier() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::create_dir(root.join("child")).unwrap();
    fs::write(root.join("child/state"), b"published").unwrap();
    fs::write(root.join("astrid.volume"), b"authority").unwrap();
    let mut events = Vec::new();
    let error = retire_with_sync(
        root,
        || {},
        |_, kind| {
            events.push(kind);
            if kind == RetirementSync::Directory {
                Err(io::Error::other("injected intermediate sync error"))
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("intermediate sync"));
    assert_eq!(events, [RetirementSync::Directory, RetirementSync::Device]);
    assert!(!root.join("child/state").exists());
    assert!(root.join("child").is_dir());
    assert_eq!(fs::read(root.join("astrid.volume")).unwrap(), b"authority");
}

#[test]
fn root_directory_sync_error_still_runs_terminal_device_barrier() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::create_dir(root.join("child")).unwrap();
    fs::write(root.join("astrid.volume"), b"authority").unwrap();
    let root_inode = fs::metadata(root).unwrap().ino();
    let mut events = Vec::new();
    let error = retire_with_sync(
        root,
        || {},
        |file, kind| {
            events.push(kind);
            if kind == RetirementSync::Directory && file.metadata()?.ino() == root_inode {
                Err(io::Error::other("injected root directory sync error"))
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("root directory sync"));
    assert_eq!(events.last(), Some(&RetirementSync::Device));
    assert!(!root.join("child").exists());
    assert_eq!(fs::read(root.join("astrid.volume")).unwrap(), b"authority");
}

#[test]
fn terminal_device_barrier_error_is_not_success() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::write(root.join("state"), b"published").unwrap();
    fs::write(root.join("astrid.volume"), b"authority").unwrap();
    let error = retire_with_sync(
        root,
        || {},
        |_, kind| {
            assert_eq!(kind, RetirementSync::Device);
            Err(io::Error::other("injected terminal device barrier error"))
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("terminal device barrier"));
    assert!(!root.join("state").exists());
    assert_eq!(fs::read(root.join("astrid.volume")).unwrap(), b"authority");
}

#[test]
fn failed_preflight_does_not_sync_or_mutate_projection() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::write(root.join("a-state"), b"published").unwrap();
    std::os::unix::fs::symlink("a-state", root.join("z-redirect")).unwrap();
    let mut synced = false;
    assert!(
        retire_with_sync(
            root,
            || {},
            |_: &File, _| {
                synced = true;
                Ok(())
            }
        )
        .is_err()
    );
    assert!(!synced);
    assert_eq!(fs::read(root.join("a-state")).unwrap(), b"published");
}

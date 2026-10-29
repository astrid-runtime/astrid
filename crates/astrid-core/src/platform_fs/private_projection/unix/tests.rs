use std::cell::RefCell;
#[cfg(target_os = "linux")]
use std::ffi::OsString;
use std::fs;
use std::io;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use super::hooks::{self, Event};
use crate::platform_fs::PrivateFileProjection;

fn assert_no_temporary_files(root: &Path) {
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        assert!(
            !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".astrid-private-")
        );
    }
}

#[test]
fn batch_has_two_ancestry_walks_and_one_terminal_hardware_fence() {
    let root = tempfile::tempdir().unwrap();
    let events = Rc::new(RefCell::new(Vec::new()));
    let recorded = Rc::clone(&events);
    let _hook = hooks::install(move |event| {
        recorded.borrow_mut().push(event);
        Ok(())
    });
    crate::platform_fs::reset_directory_walk_count();
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    for index in 0..32 {
        let relative = PathBuf::from(format!("sibling-{index}"));
        assert_eq!(projection.snapshot(&relative).unwrap(), None);
        projection.write(&relative, b"authoritative bytes").unwrap();
    }
    projection.sync().unwrap();
    assert_eq!(crate::platform_fs::directory_walk_count(), 2);
    let events = events.borrow();
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == Event::FileSynced)
            .count(),
        32
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == Event::ParentSynced)
            .count(),
        32
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == Event::RootSynced)
            .count(),
        1
    );
    assert_eq!(events.len(), 97);
    for group in events[..96].chunks_exact(3) {
        assert_eq!(
            group,
            [Event::FileSynced, Event::BeforeRename, Event::ParentSynced]
        );
    }
    assert_eq!(events[96], Event::RootSynced);
}

#[test]
fn ordinary_mode_and_hardlinked_snapshot_preserves_external_alias() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    let destination = root.join("state");
    let alias = directory.path().join("external-alias");
    fs::write(&destination, b"previous bytes").unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o644)).unwrap();
    fs::hard_link(&destination, &alias).unwrap();
    let projection = PrivateFileProjection::open(&root).unwrap();
    assert_eq!(
        projection.snapshot(Path::new("state")).unwrap(),
        Some(b"previous bytes".to_vec())
    );
    projection.write(Path::new("state"), b"new bytes").unwrap();
    projection.sync().unwrap();
    assert_eq!(fs::read(alias).unwrap(), b"previous bytes");
    assert_eq!(fs::read(&destination).unwrap(), b"new bytes");
    let stat = fs::metadata(destination).unwrap();
    assert_eq!(stat.permissions().mode() & 0o777, 0o600);
    assert_eq!(stat.nlink(), 1);
}

#[test]
fn unreadable_existing_destination_can_be_atomically_replaced() {
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("state");
    fs::write(&destination, b"previous").unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o0)).unwrap();
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    projection
        .write(Path::new("state"), b"replacement")
        .unwrap();
    projection.sync().unwrap();
    assert_eq!(fs::read(destination).unwrap(), b"replacement");
}

#[test]
fn rejects_non_normal_names_before_mutation() {
    let root = tempfile::tempdir().unwrap();
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    for path in [
        "",
        ".",
        "..",
        "../escaped",
        "/absolute",
        "a/../b",
        "a/./b",
        "a//b",
        "a/",
    ] {
        assert!(
            projection.snapshot(Path::new(path)).is_err(),
            "snapshot accepted {path:?}"
        );
        assert!(
            projection.write(Path::new(path), b"bad").is_err(),
            "write accepted {path:?}"
        );
        assert!(
            projection.ensure_directory(Path::new(path)).is_err(),
            "directory accepted {path:?}"
        );
        assert!(
            projection.remove(Path::new(path)).is_err(),
            "remove accepted {path:?}"
        );
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn redirects_and_special_destinations_leave_external_bytes_intact() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    let outside = directory.path().join("outside");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("state"), b"outside").unwrap();
    symlink(&outside, root.join("redirect")).unwrap();
    symlink(outside.join("state"), root.join("file-redirect")).unwrap();
    nix::unistd::mkfifo(&root.join("fifo"), nix::sys::stat::Mode::S_IRUSR).unwrap();
    let projection = PrivateFileProjection::open(&root).unwrap();
    for path in ["redirect/state", "file-redirect", "fifo"] {
        assert!(projection.snapshot(Path::new(path)).is_err());
        assert!(projection.write(Path::new(path), b"bad").is_err());
        assert!(projection.remove(Path::new(path)).is_err());
    }
    assert_eq!(fs::read(outside.join("state")).unwrap(), b"outside");
}

#[test]
fn missing_or_redirected_root_cannot_target_an_ancestor() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("sentinel"), b"keep").unwrap();
    assert!(PrivateFileProjection::open(&directory.path().join("missing/nested")).is_err());
    let redirected = directory.path().join("redirect");
    symlink(directory.path(), &redirected).unwrap();
    assert!(PrivateFileProjection::open(&redirected).is_err());
    assert_eq!(
        fs::read(directory.path().join("sentinel")).unwrap(),
        b"keep"
    );
}

#[test]
fn file_fence_error_preserves_destination_and_cleans_temporary() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("state"), b"previous").unwrap();
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    let hook = hooks::install(|event| {
        if event == Event::FileSynced {
            Err(io::Error::other("injected after real file fsync"))
        } else {
            Ok(())
        }
    });
    let error = projection.write(Path::new("state"), b"new").unwrap_err();
    assert!(error.to_string().contains("after real file fsync"));
    drop(hook);
    assert_eq!(fs::read(root.path().join("state")).unwrap(), b"previous");
    assert_no_temporary_files(root.path());
    projection.sync().unwrap();
}

#[test]
fn parent_swap_before_rename_is_rejected_and_temp_cleanup_stays_anchored() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    let outside = directory.path().join("outside");
    fs::create_dir_all(root.join("nested")).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(root.join("nested/state"), b"previous").unwrap();
    fs::write(outside.join("state"), b"outside").unwrap();
    let projection = PrivateFileProjection::open(&root).unwrap();
    let changed_root = root.clone();
    let changed_outside = outside.clone();
    let hook = hooks::install(move |event| {
        if event == Event::BeforeRename {
            fs::rename(changed_root.join("nested"), changed_root.join("captured")).unwrap();
            symlink(&changed_outside, changed_root.join("nested")).unwrap();
        }
        Ok(())
    });
    assert!(projection.write(Path::new("nested/state"), b"new").is_err());
    drop(hook);
    assert_eq!(fs::read(root.join("captured/state")).unwrap(), b"previous");
    assert_eq!(fs::read(outside.join("state")).unwrap(), b"outside");
    assert_no_temporary_files(&root.join("captured"));
}

#[test]
fn terminal_error_propagates_after_actual_root_fence() {
    let root = tempfile::tempdir().unwrap();
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    projection.write(Path::new("state"), b"new").unwrap();
    let _hook = hooks::install(|event| {
        if event == Event::RootSynced {
            Err(io::Error::other("injected terminal fence error"))
        } else {
            Ok(())
        }
    });
    assert!(
        projection
            .sync()
            .unwrap_err()
            .to_string()
            .contains("terminal fence error")
    );
}

#[test]
fn terminal_validation_rejects_absolute_ancestor_redirect() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("parent");
    fs::create_dir_all(parent.join("root")).unwrap();
    let projection = PrivateFileProjection::open(&parent.join("root")).unwrap();
    fs::rename(&parent, directory.path().join("captured-parent")).unwrap();
    symlink(directory.path().join("captured-parent"), &parent).unwrap();
    assert!(projection.sync().is_err());
}

#[test]
fn rooted_rollback_restores_and_removes_files() {
    rollback_name(PathBuf::from("state-λ"));
}

// APFS rejects non-UTF-8 filenames at creation; Linux permits opaque bytes.
#[cfg(target_os = "linux")]
#[test]
fn rooted_rollback_preserves_non_utf8_names() {
    rollback_name(PathBuf::from(OsString::from_vec(vec![b's', 0xff])));
}

fn rollback_name(opaque: PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    projection
        .ensure_directory(Path::new("nested/deeper"))
        .unwrap();
    projection.write(&opaque, b"original").unwrap();
    let previous = projection.snapshot(&opaque).unwrap().unwrap();
    projection.write(&opaque, b"replacement").unwrap();
    projection.write(&opaque, &previous).unwrap();
    assert_eq!(fs::read(root.path().join(&opaque)).unwrap(), b"original");
    projection.remove(&opaque).unwrap();
    projection.remove(&opaque).unwrap();
    projection
        .remove(Path::new("missing/also-missing"))
        .unwrap();
    projection.sync().unwrap();
    assert!(!root.path().join(opaque).exists());
    assert_eq!(
        fs::metadata(root.path().join("nested/deeper"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn root_replacement_before_write_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    let projection = PrivateFileProjection::open(&root).unwrap();
    fs::rename(&root, directory.path().join("captured-root")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("sentinel"), b"replacement root").unwrap();
    assert!(projection.write(Path::new("state"), b"bad").is_err());
    assert!(projection.sync().is_err());
    assert!(!root.join("state").exists());
    assert!(!directory.path().join("captured-root/state").exists());
    assert_eq!(
        fs::read(root.join("sentinel")).unwrap(),
        b"replacement root"
    );
}

#[test]
fn parent_fence_error_can_be_rolled_back_through_same_root() {
    let root = tempfile::tempdir().unwrap();
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    projection.write(Path::new("state"), b"previous").unwrap();
    let previous = projection.snapshot(Path::new("state")).unwrap().unwrap();
    let hook = hooks::install(|event| {
        if event == Event::ParentSynced {
            Err(io::Error::other("injected after actual parent fsync"))
        } else {
            Ok(())
        }
    });
    assert!(
        projection
            .write(Path::new("state"), b"replacement")
            .is_err()
    );
    drop(hook);
    projection.write(Path::new("state"), &previous).unwrap();
    projection.sync().unwrap();
    assert_eq!(fs::read(root.path().join("state")).unwrap(), b"previous");
    assert_no_temporary_files(root.path());
}

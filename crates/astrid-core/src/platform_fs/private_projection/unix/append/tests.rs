//! Root, live parent and leaf substitution regressions for append authority.

use super::super::hooks::{self, Event};
use crate::platform_fs::{PrivateProjectionInspection, ensure_private_directory};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::Path;

fn capture(path: &Path) -> crate::platform_fs::PrivateAppendRoot {
    ensure_private_directory(path).unwrap();
    PrivateProjectionInspection::try_open(path)
        .unwrap()
        .capture_append_root()
        .unwrap()
}

#[test]
fn captured_root_and_ancestor_replacement_are_not_adopted() {
    for ancestor in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("parent");
        let home = parent.join("home");
        let append = capture(&home);
        let moved = if ancestor {
            parent.clone()
        } else {
            home.clone()
        };
        fs::rename(&moved, dir.path().join("parked")).unwrap();
        ensure_private_directory(&home).unwrap();
        assert!(append.open_private_append(Path::new("day.log")).is_err());
        assert!(!home.join("day.log").exists());
    }
}

#[test]
fn redirected_parent_or_leaf_does_not_receive_append_data() {
    for parent in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let append = capture(&home);
        let outside = dir.path().join("outside");
        ensure_private_directory(&outside).unwrap();
        fs::write(outside.join("day.log"), b"outside").unwrap();
        if parent {
            symlink(&outside, home.join("log")).unwrap();
        } else {
            ensure_private_directory(&home.join("log")).unwrap();
            symlink(outside.join("day.log"), home.join("log/day.log")).unwrap();
        }
        assert!(
            append
                .open_private_append(Path::new("log/day.log"))
                .is_err()
        );
        assert_eq!(fs::read(outside.join("day.log")).unwrap(), b"outside");
    }
}

#[test]
fn replacement_after_open_is_rejected_before_file_is_returned() {
    for parent in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let append = capture(&home);
        let parent_path = home.join("log");
        let leaf = parent_path.join("day.log");
        let moved = if parent {
            parent_path.clone()
        } else {
            leaf.clone()
        };
        let parked = home.join("parked");
        let replacement = moved.clone();
        let hook = hooks::install(move |event| {
            if event == Event::BeforeAppendReturn {
                fs::rename(&moved, &parked)?;
                if parent {
                    ensure_private_directory(&replacement)?;
                } else {
                    fs::write(&replacement, b"replacement")?;
                }
            }
            Ok(())
        });
        assert!(
            append
                .open_private_append(Path::new("log/day.log"))
                .is_err()
        );
        drop(hook);
        if !parent {
            assert_eq!(fs::read(leaf).unwrap(), b"replacement");
        }
    }
}

#[test]
fn existing_ordinary_mode_is_repaired_without_truncating_history() {
    let dir = tempfile::tempdir().unwrap();
    let append = capture(dir.path());
    let path = dir.path().join("day.log");
    fs::write(&path, b"history").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    append
        .open_private_append(Path::new("day.log"))
        .unwrap()
        .write_all(b" appended")
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"history appended");
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn failed_final_validation_does_not_return_an_append_stream() {
    let dir = tempfile::tempdir().unwrap();
    let append = capture(dir.path());
    let hook = hooks::install(|event| {
        if event == Event::BeforeAppendReturn {
            return Err(std::io::Error::other("injected append fence"));
        }
        Ok(())
    });
    let error = append
        .open_private_append(Path::new("log/day.log"))
        .unwrap_err();
    drop(hook);
    assert!(error.to_string().contains("injected append fence"));
    assert_eq!(
        fs::metadata(dir.path().join("log/day.log")).unwrap().len(),
        0
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires CAP_SYS_ADMIN in caller-owned mount namespace; native Linux CI"]
fn append_rejects_same_device_bind_mount_parent_and_leaf() {
    use crate::platform_fs::mount_fixtures::{BindMount, require_private_namespace};
    require_private_namespace();
    for parent in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let append = capture(dir.path());
        append
            .open_private_append(Path::new("log/day.log"))
            .unwrap()
            .write_all(b"original")
            .unwrap();
        let target = dir.path().join(if parent { "log" } else { "log/day.log" });
        let mut mount = BindMount::attach(&target).unwrap();
        assert!(
            append
                .open_private_append(Path::new("log/day.log"))
                .is_err()
        );
        mount.unmount().unwrap();
        assert_eq!(
            fs::read(dir.path().join("log/day.log")).unwrap(),
            b"original"
        );
    }
}

#[test]
fn append_parent_walk_adds_no_projection_fences_but_writer_still_does() {
    use super::super::anchor::take_directory_fences;
    use crate::platform_fs::PrivateFileProjection;
    let dir = tempfile::tempdir().unwrap();
    let append = capture(dir.path());
    take_directory_fences();
    append
        .open_private_append(Path::new("log/nested/day.log"))
        .unwrap();
    assert_eq!(
        take_directory_fences(),
        0,
        "native append has no directory birth fences"
    );
    fs::set_permissions(dir.path().join("log"), fs::Permissions::from_mode(0o755)).unwrap();
    append
        .open_private_append(Path::new("log/nested/day.log"))
        .unwrap();
    assert_eq!(
        take_directory_fences(),
        0,
        "native append privacy repair has no directory fences"
    );
    let writer = PrivateFileProjection::open(dir.path()).unwrap();
    writer
        .ensure_directory(Path::new("projection/nested"))
        .unwrap();
    assert_eq!(
        take_directory_fences(),
        4,
        "projection writer keeps child+parent birth fences"
    );
    fs::set_permissions(
        dir.path().join("projection"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    writer
        .ensure_directory(Path::new("projection/nested"))
        .unwrap();
    assert_eq!(
        take_directory_fences(),
        2,
        "projection writer keeps privacy repair fences"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires CAP_SYS_ADMIN in caller-owned mount namespace; native Linux CI"]
fn append_rejects_same_inode_leaf_bind_mount_installed_after_source_open() {
    use crate::platform_fs::mount_fixtures::{BindMount, require_private_namespace};
    use std::cell::RefCell;
    use std::os::unix::fs::MetadataExt as _;
    use std::rc::Rc;
    require_private_namespace();
    let dir = tempfile::tempdir().unwrap();
    let append = capture(dir.path());
    let relative = Path::new("log/day.log");
    append
        .open_private_append(relative)
        .unwrap()
        .write_all(b"history")
        .unwrap();
    let target = dir.path().join(relative);
    let metadata = fs::metadata(&target).unwrap();
    let original = (metadata.dev(), metadata.ino());
    let mounted = Rc::new(RefCell::new(None));
    let captured = Rc::clone(&mounted);
    let mount_target = target.clone();
    let hook = hooks::install(move |event| {
        if event == Event::BeforeAppendReturn {
            assert!(captured.borrow().is_none());
            *captured.borrow_mut() = Some(BindMount::attach(&mount_target)?);
            let current = fs::metadata(&mount_target)?;
            assert_eq!(
                (current.dev(), current.ino()),
                original,
                "test requires same-inode bind"
            );
        }
        Ok(())
    });
    let error = append.open_private_append(relative).unwrap_err();
    drop(hook);
    assert!(error.to_string().contains("mount boundary"), "{error}");
    mounted
        .borrow_mut()
        .as_mut()
        .expect("post-open bind hook reached")
        .unmount()
        .unwrap();
    assert_eq!(fs::read(target).unwrap(), b"history");
}

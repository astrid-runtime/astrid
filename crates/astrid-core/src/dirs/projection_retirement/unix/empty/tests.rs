//! Real traversal hooks exercise late failures, empty checks and exact fences.

use super::*;
use std::cell::RefCell;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

fn fixture() -> (tempfile::TempDir, File) {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("astrid.volume"), b"volume").unwrap();
    fs::write(dir.path().join("config"), b"retained").unwrap();
    for uid in ["a", "b"] {
        let child = dir.path().join(format!("log/principals/{uid}/capsule"));
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("day.log"), b"").unwrap();
    }
    let volume = File::open(dir.path().join("astrid.volume")).unwrap();
    (dir, volume)
}

fn targets() -> Vec<PathBuf> {
    vec!["log/principals/a".into(), "log/principals/b".into()]
}

#[test]
fn retained_parent_has_one_after_fence_and_no_removed_descendant_fences() {
    let (dir, volume) = fixture();
    let config = fs::metadata(dir.path().join("config")).unwrap();
    let events = RefCell::new(Vec::new());
    let authorized = std::cell::Cell::new(0);
    PreparedProjectionRetirement::prepare(dir.path())
        .unwrap()
        .retire_empty_with_hooks(
            &volume,
            &targets(),
            &mut |_, _| {
                authorized.set(authorized.get() + 1);
                Ok(())
            },
            &mut RetirementHooks {
                before_unlink: |path: &Path| {
                    assert_eq!(authorized.get(), 6);
                    events.borrow_mut().push(format!(
                        "unlink:{}",
                        path.strip_prefix(dir.path()).unwrap().display()
                    ));
                    Ok(())
                },
                sync_directory: |directory: &File, path: &Path| {
                    assert_eq!(authorized.get(), 6);
                    events.borrow_mut().push(format!(
                        "sync:{}",
                        path.strip_prefix(dir.path()).unwrap().display()
                    ));
                    directory.sync_all()
                },
            },
        )
        .unwrap();
    let events = events.into_inner();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.starts_with("sync:"))
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["sync:log/principals"]
    );
    assert_eq!(events.last().unwrap(), "sync:log/principals");
    let after = fs::metadata(dir.path().join("config")).unwrap();
    assert_eq!(
        (
            config.dev(),
            config.ino(),
            config.mode(),
            config.len(),
            config.mtime(),
            config.mtime_nsec()
        ),
        (
            after.dev(),
            after.ino(),
            after.mode(),
            after.len(),
            after.mtime(),
            after.mtime_nsec()
        )
    );
}

#[test]
fn same_inode_append_immediately_before_unlink_is_not_discarded() {
    let (dir, volume) = fixture();
    let path = dir.path().join("log/principals/a/capsule/day.log");
    let identity = fs::metadata(&path).unwrap().ino();
    let result = PreparedProjectionRetirement::prepare(dir.path())
        .unwrap()
        .retire_empty_with_hooks(
            &volume,
            &targets(),
            &mut |_, _| Ok(()),
            &mut RetirementHooks {
                before_unlink: |entry: &Path| {
                    if entry == path {
                        fs::OpenOptions::new()
                            .append(true)
                            .open(entry)?
                            .write_all(b"late line")?;
                    }
                    Ok(())
                },
                sync_directory: |directory: &File, _: &Path| directory.sync_all(),
            },
        );
    assert!(result.is_err());
    assert_eq!(fs::metadata(&path).unwrap().ino(), identity);
    assert_eq!(fs::read(path).unwrap(), b"late line");
    assert!(dir.path().join("log/principals/b/capsule/day.log").exists());
}

#[test]
fn failed_after_fence_is_retried_even_when_all_targets_are_absent() {
    let (dir, volume) = fixture();
    let result = PreparedProjectionRetirement::prepare(dir.path())
        .unwrap()
        .retire_empty_with_hooks(
            &volume,
            &targets(),
            &mut |_, _| Ok(()),
            &mut RetirementHooks {
                before_unlink: |_: &Path| Ok(()),
                sync_directory: |_: &File, _: &Path| Err(io::Error::other("after fence failure")),
            },
        );
    assert!(result.is_err());
    assert!(!dir.path().join("log/principals/a").exists());
    assert!(!dir.path().join("log/principals/b").exists());
    let mut fences = Vec::new();
    PreparedProjectionRetirement::prepare(dir.path())
        .unwrap()
        .retire_empty_with_hooks(
            &volume,
            &targets(),
            &mut |_, _| Ok(()),
            &mut RetirementHooks {
                before_unlink: |_: &Path| panic!("absent selected scopes must not unlink anything"),
                sync_directory: |directory: &File, path: &Path| {
                    fences.push(path.to_path_buf());
                    directory.sync_all()
                },
            },
        )
        .unwrap();
    assert_eq!(fences, [dir.path().join("log/principals")]);
}

#[test]
fn late_partial_failure_keeps_other_scope_and_allows_fresh_plan_retry() {
    let (dir, volume) = fixture();
    let blocked = dir.path().join("log/principals/b/capsule/day.log");
    let result = PreparedProjectionRetirement::prepare(dir.path())
        .unwrap()
        .retire_empty_with_hooks(
            &volume,
            &targets(),
            &mut |_, _| Ok(()),
            &mut RetirementHooks {
                before_unlink: |entry: &Path| {
                    if entry == blocked {
                        return Err(io::Error::other("late stop"));
                    }
                    Ok(())
                },
                sync_directory: |directory: &File, _: &Path| directory.sync_all(),
            },
        );
    assert!(result.is_err());
    assert!(!dir.path().join("log/principals/a").exists());
    assert!(blocked.exists());
    PreparedProjectionRetirement::prepare(dir.path())
        .unwrap()
        .retire_empty_subtrees(&volume, &targets(), |_, _| Ok(()))
        .unwrap();
    assert!(!dir.path().join("log/principals/b").exists());
    assert_eq!(fs::read(dir.path().join("config")).unwrap(), b"retained");
}

#[test]
fn renamed_directory_and_changed_absolute_home_fail_without_deletion() {
    for home in [false, true] {
        let (dir, volume) = fixture();
        let plan = PreparedProjectionRetirement::prepare(dir.path()).unwrap();
        if home {
            let original = dir.path().to_path_buf();
            let moved = original.with_extension("moved");
            fs::rename(&original, &moved).unwrap();
            fs::create_dir(&original).unwrap();
            let result = plan.retire_empty_subtrees(&volume, &targets(), |_, _| Ok(()));
            assert!(result.is_err());
            assert!(moved.join("log/principals/a/capsule/day.log").exists());
            fs::remove_dir(&original).unwrap();
            fs::rename(moved, original).unwrap();
        } else {
            let selected = dir.path().join("log/principals/a");
            fs::rename(&selected, dir.path().join("parked")).unwrap();
            fs::create_dir(&selected).unwrap();
            assert!(
                plan.retire_empty_subtrees(&volume, &targets(), |_, _| Ok(()))
                    .is_err()
            );
            assert!(dir.path().join("parked/capsule/day.log").exists());
            assert!(dir.path().join("log/principals/b/capsule/day.log").exists());
        }
    }
}

#[test]
fn ordinary_modes_and_unreadable_empty_leaves_remain_metadata_only() {
    for mode in [0o644, 0o000] {
        let (dir, volume) = fixture();
        let leaf = dir.path().join("log/principals/a/capsule/day.log");
        fs::set_permissions(&leaf, fs::Permissions::from_mode(mode)).unwrap();
        fs::set_permissions(
            dir.path().join("log/principals/a"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        PreparedProjectionRetirement::prepare(dir.path())
            .unwrap()
            .retire_empty_subtrees(&volume, &targets(), |_, _| Ok(()))
            .unwrap();
        assert!(!dir.path().join("log/principals/a").exists());
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires CAP_SYS_ADMIN in caller-owned private mount namespace; native Linux CI"]
fn same_inode_bind_mount_at_preunlink_is_rejected() {
    use crate::platform_fs::mount_fixtures::{BindMount, require_private_namespace};
    use std::rc::Rc;
    require_private_namespace();
    let (dir, volume) = fixture();
    let target = dir.path().join("log/principals/a/capsule/day.log");
    let before = fs::metadata(&target).unwrap();
    let original = (before.dev(), before.ino());
    let mount = Rc::new(RefCell::new(None));
    let captured = Rc::clone(&mount);
    let result = PreparedProjectionRetirement::prepare(dir.path())
        .unwrap()
        .retire_empty_with_hooks(
            &volume,
            &targets(),
            &mut |_, _| Ok(()),
            &mut RetirementHooks {
                before_unlink: |path: &Path| {
                    if path == target {
                        *captured.borrow_mut() = Some(BindMount::attach(path)?);
                        let now = fs::metadata(path)?;
                        assert_eq!((now.dev(), now.ino()), original);
                    }
                    Ok(())
                },
                sync_directory: |directory: &File, _: &Path| directory.sync_all(),
            },
        );
    assert!(result.is_err());
    mount
        .borrow_mut()
        .as_mut()
        .expect("owned mount hook reached")
        .unmount()
        .unwrap();
    assert!(target.exists());
}

#[test]
fn replacement_leaf_in_preunlink_hook_is_not_adopted() {
    let (dir, volume) = fixture();
    let target = dir.path().join("log/principals/a/capsule/day.log");
    let parked = dir.path().join("parked");
    let result = PreparedProjectionRetirement::prepare(dir.path())
        .unwrap()
        .retire_empty_with_hooks(
            &volume,
            &targets(),
            &mut |_, _| Ok(()),
            &mut RetirementHooks {
                before_unlink: |path: &Path| {
                    if path == target {
                        fs::rename(path, &parked)?;
                        fs::write(path, b"replacement")?;
                    }
                    Ok(())
                },
                sync_directory: |directory: &File, _: &Path| directory.sync_all(),
            },
        );
    assert!(result.is_err());
    assert_eq!(fs::read(target).unwrap(), b"replacement");
    assert!(parked.exists());
    assert!(dir.path().join("log/principals/b/capsule/day.log").exists());
}

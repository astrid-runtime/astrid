//! NTFS retained-parent fence and live empty admission regressions.

use super::*;
use std::cell::RefCell;
use std::fs;
use std::io::Write as _;

fn fixture() -> (tempfile::TempDir, PathBuf, File) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir(&home).unwrap();
    fs::write(home.join("astrid.volume"), b"volume").unwrap();
    fs::write(home.join("config"), b"retained").unwrap();
    for uid in ["a", "b"] {
        let child = home.join(format!("log/principals/{uid}/capsule"));
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("day.log"), b"").unwrap();
    }
    let volume = File::open(home.join("astrid.volume")).unwrap();
    (dir, home, volume)
}
fn targets() -> Vec<PathBuf> {
    vec!["log/principals/a".into(), "log/principals/b".into()]
}

#[test]
fn retained_parent_has_exactly_one_paired_before_and_after_fence() {
    let (_dir, home, volume) = fixture();
    let events = RefCell::new(Vec::new());
    let authorized = std::cell::Cell::new(0);
    PreparedProjectionRetirement::prepare(&home)
        .unwrap()
        .retire_empty_with_hooks(
            &volume,
            &targets(),
            &mut |_, _| {
                authorized.set(authorized.get() + 1);
                Ok(())
            },
            &mut |path| {
                assert_eq!(authorized.get(), 6);
                events.borrow_mut().push(format!(
                    "unlink:{}",
                    path.strip_prefix(&home).unwrap().display()
                ));
                Ok(())
            },
            &mut |path| {
                assert_eq!(authorized.get(), 6);
                events.borrow_mut().push(format!(
                    "sync:{}",
                    path.strip_prefix(&home).unwrap().display()
                ));
                Ok(())
            },
        )
        .unwrap();
    let events = events.into_inner();
    let syncs = events
        .iter()
        .filter(|event| event.starts_with("sync:"))
        .collect::<Vec<_>>();
    let expected = format!("sync:{}", Path::new("log").join("principals").display());
    assert_eq!(syncs, [&expected, &expected]);
    assert_eq!(events.first().unwrap(), &expected);
    assert_eq!(events.last().unwrap(), &expected);
    assert_eq!(fs::read(home.join("config")).unwrap(), b"retained");
}

#[test]
fn same_identity_append_at_preunlink_preserves_new_history() {
    let (_dir, home, volume) = fixture();
    let target = home.join("log/principals/a/capsule/day.log");
    let result = PreparedProjectionRetirement::prepare(&home)
        .unwrap()
        .retire_empty_with_hooks(
            &volume,
            &targets(),
            &mut |_, _| Ok(()),
            &mut |path| {
                if path == target {
                    fs::OpenOptions::new()
                        .append(true)
                        .open(path)?
                        .write_all(b"late history")?;
                }
                Ok(())
            },
            &mut |_| Ok(()),
        );
    assert!(result.is_err());
    assert_eq!(fs::read(target).unwrap(), b"late history");
    assert!(home.join("log/principals/b/capsule/day.log").exists());
}

#[test]
fn failed_after_fence_is_retried_for_absent_targets() {
    let (_dir, home, volume) = fixture();
    let mut calls = 0;
    let result = PreparedProjectionRetirement::prepare(&home)
        .unwrap()
        .retire_empty_with_hooks(
            &volume,
            &targets(),
            &mut |_, _| Ok(()),
            &mut |_| Ok(()),
            &mut |_| {
                calls += 1;
                if calls == 2 {
                    return Err(io::Error::other("after fence failure"));
                }
                Ok(())
            },
        );
    assert!(result.is_err());
    assert!(!home.join("log/principals/a").exists());
    assert!(!home.join("log/principals/b").exists());
    let mut fences = Vec::new();
    PreparedProjectionRetirement::prepare(&home)
        .unwrap()
        .retire_empty_with_hooks(
            &volume,
            &targets(),
            &mut |_, _| Ok(()),
            &mut |_| panic!("absent targets must not unlink"),
            &mut |path| {
                fences.push(path.to_path_buf());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(
        fences,
        [home.join("log/principals"), home.join("log/principals")]
    );
}

#[test]
fn partial_failure_allows_fresh_plan_retry() {
    let (_dir, home, volume) = fixture();
    let blocked = home.join("log/principals/b/capsule/day.log");
    assert!(
        PreparedProjectionRetirement::prepare(&home)
            .unwrap()
            .retire_empty_with_hooks(
                &volume,
                &targets(),
                &mut |_, _| Ok(()),
                &mut |path| {
                    if path == blocked {
                        return Err(io::Error::other("stop"));
                    }
                    Ok(())
                },
                &mut |_| Ok(())
            )
            .is_err()
    );
    assert!(!home.join("log/principals/a").exists());
    assert!(blocked.exists());
    PreparedProjectionRetirement::prepare(&home)
        .unwrap()
        .retire_empty_subtrees(&volume, &targets(), |_, _| Ok(()))
        .unwrap();
    assert!(!home.join("log/principals/b").exists());
}

#[test]
fn retained_leaf_file_id_and_bytes_are_unchanged() {
    let (_dir, home, volume) = fixture();
    let config = File::open(home.join("config")).unwrap();
    let identity = file_id_identity(&config).unwrap();
    PreparedProjectionRetirement::prepare(&home)
        .unwrap()
        .retire_empty_subtrees(&volume, &targets(), |_, _| Ok(()))
        .unwrap();
    assert_eq!(file_id_identity(&config).unwrap(), identity);
    assert_eq!(fs::read(home.join("config")).unwrap(), b"retained");
}

#[test]
fn replacement_leaf_at_preunlink_is_not_adopted() {
    let (_dir, home, volume) = fixture();
    let target = home.join("log/principals/a/capsule/day.log");
    let parked = home.join("parked");
    let result = PreparedProjectionRetirement::prepare(&home)
        .unwrap()
        .retire_empty_with_hooks(
            &volume,
            &targets(),
            &mut |_, _| Ok(()),
            &mut |path| {
                if path == target {
                    fs::rename(path, &parked)?;
                    fs::write(path, b"replacement")?;
                }
                Ok(())
            },
            &mut |_| Ok(()),
        );
    assert!(result.is_err());
    if parked.exists() {
        assert_eq!(fs::read(target).unwrap(), b"replacement");
        assert!(parked.exists());
    } else {
        assert!(target.exists(), "OS rejection must leave the captured leaf");
    }
    assert!(home.join("log/principals/b/capsule/day.log").exists());
}

#[test]
fn wrong_absolute_home_is_rejected_or_os_denies_rename() {
    let (dir, home, volume) = fixture();
    let plan = PreparedProjectionRetirement::prepare(&home).unwrap();
    let parked = dir.path().join("parked");
    if fs::rename(&home, &parked).is_ok() {
        fs::create_dir(&home).unwrap();
        fs::write(home.join("astrid.volume"), b"replacement volume").unwrap();
        assert!(
            plan.retire_empty_subtrees(&volume, &targets(), |_, _| Ok(()))
                .is_err()
        );
        assert!(parked.join("log/principals/a/capsule/day.log").exists());
    } else {
        plan.retire_empty_subtrees(&volume, &targets(), |_, _| Ok(()))
            .unwrap();
        assert!(!home.join("log/principals/a").exists());
    }
}

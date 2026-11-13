//! Exercise captured retirement authority through the common serial path.

use super::*;

fn two_leaves(root: &Path) {
    for name in ["a", "b"] {
        std::fs::write(root.join(name), b"captured").unwrap();
    }
}

#[test]
fn prepared_retirement_removes_nested_inventories_and_retains_canonical_volume() {
    for spine in ["log/principals", "etc/profiles"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        for child in ["a", "b"] {
            let directory = root.join(spine).join(child);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("leaf"), b"captured").unwrap();
        }
        std::fs::write(root.join(CANONICAL_VOLUME), b"authority").unwrap();
        let volume = File::open(root.join(CANONICAL_VOLUME)).unwrap();
        PreparedProjectionRetirement::prepare(root)
            .unwrap()
            .retire(&volume)
            .unwrap();
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 1);
        assert_eq!(
            std::fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
            b"authority"
        );
    }
}

#[test]
fn deletion_error_preserves_unremoved_entries_and_allows_fresh_plan_retry() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    two_leaves(root);
    let plan = PreparedProjectionRetirement::prepare(root).unwrap();
    let mut visited = Vec::new();
    let result = plan.retire_with_hooks(
        None,
        &mut RetirementHooks {
            before_unlink: |path: &Path| {
                visited.push(path.file_name().unwrap().to_owned());
                if path.file_name() == Some(OsStr::new("b")) {
                    return Err(io::Error::other("injected deletion error"));
                }
                Ok(())
            },
            sync_directory: |directory: &File, _: &Path| directory.sync_all(),
        },
    );
    assert!(result.is_err());
    assert_eq!(visited, [OsString::from("a"), OsString::from("b")]);
    assert!(!root.join("a").exists());
    assert_eq!(std::fs::read(root.join("b")).unwrap(), b"captured");
    super::retire(root).unwrap();
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
}

#[test]
fn prepared_retirement_rejects_replacements_and_never_authorizes_late_children() {
    for mutation in ["replacement", "late"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        two_leaves(&root);
        let plan = PreparedProjectionRetirement::prepare(&root).unwrap();
        let foreign = root.join("foreign");
        let saved = temp.path().join("saved");
        let result = plan.retire_with_hooks(
            None,
            &mut RetirementHooks {
                before_unlink: |path: &Path| {
                    if path.file_name() == Some(OsStr::new("a")) {
                        if mutation == "replacement" {
                            std::fs::rename(path, &saved)?;
                            std::fs::write(path, b"foreign replacement")?;
                        } else {
                            std::fs::write(&foreign, b"unreceipted")?;
                        }
                    }
                    Ok(())
                },
                sync_directory: |directory: &File, _: &Path| directory.sync_all(),
            },
        );
        assert!(result.is_err());
        if mutation == "replacement" {
            assert_eq!(
                std::fs::read(root.join("a")).unwrap(),
                b"foreign replacement"
            );
            assert_eq!(std::fs::read(saved).unwrap(), b"captured");
        } else {
            assert_eq!(std::fs::read(foreign).unwrap(), b"unreceipted");
            assert!(std::fs::remove_dir(&root).is_err());
        }
    }
}

#[test]
fn descendants_preserve_root_barriers_and_canonical_volume() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    for name in ["a", "b"] {
        std::fs::create_dir(root.join(name)).unwrap();
        two_leaves(&root.join(name));
    }
    std::fs::write(root.join(CANONICAL_VOLUME), b"authority").unwrap();
    let volume = File::open(root.join(CANONICAL_VOLUME)).unwrap();
    let expected = fstat(&volume).unwrap();
    let plan = PreparedProjectionRetirement::prepare(root).unwrap();
    let mut removed = Vec::new();
    let mut barriers = 0;
    plan.retire_with_hooks(
        Some(&expected),
        &mut RetirementHooks {
            before_unlink: |path: &Path| {
                if path.is_dir() {
                    assert_eq!(std::fs::read_dir(path)?.count(), 0);
                }
                removed.push(path.strip_prefix(root).unwrap().to_owned());
                Ok(())
            },
            sync_directory: |directory: &File, path: &Path| {
                assert_eq!(path, root);
                barriers += 1;
                if barriers <= 2 {
                    assert!(!root.join(if barriers == 1 { "a" } else { "b" }).exists());
                }
                directory.sync_all()
            },
        },
    )
    .unwrap();
    assert_eq!(
        removed,
        ["a/a", "a/b", "a", "b/a", "b/b", "b"].map(PathBuf::from)
    );
    assert_eq!(barriers, 3);
    assert_eq!(
        std::fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"authority"
    );
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 1);
}

#[test]
fn prepared_retirement_rejects_final_root_volume_and_namespace_changes() {
    for mutation in ["root", "volume", "late"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("log/principals")).unwrap();
        two_leaves(&root.join("log/principals"));
        std::fs::write(root.join(CANONICAL_VOLUME), b"authority").unwrap();
        let volume = File::open(root.join(CANONICAL_VOLUME)).unwrap();
        let expected = fstat(&volume).unwrap();
        let plan = PreparedProjectionRetirement::prepare(&root).unwrap();
        let mut barriers = 0;
        let result = plan.retire_with_hooks(
            Some(&expected),
            &mut RetirementHooks {
                before_unlink: |_: &Path| Ok(()),
                sync_directory: |directory: &File, _: &Path| {
                    directory.sync_all()?;
                    barriers += 1;
                    if barriers != 2 {
                        return Ok(());
                    }
                    match mutation {
                        "root" => {
                            std::fs::rename(&root, temp.path().join("saved-root"))?;
                            std::fs::create_dir(&root)?;
                            std::fs::write(root.join("foreign"), b"foreign")
                        },
                        "volume" => {
                            std::fs::rename(
                                root.join(CANONICAL_VOLUME),
                                temp.path().join("saved-volume"),
                            )?;
                            std::fs::write(root.join(CANONICAL_VOLUME), b"foreign")
                        },
                        _ => std::fs::write(root.join("foreign"), b"foreign"),
                    }
                },
            },
        );
        assert!(result.is_err(), "accepted final {mutation} mutation");
        assert_eq!(barriers, 2);
        let foreign = root.join(if mutation == "volume" {
            CANONICAL_VOLUME
        } else {
            "foreign"
        });
        assert_eq!(std::fs::read(foreign).unwrap(), b"foreign");
    }
}

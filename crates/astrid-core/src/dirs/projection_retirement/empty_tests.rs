//! Public selected-subtree contract independent of storage selection policy.

use super::PreparedProjectionRetirement;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

fn fixture() -> (tempfile::TempDir, File) {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("astrid.volume"), b"volume").unwrap();
    let volume = File::open(dir.path().join("astrid.volume")).unwrap();
    (dir, volume)
}

fn zero(root: &Path, relative: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, b"").unwrap();
}

#[test]
fn selected_empty_trees_retire_without_mutating_retained_history_or_markers() {
    let (dir, volume) = fixture();
    for name in ["log/principals/a/c/day.log", "log/principals/b/c/day.log"] {
        zero(dir.path(), name);
    }
    fs::create_dir_all(dir.path().join("etc")).unwrap();
    fs::write(dir.path().join("etc/profile"), b"configuration").unwrap();
    fs::create_dir_all(dir.path().join("keys")).unwrap();
    fs::write(dir.path().join("keys/principal"), b"key").unwrap();
    fs::create_dir_all(dir.path().join("log/principals/marker/explicit-empty")).unwrap();
    fs::create_dir_all(dir.path().join("log/principals/history/c")).unwrap();
    fs::write(
        dir.path().join("log/principals/history/c/day.log"),
        b"history",
    )
    .unwrap();
    let selected = [
        PathBuf::from("log/principals/a"),
        PathBuf::from("log/principals/b"),
    ];
    for _ in 0..2 {
        PreparedProjectionRetirement::prepare(dir.path())
            .unwrap()
            .retire_empty_subtrees(&volume, &selected, |_, _| Ok(()))
            .unwrap();
        assert!(!dir.path().join("log/principals/a").exists());
        assert!(!dir.path().join("log/principals/b").exists());
        assert_eq!(
            fs::read(dir.path().join("etc/profile")).unwrap(),
            b"configuration"
        );
        assert_eq!(fs::read(dir.path().join("keys/principal")).unwrap(), b"key");
        assert_eq!(
            fs::read(dir.path().join("log/principals/history/c/day.log")).unwrap(),
            b"history"
        );
        assert!(
            dir.path()
                .join("log/principals/marker/explicit-empty")
                .is_dir()
        );
        assert_eq!(
            fs::read(dir.path().join("astrid.volume")).unwrap(),
            b"volume"
        );
    }
}

#[test]
fn later_selected_nonempty_tree_stops_all_early_deletes() {
    let (dir, volume) = fixture();
    zero(dir.path(), "a/c/day.log");
    zero(dir.path(), "z/c/day.log");
    let plan = PreparedProjectionRetirement::prepare(dir.path()).unwrap();
    fs::write(dir.path().join("z/c/day.log"), b"new history").unwrap();
    assert!(
        plan.retire_empty_subtrees(&volume, &["a".into(), "z".into()], |_, _| Ok(()))
            .is_err()
    );
    assert!(dir.path().join("a/c/day.log").exists());
    assert_eq!(
        fs::read(dir.path().join("z/c/day.log")).unwrap(),
        b"new history"
    );
}

#[test]
fn raw_invalid_overlapping_and_obstructed_targets_do_not_authorize_deletion() {
    let invalid = [
        vec![""],
        vec!["."],
        vec!["../x"],
        vec!["/x"],
        vec!["a/../b"],
        vec!["a//b"],
        vec!["a/./b"],
        vec!["a/"],
        vec!["astrid.volume"],
        vec!["astrid.volume/child"],
        vec!["a", "a/b"],
        vec!["a/b", "a"],
        vec!["a", "a"],
    ];
    for names in invalid {
        let (dir, volume) = fixture();
        zero(dir.path(), "a/b/day.log");
        let targets = names
            .iter()
            .map(|name| PathBuf::from(*name))
            .collect::<Vec<_>>();
        let error = PreparedProjectionRetirement::prepare(dir.path())
            .unwrap()
            .retire_empty_subtrees(&volume, &targets, |_, _| Ok(()))
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{names:?}");
        assert!(dir.path().join("a/b/day.log").exists());
    }
    let (dir, volume) = fixture();
    fs::write(dir.path().join("file"), b"").unwrap();
    for target in ["file", "file/child"] {
        assert!(
            PreparedProjectionRetirement::prepare(dir.path())
                .unwrap()
                .retire_empty_subtrees(&volume, &[target.into()], |_, _| Ok(()))
                .is_err()
        );
        assert!(dir.path().join("file").is_file());
    }
}

#[test]
fn wrong_engine_volume_and_late_new_name_fail_before_selected_deletion() {
    let (dir, volume) = fixture();
    zero(dir.path(), "log/uid/day.log");
    let other = tempfile::NamedTempFile::new().unwrap();
    assert!(
        PreparedProjectionRetirement::prepare(dir.path())
            .unwrap()
            .retire_empty_subtrees(other.as_file(), &["log/uid".into()], |_, _| Ok(()))
            .is_err()
    );
    let plan = PreparedProjectionRetirement::prepare(dir.path()).unwrap();
    zero(dir.path(), "log/uid/new.log");
    assert!(
        plan.retire_empty_subtrees(&volume, &["log/uid".into()], |_, _| Ok(()))
            .is_err()
    );
    assert!(dir.path().join("log/uid/day.log").exists());
    assert!(dir.path().join("log/uid/new.log").exists());
}

#[test]
fn authorization_visits_selected_roots_directories_and_files_once_before_deletion() {
    use super::RetirementEntryKind::{Directory, File as RegularFile};
    let (dir, volume) = fixture();
    for name in ["log/principals/a/c/day.log", "log/principals/b/c/day.log"] {
        zero(dir.path(), name);
    }
    fs::create_dir_all(dir.path().join("retained-marker")).unwrap();
    let mut visits = Vec::new();
    PreparedProjectionRetirement::prepare(dir.path())
        .unwrap()
        .retire_empty_subtrees(
            &volume,
            &["log/principals/a".into(), "log/principals/b".into()],
            |relative, kind| {
                assert!(!relative.is_absolute());
                assert!(
                    dir.path().join("log/principals/a/c/day.log").exists(),
                    "all callbacks must precede every selected unlink"
                );
                assert!(dir.path().join("log/principals/b/c/day.log").exists());
                visits.push((relative.to_path_buf(), kind));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(
        visits,
        vec![
            (PathBuf::from("log/principals/a"), Directory),
            (PathBuf::from("log/principals/a/c"), Directory),
            (PathBuf::from("log/principals/a/c/day.log"), RegularFile),
            (PathBuf::from("log/principals/b"), Directory),
            (PathBuf::from("log/principals/b/c"), Directory),
            (PathBuf::from("log/principals/b/c/day.log"), RegularFile),
        ]
    );
    assert!(dir.path().join("retained-marker").is_dir());
}

#[test]
fn unknown_captured_empty_directory_blocks_all_earlier_selected_deletion() {
    use super::RetirementEntryKind::Directory;
    let (dir, volume) = fixture();
    zero(dir.path(), "a/c/day.log");
    zero(dir.path(), "z/c/day.log");
    fs::create_dir(dir.path().join("z/unrecognized-empty")).unwrap();
    let allowed = [
        Path::new("a"),
        Path::new("a/c"),
        Path::new("z"),
        Path::new("z/c"),
    ];
    let error = PreparedProjectionRetirement::prepare(dir.path())
        .unwrap()
        .retire_empty_subtrees(&volume, &["a".into(), "z".into()], |relative, kind| {
            if kind == Directory && !allowed.contains(&relative) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "unknown captured directory",
                ));
            }
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "unknown captured directory");
    assert!(dir.path().join("a/c/day.log").exists());
    assert!(dir.path().join("z/c/day.log").exists());
    assert!(dir.path().join("z/unrecognized-empty").is_dir());
}

#[test]
fn even_a_selected_root_without_files_requires_directory_authorization() {
    let (dir, volume) = fixture();
    fs::create_dir(dir.path().join("unrecognized-root")).unwrap();
    let mut visited = false;
    let error = PreparedProjectionRetirement::prepare(dir.path())
        .unwrap()
        .retire_empty_subtrees(&volume, &["unrecognized-root".into()], |relative, kind| {
            assert_eq!(relative, Path::new("unrecognized-root"));
            assert_eq!(kind, super::RetirementEntryKind::Directory);
            visited = true;
            Err(std::io::Error::other("directory root denied"))
        })
        .unwrap_err();
    assert!(visited);
    assert_eq!(error.to_string(), "directory root denied");
    assert!(dir.path().join("unrecognized-root").is_dir());
}

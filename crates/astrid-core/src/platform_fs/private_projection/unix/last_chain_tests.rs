//! Last-chain reuse is bounded and never substitutes for live binding checks.

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::Path;
use std::time::Instant;

use super::anchor::{DirectoryChain, WalkPolicy};
use super::{Projection, RelativePath};

#[test]
fn last_chain_sibling_writes_reuse_only_the_complete_parent_prefix() {
    let root = tempfile::tempdir().unwrap();
    let projection = Projection::open(root.path()).unwrap();
    super::anchor::take_new_bindings();
    for index in 0..32 {
        let path = RelativePath::parse(Path::new(&format!("nested/children/{index}"))).unwrap();
        projection.write(&path, b"value").unwrap();
        assert_eq!(projection.last_directories.retained_depth(), 2);
    }
    assert_eq!(super::anchor::take_new_bindings(), 2);
    projection.sync().unwrap();
}

#[test]
fn last_chain_different_leaves_retain_and_revalidate_only_the_shared_prefix() {
    let root = tempfile::tempdir().unwrap();
    let projection = Projection::open(root.path()).unwrap();
    super::anchor::take_new_bindings();
    for index in 0..32 {
        let path =
            RelativePath::parse(Path::new(&format!("log/principals/{index}/entry"))).unwrap();
        projection.write(&path, b"entry").unwrap();
        assert_eq!(projection.last_directories.retained_depth(), 3);
    }
    assert_eq!(super::anchor::take_new_bindings(), 34);
    projection.sync().unwrap();
}

#[test]
fn last_chain_partial_prefix_is_checked_before_creating_a_new_suffix() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    let outside = directory.path().join("outside");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&outside).unwrap();
    let projection = Projection::open(&root).unwrap();
    projection
        .write(
            &RelativePath::parse(Path::new("nested/first/file")).unwrap(),
            b"first",
        )
        .unwrap();
    fs::rename(root.join("nested"), root.join("saved")).unwrap();
    symlink(&outside, root.join("nested")).unwrap();
    assert!(
        projection
            .write(
                &RelativePath::parse(Path::new("nested/second/file")).unwrap(),
                b"ours"
            )
            .is_err()
    );
    assert!(!outside.join("second").exists());
    assert!(!root.join("saved/second").exists());
}

#[test]
fn last_chain_next_sibling_rejects_a_symlink_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    let outside = directory.path().join("outside");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("next"), b"outside").unwrap();
    let projection = Projection::open(&root).unwrap();
    projection
        .write(
            &RelativePath::parse(Path::new("nested/first")).unwrap(),
            b"first",
        )
        .unwrap();
    fs::rename(root.join("nested"), root.join("saved")).unwrap();
    symlink(&outside, root.join("nested")).unwrap();
    assert!(
        projection
            .write(
                &RelativePath::parse(Path::new("nested/next")).unwrap(),
                b"ours"
            )
            .is_err()
    );
    assert_eq!(fs::read(outside.join("next")).unwrap(), b"outside");
    assert!(!root.join("saved/next").exists());
}

#[test]
fn last_chain_private_parent_replacement_uses_the_new_bound_directory() {
    let root = tempfile::tempdir().unwrap();
    let projection = Projection::open(root.path()).unwrap();
    projection
        .write(
            &RelativePath::parse(Path::new("nested/first")).unwrap(),
            b"first",
        )
        .unwrap();
    fs::rename(root.path().join("nested"), root.path().join("saved")).unwrap();
    fs::create_dir(root.path().join("nested")).unwrap();
    fs::set_permissions(
        root.path().join("nested"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    projection
        .write(
            &RelativePath::parse(Path::new("nested/next")).unwrap(),
            b"next",
        )
        .unwrap();
    projection.sync().unwrap();
    assert_eq!(fs::read(root.path().join("nested/next")).unwrap(), b"next");
    assert!(!root.path().join("saved/next").exists());
}

#[test]
fn last_chain_outstanding_replacements_keep_their_own_authority() {
    let root = tempfile::tempdir().unwrap();
    let projection = Projection::open(root.path()).unwrap();
    let first_path = RelativePath::parse(Path::new("first/one")).unwrap();
    let second_path = RelativePath::parse(Path::new("second/two")).unwrap();
    let (first, _) = projection
        .capture_replacement(&first_path, &mut Vec::new())
        .unwrap();
    let (second, _) = projection
        .capture_replacement(&second_path, &mut Vec::new())
        .unwrap();
    assert_eq!(projection.last_directories.retained_depth(), 0);
    first.write_from(&mut &b"one"[..], 3).1.unwrap();
    assert_eq!(projection.last_directories.retained_depth(), 1);
    second.write_from(&mut &b"two"[..], 3).1.unwrap();
    assert_eq!(projection.last_directories.retained_depth(), 1);
    projection.sync().unwrap();
    assert_eq!(fs::read(root.path().join("first/one")).unwrap(), b"one");
    assert_eq!(fs::read(root.path().join("second/two")).unwrap(), b"two");
}

#[test]
fn last_chain_reuse_preserves_inspection_and_repair_policies() {
    let root = tempfile::tempdir().unwrap();
    let projection = Projection::open(root.path()).unwrap();
    projection
        .ensure_directory(&RelativePath::parse(Path::new("nested")).unwrap())
        .unwrap();
    let nested = root.path().join("nested");
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o755)).unwrap();
    let names = vec!["nested".into()];
    assert!(projection.directories(&names, WalkPolicy::Inspect).is_err());
    assert_eq!(
        fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert!(
        projection
            .directories(&names, WalkPolicy::Repair)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
        0o700
    );
    super::anchor::take_new_bindings();
    for _ in 0..2 {
        assert!(
            DirectoryChain::walk(
                &projection.root,
                &projection.boundary,
                &names,
                WalkPolicy::Inspect
            )
            .unwrap()
            .is_some()
        );
    }
    assert_eq!(
        super::anchor::take_new_bindings(),
        2,
        "inspection has no last-chain cache"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires CAP_SYS_ADMIN in a caller-owned private mount namespace; run by native Linux CI"]
fn bind_mount_last_chain_prefix_is_rechecked_before_creating_a_suffix() {
    use crate::platform_fs::mount_fixtures::{BindMount, require_private_namespace};

    require_private_namespace();
    let root = tempfile::tempdir().unwrap();
    let projection = Projection::open(root.path()).unwrap();
    projection
        .write(
            &RelativePath::parse(Path::new("mounted/first/file")).unwrap(),
            b"first",
        )
        .unwrap();
    projection.sync().unwrap();
    let mut mounted = BindMount::attach(&root.path().join("mounted")).unwrap();
    let error = projection
        .write(
            &RelativePath::parse(Path::new("mounted/second/file")).unwrap(),
            b"ours",
        )
        .unwrap_err();
    assert!(error.to_string().contains("mount boundary"), "{error}");
    mounted.unmount().unwrap();
    assert!(!root.path().join("mounted/second").exists());
    assert_eq!(
        fs::read(root.path().join("mounted/first/file")).unwrap(),
        b"first"
    );
}

#[test]
#[ignore = "operator matched filesystem microbenchmark, not a CI timing gate"]
fn last_chain_matched_microbenchmark() {
    for unique in [false, true] {
        for (sample, reuse) in [false, true, true, false].into_iter().enumerate() {
            let root = tempfile::tempdir().unwrap();
            let projection = Projection::open(root.path()).unwrap();
            super::anchor::take_new_bindings();
            let start = Instant::now();
            for index in 0..256 {
                if !reuse {
                    projection.last_directories.clear();
                }
                let parent = if unique {
                    format!("unique/{index}")
                } else {
                    "siblings/shared".to_owned()
                };
                let path =
                    RelativePath::parse(Path::new(&format!("{parent}/file-{index}"))).unwrap();
                projection.write(&path, b"benchmark payload").unwrap();
            }
            projection.sync().unwrap();
            let elapsed = start.elapsed();
            eprintln!(
                "{{\"benchmark\":\"projection_last_chain\",\"shape\":\"{}\",\"sample\":{sample},\"reuse\":{reuse},\"files\":256,\"elapsed_ns\":{},\"new_bindings\":{}}}",
                if unique { "unique" } else { "siblings" },
                elapsed.as_nanos(),
                super::anchor::take_new_bindings()
            );
        }
    }
}

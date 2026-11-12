//! Cross-platform publication/backup identity regressions.
use super::PrivateFileProjection;
use std::{fs, path::Path};

// Windows filesystem fault injectors share the existing native test lock.
// Keep its guard alive for the complete test, not just fixture creation.
fn private_root() -> (
    tempfile::TempDir,
    Option<std::sync::MutexGuard<'static, ()>>,
) {
    #[cfg(windows)]
    {
        let guard = crate::platform_fs::windows::private_test_guard();
        (
            crate::platform_fs::windows::private_test_directory(),
            Some(guard),
        )
    }
    #[cfg(unix)]
    {
        (tempfile::tempdir().unwrap(), None)
    }
}

#[test]
fn captured_absence_rejects_new_target_without_publication() {
    let (root, _native_guard) = private_root();
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    let (replacement, previous) = projection
        .capture_replacement(Path::new("state"), &mut Vec::new())
        .unwrap();
    assert_eq!(previous, None);
    fs::write(root.path().join("state"), b"concurrent").unwrap();
    let (receipt, result) = replacement.write_from(&mut &b"ours"[..], 4).into_parts();
    assert!(result.is_err());
    assert!(
        receipt.is_none(),
        "a failed prepublication write must not enroll rollback"
    );
    assert_eq!(fs::read(root.path().join("state")).unwrap(), b"concurrent");
}

#[test]
fn captured_previous_rejects_replaced_target_without_publication() {
    let (root, _native_guard) = private_root();
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    projection.write(Path::new("state"), b"previous").unwrap();
    let mut backup = Vec::new();
    let (replacement, length) = projection
        .capture_replacement(Path::new("state"), &mut backup)
        .unwrap();
    assert_eq!(length, Some(8));
    assert_eq!(backup, b"previous");
    fs::rename(root.path().join("state"), root.path().join("saved")).unwrap();
    fs::write(root.path().join("state"), b"concurrent").unwrap();
    let (receipt, result) = replacement.write_from(&mut &b"ours"[..], 4).into_parts();
    assert!(result.is_err());
    assert!(receipt.is_none());
    assert_eq!(fs::read(root.path().join("state")).unwrap(), b"concurrent");
}

#[test]
fn rollback_refuses_a_changed_published_target_and_another_session() {
    let (root, _native_guard) = private_root();
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    let (replacement, _) = projection
        .capture_replacement(Path::new("state"), &mut Vec::new())
        .unwrap();
    let (receipt, result) = replacement.write_from(&mut &b"ours"[..], 4).into_parts();
    result.unwrap();
    let receipt = receipt.unwrap();
    // Keep the old inode alive at another name: no inode-reuse ambiguity.
    fs::rename(root.path().join("state"), root.path().join("saved")).unwrap();
    fs::write(root.path().join("state"), b"concurrent").unwrap();
    assert!(projection.rollback_publication(receipt, None).is_err());
    assert_eq!(fs::read(root.path().join("state")).unwrap(), b"concurrent");
    let (replacement, _) = projection
        .capture_replacement(Path::new("second"), &mut Vec::new())
        .unwrap();
    let (receipt, result) = replacement.write_from(&mut &b"ours"[..], 4).into_parts();
    result.unwrap();
    let other = PrivateFileProjection::open(root.path()).unwrap();
    assert!(other.rollback_publication(receipt.unwrap(), None).is_err());
    assert_eq!(fs::read(root.path().join("second")).unwrap(), b"ours");
}

#[test]
fn postrename_fence_error_retains_receipt_and_restores_backup() {
    let (root, _native_guard) = private_root();
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    projection.write(Path::new("state"), b"previous").unwrap();
    let mut backup = Vec::new();
    let (replacement, _) = projection
        .capture_replacement(Path::new("state"), &mut backup)
        .unwrap();
    #[cfg(unix)]
    let fault = super::platform::fail_replacement_fence();
    #[cfg(windows)]
    let fault = crate::platform_fs::windows::install_projection_namespace_flush_failures(1);
    let (receipt, result) = replacement.write_from(&mut &b"ours"[..], 4).into_parts();
    assert!(result.is_err());
    assert_eq!(fs::read(root.path().join("state")).unwrap(), b"ours");
    drop(fault);
    projection
        .rollback_publication(
            receipt.expect("rename succeeded before the fence failed"),
            Some((&mut backup.as_slice(), u64::try_from(backup.len()).unwrap())),
        )
        .unwrap();
    projection.sync().unwrap();
    assert_eq!(fs::read(root.path().join("state")).unwrap(), b"previous");
}

#[cfg(unix)]
#[test]
fn capture_and_publish_reuse_one_relative_directory_acquisition() {
    let (root, _native_guard) = private_root();
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    projection
        .write(Path::new("nested/state"), b"previous")
        .unwrap();
    super::platform::take_relative_walks();
    projection
        .snapshot_to(Path::new("nested/state"), &mut Vec::new())
        .unwrap();
    projection
        .write_from(Path::new("nested/state"), &mut &b"middle"[..], 6)
        .unwrap();
    assert_eq!(
        super::platform::take_relative_walks(),
        2,
        "old two-operation control"
    );
    let (replacement, _) = projection
        .capture_replacement(Path::new("nested/state"), &mut Vec::new())
        .unwrap();
    let (receipt, result) = replacement.write_from(&mut &b"ours"[..], 4).into_parts();
    result.unwrap();
    assert_eq!(super::platform::take_relative_walks(), 1);
    projection
        .rollback_publication(receipt.unwrap(), None)
        .unwrap();
    projection.sync().unwrap();
}

fn reject_missing_parent(prior: Option<&[u8]>) {
    let (root, _native_guard) = private_root();
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    let name = Path::new("nested/state");
    if let Some(bytes) = prior {
        projection.write(name, bytes).unwrap();
    }
    let mut backup = Vec::new();
    let (replacement, _) = projection.capture_replacement(name, &mut backup).unwrap();
    let (publication, result) = replacement.write_from(&mut &b"ours"[..], 4).into_parts();
    result.unwrap();
    fs::remove_file(root.path().join(name)).unwrap();
    fs::remove_dir(root.path().join("nested")).unwrap();
    let mut previous = backup.as_slice();
    let previous = prior.map(|_| {
        (
            &mut previous as &mut dyn std::io::Read,
            u64::try_from(backup.len()).unwrap(),
        )
    });
    assert!(
        projection
            .rollback_publication(publication.unwrap(), previous)
            .is_err()
    );
    assert!(
        !root.path().join("nested").exists(),
        "failed identity admission must not recreate ancestors"
    );
}

#[test]
fn rollback_never_recreates_missing_parent_for_prior_bytes() {
    reject_missing_parent(Some(b"previous"));
}

#[test]
fn rollback_never_accepts_missing_parent_for_prior_absence() {
    reject_missing_parent(None);
}

#[cfg(unix)]
#[test]
fn rollback_never_repairs_unproven_parent_privacy() {
    use std::os::unix::fs::PermissionsExt as _;
    let (root, _native_guard) = private_root();
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    let name = Path::new("nested/state");
    projection.write(name, b"previous").unwrap();
    let mut backup = Vec::new();
    let (replacement, _) = projection.capture_replacement(name, &mut backup).unwrap();
    let (publication, result) = replacement.write_from(&mut &b"ours"[..], 4).into_parts();
    result.unwrap();
    let parent = root.path().join("nested");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
    let result =
        projection.rollback_publication(publication.unwrap(), Some((&mut backup.as_slice(), 8)));
    assert!(result.is_err());
    assert_eq!(
        fs::metadata(parent).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(fs::read(root.path().join(name)).unwrap(), b"ours");
}

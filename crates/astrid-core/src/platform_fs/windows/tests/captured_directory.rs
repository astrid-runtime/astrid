//! Public captured-directory owner API.

use super::super::captured_directory::{child_name_absent, query_directory_identity};
use super::*;
use crate::platform_fs::{CapturedDirectory, DirectoryIdentity};

fn write_child(dir: &Path, name: &str, bytes: &[u8]) {
    std::fs::write(dir.join(name), bytes).unwrap();
}

fn identity_with_attribute_share_delete(path: &Path) -> DirectoryIdentity {
    let wide = wide_path(path).unwrap();
    // FILE_READ_ATTRIBUTES excludes DELETE, so SHARE_DELETE is compatible with
    // a captured no-share-delete handle that itself holds DELETE.
    // SAFETY: wide is NUL-terminated, and OPEN_REPARSE_POINT prevents traversal.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    assert_ne!(
        handle,
        INVALID_HANDLE_VALUE,
        "{}",
        io::Error::last_os_error()
    );
    // SAFETY: the valid owned handle transfers exactly once into File.
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    query_directory_identity(&file).unwrap()
}

#[test]
fn captured_directory_moves_cross_parent_without_replacing() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let sources = root.path().join("sources");
    let targets = root.path().join("targets");
    crate::platform_fs::create_private_directory(&sources).unwrap();
    crate::platform_fs::create_private_directory(&targets).unwrap();
    let source = sources.join("source");
    let staged = targets.join("staged");
    crate::platform_fs::create_private_directory(&source).unwrap();
    write_child(&source, "data", b"captured bytes");

    let mut captured = CapturedDirectory::open(&source).unwrap();
    let identity = captured.identity();
    let json = serde_json::to_string(&identity).unwrap();
    let restored: DirectoryIdentity = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, identity);
    assert_eq!(identity_with_attribute_share_delete(&source), identity);

    let replacement = sources.join("replacement");
    assert!(std::fs::rename(&source, &replacement).is_err());
    assert!(source.is_dir());
    assert!(!replacement.exists());

    let cloned = captured.try_clone_directory_file().unwrap();
    captured.rename_to(&staged).unwrap();
    drop(cloned);
    assert!(!source.exists());
    assert_eq!(
        std::fs::read(staged.join("data")).unwrap(),
        b"captured bytes"
    );
    assert_eq!(captured.identity(), identity);
    assert_eq!(identity_with_attribute_share_delete(&staged), identity);

    crate::platform_fs::create_private_directory(&source).unwrap();
    write_child(&source, "sentinel", b"new source must survive");
    let mut occupant = CapturedDirectory::open(&source).unwrap();
    assert!(occupant.rename_to(&staged).is_err());
    assert_eq!(
        std::fs::read(source.join("sentinel")).unwrap(),
        b"new source must survive"
    );
    assert_eq!(
        std::fs::read(staged.join("data")).unwrap(),
        b"captured bytes"
    );
}

#[test]
fn captured_directory_child_file_must_be_dropped_before_move() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let sources = root.path().join("sources");
    let targets = root.path().join("targets");
    crate::platform_fs::create_private_directory(&sources).unwrap();
    crate::platform_fs::create_private_directory(&targets).unwrap();
    let source = sources.join("source");
    let staged = targets.join("staged");
    crate::platform_fs::create_private_directory(&source).unwrap();
    write_child(&source, "data", b"unpin before move");

    let mut captured = CapturedDirectory::open(&source).unwrap();
    let child = std::fs::File::open(source.join("data")).unwrap();
    assert!(captured.rename_to(&staged).is_err());
    assert!(source.is_dir());
    assert!(!staged.exists());
    drop(child);
    captured.rename_to(&staged).unwrap();
    assert_eq!(
        std::fs::read(staged.join("data")).unwrap(),
        b"unpin before move"
    );
}

#[test]
fn captured_directory_remove_empty_refuses_nonempty_and_deletes_empty() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let parent = root.path().join("parent");
    crate::platform_fs::create_private_directory(&parent).unwrap();
    let nonempty = parent.join("nonempty");
    crate::platform_fs::create_private_directory(&nonempty).unwrap();
    write_child(&nonempty, "data", b"keep me");
    let captured = CapturedDirectory::open(&nonempty).unwrap();
    let clone = captured.try_clone_directory_file().unwrap();
    drop(clone);
    assert!(captured.remove_empty().is_err());
    assert_eq!(std::fs::read(nonempty.join("data")).unwrap(), b"keep me");

    let empty = parent.join("empty");
    crate::platform_fs::create_private_directory(&empty).unwrap();
    let captured = CapturedDirectory::open(&empty).unwrap();
    captured.remove_empty().unwrap();
    assert!(!empty.exists());
}

#[test]
fn captured_directory_error_paths_leave_uncaptured_trees() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let parent = root.path().join("parent");
    crate::platform_fs::create_private_directory(&parent).unwrap();
    let missing = parent.join("missing");
    assert!(CapturedDirectory::open(&missing).is_err());
    assert!(!missing.exists());

    let source = parent.join("source");
    crate::platform_fs::create_private_directory(&source).unwrap();
    write_child(&source, "data", b"uncaptured stays");
    let mut captured = CapturedDirectory::open(&source).unwrap();
    let missing_dest = parent.join("no-such-parent").join("staged");
    assert!(captured.rename_to(&missing_dest).is_err());
    assert_eq!(
        std::fs::read(source.join("data")).unwrap(),
        b"uncaptured stays"
    );
}

#[test]
fn captured_directory_remove_does_not_report_success_with_a_live_duplicate() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let directory = root.path().join("pending");
    crate::platform_fs::create_private_directory(&directory).unwrap();
    let captured = CapturedDirectory::open(&directory).unwrap();
    let duplicate = captured.try_clone_directory_file().unwrap();
    let result = captured.remove_empty();
    assert!(
        result.is_err(),
        "reported removal while a duplicate remained alive"
    );
    drop(duplicate);
    assert!(!directory.exists());
}

#[test]
fn removal_confirmation_rejects_non_name_not_found_errors() {
    assert!(child_name_absent(&io::Error::from_raw_os_error(2)));
    // Path/drive/network disappearance and a delete-pending object do not
    // establish the absence of this one child in the retained parent.
    for code in [3, 5, 15, 53, 67, 303] {
        assert!(!child_name_absent(&io::Error::from_raw_os_error(code)));
    }
    assert!(!child_name_absent(&io::Error::from(
        io::ErrorKind::NotFound
    )));
}

#[test]
fn captured_directory_traversal_duplicate_cannot_rename_its_owner() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let directory = root.path().join("source");
    let moved = root.path().join("moved-through-duplicate");
    crate::platform_fs::create_private_directory(&directory).unwrap();
    let captured = CapturedDirectory::open(&directory).unwrap();
    let duplicate = captured.try_clone_directory_file().unwrap();
    let parent = TrustedPathGuard::capture(root.path()).unwrap();
    let error = rename_guarded_handle(&duplicate, &parent, &moved, false)
        .expect_err("traversal duplicate must not carry the owner's rename authority");
    assert_eq!(error.raw_os_error(), Some(5));
    assert!(directory.exists());
    assert!(!moved.exists());
    drop(duplicate);
    captured.remove_empty().unwrap();
    assert!(!directory.exists());
}

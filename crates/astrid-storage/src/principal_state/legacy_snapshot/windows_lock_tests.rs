//! A parent rename may be refused while a descendant LOCK remains open.
//! Either outcome must preserve the shared writer fence and original bytes.

use super::super::native_io::{PrivateDirectory, private_file_identity};
use std::fs::{File, TryLockError};
use std::path::Path;

mod captured_source;

pub(super) fn private_temp() -> super::test_directory::TestDirectory {
    super::test_directory::temporary().unwrap()
}

fn assert_writer_excluded(file: &File) {
    assert!(
        matches!(file.try_lock(), Err(TryLockError::WouldBlock)),
        "exclusive writer entered during the shared source fence"
    );
}

pub(super) fn assert_path_writer_excluded(path: &Path) {
    // A checkpoint handle must close before rename: an unrelated open handle
    // through the source link would itself pin that directory on Windows.
    let writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    assert_writer_excluded(&writer);
}

#[test]
fn native_outside_lock_link_preserves_the_shared_source_fence() {
    for outside_link in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let staged = root.path().join("staged");
        let outside = root.path().join("outside");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let lock = source.join("LOCK");
        let alias = outside.join("LOCK");
        std::fs::write(&lock, b"fixture").unwrap();
        let original = File::open(&lock).unwrap();
        original.try_lock_shared().unwrap();
        assert_path_writer_excluded(&lock);
        let guard = if outside_link {
            std::fs::hard_link(&lock, &alias).unwrap();
            let guard = File::open(&alias).unwrap();
            assert_eq!(
                private_file_identity(&original).unwrap(),
                private_file_identity(&guard).unwrap()
            );
            // Acquire the same-inode fence before closing the original link.
            guard.try_lock_shared().unwrap();
            assert_path_writer_excluded(&lock);
            drop(original);
            guard
        } else {
            original
        };
        assert_path_writer_excluded(&lock);
        let while_locked = std::fs::rename(&source, &staged);
        eprintln!(
            "parent rename with short-lived writer checkpoints (outside_link={outside_link}): {while_locked:?}"
        );
        let remaining = if let Err(error) = &while_locked {
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(source.is_dir());
            assert!(!staged.try_exists().unwrap());
            &source
        } else {
            &staged
        };
        assert_path_writer_excluded(&remaining.join("LOCK"));
        assert_eq!(std::fs::read(remaining.join("LOCK")).unwrap(), b"fixture");
        drop(guard);
        let writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(remaining.join("LOCK"))
            .unwrap();
        writer.try_lock().unwrap();
        writer.unlock().unwrap();
        drop(writer);
        // Both rename outcomes are recorded by this experiment. Production
        // retirement still requires success without releasing its writer fence.
        if while_locked.is_err() {
            std::fs::rename(&source, &staged).unwrap();
        }
        assert_eq!(std::fs::read(staged.join("LOCK")).unwrap(), b"fixture");
    }
}

#[test]
fn native_parent_rename_preserves_the_shared_source_fence() {
    for capability_relative in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let staged = root.path().join("staged");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("LOCK"), b"fixture").unwrap();
        let file = if capability_relative {
            let directory = PrivateDirectory::open(&source).unwrap();
            directory.open_file(Path::new("LOCK")).unwrap()
        } else {
            File::open(source.join("LOCK")).unwrap()
        };
        file.try_lock_shared().unwrap();
        let competing = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(source.join("LOCK"))
            .unwrap();
        assert_writer_excluded(&competing);
        let while_locked = std::fs::rename(&source, &staged);
        eprintln!(
            "parent rename while source fenced (relative={capability_relative}): {while_locked:?}"
        );
        if let Err(error) = &while_locked {
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(source.is_dir());
            assert!(!staged.try_exists().unwrap());
        }
        assert_writer_excluded(&competing);
        drop(file);
        competing.try_lock().unwrap();
        competing.unlock().unwrap();
        drop(competing);
        // This is fixture cleanup, never the production retirement protocol.
        // Production must retain its fence across every destructive operation.
        if while_locked.is_err() {
            std::fs::rename(&source, &staged).unwrap();
        }
        assert_eq!(std::fs::read(staged.join("LOCK")).unwrap(), b"fixture");
    }
}

fn native_link_count(file: &File) -> u32 {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the owned file handle and writable output buffer remain live.
    #[allow(unsafe_code)]
    let success = unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut info) };
    assert_ne!(success, 0, "{}", std::io::Error::last_os_error());
    info.nNumberOfLinks
}

#[test]
fn native_private_link_handoff_allows_write_through_retirement() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let staged = root.path().join("staged");
    let outside = root.path().join("outside");
    astrid_core::platform_fs::create_private_directory(&source).unwrap();
    astrid_core::platform_fs::create_private_directory(&outside).unwrap();
    std::fs::write(source.join("LOCK"), b"fixture").unwrap();
    std::fs::write(source.join("data"), b"original data").unwrap();
    let directory = PrivateDirectory::open(&source).unwrap();
    let original = directory.open_file(Path::new("LOCK")).unwrap();
    original.try_lock_shared().unwrap();
    let identity = private_file_identity(&original).unwrap();
    assert_eq!(native_link_count(&original), 1);
    assert_path_writer_excluded(&source.join("LOCK"));
    let alias = outside.join("LOCK");
    std::fs::hard_link(source.join("LOCK"), &alias).unwrap();
    let alias_directory = PrivateDirectory::open(&outside).unwrap();
    let guard = alias_directory.open_file(Path::new("LOCK")).unwrap();
    assert_eq!(private_file_identity(&guard).unwrap(), identity);
    assert_eq!(native_link_count(&guard), 2);
    guard.try_lock_shared().unwrap();
    assert_path_writer_excluded(&source.join("LOCK"));
    drop(original);
    // A retained source directory capability deliberately pins its name on
    // Windows. Only the same-file outside fence crosses this transition.
    drop(directory);
    assert_path_writer_excluded(&source.join("LOCK"));
    let moved = astrid_core::platform_fs::rename_with_write_through(&source, &staged);
    eprintln!("private same-file outside fence, write-through retirement: {moved:?}");
    moved.unwrap();
    assert!(!source.try_exists().unwrap());
    assert_path_writer_excluded(&staged.join("LOCK"));
    assert_eq!(std::fs::read(staged.join("LOCK")).unwrap(), b"fixture");
    assert_eq!(
        std::fs::read(staged.join("data")).unwrap(),
        b"original data"
    );
    assert_eq!(private_file_identity(&guard).unwrap(), identity);
    assert_eq!(native_link_count(&guard), 2);
    drop(guard);
    std::fs::remove_file(&alias).unwrap();
    let writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(staged.join("LOCK"))
        .unwrap();
    assert_eq!(private_file_identity(&writer).unwrap(), identity);
    assert_eq!(native_link_count(&writer), 1);
    writer.try_lock().unwrap();
    writer.unlock().unwrap();
}

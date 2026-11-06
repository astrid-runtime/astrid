//! A parent rename may be refused while a descendant LOCK remains open.
//! Either outcome must preserve the shared writer fence and original bytes.

use super::super::native_io::PrivateDirectory;
use std::fs::{File, TryLockError};
use std::path::Path;

fn assert_writer_excluded(file: &File) {
    assert!(
        matches!(file.try_lock(), Err(TryLockError::WouldBlock)),
        "exclusive writer entered during the shared source fence"
    );
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

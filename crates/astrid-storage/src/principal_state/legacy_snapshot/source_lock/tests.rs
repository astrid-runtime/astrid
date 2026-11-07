use super::*;
use crate::principal_state::legacy_snapshot::windows_lock_tests::assert_path_writer_excluded;
use crate::principal_state::native_io::PrivateDirectory;
use std::path::Path;

#[test]
fn shared_file_id_handoff_unpins_parent_without_admitting_a_writer() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let staged = root.path().join("staged");
    astrid_core::platform_fs::create_private_directory(&source).unwrap();
    std::fs::write(source.join("LOCK"), b"original lock").unwrap();
    std::fs::write(source.join("data"), b"original data").unwrap();
    let directory = PrivateDirectory::open(&source).unwrap();
    let original = directory.open_file(Path::new("LOCK")).unwrap();
    drop(directory);
    original.try_lock_shared().unwrap();
    let expected = identity(&original).unwrap();
    assert_path_writer_excluded(&source.join("LOCK"));
    // This is the actual pre-fix source handle, without an independent open
    // writer probe or directory capability accidentally pinning its parent.
    let before_handoff = astrid_core::platform_fs::rename_with_write_through(&source, &staged);
    eprintln!("parent move before file-ID handoff: {before_handoff:?}");
    if let Err(error) = before_handoff {
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    } else {
        // A filesystem that already permits the move must remain supported.
        astrid_core::platform_fs::rename_with_write_through(&staged, &source).unwrap();
    }
    assert!(source.is_dir());
    assert!(!staged.try_exists().unwrap());
    let guard = handoff(original).unwrap();
    assert_path_writer_excluded(&source.join("LOCK"));
    astrid_core::platform_fs::rename_with_write_through(&source, &staged).unwrap();
    assert!(!source.try_exists().unwrap());
    assert_path_writer_excluded(&staged.join("LOCK"));
    let actual = identity(&guard).unwrap();
    assert_eq!(actual.VolumeSerialNumber, expected.VolumeSerialNumber);
    assert_eq!(actual.FileId.Identifier, expected.FileId.Identifier);
    assert_eq!(
        std::fs::read(staged.join("data")).unwrap(),
        b"original data"
    );
    assert_eq!(
        std::fs::read(staged.join("LOCK")).unwrap(),
        b"original lock"
    );
    drop(guard);
    let writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(staged.join("LOCK"))
        .unwrap();
    writer.try_lock().unwrap();
    writer.unlock().unwrap();
}

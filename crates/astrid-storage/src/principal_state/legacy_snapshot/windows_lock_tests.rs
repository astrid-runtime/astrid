//! Native-only discriminator: a LOCK handle must not pin its parent name.
//! Compares opens of the same file identity without relaxing its writer fence.

use super::super::native_io::{PrivateDirectory, private_file_identity};
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::Path;
use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, ReOpenFile,
};

#[derive(Clone, Copy, Debug)]
enum LockOpen {
    Ambient,
    Capability,
    ReopenedCapability,
}

fn open_lock(path: &Path, mode: LockOpen) -> io::Result<File> {
    if matches!(mode, LockOpen::Ambient) {
        return File::open(path.join("LOCK"));
    }
    let directory = PrivateDirectory::open(path).map_err(io::Error::other)?;
    let file = directory
        .open_file(Path::new("LOCK"))
        .map_err(io::Error::other)?;
    drop(directory);
    if matches!(mode, LockOpen::Capability) {
        return Ok(file);
    }
    reopen_lock(&file)
}

fn reopen_lock(file: &File) -> io::Result<File> {
    // SAFETY: file owns a live ordinary file handle. The returned handle is
    // checked before transferring unique ownership into File; no path reopen.
    #[allow(unsafe_code)]
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle().cast(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ReOpenFile returned a new uniquely owned valid file handle.
    #[allow(unsafe_code)]
    let reopened = unsafe { File::from_raw_handle(handle.cast()) };
    if private_file_identity(file).map_err(io::Error::other)?
        != private_file_identity(&reopened).map_err(io::Error::other)?
    {
        return Err(io::Error::other("ReOpenFile changed LOCK identity"));
    }
    Ok(reopened)
}

#[test]
fn native_lock_handle_parent_rename_discriminator() {
    let mut observations = Vec::new();
    for mode in [
        LockOpen::Ambient,
        LockOpen::Capability,
        LockOpen::ReopenedCapability,
    ] {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let staged = root.path().join("staged");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("LOCK"), b"fixture").unwrap();
        let file = open_lock(&source, mode).unwrap();
        file.try_lock_shared().unwrap();
        let competing = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(source.join("LOCK"))
            .unwrap();
        assert!(
            matches!(competing.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
            "exclusive writer entered before staging"
        );
        let while_locked = std::fs::rename(&source, &staged);
        let locked_code = while_locked
            .as_ref()
            .err()
            .and_then(io::Error::raw_os_error);
        assert!(
            matches!(competing.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
            "exclusive writer entered during staging"
        );
        drop(file);
        competing.try_lock().unwrap();
        competing.unlock().unwrap();
        drop(competing);
        let after_release = if while_locked.is_err() {
            std::fs::rename(&source, &staged)
        } else {
            Ok(())
        };
        let released_code = after_release
            .as_ref()
            .err()
            .and_then(io::Error::raw_os_error);
        observations.push((mode, locked_code, released_code));
        eprintln!("LOCK parent rename observation: {:?}", observations.last());
        assert!(
            after_release.is_ok(),
            "rename is not isolated to live handle: {observations:?}"
        );
        assert_eq!(std::fs::read(staged.join("LOCK")).unwrap(), b"fixture");
    }
    eprintln!("LOCK parent rename observations: {observations:?}");
    assert!(
        observations[0].1.is_none(),
        "ambient baseline cannot stage while locked: {observations:?}"
    );
    assert!(
        observations[2].1.is_none(),
        "identity-preserving reopen cannot stage while locked: {observations:?}"
    );
}

#[test]
fn native_reopened_lock_handoff_keeps_writer_fenced_during_parent_move() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let staged = root.path().join("staged");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("LOCK"), b"fixture").unwrap();
    let original = open_lock(&source, LockOpen::Capability).unwrap();
    original.try_lock_shared().unwrap();
    let competing = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(source.join("LOCK"))
        .unwrap();
    let excluded = || {
        assert!(
            matches!(competing.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
            "exclusive writer entered during lock handoff"
        )
    };
    excluded();
    let reopened = reopen_lock(&original).unwrap();
    reopened.try_lock_shared().unwrap();
    excluded();
    drop(original);
    excluded();
    let result = std::fs::rename(&source, &staged);
    eprintln!("overlapping shared LOCK handoff parent rename: {result:?}");
    excluded();
    drop(reopened);
    competing.try_lock().unwrap();
    competing.unlock().unwrap();
    drop(competing);
    result.unwrap();
    assert_eq!(std::fs::read(staged.join("LOCK")).unwrap(), b"fixture");
}

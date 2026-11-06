//! Record whether an ID-open LOCK fences writers without pinning its old parent.
//!
//! This is an experiment, not production retirement or a supported-FS verdict.
//! A runner's ordinary temporary directory does not establish ReFS coverage.

use super::{PrivateDirectory, assert_path_writer_excluded};
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    ExtendedFileIdType, FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FILE_ID_INFO, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo, FileIdType, GetFileInformationByHandleEx,
    OpenFileById,
};

fn identity(file: &File) -> FILE_ID_INFO {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: the borrowed handle and correctly sized writable output live
    // through this synchronous query. Keep all 128 bits, including on ReFS.
    #[allow(unsafe_code)]
    let success = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileIdInfo,
            (&raw mut info).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>()).unwrap(),
        )
    };
    assert_ne!(success, 0, "{}", io::Error::last_os_error());
    info
}

fn open_by_id(original: &File, extended: bool) -> io::Result<File> {
    let info = identity(original);
    let descriptor = FILE_ID_DESCRIPTOR {
        dwSize: u32::try_from(size_of::<FILE_ID_DESCRIPTOR>()).unwrap(),
        Type: if extended {
            ExtendedFileIdType
        } else {
            FileIdType
        },
        Anonymous: if extended {
            FILE_ID_DESCRIPTOR_0 {
                ExtendedFileId: info.FileId,
            }
        } else {
            // The legacy form is a separate NTFS diagnostic, never a ReFS
            // fallback: a nonzero upper half must not be silently truncated.
            if info.FileId.Identifier[8..] != [0; 8] {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "128-bit file identity cannot use the legacy 64-bit form",
                ));
            }
            FILE_ID_DESCRIPTOR_0 {
                FileId: i64::from_le_bytes(info.FileId.Identifier[..8].try_into().unwrap()),
            }
        },
    };
    // OpenFileById accepts a live file on the same volume as its volume hint.
    // No new name or hard link is created. The existing read-only handle keeps
    // the source inode live until the same-inode shared fence is acquired.
    // SAFETY: original and the initialized matching descriptor remain live;
    // no security attributes are supplied and the returned handle is checked.
    #[allow(unsafe_code)]
    let handle = unsafe {
        OpenFileById(
            original.as_raw_handle().cast(),
            &raw const descriptor,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the newly returned valid owned handle transfers exactly once.
    #[allow(unsafe_code)]
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    Ok(file)
}

#[test]
fn native_file_id_handoff_records_parent_rename_and_writer_exclusion() {
    for extended in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let staged = root.path().join("staged");
        astrid_core::platform_fs::create_private_directory(&source).unwrap();
        std::fs::write(source.join("LOCK"), b"original lock").unwrap();
        std::fs::write(source.join("data"), b"original data").unwrap();
        let directory = PrivateDirectory::open(&source).unwrap();
        let original = directory.open_file(Path::new("LOCK")).unwrap();
        original.try_lock_shared().unwrap();
        assert_path_writer_excluded(&source.join("LOCK"));
        let guard = match open_by_id(&original, extended) {
            Ok(guard) => guard,
            Err(error) => {
                eprintln!("file-id handoff (extended={extended}): open refused: {error:?}");
                assert_path_writer_excluded(&source.join("LOCK"));
                continue;
            },
        };
        let expected = identity(&original);
        let actual = identity(&guard);
        assert_eq!(actual.VolumeSerialNumber, expected.VolumeSerialNumber);
        assert_eq!(actual.FileId.Identifier, expected.FileId.Identifier);
        guard.try_lock_shared().unwrap();
        assert_path_writer_excluded(&source.join("LOCK"));
        drop(original);
        drop(directory);
        assert_path_writer_excluded(&source.join("LOCK"));
        let moved = astrid_core::platform_fs::rename_with_write_through(&source, &staged);
        eprintln!("file-id handoff (extended={extended}): parent rename: {moved:?}");
        let remaining = if let Err(error) = &moved {
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(!staged.try_exists().unwrap());
            &source
        } else {
            assert!(!source.try_exists().unwrap());
            &staged
        };
        assert_path_writer_excluded(&remaining.join("LOCK"));
        assert_eq!(
            std::fs::read(remaining.join("data")).unwrap(),
            b"original data"
        );
        assert_eq!(
            identity(&guard).FileId.Identifier,
            expected.FileId.Identifier
        );
        drop(guard);
        let writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(remaining.join("LOCK"))
            .unwrap();
        writer.try_lock().unwrap();
        writer.unlock().unwrap();
    }
}

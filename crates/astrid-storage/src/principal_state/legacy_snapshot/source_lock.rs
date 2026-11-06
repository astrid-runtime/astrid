//! Retain the same shared source fence without retaining its parent link.

use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    ExtendedFileIdType, FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FILE_ID_INFO, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandleEx, OpenFileById,
};

pub(in crate::principal_state) fn handoff(original: File) -> io::Result<File> {
    let expected = identity(&original)?;
    let successor = open_by_id(&original, expected)?;
    let actual = identity(&successor)?;
    if actual.VolumeSerialNumber != expected.VolumeSerialNumber
        || actual.FileId.Identifier != expected.FileId.Identifier
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "legacy source LOCK identity changed during handoff",
        ));
    }
    // Overlap both shared locks. Dropping the path-open file before acquiring
    // its successor would admit a legacy writer between digest and retirement.
    successor.try_lock_shared().map_err(io::Error::from)?;
    drop(original);
    Ok(successor)
}

pub(in crate::principal_state) fn extended_identity(file: &File) -> io::Result<(u64, [u8; 16])> {
    let info = identity(file)?;
    Ok((info.VolumeSerialNumber, info.FileId.Identifier))
}

fn identity(file: &File) -> io::Result<FILE_ID_INFO> {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: the borrowed live handle and correctly sized writable output
    // remain valid throughout this synchronous query.
    #[allow(unsafe_code)]
    let success = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileIdInfo,
            (&raw mut info).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO fits in u32"),
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

fn open_by_id(original: &File, identity: FILE_ID_INFO) -> io::Result<File> {
    let descriptor = FILE_ID_DESCRIPTOR {
        dwSize: u32::try_from(size_of::<FILE_ID_DESCRIPTOR>())
            .expect("FILE_ID_DESCRIPTOR fits in u32"),
        Type: ExtendedFileIdType,
        // Preserve all 128 bits, including on ReFS. No truncated-ID fallback.
        Anonymous: FILE_ID_DESCRIPTOR_0 {
            ExtendedFileId: identity.FileId,
        },
    };
    // SAFETY: original is a live same-volume hint; the matching initialized
    // descriptor lives through the call. The resulting handle is checked and
    // transferred to File exactly once. Read-only access preserves LOCK bytes.
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
    // SAFETY: this valid owned handle transfers exactly once.
    #[allow(unsafe_code)]
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    Ok(file)
}

#[cfg(test)]
mod tests;

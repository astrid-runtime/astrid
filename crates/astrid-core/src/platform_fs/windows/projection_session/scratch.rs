//! Anonymous `ExactPrivate` Windows scratch files created with birth-time ACL.

use super::super::acl::{PrivateSecurityDescriptor, validate_private_acl_handle};
use super::super::path::{OwnedHandle, wide_path};
use super::super::prelude::*;

const SCRATCH_CREATE_ATTEMPTS: u32 = 1_024;
const SCRATCH_DESIRED_ACCESS: u32 = GENERIC_READ | GENERIC_WRITE | READ_CONTROL | DELETE;

/// Create one `ExactPrivate` anonymous scratch [`File`].
///
/// Uses `NtCreateFile` with [`PrivateSecurityDescriptor`] at creation time,
/// share-mode 0, `FILE_ATTRIBUTE_TEMPORARY`, and `FILE_DELETE_ON_CLOSE`.
/// Returns only the live `File` handle; the ephemeral name is not retained as
/// pathname authority and must not be reopened by name for secret I/O.
///
/// Birth-time `ExactPrivate` ACL replaces tempfile-then-protect: tempfile opens
/// without the rights needed for a later ACL rewrite.
pub(in crate::platform_fs) fn create_private_scratch_file() -> io::Result<File> {
    let parent = open_os_temp_parent()?;
    let security = PrivateSecurityDescriptor::new(false)?;
    for _ in 0..SCRATCH_CREATE_ATTEMPTS {
        let name = format!(".astrid-scratch-{}.tmp", uuid::Uuid::new_v4().simple());
        match create_scratch_relative(parent.0, OsStr::new(&name), &security) {
            Ok(file) => return Ok(file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "exhausted unique Windows private scratch name attempts",
    ))
}

fn open_os_temp_parent() -> io::Result<OwnedHandle> {
    let temp_dir = std::env::temp_dir();
    let wide = wide_path(&temp_dir)?;
    // FILE_WRITE_DATA is FILE_ADD_FILE on directories; required for relative create.
    let desired = FILE_WRITE_DATA
        | FILE_LIST_DIRECTORY
        | FILE_TRAVERSE
        | FILE_READ_ATTRIBUTES
        | READ_CONTROL
        | SYNCHRONIZE;
    // SAFETY: `wide` is NUL-terminated; null security/template pointers are valid.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            desired,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let handle = OwnedHandle(handle);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: handle is live and `info` is writable.
    if unsafe { GetFileInformationByHandle(handle.0, &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows temp parent is redirected or not a directory",
        ));
    }
    Ok(handle)
}

fn create_scratch_relative(
    parent: HANDLE,
    name: &OsStr,
    security: &PrivateSecurityDescriptor,
) -> io::Result<File> {
    let mut name = name.encode_wide().collect::<Vec<_>>();
    if name.is_empty() || name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Windows private scratch file name",
        ));
    }
    let byte_length = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows private scratch file name is too long",
            )
        })?;
    let unicode = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())
            .expect("OBJECT_ATTRIBUTES fits in u32"),
        RootDirectory: parent,
        ObjectName: &raw const unicode,
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE
        SecurityDescriptor: security.as_ptr(),
        SecurityQualityOfService: null(),
    };
    let mut handle = null_mut();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: parent/name/security/output buffers remain live for the call.
    let result = unsafe {
        NtCreateFile(
            &raw mut handle,
            SCRATCH_DESIRED_ACCESS | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status,
            null(),
            FILE_ATTRIBUTE_TEMPORARY,
            0, // share-mode 0
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE
                | FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_DELETE_ON_CLOSE,
            null(),
            0,
        )
    };
    if result < 0 {
        // SAFETY: conversion is defined for the returned NTSTATUS.
        let code = unsafe { RtlNtStatusToDosError(result) };
        return Err(io::Error::from_raw_os_error(code.cast_signed()));
    }
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::other(
            "NtCreateFile returned an invalid private scratch handle",
        ));
    }
    let owned = OwnedHandle(handle);
    reject_non_scratch_handle(owned.0)?;
    validate_private_acl_handle(owned.0, false, "private scratch file")?;
    let raw = owned.0;
    std::mem::forget(owned);
    // SAFETY: ownership transfers from the forgotten OwnedHandle exactly once.
    Ok(unsafe { File::from_raw_handle(raw.cast()) })
}

fn reject_non_scratch_handle(handle: HANDLE) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is live and `info` is writable.
    if unsafe { GetFileInformationByHandle(handle, &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private scratch handle is not a regular file",
        ));
    }
    if info.nNumberOfLinks != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private scratch file must have exactly one link before secrets are written",
        ));
    }
    Ok(())
}

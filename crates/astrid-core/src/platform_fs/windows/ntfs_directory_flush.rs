//! NTFS namespace flush bound to retained capture authority.
//!
//! A derived flush handle shares deletion so it can coexist with the caller's
//! birth/cleanup handles. Its paired authority duplicate retains the original
//! open's sharing restrictions throughout the operation. Trusted path guards
//! provide rename/delete denial at their selected authority boundary; a derived
//! flush file alone provides no such authority.
//!
//! `DuplicateHandle` keeps the same file object and sharing state alive:
//! <https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle>.
//! Sharing remains in force until the last handle for that open closes:
//! <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew>.
//! Durability uses NTFS `NtFlushBuffersFileEx(0)` ([MS-FSA] 2.1.5.7).

use std::ffi::OsStr;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};

use super::captured_directory::query_directory_identity;
use super::error::with_context;
use super::path::{OwnedHandle, TrustedPathGuard, wide_path};
use super::prelude::*;
use crate::platform_fs::DirectoryIdentity;
use windows_sys::Wdk::Storage::FileSystem::NtFlushBuffersFileEx;
use windows_sys::Win32::Foundation::STATUS_PENDING;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, GetVolumeInformationByHandleW,
};

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
thread_local! {
    /// Test-only reported filesystem override for the NTFS gate. Thread-local RAII;
    /// not product configuration and not a process-global fault injector.
    static REPORTED_FILESYSTEM_OVERRIDE: RefCell<Option<OsString>> = const { RefCell::new(None) };
}

/// RAII override of the filesystem name returned at the `GetVolume` gate.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ReportedFilesystemOverride {
    previous: Option<OsString>,
}

#[cfg(test)]
impl ReportedFilesystemOverride {
    pub(crate) fn install(name: impl Into<OsString>) -> Self {
        let previous = REPORTED_FILESYSTEM_OVERRIDE.with(|slot| slot.replace(Some(name.into())));
        Self { previous }
    }
}

#[cfg(test)]
impl Drop for ReportedFilesystemOverride {
    fn drop(&mut self) {
        REPORTED_FILESYSTEM_OVERRIDE.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

/// Access required to flush an NTFS `DirectoryFile` and to run
/// `NtQueryDirectoryFile` on the same handle when the caller retains it
/// (retirement). Includes `FILE_LIST_DIRECTORY`. Does not include `DELETE`;
/// unlink opens remain caller-specific.
pub(crate) const DIRECTORY_FLUSH_ACCESS: u32 = FILE_LIST_DIRECTORY
    | FILE_TRAVERSE
    | FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_READ_ATTRIBUTES
    | FILE_WRITE_ATTRIBUTES
    | READ_CONTROL
    | SYNCHRONIZE;

/// Paired NTFS flush capability retaining the caller's capture authority.
///
/// Retirement retains this entire capability. The derived file alone does not
/// carry the captured namespace authority.
pub(super) struct NtfsDirectoryFlushGuard {
    /// Derived flush open; sharing permits coexistence with cleanup handles.
    flush: File,
    identity: DirectoryIdentity,
    /// Keeps the original open's access and sharing constraints alive. Dropped
    /// after the derived flusher, so the flusher never outlives this authority.
    _authority: File,
}

impl NtfsDirectoryFlushGuard {
    pub(crate) fn identity(&self) -> DirectoryIdentity {
        self.identity
    }

    /// Synchronous NTFS directory-structure flush on the derived flush handle.
    pub(crate) fn flush(&self) -> io::Result<()> {
        flush_ntfs_directory_file(&self.flush)
    }

    /// Derived flush `File` (LIST/ADD rights) for listing and handle-relative ops.
    pub(crate) fn file(&self) -> &File {
        &self.flush
    }

    pub(crate) fn handle(&self) -> HANDLE {
        self.flush.as_raw_handle().cast()
    }
}

/// Open a paired flush capability bound to `guard`'s authority boundary.
///
/// Signature unchanged for projection. Clones the guard's authority handle
/// (`DUPLICATE_SAME_ACCESS`) as the owned rename-lock proof, then opens the
/// derived flusher with `FILE_SHARE_DELETE`. Dropping `guard` afterward is safe
/// while this capability remains alive — the owned authority duplicate continues
/// to deny delete sharing on the same file object
/// ([DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle),
/// [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)).
pub(super) fn open_flush_bound_to_guard(
    guard: &TrustedPathGuard,
) -> io::Result<NtfsDirectoryFlushGuard> {
    // SAFETY: authority handle remains owned by `guard` for this borrow.
    let authority = unsafe { BorrowedHandle::borrow_raw(guard.authority_handle().cast()) };
    open_flush_bound_to_authority(guard.authority_boundary(), authority)
}

/// Path open paired to a live authority handle, rather than an identity alone.
///
/// Duplicates `authority` into the capability, derives 128-bit identity from that
/// duplicate, opens the derived flusher with `FILE_SHARE_DELETE`, then requires
/// matching `FileIdInfo`, non-reparse directory, and NTFS.
pub(super) fn open_flush_bound_to_authority(
    path: &Path,
    authority: BorrowedHandle<'_>,
) -> io::Result<NtfsDirectoryFlushGuard> {
    let authority_file = duplicate_authority_file(authority)?;
    let expected = query_directory_identity(&authority_file).map_err(|error| {
        with_context(
            error,
            "query paired authority FileIdInfo before derived flush open",
        )
    })?;
    let flush_handle = open_derived_flush_handle_at_path(path)?;
    finish_paired_flush_capability(authority_file, File::from(flush_handle), expected, path)
}

/// Handle-relative derived flush paired to a live child authority handle.
pub(super) fn open_flush_relative_bound_to_authority(
    parent: HANDLE,
    name: &OsStr,
    authority: BorrowedHandle<'_>,
) -> io::Result<NtfsDirectoryFlushGuard> {
    let authority_file = duplicate_authority_file(authority)?;
    let expected = query_directory_identity(&authority_file).map_err(|error| {
        with_context(
            error,
            "query paired relative authority FileIdInfo before derived flush open",
        )
    })?;
    let flush_handle = open_derived_flush_handle_relative(parent, name)?;
    finish_paired_flush_capability(
        authority_file,
        File::from(flush_handle),
        expected,
        Path::new("<handle-relative-paired-flush>"),
    )
}

/// Synchronous NTFS `DirectoryFile` flush on an already-verified directory `File`.
///
/// Prefer [`NtfsDirectoryFlushGuard::flush`] for new call sites. Both the syscall
/// NTSTATUS and `IO_STATUS_BLOCK.Status` must be `0`; `STATUS_PENDING` is rejected.
pub(crate) fn flush_ntfs_directory_file(file: &File) -> io::Result<()> {
    let mut iosb = IO_STATUS_BLOCK::default();
    // SAFETY: non-overlapped directory File; Parameters unused (NULL/0);
    // `iosb` remains live for the call.
    let status =
        unsafe { NtFlushBuffersFileEx(file.as_raw_handle().cast(), 0, null(), 0, &raw mut iosb) };
    // SAFETY: union read of Status after the native call completed.
    let iosb_status = unsafe { iosb.Anonymous.Status };
    if status == STATUS_PENDING || iosb_status == STATUS_PENDING {
        return Err(io::Error::other(
            "NtFlushBuffersFileEx returned STATUS_PENDING on a non-overlapped directory handle",
        ));
    }
    if status != 0 {
        // SAFETY: conversion is defined for the NTSTATUS returned by the call.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(with_context(
            io::Error::from_raw_os_error(code.cast_signed()),
            format!(
                "NtFlushBuffersFileEx(0) syscall NTSTATUS 0x{:08X}",
                status.cast_unsigned()
            ),
        ));
    }
    if iosb_status != 0 {
        // SAFETY: conversion is defined for the IOSB NTSTATUS.
        let code = unsafe { RtlNtStatusToDosError(iosb_status) };
        return Err(with_context(
            io::Error::from_raw_os_error(code.cast_signed()),
            format!(
                "NtFlushBuffersFileEx(0) IO_STATUS_BLOCK.Status 0x{:08X}",
                iosb_status.cast_unsigned()
            ),
        ));
    }
    Ok(())
}

fn duplicate_authority_file(authority: BorrowedHandle<'_>) -> io::Result<File> {
    authority
        .try_clone_to_owned()
        .map(File::from)
        .map_err(|error| {
            with_context(
                error,
                "DuplicateHandle(SAME_ACCESS) for paired flush authority",
            )
        })
}

fn finish_paired_flush_capability(
    authority: File,
    flush: File,
    expected: DirectoryIdentity,
    path_for_errors: &Path,
) -> io::Result<NtfsDirectoryFlushGuard> {
    let actual = query_directory_identity(&flush).map_err(|error| {
        with_context(
            error,
            format!(
                "query derived flush-handle FileIdInfo {}",
                path_for_errors.display()
            ),
        )
    })?;
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "derived flush FileIdInfo diverged from paired authority for {}",
                path_for_errors.display()
            ),
        ));
    }

    // The captured authority file remains owned; its file identity cannot be
    // repointed by replacing the pathname. Compare the derived open against
    // that captured identity without a second query of the same authority.
    let filesystem = volume_filesystem_name(&flush)?;
    if !filesystem_is_ntfs(&filesystem) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "directory-structure flush requires NTFS (MS-FSA <80>); volume reports {}",
                filesystem.to_string_lossy()
            ),
        ));
    }

    reject_redirect_or_nondirectory(&flush, path_for_errors)?;

    Ok(NtfsDirectoryFlushGuard {
        _authority: authority,
        flush,
        identity: actual,
    })
}

fn reject_redirect_or_nondirectory(file: &File, path_for_errors: &Path) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: handle and output buffer are live.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut info) } == 0 {
        return Err(with_context(
            io::Error::last_os_error(),
            format!(
                "query derived flush attributes {}",
                path_for_errors.display()
            ),
        ));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "derived flush target is redirected or not a directory: {}",
                path_for_errors.display()
            ),
        ));
    }
    Ok(())
}

/// Derived flusher only: `DIRECTORY_FLUSH_ACCESS` + `FILE_SHARE_DELETE`.
///
/// Share-delete lets this open coexist with live `DELETE` holders. Rename/delete
/// denial remains on the paired authority duplicate (no share-delete), not here.
fn open_derived_flush_handle_at_path(path: &Path) -> io::Result<OwnedHandle> {
    let wide = wide_path(path)?;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    // SAFETY: NUL-terminated path; no OVERLAPPED — synchronous I/O.
    // OPEN_REPARSE_POINT opens the object itself; attributes reject redirects.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            DIRECTORY_FLUSH_ACCESS,
            share,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(with_context(
            io::Error::last_os_error(),
            format!("open derived directory flush handle {}", path.display()),
        ));
    }
    Ok(OwnedHandle(handle))
}

fn open_derived_flush_handle_relative(parent: HANDLE, name: &OsStr) -> io::Result<OwnedHandle> {
    let mut name = name.encode_wide().collect::<Vec<_>>();
    if name.is_empty() || name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid handle-relative Windows directory component for derived flush",
        ));
    }
    let byte_length = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows directory name is too long",
            )
        })?;
    let unicode = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>()).expect("OBJECT_ATTRIBUTES fits u32"),
        RootDirectory: parent,
        ObjectName: &raw const unicode,
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let mut handle = null_mut();
    let mut status = IO_STATUS_BLOCK::default();
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    // SAFETY: parent + name buffers live; OPEN_REPARSE_POINT avoids follow.
    let result = unsafe {
        NtCreateFile(
            &raw mut handle,
            DIRECTORY_FLUSH_ACCESS | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status,
            null(),
            0,
            share,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if result < 0 {
        // SAFETY: conversion defined for NTSTATUS.
        let code = unsafe { RtlNtStatusToDosError(result) };
        return Err(io::Error::from_raw_os_error(code.cast_signed()));
    }
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::other(
            "NtCreateFile returned an invalid derived flush directory handle",
        ));
    }
    Ok(OwnedHandle(handle))
}

fn volume_filesystem_name(file: &File) -> io::Result<OsString> {
    #[cfg(test)]
    if let Some(name) = REPORTED_FILESYSTEM_OVERRIDE.with(|slot| slot.borrow().clone()) {
        let _ = file;
        return Ok(name);
    }

    let mut fs_name = vec![0u16; 64];
    let mut serial = 0u32;
    let mut max_component = 0u32;
    let mut flags = 0u32;
    // SAFETY: handle live; volume name omitted; outs live for the call.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle().cast(),
            null_mut(),
            0,
            &raw mut serial,
            &raw mut max_component,
            &raw mut flags,
            fs_name.as_mut_ptr(),
            u32::try_from(fs_name.len()).expect("filesystem name buffer fits u32"),
        )
    };
    if ok == 0 {
        return Err(with_context(
            io::Error::last_os_error(),
            "GetVolumeInformationByHandleW for directory flush",
        ));
    }
    let len = fs_name
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(fs_name.len());
    Ok(OsString::from_wide(&fs_name[..len]))
}

fn filesystem_is_ntfs(name: &OsStr) -> bool {
    name.to_string_lossy().eq_ignore_ascii_case("NTFS")
}

/// Native paired-cap proof: authority duplicate denies rename after original guard drop.
///
/// Primary contracts under test:
/// - [DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
///   `DUPLICATE_SAME_ACCESS` keeps the original file-object share denial alive on the duplicate.
/// - [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
///   share flags persist until each handle closes; incompatible delete opens fail.
#[cfg(all(test, windows))]
mod paired_cap_tests {
    use super::super::acl::{apply_private_acl, validate_private_acl};
    use super::super::path::TrustedPathGuard;
    use super::open_flush_bound_to_guard;
    use directories::BaseDirs;
    use std::fs;
    use std::path::PathBuf;

    fn private_root() -> (tempfile::TempDir, PathBuf) {
        let local = BaseDirs::new().unwrap().data_local_dir().to_path_buf();
        let temp = tempfile::Builder::new()
            .prefix("astrid-paired-flush-cap-")
            .tempdir_in(local)
            .unwrap();
        apply_private_acl(temp.path(), true).unwrap();
        validate_private_acl(temp.path(), true).unwrap();
        let root = temp.path().join("paired-flush-cap");
        fs::create_dir_all(&root).unwrap();
        apply_private_acl(&root, true).unwrap();
        validate_private_acl(&root, true).unwrap();
        (temp, root)
    }

    #[test]
    fn after_original_guard_drop_paired_cap_still_blocks_root_rename() {
        let (_temp, root) = private_root();
        let relocated = root.parent().unwrap().join("paired-flush-cap-relocated");
        let guard = TrustedPathGuard::capture(&root).unwrap();
        let cap = open_flush_bound_to_guard(&guard).unwrap();
        // Drop original capture handles first; paired authority duplicate must
        // still deny rename until the capability itself drops.
        drop(guard);

        let err = fs::rename(&root, &relocated).expect_err(
            "rename must fail while paired authority duplicate is alive (CreateFileW share rules)",
        );
        assert_eq!(
            err.raw_os_error(),
            Some(32),
            "expected ERROR_SHARING_VIOLATION (32) while paired cap alive, got {err:?}"
        );
        assert!(root.is_dir());
        assert!(!relocated.exists());

        drop(cap);
        fs::rename(&root, &relocated).expect("rename must succeed after final paired-cap drop");
        assert!(relocated.is_dir());
    }

    #[test]
    fn paired_cap_flush_succeeds_while_authority_held() {
        let (_temp, root) = private_root();
        let guard = TrustedPathGuard::capture(&root).unwrap();
        let cap = open_flush_bound_to_guard(&guard).unwrap();
        drop(guard);
        cap.flush()
            .expect("derived flusher NtFlushBuffersFileEx(0)");
        let _identity = cap.identity();
        let _file: &std::fs::File = cap.file();
    }
}

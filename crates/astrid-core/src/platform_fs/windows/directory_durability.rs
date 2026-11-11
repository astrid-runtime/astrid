//! Native Windows NTFS directory-flush access check (test-only).
//!
//! [MS-FSA] 2.1.5.7 + <80>: `DirectoryFile` flush persists structure on NTFS only;
//! non-NTFS SUCCESS is a documented no-op and must fail closed before deletes.
//!
//! Opens are bound to the captured root by comparing full 128-bit `FileIdInfo`
//! identities (`query_directory_identity`) between the `TrustedPathGuard`
//! authority handle and the flush `File`. Handles are opened without
//! `FILE_FLAG_OVERLAPPED`, so `NtFlushBuffersFileEx(0)` is expected to complete
//! synchronously (`STATUS_PENDING` is rejected). Both the syscall NTSTATUS and
//! `IO_STATUS_BLOCK.Status` must be `0`.

use std::os::windows::io::BorrowedHandle;

use super::captured_directory::query_directory_identity;
use super::error::with_context;
use super::path::{OwnedHandle, TrustedPathGuard, wide_path};
use super::prelude::*;
use crate::platform_fs::DirectoryIdentity;
use windows_sys::Wdk::Storage::FileSystem::NtFlushBuffersFileEx;
use windows_sys::Win32::Foundation::{LUID, STATUS_PENDING};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE,
    ImpersonateLoggedOnUser, LUA_TOKEN, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    RevertToSelf, SE_MANAGE_VOLUME_NAME, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES,
    TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_IMPERSONATE, TOKEN_QUERY, TokenElevation,
    WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, GetVolumeInformationByHandleW,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

/// Directory write/append bits plus query rights for flush + volume identity.
const DIRECTORY_FLUSH_ACCESS: u32 =
    FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;

/// Observation printed by the native test (not a product API surface).
#[derive(Debug)]
pub(super) struct DirectoryFlushObservation {
    pub(super) filesystem: OsString,
    pub(super) desired_access: u32,
    pub(super) identity: DirectoryIdentity,
    pub(super) syscall_ntstatus: i32,
    pub(super) iosb_ntstatus: i32,
}

/// File-bound flush handle retained across a child delete in the native test.
pub(super) struct DirectoryFlushHandle {
    file: File,
}

impl DirectoryFlushHandle {
    /// Capture `path`, bind flush open to the guard's 128-bit identity, require
    /// NTFS, and prove synchronous `NtFlushBuffersFileEx(0)` before deletes.
    pub(super) fn open_verified(path: &Path) -> io::Result<(Self, DirectoryFlushObservation)> {
        let guard = TrustedPathGuard::capture(path).map_err(|error| {
            with_context(
                error,
                format!("capture directory flush root {}", path.display()),
            )
        })?;
        let expected = authority_directory_identity(&guard)?;
        let handle = open_directory_flush_handle(path, DIRECTORY_FLUSH_ACCESS)?;
        let file = into_std_file(handle);
        let actual = query_directory_identity(&file).map_err(|error| {
            with_context(
                error,
                format!("query flush-handle FileIdInfo {}", path.display()),
            )
        })?;
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "directory flush handle FileIdInfo diverged from TrustedPathGuard authority for {}",
                    path.display()
                ),
            ));
        }
        // Authority pin held through identity compare; path open is now bound.
        drop(guard);

        let filesystem = volume_filesystem_name(&file)?;
        if !filesystem_is_ntfs(&filesystem) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "directory-structure flush requires NTFS (MS-FSA <80>); volume reports {}",
                    filesystem.to_string_lossy()
                ),
            ));
        }
        let (syscall_ntstatus, iosb_ntstatus) = flush_directory_file_statuses(&file)?;
        Ok((
            Self { file },
            DirectoryFlushObservation {
                filesystem,
                desired_access: DIRECTORY_FLUSH_ACCESS,
                identity: actual,
                syscall_ntstatus,
                iosb_ntstatus,
            },
        ))
    }

    /// Persist directory structure after a child delete on this same handle.
    pub(super) fn flush_after_delete(&self) -> io::Result<()> {
        flush_directory_file_statuses(&self.file).map(|_| ())
    }
}

fn flush_directory_file_statuses(file: &File) -> io::Result<(i32, i32)> {
    let mut iosb = IO_STATUS_BLOCK::default();
    // SAFETY: non-overlapped directory File; Parameters unused (NULL/0);
    // `iosb` remains live for the call.
    let status = unsafe {
        NtFlushBuffersFileEx(
            file.as_raw_handle().cast(),
            0,
            null(),
            0,
            &raw mut iosb,
        )
    };
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
    Ok((status, iosb_status))
}

fn authority_directory_identity(guard: &TrustedPathGuard) -> io::Result<DirectoryIdentity> {
    // SAFETY: authority handle remains owned by `guard` for the borrow.
    let borrowed = unsafe { BorrowedHandle::borrow_raw(guard.authority_handle().cast()) };
    let file = borrowed.try_clone_to_owned().map(File::from).map_err(|error| {
        with_context(error, "duplicate TrustedPathGuard authority for FileIdInfo")
    })?;
    query_directory_identity(&file)
        .map_err(|error| with_context(error, "query TrustedPathGuard authority FileIdInfo"))
}

fn open_directory_flush_handle(path: &Path, desired_access: u32) -> io::Result<OwnedHandle> {
    let wide = wide_path(path)?;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    // SAFETY: NUL-terminated path; no OVERLAPPED flag — synchronous I/O.
    // OPEN_REPARSE_POINT opens the object itself; attributes reject redirects.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            desired_access,
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
            format!("open directory flush handle {}", path.display()),
        ));
    }
    let handle = OwnedHandle(handle);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: handle and output buffer are live.
    if unsafe { GetFileInformationByHandle(handle.0, &raw mut info) } == 0 {
        return Err(with_context(
            io::Error::last_os_error(),
            format!("query directory flush handle {}", path.display()),
        ));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "directory flush target is redirected or not a directory: {}",
                path.display()
            ),
        ));
    }
    Ok(handle)
}

fn volume_filesystem_name(file: &File) -> io::Result<OsString> {
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

fn into_std_file(handle: OwnedHandle) -> File {
    let raw = handle.0;
    std::mem::forget(handle);
    // SAFETY: ownership transfers from OwnedHandle exactly once.
    unsafe { File::from_raw_handle(raw.cast()) }
}

/// Current-thread ordinary-user authority for the native flush fixture.
///
/// If the process token is elevated (common on hosted GHA Windows runners),
/// builds a restricted token with `LUA_TOKEN`, disables the Administrators SID,
/// deletes `SeManageVolumePrivilege`, impersonates it, and proves the effective
/// token is non-admin. Reverts on drop. Never skips; never changes the process
/// primary token.
pub(super) struct OrdinaryUserImpersonation {
    _restricted: Option<OwnedHandle>,
    active: bool,
}

impl OrdinaryUserImpersonation {
    /// Enter ordinary-user authority on this thread, or prove it already holds.
    pub(super) fn enter() -> io::Result<Self> {
        if !process_token_is_elevated()? {
            prove_effective_token_is_ordinary()?;
            return Ok(Self {
                _restricted: None,
                active: false,
            });
        }

        let restricted = create_restricted_ordinary_token()?;
        // SAFETY: restricted token remains owned by `restricted`.
        if unsafe { ImpersonateLoggedOnUser(restricted.0) } == 0 {
            return Err(with_context(
                io::Error::last_os_error(),
                "ImpersonateLoggedOnUser(restricted ordinary-user token)",
            ));
        }
        let mut impersonation = Self {
            _restricted: Some(restricted),
            active: true,
        };
        if let Err(error) = prove_effective_token_is_ordinary() {
            let _ = impersonation.revert();
            return Err(error);
        }
        Ok(impersonation)
    }

    fn revert(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        // SAFETY: paired with ImpersonateLoggedOnUser on this thread.
        if unsafe { RevertToSelf() } == 0 {
            return Err(with_context(
                io::Error::last_os_error(),
                "RevertToSelf after ordinary-user impersonation",
            ));
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for OrdinaryUserImpersonation {
    fn drop(&mut self) {
        if self.active && self.revert().is_err() {
            // Leaving a worker thread under a restricted token would corrupt
            // later tests; abort matches local_transport impersonation posture.
            std::process::abort();
        }
    }
}


fn create_restricted_ordinary_token() -> io::Result<OwnedHandle> {
    let mut process_token = null_mut();
    // SAFETY: out handle transferred into OwnedHandle on success.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE,
            &raw mut process_token,
        )
    } == 0
    {
        return Err(with_context(
            io::Error::last_os_error(),
            "OpenProcessToken for restricted ordinary-user token",
        ));
    }
    let process_token = OwnedHandle(process_token);

    let mut admin_bytes = [0_u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(size_of::<u32>())];
    let mut admin_len = SECURITY_MAX_SID_SIZE;
    // SAFETY: well-known Administrators SID written into stack buffer.
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            null_mut(),
            admin_bytes.as_mut_ptr().cast(),
            &raw mut admin_len,
        )
    } == 0
    {
        return Err(with_context(
            io::Error::last_os_error(),
            "CreateWellKnownSid(WinBuiltinAdministratorsSid)",
        ));
    }
    let disable_sid = SID_AND_ATTRIBUTES {
        Sid: admin_bytes.as_mut_ptr().cast(),
        Attributes: 0,
    };

    let mut manage_volume = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: SE_MANAGE_VOLUME_NAME is a static wide string; LUID out is live.
    if unsafe { LookupPrivilegeValueW(null(), SE_MANAGE_VOLUME_NAME, &raw mut manage_volume) } == 0
    {
        return Err(with_context(
            io::Error::last_os_error(),
            "LookupPrivilegeValueW(SeManageVolumePrivilege)",
        ));
    }
    let delete_privilege = LUID_AND_ATTRIBUTES {
        Luid: manage_volume,
        Attributes: 0,
    };

    let mut restricted = null_mut();
    // SAFETY: source token live; disable/delete arrays live for the call.
    if unsafe {
        CreateRestrictedToken(
            process_token.0,
            LUA_TOKEN | DISABLE_MAX_PRIVILEGE,
            1,
            &raw const disable_sid,
            1,
            &raw const delete_privilege,
            0,
            null(),
            &raw mut restricted,
        )
    } == 0
    {
        return Err(with_context(
            io::Error::last_os_error(),
            "CreateRestrictedToken(LUA_TOKEN|DISABLE_MAX_PRIVILEGE, deny Administrators, delete SeManageVolume)",
        ));
    }
    Ok(OwnedHandle(restricted))
}

fn process_token_is_elevated() -> io::Result<bool> {
    let mut token = null_mut();
    // SAFETY: out handle owned below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(with_context(
            io::Error::last_os_error(),
            "OpenProcessToken(TOKEN_QUERY) for elevation",
        ));
    }
    let token = OwnedHandle(token);
    token_is_elevated(token.0)
}

fn token_is_elevated(token: HANDLE) -> io::Result<bool> {
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    // SAFETY: token live; elevation out live.
    if unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            u32::try_from(size_of::<TOKEN_ELEVATION>()).expect("TOKEN_ELEVATION fits u32"),
            &raw mut returned,
        )
    } == 0
    {
        return Err(with_context(
            io::Error::last_os_error(),
            "GetTokenInformation(TokenElevation)",
        ));
    }
    Ok(elevation.TokenIsElevated != 0)
}

fn prove_effective_token_is_ordinary() -> io::Result<()> {
    let mut token = null_mut();
    // Prefer the impersonation token when present; else the process token.
    // SAFETY: GetCurrentThread handle is pseudo-handle; OpenAsSelf=false uses
    // the thread's impersonation token when active.
    let opened = unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY,
            0,
            &raw mut token,
        )
    };
    let token = if opened == 0 {
        let mut process_token = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut process_token) }
            == 0
        {
            return Err(with_context(
                io::Error::last_os_error(),
                "OpenProcessToken while proving ordinary-user authority",
            ));
        }
        OwnedHandle(process_token)
    } else {
        OwnedHandle(token)
    };

    if token_is_elevated(token.0)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "effective token is still elevated after ordinary-user preparation",
        ));
    }

    let mut admin_bytes = [0_u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(size_of::<u32>())];
    let mut admin_len = SECURITY_MAX_SID_SIZE;
    // SAFETY: Administrators SID buffer live for CreateWellKnownSid.
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            null_mut(),
            admin_bytes.as_mut_ptr().cast(),
            &raw mut admin_len,
        )
    } == 0
    {
        return Err(with_context(
            io::Error::last_os_error(),
            "CreateWellKnownSid while proving ordinary-user authority",
        ));
    }
    let mut is_member = 0i32;
    // SAFETY: NULL tokenhandle => effective thread token; SID buffer live.
    if unsafe {
        CheckTokenMembership(
            null_mut(),
            admin_bytes.as_mut_ptr().cast(),
            &raw mut is_member,
        )
    } == 0
    {
        return Err(with_context(
            io::Error::last_os_error(),
            "CheckTokenMembership(Administrators) while proving ordinary-user authority",
        ));
    }
    if is_member != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "effective token still contains enabled Administrators SID",
        ));
    }
    Ok(())
}

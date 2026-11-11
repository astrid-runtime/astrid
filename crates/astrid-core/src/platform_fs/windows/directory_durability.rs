//! Native Windows NTFS directory-flush access fixture (test-only).
//!
//! Demoted onto the production shared module
//! `super::ntfs_directory_flush`: one FileId+NTFS flush-capable open and one
//! shared flush protocol ([MS-FSA] 2.1.5.7 + <80>). This file keeps
//! only the ordinary-user token fixture, authority-relative child delete under a
//! retained `TrustedPathGuard`, and native diagnostic printing after checked
//! shared-production success.
//!
//! Raw syscall/IOSB NTSTATUS values are not synthesized here — the shared helper
//! returns `io::Result` only. Diagnostics report `shared_production_flush=PASS`
//! after a successful `NtfsDirectoryFlushGuard::flush`, plus the shared
//! `DIRECTORY_FLUSH_ACCESS` constant and the bound identity.

use super::error::with_context;
use super::io::remove_guarded_file;
use super::ntfs_directory_flush::{
    DIRECTORY_FLUSH_ACCESS, NtfsDirectoryFlushGuard, open_flush_bound_to_guard,
};
use super::path::{OwnedHandle, TrustedPathGuard};
use super::prelude::*;
use crate::platform_fs::DirectoryIdentity;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_NO_TOKEN, LUID};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE,
    ImpersonateLoggedOnUser, LUA_TOKEN, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, RevertToSelf,
    SE_MANAGE_VOLUME_NAME, SE_PRIVILEGE_ENABLED, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES,
    TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TokenElevation, TokenPrivileges, WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

/// Observation printed by the native test (not a product API surface).
///
/// Does not invent NTSTATUS codes. `shared_production_flush` is set only after
/// the shared opener+flush path returned `Ok`.
#[derive(Debug)]
pub(super) struct DirectoryFlushObservation {
    pub(super) desired_access: u32,
    pub(super) identity: DirectoryIdentity,
    pub(super) shared_production_flush: bool,
}

/// File-bound flush handle retained across a child delete in the native test.
///
/// Retains the authority [`TrustedPathGuard`] for handle-relative child deletion
/// and the shared [`NtfsDirectoryFlushGuard`] for post-delete flush so mutation
/// stays bound to the captured root identity.
pub(super) struct DirectoryFlushHandle {
    guard: TrustedPathGuard,
    flush: NtfsDirectoryFlushGuard,
}

impl DirectoryFlushHandle {
    /// Capture `path`, open via shared FileId+NTFS flush opener, and prove a
    /// successful shared-production flush before deletes.
    pub(super) fn open_verified(path: &Path) -> io::Result<(Self, DirectoryFlushObservation)> {
        let guard = TrustedPathGuard::capture(path).map_err(|error| {
            with_context(
                error,
                format!("capture directory flush root {}", path.display()),
            )
        })?;
        let flush = open_flush_bound_to_guard(&guard)?;
        // Pre-delete durability proof through the exact production helper.
        flush.flush()?;
        let observation = DirectoryFlushObservation {
            desired_access: DIRECTORY_FLUSH_ACCESS,
            identity: flush.identity(),
            shared_production_flush: true,
        };
        Ok((Self { guard, flush }, observation))
    }

    /// Delete a direct child under the retained authority guard (handle-relative).
    pub(super) fn remove_child_file(&self, path: &Path) -> io::Result<()> {
        remove_guarded_file(&self.guard, path)
    }

    /// Persist directory structure after a child delete via the shared production flush.
    pub(super) fn flush_after_delete(&self) -> io::Result<()> {
        self.flush.flush()
    }
}

/// Current-thread ordinary-user authority for the native flush fixture.
///
/// If the process token is elevated (common on hosted GHA Windows runners),
/// builds a restricted token with `LUA_TOKEN` + `DISABLE_MAX_PRIVILEGE`,
/// disables the Administrators SID, impersonates it, and proves the effective
/// token is non-admin with `SeManageVolumePrivilege` absent or not enabled.
/// Reverts on drop. Never skips; never changes the process primary token.
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

    let mut restricted = null_mut();
    // SAFETY: source token live; disable-SID array live for the call.
    // `DISABLE_MAX_PRIVILEGE` disables privileges (including SeManageVolume);
    // DeletePrivilegeCount/PrivilegesToDelete are ignored with that flag and
    // must not be supplied as if they performed a literal privilege deletion.
    if unsafe {
        CreateRestrictedToken(
            process_token.0,
            LUA_TOKEN | DISABLE_MAX_PRIVILEGE,
            1,
            &raw const disable_sid,
            0,
            null(),
            0,
            null(),
            &raw mut restricted,
        )
    } == 0
    {
        return Err(with_context(
            io::Error::last_os_error(),
            "CreateRestrictedToken(LUA_TOKEN|DISABLE_MAX_PRIVILEGE, deny Administrators)",
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

/// Prefer the thread impersonation token; fall back to the process token only
/// when `OpenThreadToken` fails with `ERROR_NO_TOKEN`. Any other thread-token
/// error fails closed and preserves the original error (no process fallback).
pub(super) fn select_effective_query_token<T>(
    open_thread_token: impl FnOnce() -> io::Result<T>,
    open_process_token: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    match open_thread_token() {
        Ok(token) => Ok(token),
        Err(error) if error.raw_os_error() == Some(ERROR_NO_TOKEN.cast_signed()) => {
            open_process_token()
        },
        Err(error) => Err(error),
    }
}

fn open_thread_query_token() -> io::Result<OwnedHandle> {
    let mut token = null_mut();
    // SAFETY: GetCurrentThread handle is a pseudo-handle; OpenAsSelf=false uses
    // the thread's impersonation token when active.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &raw mut token) };
    if opened == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedHandle(token))
}

fn open_process_query_token() -> io::Result<OwnedHandle> {
    let mut process_token = null_mut();
    // SAFETY: out handle owned by caller on success.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut process_token) } == 0 {
        return Err(with_context(
            io::Error::last_os_error(),
            "OpenProcessToken while proving ordinary-user authority",
        ));
    }
    Ok(OwnedHandle(process_token))
}

fn prove_effective_token_is_ordinary() -> io::Result<()> {
    let token = select_effective_query_token(open_thread_query_token, open_process_query_token)?;

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

    prove_se_manage_volume_disabled_or_absent(token.0)
}

fn prove_se_manage_volume_disabled_or_absent(token: HANDLE) -> io::Result<()> {
    let manage_volume = lookup_se_manage_volume_luid()?;
    let (buffer, returned_len) = read_token_privileges_buffer(token)?;
    assert_se_manage_volume_absent_or_disabled(&buffer, returned_len, manage_volume)
}

fn lookup_se_manage_volume_luid() -> io::Result<LUID> {
    let mut manage_volume = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: SE_MANAGE_VOLUME_NAME is a static wide string; LUID out is live.
    if unsafe { LookupPrivilegeValueW(null(), SE_MANAGE_VOLUME_NAME, &raw mut manage_volume) } == 0
    {
        return Err(with_context(
            io::Error::last_os_error(),
            "LookupPrivilegeValueW(SeManageVolumePrivilege) while proving ordinary-user authority",
        ));
    }
    Ok(manage_volume)
}

fn read_token_privileges_buffer(token: HANDLE) -> io::Result<(Vec<usize>, usize)> {
    let mut required = 0u32;
    // SAFETY: null/zero size query is the documented TokenPrivileges sizing call.
    let sized =
        unsafe { GetTokenInformation(token, TokenPrivileges, null_mut(), 0, &raw mut required) };
    if sized != 0 || required == 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(with_context(
            io::Error::last_os_error(),
            "GetTokenInformation(TokenPrivileges) size query while proving ordinary-user authority",
        ));
    }

    let byte_length = usize::try_from(required).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TokenPrivileges length overflow while proving ordinary-user authority",
        )
    })?;
    if byte_length < size_of::<u32>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TokenPrivileges buffer smaller than PrivilegeCount header",
        ));
    }

    let word_length = byte_length.div_ceil(size_of::<usize>());
    let mut buffer = vec![0_usize; word_length];
    let mut returned = 0u32;
    // SAFETY: `buffer` is usize-aligned and provides at least `required` bytes.
    if unsafe {
        GetTokenInformation(
            token,
            TokenPrivileges,
            buffer.as_mut_ptr().cast::<c_void>(),
            required,
            &raw mut returned,
        )
    } == 0
    {
        return Err(with_context(
            io::Error::last_os_error(),
            "GetTokenInformation(TokenPrivileges) while proving ordinary-user authority",
        ));
    }
    let returned_len = usize::try_from(returned).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TokenPrivileges returned length overflow",
        )
    })?;
    if returned_len < size_of::<u32>() || returned_len > byte_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "TokenPrivileges returned length {returned_len} outside allocated buffer {byte_length}"
            ),
        ));
    }
    Ok((buffer, returned_len))
}

fn assert_se_manage_volume_absent_or_disabled(
    buffer: &[usize],
    returned_len: usize,
    manage_volume: LUID,
) -> io::Result<()> {
    let privilege_header = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    // SAFETY: GetTokenInformation wrote a TOKEN_PRIVILEGES header into the
    // aligned buffer; PrivilegeCount is the leading u32.
    let privilege_count = unsafe { buffer.as_ptr().cast::<u32>().read() };
    let privilege_count_usize = usize::try_from(privilege_count).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TokenPrivileges PrivilegeCount overflow",
        )
    })?;
    let entry_size = size_of::<LUID_AND_ATTRIBUTES>();
    let privileges_bytes = privilege_count_usize
        .checked_mul(entry_size)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "TokenPrivileges privilege array byte-length overflow",
            )
        })?;
    let needed = privilege_header
        .checked_add(privileges_bytes)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "TokenPrivileges total byte-length overflow",
            )
        })?;
    if needed > returned_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "TokenPrivileges PrivilegeCount {privilege_count} exceeds returned buffer ({needed} > {returned_len})"
            ),
        ));
    }

    for index in 0..privilege_count_usize {
        let offset = privilege_header.strict_add(index.strict_mul(entry_size));
        // SAFETY: offset was bounds-checked against returned_len; entries are
        // 4-byte aligned LUID_AND_ATTRIBUTES values inside the owned buffer.
        let entry = unsafe {
            buffer
                .as_ptr()
                .byte_add(offset)
                .cast::<LUID_AND_ATTRIBUTES>()
                .read()
        };
        if entry.Luid.LowPart == manage_volume.LowPart
            && entry.Luid.HighPart == manage_volume.HighPart
        {
            if entry.Attributes & SE_PRIVILEGE_ENABLED != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "effective token still has SeManageVolumePrivilege enabled",
                ));
            }
            // Present but disabled is acceptable under DISABLE_MAX_PRIVILEGE.
            return Ok(());
        }
    }
    // Absent from the effective privilege set is also acceptable.
    Ok(())
}

#[cfg(test)]
mod select_effective_query_token_tests {
    use super::{ERROR_ACCESS_DENIED, ERROR_NO_TOKEN, select_effective_query_token};
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn open_thread_token_access_denied_does_not_fall_back_to_process_token() {
        let process_called = AtomicBool::new(false);
        let error = select_effective_query_token::<()>(
            || {
                Err(io::Error::from_raw_os_error(
                    ERROR_ACCESS_DENIED.cast_signed(),
                ))
            },
            || {
                process_called.store(true, Ordering::SeqCst);
                Err(io::Error::other("process token fallback must not run"))
            },
        )
        .expect_err("OpenThreadToken ACCESS_DENIED must fail closed");
        assert!(
            !process_called.load(Ordering::SeqCst),
            "OpenProcessToken fallback must not run on OpenThreadToken ACCESS_DENIED"
        );
        assert_eq!(
            error.raw_os_error(),
            Some(ERROR_ACCESS_DENIED.cast_signed())
        );
    }

    #[test]
    fn open_thread_token_no_token_uses_process_fallback() {
        let process_called = AtomicBool::new(false);
        let value = select_effective_query_token(
            || Err(io::Error::from_raw_os_error(ERROR_NO_TOKEN.cast_signed())),
            || {
                process_called.store(true, Ordering::SeqCst);
                Ok(0xA11Cu32)
            },
        )
        .expect("ERROR_NO_TOKEN must use process fallback");
        assert!(process_called.load(Ordering::SeqCst));
        assert_eq!(value, 0xA11C);
    }
}

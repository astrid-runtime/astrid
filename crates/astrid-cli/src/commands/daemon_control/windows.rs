//! Windows process identity and termination primitives.
//!
//! Process IDs are untrusted persisted state. Every destructive operation opens
//! a fresh kernel handle, and the caller rechecks the executable identity before
//! reaching [`terminate_verified_process`].

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::ptr::null;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, QueryFullProcessImageNameW,
    TerminateProcess, WaitForSingleObject,
};

const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const TERMINATE_EXIT_CODE: u32 = 1;
const MAX_LONG_PATH_UTF16: usize = 32_767;

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn open(pid: u32, access: u32) -> Option<Self> {
        if pid == 0 {
            return None;
        }
        // SAFETY: `OpenProcess` receives a non-zero scalar PID and access mask.
        // The returned handle is either null or owned and closed by `Drop`.
        let handle = unsafe { OpenProcess(access, 0, pid) };
        (!handle.is_null()).then_some(Self(handle))
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper is constructed only from a successful
        // `OpenProcess`, owns the handle, and closes it exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

pub(super) fn is_process_alive(pid: u32) -> bool {
    !is_process_confirmed_gone(pid)
}

pub(super) fn is_process_confirmed_gone(pid: u32) -> bool {
    if pid == 0 {
        return true;
    }
    let Some(handle) = OwnedHandle::open(pid, SYNCHRONIZE_ACCESS) else {
        // Only INVALID_PARAMETER proves that no process has this PID. Access
        // denied proves existence, and every unexpected error stays fail-closed.
        return std::io::Error::last_os_error()
            .raw_os_error()
            .is_some_and(|code| u32::try_from(code).ok() == Some(ERROR_INVALID_PARAMETER));
    };
    // SAFETY: `handle` remains valid for the duration of this zero-timeout wait.
    unsafe { WaitForSingleObject(handle.0, 0) == WAIT_OBJECT_0 }
}

pub(super) fn exe_path_of_pid(pid: u32) -> Option<PathBuf> {
    let handle = OwnedHandle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    exe_path_from_handle(&handle)
}

fn exe_path_from_handle(handle: &OwnedHandle) -> Option<PathBuf> {
    let mut buffer = vec![0_u16; MAX_LONG_PATH_UTF16];
    let mut length = u32::try_from(buffer.len()).ok()?;
    // SAFETY: `buffer` is writable for `length` UTF-16 elements, the length
    // pointer is valid, and `handle` has query-limited-information access.
    let ok =
        unsafe { QueryFullProcessImageNameW(handle.0, 0, buffer.as_mut_ptr(), &raw mut length) };
    if ok == 0 {
        return None;
    }
    let length = usize::try_from(length).ok()?;
    buffer.truncate(length);
    Some(PathBuf::from(OsString::from_wide(&buffer)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VerifiedTermination {
    NotRunning,
    Unverified,
    Exited,
    StillAlive,
}

pub(super) fn terminate_verified_process(
    pid: u32,
    recorded_exe: &Path,
    budget: std::time::Duration,
) -> VerifiedTermination {
    let Some(handle) = OwnedHandle::open(
        pid,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE_ACCESS,
    ) else {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(code) if u32::try_from(code).ok() == Some(ERROR_INVALID_PARAMETER) => {
                VerifiedTermination::NotRunning
            },
            _ => VerifiedTermination::Unverified,
        };
    };
    let Some(live_exe) = exe_path_from_handle(&handle) else {
        return VerifiedTermination::Unverified;
    };
    if !paths_equal(recorded_exe, &live_exe)
        && !std::fs::canonicalize(&live_exe)
            .is_ok_and(|canonical| paths_equal(recorded_exe, &canonical))
    {
        return VerifiedTermination::Unverified;
    }

    // SAFETY: the same handle used to query and verify the executable is live
    // and carries PROCESS_TERMINATE. Holding it closes the PID-reuse gap.
    if unsafe { TerminateProcess(handle.0, TERMINATE_EXIT_CODE) } == 0 {
        return match unsafe { WaitForSingleObject(handle.0, 0) } {
            WAIT_OBJECT_0 => VerifiedTermination::Exited,
            _ => VerifiedTermination::StillAlive,
        };
    }
    let millis = u32::try_from(budget.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: the owned handle stays live throughout the bounded wait.
    match unsafe { WaitForSingleObject(handle.0, millis) } {
        WAIT_OBJECT_0 => VerifiedTermination::Exited,
        _ => VerifiedTermination::StillAlive,
    }
}

pub(super) fn paths_equal(left: &Path, right: &Path) -> bool {
    let left = left.as_os_str().encode_wide().collect::<Vec<_>>();
    let right = right.as_os_str().encode_wide().collect::<Vec<_>>();
    let (Ok(left_len), Ok(right_len)) = (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return false;
    };
    let left_ptr = left.first().map_or(null(), std::ptr::from_ref);
    let right_ptr = right.first().map_or(null(), std::ptr::from_ref);
    // SAFETY: both pointers address their corresponding immutable UTF-16
    // buffers for exactly the supplied lengths. Empty paths use a null pointer
    // with a zero count, which the API permits.
    unsafe { CompareStringOrdinal(left_ptr, left_len, right_ptr, right_len, 1) == CSTR_EQUAL }
}

#[cfg(test)]
mod tests {
    use super::{exe_path_of_pid, is_process_alive, paths_equal};

    #[test]
    fn current_process_is_live_and_has_an_executable() {
        let pid = std::process::id();
        assert!(is_process_alive(pid));
        assert!(exe_path_of_pid(pid).is_some_and(|path| path.is_file()));
    }

    #[test]
    fn windows_path_identity_is_case_insensitive() {
        assert!(paths_equal(
            std::path::Path::new(r"C:\Users\Astrid\astrid-daemon.exe"),
            std::path::Path::new(r"c:\users\astrid\ASTRID-DAEMON.EXE"),
        ));
        assert!(!paths_equal(
            std::path::Path::new(r"C:\Astrid\astrid-daemon.exe"),
            std::path::Path::new(r"C:\Other\astrid-daemon.exe"),
        ));
    }

    #[tokio::test]
    async fn verified_child_can_be_terminated_and_confirmed_exited() {
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "ping -n 30 127.0.0.1 >NUL"])
            .spawn()
            .unwrap();
        let pid = child.id();
        let executable = (0..50)
            .find_map(|_| {
                let path = exe_path_of_pid(pid);
                if path.is_none() {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                path
            })
            .expect("child executable is queryable");

        assert_eq!(
            super::super::terminate_known(pid, Some(&executable)).await,
            super::super::KillOutcome::KilledExited
        );
        assert!(child.wait().unwrap().code().is_some());
        assert!(!is_process_alive(pid));
    }
}

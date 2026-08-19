//! Parent-process creation identity used to bind provider lifetime to the
//! exact kernel process instance rather than a reusable PID.

// Windows has no safe standard-library API for querying another process's
// creation time. The narrowly-scoped implementation below uses the Win32
// handles only to read that immutable identity and closes every handle before
// returning; the rest of the kernel remains `#![deny(unsafe_code)]`.
#![cfg_attr(windows, allow(unsafe_code))]

#[cfg(target_os = "linux")]
pub(super) fn parent_start_identity(pid: u32) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = text.rsplit_once(") ")?;
    rest.split_whitespace()
        .nth(19)?
        .parse::<u64>()
        .ok()
        .map(|value| value.to_string())
}

#[cfg(target_os = "macos")]
pub(super) fn parent_start_identity(pid: u32) -> Option<String> {
    use libproc::libproc::bsd_info::BSDInfo;
    use libproc::libproc::proc_pid::pidinfo;

    let info = pidinfo::<BSDInfo>(i32::try_from(pid).ok()?, 0).ok()?;
    Some(format!(
        "{}:{}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    ))
}

#[cfg(windows)]
pub(super) fn parent_start_identity(pid: u32) -> Option<String> {
    use std::mem::MaybeUninit;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut creation = MaybeUninit::<FILETIME>::uninit();
    let mut exit = MaybeUninit::<FILETIME>::uninit();
    let mut kernel = MaybeUninit::<FILETIME>::uninit();
    let mut user = MaybeUninit::<FILETIME>::uninit();
    let ok = unsafe {
        GetProcessTimes(
            handle,
            creation.as_mut_ptr(),
            exit.as_mut_ptr(),
            kernel.as_mut_ptr(),
            user.as_mut_ptr(),
        ) != 0
    };
    unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
    if !ok {
        return None;
    }
    let creation = unsafe { creation.assume_init() };
    Some((u64::from(creation.dwHighDateTime) << 32 | u64::from(creation.dwLowDateTime)).to_string())
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
pub(super) fn parent_start_identity(_pid: u32) -> Option<String> {
    None
}

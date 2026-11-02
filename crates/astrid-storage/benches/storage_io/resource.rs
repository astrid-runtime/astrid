//! Current process resident-set sampling for recovery attribution.
//!
//! These values are the live resident set, not `ru_maxrss` and not a
//! decomposition of maps, cache charge, or allocator slack. Unsupported
//! platforms return `Ok(None)` so callers omit RSS peaks instead of
//! recording a fake zero.

use std::io::{self, ErrorKind};

/// Current resident-set size in bytes for this process.
///
/// `Ok(None)` means this platform has no current-RSS sampler. Callers must
/// omit RSS peaks rather than store zero.
pub(super) fn process_resident_bytes() -> io::Result<Option<u64>> {
    core::cfg_select! {
        target_os = "macos" => macos_resident_bytes().map(Some),
        target_os = "linux" => linux_resident_bytes().map(Some),
        _ => Ok(None),
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn macos_resident_bytes() -> io::Result<u64> {
    let pid = libc::pid_t::try_from(std::process::id())
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "process id exceeds pid_t"))?;
    let mut info = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
    // SAFETY: `info` is a writable `rusage_info_v2` for this process only.
    // Darwin `proc_pid_rusage(pid, RUSAGE_INFO_V2, buffer)` writes that
    // struct through the `rusage_info_t*` alias when the return is zero.
    // We read `ri_resident_size` only after that success path, matching
    // the owned `proc_pid_rusage(RUSAGE_INFO_V2)` RSS samples.
    let resident = unsafe {
        let result = libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V2, info.as_mut_ptr().cast());
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        info.assume_init().ri_resident_size
    };
    Ok(resident)
}

#[cfg(target_os = "linux")]
fn linux_resident_bytes() -> io::Result<u64> {
    linux::parse_linux_vm_rss_bytes(&std::fs::read_to_string("/proc/self/status")?)
}

#[cfg(target_os = "linux")]
#[path = "resource/linux.rs"]
mod linux;

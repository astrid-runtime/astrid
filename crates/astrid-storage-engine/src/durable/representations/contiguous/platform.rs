//! Whole-file copy-on-write clone primitives for loose-blob adoption.

use std::path::Path;

#[cfg(target_os = "macos")]
pub(super) fn clone_file_no_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let source = CString::new(source.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "clone source has NUL")
    })?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "clone destination has NUL",
        )
    })?;
    // SAFETY: both C strings are NUL-terminated and outlive the call. The
    // destination does not exist, and clonefile retains neither pointer.
    #[allow(unsafe_code)]
    let result = unsafe { libc::clonefile(source.as_ptr(), destination.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
pub(super) fn clone_file_no_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::fs::{File, OpenOptions};
    use std::os::fd::AsRawFd as _;

    const FICLONE: libc::c_ulong = 0x4004_9409;
    let source = File::open(source)?;
    let destination_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    // SAFETY: both descriptors remain valid for the call; FICLONE copies no
    // user pointers and retains neither descriptor.
    #[allow(unsafe_code)]
    let result = unsafe { libc::ioctl(destination_file.as_raw_fd(), FICLONE, source.as_raw_fd()) };
    if result == 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        drop(destination_file);
        let _ = std::fs::remove_file(destination);
        Err(error)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn clone_file_no_replace(_source: &Path, _destination: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "copy-on-write file cloning is unavailable",
    ))
}

pub(super) fn clone_is_unsupported(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::Unsupported
        || matches!(
            error.raw_os_error(),
            Some(libc::ENOTSUP | libc::EXDEV | libc::EINVAL)
        )
}

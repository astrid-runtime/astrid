//! Whole-file copy-on-write clone primitives for loose-blob adoption.

use std::fs::File;
use std::path::Path;

#[cfg(unix)]
pub(super) fn open_regular_read(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "path is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
pub(super) fn open_regular_read(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "path is redirected or not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
pub(super) fn open_regular_read(path: &Path) -> std::io::Result<File> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "path is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(target_os = "macos")]
pub(super) fn clone_file_no_replace(source: &File, destination: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "clone destination has NUL",
        )
    })?;
    // SAFETY: the source descriptor and destination C string remain valid for
    // the call. The destination does not exist and the call retains neither.
    #[allow(unsafe_code)]
    let result =
        unsafe { libc::fclonefileat(source.as_raw_fd(), libc::AT_FDCWD, destination.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
pub(super) fn clone_file_no_replace(source: &File, destination: &Path) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd as _;

    const FICLONE: libc::c_ulong = 0x4004_9409;
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
pub(super) fn clone_file_no_replace(_source: &File, _destination: &Path) -> std::io::Result<()> {
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

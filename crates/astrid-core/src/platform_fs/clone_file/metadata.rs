//! Only data blocks from a disposable source may reach a private projection.
#![allow(unsafe_code)]

use std::fs::{File, OpenOptions, Permissions};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::macos::fs::MetadataExt as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

pub(super) fn eligible(source: &File) -> io::Result<bool> {
    if source.metadata()?.st_flags() != 0 {
        return Ok(false);
    }
    // SAFETY: querying the required size writes no buffer and borrows an open
    // descriptor. No source pathname is resolved again.
    let count = unsafe { nix::libc::flistxattr(source.as_raw_fd(), std::ptr::null_mut(), 0, 0) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(count == 0)
}

pub(super) fn prepare(destination: &Path) -> io::Result<bool> {
    let result = (|| {
        let metadata = std::fs::symlink_metadata(destination)?;
        if !metadata.is_file() || metadata.st_flags() != 0 {
            return Ok(false);
        }
        // A source's read-only or executable mode is not target authority.
        std::fs::set_permissions(destination, Permissions::from_mode(0o600))?;
        let opened = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
            .open(destination)?;
        // Recheck the captured clone: source attributes can change after the
        // preflight. Its private inode is independent after the clone syscall.
        eligible(&opened)
    })();
    if !matches!(result, Ok(true)) {
        discard(destination)?;
    }
    result
}

fn discard(destination: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    if std::fs::symlink_metadata(destination)?.st_flags() != 0 {
        let path = CString::new(destination.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "clone path contains NUL"))?;
        // SAFETY: a live NUL-terminated path names our newly created private
        // clone. lchflags does not follow a redirected final component.
        if unsafe { lchflags(path.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    std::fs::remove_file(destination)
}

// macOS sys/stat.h; libc does not currently expose this no-follow variant.
unsafe extern "C" {
    fn lchflags(path: *const nix::libc::c_char, flags: u32) -> nix::libc::c_int;
}

#[cfg(test)]
mod tests;

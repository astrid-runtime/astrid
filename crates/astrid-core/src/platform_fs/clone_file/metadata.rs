//! Reject side data and compare OS provenance with a fresh private local file.
#![allow(unsafe_code)]

use std::fs::{File, OpenOptions, Permissions};
use std::io;
use std::os::macos::fs::MetadataExt as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
mod attributes;

pub(super) fn eligible(source: &File) -> io::Result<bool> {
    if source.metadata()?.st_flags() != 0 {
        return Ok(false);
    }
    attributes::permitted_names(source)
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
        Ok(eligible(&opened)?
            && attributes::matches_local(
                &opened,
                destination
                    .parent()
                    .ok_or_else(|| io::Error::other("clone destination has no parent"))?,
            )?)
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

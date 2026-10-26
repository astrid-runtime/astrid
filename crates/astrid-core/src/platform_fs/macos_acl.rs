//! Inspect and remove extended ACLs on the already captured filesystem object.
#![allow(unsafe_code)]

use nix::libc::{c_int, c_void};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;
use std::ptr::NonNull;

// Darwin sys/acl.h ABI values, not operator policy or tunable limits.
const ACL_TYPE_EXTENDED: c_int = 0x100;
const ACL_FIRST_ENTRY: c_int = 0;

struct OwnedAcl(NonNull<c_void>);

impl Drop for OwnedAcl {
    fn drop(&mut self) {
        // SAFETY: this is the unique owner of an allocation returned by the
        // Darwin ACL API; no borrowed entry escapes its lifetime.
        unsafe { acl_free(self.0.as_ptr()) };
    }
}

// Darwin sys/fcntl.h filesec_property_t value.
const FILESEC_ACL: c_int = 5;

struct OwnedFileSecurity(NonNull<c_void>);

impl OwnedFileSecurity {
    fn new() -> io::Result<Self> {
        // SAFETY: filesec_init returns a new independently owned container.
        NonNull::new(unsafe { filesec_init() })
            .map(Self)
            .ok_or_else(io::Error::last_os_error)
    }

    fn validate_acl(&self) -> io::Result<()> {
        let mut acl: *mut c_void = std::ptr::null_mut();
        // SAFETY: FILESEC_ACL writes an independently allocated ACL pointer to
        // the writable output slot; the live container owns no returned ACL.
        if unsafe { filesec_get_property(self.0.as_ptr(), FILESEC_ACL, (&raw mut acl).cast()) } != 0
        {
            let error = io::Error::last_os_error();
            // Only a missing property after a successful stat means no ACL.
            return if error.raw_os_error() == Some(nix::libc::ENOENT) {
                Ok(())
            } else {
                Err(error)
            };
        }
        validate_acl(acl)
    }
}

impl Drop for OwnedFileSecurity {
    fn drop(&mut self) {
        // SAFETY: this uniquely owned container was returned by filesec_init.
        unsafe { filesec_free(self.0.as_ptr()) };
    }
}

pub(super) fn validate(file: &File) -> io::Result<()> {
    let security = OwnedFileSecurity::new()?;
    let mut stat = std::mem::MaybeUninit::<nix::libc::stat>::uninit();
    // SAFETY: the descriptor, security container and correctly sized output
    // stay live. Stat failure is distinct from an absent ACL property.
    if unsafe { fstatx_np(file.as_raw_fd(), stat.as_mut_ptr(), security.0.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    security.validate_acl()
}

fn validate_acl(acl: *mut c_void) -> io::Result<()> {
    let acl = NonNull::new(acl).ok_or_else(|| io::Error::other("ACL property returned no ACL"))?;
    let acl = OwnedAcl(acl);
    // SAFETY: acl is the live, uniquely owned value returned by filesec_get_property.
    if unsafe { acl_valid(acl.0.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: the ACL and writable entry pointer remain live for this call.
    let result = unsafe { acl_get_entry(acl.0.as_ptr(), ACL_FIRST_ENTRY, &raw mut entry) };
    if result == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private path has an extended access-control list",
        ));
    }
    let error = io::Error::last_os_error();
    // Darwin returns -1/EINVAL for FIRST_ENTRY on a valid empty ACL.
    if result == -1 && error.raw_os_error() == Some(nix::libc::EINVAL) {
        Ok(())
    } else {
        Err(error)
    }
}

/// Socket vnodes cannot be opened with open(2), including `O_EVTONLY`.
/// Keep their parent captured and reject replacement during ACL inspection.
pub(super) fn validate_socket(path: &std::path::Path) -> io::Result<()> {
    use nix::fcntl::AtFlags;
    use nix::sys::stat::fstatat;
    use std::os::unix::ffi::OsStrExt as _;

    let parent = path
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let directory = super::open_directory_no_follow_unix(parent)?;
    let stat =
        || fstatat(&directory, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(super::nix_io_error);
    let before = stat()?;
    if before.st_mode & nix::libc::S_IFMT != nix::libc::S_IFSOCK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ACL path is not a socket",
        ));
    }
    let native_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let (inspected, security) = inspect_socket_path(&native_path)?;
    let result = security.validate_acl();
    let after = stat()?;
    let named = inspected;
    if (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_ctime,
        after.st_ctime_nsec,
    ) != (
        named.st_dev,
        named.st_ino,
        named.st_mode,
        named.st_uid,
        named.st_gid,
        named.st_ctime,
        named.st_ctime_nsec,
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socket pathname changed during ACL inspection",
        ));
    }
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_ctime,
        before.st_ctime_nsec,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_ctime,
        after.st_ctime_nsec,
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socket changed during ACL inspection",
        ));
    }
    result
}

fn inspect_socket_path(path: &std::ffi::CStr) -> io::Result<(nix::libc::stat, OwnedFileSecurity)> {
    let security = OwnedFileSecurity::new()?;
    let mut inspected = std::mem::MaybeUninit::<nix::libc::stat>::uninit();
    // SAFETY: the NUL-terminated path, correctly sized stat output and unique
    // security container stay live. lstatx_np never follows the final symlink.
    // Inspect identity and ACL from the same successful filesystem query.
    if unsafe { lstatx_np(path.as_ptr(), inspected.as_mut_ptr(), security.0.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful lstatx_np initialized the complete stat output.
    let inspected = unsafe { inspected.assume_init() };
    Ok((inspected, security))
}

pub(super) fn restrict(file: &File) -> io::Result<()> {
    // SAFETY: zero requests an empty ACL, whose allocation has one owner.
    let acl = NonNull::new(unsafe { acl_init(0) }).ok_or_else(io::Error::last_os_error)?;
    let acl = OwnedAcl(acl);
    // SAFETY: both the descriptor and ACL are live. Darwin copies the ACL into
    // the filesystem object; it does not retain the allocation after returning.
    if unsafe { acl_set_fd_np(file.as_raw_fd(), acl.0.as_ptr(), ACL_TYPE_EXTENDED) } != 0 {
        return Err(io::Error::last_os_error());
    }
    validate(file)
}

// Darwin sys/{acl,fcntl,stat}.h. libc does not expose these entry points.
unsafe extern "C" {
    fn filesec_init() -> *mut c_void;
    fn filesec_free(security: *mut c_void);
    fn filesec_get_property(security: *mut c_void, property: c_int, value: *mut c_void) -> c_int;
    #[cfg_attr(target_arch = "x86_64", link_name = "fstatx_np$INODE64")]
    fn fstatx_np(fd: c_int, stat: *mut nix::libc::stat, security: *mut c_void) -> c_int;
    #[cfg_attr(target_arch = "x86_64", link_name = "lstatx_np$INODE64")]
    fn lstatx_np(
        path: *const nix::libc::c_char,
        stat: *mut nix::libc::stat,
        security: *mut c_void,
    ) -> c_int;
    fn acl_set_fd_np(fd: c_int, acl: *mut c_void, kind: c_int) -> c_int;
    fn acl_init(count: c_int) -> *mut c_void;
    fn acl_valid(acl: *mut c_void) -> c_int;
    fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_free(acl: *mut c_void) -> c_int;
}

#[cfg(test)]
#[path = "macos_acl/tests.rs"]
mod tests;

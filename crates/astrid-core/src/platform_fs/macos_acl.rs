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

pub(super) fn validate(file: &File) -> io::Result<()> {
    // SAFETY: file keeps its descriptor live throughout the call. The returned
    // ACL is independent storage and is released through OwnedAcl on every path.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    let Some(acl) = NonNull::new(acl) else {
        let error = io::Error::last_os_error();
        // On a captured live descriptor, Darwin FILESEC_ACL reports ENOENT
        // when the object has no ACL property. Other inspection errors fail.
        return if error.raw_os_error() == Some(nix::libc::ENOENT) {
            Ok(())
        } else {
            Err(error)
        };
    };
    let acl = OwnedAcl(acl);
    // SAFETY: acl is the live, uniquely owned value returned by acl_get_fd_np.
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

// Darwin sys/acl.h. libc does not currently expose these ACL entry points.
unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
    fn acl_set_fd_np(fd: c_int, acl: *mut c_void, kind: c_int) -> c_int;
    fn acl_init(count: c_int) -> *mut c_void;
    fn acl_valid(acl: *mut c_void) -> c_int;
    fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_free(acl: *mut c_void) -> c_int;
}

#[cfg(test)]
#[path = "macos_acl/tests.rs"]
mod tests;

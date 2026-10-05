//! Descriptor-bound Darwin ACL operations; never parse command output.
// The Apple SDK's sys/acl.h declares these APIs, not the Rust libc crate.
#![allow(unsafe_code)]

use nix::libc;
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;
use std::path::Path;
use std::ptr::NonNull;

const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
const ACL_FIRST_ENTRY: libc::c_int = 0;

unsafe extern "C" {
    fn acl_init(count: libc::c_int) -> *mut c_void;
    fn acl_free(acl: *mut c_void) -> libc::c_int;
    fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
    fn acl_set_fd_np(fd: libc::c_int, acl: *mut c_void, kind: libc::c_int) -> libc::c_int;
    fn acl_valid(acl: *mut c_void) -> libc::c_int;
    fn acl_get_entry(
        acl: *mut c_void,
        entry_id: libc::c_int,
        entry: *mut *mut c_void,
    ) -> libc::c_int;
}

struct Acl(NonNull<c_void>);

impl Acl {
    fn owned(pointer: *mut c_void) -> io::Result<Self> {
        NonNull::new(pointer)
            .map(Self)
            .ok_or_else(io::Error::last_os_error)
    }
}

impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: this allocation comes exclusively from Darwin's ACL allocator
        // and is owned by this wrapper. Nothing borrows it after drop.
        unsafe { acl_free(self.0.as_ptr()) };
    }
}

fn open(path: &Path) -> io::Result<File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        super::open_directory_no_follow_unix(path)
    } else if metadata.is_file() {
        super::open_file_no_follow_unix(path)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACL path must be a real file or directory",
        ))
    }
}

pub(super) fn remove(path: &Path) -> io::Result<()> {
    let file = open(path)?;
    // SAFETY: zero requests an empty ACL; the returned allocation is owned.
    let empty = Acl::owned(unsafe { acl_init(0) })?;
    // SAFETY: the descriptor and ACL remain alive for the synchronous call.
    if unsafe { acl_set_fd_np(file.as_raw_fd(), empty.0.as_ptr(), ACL_TYPE_EXTENDED) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn validate(path: &Path) -> io::Result<()> {
    let file = open(path)?;
    // SAFETY: descriptor remains live; returned ACL is a separately owned snapshot.
    let acl = match Acl::owned(unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) }) {
        Ok(acl) => acl,
        // Darwin's fstatx_np leaves FILESEC_ACL unset when KAUTH_FILESEC_NOACL
        // is present; filesec_get_property then returns ENOENT. The descriptor
        // is already open, so this is absent ACL metadata, not a missing path.
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
        Err(error) => return Err(error),
    };
    // SAFETY: acl is a live allocation returned by the system.
    if unsafe { acl_valid(acl.0.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: ACL and writable entry pointer remain alive. Darwin returns zero
    // for an entry, unlike Linux's API; a valid empty ACL returns EINVAL.
    if unsafe { acl_get_entry(acl.0.as_ptr(), ACL_FIRST_ENTRY, &raw mut entry) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private path has an extended access-control list",
        ));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EINVAL) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_and_removes_real_file_and_directory_acls() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        std::fs::write(&file, b"kept").unwrap();
        for path in [root.path(), file.as_path()] {
            validate(path).unwrap();
            assert!(
                std::process::Command::new("/bin/chmod")
                    .args(["+a", "everyone allow read"])
                    .arg(path)
                    .status()
                    .unwrap()
                    .success()
            );
            assert_eq!(
                validate(path).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            remove(path).unwrap();
            validate(path).unwrap();
        }
        assert_eq!(std::fs::read(file).unwrap(), b"kept");
    }

    #[test]
    fn refuses_symlink_without_touching_target() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("target");
        std::fs::write(&file, b"kept").unwrap();
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow read"])
                .arg(&file)
                .status()
                .unwrap()
                .success()
        );
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(validate(&link).is_err());
        assert!(remove(&link).is_err());
        assert_eq!(
            validate(&file).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn refuses_missing_paths_and_symlink_ancestors() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        assert!(validate(&missing).is_err());
        assert!(remove(&missing).is_err());
        let directory = root.path().join("real");
        std::fs::create_dir(&directory).unwrap();
        let file = directory.join("file");
        std::fs::write(&file, b"kept").unwrap();
        let link = root.path().join("alias");
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        assert!(validate(&link.join("file")).is_err());
        assert!(remove(&link.join("file")).is_err());
        assert_eq!(std::fs::read(file).unwrap(), b"kept");
    }

    #[test]
    fn removes_inherited_acl_without_changing_payload() {
        let root = tempfile::tempdir().unwrap();
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow read,file_inherit,directory_inherit"])
                .arg(root.path())
                .status()
                .unwrap()
                .success()
        );
        let file = root.path().join("inherited");
        std::fs::write(&file, b"kept").unwrap();
        assert_eq!(
            validate(&file).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        remove(&file).unwrap();
        validate(&file).unwrap();
        assert_eq!(std::fs::read(file).unwrap(), b"kept");
        assert_eq!(
            validate(root.path()).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}

//! Descriptor-bound copy-on-write cloning into a fresh private path.

use std::fs::File;
use std::io;
use std::path::Path;

#[cfg(target_os = "macos")]
mod metadata;

/// Clone regular-file contents into a new, independent inode when supported.
///
/// The source descriptor pins the opened file rather than following its path
/// again. Callers must own the destination parent and authenticate the cloned
/// bytes before publication: cloning confers neither identity nor authority.
/// On macOS, sources with file flags or extended attributes use the ordinary
/// copy fallback; accepted clones receive private owner-readable/writable mode.
/// Returns `false` without creating a destination on unsupported filesystems
/// or platforms. The caller can then write its already authenticated bytes.
///
/// # Errors
///
/// Rejects non-regular source files, existing destinations, and filesystem
/// errors other than unsupported cloning or cross-device operation.
pub fn try_clone_file(source: &File, destination: &Path) -> io::Result<bool> {
    if !source.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "clone source is not a regular file",
        ));
    }
    platform_clone(source, destination)
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn platform_clone(source: &File, destination: &Path) -> io::Result<bool> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    const CLONE_NOOWNERCOPY: u32 = 0x0002; // macOS sys/clonefile.h ABI.
    if !metadata::eligible(source)? {
        return Ok(false);
    }
    let destination_cstring = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "clone path contains NUL"))?;
    // SAFETY: the source descriptor remains borrowed and open for the call;
    // destination is NUL-terminated and alive. The syscall retains neither.
    // fclonefileat creates a new inode and never overwrites an existing path.
    let result = unsafe {
        nix::libc::fclonefileat(
            source.as_raw_fd(),
            nix::libc::AT_FDCWD,
            destination_cstring.as_ptr(),
            CLONE_NOOWNERCOPY,
        )
    };
    if result == 0 {
        return metadata::prepare(destination);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(nix::libc::ENOTSUP | nix::libc::EXDEV) => Ok(false),
        _ => Err(error),
    }
}

#[cfg(not(target_os = "macos"))]
fn platform_clone(_source: &File, _destination: &Path) -> io::Result<bool> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_is_independent_and_does_not_clobber() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let target = root.path().join("target");
        std::fs::write(&source, vec![7; 1024 * 1024]).unwrap();
        let opened = File::open(&source).unwrap();
        if !try_clone_file(&opened, &target).unwrap() {
            assert!(!target.exists());
            return;
        }
        assert_eq!(
            std::fs::read(&source).unwrap(),
            std::fs::read(&target).unwrap()
        );
        assert!(try_clone_file(&opened, &target).is_err());
        std::fs::write(&target, b"target change").unwrap();
        assert_eq!(std::fs::read(&source).unwrap(), vec![7; 1024 * 1024]);
        std::fs::write(&source, b"source change").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"target change");
    }

    #[test]
    fn cloned_descriptor_does_not_reopen_a_replaced_source_path() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let target = root.path().join("target");
        std::fs::write(&source, b"captured").unwrap();
        let opened = File::open(&source).unwrap();
        std::fs::rename(&source, root.path().join("old")).unwrap();
        std::fs::write(&source, b"substitution").unwrap();
        if try_clone_file(&opened, &target).unwrap() {
            assert_eq!(std::fs::read(&target).unwrap(), b"captured");
        } else {
            assert!(!target.exists());
        }
    }
}

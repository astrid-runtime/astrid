//! Compare the sole permitted OS attribute with a fresh local-file baseline.
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

const PROVENANCE: &[u8] = b"com.apple.provenance\0";

pub(super) fn permitted_names(file: &File) -> io::Result<bool> {
    // Fixed-name storage prevents untrusted side data from sizing an allocation.
    let mut names = [0_u8; PROVENANCE.len()];
    // SAFETY: the descriptor and fixed output buffer remain live for this call.
    let count = unsafe {
        nix::libc::flistxattr(file.as_raw_fd(), names.as_mut_ptr().cast(), names.len(), 0)
    };
    if count < 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(nix::libc::ERANGE) {
            Ok(false)
        } else {
            Err(error)
        };
    }
    Ok(
        count == 0
            || (usize::try_from(count).ok() == Some(PROVENANCE.len()) && names == PROVENANCE),
    )
}

pub(super) fn matches_local(file: &File, parent: &Path) -> io::Result<bool> {
    if !permitted_names(file)? {
        return Ok(false);
    }
    let size = value_size(file)?;
    if size.is_none() {
        return Ok(true);
    }
    let path = parent.join(format!(
        ".astrid-clone-metadata-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let baseline = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&path)?;
    // The descriptor now owns the empty baseline; no extra projection survives.
    std::fs::remove_file(path)?;
    if !permitted_names(&baseline)? {
        return Ok(false);
    }
    let expected_size = value_size(&baseline)?;
    if size != expected_size {
        return Ok(false);
    }
    let Some(length) = expected_size else {
        return Ok(false);
    };
    let expected = read_value(&baseline, length)?;
    Ok(read_value(file, length)? == expected)
}

fn value_size(file: &File) -> io::Result<Option<usize>> {
    // SAFETY: query size only, with an open descriptor and static C string.
    let count = unsafe {
        nix::libc::fgetxattr(
            file.as_raw_fd(),
            c"com.apple.provenance".as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            0,
        )
    };
    if count < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(nix::libc::ENOATTR) {
            return Ok(None);
        }
        return Err(error);
    }
    usize::try_from(count)
        .map(Some)
        .map_err(|_| io::Error::other("attribute size overflow"))
}

fn read_value(file: &File, length: usize) -> io::Result<Vec<u8>> {
    // Only the fresh, empty local baseline supplies the allocation length.
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|error| io::Error::other(error.to_string()))?;
    bytes.resize(length, 0);
    // SAFETY: open descriptor, static name and live output buffer of length.
    let count = unsafe {
        nix::libc::fgetxattr(
            file.as_raw_fd(),
            c"com.apple.provenance".as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            0,
            0,
        )
    };
    if usize::try_from(count).ok() != Some(length) {
        return Err(io::Error::other(
            "attribute changed during clone validation",
        ));
    }
    Ok(bytes)
}

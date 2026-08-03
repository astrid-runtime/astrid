//! Durable Windows namespace transitions.

use std::io;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

use super::path::wide_path;

pub(in crate::platform_fs) fn rename_with_write_through(
    source: &Path,
    destination: &Path,
) -> io::Result<()> {
    let source = wide_path(source)?;
    let destination = wide_path(destination)?;
    // SAFETY: both paths are NUL terminated. Omitting REPLACE_EXISTING keeps
    // the private staging transition fail-closed if a destination appears.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

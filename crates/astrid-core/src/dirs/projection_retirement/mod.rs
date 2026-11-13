//! The single fail-closed boundary for retiring an Astrid runtime projection.

use std::io;
use std::path::Path;

#[cfg(all(test, unix))]
mod tests;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::PreparedProjectionRetirement;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::PreparedProjectionRetirement;

#[cfg(all(feature = "test-support", unix))]
mod replay;
#[cfg(all(feature = "test-support", unix))]
pub use replay::interrupt_retirement_before_unlink_once;

const CANONICAL_VOLUME: &str = "astrid.volume";

/// Validate the complete projection before deleting any entry.
///
/// Every caller must use this function so a regular file is never removed
/// before a later root special or nested redirect can stop retirement. The
/// canonical media file is the only survivor. Successful return durably commits
/// that root namespace. Partial deletion progress after an error is not a
/// durable checkpoint; the caller must retain its recovery authority until
/// retirement succeeds.
///
/// On Windows, durable commit requires NTFS `DirectoryFile` flush
/// (`NtFlushBuffersFileEx(0)`) before and after handle-relative deletes.
///
/// # Errors
///
/// Returns an I/O error when a projection entry is redirected, is neither a
/// regular file nor a real directory, cannot be removed, or (Windows) the
/// filesystem cannot prove NTFS directory-structure flush. A preflight error
/// leaves the tree untouched; a mid-retire error leaves the durable volume as
/// the recovery authority.
pub fn retire_projection_root(root: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        unix::retire(root)
    }
    #[cfg(windows)]
    {
        windows::retire(root)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = root;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "projection retirement requires unix or windows",
        ))
    }
}

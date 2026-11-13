//! The single fail-closed boundary for retiring an Astrid runtime projection.

use std::io;
use std::path::Path;

#[cfg(all(test, any(unix, windows)))]
mod checked_tests;
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

/// Optional content admission during the same complete namespace capture.
#[cfg(any(unix, windows))]
struct SourceChecker<'a> {
    select: &'a mut dyn FnMut(&Path) -> bool,
    verify: &'a mut dyn FnMut(&Path, &mut std::fs::File) -> io::Result<()>,
}

#[cfg(any(unix, windows))]
impl PreparedProjectionRetirement {
    /// Compare an opened source with an exact-length authenticated stream.
    ///
    /// This read-only helper checks bytes and exact EOF using bounded buffers.
    /// It performs no pathname, privacy, identity or mount checks; use it on
    /// the read-only file supplied by [`Self::prepare_checked`], whose capture
    /// owns those checks. Neither stream is rewound by this function.
    ///
    /// # Errors
    /// Returns an error on source or authenticated-stream read failure, or an
    /// expected stream longer than its declared length. Byte mismatch is false.
    pub fn matches_file_from(
        source: &mut std::fs::File,
        length: u64,
        expected: &mut dyn io::Read,
    ) -> io::Result<bool> {
        crate::platform_fs::matches_projection_file_from(source, length, expected)
    }
}

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

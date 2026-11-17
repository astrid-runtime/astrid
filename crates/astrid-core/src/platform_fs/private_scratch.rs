//! Anonymous private scratch files for in-process rollback bytes.
//!
//! Scratch lives in OS temporary capacity and is reaped with the process. It is
//! not a durable recovery authority; RETIRING volume inventory remains that role.

use std::fs::File;
use std::io;

/// Create one private anonymous scratch file.
///
/// Platform privacy is established before prior-generation bytes are copied.
/// The handle's lifetime owns cleanup; no application-home sidecar is created.
///
/// # Errors
/// Returns an I/O error when the operating system cannot create a private
/// temporary file, or when Windows protection fails.
pub fn create_private_scratch_file() -> io::Result<File> {
    #[cfg(windows)]
    {
        super::windows::create_private_scratch_file()
    }
    #[cfg(not(windows))]
    {
        let file = tempfile::tempfile()?;
        // Darwin can inherit allow entries despite mode 0600. Reject them
        // before any secret bytes are copied; permission repair cannot revoke
        // a handle opened before the anonymous file was unlinked.
        #[cfg(target_os = "macos")]
        super::macos_acl::validate(&file)?;
        Ok(file)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests;

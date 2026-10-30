//! One bounded, rooted session for restoring private projection files.

use std::ffi::OsString;
use std::io;
use std::path::{Component, Path};

#[cfg(unix)]
#[path = "private_projection/unix/mod.rs"]
mod platform;
#[cfg(not(unix))]
#[path = "private_projection/portable.rs"]
mod platform;

/// Restore private files relative to one captured projection root.
///
/// Each Unix file retains its data and parent metadata fsyncs. Call [`Self::sync`]
/// after the batch, including after rollback or a failed operation, to complete
/// the root hardware durability fence and validate the absolute root binding.
/// Descriptors are bounded by the root and the current relative path depth;
/// no directory cache grows with the number of files.
pub struct PrivateFileProjection {
    platform: platform::Projection,
}

impl PrivateFileProjection {
    /// Open an existing projection root without following redirects.
    ///
    /// # Errors
    /// Returns an error if the root is missing, redirected, or cannot be private.
    pub fn open(root: &Path) -> io::Result<Self> {
        Ok(Self {
            platform: platform::Projection::open(root)?,
        })
    }

    /// Snapshot an existing regular destination for rollback.
    ///
    /// Existing regular files may have ordinary modes, owners or other hard
    /// links; replacement creates a new private file without altering aliases.
    ///
    /// # Errors
    /// Returns an error for invalid names, redirects, special files or I/O failure.
    pub fn snapshot(&self, relative: &Path) -> io::Result<Option<Vec<u8>>> {
        self.platform.snapshot(&RelativePath::parse(relative)?)
    }

    /// Atomically publish a private regular file and fsync its data and parent.
    ///
    /// # Errors
    /// Returns an error on unsafe paths, changed identities or any write/fence failure.
    pub fn write(&self, relative: &Path, bytes: &[u8]) -> io::Result<()> {
        self.platform.write(&RelativePath::parse(relative)?, bytes)
    }

    /// Remove a regular projected file during rollback; absence is success.
    ///
    /// # Errors
    /// Returns an error for redirects, special entries, changed identities or I/O failure.
    pub fn remove(&self, relative: &Path) -> io::Result<()> {
        self.platform.remove(&RelativePath::parse(relative)?)
    }

    /// Create a private directory marker, fsyncing changed directory metadata.
    ///
    /// # Errors
    /// Returns an error for unsafe paths, directory substitutions or I/O failure.
    pub fn ensure_directory(&self, relative: &Path) -> io::Result<()> {
        self.platform
            .ensure_directory(&RelativePath::parse(relative)?)
    }

    /// Complete the batch's terminal durability fence and validate its root.
    ///
    /// # Errors
    /// Returns an error for a changed root binding or an unsuccessful fence.
    pub fn sync(&self) -> io::Result<()> {
        self.platform.sync()
    }
}

struct RelativePath(Vec<OsString>);

impl RelativePath {
    fn parse(path: &Path) -> io::Result<Self> {
        let mut names = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(name) => names.push(name.to_os_string()),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "projection path is not strictly relative",
                    ));
                },
            }
        }
        // components() normalizes interior dots and repeated separators. Reject
        // those spellings too, while accepting either native Windows separator.
        let abnormal = path
            .as_os_str()
            .as_encoded_bytes()
            .split(|byte| *byte == b'/' || cfg!(windows) && *byte == b'\\')
            .any(|part| part.is_empty() || part == b"." || part == b"..");
        if names.is_empty() || abnormal {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "projection path contains a non-normal component",
            ));
        }
        Ok(Self(names))
    }
}
